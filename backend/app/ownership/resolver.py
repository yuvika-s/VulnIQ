"""
Ownership Resolution Engine — makes Engineering ownership a first-class,
deterministic dimension across VulnIQ.

Authoritative source: backend/data/ownership.json (derived from Assets.xlsx
'Owners - Repo' + 'Owners - Apps', with canonical head identities resolved so the
same person isn't double-counted across the two sheets).

A finding maps to EXACTLY ONE engineering head via a deterministic 5-tier
priority (first hit wins, same input → same owner, always):

  1. Repository      → head   (Owners - Repo)        — most specific
  2. Application     → head   (Owners - Apps, by asset/app name)
  3. Asset/IP corr.  → head   (Tenable host → app → head, via the asset name the
                               IP-correlation layer already resolved)
  4. Chain endpoint  → head   (a finding with no direct owner but sitting on a
                               chain inherits that chain's primary owner)
  5. Miscellaneous           (no signal — never silently dropped)

A chain maps to EXACTLY ONE primary owner — the team that owns the END-STATE
risk (the crown jewel / final objective), with every other contributing team
tracked as a SECONDARY owner (so dashboards can show cross-team chains without
ever counting a chain twice).
"""
from __future__ import annotations

import json
import os
import re

_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data", "ownership.json")

MISC = "Miscellaneous"


# ── load ─────────────────────────────────────────────────────────────────── #
def load_ownership() -> dict:
    """repo_to_head / app_to_head / app_to_bu / heads. Returns empty maps if the
    artifact is absent so the pipeline degrades gracefully (everything → Misc)."""
    try:
        with open(_DATA) as fh:
            d = json.load(fh)
    except Exception:
        d = {}
    d.setdefault("repo_to_head", {})
    d.setdefault("app_to_head", {})
    d.setdefault("app_to_bu", {})
    d.setdefault("head_to_bu", {})
    d.setdefault("heads", {})
    return d


# ── normalisation ────────────────────────────────────────────────────────── #
def _norm_app(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()


_REPO_RE = re.compile(r"repo:([^\s·|]+)", re.I)


def _last(slug: str) -> str:
    return str(slug).strip().lower().strip("/").split("/")[-1]


def _repo_of(finding) -> str | None:
    """Best-effort repository slug for a finding. Snyk carries it in location —
    either as an explicit 'repo:<slug>' token (app-matched findings) or as the
    first 'org/repo:branch:file' segment (un-matched findings). Also checks
    source_metadata. Returns None when no repo signal exists (e.g. Tenable host)."""
    loc = getattr(finding, "location", "") or ""
    m = _REPO_RE.search(loc)
    if m:
        return _last(m.group(1))
    # 'angel-one/smart-api-order-service:branch:file' → 'smart-api-order-service'
    for part in loc.split("·"):
        seg = part.strip().split(":")[0].strip()
        if seg and "/" in seg:
            return _last(seg)
    md = getattr(finding, "source_metadata", {}) or {}
    for k in ("repo", "repository", "repo_short", "snyk_repo"):
        if md.get(k):
            return _last(md[k])
    return None


# ── per-finding resolution (tiers 1–3; tier 4–5 applied in resolve_all) ────── #
def _direct_owner(finding, assets: dict, own: dict):
    """Return (head, business_unit, tier) for tiers 1–3, or (None, None, None)."""
    # Tier 1 — repository → head
    repo = _repo_of(finding)
    if repo and repo in own["repo_to_head"]:
        head = own["repo_to_head"][repo]
        bu = _bu_for_finding(finding, assets, own)
        return head, bu, 1

    # Tier 2/3 — application / asset name → head. The asset name is the inventory
    # application (Snyk repo→app match, tier 2) OR the IP-correlated application
    # (Tenable host → app, tier 3); both resolve through the one app-name lookup
    # because the IP-correlation layer already turned the host into its app name.
    a = assets.get(finding.affected_asset_id)
    app_key = _norm_app(a.name if a else finding.affected_asset_id)
    if app_key in own["app_to_head"]:
        tier = 3 if (a and getattr(a, "ip_derived", False)) else 2
        return own["app_to_head"][app_key], own["app_to_bu"].get(app_key, MISC), tier

    # Tier 3 (asset correlation) — the asset/app slug is itself a repository in the
    # ownership sheet. Catches infra services (us-market-data, MDS_API_Automation)
    # whose asset name is a repo, not an Owners-Apps application.
    for cand in {finding.affected_asset_id, app_key.replace(" ", "-")}:
        slug = _last(cand)
        if slug in own["repo_to_head"]:
            return own["repo_to_head"][slug], _bu_for_finding(finding, assets, own), 3

    return None, None, None


def _bu_for_finding(finding, assets: dict, own: dict) -> str:
    a = assets.get(finding.affected_asset_id)
    app_key = _norm_app(a.name if a else finding.affected_asset_id)
    return own["app_to_bu"].get(app_key, MISC)


# ── chain ownership ──────────────────────────────────────────────────────── #
def _chain_primary_and_secondary(chain, fmap, assets, own, finding_head: dict):
    """Primary = owner of the END-STATE (crown jewel, else endpoint finding, else
    entry). Secondary = every other contributing owner, deduped, minus primary.
    A chain is therefore counted under exactly ONE primary owner."""
    # owner of the crown-jewel asset (end-state target)
    primary = None
    cj = assets.get(getattr(chain, "crown_jewel", "")) if assets else None
    if cj:
        ck = _norm_app(cj.name)
        primary = own["app_to_head"].get(ck)
    # else the endpoint finding's owner, else the entry finding's owner
    path = list(chain.finding_ids)
    if not primary and path:
        primary = finding_head.get(path[-1])
    if not primary and path:
        primary = finding_head.get(path[0])
    primary = primary or MISC

    contributors = []
    for fid in path:
        h = finding_head.get(fid, MISC)
        if h != primary and h not in contributors:
            contributors.append(h)
    return primary, contributors


# ── public entry point ───────────────────────────────────────────────────── #
def resolve_all(findings: list, chains: list, assets: dict, own: dict | None = None):
    """Stamp owner_head / business_unit on every finding and primary_owner /
    secondary_owners on every chain. Deterministic and idempotent. Returns the
    ownership maps used (for validation)."""
    own = own or load_ownership()

    # pass 1 — direct owners (tiers 1–3)
    head_to_bu = own.get("head_to_bu", {})
    finding_head: dict[str, str] = {}
    for f in findings:
        head, bu, tier = _direct_owner(f, assets, own)
        f.owner_head = head            # may be None → filled in pass 3
        bu = bu or MISC
        # repo-resolved findings have a head but no application BU — fall back to
        # that head's dominant business unit so BU attribution isn't all Misc.
        if bu == MISC and head and head in head_to_bu:
            bu = head_to_bu[head]
        f.business_unit = bu
        f.owner_tier = tier or 0
        if head:
            finding_head[f.finding_id] = head

    fmap = {f.finding_id: f for f in findings}

    # pass 2 — chain owners (needs the direct finding owners above)
    for c in chains:
        primary, secondary = _chain_primary_and_secondary(
            c, fmap, assets, own, finding_head)
        c.primary_owner = primary
        c.secondary_owners = secondary

    # pass 3 — tier 4 (chain-endpoint inheritance) then tier 5 (Miscellaneous)
    inherited: dict[str, str] = {}
    for c in chains:
        for fid in c.finding_ids:
            f = fmap.get(fid)
            if f and not f.owner_head and fid not in inherited:
                inherited[fid] = c.primary_owner
    for f in findings:
        if not f.owner_head:
            if f.finding_id in inherited:
                f.owner_head = inherited[f.finding_id]
                f.owner_tier = 4
            else:
                f.owner_head = MISC
                f.owner_tier = 5
    return own
