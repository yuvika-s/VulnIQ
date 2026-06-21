"""
IP -> Application correlation for host findings (Tenable / Nessus / Qualys …).

Host scanners report a finding against an IP, not an application. AngelOne's
asset inventory (Assets.xlsx → backend/data/ip_assets.json) maps every server IP
to its owning application + environment + business-criticality. Resolving the IP
to that application lets a host finding share an asset node with the SAME
application's source/dependency/cloud findings — which is exactly what turns a
pile of single-host CVEs into cross-source attack chains:

    Tenable finding → IP → Assets.xlsx → Application → Business context → graph

This is a deterministic, auditable lookup (no LLM). It is intentionally separate
from repo→app matching (asset_match.py) but reuses the same token matcher so a
resolved application name lands on the same asset node a Snyk repo would.
"""
from __future__ import annotations

import json
import os
import re

from app.models import Asset
from app.ingestion.asset_match import match_repo_to_app, build_app_index

_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data", "ip_assets.json")

# Tenable.sc criticality / our IP-sheet criticality → asset tier.
# CRITICAL infra is tier 0 (crown-jewel adjacent); everything else stays low so
# host hygiene findings don't get over-promoted.
_CRIT_TIER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s or "unknown-host"


def load_ip_assets() -> dict:
    """IP -> {application, environment, criticality, dc, trading_server}.

    Returns {} when the artifact is absent (e.g. a deployment that ships without
    the IP inventory) so the rest of the pipeline degrades gracefully to
    hostname-based asset ids instead of failing.
    """
    try:
        with open(_DATA) as fh:
            return json.load(fh).get("ip_assets", {})
    except Exception:
        return {}


def resolve_ip(ip: str, ip_map: dict) -> dict | None:
    """Return the IP inventory record for an IP, or None if unknown."""
    if not ip:
        return None
    return ip_map.get(ip.strip())


def application_asset_id(application: str, assets: dict, index: dict | None = None):
    """Resolve an application NAME to an existing inventory asset_id when one
    matches (so host findings co-locate with that app's other findings), else a
    deterministic slug. Returns (asset_id, matched_inventory_bool)."""
    if not application:
        return None, False
    aid, _tok = match_repo_to_app(application, assets, index)
    if aid:
        return aid, True
    return _slug(application), False


def asset_for_ip_record(asset_id: str, rec: dict) -> Asset:
    """Build a context-rich Asset for an application that the IP inventory knows
    about but the application inventory doesn't. Criticality/environment from the
    IP sheet flow straight into prioritization + chaining (tier drives crown-jewel
    proximity and the P1..P5 matrix). Internet-facing is left False — the IP sheet
    has no exposure column, and we never fabricate exposure we can't evidence."""
    crit = (rec.get("criticality") or "").upper()
    env = rec.get("environment") or ""
    tier = _CRIT_TIER.get(crit, 3)
    return Asset(
        asset_id=asset_id,
        name=rec.get("application") or asset_id,
        tier=tier,
        internet_facing=False,
        data_classification=f"{env.lower()}_infrastructure" if env else "infrastructure",
        business_function=(f"{env} infrastructure"
                           + (f" · {rec.get('dc')}" if rec.get("dc") else "")
                           + (f" · {rec.get('trading_server')}" if rec.get("trading_server") else "")).strip(" ·"),
        is_crown_jewel=False,
        ip_derived=True,
    )


def ensure_ip_assets(findings_records: list[dict], assets: dict, ip_map: dict) -> int:
    """For a batch of raw host records (each carrying an 'ip'), make sure every
    resolved application has an Asset in `assets`, enriching the registry with
    IP-sheet criticality/environment. Returns how many assets were added.

    Mutates `assets` in place (the engine's live registry), mirroring how real
    asset correlation should *strengthen* the shared graph rather than spawn a
    parallel one. Existing inventory assets are never overwritten.
    """
    index = build_app_index(assets)
    added = 0
    for r in findings_records:
        rec = resolve_ip(r.get("ip", ""), ip_map)
        if not rec:
            continue
        aid, matched = application_asset_id(rec.get("application", ""), assets, index)
        if not aid or matched or aid in assets:
            continue
        assets[aid] = asset_for_ip_record(aid, rec)
        # keep the index current so later records in the same batch reuse it
        for t in set(re.split(r"[^a-z0-9]+", aid.lower())):
            if len(t) >= 3:
                index.setdefault(t, []).append(aid)
        added += 1
    return added
