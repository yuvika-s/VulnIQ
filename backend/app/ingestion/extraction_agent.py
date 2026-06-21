"""
Extraction & Normalization Agent — Role 4 of VulnIQ's AI.

THIS IS THE MOST CRUCIAL AGENT. Teams will submit findings in wildly different
formats and documentation styles: a Qualys PDF, a Burp XML, a Semgrep JSON, a
hand-written CSV of "observations". The quality of everything downstream — the
attack graph, the chaining, the prioritization — depends entirely on how well
we normalize these into the unified `Finding` schema.

This agent does NOT just map columns. It *understands* each finding:
  - infers the OSI layer and finding_type from prose
  - infers the attacker capabilities it grants (the key to chaining)
  - resolves which asset it affects, matching against the known asset inventory
  - fills missing fields (CVSS, CWE, exposure) by reasoning, not guessing blindly
  - assigns an extraction_confidence 0-1 and explains low-confidence calls
  - flags anything ambiguous for human review (per product decision)

Like the other roles, it has a deterministic fallback so the pipeline runs
offline — but extraction quality is dramatically better with the LLM, because
this is fundamentally a deep-reading task.
"""
from __future__ import annotations

import json
import logging
import os
import re

from app.ai_config import MODEL, make_client, has_credentials
from app.models import (Finding, Layer, Capability, Exposure)
from app.graph.cwe_capability_map import grants_for

try:
    import anthropic
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False


log = logging.getLogger("vulniq.extract")

LAYERS = [l.value for l in Layer]
CAPS = [c.value for c in Capability]
EXPOSURES = [e.value for e in Exposure]


def _system_prompt(asset_ids: list[str], asset_blurbs: str) -> str:
    return f"""You are a senior application & infrastructure security analyst with deep \
knowledge of SAST, DAST, SCA, cloud, container, IAM and network security. You are \
normalizing raw security findings from many different tools and report styles into a \
single structured schema so they can be correlated into attack chains.

For each finding you are given, extract a JSON object with EXACTLY these fields:

- "title": short finding title (<=90 chars)
- "description": 1-3 sentence plain description of the issue
- "source_tool": the tool/source that produced it (infer from content; "manual" if a human observation)
- "layer": one of {LAYERS}
- "finding_type": short type like "SQLi","XSS","SSRF","exposed_endpoint","CVE","misconfig","overprivileged_role","secret_leak","weak_tls","open_port","RCE","IDOR","auth_bypass", etc.
- "raw_severity": the tool's own severity word if present, else your best label ("Critical/High/Medium/Low/Info")
- "cvss": number 0.0-10.0. If a CVSS is stated, use it. If not, estimate from severity/impact — this is routine and does NOT by itself lower confidence.
- "cwe": "CWE-89" style if identifiable, else null
- "cve": "CVE-YYYY-NNNNN" if present, else null
- "affected_asset_id": MUST match one of the known asset IDs below if the finding clearly maps to one; otherwise use the source repo/app slug verbatim (e.g. "nxt-orchestrator"). A separate step maps repo slugs to applications by name, so a repo-slug asset is EXPECTED and does NOT lower confidence or require review.
- "component": affected library/service/bucket/endpoint if mentioned, else ""
- "location": file:line, URL, host:port, or ARN if present, else ""
- "network_exposure": one of {EXPOSURES} — infer from asset and finding (internet-facing endpoints => internet)
- "grants": list of attacker capabilities this finding gives, chosen from {CAPS}. THINK like an attacker: a SQLi grants ["data_read","credential_access"]; an exposed admin endpoint grants ["initial_access"]; hardcoded DB creds grant ["credential_access","data_read"]; an RCE grants ["code_execution"]. This list is the SINGLE MOST IMPORTANT field for chaining — reason carefully.
- "extraction_confidence": 0.0-1.0 — how confident you are the TYPE, LAYER and GRANTS are correct. For a clearly-structured tool export (Snyk/SCA/container/IaC row with a package, severity and CWE/title) this is normally 0.8-0.95 even without a CVE. Only go below 0.6 when the finding's meaning is genuinely ambiguous.
- "needs_review": true ONLY if you could not confidently determine the finding_type, layer, or grants (i.e. the meaning is unclear). A missing CVE, an estimated CVSS, or a repo-slug asset are NOT reasons to flag review.
- "review_reason": short note on what is genuinely uncertain, else ""

KNOWN ASSETS (match affected_asset_id to these when possible):
{asset_blurbs}

Rules:
- If one input record actually describes MULTIPLE distinct findings, return multiple objects.
- Never invent a CVE or CWE that isn't supported by the text. Use null instead.
- Lower extraction_confidence only when the finding's TYPE/LAYER/GRANTS are unclear — not for routine estimation of CVSS or a repo-slug asset.
- Output ONLY a JSON array of finding objects. No prose, no markdown fences."""


def _asset_blurbs(assets: dict) -> str:
    lines = []
    for a in assets.values():
        lines.append(f"- {a.asset_id}: {a.name} | tier {a.tier} | "
                     f"{'internet-facing' if a.internet_facing else 'internal'} | "
                     f"{a.data_classification}")
    return "\n".join(lines)


def extract_findings_from_records(records: list[str], assets: dict,
                                  use_llm: bool | None = None,
                                  id_start: int = 1000) -> dict:
    """
    Takes raw text records (from extractors.extract) and returns:
    {
      "findings": [Finding, ...],
      "review_queue": [ {finding_id, reason, confidence}, ... ],
      "method": "llm" | "deterministic",
      "stats": {...}
    }
    """
    if use_llm is None:
        use_llm = _HAS_SDK and has_credentials()

    if use_llm:
        try:
            return _extract_llm(records, assets, id_start)
        except Exception as e:
            out = _extract_deterministic(records, assets, id_start)
            out["method"] = "deterministic"
            out["fallback_reason"] = str(e)[:160]
            return out
    return _extract_deterministic(records, assets, id_start)


# --------------------------------------------------------------------------- #
# LLM extraction — batched, the real deal
# --------------------------------------------------------------------------- #
def _extract_llm(records: list[str], assets: dict, id_start: int) -> dict:
    client = make_client()
    if client is None:  # SDK/key vanished between the gate and here
        return _extract_deterministic(records, assets, id_start)
    system = _system_prompt(list(assets.keys()), _asset_blurbs(assets))

    findings, review = [], []
    counter = id_start
    BATCH = 6  # records per call — keeps prompt focused, controls cost
    total_batches = (len(records) + BATCH - 1) // BATCH

    for i in range(0, len(records), BATCH):
        batch = records[i:i + BATCH]
        log.info("  normalization batch %d/%d (%d record(s))...",
                 i // BATCH + 1, total_batches, len(batch))
        user = "Normalize these findings into the schema. Records are separated " \
               "by '=====':\n\n" + "\n=====\n".join(
                   f"RECORD {j+1}:\n{r[:4000]}" for j, r in enumerate(batch))
        resp = client.messages.create(
            model=MODEL, max_tokens=4000, system=system,
            messages=[{"role": "user", "content": user}])
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        objs = _safe_json_array(text)
        for o in objs:
            f, rev = _obj_to_finding(o, assets, counter)
            if f:
                findings.append(f)
                if rev:
                    review.append(rev)
                counter += 1

    return {"findings": findings, "review_queue": review, "method": "llm",
            "stats": _stats(findings, review)}


def _safe_json_array(text: str) -> list:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except Exception:
        # try to salvage the first [...] block
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return []
        return []


def _obj_to_finding(o: dict, assets: dict, counter: int):
    """Convert one LLM JSON object into a typed Finding + optional review item."""
    try:
        layer = Layer(o.get("layer", "source_code"))
    except ValueError:
        layer = Layer.SOURCE_CODE
    try:
        expo = Exposure(o.get("network_exposure", "internal"))
    except ValueError:
        expo = Exposure.INTERNAL

    grants = []
    for g in o.get("grants", []):
        try:
            grants.append(Capability(g))
        except ValueError:
            pass

    aid = o.get("affected_asset_id", "") or "unassigned"
    asset_resolved = aid in assets

    # Repo -> application mapping. Findings arrive tagged with a GitHub repo
    # slug; the inventory holds applications. AngelOne repos carry the app name
    # as a token, so attach the finding to its application (which provides the
    # criticality / internet-facing context for prioritization + chaining).
    repo_orig = None
    if not asset_resolved and aid not in ("", "unassigned"):
        from app.ingestion.asset_match import match_repo_to_app
        app_id, _tok = match_repo_to_app(aid, assets)
        if app_id:
            repo_orig, aid = aid, app_id
            asset_resolved = True

    fid = f"F-U{counter:04d}"  # "U" = uploaded, to distinguish from synthetic
    conf = float(o.get("extraction_confidence", 0.5) or 0.5)
    if repo_orig:  # mapped a repo slug to a known application -> more certain
        conf = min(1.0, conf + 0.1)
    # Flag for human review only when genuinely unanchored: the asset couldn't be
    # mapped to a known application, or confidence is low. A missing CVE, an
    # estimated CVSS, or a repo-slug asset are normal for tool exports and do NOT
    # trigger review (otherwise every Snyk row lands in the queue).
    needs_review = (not asset_resolved) or conf < 0.45

    f = Finding(
        finding_id=fid,
        source_tool=o.get("source_tool", "uploaded") or "uploaded",
        layer=layer,
        finding_type=o.get("finding_type", "unknown") or "unknown",
        title=(o.get("title") or "Untitled finding")[:120],
        description=o.get("description", "") or "",
        raw_severity=o.get("raw_severity", "") or "",
        cvss=_clamp_cvss(o.get("cvss")),
        affected_asset_id=aid,
        component=o.get("component", "") or "",
        cwe=o.get("cwe") or None,
        cve=o.get("cve") or None,
        location=o.get("location", "") or "",
        network_exposure=expo,
        evidence=o.get("evidence", "") or "",
    )
    # if the model didn't give grants, fall back to the deterministic map
    f.grants = grants or grants_for(f)

    rev = None
    if needs_review:
        reasons = []
        if not asset_resolved:
            reasons.append(f"asset '{aid}' could not be mapped to a known application — assign one")
        if conf < 0.45:
            reasons.append(f"low confidence {conf:.2f}")
        if o.get("review_reason"):
            reasons.append(o["review_reason"])
        rev = {"finding_id": fid, "title": f.title,
               "confidence": round(conf, 2),
               "reason": "; ".join(reasons) or "flagged by extractor",
               "asset_resolved": asset_resolved}
    # keep the source repo visible after remapping to its application
    if repo_orig:
        if not f.location:
            f.location = f"repo:{repo_orig}"
        f.evidence = (f.evidence + f" [repo:{repo_orig}->app:{aid}]").strip()
    # store confidence on the finding via evidence-ish channel (kept simple)
    f.evidence = (f.evidence + f" [extraction_confidence={conf:.2f}]").strip()
    return f, rev


def _clamp_cvss(v) -> float:
    try:
        return max(0.0, min(10.0, float(v)))
    except (TypeError, ValueError):
        return 5.0


# --------------------------------------------------------------------------- #
# Deterministic fallback — keyword heuristics so offline still works
# --------------------------------------------------------------------------- #
SEV_TO_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}
TYPE_HINTS = {
    "sql": ("SQLi", Layer.SOURCE_CODE, ["data_read", "credential_access"]),
    "xss": ("XSS", Layer.APPSEC_RUNTIME, ["initial_access"]),
    "ssrf": ("SSRF", Layer.APPSEC_RUNTIME, ["lateral_move"]),
    "rce": ("RCE", Layer.DEPENDENCY, ["code_execution"]),
    "remote code": ("RCE", Layer.DEPENDENCY, ["code_execution"]),
    "credential": ("secret_leak", Layer.DATA, ["credential_access"]),
    "secret": ("secret_leak", Layer.DATA, ["credential_access"]),
    "hardcoded": ("secret_leak", Layer.DATA, ["credential_access"]),
    "privilege": ("overprivileged_role", Layer.IAM_IDENTITY, ["priv_escalation"]),
    "iam": ("overprivileged_role", Layer.IAM_IDENTITY, ["priv_escalation"]),
    "open port": ("open_port", Layer.NETWORK, ["initial_access"]),
    "exposed": ("exposed_endpoint", Layer.APPSEC_RUNTIME, ["initial_access"]),
    "misconfig": ("misconfig", Layer.CLOUD_CONFIG, ["lateral_move"]),
    "tls": ("weak_tls", Layer.NETWORK, []),
    "cve": ("CVE", Layer.DEPENDENCY, ["code_execution"]),
}


def _extract_deterministic(records: list[str], assets: dict, id_start: int) -> dict:
    findings, review = [], []
    counter = id_start
    asset_ids = list(assets.keys())
    for rec in records:
        low = rec.lower()
        ftype, layer, caps = "unknown", Layer.SOURCE_CODE, []
        for hint, (t, l, c) in TYPE_HINTS.items():
            if hint in low:
                ftype, layer, caps = t, l, c
                break
        sev = next((s for s in SEV_TO_CVSS if s in low), "medium")
        cve = (re.search(r"CVE-\d{4}-\d{4,7}", rec, re.I) or [None])
        cve = cve.group(0) if hasattr(cve, "group") else None
        cwe = re.search(r"CWE-\d+", rec, re.I)
        cwe = cwe.group(0) if cwe else None
        # naive asset match
        aid = next((a for a in asset_ids if a.lower() in low), "unassigned")
        title = rec.strip().split("\n")[0][:90] or "Uploaded finding"

        fid = f"F-U{counter:04d}"
        f = Finding(
            finding_id=fid, source_tool="uploaded", layer=layer,
            finding_type=ftype, title=title, description=rec[:300],
            raw_severity=sev, cvss=SEV_TO_CVSS[sev], affected_asset_id=aid,
            cve=cve, cwe=cwe, network_exposure=Exposure.INTERNAL,
        )
        f.grants = [Capability(c) for c in caps] or grants_for(f)
        f.evidence = "[extraction_confidence=0.40 deterministic]"
        findings.append(f)
        review.append({"finding_id": fid, "title": title, "confidence": 0.40,
                       "reason": "deterministic extraction (no LLM) — verify all fields",
                       "asset_resolved": aid in assets})
        counter += 1
    return {"findings": findings, "review_queue": review,
            "method": "deterministic", "stats": _stats(findings, review)}


def _stats(findings, review) -> dict:
    return {
        "extracted": len(findings),
        "needs_review": len(review),
        "auto_accepted": len(findings) - len(review),
        "by_layer": _count(findings, lambda f: f.layer.value),
    }


def _count(items, key):
    out = {}
    for it in items:
        k = key(it)
        out[k] = out.get(k, 0) + 1
    return out
