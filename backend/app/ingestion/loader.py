"""Loads synthetic findings + assets into typed models and enriches with intel."""
from __future__ import annotations

import json
import os

from app.models import Finding, Asset, Layer, Exposure
from app.graph.cwe_capability_map import grants_for
from app.context.intel.threat_intel import enrich

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def load_assets() -> dict[str, Asset]:
    with open(os.path.join(DATA_DIR, "assets.json")) as f:
        raw = json.load(f)["assets"]
    out = {}
    for a in raw:
        out[a["asset_id"]] = Asset(**a)
    return out


def load_findings(do_enrich: bool = True) -> list[Finding]:
    with open(os.path.join(DATA_DIR, "synthetic_findings.json")) as f:
        raw = json.load(f)["findings"]
    findings = []
    for r in raw:
        f = Finding(
            finding_id=r["finding_id"],
            source_tool=r["source_tool"],
            layer=Layer(r["layer"]),
            finding_type=r["finding_type"],
            title=r["title"],
            description=r["description"],
            raw_severity=r["raw_severity"],
            cvss=float(r["cvss"]),
            affected_asset_id=r["affected_asset_id"],
            component=r.get("component", ""),
            cwe=r.get("cwe"),
            cve=r.get("cve"),
            location=r.get("location", ""),
            network_exposure=Exposure(r.get("network_exposure", "internal")),
            evidence=r.get("evidence", ""),
        )
        f.grants = grants_for(f)
        if do_enrich:
            enrich(f)
        findings.append(f)
    return findings


def load_golden_chains() -> dict:
    with open(os.path.join(DATA_DIR, "synthetic_findings.json")) as f:
        return json.load(f).get("golden_chains", {})
