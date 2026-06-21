"""
Executive brief generator: turns the engine state into a board-ready summary
with regulatory control mapping (SEBI CSCRF, ISO 27001 Annex A, RBI cyber
resilience). Outputs structured JSON the frontend renders as a one-pager.
"""
from __future__ import annotations

from app.engine import ENGINE
from app.agent.dashboard_agent import narrate_chain, tool_best_single_fix

# Minimal control mapping by finding type / theme.
CONTROL_MAP = {
    "hardcoded_credentials": ["ISO 27001 A.8.24 (key mgmt)", "SEBI CSCRF: Secure SDLC",
                              "RBI: Application security controls"],
    "secret_leak": ["ISO 27001 A.8.24", "SEBI CSCRF: Secure SDLC"],
    "overprivileged_role": ["ISO 27001 A.5.15 (access control)", "SEBI CSCRF: Least privilege",
                            "RBI: Access management"],
    "SQLi": ["ISO 27001 A.8.28 (secure coding)", "SEBI CSCRF: Application security"],
    "SSRF": ["ISO 27001 A.8.28", "SEBI CSCRF: Application security"],
    "exposed_endpoint": ["ISO 27001 A.8.20 (network security)", "SEBI CSCRF: Network segmentation"],
    "CVE": ["ISO 27001 A.8.8 (technical vulnerability mgmt)", "SEBI CSCRF: Vulnerability mgmt",
            "RBI: Patch management"],
    "misconfig": ["ISO 27001 A.8.9 (configuration mgmt)", "SEBI CSCRF: Secure configuration"],
}


def _controls_for(finding):
    return CONTROL_MAP.get(finding.finding_type, CONTROL_MAP.get(
        "CVE" if finding.cve else "misconfig"))


def generate_brief(scope: str = "all") -> dict:
    s = ENGINE.stats()
    top_chains = ENGINE.chains[:5]
    best_fix = tool_best_single_fix()

    chain_summaries = []
    for c in top_chains:
        controls = set()
        for fid in c.finding_ids:
            f = ENGINE.finding(fid)
            if f:
                controls.update(_controls_for(f))
        chain_summaries.append({
            "chain_id": c.chain_id,
            "risk": c.chain_risk,
            "crown_jewel": c.crown_jewel,
            "path": c.finding_ids,
            "narrative": narrate_chain(c.chain_id),
            "controls": sorted(controls),
        })

    critical = sorted(
        [f for f in ENGINE.findings if f.priority and
         f.priority.value == "break_chain_critical"],
        key=lambda x: -x.final_score)

    return {
        "title": "VulnIQ Executive Security Brief",
        "subtitle": "Context-aware, attack-chain-prioritized exposure summary",
        "generated_for": "Angel One — CISO / Risk Committee",
        "headline": {
            "org_risk_score": s["org_risk_score"],
            "active_attack_chains": s["total_chains"],
            "crown_jewels_reachable": len({c.crown_jewel for c in top_chains}),
            "total_findings": s["total_findings"],
            "deferred_as_noise": s["by_priority"].get("defer", 0),
            "noise_reduction_pct": round(
                100 * s["by_priority"].get("defer", 0) / max(s["total_findings"], 1), 1),
        },
        "recommended_first_action": {
            "finding_id": best_fix.get("finding_id"),
            "title": best_fix.get("title"),
            "chains_collapsed": best_fix.get("chains_collapsed"),
            "risk_drop_pct": best_fix.get("risk_drop_pct"),
        },
        "top_attack_chains": chain_summaries,
        "break_chain_critical_findings": [
            {"finding_id": f.finding_id, "title": f.title,
             "asset": f.affected_asset_id, "cvss": f.cvss,
             "chains": f.chain_count, "controls": _controls_for(f)}
            for f in critical
        ],
        "compliance_note": (
            "Prioritization decisions in this brief are risk-based and "
            "auditable, supporting SEBI CSCRF vulnerability-management "
            "requirements, ISO 27001 Annex A.8.8, and RBI cyber-resilience "
            "expectations. Every ranking is traceable to the contributing "
            "findings, threat intelligence (EPSS/CISA KEV), and asset context."),
    }
