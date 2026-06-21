"""
VulnIQ Knowledge Context Layer.

The copilot NEVER receives raw findings. It queries this layer, which:

  • BUILDS    a compact, grounded view of the live engine + persisted history
  • RETRIEVES the slices relevant to a question (findings / chains / ownership /
              history / trend / executive)
  • FILTERS   by owner, business unit, application/asset, source (Snyk/Tenable/
              manual), priority, objective, internet/KEV
  • RANKS     by the metrics that matter (final_score, chain_risk × confidence,
              remediation leverage)
  • INJECTS   an always-on posture summary into the system prompt so basic facts
              are never hallucinated

Every value here is read from ENGINE (live) or the persistence repository
(history) — so if a fact isn't present, the layer returns an explicit empty/None
signal and the copilot is instructed to say "no evidence" rather than invent.
"""
from __future__ import annotations

from app.engine import ENGINE

MISC = "Miscellaneous"
_SOURCE_KEYS = {"snyk", "tenable", "manual"}


# ── normalisation / scope matching ───────────────────────────────────────── #
def _low(s) -> str:
    return str(s or "").strip().lower()


def _system_of(f) -> str:
    st = _low(f.source_tool)
    if st.startswith("snyk"):
        return "snyk"
    if st.startswith("tenable"):
        return "tenable"
    return "manual"


def _asset_name(f) -> str:
    a = ENGINE.assets.get(f.affected_asset_id)
    return a.name if a else f.affected_asset_id


def scope_match(f, scope: str) -> bool:
    """Flexible owner/team/BU/application scope match — powers 'what should KYC
    fix', 'show only OMS findings', 'RMS team's P1s'. Matches the scope token
    against engineering head, business unit, asset id and application name."""
    if not scope:
        return True
    q = _low(scope)
    hay = " ".join(_low(x) for x in (
        getattr(f, "owner_head", ""), getattr(f, "business_unit", ""),
        f.affected_asset_id, _asset_name(f)))
    return q in hay


def _finding_brief(f) -> dict:
    return {
        "id": f.finding_id, "title": f.title, "type": f.finding_type,
        "priority": f.priority_p or (f.priority.value if f.priority else None),
        "cvss": f.cvss, "epss": round(f.epss, 3), "kev": f.in_kev,
        "source": (f.sources[0] if f.sources else f.source_tool),
        "asset": f.affected_asset_id, "application": _asset_name(f),
        "owner": getattr(f, "owner_head", MISC), "business_unit": getattr(f, "business_unit", MISC),
        "on_chains": f.chain_count, "chains_collapsed": f.chains_collapsed,
        "leverage": f.remediation_leverage, "leverage_label": f.remediation_leverage_label,
        "objectives": f.attack_objectives[:3],
        "internet": f.network_exposure.value == "internet",
        "remediation": f.remediation_action,
    }


def _chain_brief(c) -> dict:
    return {
        "id": c.chain_id, "risk": c.chain_risk, "confidence": c.chain_confidence,
        "speculative": c.speculative, "objective": c.primary_objective,
        "objective_reachability": c.objective_reachability_score,
        "crown_jewel": c.crown_jewel, "primary_owner": getattr(c, "primary_owner", MISC),
        "secondary_owners": getattr(c, "secondary_owners", []),
        "sources": c.products, "num_assets": c.num_assets,
        "path": c.finding_ids, "impact": (c.attack_path or {}).get("impact", ""),
    }


# ── always-on posture summary (injected into the system prompt) ──────────── #
def posture_summary() -> dict:
    s = ENGINE.stats()
    crown = [a.name for a in ENGINE.assets.values() if a.is_crown_jewel][:12]
    top_owners = dict(sorted(s.get("chains_by_owner", {}).items(), key=lambda x: -x[1])[:6])
    return {
        "total_findings": s["total_findings"], "total_chains": s["total_chains"],
        "org_risk_score": s["org_risk_score"], "crown_jewels": crown,
        "by_priority": s["by_priority"], "by_source": s.get("by_source", {}),
        "findings_by_owner": s.get("by_owner", {}),
        "findings_by_business_unit": s.get("by_business_unit", {}),
        "chains_by_owner": top_owners,
        "engine_empty": s["total_findings"] == 0,
    }


# ── RETRIEVE + FILTER + RANK ─────────────────────────────────────────────── #
def retrieve_findings(scope: str = "", source: str = "", priority: str = "",
                      objective: str = "", internet_only: bool = False,
                      kev_only: bool = False, on_chains_only: bool = False,
                      limit: int = 12) -> dict:
    """Ranked findings matching the filters (ranked by final_score)."""
    out = []
    for f in ENGINE.findings:
        if scope and not scope_match(f, scope):
            continue
        if source and source.lower() in _SOURCE_KEYS and _system_of(f) != source.lower():
            continue
        if priority and (f.priority_p or "").lower() != priority.lower() \
                and (f.priority.value if f.priority else "") != priority.lower():
            continue
        if objective and objective.lower() not in " ".join(_low(o) for o in f.attack_objectives):
            continue
        if internet_only and f.network_exposure.value != "internet":
            continue
        if kev_only and not f.in_kev:
            continue
        if on_chains_only and f.chain_count <= 0:
            continue
        out.append(f)
    out.sort(key=lambda x: -(x.final_score or 0))
    return {"count": len(out), "findings": [_finding_brief(f) for f in out[:limit]]}


def retrieve_chains(scope: str = "", source: str = "", objective: str = "",
                    crown_jewel: str = "", cross_source_only: bool = False,
                    include_speculative: bool = False, limit: int = 8) -> dict:
    """Ranked attack chains (by risk × confidence) matching the filters."""
    fmap = {f.finding_id: f for f in ENGINE.findings}
    out = []
    for c in ENGINE.chains:
        if not include_speculative and c.speculative:
            continue
        if crown_jewel and crown_jewel.lower() not in _low(c.crown_jewel):
            continue
        if objective and objective.lower() not in _low(c.primary_objective):
            continue
        if source and source.lower() in _SOURCE_KEYS \
                and not any(_system_of(fmap[p]) == source.lower() for p in c.finding_ids if p in fmap):
            continue
        if cross_source_only:
            systems = {_system_of(fmap[p]) for p in c.finding_ids if p in fmap}
            if len(systems) < 2:
                continue
        if scope:
            owners = [getattr(c, "primary_owner", "")] + list(getattr(c, "secondary_owners", []))
            apps = [_asset_name(fmap[p]) for p in c.finding_ids if p in fmap]
            hay = " ".join(_low(x) for x in owners + apps + [c.crown_jewel])
            if _low(scope) not in hay:
                continue
        out.append(c)
    out.sort(key=lambda c: -c.chain_risk * (0.3 + 0.7 * c.chain_confidence / 100.0))
    return {"count": len(out), "chains": [_chain_brief(c) for c in out[:limit]]}


def owner_view(scope: str, limit: int = 8) -> dict:
    """Owner/team/BU-scoped posture: their findings, P1s, chains, leverage fixes."""
    fs = [f for f in ENGINE.findings if scope_match(f, scope)]
    if not fs:
        return {"scope": scope, "found": False,
                "note": f"No findings map to '{scope}'. Check the owner/team/application name."}
    p1 = [f for f in fs if f.priority_p == "P1"]
    on_chain = [f for f in fs if f.chain_count > 0]
    lev = sorted(fs, key=lambda x: -(x.remediation_leverage or 0))[:limit]
    ch = retrieve_chains(scope=scope, limit=limit)
    return {
        "scope": scope, "found": True,
        "total_findings": len(fs), "p1": len(p1),
        "findings_on_chains": len(on_chain),
        "business_units": sorted({getattr(f, "business_unit", MISC) for f in fs}),
        "owners": sorted({getattr(f, "owner_head", MISC) for f in fs}),
        "top_p1": [_finding_brief(f) for f in sorted(p1, key=lambda x: -x.final_score)[:limit]],
        "highest_leverage_fixes": [_finding_brief(f) for f in lev],
        "chains": ch["chains"],
    }


def leverage_ranking(scope: str = "", n: int = 10) -> dict:
    """Top remediation-leverage fixes (the smallest set of fixes removing the most
    realistic, well-evidenced risk). Optionally scoped to an owner/team/app."""
    fs = [f for f in ENGINE.findings
          if f.chain_count > 0 and (not scope or scope_match(f, scope))]
    fs.sort(key=lambda x: (-(x.remediation_leverage or 0), -(x.chains_collapsed or 0)))
    return {"count": len(fs),
            "fixes": [dict(_finding_brief(f), rank=i + 1) for i, f in enumerate(fs[:n])]}


def fix_impact(finding_id: str) -> dict:
    """What collapses if a finding is fixed (no graph rebuild — chains that
    literally contain it). Mirrors the dashboard modal."""
    f = ENGINE.finding(finding_id)
    if not f:
        return {"found": False, "note": f"No finding {finding_id}."}
    chains = ENGINE.chains
    before = round(sum(c.chain_risk for c in chains), 1)
    surviving = [c for c in chains if finding_id not in c.finding_ids]
    after = round(sum(c.chain_risk for c in surviving), 1)
    collapsed = [c.chain_id for c in chains if finding_id in c.finding_ids]
    return {
        "found": True, "finding_id": finding_id, "title": f.title,
        "owner": getattr(f, "owner_head", MISC), "application": _asset_name(f),
        "chains_collapsed": len(collapsed), "chains_before": len(chains),
        "collapsed_chain_ids": collapsed[:25],
        "org_risk_before": before, "org_risk_after": after,
        "risk_drop_pct": round((before - after) / before * 100, 1) if before else 0,
    }


def reduce_risk_plan(target_pct: float = 50.0, scope: str = "") -> dict:
    """Greedy minimal set of fixes (by leverage) to cut org chain-risk by
    target_pct. Answers 'shortest path to reduce risk by 50%'."""
    chains = list(ENGINE.chains)
    total = round(sum(c.chain_risk for c in chains), 1)
    if not total:
        return {"note": "No active chains — no risk to reduce.", "fixes": []}
    cands = [f for f in ENGINE.findings
             if f.chain_count > 0 and (not scope or scope_match(f, scope))]
    cands.sort(key=lambda x: -(x.remediation_leverage or 0))
    remaining = {c.chain_id: c for c in chains}
    picked, removed_risk = [], 0.0
    for f in cands:
        gone = [cid for cid, c in remaining.items() if f.finding_id in c.finding_ids]
        if not gone:
            continue
        removed_risk += sum(remaining[cid].chain_risk for cid in gone)
        for cid in gone:
            remaining.pop(cid, None)
        picked.append(dict(_finding_brief(f), chains_removed=len(gone)))
        if removed_risk / total * 100 >= target_pct:
            break
    return {
        "target_pct": target_pct, "org_risk": total,
        "achieved_pct": round(removed_risk / total * 100, 1),
        "num_fixes": len(picked), "fixes": picked,
    }


def objective_view(objective: str, limit: int = 10) -> dict:
    """Findings + chains that advance a specific attacker objective
    (e.g. 'unauthorized_trading', 'crown jewel')."""
    ch = retrieve_chains(objective=objective, limit=limit)
    f = retrieve_findings(objective=objective, limit=limit)
    return {"objective": objective, "chains": ch["chains"], "findings": f["findings"],
            "chain_count": ch["count"], "finding_count": f["count"]}


# ── HISTORY / TREND / COMPARE / EXECUTIVE context ────────────────────────── #
def historical_context() -> dict:
    """Trend series + latest-vs-previous compare (incl. owner deltas). Returns an
    explicit 'no history' signal when persistence is off or <2 runs exist."""
    try:
        from app.db.database import db_enabled
        from app.db import repository as repo
    except Exception:
        return {"available": False, "note": "Persistence layer unavailable."}
    if not db_enabled():
        return {"available": False, "note": "Persistence is off (no DATABASE_URL) — no history/trends."}
    runs = repo.list_runs(50)
    if len(runs) < 2:
        return {"available": False, "note": "Fewer than two persisted runs — no comparison yet.",
                "runs": runs}
    latest, prev = runs[0]["run_id"], runs[1]["run_id"]
    cmp = repo.compare_runs(prev, latest) or {}
    return {
        "available": True,
        "runs": runs[:8],
        "trend": repo.trends(12).get("runs", []),
        "compare": {
            "from_run": prev, "to_run": latest,
            "new_findings": cmp.get("findings", {}).get("new"),
            "resolved_findings": cmp.get("findings", {}).get("resolved"),
            "p1": cmp.get("p1"), "chains": {k: cmp.get("chains", {}).get(k)
                                            for k in ("from", "to", "new", "removed")},
            "risk": cmp.get("risk"),
            "owner_risk_reduction": cmp.get("owner_risk_reduction", []),
            "owner_new_p1": cmp.get("owner_new_p1", []),
            "most_regressed_assets": cmp.get("most_regressed_assets", []),
            "new_attack_paths": cmp.get("chains", {}).get("new_sample", [])[:6],
        },
    }


def ownership_context() -> dict:
    """Per-head + per-BU breakdown from the latest persisted run (falls back to
    the live engine if persistence is off)."""
    try:
        from app.db.database import db_enabled
        from app.db import repository as repo
        if db_enabled():
            ob = repo.owner_breakdown(None)
            if ob.get("owners"):
                return {"source": "persisted", **ob}
    except Exception:
        pass
    # live fallback
    s = ENGINE.stats()
    by_owner = s.get("by_owner", {})
    cbo = s.get("chains_by_owner", {})
    owners = sorted(({"owner": o, "findings": by_owner[o], "chains": cbo.get(o, 0)}
                     for o in by_owner), key=lambda x: (-x["chains"], -x["findings"]))
    return {"source": "live", "owners": owners,
            "business_units": s.get("by_business_unit", {})}


def owner_dashboard() -> dict:
    """Full live ownership table (per engineering head + per business unit) for
    the Engineering Ownership dashboard. Computed from the live engine so it
    reflects the current session; reconciles exactly with global totals."""
    from collections import Counter, defaultdict
    F, CH = ENGINE.findings, ENGINE.chains
    fbo = Counter(getattr(f, "owner_head", MISC) or MISC for f in F)
    p1 = Counter((getattr(f, "owner_head", MISC) or MISC) for f in F if f.priority_p == "P1")
    p2 = Counter((getattr(f, "owner_head", MISC) or MISC) for f in F if f.priority_p == "P2")
    cbo = Counter(getattr(c, "primary_owner", MISC) or MISC for c in CH)
    risk = defaultdict(float)
    crown = Counter()
    for c in CH:
        o = getattr(c, "primary_owner", MISC) or MISC
        risk[o] += c.chain_risk
        if (c.objective_reachability_score or 0) >= 40 and not c.speculative:
            crown[o] += 1
    owner_bu = {(getattr(f, "owner_head", MISC) or MISC): (getattr(f, "business_unit", MISC) or MISC) for f in F}
    heads = sorted(
        ({"owner": o, "findings": fbo[o], "p1": p1.get(o, 0), "p2": p2.get(o, 0),
          "chains": cbo.get(o, 0), "risk": round(risk.get(o, 0), 1),
          "crown_exposure": crown.get(o, 0), "business_unit": owner_bu.get(o, MISC)}
         for o in fbo), key=lambda x: (-x["risk"], -x["chains"], -x["findings"]))
    fbb = Counter(getattr(f, "business_unit", MISC) or MISC for f in F)
    risk_bu = defaultdict(float)
    chains_bu = Counter()
    for c in CH:
        bu = owner_bu.get(getattr(c, "primary_owner", MISC) or MISC, MISC)
        risk_bu[bu] += c.chain_risk
        chains_bu[bu] += 1
    bus = sorted(
        ({"business_unit": b, "findings": fbb[b], "chains": chains_bu.get(b, 0),
          "risk": round(risk_bu.get(b, 0), 1)} for b in fbb),
        key=lambda x: (-x["risk"], -x["findings"]))
    return {
        "heads": heads, "business_units": bus,
        "totals": {"findings": len(F), "chains": len(CH),
                   "p1": sum(p1.values()), "p2": sum(p2.values()),
                   "risk": round(sum(c.chain_risk for c in CH), 1)},
        "reconciles": sum(fbo.values()) == len(F) and sum(cbo.values()) == len(CH),
    }
