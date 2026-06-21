"""
Repository layer — the ONLY module that reads/writes persistence.

Responsibilities:
  - snapshot the live engine into a ScanRun (+ findings/chains/graph/metrics)
  - serve historical runs in the same shape as /api/snapshot (so the UI loads a
    past run identically to a fresh one)
  - compare two runs (new/resolved findings & chains, deltas)
  - produce trend series for executive/board reporting

Trend accuracy: findings are identified by a CONTENT fingerprint (asset + type +
cwe + cve + title + component), chains by a signature (objective + member
fingerprints). Re-running an identical scan therefore produces identical
fingerprints → zero new/resolved → no false trend movement.
"""
from __future__ import annotations

import hashlib
import logging
from collections import Counter

from app.db.database import db_enabled, session_scope
from app.db.orm import ScanRun, FindingRow, ChainRow, GraphSnapshot, SeedMeta

log = logging.getLogger("vulniq.db")


# ── fingerprints ─────────────────────────────────────────────────────────── #
def _sha(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:16]


def finding_fingerprint(d: dict) -> str:
    """Stable identity for a finding ACROSS runs (ignores volatile run-local ids
    and recomputed scores)."""
    key = "|".join(str(d.get(k, "")).strip().lower() for k in
                   ("affected_asset_id", "finding_type", "cwe", "cve", "title", "component"))
    return _sha(key)


def chain_signature(d: dict, fp_by_fid: dict) -> str:
    members = sorted(fp_by_fid.get(fid, fid) for fid in d.get("finding_ids", []))
    return _sha((d.get("primary_objective", "") or "") + "::" + ",".join(members))


# ── snapshot a run ───────────────────────────────────────────────────────── #
def _exposure_scores(findings: list[dict], assets: dict) -> tuple[float, float]:
    crown = internet = 0.0
    for f in findings:
        a = assets.get(f.get("affected_asset_id"))
        if not a:
            continue
        w = 3.0 if str(f.get("priority_p")) in ("P1", "P2") else 1.0
        if getattr(a, "is_crown_jewel", False):
            crown += w
        if getattr(a, "internet_facing", False):
            internet += w
    return round(crown, 1), round(internet, 1)


def _build_metrics(findings: list[dict], chains: list[dict], stats: dict) -> dict:
    by_sev = Counter(f.get("raw_severity", "") or "unknown" for f in findings)
    by_source = stats.get("by_source", {})
    by_asset = Counter(f.get("affected_asset_id", "") for f in findings)
    by_priority = Counter(str(f.get("priority_p")) for f in findings)
    by_objective = Counter(c.get("primary_objective", "") or "none" for c in chains)
    conf_buckets = Counter()
    for c in chains:
        cf = c.get("chain_confidence", 0) or 0
        conf_buckets["high(>=65)" if cf >= 65 else "med(50-65)" if cf >= 50 else "low(<50)"] += 1
    lev_buckets = Counter(f.get("remediation_leverage_label", "None") or "None" for f in findings)

    # ── ownership aggregates (per engineering head + per business unit) ─────── #
    MISC = "Miscellaneous"
    findings_by_owner = Counter((f.get("owner_head") or MISC) for f in findings)
    findings_by_bu = Counter((f.get("business_unit") or MISC) for f in findings)
    p1_by_owner = Counter((f.get("owner_head") or MISC)
                          for f in findings if str(f.get("priority_p")) == "P1")
    p2_by_owner = Counter((f.get("owner_head") or MISC)
                          for f in findings if str(f.get("priority_p")) == "P2")
    chains_by_owner = Counter((c.get("primary_owner") or MISC) for c in chains)
    chains_by_bu = Counter()
    risk_by_owner: dict = {}
    risk_by_bu: dict = {}
    owner_bu = {(f.get("owner_head") or MISC): (f.get("business_unit") or MISC) for f in findings}
    for c in chains:
        o = c.get("primary_owner") or MISC
        risk_by_owner[o] = round(risk_by_owner.get(o, 0.0) + (c.get("chain_risk") or 0), 1)
        bu = owner_bu.get(o, MISC)
        chains_by_bu[bu] += 1
        risk_by_bu[bu] = round(risk_by_bu.get(bu, 0.0) + (c.get("chain_risk") or 0), 1)
    # crown-jewel exposure per owner: chains whose objective actually reaches a
    # crown jewel (reachability >= 40, non-speculative), credited to the owner.
    crown_by_owner = Counter()
    for c in chains:
        if (c.get("objective_reachability_score") or 0) >= 40 and not c.get("speculative"):
            crown_by_owner[c.get("primary_owner") or MISC] += 1

    return {
        "findings_by_severity": dict(by_sev),
        "findings_by_source": dict(by_source),
        "findings_by_asset": dict(by_asset.most_common(25)),
        "findings_by_priority": dict(by_priority),
        "chains_by_objective": dict(by_objective),
        "chain_confidence_distribution": dict(conf_buckets),
        "remediation_leverage_distribution": dict(lev_buckets),
        # ownership — first-class, persisted with every run for trend/compare
        "findings_by_owner": dict(findings_by_owner),
        "findings_by_business_unit": dict(findings_by_bu),
        "p1_by_owner": dict(p1_by_owner),
        "p2_by_owner": dict(p2_by_owner),
        "chains_by_owner": dict(chains_by_owner),
        "chains_by_business_unit": dict(chains_by_bu),
        "risk_by_owner": risk_by_owner,
        "risk_by_business_unit": risk_by_bu,
        "crown_exposure_by_owner": dict(crown_by_owner),
        "total_findings": len(findings),
        "total_chains": len(chains),
        "risk_score": stats.get("org_risk_score", 0),
    }


def persist_run(source: str, run_type: str, sync_metadata: dict | None = None,
                notes: str = "") -> dict | None:
    """Snapshot the live ENGINE into a new ScanRun. No-op when DB disabled."""
    if not db_enabled():
        return None
    try:
        from app.engine import ENGINE
        findings = [f.to_dict() for f in ENGINE.findings]
        chains = [c.to_dict() for c in ENGINE.chains]
        stats = ENGINE.stats()
        assets = ENGINE.assets

        fp_by_fid = {f.get("finding_id"): finding_fingerprint(f) for f in findings}
        run_fps = sorted(set(fp_by_fid.values()))
        chain_sigs = sorted(chain_signature(c, fp_by_fid) for c in chains)
        run_fp = _sha(",".join(run_fps) + "||" + ",".join(chain_sigs))

        pcount = Counter(str(f.get("priority_p")) for f in findings)
        crown_exp, inet_exp = _exposure_scores(findings, assets)
        metrics = _build_metrics(findings, chains, stats)
        metrics["crown_exposure_score"] = crown_exp
        metrics["internet_exposure_score"] = inet_exp

        graph_payload = _graph_snapshot(chains, findings, assets)

        with session_scope() as s:
            run = ScanRun(
                source=source, run_type=run_type, fingerprint=run_fp,
                findings_count=len(findings), chains_count=len(chains),
                p1_count=pcount.get("P1", 0), p2_count=pcount.get("P2", 0),
                p3_count=pcount.get("P3", 0), p4_count=pcount.get("P4", 0),
                p5_count=pcount.get("P5", 0),
                risk_score=float(stats.get("org_risk_score", 0) or 0),
                crown_exposure=crown_exp, internet_exposure=inet_exp,
                sync_metadata=sync_metadata or {}, metrics=metrics, notes=notes,
            )
            s.add(run)
            s.flush()                      # assign run.id
            for f in findings:
                s.add(FindingRow(
                    run_id=run.id, finding_id=f.get("finding_id", ""),
                    fingerprint=fp_by_fid.get(f.get("finding_id"), ""),
                    title=(f.get("title") or "")[:255], asset=f.get("affected_asset_id", ""),
                    finding_type=f.get("finding_type", ""), severity=f.get("raw_severity", ""),
                    cwe=f.get("cwe") or "", cve=f.get("cve") or "",
                    cvss=float(f.get("cvss") or 0), epss=float(f.get("epss") or 0),
                    in_kev=bool(f.get("in_kev")), priority=f.get("priority") or "",
                    priority_p=f.get("priority_p") or "", chain_count=int(f.get("chain_count") or 0),
                    remediation_leverage=float(f.get("remediation_leverage") or 0),
                    owner_head=(f.get("owner_head") or "Miscellaneous"),
                    business_unit=(f.get("business_unit") or "Miscellaneous"),
                    sources=f.get("sources") or [], grants=f.get("grants") or [], data=f))
            for c in chains:
                s.add(ChainRow(
                    run_id=run.id, chain_id=c.get("chain_id", ""),
                    signature=chain_signature(c, fp_by_fid),
                    objective=c.get("primary_objective") or "", confidence=float(c.get("chain_confidence") or 0),
                    chain_risk=float(c.get("chain_risk") or 0), num_products=int(c.get("num_products") or 0),
                    num_assets=int(c.get("num_assets") or 0), speculative=bool(c.get("speculative")),
                    crown_jewel=c.get("crown_jewel", ""),
                    primary_owner=(c.get("primary_owner") or "Miscellaneous"),
                    secondary_owners=c.get("secondary_owners") or [],
                    products=c.get("products") or [],
                    finding_ids=c.get("finding_ids") or [], data=c))
            s.add(GraphSnapshot(run_id=run.id, nodes=graph_payload["nodes"],
                                edges=graph_payload["edges"]))
            rid = run.id
        log.info("db: persisted run #%d (%s, %d findings, %d chains, fp=%s)",
                 rid, source, len(findings), len(chains), run_fp)
        return {"run_id": rid, "fingerprint": run_fp}
    except Exception:
        log.exception("db: persist_run failed (engine state preserved)")
        return None


def _graph_snapshot(chains: list[dict], findings: list[dict], assets: dict) -> dict:
    """Compact node/edge snapshot built from the chains (so a run's graph can be
    redrawn historically without rebuilding)."""
    fmap = {f.get("finding_id"): f for f in findings}
    node_ids, nodes, edges, seen = set(), [], [], set()
    for c in chains[:60]:
        fids = c.get("finding_ids", [])
        for fid in fids:
            f = fmap.get(fid)
            if fid not in node_ids and f:
                node_ids.add(fid)
                nodes.append({"id": fid, "kind": "finding", "label": f.get("title", ""),
                              "asset": f.get("affected_asset_id"), "product": (f.get("sources") or ["?"])[0],
                              "priority": f.get("priority_p")})
            if fid not in node_ids and not f:
                node_ids.add(fid)
        cj = c.get("crown_jewel")
        if cj and cj not in node_ids:
            node_ids.add(cj)
            a = assets.get(cj)
            nodes.append({"id": cj, "kind": "crown_jewel",
                          "label": getattr(a, "name", cj) if a else cj})
        for u, v in zip(fids, fids[1:]):
            if (u, v) not in seen:
                seen.add((u, v)); edges.append({"source": u, "target": v, "kind": "ENABLES"})
        if fids and cj:
            edges.append({"source": fids[-1], "target": cj, "kind": "REACHES"})
    return {"nodes": nodes, "edges": edges}


# ── queries ──────────────────────────────────────────────────────────────── #
def list_runs(limit: int = 100) -> list[dict]:
    if not db_enabled():
        return []
    with session_scope() as s:
        rows = s.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(limit).all()
        return [_run_summary(r) for r in rows]


def _run_summary(r: ScanRun) -> dict:
    return {"run_id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None,
            "source": r.source, "run_type": r.run_type, "fingerprint": r.fingerprint,
            "findings_count": r.findings_count, "chains_count": r.chains_count,
            "p1_count": r.p1_count, "p2_count": r.p2_count, "p3_count": r.p3_count,
            "p4_count": r.p4_count, "p5_count": r.p5_count, "risk_score": r.risk_score,
            "crown_exposure": r.crown_exposure, "internet_exposure": r.internet_exposure,
            "notes": r.notes}


def get_run_snapshot(run_id: int) -> dict | None:
    """Return a run in the SAME shape as /api/snapshot so the dashboard can load
    a historical run with the full experience."""
    if not db_enabled():
        return None
    with session_scope() as s:
        r = s.get(ScanRun, run_id)
        if not r:
            return None
        findings = [fr.data for fr in r.findings]
        chains = [cr.data for cr in r.chains]
        g = r.graph
        return {
            "run": _run_summary(r),
            "historical": True,
            "stats": _stats_for_snapshot(r, findings, chains),
            "findings": findings,
            "chains": chains,
            "graph": {"nodes": g.nodes if g else [], "edges": g.edges if g else []},
            "brief": _brief_for_snapshot(r, findings, chains),
        }


def _stats_for_snapshot(r, findings: list[dict], chains: list[dict]) -> dict:
    """Rebuild the SAME stats shape the live /api/snapshot returns, from stored
    findings/chains, so the dashboard renders a historical run without errors."""
    by_layer = Counter(f.get("layer", "") for f in findings)
    by_tool = Counter(f.get("source_tool", "") for f in findings)
    by_priority = Counter(f.get("priority") for f in findings if f.get("priority"))
    m = r.metrics or {}
    return {
        "total_findings": r.findings_count, "total_chains": r.chains_count,
        "total_assets": len(by_tool) and len({f.get("affected_asset_id") for f in findings}),
        "crown_jewels": 0, "correlation_clusters": 0,
        "by_layer": dict(by_layer), "by_tool": dict(by_tool),
        "by_priority": dict(by_priority),
        "by_source": m.get("findings_by_source", {}),
        "org_risk_score": r.risk_score,
        "top_chain_risk": max((c.get("chain_risk", 0) for c in chains), default=0),
    }


def _brief_for_snapshot(r, findings: list[dict], chains: list[dict]) -> dict:
    """Minimal but COMPLETE brief (all fields the dashboard reads) for a run."""
    total = r.findings_count or 1
    deferred = sum(1 for f in findings if f.get("priority") == "defer")
    crit = [f for f in findings if f.get("priority") == "break_chain_critical"]
    return {
        "title": "VulnIQ Security Brief",
        "subtitle": f"Historical run #{r.id} · {r.source}",
        "generated_for": r.created_at.isoformat() if r.created_at else "",
        "headline": {
            "org_risk_score": r.risk_score,
            "noise_reduction_pct": round(100 * deferred / total, 1),
            "total_findings": r.findings_count, "total_chains": r.chains_count,
        },
        "recommended_first_action": "",
        "top_attack_chains": [
            {"chain_id": c.get("chain_id"), "chain_risk": c.get("chain_risk"),
             "crown_jewel": c.get("crown_jewel"), "narrative": (c.get("attack_path") or {}).get("impact", "")}
            for c in sorted(chains, key=lambda x: -(x.get("chain_risk") or 0))[:5]],
        "break_chain_critical_findings": [
            {"finding_id": f.get("finding_id"), "title": f.get("title"),
             "affected_asset_id": f.get("affected_asset_id")} for f in crit[:8]],
        "compliance_note": "Historical snapshot — mapped to SEBI CSCRF / ISO 27001 / RBI.",
    }


# ── comparison ───────────────────────────────────────────────────────────── #
def _fps(s, run_id):
    rows = s.query(FindingRow).filter(FindingRow.run_id == run_id).all()
    return {fr.fingerprint: fr for fr in rows}


def compare_runs(from_id: int, to_id: int) -> dict | None:
    if not db_enabled():
        return None
    with session_scope() as s:
        a = s.get(ScanRun, from_id)
        b = s.get(ScanRun, to_id)
        if not a or not b:
            return None
        fa, fb = _fps(s, from_id), _fps(s, to_id)
        new_fps = set(fb) - set(fa)
        resolved_fps = set(fa) - set(fb)
        p1_a = {fp for fp, r in fa.items() if r.priority_p == "P1"}
        p1_b = {fp for fp, r in fb.items() if r.priority_p == "P1"}
        ca = {c.signature for c in s.query(ChainRow).filter(ChainRow.run_id == from_id).all()}
        cb_rows = s.query(ChainRow).filter(ChainRow.run_id == to_id).all()
        cb = {c.signature for c in cb_rows}
        new_chain_sigs, removed_chain_sigs = cb - ca, ca - cb

        # per-asset delta (findings count)
        asset_a = Counter(r.asset for r in fa.values())
        asset_b = Counter(r.asset for r in fb.values())
        all_assets = set(asset_a) | set(asset_b)
        asset_delta = sorted(((aid, asset_b[aid] - asset_a[aid]) for aid in all_assets),
                             key=lambda x: x[1])
        # objective delta
        obj_a = Counter(c.objective for c in s.query(ChainRow).filter(ChainRow.run_id == from_id).all())
        obj_b = Counter(c.objective for c in cb_rows)

        def _pct(old, new):
            return round((new - old) / old * 100, 1) if old else (100.0 if new else 0.0)

        def _sample(rows_by_fp, fps, n=20):
            return [{"finding_id": rows_by_fp[fp].finding_id, "title": rows_by_fp[fp].title,
                     "asset": rows_by_fp[fp].asset, "priority": rows_by_fp[fp].priority_p}
                    for fp in list(fps)[:n]]

        new_chains_sample = [{"chain_id": c.chain_id, "objective": c.objective,
                              "confidence": c.confidence, "products": c.products}
                             for c in cb_rows if c.signature in new_chain_sigs][:20]

        # ── ownership deltas (answers the leadership questions) ─────────────── #
        ma, mb = (a.metrics or {}), (b.metrics or {})
        risk_a, risk_b = ma.get("risk_by_owner", {}), mb.get("risk_by_owner", {})
        p1o_a, p1o_b = ma.get("p1_by_owner", {}), mb.get("p1_by_owner", {})
        owners = set(risk_a) | set(risk_b) | set(p1o_a) | set(p1o_b)
        # positive risk_reduction = risk went DOWN for that owner
        risk_reduction = sorted(
            ({"owner": o, "from": round(risk_a.get(o, 0), 1), "to": round(risk_b.get(o, 0), 1),
              "reduction": round(risk_a.get(o, 0) - risk_b.get(o, 0), 1)} for o in owners),
            key=lambda x: -x["reduction"])
        new_p1_by_owner = sorted(
            ({"owner": o, "new_p1": p1o_b.get(o, 0) - p1o_a.get(o, 0)} for o in owners),
            key=lambda x: -x["new_p1"])

        return {
            "from": _run_summary(a), "to": _run_summary(b),
            "findings": {"new": len(new_fps), "resolved": len(resolved_fps),
                         "new_sample": _sample(fb, new_fps), "resolved_sample": _sample(fa, resolved_fps)},
            "p1": {"from": len(p1_a), "to": len(p1_b), "new": len(p1_b - p1_a),
                   "resolved": len(p1_a - p1_b), "pct_change": _pct(len(p1_a), len(p1_b))},
            "chains": {"from": len(ca), "to": len(cb), "new": len(new_chain_sigs),
                       "removed": len(removed_chain_sigs), "pct_change": _pct(len(ca), len(cb)),
                       "new_sample": new_chains_sample},
            "risk": {"from": a.risk_score, "to": b.risk_score,
                     "delta": round(b.risk_score - a.risk_score, 1),
                     "pct_change": _pct(a.risk_score, b.risk_score)},
            "objective_delta": {k: obj_b.get(k, 0) - obj_a.get(k, 0)
                                for k in set(obj_a) | set(obj_b) if k},
            "most_improved_assets": [{"asset": a_, "delta": d} for a_, d in asset_delta[:5] if d < 0],
            "most_regressed_assets": [{"asset": a_, "delta": d} for a_, d in reversed(asset_delta[-5:]) if d > 0],
            # ownership: who reduced the most risk, who introduced the most P1s
            "owner_risk_reduction": [x for x in risk_reduction if x["reduction"] != 0][:10],
            "owner_new_p1": [x for x in new_p1_by_owner if x["new_p1"] != 0][:10],
        }


# ── trends ───────────────────────────────────────────────────────────────── #
def trends(limit: int = 50) -> dict:
    if not db_enabled():
        return {"runs": []}
    with session_scope() as s:
        rows = s.query(ScanRun).order_by(ScanRun.created_at.asc()).limit(limit).all()
        series = [{"run_id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None,
                   "source": r.source, "findings": r.findings_count, "chains": r.chains_count,
                   "p1": r.p1_count, "risk": r.risk_score, "crown_exposure": r.crown_exposure,
                   "internet_exposure": r.internet_exposure,
                   "by_source": (r.metrics or {}).get("findings_by_source", {}),
                   "by_objective": (r.metrics or {}).get("chains_by_objective", {}),
                   "risk_by_owner": (r.metrics or {}).get("risk_by_owner", {}),
                   "p1_by_owner": (r.metrics or {}).get("p1_by_owner", {})}
                  for r in rows]
        return {"runs": series}


# ── ownership analytics (queryable + reportable) ─────────────────────────────#
def owner_breakdown(run_id: int | None = None) -> dict:
    """Per-engineering-head + per-business-unit posture for a run (latest if
    run_id is None). Sourced from the run's persisted ownership metrics — so it is
    historically accurate, not recomputed from the live engine."""
    if not db_enabled():
        return {"enabled": False, "owners": [], "business_units": []}
    with session_scope() as s:
        r = (s.get(ScanRun, run_id) if run_id else
             s.query(ScanRun).order_by(ScanRun.created_at.desc()).first())
        if not r:
            return {"enabled": True, "owners": [], "business_units": []}
        m = r.metrics or {}
        fbo, p1o, p2o = m.get("findings_by_owner", {}), m.get("p1_by_owner", {}), m.get("p2_by_owner", {})
        cbo, rbo, ceo = m.get("chains_by_owner", {}), m.get("risk_by_owner", {}), m.get("crown_exposure_by_owner", {})
        owners = sorted(
            ({"owner": o, "findings": fbo.get(o, 0), "p1": p1o.get(o, 0), "p2": p2o.get(o, 0),
              "chains": cbo.get(o, 0), "risk": round(rbo.get(o, 0), 1),
              "crown_exposure": ceo.get(o, 0)} for o in set(fbo) | set(cbo)),
            key=lambda x: (-x["risk"], -x["chains"], -x["p1"], -x["findings"]))
        fbb = m.get("findings_by_business_unit", {})
        rbb, cbb = m.get("risk_by_business_unit", {}), m.get("chains_by_business_unit", {})
        bus = sorted(
            ({"business_unit": b, "findings": fbb.get(b, 0), "chains": cbb.get(b, 0),
              "risk": round(rbb.get(b, 0), 1)} for b in set(fbb) | set(cbb)),
            key=lambda x: (-x["risk"], -x["findings"]))
        return {"enabled": True, "run_id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "owners": owners, "business_units": bus,
                "totals": {"findings": r.findings_count, "chains": r.chains_count,
                           "p1": r.p1_count, "risk": r.risk_score}}


def owner_trends(limit: int = 50) -> dict:
    """Risk / P1 per engineering head across runs — for owner trend charts and
    'which head reduced the most risk this month' style questions."""
    if not db_enabled():
        return {"runs": []}
    with session_scope() as s:
        rows = s.query(ScanRun).order_by(ScanRun.created_at.asc()).limit(limit).all()
        return {"runs": [{"run_id": r.id,
                          "created_at": r.created_at.isoformat() if r.created_at else None,
                          "risk_by_owner": (r.metrics or {}).get("risk_by_owner", {}),
                          "p1_by_owner": (r.metrics or {}).get("p1_by_owner", {}),
                          "chains_by_owner": (r.metrics or {}).get("chains_by_owner", {})}
                         for r in rows]}


# ── seed bookkeeping ─────────────────────────────────────────────────────── #
def is_seeded() -> bool:
    if not db_enabled():
        return False
    with session_scope() as s:
        return s.get(SeedMeta, "seeded") is not None


def mark_seeded():
    with session_scope() as s:
        if not s.get(SeedMeta, "seeded"):
            s.add(SeedMeta(key="seeded", value="1"))


def has_runs() -> bool:
    if not db_enabled():
        return False
    with session_scope() as s:
        return s.query(ScanRun.id).first() is not None
