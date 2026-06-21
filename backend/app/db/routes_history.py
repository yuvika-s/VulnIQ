"""
Historical posture + trend + comparison + executive-reporting API.

All endpoints degrade gracefully when DATABASE_URL is unset (return enabled:false
+ empty data) so the dashboard works in JSON mode too.
"""
from __future__ import annotations

from fastapi import APIRouter, Query

from app.db.database import db_enabled
from app.db import repository as repo

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def history(limit: int = 100):
    """List historical runs (newest first)."""
    return {"enabled": db_enabled(), "runs": repo.list_runs(limit)}


@router.get("/trends")
def trends(limit: int = 50):
    """Trend series across runs (findings/chains/P1/risk/source/objective over time)."""
    return {"enabled": db_enabled(), **repo.trends(limit)}


@router.get("/compare")
def compare(from_run: int = Query(..., alias="from"), to_run: int = Query(..., alias="to")):
    """Compare two runs: new/resolved findings & chains, P1/risk/objective deltas."""
    if not db_enabled():
        return {"enabled": False}
    res = repo.compare_runs(from_run, to_run)
    if res is None:
        return {"enabled": True, "error": "run not found"}
    return {"enabled": True, **res}


@router.get("/executive")
def executive(from_run: int = Query(..., alias="from"), to_run: int = Query(..., alias="to")):
    """Board-level summary built from a run comparison."""
    if not db_enabled():
        return {"enabled": False}
    c = repo.compare_runs(from_run, to_run)
    if c is None:
        return {"enabled": True, "error": "run not found"}
    headline = [
        {"metric": "P1 Findings", "from": c["p1"]["from"], "to": c["p1"]["to"], "pct": c["p1"]["pct_change"]},
        {"metric": "Attack Chains", "from": c["chains"]["from"], "to": c["chains"]["to"], "pct": c["chains"]["pct_change"]},
        {"metric": "Risk Score", "from": c["risk"]["from"], "to": c["risk"]["to"], "pct": c["risk"]["pct_change"]},
    ]
    return {"enabled": True, "headline": headline,
            "most_improved_assets": c["most_improved_assets"],
            "most_regressed_assets": c["most_regressed_assets"],
            "top_new_attack_paths": c["chains"]["new_sample"][:10],
            "resolved_findings": c["findings"]["resolved"],
            "new_findings": c["findings"]["new"],
            "objective_delta": c["objective_delta"]}


@router.get("/ownership/breakdown")
def ownership_breakdown(run: int | None = None):
    """Per-engineering-head + per-business-unit posture (latest run unless `run`)."""
    return {"enabled": db_enabled(), **repo.owner_breakdown(run)}


@router.get("/ownership/trends")
def ownership_trends(limit: int = 50):
    """Risk / P1 / chains per engineering head across runs."""
    return {"enabled": db_enabled(), **repo.owner_trends(limit)}


@router.get("/{run_id}")
def run_snapshot(run_id: int):
    """Full snapshot of one run — same shape as /api/snapshot, so the dashboard
    loads a historical run with the complete experience."""
    if not db_enabled():
        return {"enabled": False}
    snap = repo.get_run_snapshot(run_id)
    if snap is None:
        return {"enabled": True, "error": "run not found"}
    # attach the (fairly static) asset inventory so chain cards can show names
    try:
        from app.engine import ENGINE
        snap["assets"] = [a.to_dict() for a in ENGINE.assets.values()]
    except Exception:
        snap["assets"] = []
    return snap
