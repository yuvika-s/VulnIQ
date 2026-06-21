"""
Tenable sync endpoints (mirror routes_snyk.py).

  POST /api/sync/tenable          trigger a sync (background)
  GET  /api/sync/tenable/status   sync metadata (status, counts, duration, errors)

Wired into main.py via: app.include_router(tenable_router)
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter
from pydantic import BaseModel

from app.ingestion.tenable_sync import run_tenable_sync, get_sync_status
from app.ai_config import tenable_configured, TENABLE_SEVERITY, TENABLE_MAX_FINDINGS

router = APIRouter(prefix="/api/sync/tenable", tags=["tenable"])


class SyncRequest(BaseModel):
    max_findings: int | None = None
    severity: str | None = None


@router.post("")
async def trigger_sync(body: SyncRequest | None = None):
    """Kick off a Tenable sync in the background; returns immediately."""
    if not tenable_configured():
        return {"triggered": False,
                "message": ("Tenable not configured — set TENABLE_BASE_URL, "
                            "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in backend/.env"),
                "sync_status": get_sync_status()}
    cur = get_sync_status()
    if cur["sync_status"] == "running":
        return {"triggered": False, "message": "A sync is already running",
                "sync_status": cur}
    cap = (body.max_findings if body else None) or TENABLE_MAX_FINDINGS
    sev = (body.severity if body else None) or TENABLE_SEVERITY
    asyncio.create_task(run_tenable_sync(cap, sev))
    return {"triggered": True,
            "message": f"Tenable sync started (severity={sev}, up to {cap} findings)",
            "sync_status": get_sync_status()}


@router.get("/status")
async def sync_status():
    return get_sync_status()
