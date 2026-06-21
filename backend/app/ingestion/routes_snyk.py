"""
Snyk sync endpoints.

  POST /api/sync/snyk          trigger a sync (background) for the last N days
  GET  /api/sync/snyk/status   sync metadata (status, counts, duration, errors)

Wired into main.py via: app.include_router(snyk_router)
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter
from pydantic import BaseModel

from app.ingestion.snyk_sync import run_snyk_sync, get_sync_status
from app.ai_config import snyk_configured, SNYK_LOOKBACK_DAYS

router = APIRouter(prefix="/api/sync/snyk", tags=["snyk"])


class SyncRequest(BaseModel):
    lookback_days: int | None = None


@router.post("")
async def trigger_sync(body: SyncRequest | None = None):
    """Kick off a Snyk sync in the background; returns immediately."""
    if not snyk_configured():
        return {"triggered": False,
                "message": "Snyk not configured — set SNYK_API_TOKEN and SNYK_ORG_ID in backend/.env",
                "sync_status": get_sync_status()}
    cur = get_sync_status()
    if cur["sync_status"] == "running":
        return {"triggered": False, "message": "A sync is already running",
                "sync_status": cur}
    lookback = (body.lookback_days if body else None) or SNYK_LOOKBACK_DAYS
    asyncio.create_task(run_snyk_sync(lookback))
    return {"triggered": True,
            "message": f"Snyk sync started (last {lookback} days)",
            "sync_status": get_sync_status()}


@router.get("/status")
async def sync_status():
    return get_sync_status()
