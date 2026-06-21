"""
Snyk -> VulnIQ sync orchestrator.

    SnykConnector.fetch_findings()   (last N days, all 5 products)
      -> normalize_snyk_records()    (raw -> unified Findings, no LLM)
      -> ENGINE.ingest_snyk()        (incremental merge + recompute everything)

Tracks sync metadata for the dashboard. Native Snyk is just one source; after
ingest, the unified inventory drives one attack graph for Snyk + manual uploads.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from app.ai_config import (snyk_configured, SNYK_LOOKBACK_DAYS,
                           SNYK_SCHEDULED_SYNC, SNYK_SYNC_INTERVAL_HOURS,
                           has_credentials)

log = logging.getLogger("vulniq.snyk")

_state = {
    "configured": False,
    "last_sync_time": None,
    "sync_status": "never",        # never | running | ok | error
    "findings_added": 0,
    "findings_updated": 0,
    "findings_removed": 0,
    "sync_duration_sec": 0.0,
    "lookback_days": SNYK_LOOKBACK_DAYS,
    "by_source": {},
    "errors": [],
}
_lock = asyncio.Lock()


def get_sync_status() -> dict:
    s = dict(_state)
    s["configured"] = snyk_configured()
    return s


async def run_snyk_sync(lookback_days: int | None = None) -> dict:
    """One full sync cycle. Safe to call from an endpoint or the scheduler."""
    if not snyk_configured():
        _state.update(sync_status="error",
                      errors=["SNYK_API_TOKEN / SNYK_ORG_ID not set in .env"])
        return get_sync_status()

    if _lock.locked():
        return get_sync_status()                 # a sync is already running

    async with _lock:
        from app.ingestion.snyk_connector import SnykConnector
        from app.ingestion.snyk_normalize import normalize_snyk_records
        from app.engine import ENGINE

        _state.update(sync_status="running", errors=[])
        t0 = time.time()
        log.info("[snyk] sync starting (lookback=%s days)",
                 lookback_days or SNYK_LOOKBACK_DAYS)
        try:
            from app.context.intel.threat_intel import enrich_many
            connector = SnykConnector()
            raw = await connector.fetch_findings(lookback_days)
            findings = normalize_snyk_records(raw, ENGINE.assets, do_enrich=False)
            enrich_many(findings)              # batched EPSS/KEV (one pass, not per-finding)
            # ingest_snyk recomputes the graph; run it off the event loop because
            # edge inference may make blocking LLM calls.
            res = await asyncio.to_thread(
                ENGINE.ingest_snyk, findings, has_credentials())
            # Persist a historical snapshot of this sync (no-op without DATABASE_URL).
            try:
                from app.db.repository import persist_run
                await asyncio.to_thread(
                    persist_run, "Snyk", "snyk_sync",
                    {"added": res["findings_added"], "updated": res["findings_updated"],
                     "removed": res["findings_removed"], "by_source": res["by_source"]})
            except Exception:
                log.exception("[snyk] persistence snapshot failed (sync unaffected)")
            _state.update(
                last_sync_time=datetime.now(timezone.utc).isoformat(),
                sync_status="ok",
                findings_added=res["findings_added"],
                findings_updated=res["findings_updated"],
                findings_removed=res["findings_removed"],
                sync_duration_sec=round(time.time() - t0, 2),
                lookback_days=lookback_days or SNYK_LOOKBACK_DAYS,
                by_source=res["by_source"],
                errors=[])
            log.info("[snyk] sync ok: +%d ~%d -%d in %.1fs",
                     res["findings_added"], res["findings_updated"],
                     res["findings_removed"], time.time() - t0)
        except Exception as exc:
            _state.update(sync_status="error",
                          sync_duration_sec=round(time.time() - t0, 2),
                          errors=[str(exc)],
                          last_sync_time=datetime.now(timezone.utc).isoformat())
            log.exception("[snyk] sync failed")
        return get_sync_status()


async def scheduled_sync_loop():
    """Optional background loop. Started at app startup only when
    SNYK_SCHEDULED_SYNC=true; the first run waits one interval so startup stays
    fast (no Snyk fetch at boot)."""
    if not (SNYK_SCHEDULED_SYNC and snyk_configured()):
        return
    interval = max(0.1, SNYK_SYNC_INTERVAL_HOURS) * 3600
    log.info("[snyk] scheduled sync enabled every %.1fh", SNYK_SYNC_INTERVAL_HOURS)
    while True:
        await asyncio.sleep(interval)
        try:
            await run_snyk_sync()
        except Exception:
            log.exception("[snyk] scheduled sync iteration failed")
