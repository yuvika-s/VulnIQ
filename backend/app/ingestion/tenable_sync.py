"""
Tenable -> VulnIQ sync orchestrator (mirrors snyk_sync.py).

    TenableConnector.fetch_findings()    (SC cumulative vulns, severity-capped)
      -> normalize_tenable_records()     (raw -> unified Findings + IP→app, no LLM)
      -> ENGINE.ingest_tenable()         (incremental merge + recompute everything)
      -> persist_run()                   (historical snapshot, source="Tenable")

Native Tenable is just one source; after ingest, the unified inventory drives the
ONE attack graph spanning Tenable + Snyk + manual uploads.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from app.ai_config import (tenable_configured, TENABLE_SEVERITY, TENABLE_MAX_FINDINGS,
                           TENABLE_SCHEDULED_SYNC, TENABLE_SYNC_INTERVAL_HOURS,
                           has_credentials, configure_tls)

log = logging.getLogger("vulniq.tenable")

_state = {
    "configured": False,
    "last_sync_time": None,
    "sync_status": "never",        # never | running | ok | error
    "findings_added": 0,
    "findings_updated": 0,
    "findings_removed": 0,
    "sync_duration_sec": 0.0,
    "severity": TENABLE_SEVERITY,
    "max_findings": TENABLE_MAX_FINDINGS,
    "by_source": {},
    "errors": [],
}
_lock = asyncio.Lock()


def get_sync_status() -> dict:
    s = dict(_state)
    s["configured"] = tenable_configured()
    return s


def _do_sync(max_findings: int | None, severity: str | None) -> dict:
    """Blocking sync body — run via asyncio.to_thread (httpx.Client + LLM edges)."""
    from app.ingestion.tenable_connector import TenableConnector
    from app.ingestion.tenable_normalize import normalize_tenable_records
    from app.ingestion.ip_match import load_ip_assets
    from app.context.intel.threat_intel import enrich_many
    from app.engine import ENGINE

    configure_tls()
    raw = TenableConnector().fetch_findings(max_findings=max_findings, severity=severity)
    ip_map = load_ip_assets()
    findings = normalize_tenable_records(raw, ENGINE.assets, ip_map, do_enrich=False)
    enrich_many(findings)                  # batched EPSS/KEV (one pass)
    return ENGINE.ingest_tenable(findings, has_credentials())


async def run_tenable_sync(max_findings: int | None = None,
                           severity: str | None = None) -> dict:
    """One full sync cycle. Safe to call from an endpoint or the scheduler."""
    if not tenable_configured():
        _state.update(sync_status="error",
                      errors=["TENABLE_BASE_URL / TENABLE_ACCESS_KEY / "
                              "TENABLE_SECRET_KEY not set in backend/.env"])
        return get_sync_status()

    if _lock.locked():
        return get_sync_status()                  # a sync is already running

    async with _lock:
        _state.update(sync_status="running", errors=[])
        t0 = time.time()
        log.info("[tenable] sync starting (severity=%s, cap=%s)",
                 severity or TENABLE_SEVERITY, max_findings or TENABLE_MAX_FINDINGS)
        try:
            res = await asyncio.to_thread(_do_sync, max_findings, severity)
            try:
                from app.db.repository import persist_run
                await asyncio.to_thread(
                    persist_run, "Tenable", "tenable_sync",
                    {"added": res["findings_added"], "updated": res["findings_updated"],
                     "removed": res["findings_removed"], "by_source": res["by_source"]})
            except Exception:
                log.exception("[tenable] persistence snapshot failed (sync unaffected)")
            _state.update(
                last_sync_time=datetime.now(timezone.utc).isoformat(),
                sync_status="ok",
                findings_added=res["findings_added"],
                findings_updated=res["findings_updated"],
                findings_removed=res["findings_removed"],
                sync_duration_sec=round(time.time() - t0, 2),
                by_source=res["by_source"], errors=[])
            log.info("[tenable] sync ok: +%d ~%d -%d in %.1fs",
                     res["findings_added"], res["findings_updated"],
                     res["findings_removed"], time.time() - t0)
        except Exception as exc:
            _state.update(sync_status="error",
                          sync_duration_sec=round(time.time() - t0, 2),
                          errors=[str(exc)],
                          last_sync_time=datetime.now(timezone.utc).isoformat())
            log.exception("[tenable] sync failed")
        return get_sync_status()


async def scheduled_sync_loop():
    """Optional background loop, enabled only via TENABLE_SCHEDULED_SYNC=true.
    First run waits one full interval so startup stays fast."""
    if not (TENABLE_SCHEDULED_SYNC and tenable_configured()):
        return
    interval = max(0.1, TENABLE_SYNC_INTERVAL_HOURS) * 3600
    log.info("[tenable] scheduled sync enabled every %.1fh", TENABLE_SYNC_INTERVAL_HOURS)
    while True:
        await asyncio.sleep(interval)
        try:
            await run_tenable_sync()
        except Exception:
            log.exception("[tenable] scheduled sync iteration failed")
