"""
First-boot seed + restart hydration.

On startup (DB enabled):
  1. ensure schema exists
  2. if never seeded -> capture the initial JSON-loaded engine state as run #1,
     then mark seeded (so we never reseed)
  3. if runs exist -> hydrate the live engine from the LATEST run so that all
     live endpoints reflect persisted data after a restart (findings/chains/
     priorities survive). Historical runs keep their own stored snapshots.
"""
from __future__ import annotations

import logging

from app.db.database import db_enabled, init_db, session_scope
from app.db import repository as repo

log = logging.getLogger("vulniq.db")


def bootstrap_persistence():
    """Call once at startup, AFTER ENGINE.build(). Safe no-op without a DB."""
    if not db_enabled():
        log.info("db: DATABASE_URL not set — JSON/in-memory mode (no persistence)")
        return
    try:
        init_db()                                   # create_all fallback (Alembic also runs in Docker)
    except Exception:
        log.exception("db: schema init failed; continuing without persistence")
        return

    try:
        if not repo.is_seeded():
            # capture the freshly-built engine (from JSON) as the founding run
            repo.persist_run(source="seed", run_type="seed",
                             notes="initial seed from JSON files")
            repo.mark_seeded()
            log.info("db: first-boot seed complete — DB is now source of truth")
        elif _hydrate_on_start():
            # Opt-in (VULNIQ_HYDRATE_ON_START=true): repopulate the LIVE engine
            # from the latest run so a restart restores the working set.
            _hydrate_latest()
        else:
            # Default: the LIVE view reflects only the CURRENT session. Startup is
            # blank (no findings) until this session runs a sync/upload; past runs
            # remain fully browsable in the History tab. Persistence is unaffected.
            log.info("db: blank-start mode — live engine empty on boot; "
                     "history retains all runs (set VULNIQ_HYDRATE_ON_START=true "
                     "to restore last run into the live view)")
    except Exception:
        log.exception("db: bootstrap_persistence failed; engine still usable")


def _hydrate_on_start() -> bool:
    import os
    return str(os.environ.get("VULNIQ_HYDRATE_ON_START", "")).strip().lower() \
        in ("1", "true", "yes", "on")


def _hydrate_latest():
    """Load the most recent run's findings into the live engine and rebuild, so a
    restart restores the working set."""
    from app.engine import ENGINE
    from app.models import Finding
    from app.db.orm import ScanRun, FindingRow
    with session_scope() as s:
        run = s.query(ScanRun).order_by(ScanRun.created_at.desc()).first()
        if not run:
            return
        rows = s.query(FindingRow).filter(FindingRow.run_id == run.id).all()
        findings = [Finding.from_dict(r.data) for r in rows if r.data]
    if not findings:
        return
    ENGINE.findings = findings
    use_llm = getattr(ENGINE, "_use_llm", None)
    ENGINE._rebuild(use_llm=False if use_llm is None else use_llm)
    ENGINE._built = True
    log.info("db: hydrated engine from run #%d — %d findings, %d chains restored",
             run.id, len(ENGINE.findings), len(ENGINE.chains))
