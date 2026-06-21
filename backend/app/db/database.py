"""
Database session/engine management.

Persistence is OPT-IN via DATABASE_URL:
  - set    -> SQLAlchemy engine (PostgreSQL in prod, any SQLAlchemy URL works;
              SQLite is handy for local dev/tests)
  - unset  -> db_enabled() is False; the whole persistence layer is a no-op and
              VulnIQ keeps its original in-memory + JSON workflow unchanged.

Nothing here imports the attack-path engine; persistence sits strictly
underneath it.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("vulniq.db")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

_engine = None
_Session = None


def db_enabled() -> bool:
    return bool(DATABASE_URL)


def get_engine():
    global _engine
    if _engine is None and DATABASE_URL:
        from sqlalchemy import create_engine
        kwargs: dict = {"pool_pre_ping": True, "future": True}
        if DATABASE_URL.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(DATABASE_URL, **kwargs)
        log.info("db: engine created (%s)", DATABASE_URL.split("://", 1)[0])
    return _engine


def get_session():
    """Return a new Session. Caller is responsible for closing (use as context
    manager via session_scope below)."""
    global _Session
    if _Session is None:
        from sqlalchemy.orm import sessionmaker
        _Session = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _Session()


class session_scope:
    """`with session_scope() as s:` — commits on success, rolls back on error."""
    def __enter__(self):
        self.s = get_session()
        return self.s

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.s.commit()
            else:
                self.s.rollback()
        finally:
            self.s.close()
        return False


def init_db():
    """Create tables if they don't exist. Used both as the SQLite/dev fallback
    and as the body of the initial Alembic migration."""
    if not DATABASE_URL:
        return
    from app.db.orm import Base
    Base.metadata.create_all(bind=get_engine())
    log.info("db: schema ensured (create_all)")
    _ensure_owner_columns()


def _ensure_owner_columns():
    """Idempotently add the ownership columns to EXISTING tables. create_all only
    creates missing tables, never alters existing ones, so a DB seeded before the
    ownership feature needs these added in place. ADD COLUMN IF NOT EXISTS is a
    no-op when they're already present (and on a fresh DB create_all made them)."""
    from sqlalchemy import text
    stmts = [
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_head VARCHAR(128) DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS business_unit VARCHAR(128) DEFAULT ''",
        "ALTER TABLE chains ADD COLUMN IF NOT EXISTS primary_owner VARCHAR(128) DEFAULT ''",
        "ALTER TABLE chains ADD COLUMN IF NOT EXISTS secondary_owners JSON DEFAULT '[]'",
        "CREATE INDEX IF NOT EXISTS ix_findings_owner_head ON findings (owner_head)",
        "CREATE INDEX IF NOT EXISTS ix_findings_business_unit ON findings (business_unit)",
        "CREATE INDEX IF NOT EXISTS ix_chains_primary_owner ON chains (primary_owner)",
    ]
    eng = get_engine()
    # ADD COLUMN IF NOT EXISTS is Postgres/SQLite-3.35+; guard so a failure on an
    # exotic backend never blocks startup (the JSON `data` column still carries it).
    try:
        with eng.begin() as conn:
            for s in stmts:
                try:
                    conn.execute(text(s))
                except Exception as e:
                    log.warning("db: owner-column ensure skipped (%s)", e)
        log.info("db: ownership columns ensured")
    except Exception:
        log.exception("db: could not ensure ownership columns; ownership still in JSON")
