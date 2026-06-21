"""
SQLAlchemy ORM — historical persistence schema.

Structure (per the spec):
    ScanRun (one per sync/upload — a complete posture snapshot)
      ├── FindingRow[]      (findings as they were in that run)
      ├── ChainRow[]        (attack chains as computed in that run)
      ├── GraphSnapshot     (nodes + edges for that run)
      └── metrics (JSON on the run)

Heavy nested structures (chain edges/evidence/narrative, finding detail, graph)
are stored as JSON for full fidelity, with the high-signal fields promoted to
indexed columns for querying + trend analysis. A stable content `fingerprint`
(findings) / `signature` (chains) makes trend comparison count *unique state
changes*, not the number of executions.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (String, Integer, Float, Boolean, DateTime, ForeignKey,
                        JSON, Text, Index)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SeedMeta(Base):
    """Key/value bootstrap flags — notably whether the one-time JSON seed ran."""
    __tablename__ = "seed_meta"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    source: Mapped[str] = mapped_column(String(128), default="")     # "Snyk" | "Upload:foo.xlsx" | "seed"
    run_type: Mapped[str] = mapped_column(String(32), default="")    # snyk_sync | upload | seed | rebuild
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, default="")  # content hash of run
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    chains_count: Mapped[int] = mapped_column(Integer, default=0)
    p1_count: Mapped[int] = mapped_column(Integer, default=0)
    p2_count: Mapped[int] = mapped_column(Integer, default=0)
    p3_count: Mapped[int] = mapped_column(Integer, default=0)
    p4_count: Mapped[int] = mapped_column(Integer, default=0)
    p5_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    crown_exposure: Mapped[float] = mapped_column(Float, default=0.0)
    internet_exposure: Mapped[float] = mapped_column(Float, default=0.0)
    sync_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")

    findings = relationship("FindingRow", back_populates="run", cascade="all, delete-orphan")
    chains = relationship("ChainRow", back_populates="run", cascade="all, delete-orphan")
    graph = relationship("GraphSnapshot", back_populates="run", uselist=False,
                         cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(64), default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, default="")  # stable identity across runs
    title: Mapped[str] = mapped_column(String(255), default="")
    asset: Mapped[str] = mapped_column(String(128), index=True, default="")
    finding_type: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    cwe: Mapped[str] = mapped_column(String(32), default="")
    cve: Mapped[str] = mapped_column(String(32), default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[str] = mapped_column(String(32), default="")
    priority_p: Mapped[str] = mapped_column(String(4), index=True, default="")
    chain_count: Mapped[int] = mapped_column(Integer, default=0)
    remediation_leverage: Mapped[float] = mapped_column(Float, default=0.0)
    # Engineering ownership — promoted to indexed columns for owner-scoped queries.
    owner_head: Mapped[str] = mapped_column(String(128), index=True, default="")
    business_unit: Mapped[str] = mapped_column(String(128), index=True, default="")
    sources: Mapped[list] = mapped_column(JSON, default=list)
    grants: Mapped[list] = mapped_column(JSON, default=list)
    data: Mapped[dict] = mapped_column(JSON, default=dict)   # full finding.to_dict()

    run = relationship("ScanRun", back_populates="findings")


class ChainRow(Base):
    __tablename__ = "chains"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    chain_id: Mapped[str] = mapped_column(String(32), default="")
    signature: Mapped[str] = mapped_column(String(64), index=True, default="")  # stable identity across runs
    objective: Mapped[str] = mapped_column(String(64), index=True, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    chain_risk: Mapped[float] = mapped_column(Float, default=0.0)
    num_products: Mapped[int] = mapped_column(Integer, default=0)
    num_assets: Mapped[int] = mapped_column(Integer, default=0)
    speculative: Mapped[bool] = mapped_column(Boolean, default=False)
    crown_jewel: Mapped[str] = mapped_column(String(128), default="")
    # Engineering ownership — one primary owner per chain; contributors as secondary.
    primary_owner: Mapped[str] = mapped_column(String(128), index=True, default="")
    secondary_owners: Mapped[list] = mapped_column(JSON, default=list)
    products: Mapped[list] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    data: Mapped[dict] = mapped_column(JSON, default=dict)   # full chain.to_dict()

    run = relationship("ScanRun", back_populates="chains")


class GraphSnapshot(Base):
    __tablename__ = "graph_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"),
                                        unique=True, index=True)
    nodes: Mapped[list] = mapped_column(JSON, default=list)
    edges: Mapped[list] = mapped_column(JSON, default=list)

    run = relationship("ScanRun", back_populates="graph")


Index("ix_findings_run_fp", FindingRow.run_id, FindingRow.fingerprint)
Index("ix_chains_run_sig", ChainRow.run_id, ChainRow.signature)
