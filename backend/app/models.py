"""
VulnIQ core data models.

The whole project hinges on ONE idea: every security tool, across every OSI
layer, emits findings in a different format. We normalize all of them into a
single `Finding` schema so they can live in one graph and be correlated.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------- #
# Enums: the controlled vocabulary that makes cross-tool correlation possible
# --------------------------------------------------------------------------- #
class Layer(str, Enum):
    """The OSI-ish layer a finding belongs to. Spans the full stack."""
    SOURCE_CODE = "source_code"        # SAST: Semgrep, Checkmarx
    APPSEC_RUNTIME = "appsec_runtime"  # DAST: OWASP ZAP, Burp
    DEPENDENCY = "dependency"          # SCA: Snyk, Trivy (libs)
    INFRA_HOST = "infra_host"          # Qualys, Nessus
    CONTAINER = "container"            # Trivy image scan
    CLOUD_CONFIG = "cloud_config"      # Prowler, ScoutSuite, Wiz
    IAM_IDENTITY = "iam_identity"      # IAM / privilege scans
    NETWORK = "network"                # exposed ports, segmentation
    DATA = "data"                      # secrets, data exposure


class Capability(str, Enum):
    """
    What an attacker GAINS by exploiting a finding. This is the bridge that
    lets us chain findings: the capability output of one finding becomes the
    enabling precondition of the next.
    """
    INITIAL_ACCESS = "initial_access"
    CODE_EXECUTION = "code_execution"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    PRIV_ESCALATION = "priv_escalation"
    LATERAL_MOVE = "lateral_move"
    FUNDS_ACCESS = "funds_access"       # the crown-jewel capability for a broker
    # cloud / container capabilities that bridge security domains (cross-product)
    AWS_AUTHENTICATED_ACCESS = "aws_authenticated_access"  # valid cloud creds obtained
    CLOUD_ADMIN = "cloud_admin"                            # cloud control-plane control
    NODE_EXECUTION = "node_execution"                      # container/node compromise


class Exposure(str, Enum):
    INTERNET = "internet"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class Priority(str, Enum):
    BREAK_CHAIN_CRITICAL = "break_chain_critical"  # fixing collapses many chains
    PATCH_THIS_WEEK = "patch_this_week"
    PATCH_THIS_MONTH = "patch_this_month"
    DEFER = "defer"                                # high CVSS, no viable chain


# --------------------------------------------------------------------------- #
# Core records
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single normalized security finding from any tool, any layer."""
    finding_id: str
    source_tool: str
    layer: Layer
    finding_type: str               # e.g. "SQLi", "exposed_endpoint", "CVE"
    title: str
    description: str
    raw_severity: str               # tool-native severity label
    cvss: float                     # 0.0 - 10.0
    affected_asset_id: str
    component: str = ""             # library / service / bucket
    cwe: Optional[str] = None
    cve: Optional[str] = None
    location: str = ""             # file:line | URL | host:port | ARN
    network_exposure: Exposure = Exposure.INTERNAL
    evidence: str = ""

    # Enriched at runtime
    epss: float = 0.0               # exploit probability (0-1) from FIRST.org
    in_kev: bool = False            # CISA Known Exploited Vulnerabilities

    # Computed by the engine
    grants: list[Capability] = field(default_factory=list)
    priority: Optional[Priority] = None
    priority_p: Optional[str] = None  # P1..P5 — combined exposure×criticality×exploit×severity×chain
    chain_count: int = 0            # how many high-risk chains it sits on
    centrality: float = 0.0         # betweenness on high-risk subgraph
    final_score: float = 0.0
    # Objective-driven attack-path layer
    attack_objectives: list[str] = field(default_factory=list)  # goals this finding advances
    remediation_leverage: float = 0.0          # 0-100: realistic high-value risk removed if fixed
    remediation_leverage_label: str = ""       # Very High / High / Medium / Low / None
    chains_collapsed: int = 0                   # chains broken if this finding is fixed
    crown_paths_collapsed: int = 0             # of those, how many reached a crown-jewel objective
    # Deduplication / remediation grouping
    duplicate_count: int = 1                    # exact duplicates merged into this finding (incl. itself)
    remediation_group: str = ""                 # asset + package/rule — one fix collapses the group
    remediation_action: str = ""                # human label, e.g. "Upgrade node 18.13.0"
    # Source provenance (manual upload vs native Snyk; same issue may have several)
    sources: list[str] = field(default_factory=list)  # e.g. ["Snyk Open Source", "AppSec VAPT"]
    external_id: str = ""                        # source system id (Snyk issue id) for incremental sync
    status: str = "open"                         # open | resolved | reopened
    source_metadata: dict = field(default_factory=dict)  # preserved raw source fields
    # Engineering ownership (first-class). Deterministically resolved each rebuild
    # via the 5-tier priority in app.ownership.resolver — EXACTLY one head/finding.
    owner_head: Optional[str] = None             # canonical engineering head
    business_unit: str = ""                      # owning business unit
    owner_tier: int = 0                          # which resolution tier matched (1..5)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["network_exposure"] = self.network_exposure.value
        d["grants"] = [c.value for c in self.grants]
        d["priority"] = self.priority.value if self.priority else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Reconstruct a Finding from a stored to_dict(). Only the INPUT fields
        are restored — the engine re-derives computed fields (priority, chains,
        leverage, objectives, evidence) on the next rebuild. Used to hydrate the
        live engine from a persisted run after a restart."""
        def _enum(enum_cls, val, default):
            try:
                return enum_cls(val)
            except (ValueError, KeyError):
                return default
        f = cls(
            finding_id=d.get("finding_id", ""), source_tool=d.get("source_tool", ""),
            layer=_enum(Layer, d.get("layer"), Layer.SOURCE_CODE),
            finding_type=d.get("finding_type", "unknown"),
            title=d.get("title", ""), description=d.get("description", ""),
            raw_severity=d.get("raw_severity", ""), cvss=float(d.get("cvss") or 0),
            affected_asset_id=d.get("affected_asset_id", ""), component=d.get("component", ""),
            cwe=d.get("cwe"), cve=d.get("cve"), location=d.get("location", ""),
            network_exposure=_enum(Exposure, d.get("network_exposure"), Exposure.INTERNAL),
            evidence=d.get("evidence", ""), epss=float(d.get("epss") or 0),
            in_kev=bool(d.get("in_kev")),
            sources=list(d.get("sources") or []), external_id=d.get("external_id", ""),
            status=d.get("status", "open"), source_metadata=d.get("source_metadata") or {},
            duplicate_count=int(d.get("duplicate_count") or 1),
        )
        f.grants = [_enum(Capability, c, None) for c in (d.get("grants") or [])]
        f.grants = [c for c in f.grants if c is not None]
        return f


@dataclass
class Asset:
    """A system in the environment. Its context is what turns a generic CVE
    into a real, prioritized risk."""
    asset_id: str
    name: str
    tier: int                       # 0 = crown-jewel-adjacent, higher = less critical
    internet_facing: bool
    data_classification: str
    business_function: str
    upstream_dependencies: list[str] = field(default_factory=list)
    downstream_access: list[str] = field(default_factory=list)
    compensating_controls: list[str] = field(default_factory=list)
    is_crown_jewel: bool = False
    ip_derived: bool = False        # auto-registered from the IP inventory (Tenable host)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackChain:
    """A path through the graph from an exposed entry finding to a crown jewel."""
    chain_id: str
    finding_ids: list[str]
    asset_path: list[str]
    entry_finding: str
    crown_jewel: str
    narrative: str = ""
    chain_risk: float = 0.0
    entry_exposure: float = 0.0
    exploit_likelihood: float = 0.0
    path_feasibility: float = 0.0
    crown_jewel_value: float = 0.0
    control_gap: float = 0.0
    # Objective-driven attack-path layer
    objectives: list[str] = field(default_factory=list)        # attacker goals this chain reaches
    primary_objective: str = ""                                # highest-value objective reached
    objective_reachability_score: float = 0.0                  # 0-100
    realism_score: float = 0.0                                 # 0-100 operational realism
    attack_path: dict = field(default_factory=dict)            # structured narrative (goal/access/pivot/escalation/impact)
    # Evidence validation layer
    edges: list = field(default_factory=list)                  # per-edge evidence objects
    products: list = field(default_factory=list)               # source products spanned (composition)
    num_products: int = 0                                      # how many distinct products
    num_assets: int = 0                                        # how many distinct assets
    chain_confidence: float = 0.0                              # 0-100 evidence-validated confidence
    confidence_breakdown: dict = field(default_factory=dict)   # the six confidence factors
    evidence_steps: list = field(default_factory=list)         # human "why this chain is valid" steps
    speculative: bool = False                                  # below confidence threshold -> won't escalate
    # Engineering ownership — a chain is owned by EXACTLY ONE primary owner (the
    # team responsible for the end-state crown-jewel risk); contributing teams are
    # tracked as secondary owners so cross-team chains are visible but never
    # double-counted. Resolved in app.ownership.resolver.
    primary_owner: str = ""
    secondary_owners: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
