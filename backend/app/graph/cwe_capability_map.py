"""
The capability map: the deterministic backbone of correlation.

Each finding TYPE / CWE grants the attacker one or more capabilities, and may
REQUIRE a precondition capability to be exploited. Chaining works by matching
the `grants` of one finding to the `requires` of a reachable next finding.

This is intentionally a transparent lookup table (not ML) so that the
deterministic layer is fully auditable. The LLM layer refines it with semantic
nuance, but the skeleton lives here.
"""
from app.models import Capability

# finding_type -> capabilities granted.
# Types that represent low-value noise (headers, logging, weak checksums) grant
# NOTHING chainable — they should never become attack-chain hubs.
TYPE_GRANTS: dict[str, list[Capability]] = {
    "SQLi": [Capability.DATA_READ, Capability.CREDENTIAL_ACCESS],
    "SSRF": [Capability.DATA_READ, Capability.LATERAL_MOVE],
    "XSS": [Capability.CREDENTIAL_ACCESS],
    "exposed_endpoint": [Capability.INITIAL_ACCESS, Capability.DATA_READ],
    "command_injection": [Capability.CODE_EXECUTION],
    "RCE": [Capability.CODE_EXECUTION],
    # secrets / hardcoded cloud keys -> valid cloud credentials (bridges to IaC)
    "hardcoded_credentials": [Capability.CREDENTIAL_ACCESS, Capability.AWS_AUTHENTICATED_ACCESS],
    "secret_leak": [Capability.CREDENTIAL_ACCESS, Capability.AWS_AUTHENTICATED_ACCESS],
    # over-privileged IAM -> cloud control plane (consumes cloud creds)
    "overprivileged_role": [Capability.CLOUD_ADMIN, Capability.PRIV_ESCALATION, Capability.DATA_WRITE],
    # privileged container -> node compromise (consumes code exec)
    "privileged_container": [Capability.NODE_EXECUTION, Capability.PRIV_ESCALATION, Capability.LATERAL_MOVE],
    # publicly exposed cloud resource -> data + lateral (consumes cloud admin)
    "public_resource": [Capability.DATA_READ, Capability.LATERAL_MOVE],
    "misconfig": [Capability.LATERAL_MOVE],
    "missing_control": [Capability.INITIAL_ACCESS],
    "path_traversal": [Capability.DATA_READ],
    "open_port": [Capability.INITIAL_ACCESS],
    # --- host / infrastructure finding types (Nessus/Tenable/Qualys, also any
    #     manual host scanner). Added so host findings are first-class chain
    #     participants WITHOUT a parallel capability vocabulary — they reuse the
    #     same Capability enum and the same handoff rules as every other source. ---
    # A reachable network service is an entry point (no precondition). It does NOT
    # by itself grant code execution — only INITIAL_ACCESS — so it can begin a
    # chain but cannot manufacture deeper impact on its own.
    "remote_service": [Capability.INITIAL_ACCESS],
    # Local privilege escalation: only useful AFTER a foothold (see requires),
    # so it deepens a real chain rather than inventing one.
    "privilege_escalation": [Capability.PRIV_ESCALATION],
    # Information disclosure (config/version/metadata leak) → read access only.
    "info_disclosure": [Capability.DATA_READ],
    # Unpatched software is pure patch hygiene by default and grants NOTHING
    # chainable. If the underlying CVE/CWE denotes real impact (e.g. CWE-502
    # deserialization → code execution) that is added via CWE_GRANTS below — so
    # an unpatched deserialization CVE still chains, but an unpatched library
    # with no exploit primitive never becomes an artificial attack-graph hub.
    "unpatched_software": [],
    # --- inert noise types (no chainable capability) ---
    "weak_crypto": [],
    "weak_control": [],
}

# Finding types considered pure-noise: never grant capabilities regardless of CWE.
INERT_TYPES = {"weak_crypto"}
# Title keywords that mark a finding as non-chainable hygiene noise.
INERT_TITLE_HINTS = ("security header", "logging disabled", "unused iam access key",
                     "md5", "telnet open")

# CWE -> capabilities (used when finding_type is generic, e.g. "CVE")
CWE_GRANTS: dict[str, list[Capability]] = {
    "CWE-502": [Capability.CODE_EXECUTION],            # deserialization
    "CWE-94": [Capability.CODE_EXECUTION],             # code injection
    "CWE-78": [Capability.CODE_EXECUTION],             # OS command injection
    "CWE-77": [Capability.CODE_EXECUTION],             # command injection
    "CWE-20": [Capability.CODE_EXECUTION],             # input validation -> RCE
    "CWE-787": [Capability.CODE_EXECUTION],            # OOB write
    "CWE-284": [Capability.PRIV_ESCALATION],           # improper access control
    "CWE-732": [Capability.DATA_READ],                 # incorrect permission
    "CWE-89": [Capability.DATA_READ, Capability.CREDENTIAL_ACCESS],  # SQLi
    "CWE-918": [Capability.LATERAL_MOVE, Capability.DATA_READ],      # SSRF
    "CWE-200": [Capability.DATA_READ],                 # info disclosure
    "CWE-269": [Capability.PRIV_ESCALATION, Capability.DATA_WRITE],  # priv mgmt
    "CWE-798": [Capability.CREDENTIAL_ACCESS],         # hardcoded creds
    "CWE-732": [Capability.DATA_READ],                 # perms
    "CWE-307": [Capability.INITIAL_ACCESS],            # no rate limit / brute force
    "CWE-923": [Capability.LATERAL_MOVE],              # improper network endpoint
    "CWE-79": [Capability.CREDENTIAL_ACCESS],
    "CWE-22": [Capability.DATA_READ],
    "CWE-327": [Capability.CREDENTIAL_ACCESS],
}

# Which capability is required to *reach* / exploit a finding of this type.
# None = exploitable directly (an entry point) given network reachability.
TYPE_REQUIRES: dict[str, list[Capability]] = {
    "SQLi": [],                              # directly exploitable if reachable
    "SSRF": [Capability.INITIAL_ACCESS],
    "exposed_endpoint": [],                  # entry point
    "command_injection": [Capability.INITIAL_ACCESS],   # reach the endpoint first
    "RCE": [Capability.INITIAL_ACCESS],
    # reading a secret needs code exec OR data read (Code/OSS RCE -> Secrets)
    "hardcoded_credentials": [Capability.CODE_EXECUTION, Capability.DATA_READ],
    "secret_leak": [Capability.CODE_EXECUTION, Capability.DATA_READ],
    # assuming an over-privileged role needs cloud creds (Secrets/IaC -> IaC IAM)
    "overprivileged_role": [Capability.AWS_AUTHENTICATED_ACCESS, Capability.CREDENTIAL_ACCESS],
    # compromising a privileged container needs code exec on it (Code/OSS -> Container)
    "privileged_container": [Capability.CODE_EXECUTION, Capability.NODE_EXECUTION],
    # reaching a public cloud resource follows cloud-plane control (IaC IAM -> resource)
    "public_resource": [Capability.CLOUD_ADMIN, Capability.LATERAL_MOVE],
    # Generic misconfig now requires only INITIAL_ACCESS (NOT lateral_move). This
    # breaks the dense misconfig<->misconfig clique that consumed the candidate
    # budget — a misconfig is reached from an entry, not from any other misconfig.
    "misconfig": [Capability.INITIAL_ACCESS],
    "missing_control": [],
    "open_port": [],
    # host / infra types
    "remote_service": [],                                   # entry point
    # local priv-esc is only reachable once the attacker already has a foothold
    # (code exec or initial access) on the host — never a standalone entry.
    "privilege_escalation": [Capability.CODE_EXECUTION, Capability.INITIAL_ACCESS],
    "info_disclosure": [Capability.INITIAL_ACCESS],
    "unpatched_software": [Capability.INITIAL_ACCESS],
}


def grants_for(finding) -> list[Capability]:
    """Resolve the capabilities a finding grants, preferring specific type.
    Noise/hygiene findings grant nothing so they cannot become chain hubs."""
    title_l = (finding.title or "").lower()
    if finding.finding_type in INERT_TYPES or \
       any(h in title_l for h in INERT_TITLE_HINTS):
        return []

    caps: list[Capability] = []
    if finding.finding_type in TYPE_GRANTS:
        caps.extend(TYPE_GRANTS[finding.finding_type])
    if finding.cwe in CWE_GRANTS:
        caps.extend(CWE_GRANTS[finding.cwe])
    seen, out = set(), []
    for c in caps:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def requires_for(finding) -> list[Capability]:
    """Capabilities needed to exploit this finding (empty = entry point)."""
    return TYPE_REQUIRES.get(finding.finding_type, [Capability.INITIAL_ACCESS])
