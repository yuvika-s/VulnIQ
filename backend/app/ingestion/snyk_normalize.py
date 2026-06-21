"""
Snyk raw record -> unified VulnIQ Finding.

Snyk data is already structured (CWE, CVE, CVSS, package, severity), so this is a
deterministic mapping — no LLM needed. The output Finding is identical in shape
to one produced from a manual upload, so it flows into the same capability map,
graph, chaining, evidence, objective and prioritization engine.
"""
from __future__ import annotations

import hashlib

from app.models import Finding, Layer, Exposure
from app.graph.cwe_capability_map import grants_for
from app.ingestion.extraction_agent import TYPE_HINTS, SEV_TO_CVSS
from app.ingestion.asset_match import match_repo_to_app
from app.context.intel.threat_intel import enrich

_PRODUCT_LAYER = {
    "Snyk Open Source": Layer.DEPENDENCY,
    "Snyk Container": Layer.CONTAINER,
    "Snyk IaC": Layer.CLOUD_CONFIG,
    "Snyk Code": Layer.SOURCE_CODE,
    "Snyk Secrets": Layer.DATA,
}
_PRODUCT_TYPE = {
    "Snyk Open Source": "CVE",
    "Snyk Container": "CVE",
    "Snyk IaC": "misconfig",
    "Snyk Code": "code_flaw",
    "Snyk Secrets": "secret_leak",
}


def _finding_id(external_id: str) -> str:
    h = hashlib.md5(external_id.encode("utf-8")).hexdigest()[:8].upper()
    return f"F-SNYK-{h}"


# Product-specific title classification (first match wins). Maps Snyk's free-text
# titles to specific VulnIQ finding types so capabilities are varied and
# cross-product handoffs exist — instead of every IaC finding collapsing to the
# generic "misconfig" (which created the dense IaC<->IaC lateral_move clique).
_IAC_RULES = [
    (("credential", "provider attribute", "access key", "secret", "hardcoded",
      "api key", "private key", "password"), "hardcoded_credentials"),
    (("role", " iam", "iam ", "privilege", "permission", "policy", "clusterrole",
      "wildcard", "assume", "sts", "overly permissive", "admin"), "overprivileged_role"),
    (("privileged", "run as root", "runasnonroot", "allowprivilegeescalation",
      "host path", "hostpath", "capabilities", "security context", "seccomp",
      "container"), "privileged_container"),
    (("ingress", "0.0.0.0", "publicly", "public ", "open to", "exposed",
      "unrestricted", "cidr", "internet"), "exposed_endpoint"),
    (("bucket", "public access", "encryption", "logging", "versioning",
      "snapshot", "backup"), "public_resource"),
]
_CODE_RULES = [
    (("sql injection", "sqli"), "SQLi"),
    (("command injection", "os command", "argument injection"), "command_injection"),
    (("code injection", "remote code", "deserial", "rce"), "RCE"),
    (("path traversal", "directory traversal"), "path_traversal"),
    (("cross-site scripting", "xss"), "XSS"),
    (("ssrf", "server-side request"), "SSRF"),
    (("hardcoded", "secret", "credential", "api key", "password", "token"), "hardcoded_credentials"),
    (("authorization", "access control", "permissive trust", "missing auth",
      "improper auth", "open redirect"), "exposed_endpoint"),
]


def _match_rules(low, rules):
    for kws, t in rules:
        if any(k in low for k in kws):
            return t
    return None


def _type_and_layer(title: str, product: str):
    low = (title or "").lower()
    layer = _PRODUCT_LAYER.get(product, Layer.DEPENDENCY)
    if product == "Snyk IaC":
        return _match_rules(low, _IAC_RULES) or "misconfig", layer
    if product in ("Snyk Code", "Snyk Secrets"):
        return _match_rules(low, _CODE_RULES) or _PRODUCT_TYPE.get(product, "code_flaw"), layer
    # OSS / Container — dependency CVEs: title hints then generic CVE
    for hint, (t, _l, _c) in TYPE_HINTS.items():
        if hint in low:
            return t, layer
    return _PRODUCT_TYPE.get(product, "CVE"), layer


def normalize_snyk_records(records: list[dict], assets: dict,
                           do_enrich: bool = True) -> list[Finding]:
    findings = []
    for r in records:
        product = r.get("source_tool", "Snyk")
        ftype, layer = _type_and_layer(r.get("title", ""), product)

        # asset: map the repo to a known application; fall back to the repo slug
        # (the engine auto-registers unmapped repos as low-tier assets).
        repo = r.get("repo_short") or r.get("repository") or ""
        app_id, _tok = match_repo_to_app(repo, assets) if repo else (None, None)
        asset_id = app_id or (repo or "unassigned")

        # CVSS: explicit score, else map from severity
        cvss = r.get("cvss_score")
        if cvss is None:
            cvss = SEV_TO_CVSS.get((r.get("severity") or "medium").lower(), 5.5)

        loc_bits = [b for b in (r.get("repository"), r.get("branch"),
                                r.get("target_file")) if b]
        location = ":".join(loc_bits) if loc_bits else f"repo:{repo}"

        f = Finding(
            finding_id=_finding_id(r.get("external_id", "") or r.get("title", "")),
            source_tool=product,
            layer=layer,
            finding_type=ftype,
            title=(r.get("title") or "Snyk finding")[:120],
            description=r.get("description", "") or "",
            raw_severity=(r.get("severity") or "medium").lower(),
            cvss=float(cvss),
            affected_asset_id=asset_id,
            component=r.get("affected_component", "") or r.get("package", ""),
            cwe=r.get("cwe"),
            cve=r.get("cve"),
            location=location if not app_id else f"repo:{repo} · {location}",
            network_exposure=Exposure.INTERNAL,
            evidence=(f"snyk:{r.get('issue_type','')} maturity={r.get('exploit_maturity') or 'n/a'}"
                      f" fix={r.get('fix_version') or 'none'}").strip(),
            status=(r.get("status") or "open"),
            external_id=r.get("external_id", ""),
            sources=[product],
            source_metadata=r.get("source_metadata", {}),
        )
        f.grants = grants_for(f)
        if do_enrich:
            try:
                enrich(f)        # EPSS / KEV where a CVE exists
            except Exception:
                pass
        findings.append(f)
    return findings
