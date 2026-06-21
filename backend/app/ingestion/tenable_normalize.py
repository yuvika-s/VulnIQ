"""
Tenable raw record -> unified VulnIQ Finding.

Tenable host data is structured, so this is a deterministic mapping (no LLM). The
output Finding is identical in shape to one produced from a Snyk record or a
manual upload, so it flows into the SAME capability map, graph, chaining,
evidence, objective and prioritization engine — Tenable is a first-class source,
not a special case.

Two correlation moves make Tenable findings *chain* rather than just list:
  1. IP -> Application (ip_match): a host CVE lands on the same asset node as
     that application's Snyk/manual findings, enabling cross-source chains.
  2. finding_type is mapped into the EXISTING VulnIQ vocabulary so capabilities
     come from the shared cwe_capability_map — no parallel capability set, no
     fabricated attack primitives. Unclassified host hygiene (unpatched package,
     no exploit primitive) grants nothing and can never become a chain hub.
"""
from __future__ import annotations

import hashlib

from app.models import Finding, Layer, Exposure
from app.graph.cwe_capability_map import grants_for
from app.ingestion.ip_match import (resolve_ip, application_asset_id,
                                     ensure_ip_assets, _slug)
from app.context.intel.threat_intel import enrich

# Tenable plugin family (family.name) -> VulnIQ OSI layer. Substring match, so
# variants ("Red Hat Local Security Checks", "Ubuntu Local Security Checks") all
# resolve. Host/OS checks dominate, hence the INFRA_HOST default.
_FAMILY_LAYER = [
    (("web server", "cgi", "service detection : web"), Layer.APPSEC_RUNTIME),
    (("database",), Layer.APPSEC_RUNTIME),
    (("container", "docker"), Layer.CONTAINER),
    (("dns", "snmp", "smtp", "ftp", "firewall", "port scanner", "service detection",
      "netware"), Layer.NETWORK),
    (("local security checks", "windows", "unix", "patch management", "red hat",
      "ubuntu", "suse", "centos", "oracle linux", "misc", "general", "vmware"),
     Layer.INFRA_HOST),
]

# Plugin-name keyword -> VulnIQ finding_type (most specific first). These reuse
# the existing finding_type vocabulary so the shared capability map applies. Only
# keywords that genuinely evidence an attack primitive promote a finding above
# inert host hygiene.
_NAME_RULES = [
    (("remote code execution", "arbitrary code", "deserial", " rce", "rce ",
      "code execution"), "RCE"),
    (("os command", "command injection", "argument injection"), "command_injection"),
    (("sql injection", "sqli"), "SQLi"),
    (("cross-site scripting", "xss"), "XSS"),
    (("server-side request", "ssrf"), "SSRF"),
    (("directory traversal", "path traversal", "local file inclusion"), "path_traversal"),
    (("default password", "default credential", "default account", "weak password",
      "hardcoded", "blank password", "anonymous", "credential disclosure"),
     "hardcoded_credentials"),
    (("privilege escalation", "elevation of privilege", "local privilege",
      " sudo", "setuid"), "privilege_escalation"),
    (("information disclosure", "sensitive information", "information leak",
      "info leak", "memory disclosure", "directory listing"), "info_disclosure"),
    (("unsupported", "end of life", "end-of-life", " eol", "obsolete",
      "no longer supported"), "unpatched_software"),
]
# Family fallback when the plugin name carries no primitive keyword.
_FAMILY_TYPE = [
    (("web server", "cgi", "database"), "remote_service"),
    (("dns", "snmp", "smtp", "ftp", "firewall", "port scanner", "service detection"),
     "remote_service"),
]


def _finding_id(external_id: str) -> str:
    h = hashlib.md5(external_id.encode("utf-8")).hexdigest()[:8].upper()
    return f"F-TNS-{h}"


def _match(low: str, rules):
    for kws, t in rules:
        if any(k in low for k in kws):
            return t
    return None


def _layer_for(family: str) -> Layer:
    low = (family or "").lower()
    for kws, layer in _FAMILY_LAYER:
        if any(k in low for k in kws):
            return layer
    return Layer.INFRA_HOST


def _type_for(plugin_name: str, family: str) -> str:
    low = (plugin_name or "").lower()
    t = _match(low, _NAME_RULES)
    if t:
        return t
    t = _match((family or "").lower(), _FAMILY_TYPE)
    if t:
        return t
    # Default: pure patch hygiene — grants nothing chainable (see capability map).
    return "unpatched_software"


def normalize_tenable_records(records: list[dict], assets: dict, ip_map: dict,
                              do_enrich: bool = True) -> list[Finding]:
    # Enrich the asset registry with IP-sheet criticality/environment FIRST so
    # findings resolve onto context-rich assets (drives tier/priority/chaining).
    ensure_ip_assets(records, assets, ip_map)
    from app.ingestion.asset_match import build_app_index
    index = build_app_index(assets)

    findings: list[Finding] = []
    for r in records:
        family = r.get("family", "")
        plugin_name = r.get("title", "")
        ftype = _type_for(plugin_name, family)
        layer = _layer_for(family)

        # IP -> application -> asset node (shared with Snyk/manual for that app)
        rec = resolve_ip(r.get("ip", ""), ip_map)
        if rec:
            asset_id, _matched = application_asset_id(rec.get("application", ""),
                                                      assets, index)
        else:
            # unknown IP: fall back to hostname, then a synthetic per-host asset
            host = r.get("dns_name") or r.get("ip") or "unassigned-host"
            asset_id = _slug(host.split(".")[0] if host else "unassigned-host")
        asset = assets.get(asset_id)

        # Host findings inherit exposure from the asset (we never fabricate
        # internet exposure the inventory doesn't assert).
        exposure = (Exposure.INTERNET if (asset and asset.internet_facing)
                    else Exposure.INTERNAL)

        cvss = r.get("cvss_score")
        if cvss is None:
            from app.ingestion.extraction_agent import SEV_TO_CVSS
            cvss = SEV_TO_CVSS.get((r.get("severity") or "medium").lower(), 5.5)

        host_label = r.get("dns_name") or r.get("ip") or ""
        loc_bits = [b for b in (host_label,
                                f"port {r.get('port')}/{r.get('protocol')}"
                                if r.get("port") and r.get("port") != "0" else "",
                                r.get("plugin_id") and f"plugin:{r.get('plugin_id')}")
                    if b]
        location = "host:" + " · ".join(loc_bits) if loc_bits else "host"

        f = Finding(
            finding_id=_finding_id(r.get("external_id", "") or plugin_name),
            source_tool="Tenable",
            layer=layer,
            finding_type=ftype,
            title=(plugin_name or "Tenable finding")[:160],
            description=r.get("description", "") or r.get("synopsis", "") or "",
            raw_severity=(r.get("severity") or "medium").lower(),
            cvss=float(cvss),
            affected_asset_id=asset_id,
            component=(r.get("operating_system") or "").split(" on ")[0][:80],
            cwe=None,                       # SC vulndetails carries no CWE
            cve=r.get("cve"),
            location=location,
            network_exposure=exposure,
            evidence=(f"tenable:{family} plugin={r.get('plugin_id')}"
                      f" exploit={'yes' if r.get('exploit_available') else 'no'}").strip(),
            status=(r.get("status") or "open"),
            external_id=r.get("external_id", ""),
            sources=["Tenable"],
            source_metadata=r.get("source_metadata", {}),
        )
        f.grants = grants_for(f)

        # Threat intel: Tenable already provides EPSS + exploit availability.
        # Enrich from the CVE too, then keep the strongest signal. A public
        # exploit (exploitAvailable) floors EPSS so "active exploit" reflects it
        # in prioritization — without over-claiming CISA KEV membership.
        tns_epss = float(r.get("epss") or 0.0)
        if do_enrich and f.cve:
            try:
                enrich(f)
            except Exception:
                pass
        f.epss = max(f.epss, tns_epss)
        if r.get("exploit_available"):
            f.epss = max(f.epss, 0.5)
        findings.append(f)
    return findings
