"""
Tenable export (CSV) → VulnIQ raw records.

A Tenable.sc / Nessus CSV export carries the same vulnerability facts as the SC
REST API, just column-shaped. This adapter turns each CSV row into the EXACT same
raw-record dict that `tenable_connector._to_record` emits, so an uploaded Tenable
export flows through the identical pipeline as a native API sync:

    CSV rows → raw records → normalize_tenable_records → ENGINE.ingest_tenable
             → graph → chains → confidence → ownership → persistence → Ask VulnIQ

There is NO separate Tenable workflow. Source attribution stays "Tenable".
"""
from __future__ import annotations

import csv
import io
import logging
import re
import sys

log = logging.getLogger("vulniq.tenable")

# Tenable "Plugin Output" cells can exceed Python's default 128 KB CSV field cap.
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:                       # some platforms reject sys.maxsize
    csv.field_size_limit(2 ** 31 - 1)

# Header signature that identifies a Tenable/Nessus export (order-independent).
_SIGNATURE = {"plugin name", "ip address", "severity"}

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


def is_tenable_csv(content: bytes) -> bool:
    """True when the file looks like a Tenable/Nessus CSV export."""
    try:
        head = content[:4096].decode("utf-8", "ignore").lower()
        first = head.splitlines()[0] if head.splitlines() else ""
    except Exception:
        return False
    cols = {c.strip().strip('"') for c in first.split(",")}
    return _SIGNATURE.issubset(cols)


def _get(row: dict, *names: str) -> str:
    for n in names:
        for k in row:
            if k and k.strip().lower() == n:
                return (row[k] or "").strip()
    return ""


def _f(x: str):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def parse_tenable_csv(content: bytes, max_findings: int = 1500,
                      severity: str = "critical,high,medium") -> list[dict]:
    """Parse a Tenable CSV export into VulnIQ raw records (connector shape).

    Severity-filtered (default Critical/High/Medium) and capped, worst-first, so a
    100k-row export ingests the highest-signal findings without flooding the graph.
    """
    text = content.decode("utf-8", "ignore")
    wanted = {s.strip().lower() for s in (severity or "").split(",") if s.strip()}
    rows = list(csv.DictReader(io.StringIO(text)))
    records = []
    for r in rows:
        sev = _get(r, "severity").lower() or "medium"
        if sev in ("informational",):
            sev = "info"
        if wanted and sev not in wanted:
            continue
        plugin_id = _get(r, "plugin", "plugin id")
        ip = _get(r, "ip address", "ip")
        dns = _get(r, "dns name", "dns")
        name = _get(r, "plugin name", "name") or "Tenable finding"
        cves = [c.strip() for c in re.split(r"[,\s]+", _get(r, "cve")) if c.strip().upper().startswith("CVE")]
        cvss = _f(_get(r, "cvss v3 base score")) or _f(_get(r, "cvss v4 base score")) \
            or _f(_get(r, "cvss v2 base score"))
        epss = _f(_get(r, "exploit prediction scoring system (epss)", "epss"))
        if epss > 1:                       # exports sometimes store EPSS as a percent
            epss = epss / 100.0
        exploit_ease = _get(r, "exploit ease").lower()
        exploit_available = "available" in exploit_ease and "no " not in exploit_ease

        external_id = f"TNS-{plugin_id}-{ip.replace('.', '_') or dns or 'host'}"
        records.append({
            "source_tool": "Tenable",
            "external_id": external_id,
            "plugin_id": plugin_id,
            "title": name[:200],
            "description": (_get(r, "description") or _get(r, "synopsis"))[:4000],
            "synopsis": _get(r, "synopsis"),
            "solution": _get(r, "steps to remediate", "solution"),
            "severity": sev,
            "cvss_score": cvss or None,
            "cve": cves[0] if cves else None,
            "all_cves": cves,
            "family": "",                  # CSV exports omit plugin family
            "ip": ip,
            "dns_name": dns,
            "operating_system": _get(r, "operating system"),
            "port": _get(r, "port"),
            "protocol": _get(r, "protocol"),
            "epss": epss,
            "exploit_available": exploit_available,
            "first_seen": _get(r, "first discovered"),
            "last_seen": _get(r, "last observed"),
            "status": "open",
            "source_metadata": {
                "tenable_plugin_id": plugin_id,
                "tenable_ip": ip, "tenable_dns": dns,
                "tenable_port": _get(r, "port"), "tenable_protocol": _get(r, "protocol"),
                "exploit_ease": exploit_ease, "exploit_available": exploit_available,
                "all_cves": cves, "ingest": "csv_export",
                "first_discovered": _get(r, "first discovered"),
                "last_observed": _get(r, "last observed"),
            },
        })
    # worst-first, then cap
    records.sort(key=lambda x: -_SEV_ORDER.get(x["severity"], 0))
    if max_findings and len(records) > max_findings:
        log.info("[tenable-csv] %d records match severity %s; capping to %d",
                 len(records), severity, max_findings)
        records = records[:max_findings]
    log.info("[tenable-csv] parsed %d rows → %d raw records (severity=%s)",
             len(rows), len(records), severity)
    return records
