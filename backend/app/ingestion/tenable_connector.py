"""
Tenable Security Center (Tenable.sc) connector.

Pulls cumulative vulnerability findings from SC's /rest/analysis endpoint and
emits VulnIQ *raw records* — the same intermediate shape Snyk emits — which then
flow through tenable_normalize -> the unified Finding schema -> the one shared
graph/chain/prioritize engine. Tenable is a finding SOURCE, never a parallel
pipeline.

Validated against a live SC 6.x instance (release 2026-02). Notable real-world
field shapes this code relies on (the SC schema differs from the public docs in
places):
  - plugin family lives in `family.name` (top-level `pluginFamily` is null)
  - severity is an object: `severity.id` in {0..4}, `severity.name`
  - SC already provides `epssScore` and `exploitAvailable` ("Yes"/"No")
  - one row per (plugin, host); `ip` + `dnsName` + `operatingSystem` per row

Auth is the SC API-key header: `X-APIKey: accesskey=<a>; secretkey=<s>`.
On-prem SC uses a self-signed cert, so TLS verification defaults OFF
(TENABLE_VERIFY_SSL=true to enforce a CA-signed cert).
"""
from __future__ import annotations

import logging

from app.ai_config import (TENABLE_BASE_URL, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY,
                           TENABLE_VERIFY_SSL, TENABLE_SEVERITY, TENABLE_MAX_FINDINGS,
                           insecure_ssl_context)

log = logging.getLogger("vulniq.tenable")

# Tenable severity id -> label/order. We fetch Critical first, then High, so a
# capped sync keeps the highest-signal findings.
_SEV_ID = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_LABEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
_PAGE = 500


class TenableError(Exception):
    pass


class TenableConnector:
    def __init__(self, base=None, access_key=None, secret_key=None, verify=None):
        self.base = (base or TENABLE_BASE_URL).rstrip("/")
        self.access_key = access_key or TENABLE_ACCESS_KEY
        self.secret_key = secret_key or TENABLE_SECRET_KEY
        verify_flag = TENABLE_VERIFY_SSL if verify is None else verify
        # verify=True -> normal verification (truststore/OS store handles CA-signed
        # SC). verify=False -> a genuine unverified context that the corporate
        # truststore can't override (on-prem self-signed SC).
        self.verify = True if verify_flag else insecure_ssl_context()
        if not self.base:
            raise TenableError("TENABLE_BASE_URL is not set (.env)")
        if not (self.access_key and self.secret_key):
            raise TenableError("TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY not set (.env)")
        self._headers = {
            "X-APIKey": f"accesskey={self.access_key}; secretkey={self.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ── public ────────────────────────────────────────────────────────────── #
    def fetch_findings(self, max_findings: int | None = None,
                       severity: str | None = None) -> list[dict]:
        """Return VulnIQ raw records across the requested severities, bounded by
        max_findings. Each severity gets a fair QUOTA of the cap (highest first)
        so a flood of Critical/High host CVEs can't crowd Medium findings out of
        the budget — Medium pivots are exactly what complete attack chains.
        Synchronous (httpx.Client); the sync orchestrator runs it off the loop."""
        import httpx

        cap = max_findings if max_findings is not None else TENABLE_MAX_FINDINGS
        sev_ids = self._severity_ids(severity)        # Critical -> High -> Medium …
        # Even quota per severity; any unused share rolls forward to the next
        # (so a thin severity doesn't waste budget and we still fill to cap).
        per_sev = (cap // len(sev_ids)) if cap and sev_ids else cap
        leftover = 0

        records: list[dict] = []
        with httpx.Client(base_url=self.base, headers=self._headers,
                          verify=self.verify, timeout=60) as client:
            self._client = client
            for sid in sev_ids:
                budget = (per_sev + leftover) if cap else 0
                got = self._fetch_severity(sid, budget)
                if cap:
                    leftover = max(0, budget - len(got))
                log.info("[tenable] severity %s: %d records (budget %s)",
                         _SEV_LABEL.get(sid, sid), len(got), budget or "all")
                for raw in got:
                    rec = self._to_record(raw)
                    if rec:
                        records.append(rec)
        log.info("[tenable] %d raw records normalized across %d severities",
                 len(records), len(sev_ids))
        return records

    def health(self) -> dict:
        """Lightweight connectivity/auth check used by the status endpoint."""
        import httpx
        with httpx.Client(base_url=self.base, headers=self._headers,
                          verify=self.verify, timeout=20) as client:
            r = client.get("/rest/currentUser")
            if r.status_code in (401, 403):
                raise TenableError(f"Tenable auth failed ({r.status_code}) — check API keys")
            r.raise_for_status()
            u = r.json().get("response", {})
            return {"ok": True, "username": u.get("username", ""), "user_id": u.get("id", "")}

    # ── private ───────────────────────────────────────────────────────────── #
    def _severity_ids(self, severity: str | None) -> list[int]:
        sev = (severity or TENABLE_SEVERITY or "critical,high").strip().lower()
        if sev in ("", "all"):
            ids = [4, 3, 2, 1]
        else:
            ids = [_SEV_ID[s.strip()] for s in sev.split(",")
                   if s.strip() in _SEV_ID]
        # always Critical -> High -> … so a capped pull keeps the worst first
        return sorted(set(ids), reverse=True)

    def _post_with_retry(self, path: str, payload: dict, retries: int = 4):
        """POST with backoff retry on TRANSIENT network errors so one dropped
        page doesn't abort the whole sync. Auth/HTTP errors are not retried."""
        import time
        import httpx
        transient = (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError,
                     httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout,
                     httpx.WriteError)
        last = None
        for attempt in range(retries):
            try:
                return self._client.post(path, json=payload)
            except transient as exc:
                last = exc
                wait = min(2 ** attempt, 8) * 0.5
                log.warning("[tenable] transient network error (%s) on attempt %d/%d; "
                            "retrying in %.1fs", type(exc).__name__, attempt + 1,
                            retries, wait)
                time.sleep(wait)
        raise TenableError(f"Tenable request failed after {retries} attempts "
                           f"({type(last).__name__}: {last}) — likely a network "
                           f"drop; re-run the sync")

    def _fetch_severity(self, sev_id: int, cap: int) -> list[dict]:
        out: list[dict] = []
        offset = 0
        while True:
            end = offset + _PAGE
            payload = {
                "type": "vuln",
                "sourceType": "cumulative",
                "query": {
                    "tool": "vulndetails",
                    "type": "vuln",
                    "startOffset": offset,
                    "endOffset": end,
                    "filters": [{"filterName": "severity", "operator": "=",
                                 "value": str(sev_id)}],
                },
                "startOffset": offset,
                "endOffset": end,
            }
            r = self._post_with_retry("/rest/analysis", payload)
            if r.status_code in (401, 403):
                raise TenableError(f"Tenable auth failed ({r.status_code}) — check API keys")
            r.raise_for_status()
            resp = r.json().get("response", {})
            results = resp.get("results", []) or []
            out.extend(results)
            total = int(resp.get("totalRecords", 0) or 0)
            offset += _PAGE
            if not results or offset >= total:
                break
            if cap and len(out) >= cap:
                break
        return out[:cap] if cap else out

    @staticmethod
    def _csv(val: str) -> list[str]:
        return [x.strip() for x in (val or "").split(",") if x.strip()]

    def _to_record(self, v: dict) -> dict | None:
        """One SC vulndetails row -> VulnIQ raw record (kept source-shaped; the
        normalizer maps it into the unified Finding schema)."""
        sev = v.get("severity") or {}
        sev_id = int(sev.get("id", 2) or 2)
        family = (v.get("family") or {}).get("name", "") or "General"
        plugin_id = str(v.get("pluginID", "") or "")
        plugin_name = v.get("pluginName", "") or "Unknown plugin"
        ip = (v.get("ip") or "").strip()
        dns = (v.get("dnsName") or "").strip()
        cves = self._csv(v.get("cve", ""))

        # CVSS: prefer v3 base, else legacy base score
        def _f(x):
            try:
                return float(x)
            except (TypeError, ValueError):
                return 0.0
        cvss = _f(v.get("cvssV3BaseScore")) or _f(v.get("baseScore"))

        # SC ships EPSS + exploit availability directly — carry them through so
        # threat-intel enrichment can prefer real values over a CVE lookup.
        epss = _f(v.get("epssScore"))
        exploit_available = (v.get("exploitAvailable") or "").strip().lower() == "yes"

        # stable id per (plugin, host) so re-syncs update rather than duplicate
        external_id = f"TNS-{plugin_id}-{ip.replace('.', '_') or dns or 'host'}"

        return {
            "source_tool": "Tenable",
            "external_id": external_id,
            "plugin_id": plugin_id,
            "title": plugin_name[:200],
            "description": (v.get("description") or v.get("synopsis") or "")[:4000],
            "synopsis": v.get("synopsis", ""),
            "solution": v.get("solution", ""),
            "severity": _SEV_LABEL.get(sev_id, "medium"),
            "cvss_score": cvss or None,
            "cve": cves[0] if cves else None,
            "all_cves": cves,
            "family": family,
            "ip": ip,
            "dns_name": dns,
            "operating_system": v.get("operatingSystem", ""),
            "port": str(v.get("port", "") or ""),
            "protocol": v.get("protocol", ""),
            "epss": epss,
            "exploit_available": exploit_available,
            "first_seen": v.get("firstSeen", ""),
            "last_seen": v.get("lastSeen", ""),
            "status": "open",
            "source_metadata": {
                "tenable_plugin_id": plugin_id,
                "tenable_family": family,
                "tenable_ip": ip,
                "tenable_dns": dns,
                "tenable_port": str(v.get("port", "") or ""),
                "tenable_protocol": v.get("protocol", ""),
                "tenable_repository": (v.get("repository") or {}).get("name", ""),
                "exploit_available": exploit_available,
                "exploit_ease": v.get("exploitEase", ""),
                "vpr_score": v.get("vprScore", ""),
                "all_cves": cves,
                "operating_system": v.get("operatingSystem", ""),
            },
        }
