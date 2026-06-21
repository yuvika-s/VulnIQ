"""
Snyk Enterprise connector — pulls findings from the Snyk REST API and turns them
into VulnIQ raw records. Snyk is just another finding *source*; the records it
emits flow into the exact same normalize -> graph -> chain -> prioritize pipeline
as manual uploads.

Design notes (validated against the live US API, version 2024-10-15):
  - Issues are fetched org-wide (one paginated call) and joined to their project
    for repo/branch/type context — far fewer calls than per-project.
  - Freshness: `updated_after` is applied server-side so only findings touched in
    the last SNYK_LOOKBACK_DAYS are pulled (no stale history).
  - The five Snyk products (Code / Open Source / IaC / Container / Secrets) are
    derived from the issue type + project type.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.ai_config import (SNYK_API_TOKEN, SNYK_ORG_ID, SNYK_REGION_BASE,
                           SNYK_API_VERSION, SNYK_LOOKBACK_DAYS, SNYK_SEVERITY,
                           SNYK_MAX_PER_PRODUCT, SNYK_IAC_LOOKBACK_DAYS,
                           configure_tls)

log = logging.getLogger("vulniq.snyk")

PAGE_LIMIT = 100
_CONTAINER_PT = {"deb", "rpm", "apk", "dockerfile", "linux", "apt"}
_IAC_PT = {"terraformconfig", "k8sconfig", "cloudformationconfig", "armconfig",
           "helmconfig", "terraformplan", "cloudconfig"}
_SECRET_HINTS = ("secret", "hardcoded", "credential", "api key", "api-key",
                 "private key", "token", "password")


class SnykError(Exception):
    pass


def _parse_repo(name: str) -> str:
    """Extract 'org/repo' from a Snyk project name. Handles both formats:
      'angel-one/repo(branch):path/file'   and
      'angel-one/repo:path/file'           and plain 'angel-one/repo'."""
    base = (name or "").split("(", 1)[0]      # drop (branch):file
    base = base.split(":", 1)[0]              # drop :path/file when no parens
    base = base.strip().strip("/")
    parts = [p for p in base.split("/") if p]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"       # org/repo
    return base


class SnykConnector:
    def __init__(self, token=None, org_id=None, base=None, version=None):
        self.token = token or SNYK_API_TOKEN
        self.org_id = org_id or SNYK_ORG_ID
        self.base = (base or SNYK_REGION_BASE).rstrip("/")
        self.version = version or SNYK_API_VERSION
        if not self.token:
            raise SnykError("SNYK_API_TOKEN is not set (.env)")
        if not self.org_id:
            raise SnykError("SNYK_ORG_ID is not set (.env)")
        self._headers = {"Authorization": f"token {self.token}",
                         "Accept": "application/vnd.api+json"}

    # ── public ────────────────────────────────────────────────────────────── #
    def _product_specs(self, lookback: int) -> list[dict]:
        """One fetch per Snyk product family so all five participate. Each has
        product-appropriate freshness + severity, and its own cap so the
        dependency-CVE flood can't crowd out Code / IaC / Secrets."""
        now = datetime.now(timezone.utc)
        d30 = (now - timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d_iac = (now - timedelta(days=max(lookback, SNYK_IAC_LOOKBACK_DAYS))
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return [
            # Snyk Code (SAST) + in-code Secrets — capability-rich, any severity.
            {"label": "code", "type": "code", "updated_after": d30,
             "severity": None, "cap": SNYK_MAX_PER_PRODUCT},
            # Snyk IaC (misconfig) — wide window (infrequent re-scans), any severity.
            {"label": "iac", "type": "config", "updated_after": d_iac,
             "severity": None, "cap": SNYK_MAX_PER_PRODUCT},
            # Open Source + Container — high volume, so apply the severity floor.
            {"label": "package_vulnerability", "type": "package_vulnerability",
             "updated_after": d30, "severity": SNYK_SEVERITY,
             "cap": SNYK_MAX_PER_PRODUCT},
        ]

    async def fetch_findings(self, lookback_days: int | None = None) -> list[dict]:
        """Return VulnIQ raw records across all Snyk products, joined to project
        context. Fetches per product family so Code / IaC / Secrets are never
        starved by the dependency-vulnerability volume."""
        import httpx
        configure_tls()                       # trust the corporate/Zscaler root
        lookback = lookback_days if lookback_days is not None else SNYK_LOOKBACK_DAYS

        async with httpx.AsyncClient(timeout=45) as client:
            self._client = client
            projects = await self._projects()
            log.info("[snyk] %d projects in org", len(projects))
            issues = []
            for spec in self._product_specs(lookback):
                got = await self._issues_for(spec)
                log.info("[snyk] %s: %d issues", spec["label"], len(got))
                issues.extend(got)

        oldest = datetime(2000, 1, 1, tzinfo=timezone.utc)   # transform keeps all fetched
        records = []
        for issue in issues:
            try:
                rec = self._to_record(issue, projects, oldest)
                if rec is not None:
                    records.append(rec)
            except Exception as exc:                     # never lose the whole sync
                log.warning("[snyk] skipping issue %s: %s", issue.get("id", "?"), exc)
        # NOTE: volume is bounded by the per-product caps (SNYK_MAX_PER_PRODUCT).
        # We deliberately do NOT truncate the combined list here — doing so would
        # bias against whichever product is fetched last (e.g. drop all Open
        # Source / Container because they trail Code + IaC in the list).
        log.info("[snyk] %d records normalized across all products", len(records))
        return records

    # ── private API ───────────────────────────────────────────────────────── #
    async def _projects(self) -> dict:
        url = f"{self.base}/orgs/{self.org_id}/projects"
        data = await self._paginate(url, {"version": self.version, "limit": PAGE_LIMIT})
        out = {}
        for p in data:
            a = p.get("attributes", {})
            name = a.get("name", "")
            repo = _parse_repo(name)                       # robust org/repo extraction
            out[p["id"]] = {
                "name": name,
                "repository": repo,
                "repo_short": repo.split("/")[1] if repo.count("/") >= 1 else repo,
                "branch": a.get("target_reference", ""),
                "type": (a.get("type") or "").lower(),
                "origin": a.get("origin", ""),
                "business_criticality": a.get("business_criticality", []),
                "tags": a.get("tags", []),
                "target_file": a.get("target_file", ""),
            }
        return out

    async def _issues_for(self, spec: dict) -> list[dict]:
        url = f"{self.base}/orgs/{self.org_id}/issues"
        params = {"version": self.version, "limit": PAGE_LIMIT, "status": "open",
                  "type": spec["type"], "updated_after": spec["updated_after"]}
        # Severity floor (comma-separated, server-side; repeated keys 400). Only
        # applied where spec asks for it (the high-volume dependency product).
        sev = (spec.get("severity") or "").strip().lower()
        if sev and sev != "all":
            params["effective_severity_level"] = ",".join(
                s.strip() for s in sev.split(",") if s.strip())
        return await self._paginate(url, params, max_items=spec.get("cap", 0))

    async def _get_with_retry(self, url, params, retries: int = 4):
        """GET with backoff retry on TRANSIENT network errors. Behind an
        HTTPS-inspecting proxy (Zscaler) a long multi-page sync regularly sees a
        connection dropped mid-response (httpx.ReadError / RemoteProtocolError /
        a read timeout). Without a retry a single dropped page aborts the whole
        sync. Auth/HTTP status errors are NOT retried — they're not transient."""
        import asyncio
        import httpx
        transient = (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError,
                     httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout,
                     httpx.WriteError)
        last = None
        for attempt in range(retries):
            try:
                return await self._client.get(url, headers=self._headers, params=params)
            except transient as exc:
                last = exc
                wait = min(2 ** attempt, 8) * 0.5            # 0.5, 1, 2, 4s
                log.warning("[snyk] transient network error (%s) on attempt %d/%d; "
                            "retrying in %.1fs", type(exc).__name__, attempt + 1,
                            retries, wait)
                await asyncio.sleep(wait)
        raise SnykError(f"Snyk request failed after {retries} attempts "
                        f"({type(last).__name__}: {last}) — likely a proxy/network "
                        f"drop; re-run the sync")

    async def _paginate(self, url, params, max_items: int = 0) -> list[dict]:
        from urllib.parse import urlsplit, parse_qsl
        sp = urlsplit(self.base)
        origin = f"{sp.scheme}://{sp.netloc}"
        results, next_url, pages = [], url, 0
        while next_url and pages < 200:                  # hard safety cap
            r = await self._get_with_retry(next_url, params)
            if r.status_code in (401, 403):
                raise SnykError(f"Snyk auth failed ({r.status_code}) — check token/org/region")
            r.raise_for_status()
            body = r.json()
            results.extend(body.get("data", []))
            if max_items and len(results) >= max_items:  # severity-first; stop early
                return results[:max_items]
            nxt = body.get("links", {}).get("next")
            if not nxt:
                break
            # Snyk's next link embeds a percent-encoded cursor (…%3D). Split path
            # from query and pass params as a dict so httpx encodes it exactly
            # once — passing the raw URL would double-encode and 404.
            parts = urlsplit(nxt)
            next_url = origin + parts.path
            params = dict(parse_qsl(parts.query))
            pages += 1
        return results

    # ── transform ─────────────────────────────────────────────────────────── #
    def _to_record(self, issue, projects, since) -> dict | None:
        a = issue.get("attributes", {})
        # freshness double-check (server filter + client safety net)
        upd = a.get("updated_at") or a.get("created_at") or ""
        if upd:
            try:
                if datetime.fromisoformat(upd.replace("Z", "+00:00")) < since:
                    return None
            except Exception:
                pass

        proj_id = (issue.get("relationships", {}).get("scan_item", {})
                   .get("data", {}).get("id", ""))
        proj = projects.get(proj_id, {})
        issue_type = (a.get("type") or "").lower()
        product = self._product(issue_type, proj.get("type", ""), a.get("title", ""), a)

        # identifiers
        cwes = [c["id"] for c in a.get("classes", []) if (c.get("source") or "").upper() == "CWE"]
        cves = [p["id"] for p in a.get("problems", [])
                if (p.get("source") or "").upper() in ("NVD", "CVE")
                or str(p.get("id", "")).upper().startswith("CVE-")]

        # CVSS — prefer Snyk's score, else the highest reported
        sev_list = a.get("severities", []) or []
        cvss = None
        snyk_sev = next((s for s in sev_list if (s.get("source") or "") == "Snyk"), None)
        if snyk_sev and snyk_sev.get("score") is not None:
            cvss = snyk_sev["score"]
        else:
            scores = [s["score"] for s in sev_list if s.get("score") is not None]
            cvss = max(scores) if scores else None

        # package / version / fix
        coords = a.get("coordinates", []) or [{}]
        c0 = coords[0] if coords else {}
        rep = (c0.get("representations") or [{}])[0]
        dep = rep.get("dependency", {}) if isinstance(rep, dict) else {}
        pkg = dep.get("package_name", "")
        ver = dep.get("package_version", "")
        component = f"{pkg}@{ver}" if pkg and ver else (pkg or "")
        fix_version = ""
        remediation = ""
        for rem in (c0.get("remedies") or []):
            fixed = (((rem.get("meta") or {}).get("data") or {}).get("fixed_in") or [])
            if fixed:
                fix_version = fixed[0]
                remediation = f"Upgrade {pkg or 'package'} to {fix_version}"
                break

        # exploit maturity
        maturity = ""
        for m in (a.get("exploit_details", {}) or {}).get("maturity_levels", []):
            lvl = (m.get("level") or "")
            if lvl and lvl.lower() not in ("not defined", "no data"):
                maturity = lvl
                break

        return {
            "source_tool": product,
            "external_id": issue.get("id", ""),
            "title": a.get("title", "Unknown vulnerability"),
            "description": a.get("description", "") or "",
            "severity": (a.get("effective_severity_level") or "medium").upper(),
            "cvss_score": cvss,
            "cve": cves[0] if cves else None,
            "cwe": cwes[0] if cwes else None,
            "issue_type": issue_type,
            "package": pkg,
            "version": ver,
            "affected_component": component,
            "fix_version": fix_version,
            "remediation": remediation,
            "exploit_maturity": maturity,
            "status": a.get("status", "open"),
            "discovered_at": a.get("created_at", ""),
            "updated_at": a.get("updated_at", ""),
            # project / asset context
            "project_id": proj_id,
            "project_name": proj.get("name", ""),
            "repository": proj.get("repository", ""),
            "repo_short": proj.get("repo_short", ""),
            "branch": proj.get("branch", ""),
            "target_file": proj.get("target_file", ""),
            "tags": proj.get("tags", []),
            # preserved raw metadata
            "source_metadata": {
                "snyk_issue_id": issue.get("id", ""),
                "snyk_project_id": proj_id,
                "snyk_issue_type": issue_type,
                "snyk_project_type": proj.get("type", ""),
                "snyk_origin": proj.get("origin", ""),
                "snyk_url": f"https://app.us.snyk.io/org/{self.org_id}/project/{proj_id}",
                "all_cves": cves,
                "all_cwes": cwes,
                "reachability": c0.get("reachability", ""),
            },
        }

    @staticmethod
    def _product(issue_type: str, project_type: str, title: str, attrs: dict) -> str:
        pt = (project_type or "").lower()
        low_title = (title or "").lower()
        if issue_type == "code":
            if any(h in low_title for h in _SECRET_HINTS):
                return "Snyk Secrets"
            return "Snyk Code"
        if issue_type in ("cloud", "config", "iac", "misconfiguration") or pt in _IAC_PT:
            return "Snyk IaC"
        if pt in _CONTAINER_PT:
            return "Snyk Container"
        if issue_type in ("package_vulnerability", "license"):
            return "Snyk Open Source"
        return "Snyk Open Source"
