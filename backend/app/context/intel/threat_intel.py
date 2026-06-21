"""
Threat-intelligence enrichment.

Pulls EPSS (exploit probability) and CISA KEV (known-exploited) for each CVE.
These are FREE public APIs with no auth. We cache aggressively and fall back to
sensible offline values so a demo never breaks on a flaky conference network.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

CACHE_FILE = os.path.join(os.path.dirname(__file__), "_intel_cache.json")
_cache: dict | None = None

# Offline fallback EPSS scores for the well-known CVEs in our dataset, so the
# demo still shows differentiated exploit likelihoods without network access.
EPSS_FALLBACK = {
    "CVE-2021-44228": 0.975,  # Log4Shell - extremely high
    "CVE-2022-22965": 0.972,  # Spring4Shell
    "CVE-2023-34362": 0.94,   # MOVEit
    "CVE-2023-4966": 0.93,    # CitrixBleed
    "CVE-2017-5638": 0.975,   # Struts2
    "CVE-2023-22515": 0.91,   # Confluence
    "CVE-2024-21762": 0.88,   # FortiOS
    "CVE-2022-3602": 0.12,    # OpenSSL - lower
}

KEV_FALLBACK = {
    "CVE-2021-44228", "CVE-2022-22965", "CVE-2023-34362", "CVE-2023-4966",
    "CVE-2017-5638", "CVE-2023-22515", "CVE-2024-21762",
}


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                _cache = json.load(f)
        else:
            _cache = {"epss": {}, "kev": None}
    return _cache


def _save_cache():
    if _cache is not None:
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f)


def _http_get(url: str, timeout: float = 4.0) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnIQ/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
        return None


def get_epss(cve: str) -> float:
    """Exploit Prediction Scoring System probability (0-1)."""
    if not cve:
        return 0.0
    cache = _load_cache()
    if cve in cache["epss"]:
        return cache["epss"][cve]

    data = _http_get(f"https://api.first.org/data/v1/epss?cve={cve}")
    score = None
    if data and data.get("data"):
        try:
            score = float(data["data"][0]["epss"])
        except (KeyError, IndexError, ValueError):
            score = None
    if score is None:
        score = EPSS_FALLBACK.get(cve, 0.05)  # generic low default

    cache["epss"][cve] = score
    _save_cache()
    return score


def _load_kev_set() -> set[str]:
    cache = _load_cache()
    if cache.get("kev"):
        return set(cache["kev"])
    data = _http_get("https://www.cisa.gov/sites/default/files/feeds/"
                     "known_exploited_vulnerabilities.json", timeout=6.0)
    if data and data.get("vulnerabilities"):
        kev = {v["cveID"] for v in data["vulnerabilities"]}
    else:
        kev = set(KEV_FALLBACK)
    cache["kev"] = sorted(kev)
    _save_cache()
    return kev


def in_kev(cve: str) -> bool:
    if not cve:
        return False
    return cve in _load_kev_set()


def enrich(finding):
    """Mutate a Finding with live EPSS + KEV signals."""
    if finding.cve:
        finding.epss = get_epss(finding.cve)
        finding.in_kev = in_kev(finding.cve)
    else:
        # non-CVE findings: estimate exploitability from CVSS
        finding.epss = min(0.6, finding.cvss / 10.0 * 0.6)
        finding.in_kev = False
    return finding


def enrich_many(findings):
    """Enrich a batch of findings efficiently. Fetches EPSS for every unique,
    uncached CVE in a few batched FIRST.org calls (comma-separated) instead of
    one HTTP request per finding — essential when a Snyk sync brings thousands
    of findings. KEV is loaded once. Falls back to cache/defaults offline."""
    cache = _load_cache()
    kev = _load_kev_set()
    todo = sorted({f.cve for f in findings if f.cve and f.cve not in cache["epss"]})
    BATCH = 80
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        data = _http_get("https://api.first.org/data/v1/epss?cve="
                         + ",".join(chunk) + f"&limit={len(chunk)}", timeout=8.0)
        got = {}
        if data and data.get("data"):
            for row in data["data"]:
                try:
                    got[row["cve"]] = float(row["epss"])
                except (KeyError, ValueError):
                    pass
        for cve in chunk:
            cache["epss"][cve] = got.get(cve, EPSS_FALLBACK.get(cve, 0.05))
    _save_cache()
    for f in findings:
        if f.cve:
            f.epss = cache["epss"].get(f.cve, 0.05)
            f.in_kev = f.cve in kev
        else:
            f.epss = min(0.6, (f.cvss or 0) / 10.0 * 0.6)
            f.in_kev = False
    return findings
