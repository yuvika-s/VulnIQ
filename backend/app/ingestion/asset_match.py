"""
Repo -> Application matcher.

Findings come in tagged with a *repo* slug (e.g. "nxt-orchestrator",
"amx-margin-maker"). The asset inventory is a list of *applications*
(e.g. "NXT", "AMX Risk UI"). AngelOne's GitHub repos almost always carry the
application name as a token inside the repo name, so we can attach a repo
finding to its application by matching distinctive application-name tokens
against the repo slug. The application then provides the criticality /
internet-facing context used for prioritization and chaining.

This is a deterministic, transparent heuristic — no LLM — so the mapping is
auditable and stable across uploads.
"""
from __future__ import annotations

import re

# Generic words that appear in many application names and therefore carry no
# discriminating power for repo->app matching. Matching on these would create
# false links (e.g. every "*-admin" repo hitting every "* Admin Portal" app).
_STOPWORDS = {
    "admin", "portal", "back", "office", "dashboard", "app", "apps",
    "application", "web", "api", "service", "services", "internal", "external",
    "customer", "partner", "trading", "mobile", "vendor", "platform", "prod",
    "production", "the", "and", "ui", "ux", "server", "system", "tool",
    "management", "reset", "password", "creation", "deletion", "registration",
}


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t]


def build_app_index(assets: dict) -> dict:
    """Map distinctive token -> list of asset_ids that contain it.

    Only applications (assets) contribute. Tokens shorter than 3 chars or in
    the stopword list are ignored.
    """
    index: dict[str, list[str]] = {}
    for aid, a in assets.items():
        name = getattr(a, "name", "") or ""
        toks = set(_tokens(name)) | set(_tokens(aid))
        for t in toks:
            if len(t) < 3 or t in _STOPWORDS:
                continue
            index.setdefault(t, [])
            if aid not in index[t]:
                index[t].append(aid)
    return index


def match_repo_to_app(repo_slug: str, assets: dict, index: dict | None = None):
    """Return (asset_id, matched_token) for the best application match, or
    (None, None). A repo matches an app when a distinctive app token appears in
    the repo slug. The longest token wins (most specific); ties are broken
    toward internet-facing crown jewels, then the shorter application name.
    """
    if not repo_slug:
        return None, None
    # exact inventory hit first
    if repo_slug in assets:
        return repo_slug, repo_slug
    if index is None:
        index = build_app_index(assets)

    repo_tokens = set(_tokens(repo_slug))
    repo_str = repo_slug.lower()

    # candidate (asset_id, token) where the app token is present in the repo
    candidates: list[tuple[str, str]] = []
    for token, aids in index.items():
        hit = token in repo_tokens or token in repo_str
        if not hit:
            continue
        for aid in aids:
            candidates.append((aid, token))
    if not candidates:
        return None, None

    def rank(c):
        aid, token = c
        a = assets[aid]
        return (
            len(token),                              # longest/most specific token
            1 if getattr(a, "is_crown_jewel", False) else 0,
            1 if getattr(a, "internet_facing", False) else 0,
            -len(getattr(a, "name", aid)),           # prefer shorter app name
        )

    best_aid, best_token = max(candidates, key=rank)
    return best_aid, best_token
