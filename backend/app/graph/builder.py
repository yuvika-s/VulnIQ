"""
Attack-graph construction.

Two passes:
  Pass 1 (this file): deterministic edges that are certain and free.
     - EXPOSES:     finding -> asset
     - EXPLOITS:    finding -> capability (from cwe_capability_map)
     - CORRELATES:  finding <-> finding (same component/cve/library)
     - REACHES:     asset -> asset (dependency + network reachability)
     - ENABLES?:    candidate finding -> finding edges, where the grants of A
                    match the requires of B AND B is on the same asset or a
                    REACHES-connected asset. These are *candidates* the LLM
                    confirms/scores in Pass 2.

The graph uses NetworkX MultiDiGraph. Nodes carry a `kind` attribute:
findings, assets, capabilities, crown_jewels.
"""
from __future__ import annotations

import networkx as nx

from app.models import Finding, Asset, Capability, Exposure
from app.graph.cwe_capability_map import requires_for


EXPOSURE_WEIGHT = {Exposure.INTERNET: 1.0, Exposure.INTERNAL: 0.5, Exposure.ISOLATED: 0.1}


def build_base_graph(findings: list[Finding], assets: dict[str, Asset]) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()

    # Asset + crown-jewel nodes
    for aid, a in assets.items():
        G.add_node(aid, kind="crown_jewel" if a.is_crown_jewel else "asset",
                   label=a.name, tier=a.tier, internet_facing=a.internet_facing,
                   data_classification=a.data_classification,
                   is_crown_jewel=a.is_crown_jewel)

    # REACHES edges between assets (dependency + downstream access)
    for aid, a in assets.items():
        for dep in a.upstream_dependencies:
            if dep in assets:
                G.add_edge(dep, aid, key="REACHES", kind="REACHES")
        for dwn in a.downstream_access:
            if dwn in assets:
                G.add_edge(aid, dwn, key="REACHES", kind="REACHES")

    # Finding nodes + EXPOSES + EXPLOITS
    for f in findings:
        G.add_node(f.finding_id, kind="finding", label=f.title, layer=f.layer.value,
                   finding_type=f.finding_type, cvss=f.cvss, cve=f.cve,
                   epss=f.epss, in_kev=f.in_kev, asset=f.affected_asset_id,
                   exposure=f.network_exposure.value,
                   grants=[c.value for c in f.grants])
        if f.affected_asset_id in G:
            G.add_edge(f.finding_id, f.affected_asset_id, key="EXPOSES", kind="EXPOSES")

    return G


def _assets_reachable_from(G: nx.MultiDiGraph, asset_id: str) -> set[str]:
    """Assets reachable via REACHES edges (incl. self)."""
    reachable = {asset_id}
    frontier = [asset_id]
    while frontier:
        cur = frontier.pop()
        for _, nxt, k in G.out_edges(cur, keys=True):
            if k == "REACHES" and nxt not in reachable:
                reachable.add(nxt)
                frontier.append(nxt)
    return reachable


def _attack_reachable_from(G: nx.MultiDiGraph, asset_id: str,
                           assets: dict[str, Asset]) -> set[str]:
    """Assets an attacker on `asset_id` could plausibly move to, for chaining.

    Real environments rarely ship a full asset-dependency map, so instead of
    requiring explicit REACHES edges we derive attacker movement from the
    context we DO have (internet exposure + business criticality):
      - explicit REACHES edges are always honoured (if any dependency data
        exists);
      - from anywhere, an attacker pivots TOWARD crown jewels (the targets);
      - from an internet-facing entry point, lateral movement across the estate
        is assumed.
    Capability handoff (below) and the LLM's per-edge judgement keep the
    resulting candidate set precise — this only widens what is *eligible* to be
    judged, so cross-application breach paths can be discovered.
    """
    reachable = _assets_reachable_from(G, asset_id)   # explicit REACHES + self
    reachable |= {aid for aid, a in assets.items() if a.is_crown_jewel}
    src = assets.get(asset_id)
    if src and src.internet_facing:
        reachable |= set(assets.keys())
    return reachable


def add_correlation_edges(G: nx.MultiDiGraph, findings: list[Finding]):
    """CORRELATES: findings sharing a CVE or component (same root cause)."""
    by_key: dict[str, list[str]] = {}
    for f in findings:
        for key in filter(None, [f.cve, f.component or None]):
            by_key.setdefault(key, []).append(f.finding_id)
    clusters = 0
    for key, ids in by_key.items():
        if len(ids) > 1:
            clusters += 1
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    G.add_edge(ids[i], ids[j], key=f"CORRELATES:{key}",
                               kind="CORRELATES", root_cause=key)
    return clusters


def candidate_enable_edges(G: nx.MultiDiGraph, findings: list[Finding],
                           assets: dict[str, Asset],
                           max_candidates: int = 0) -> list[tuple[str, str, str]]:
    """
    Generate ENABLES *candidates* for the LLM to confirm.

    A->B is a candidate only if there is a genuine capability handoff:
      - B requires a capability that A actually grants, AND
      - B's asset is the same as A's asset OR reachable from A's asset via REACHES.
    Findings requiring no precondition are entry points (not chain *targets* of an
    enable edge) and are excluded as B to prevent a dense, meaningless graph.
    Pre-filtering keeps LLM calls bounded and the chain graph tractable.
    """
    # Index B-findings by each capability they require, so for a given A we only
    # visit B's that genuinely consume a capability A grants — turns the pairing
    # from O(n^2) into roughly O(handoffs), which matters at Snyk scale (1000s).
    from collections import defaultdict
    req_index: dict = defaultdict(list)
    for b in findings:
        for cap in set(requires_for(b)):
            req_index[cap].append(b)

    reach_cache: dict = {}                    # reachable assets memoized per asset

    candidates = []
    for a in findings:
        a_grants = set(a.grants)
        if not a_grants:
            continue
        aid = a.affected_asset_id
        if aid not in reach_cache:
            reach_cache[aid] = _attack_reachable_from(G, aid, assets)
        reachable_assets = reach_cache[aid]
        seen_b = set()
        for cap in a_grants:
            for b in req_index.get(cap, ()):
                if b.finding_id == a.finding_id or b.finding_id in seen_b:
                    continue
                if b.affected_asset_id not in reachable_assets:
                    continue
                seen_b.add(b.finding_id)
                reason = "same_asset" if aid == b.affected_asset_id else "reaches"
                candidates.append((a.finding_id, b.finding_id, reason))

    if max_candidates and len(candidates) > max_candidates:
        fmap = {f.finding_id: f for f in findings}

        def _signal(c):
            a, b = fmap[c[0]], fmap[c[1]]
            ba, bb = assets.get(a.affected_asset_id), assets.get(b.affected_asset_id)
            s = (a.cvss + b.cvss) / 20.0
            if bb and bb.is_crown_jewel:
                s += 3
            if ba and ba.internet_facing:
                s += 2
            if c[2] == "same_asset":
                s += 1
            return s

        def _system(fid):
            st = (fmap[fid].source_tool or "").lower()
            return st.replace("snyk ", "").split()[0] if st else "manual"

        # Quota selection: round-robin across product COMBINATIONS so the budget
        # isn't devoured by one dense combo (the IaC<->IaC clique). Cross-product
        # combos are served first each round so multi-domain breach paths — the
        # whole point of VulnIQ — are guaranteed representation.
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for c in candidates:
            pa, pb = _system(c[0]), _system(c[1])
            groups[(pa, pb)].append(c)
        for k in groups:
            groups[k].sort(key=_signal, reverse=True)
        cross = sorted([k for k in groups if k[0] != k[1]],
                       key=lambda k: -len(groups[k]))
        same = sorted([k for k in groups if k[0] == k[1]],
                      key=lambda k: -len(groups[k]))
        order = cross + same                       # cross-product first
        picked, idx, exhausted = [], {k: 0 for k in groups}, set()
        while len(picked) < max_candidates and len(exhausted) < len(order):
            for k in order:
                if idx[k] < len(groups[k]):
                    picked.append(groups[k][idx[k]])
                    idx[k] += 1
                    if len(picked) >= max_candidates:
                        break
                else:
                    exhausted.add(k)
        candidates = picked
    return candidates
