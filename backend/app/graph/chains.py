"""
Chain analysis: turn the graph into ranked attack chains and finding priorities.

Steps:
  1. Add confirmed ENABLES edges (from the edge agent) to the graph.
  2. Find chains: paths of findings from an internet/internal-exposed ENTRY
     finding, through ENABLES edges, to a finding whose asset (or a REACHES-
     reachable asset) is a crown jewel.
  3. Score each chain: ChainRisk = EntryExposure x ExploitLikelihood
        x PathFeasibility x CrownJewelValue x ControlGap
  4. Prioritize findings by betweenness centrality on the high-risk subgraph:
     a finding on many high-risk chains = "break-chain critical".
"""
from __future__ import annotations

import networkx as nx

from app.models import Finding, Asset, AttackChain, Priority, Exposure
from app.graph.builder import EXPOSURE_WEIGHT, _assets_reachable_from
from app.graph.objectives import objectives_for

MAX_CHAIN_LEN = 6
MAX_PATHS_PER_PAIR = 40
MAX_TOTAL_CHAINS = 500


def add_enable_edges(G: nx.MultiDiGraph, edges: list[dict]):
    for e in edges:
        G.add_edge(e["a"], e["b"], key="ENABLES", kind="ENABLES",
                   confidence=e["confidence"], rationale=e["rationale"],
                   method=e.get("method", "llm"))


def _finding_enable_subgraph(G: nx.MultiDiGraph) -> nx.DiGraph:
    """Project to a simple finding->finding DiGraph over ENABLES edges."""
    H = nx.DiGraph()
    for n, d in G.nodes(data=True):
        if d.get("kind") == "finding":
            H.add_node(n, **d)
    for u, v, k, d in G.edges(keys=True, data=True):
        if k == "ENABLES":
            if H.has_edge(u, v):
                H[u][v]["confidence"] = max(H[u][v]["confidence"], d["confidence"])
            else:
                H.add_edge(u, v, confidence=d["confidence"], rationale=d["rationale"])
    return H


def _crown_jewel_findings(findings, assets, G) -> set[str]:
    """Findings that sit on (or can reach) a crown jewel."""
    cj_assets = {aid for aid, a in assets.items() if a.is_crown_jewel}
    out = set()
    for f in findings:
        reach = _assets_reachable_from(G, f.affected_asset_id)
        if reach & cj_assets:
            out.add(f.finding_id)
    return out


def _entry_findings(findings) -> set[str]:
    """Valid chain entry points: exposed (not isolated), and actually grant a
    capability (i.e. not inert hygiene noise)."""
    out = set()
    for f in findings:
        if f.network_exposure == Exposure.ISOLATED:
            continue
        if not f.grants:
            continue
        out.add(f.finding_id)
    return out


def find_chains(G, findings, assets) -> list[AttackChain]:
    fmap = {f.finding_id: f for f in findings}
    H = _finding_enable_subgraph(G)
    entries = _entry_findings(findings)
    targets = _crown_jewel_findings(findings, assets, G)

    chains: list[AttackChain] = []
    cid = 0
    seen_paths = set()

    for entry in entries:
        if entry not in H:
            continue
        for target in targets:
            if target not in H or entry == target:
                continue
            try:
                paths = nx.all_simple_paths(H, entry, target, cutoff=MAX_CHAIN_LEN)
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
            per_pair = 0
            for path in paths:
                if per_pair >= MAX_PATHS_PER_PAIR:
                    break
                sig = tuple(path)
                if sig in seen_paths or len(path) < 2:
                    continue
                seen_paths.add(sig)
                per_pair += 1
                cid += 1
                chain = _score_chain(f"CH-{cid:04d}", path, fmap, assets, G, H)
                if chain.chain_risk > 0:
                    chains.append(chain)
            if len(chains) >= MAX_TOTAL_CHAINS:
                break
        if len(chains) >= MAX_TOTAL_CHAINS:
            break

    # Favor well-evidenced chains: rank by risk weighted by chain confidence, so
    # a speculative high-risk path doesn't outrank a confident one.
    chains.sort(key=lambda c: c.chain_risk * (0.3 + 0.7 * c.chain_confidence / 100.0),
                reverse=True)
    return chains


def _score_chain(chain_id, path, fmap, assets, G, H) -> AttackChain:
    entry_f = fmap[path[0]]
    target_f = fmap[path[-1]]

    # EntryExposure
    entry_exposure = EXPOSURE_WEIGHT.get(entry_f.network_exposure, 0.3)

    # ExploitLikelihood: max EPSS along path, boosted by any KEV presence
    epss_vals = [fmap[p].epss for p in path]
    exploit_likelihood = max(epss_vals) if epss_vals else 0.1
    if any(fmap[p].in_kev for p in path):
        exploit_likelihood = min(1.0, exploit_likelihood + 0.15)

    # PathFeasibility: product of edge confidences
    feasibility = 1.0
    for u, v in zip(path, path[1:]):
        c = H[u][v]["confidence"] if H.has_edge(u, v) else 0.5
        feasibility *= c

    # CrownJewelValue: from target asset tier + crown jewel + data class
    reach = _assets_reachable_from(G, target_f.affected_asset_id)
    cj_value = 0.5
    crown_jewel = target_f.affected_asset_id
    for aid in reach:
        a = assets.get(aid)
        if a and a.is_crown_jewel:
            crown_jewel = aid
            funds = "funds" in a.data_classification.lower()
            cj_value = 1.0 if funds else 0.9
            break

    # ControlGap: reduce if compensating controls on path assets
    path_assets = {fmap[p].affected_asset_id for p in path}
    controls = 0
    for aid in path_assets:
        a = assets.get(aid)
        if a:
            controls += len(a.compensating_controls)
    control_gap = max(0.4, 1.0 - 0.1 * controls)

    risk = entry_exposure * exploit_likelihood * feasibility * cj_value * control_gap

    # --- objective-driven layer ---
    objectives, primary, obj_score = _objective_reachability(path, fmap, assets, crown_jewel)
    realism = _realism_score(path, fmap, assets, entry_f, feasibility)
    attack_path = _attack_path_narrative(path, fmap, assets, primary, crown_jewel)

    # --- evidence validation layer ---
    from app.graph.evidence import edge_evidence, chain_confidence as _chain_conf
    from app.ai_config import CHAIN_CONFIDENCE_MIN
    edges = []
    for u, v in zip(path, path[1:]):
        ec = H[u][v]["confidence"] if H.has_edge(u, v) else 0.5
        erat = H[u][v].get("rationale", "") if H.has_edge(u, v) else ""
        edges.append(edge_evidence(
            fmap[u], fmap[v], assets.get(fmap[u].affected_asset_id),
            assets.get(fmap[v].affected_asset_id), G, ec, erat))
    chain_conf, breakdown = _chain_conf(
        edges, [fmap[p] for p in path],
        max_epss=(max(epss_vals) if epss_vals else 0.0),
        any_kev=any(fmap[p].in_kev for p in path))
    speculative = chain_conf < CHAIN_CONFIDENCE_MIN
    evidence_steps = _evidence_steps(path, fmap, assets, edges, primary, chain_conf, crown_jewel)

    # composition metrics: which source products + how many assets this path spans
    products = sorted({(fmap[p].sources[0] if fmap[p].sources else fmap[p].source_tool)
                       for p in path})
    num_assets = len({fmap[p].affected_asset_id for p in path})

    return AttackChain(
        chain_id=chain_id,
        finding_ids=list(path),
        asset_path=[fmap[p].affected_asset_id for p in path],
        entry_finding=path[0],
        crown_jewel=crown_jewel,
        chain_risk=round(risk * 100, 1),
        entry_exposure=round(entry_exposure, 2),
        exploit_likelihood=round(exploit_likelihood, 3),
        path_feasibility=round(feasibility, 3),
        crown_jewel_value=round(cj_value, 2),
        control_gap=round(control_gap, 2),
        objectives=objectives,
        primary_objective=primary,
        objective_reachability_score=obj_score,
        realism_score=realism,
        attack_path=attack_path,
        edges=edges,
        products=products,
        num_products=len(products),
        num_assets=num_assets,
        chain_confidence=chain_conf,
        confidence_breakdown=breakdown,
        evidence_steps=evidence_steps,
        speculative=speculative,
    )


def _evidence_steps(path, fmap, assets, edges, primary, conf, crown_jewel):
    """Human 'why this chain is valid' walk: finding -> evidence -> finding ->
    ... -> objective, with the confidence. Mirrors the requested example."""
    from app.graph.objectives import objective_label
    steps = []
    for i, fid in enumerate(path):
        f = fmap[fid]
        a = assets.get(f.affected_asset_id)
        steps.append({"kind": "node", "title": f.title,
                      "detail": f"{f.finding_type} on {a.name if a else f.affected_asset_id}"})
        if i < len(edges):
            e = edges[i]
            ev = sorted(e["evidence"], key=lambda x: -x["strength"])
            why = next((x for x in ev if x["type"] in
                        ("identity", "cloud_role", "k8s", "network", "service_trust")),
                       ev[0] if ev else None)
            steps.append({"kind": "edge",
                          "handoff": e["capability_handoff"],
                          "why": why["note"] if why else "",
                          "verdict": why["verdict"] if why else "",
                          "confidence": round(e["validation_confidence"] * 100)})
    steps.append({"kind": "objective",
                  "objective": objective_label(primary) if primary else f"reach {crown_jewel}",
                  "chain_confidence": conf})
    return steps


def _objective_reachability(path, fmap, assets, crown_jewel):
    """Objectives the completed chain reaches + a 0-100 reachability score.

    Mirrors the requested factors: does the chain reach a crown jewel? production?
    customer data? trading? privileged cloud? The attacker who walks the whole
    chain holds the union of every finding's objectives.
    """
    from app.graph.objectives import (objectives_for, categories_of,
                                       objective_weight, OBJECTIVE_META)
    objs: set[str] = set()
    for p in path:
        f = fmap[p]
        objs |= set(objectives_for(f, assets.get(f.affected_asset_id)))
    cats = categories_of(objs)

    cj = assets.get(crown_jewel)
    score = 0.0
    if cj and cj.is_crown_jewel:
        score += 40                                  # reaches a crown jewel
    score += 20 if "trading" in cats else 0
    score += 15 if "production" in cats else 0
    score += 15 if "customer_data" in cats else 0
    score += 12 if "payment" in cats or "financial" in cats else 0
    score += 10 if "cloud" in cats else 0
    score += 8 if "admin" in cats else 0
    # weight by the single most valuable objective reached
    top_w = max((objective_weight(o) for o in objs), default=0.0)
    score = min(100.0, score * (0.6 + 0.4 * top_w))
    primary = max(objs, key=objective_weight, default="")
    ordered = sorted(objs, key=objective_weight, reverse=True)
    return ordered, primary, round(score, 1)


def _realism_score(path, fmap, assets, entry_f, feasibility):
    """0-100 operational realism: many chains are technically possible but
    unrealistic. Combines initial-access plausibility, exploit maturity / active
    exploitation, LLM-judged edge feasibility, attacker sophistication (length)
    and trust-boundary crossings (distinct assets)."""
    initial = {Exposure.INTERNET: 1.0, Exposure.INTERNAL: 0.65,
               Exposure.ISOLATED: 0.35}.get(entry_f.network_exposure, 0.6)
    max_epss = max((fmap[p].epss for p in path), default=0.0)
    kev = any(fmap[p].in_kev for p in path)
    maturity = min(1.0, 0.5 + 0.5 * max_epss + (0.15 if kev else 0.0))
    hops = len(path) - 1
    sophistication = 0.9 ** max(0, hops - 2)        # longer = harder
    distinct_assets = len({fmap[p].affected_asset_id for p in path})
    boundary = 0.9 ** max(0, distinct_assets - 1)   # each trust boundary crossed
    realism = 100.0 * initial * maturity * max(feasibility, 0.05) * sophistication * boundary
    return round(min(100.0, realism), 1)


def _attack_path_narrative(path, fmap, assets, primary, crown_jewel):
    """Structured attacker narrative: goal / initial access / pivot / privilege
    escalation / impact. Deterministic so it never costs tokens on refresh."""
    from app.graph.objectives import objective_label
    entry = fmap[path[0]]
    target = fmap[path[-1]]
    cj = assets.get(crown_jewel)
    cj_name = cj.name if cj else crown_jewel

    pivots = []
    for p in path[1:-1]:
        f = fmap[p]
        pivots.append(f"{f.title} ({f.layer.value.replace('_',' ')}) on {f.affected_asset_id}")
    esc_caps = []
    for p in path:
        for c in fmap[p].grants:
            v = c.value if hasattr(c, "value") else str(c)
            if v in ("priv_escalation", "credential_access", "code_execution", "funds_access") and v not in esc_caps:
                esc_caps.append(v)
    return {
        "attacker_goal": objective_label(primary) if primary else f"Compromise {cj_name}",
        "initial_access": f"{entry.title} ({entry.layer.value.replace('_',' ')}) on "
                          f"{entry.affected_asset_id}"
                          f"{' — internet-facing' if entry.network_exposure == Exposure.INTERNET else ''}",
        "pivot_path": pivots or ["direct — entry finding sits on the target asset"],
        "privilege_escalation": [c.replace("_", " ") for c in esc_caps] or ["none required"],
        "impact": f"{objective_label(primary) if primary else 'control'} — reaches {cj_name}"
                 f" via {target.title}",
    }


def prioritize_findings(findings, chains, assets=None, top_chain_n: int = 20):
    """
    Assign each finding a priority tier based on its role in high-risk chains.
    Uses betweenness centrality over the union of top-N chain paths.

    Findings that are not on any chain are not automatically dismissed as noise:
    if they sit on a crown-jewel and/or internet-facing application they are
    surfaced (Patch This Week / Month) so internet-facing + critical assets are
    prioritized even before chain context exists. Everything else defers.
    """
    assets = assets or {}
    fmap = {f.finding_id: f for f in findings}
    top_chains = chains[:top_chain_n]

    # Build subgraph of just the top chains
    sub = nx.DiGraph()
    chain_membership: dict[str, list[str]] = {}
    risk_weight: dict[str, float] = {}
    for ch in top_chains:
        for fid in ch.finding_ids:
            chain_membership.setdefault(fid, []).append(ch.chain_id)
            risk_weight[fid] = risk_weight.get(fid, 0) + ch.chain_risk
        for u, v in zip(ch.finding_ids, ch.finding_ids[1:]):
            sub.add_edge(u, v)

    centrality = nx.betweenness_centrality(sub) if sub.number_of_nodes() else {}

    for f in findings:
        f.chain_count = len(chain_membership.get(f.finding_id, []))
        f.centrality = round(centrality.get(f.finding_id, 0.0), 3)
        f.attack_objectives = objectives_for(f, assets.get(f.affected_asset_id))

    # Remediation leverage: how much realistic, high-value risk collapses if each
    # finding is fixed. The engine's headline metric — the smallest set of fixes
    # that removes the most organizational risk falls out of ranking by this.
    compute_remediation_leverage(findings, chains)

    # Per-finding chain context. Escalation only counts CONFIDENT (non-
    # speculative) chains, so low-evidence paths never push a finding to P1.
    best_obj: dict[str, float] = {}
    best_conf: dict[str, float] = {}
    conf_chain_count: dict[str, int] = {}
    for c in chains:
        for fid in c.finding_ids:
            best_conf[fid] = max(best_conf.get(fid, 0.0), c.chain_confidence)
            if not c.speculative:
                conf_chain_count[fid] = conf_chain_count.get(fid, 0) + 1
                best_obj[fid] = max(best_obj.get(fid, 0.0), c.objective_reachability_score)

    for f in findings:
        a = assets.get(f.affected_asset_id)
        p = _classify_p(f, a,
                        best_obj.get(f.finding_id, 0.0),
                        best_conf.get(f.finding_id, 0.0),
                        conf_chain_count.get(f.finding_id, 0))
        f.priority_p = f"P{p}"
        f.priority = _P_TO_TIER[p]
        # final_score: remediation leverage is the headline, then P-level, then
        # the finding's own exploitability/severity.
        f.final_score = round(
            (6 - p) * 1000
            + f.remediation_leverage * 6
            + (f.cvss or 0) * 5
            + f.epss * 20
            + (40 if f.in_kev else 0), 1)

    return findings


def compute_remediation_leverage(findings, chains):
    """Set per-finding remediation leverage: how many realistic, high-value
    attack chains collapse if this finding is fixed. Ranking by this directly
    answers 'what is the smallest set of fixes that removes the most risk?'"""
    agg = {f.finding_id: {"n": 0, "crown": 0, "val": 0.0} for f in findings}
    for c in chains:
        # value of breaking this chain = realistic, high-value, well-EVIDENCED
        # risk it carries. Confidence is a direct multiplier so fixing a finding
        # on speculative paths earns little leverage.
        val = (c.objective_reachability_score / 100.0) * (c.realism_score / 100.0) \
            * (c.chain_confidence / 100.0) * max(c.chain_risk, 1.0)
        reaches_crown = c.objective_reachability_score >= 40 and not c.speculative
        for fid in c.finding_ids:
            if fid in agg:
                agg[fid]["n"] += 1
                agg[fid]["val"] += val
                if reaches_crown:
                    agg[fid]["crown"] += 1
    maxval = max((a["val"] for a in agg.values()), default=0.0) or 1.0
    for f in findings:
        a = agg[f.finding_id]
        f.chains_collapsed = a["n"]
        f.crown_paths_collapsed = a["crown"]
        f.remediation_leverage = round(100.0 * a["val"] / maxval, 1)
        f.remediation_leverage_label = (
            "Very High" if (a["crown"] >= 3 or a["n"] >= 5) else
            "High" if (a["crown"] >= 1 and a["n"] >= 2) or a["n"] >= 3 else
            "Medium" if a["n"] >= 2 else
            "Low" if a["n"] >= 1 else "None")
    return findings


# P1..P5 -> the 4 dashboard tiers (UI unchanged; P-level carried alongside)
_P_TO_TIER = {
    1: Priority.BREAK_CHAIN_CRITICAL,
    2: Priority.PATCH_THIS_WEEK,
    3: Priority.PATCH_THIS_MONTH,
    4: Priority.DEFER,
    5: Priority.DEFER,
}


def _classify_p(f, asset, best_obj: float = 0.0, best_conf: float = 0.0,
                conf_chain_count: int = 0) -> int:
    """Return P1 (highest) .. P5 (lowest). Final formula combines: asset
    criticality, internet exposure, severity, active exploit, objective
    reachability, chain realism, remediation leverage AND evidence-validated
    chain confidence.

    Only a CONFIDENT chain (above the confidence threshold) escalates a finding.
    A finding sitting solely on speculative paths is judged on its own asset
    criticality, so unverified hops can't manufacture a P1.
    """
    internet = bool(asset and asset.internet_facing) or \
        f.network_exposure == Exposure.INTERNET
    crown = bool(asset and asset.is_crown_jewel)
    active_exploit = f.in_kev or f.epss >= 0.5
    sev = f.cvss or 0.0
    sev_crit, sev_high, sev_med = sev >= 9.0, sev >= 7.0, sev >= 4.0

    on_confident_chain = conf_chain_count > 0
    # reaches a crown-jewel objective by a well-evidenced path
    realistic_obj = best_obj >= 40 and best_conf >= 55
    strong = (f.crown_paths_collapsed >= 2 or conf_chain_count >= 3
              or (best_obj >= 55 and best_conf >= 65))

    # --- on a CONFIDENT chain: objective reachability x evidence drive it ---
    if on_confident_chain:
        if strong or (realistic_obj and (internet or crown)):
            return 1
        if realistic_obj or internet or crown or active_exploit:
            return 2
        return 3

    # --- not on a confident chain (incl. speculative-only): criticality matrix ---
    if internet and crown and (sev_high or active_exploit):
        return 1
    if sev_crit or (crown and (sev_high or active_exploit)) or (internet and active_exploit):
        return 2
    if crown or internet or sev_high or sev_med or active_exploit:
        return 3
    if sev > 0:
        return 4
    return 5
