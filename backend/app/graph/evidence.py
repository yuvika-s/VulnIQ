"""
Attack-chain evidence validation — the layer that separates real breach paths
from speculative ones.

A capability handoff (A grants X, B requires X) is necessary but NOT sufficient
for a real attack path. The attacker also needs the *relationship* to exist:
network reachability, an identity/credential that actually unlocks B, a cloud
role that can be assumed, Kubernetes reachability, service-to-service trust.

For every chain edge we attach structured evidence for each relationship type
with a verdict (verified / inferred / assumed) and a strength, then roll the
edges up into a Chain Confidence Score. Chains built on "assumed" hops score low
and are NOT allowed to materially escalate priority.
"""
from __future__ import annotations

from app.graph.cwe_capability_map import requires_for

# capability values that imply an identity / credential relationship is needed
_IDENTITY_CAPS = {"credential_access", "priv_escalation"}
_CLOUD_KW = ("aws", "iam", "sts", "assume", "role", "s3", "ec2", "lambda",
             "terraform", "cloudformation", "secrets manager", "ssm", "rds")
_K8S_KW = ("k8s", "kube", "kubernetes", "eks", "pod", "cluster", "container",
           "helm", "namespace", "service account")


def _cv(c) -> str:
    return c.value if hasattr(c, "value") else str(c)


def capability_handoff(a_finding, b_finding) -> list[str]:
    """Capabilities A grants that B actually requires."""
    a_grants = {_cv(c) for c in (a_finding.grants or [])}
    b_req = {_cv(c) for c in requires_for(b_finding)}
    return sorted(a_grants & b_req)


def _text(finding, asset) -> str:
    parts = [getattr(finding, "component", ""), getattr(finding, "title", ""),
             getattr(finding, "location", "")]
    if asset:
        parts += [getattr(asset, "name", ""), getattr(asset, "asset_id", ""),
                  getattr(asset, "data_classification", ""),
                  getattr(asset, "business_function", "")]
    return " ".join(str(p).lower() for p in parts)


def _has_reaches(G, a_aid, b_aid) -> bool:
    if not G or a_aid not in G:
        return False
    seen, frontier = {a_aid}, [a_aid]
    while frontier:
        cur = frontier.pop()
        for _, nxt, k in G.out_edges(cur, keys=True):
            if k == "REACHES" and nxt not in seen:
                if nxt == b_aid:
                    return True
                seen.add(nxt); frontier.append(nxt)
    return False


def _network_evidence(a_asset, b_asset, G):
    a_aid = getattr(a_asset, "asset_id", None)
    b_aid = getattr(b_asset, "asset_id", None)
    if a_aid and a_aid == b_aid:
        return 1.0, "verified", "same asset/service — no network boundary crossed"
    if a_aid and b_aid and _has_reaches(G, a_aid, b_aid):
        return 0.9, "verified", "declared dependency / network reachability (REACHES edge)"
    if a_asset and getattr(a_asset, "internet_facing", False):
        return 0.55, "inferred", "internet-facing entry can plausibly reach internal services"
    if b_asset and getattr(b_asset, "is_crown_jewel", False):
        return 0.30, "assumed", "attacker pivot toward crown jewel — no declared network path"
    return 0.25, "assumed", "no declared network reachability between assets"


def _identity_evidence(handoff, a_finding, a_asset, b_asset):
    if not (set(handoff) & _IDENTITY_CAPS):
        return None  # this edge doesn't depend on an identity relationship
    a_text = _text(a_finding, a_asset)
    b_text = _text(None, b_asset)
    a_cloud = any(k in a_text for k in _CLOUD_KW)
    b_cloud = any(k in b_text for k in _CLOUD_KW) or (
        b_asset and "cloud" in (getattr(b_asset, "business_function", "") or "").lower())
    if a_cloud and b_cloud:
        return 0.8, "inferred", "credential/role from source maps to target's cloud identity domain"
    if a_cloud or b_cloud:
        return 0.55, "inferred", "credential could grant access to target — identity domain partial match"
    return 0.35, "assumed", "credential-to-target identity relationship not established"


def edge_evidence(a_finding, b_finding, a_asset, b_asset, G,
                  llm_confidence: float = 0.5, rationale: str = ""):
    """Structured evidence for one chain edge + a 0-1 validation confidence."""
    handoff = capability_handoff(a_finding, b_finding)
    items = []

    # 1. capability handoff (necessary condition)
    if handoff:
        items.append({"type": "capability", "verdict": "verified", "strength": 1.0,
                      "note": f"source grants {', '.join(handoff)}; target requires it"})
    else:
        items.append({"type": "capability", "verdict": "assumed", "strength": 0.2,
                      "note": "no explicit capability precondition on target"})

    # 2. network reachability
    ns, nv, nn = _network_evidence(a_asset, b_asset, G)
    items.append({"type": "network", "verdict": nv, "strength": ns, "note": nn})

    # 3. identity relationship (only when the handoff needs one)
    ie = _identity_evidence(handoff, a_finding, a_asset, b_asset)
    if ie:
        s, v, n = ie
        items.append({"type": "identity", "verdict": v, "strength": s, "note": n})

    # 4. cloud role assumption (bonus evidence richness)
    txt = _text(a_finding, a_asset) + " " + _text(b_finding, b_asset)
    if (set(handoff) & _IDENTITY_CAPS) and any(k in txt for k in ("assume", "sts", "iam", "role")):
        items.append({"type": "cloud_role", "verdict": "inferred", "strength": 0.6,
                      "note": "cloud role assumption plausible (assume-role / STS)"})
    # 5. kubernetes reachability
    if any(k in txt for k in _K8S_KW):
        items.append({"type": "k8s", "verdict": "inferred", "strength": 0.55,
                      "note": "Kubernetes service/pod reachability"})
    # 6. service-to-service trust
    if getattr(a_asset, "asset_id", 1) == getattr(b_asset, "asset_id", 2):
        items.append({"type": "service_trust", "verdict": "verified", "strength": 0.9,
                      "note": "service-to-service trust within the same application"})

    # validation confidence: capability base + network + identity (+ small bonus)
    identity_strength = next((i["strength"] for i in items if i["type"] == "identity"), None)
    bonus = 0.05 * sum(1 for i in items if i["type"] in ("cloud_role", "k8s", "service_trust"))
    base = 0.30 if handoff else 0.10
    val = base + 0.40 * ns + (0.20 * identity_strength if identity_strength is not None else 0.20 * ns) + bonus
    val = round(max(0.0, min(1.0, val)), 3)

    return {
        "source": a_finding.finding_id,
        "destination": b_finding.finding_id,
        "capability_handoff": handoff,
        "evidence": items,
        "validation_confidence": val,
        "llm_confidence": round(float(llm_confidence), 3),
        "rationale": rationale or "",
    }


def chain_confidence(edges: list[dict], path_findings: list, *, max_epss: float,
                     any_kev: bool) -> tuple[float, dict]:
    """Roll edge evidence into a 0-100 Chain Confidence Score over the six factors:
    capability match, identity evidence, network evidence, exploit maturity,
    asset relationship, LLM confidence. Network uses the WEAKEST link (one
    assumed hop breaks the chain)."""
    if not edges:
        return 0.0, {}

    def _strength(et, default):
        vals = [i["strength"] for e in edges for i in e["evidence"] if i["type"] == et]
        return (sum(vals) / len(vals)) if vals else default

    capability = sum(1 for e in edges if e["capability_handoff"]) / len(edges)
    network = min((i["strength"] for e in edges for i in e["evidence"]
                   if i["type"] == "network"), default=0.3)        # weakest link
    identity = _strength("identity", 0.7)                          # 0.7 neutral if N/A
    asset_rel = sum(1 for e in edges for i in e["evidence"]
                    if i["type"] == "network" and i["verdict"] == "verified") / len(edges)
    llm = sum(e["llm_confidence"] for e in edges) / len(edges)
    exploit = min(1.0, 0.4 + 0.6 * max_epss + (0.15 if any_kev else 0.0))

    score = 100.0 * (0.15 * capability + 0.15 * identity + 0.25 * network
                     + 0.10 * exploit + 0.15 * asset_rel + 0.20 * llm)

    # Each hop that rests on an *assumed* (unverified) relationship makes the
    # whole path materially more speculative — a single unproven pivot can sink
    # an otherwise plausible chain below the confidence threshold.
    assumed_hops = sum(1 for e in edges for i in e["evidence"]
                       if i["type"] == "network" and i["verdict"] == "assumed")
    score *= 0.72 ** assumed_hops
    breakdown = {
        "capability_match": round(capability * 100, 0),
        "identity_evidence": round(identity * 100, 0),
        "network_evidence": round(network * 100, 0),
        "exploit_maturity": round(exploit * 100, 0),
        "asset_relationship": round(asset_rel * 100, 0),
        "llm_confidence": round(llm * 100, 0),
    }
    return round(min(100.0, score), 1), breakdown
