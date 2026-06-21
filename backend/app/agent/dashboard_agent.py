"""
Embedded dashboard agent: Q&A over findings + ACTIONS (re-rank, simulate patch,
generate brief). This is the conversational layer that lives inside the
dashboard.

It is genuinely agentic: Claude decides which tool(s) to call to answer a fuzzy
question, can chain calls, and synthesizes a final answer. When no API key is
present, a deterministic intent-router provides the same tool access so the
demo works offline.
"""
from __future__ import annotations

import json
import os

from app.engine import ENGINE
from app.ai_config import MODEL, make_client, has_credentials  # single source of truth

try:
    import anthropic
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False


# --------------------------------------------------------------------------- #
# Tool implementations (the agent's hands)
# --------------------------------------------------------------------------- #
def tool_get_top_chains(n: int = 5):
    out = []
    for c in ENGINE.chains[:n]:
        out.append({
            "chain_id": c.chain_id, "risk": c.chain_risk,
            "path": c.finding_ids, "crown_jewel": c.crown_jewel,
            "narrative": narrate_chain(c.chain_id),
        })
    return out


def tool_query_findings(priority: str = None, layer: str = None,
                        internet_only: bool = False, limit: int = 10):
    res = []
    for f in ENGINE.findings:
        if priority and (not f.priority or f.priority.value != priority):
            continue
        if layer and f.layer.value != layer:
            continue
        if internet_only and f.network_exposure.value != "internet":
            continue
        res.append(f)
    res.sort(key=lambda x: -x.final_score)
    return [{"finding_id": f.finding_id, "title": f.title,
             "priority": f.priority.value if f.priority else None,
             "cvss": f.cvss, "epss": round(f.epss, 3), "in_kev": f.in_kev,
             "chains": f.chain_count, "asset": f.affected_asset_id,
             "layer": f.layer.value} for f in res[:limit]]


def tool_get_stats(dimension: str = "all"):
    s = ENGINE.stats()
    if dimension in s:
        return {dimension: s[dimension]}
    return s


def _cheap_fix_impact(fid: str) -> dict:
    """Patch impact WITHOUT rebuilding the graph: a chain collapses iff it
    contains the finding. Same definition the dashboard modal uses client-side,
    so the brief's headline matches the modal exactly. O(chains), not O(rebuild).
    The expensive, graph-rebuilding ENGINE.simulate_patch stays for the explicit
    on-demand /api/simulate-patch action."""
    chains = ENGINE.chains
    before = len(chains)
    before_risk = round(sum(c.chain_risk for c in chains), 1)
    surviving = [c for c in chains if fid not in c.finding_ids]
    after_risk = round(sum(c.chain_risk for c in surviving), 1)
    return {
        "finding_id": fid,
        "chains_before": before, "chains_after": len(surviving),
        "chains_collapsed": before - len(surviving),
        "org_risk_before": before_risk, "org_risk_after": after_risk,
        "risk_drop_pct": round((before_risk - after_risk) / before_risk * 100, 1)
                         if before_risk else 0,
    }


def tool_best_single_fix():
    """Find the finding whose patch collapses the most chain risk.

    Ranks by the already-computed per-finding chains_collapsed (set during
    prioritization) and scores the top candidates with the cheap, no-rebuild
    impact. Previously this ran ENGINE.simulate_patch (a FULL graph rebuild) for
    8 candidates — ~40s on a multi-source inventory — on the hot path of every
    /api/snapshot, which made the dashboard look frozen on the baked-in data."""
    candidates = [f for f in ENGINE.findings if f.chain_count > 0]
    if not candidates:
        return {"message": "No chains present."}
    candidates.sort(key=lambda x: -(getattr(x, "chains_collapsed", 0) or x.chain_count))
    best = None
    for f in candidates[:12]:
        sim = _cheap_fix_impact(f.finding_id)
        sim["title"] = f.title
        if best is None or sim["risk_drop_pct"] > best["risk_drop_pct"]:
            best = sim
    return best or {"message": "No chains present."}


def tool_simulate_patch(finding_ids: list[str]):
    return ENGINE.simulate_patch(finding_ids)


def tool_get_asset_risk(asset_id: str):
    fs = [f for f in ENGINE.findings if f.affected_asset_id == asset_id]
    on_chain = [f for f in fs if f.chain_count > 0]
    a = ENGINE.assets.get(asset_id)
    return {
        "asset_id": asset_id,
        "name": a.name if a else asset_id,
        "is_crown_jewel": a.is_crown_jewel if a else False,
        "total_findings": len(fs),
        "findings_on_chains": len(on_chain),
        "top_findings": [{"finding_id": f.finding_id, "title": f.title,
                          "priority": f.priority.value if f.priority else None}
                         for f in sorted(on_chain, key=lambda x: -x.final_score)[:5]],
    }


# --------------------------------------------------------------------------- #
# Context-layer tools (the grounded retrieval surface — see app.agent.context).
# The copilot reasons over THESE, never raw findings.
# --------------------------------------------------------------------------- #
from app.agent import context as ctx

TOOLS_SPEC = [
    {"name": "posture_overview", "description": "Org-wide posture: totals, priority/source/owner breakdown, crown jewels, org risk. Call this first for broad questions.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "find_findings", "description": "Retrieve ranked findings with filters. scope=owner/team/business-unit/application name (e.g. 'KYC','OMS','Trading'); source=snyk|tenable|manual; priority=P1..P5; objective substring; internet_only; kev_only; on_chains_only.",
     "input_schema": {"type": "object", "properties": {
         "scope": {"type": "string"}, "source": {"type": "string"}, "priority": {"type": "string"},
         "objective": {"type": "string"}, "internet_only": {"type": "boolean"},
         "kev_only": {"type": "boolean"}, "on_chains_only": {"type": "boolean"},
         "limit": {"type": "integer"}}}},
    {"name": "find_chains", "description": "Retrieve ranked attack chains. Filters: scope (owner/team/app), source, objective, crown_jewel, cross_source_only (chains combining >1 scanner).",
     "input_schema": {"type": "object", "properties": {
         "scope": {"type": "string"}, "source": {"type": "string"}, "objective": {"type": "string"},
         "crown_jewel": {"type": "string"}, "cross_source_only": {"type": "boolean"},
         "limit": {"type": "integer"}}}},
    {"name": "owner_posture", "description": "Posture for one engineering head / team / business unit / application: their findings, P1s, chains, highest-leverage fixes. Use for 'what should KYC fix', 'RMS team's P1s'.",
     "input_schema": {"type": "object", "properties": {"scope": {"type": "string"}}, "required": ["scope"]}},
    {"name": "ownership_breakdown", "description": "Per-engineering-head and per-business-unit breakdown (findings, P1, chains, risk, crown-jewel exposure). Use for 'which team owns the highest risk', 'which head owns most crown-jewel exposure'.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "top_leverage_fixes", "description": "Highest remediation-leverage fixes (smallest set removing most risk). Optional scope to an owner/team/app.",
     "input_schema": {"type": "object", "properties": {"scope": {"type": "string"}, "n": {"type": "integer"}}}},
    {"name": "fix_impact", "description": "What collapses if a specific finding is fixed: chains collapsed and org-risk drop. Use for 'what happens if we fix X', 'what chains disappear if X is remediated'.",
     "input_schema": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"name": "reduce_risk_plan", "description": "Greedy minimal set of fixes to cut org chain-risk by target_pct (e.g. 50). Optional scope. Use for 'shortest path to reduce risk by 50%'.",
     "input_schema": {"type": "object", "properties": {"target_pct": {"type": "number"}, "scope": {"type": "string"}}}},
    {"name": "objective_view", "description": "Findings + chains advancing a specific attacker objective, e.g. 'unauthorized_trading', 'crown jewel', 'customer data'.",
     "input_schema": {"type": "object", "properties": {"objective": {"type": "string"}}, "required": ["objective"]}},
    {"name": "history_and_trends", "description": "Historical runs, trend series, and latest-vs-previous comparison INCLUDING owner risk-reduction and new-P1-by-owner. Use for 'what changed since last scan', 'which head reduced most risk', 'which team introduced most P1s', 'what's getting worse'.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "simulate_patch", "description": "Accurately simulate patching finding(s) by rebuilding the graph; returns chains collapsed and org-risk drop.",
     "input_schema": {"type": "object", "properties": {"finding_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["finding_ids"]}},
]

DISPATCH = {
    "posture_overview": lambda: ctx.posture_summary(),
    "find_findings": ctx.retrieve_findings,
    "find_chains": ctx.retrieve_chains,
    "owner_posture": ctx.owner_view,
    "ownership_breakdown": lambda: ctx.ownership_context(),
    "top_leverage_fixes": ctx.leverage_ranking,
    "fix_impact": ctx.fix_impact,
    "reduce_risk_plan": ctx.reduce_risk_plan,
    "objective_view": ctx.objective_view,
    "history_and_trends": lambda: ctx.historical_context(),
    "simulate_patch": tool_simulate_patch,
}

SYSTEM = (
    "You are VulnIQ's Security Intelligence Copilot, embedded in the attack-chain "
    "prioritization platform for Angel One (a SEBI-regulated stock broker). You "
    "reason over the VulnIQ knowledge graph — findings, attack chains, assets, "
    "applications, criticality, crown jewels, objectives, risk scores, priorities, "
    "remediation leverage, multi-source ingestion (Snyk, Tenable, manual), "
    "engineering ownership, business units, and historical/trend/compare data.\n\n"
    "HARD RULES:\n"
    "1. GROUND EVERY CLAIM in tool results. Never invent finding IDs, chains, "
    "owners, numbers, applications, or trends. If a tool returns nothing / "
    "'no evidence' / 'not found', say so plainly — do NOT guess.\n"
    "2. You only know VulnIQ data. Do not use outside knowledge about CVEs, "
    "companies, or people beyond what tools return.\n"
    "3. Ownership questions ('what should KYC fix', 'RMS team's P1s', 'which head "
    "owns most risk') → use owner_posture / ownership_breakdown. Treat owner, "
    "team, business unit and application names as a scope filter.\n"
    "4. Temporal questions ('changed since last scan', 'getting worse', 'who "
    "reduced risk', 'new P1s') → use history_and_trends; if it reports no history, "
    "say persistence/history isn't available yet.\n"
    "5. Be concise and concrete. Lead with the number or name that matters. Refer "
    "to findings by ID, chains by ID, and name the owner/application. When "
    "recommending fixes, give chains collapsed and org-risk drop.\n"
    "6. If the engine is empty (no scan run this session), say so and suggest "
    "running a Snyk/Tenable sync or an upload."
)


# --------------------------------------------------------------------------- #
# Agent loop
# --------------------------------------------------------------------------- #
def _grounding_preamble() -> str:
    """Always-on posture summary injected as the first turn so the model never
    hallucinates basic totals and knows whether the engine is empty."""
    try:
        return ("CURRENT VULNIQ POSTURE (ground truth for this session):\n"
                + json.dumps(ctx.posture_summary(), default=str))
    except Exception:
        return "CURRENT VULNIQ POSTURE: unavailable."


def ask(message: str, history: list[dict] | None = None) -> dict:
    history = history or []
    use_llm = _HAS_SDK and has_credentials()
    if use_llm:
        return _ask_llm(message, history)
    return _ask_offline(message)


def _ask_llm(message, history):
    client = make_client()
    if client is None:
        return _ask_offline(message)
    messages = (history or []) + [
        {"role": "user", "content": _grounding_preamble() + "\n\nUSER QUESTION: " + message}]
    tool_trace = []
    try:
        for _ in range(8):  # bounded agentic loop
            resp = client.messages.create(
                model=MODEL, max_tokens=1600, system=SYSTEM,
                tools=TOOLS_SPEC, messages=messages)
            if resp.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": resp.content})
                tool_results = []
                for block in resp.content:
                    if block.type == "tool_use":
                        fn = DISPATCH.get(block.name)
                        try:
                            result = fn(**block.input) if fn else {"error": "unknown tool"}
                        except Exception as e:
                            result = {"error": f"{type(e).__name__}: {e}"}
                        tool_trace.append({"tool": block.name, "input": block.input})
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": block.id,
                            "content": json.dumps(result, default=str)[:12000]})
                messages.append({"role": "user", "content": tool_results})
            else:
                text = "".join(b.text for b in resp.content if b.type == "text")
                return {"answer": text, "tool_trace": tool_trace}
        return {"answer": "Reached reasoning limit — try a more specific question.",
                "tool_trace": tool_trace}
    except Exception as e:
        # LLM unavailable (auth/timeout/rate-limit) → degrade to the grounded
        # offline router rather than 500. The answer stays grounded; only the
        # natural-language synthesis is lost.
        import logging
        logging.getLogger("vulniq").warning("copilot: LLM path failed (%s) — offline fallback", e)
        out = _ask_offline(message)
        out["llm_error"] = f"{type(e).__name__}"
        return out


def _ask_offline(message: str) -> dict:
    """Deterministic intent router that reasons over the SAME context layer, so
    the copilot stays grounded even without an API key."""
    import re
    m = message.lower()
    trace = []

    def t(name, inp):
        trace.append({"tool": name, "input": inp})

    def done(ans):
        return {"answer": ans, "tool_trace": trace}

    if ctx.posture_summary().get("engine_empty"):
        return done("No scan data in the live view yet. Run a **Snyk** or **Tenable** "
                    "sync, or upload a report, then ask again. (Past runs are in History.)")

    # explicit finding impact / simulate
    ids = [x.upper() for x in re.findall(r"[Ff]-[A-Za-z0-9\-]{3,}", message)]
    if ids and ("fix" in m or "patch" in m or "simulate" in m or "remediat" in m or "happen" in m):
        t("fix_impact", {"finding_id": ids[0]})
        r = ctx.fix_impact(ids[0])
        if not r.get("found"):
            return done(r["note"])
        return done(f"Fixing **{r['finding_id']}** ({r['application']}, owner {r['owner']}) "
                    f"collapses **{r['chains_collapsed']} of {r['chains_before']}** chains and "
                    f"drops org risk **{r['risk_drop_pct']}%** ({r['org_risk_before']} → {r['org_risk_after']}).")

    # reduce risk by X%
    mpct = re.search(r"(\d+)\s*%", m)
    if "reduce" in m and "risk" in m and mpct:
        pct = float(mpct.group(1))
        t("reduce_risk_plan", {"target_pct": pct})
        r = ctx.reduce_risk_plan(pct)
        if not r.get("fixes"):
            return done(r.get("note", "No fixes available."))
        lines = [f"**{r['num_fixes']} fixes** cut org risk by ~**{r['achieved_pct']}%** (target {pct}%):"]
        for f in r["fixes"][:10]:
            lines.append(f"• {f['id']} — {f['title'][:60]} ({f['owner']}, removes {f['chains_removed']} chains)")
        return done("\n".join(lines))

    # cross-source chains (must precede the single-source filter so 'tenable AND
    # snyk' isn't captured as a plain Tenable query)
    if "chain" in m and (("combine" in m or "cross" in m or "both" in m
                          or ("tenable" in m and "snyk" in m))):
        t("find_chains", {"cross_source_only": True})
        r = ctx.retrieve_chains(cross_source_only=True, limit=6)
        if not r["chains"]:
            return done("No chains currently combine findings from more than one scanner.")
        lines = [f"{r['count']} cross-source chains (combining ≥2 scanners):"]
        for c in r["chains"]:
            lines.append(f"• **{c['id']}** risk {c['risk']} → {c['crown_jewel']} "
                         f"[{', '.join(c['sources'])}] owner {c['primary_owner']}")
        return done("\n".join(lines))

    # history / trends / changed (must precede owner-scope so 'previous scan'
    # isn't matched as a team named 'scan')
    if any(k in m for k in ["chang", "since", "previous", "trend", "getting worse",
                            "new p1", "new critical", "reduced risk", "introduced", "over time"]):
        t("history_and_trends", {})
        h = ctx.historical_context()
        if not h.get("available"):
            return done(h.get("note", "No history available."))
        c = h["compare"]
        lines = [f"Since run #{c['from_run']} → #{c['to_run']}: "
                 f"+{c['new_findings']} new, −{c['resolved_findings']} resolved findings; "
                 f"risk {c['risk'].get('from')} → {c['risk'].get('to')}."]
        if c.get("owner_risk_reduction"):
            top = c["owner_risk_reduction"][0]
            lines.append(f"Biggest risk reduction: **{top['owner']}** (−{top['reduction']}).")
        if c.get("owner_new_p1"):
            top = c["owner_new_p1"][0]
            lines.append(f"Most new P1s: **{top['owner']}** (+{top['new_p1']}).")
        return done("\n".join(lines))

    # ownership / team / leadership
    if any(k in m for k in ["which team", "which head", "which engineering", "owns the", "ownership", "by team", "by head", "business unit"]):
        t("ownership_breakdown", {})
        ob = ctx.ownership_context()
        rows = ob.get("owners", [])[:6]
        lines = ["Engineering ownership (by risk):"]
        for o in rows:
            lines.append(f"• **{o['owner']}** — {o.get('risk', '?')} risk · {o.get('chains', 0)} chains · {o['findings']} findings")
        return done("\n".join(lines))

    # owner-scoped ("what should KYC fix", "OMS findings", "Trading P1s")
    for scope in _candidate_scopes(message):
        ov = ctx.owner_view(scope)
        if ov.get("found"):
            t("owner_posture", {"scope": scope})
            lines = [f"**{scope}** — {ov['total_findings']} findings, {ov['p1']} P1, "
                     f"{len(ov['chains'])} chains. Highest-leverage fixes:"]
            for f in ov["highest_leverage_fixes"][:5]:
                lines.append(f"• {f['id']} — {f['title'][:60]} ({f['leverage_label']} leverage)")
            return done("\n".join(lines))

    # source filter
    for src in ("tenable", "snyk", "manual"):
        if src in m:
            t("find_findings", {"source": src})
            r = ctx.retrieve_findings(source=src, limit=8)
            lines = [f"Top {src.title()} findings ({r['count']} total):"]
            for f in r["findings"]:
                lines.append(f"• {f['id']} ({f['priority']}) {f['title'][:55]} — {f['application']}")
            return done("\n".join(lines))

    # dangerous chains
    if any(k in m for k in ["dangerous", "worst", "top chain", "attack path", "breach", "crown jewel"]):
        t("find_chains", {})
        r = ctx.retrieve_chains(limit=4)
        lines = ["Most dangerous attack paths:"]
        for c in r["chains"]:
            lines.append(f"• **{c['id']}** risk {c['risk']} (conf {c['confidence']}) → {c['crown_jewel']} "
                         f"[owner {c['primary_owner']}]: {' → '.join(c['path'])}")
        return done("\n".join(lines))

    # leverage / where to start
    if any(k in m for k in ["leverage", "one thing", "fix first", "where do i start", "biggest impact", "this week", "priorit"]):
        t("top_leverage_fixes", {"n": 6})
        r = ctx.leverage_ranking(n=6)
        lines = ["Highest-leverage fixes (most risk removed per fix):"]
        for f in r["fixes"]:
            lines.append(f"{f['rank']}. {f['id']} — {f['title'][:55]} ({f['owner']}, breaks {f['chains_collapsed']} chains)")
        return done("\n".join(lines))

    # default → posture
    s = ctx.posture_summary()
    return done(f"**Posture:** {s['total_findings']} findings, {s['total_chains']} chains, "
                f"org risk **{s['org_risk_score']}**. Priorities: {s['by_priority']}.\n\n"
                "Ask about a team (\"what should KYC fix\"), a source (\"Tenable findings\"), "
                "ownership (\"which team owns the highest risk\"), impact (\"what if we fix F-…\"), "
                "or change (\"what changed since last scan\").")


def _candidate_scopes(message: str) -> list[str]:
    """Pull likely owner/team/app tokens from the question for the offline router
    (the LLM path handles this natively)."""
    import re
    words = re.findall(r"[A-Za-z][A-Za-z0-9\-]{1,}", message)
    stop = {"what", "should", "the", "fix", "this", "week", "show", "only", "findings",
            "are", "team", "teams", "for", "and", "with", "risk", "risks", "owned",
            "by", "highest", "leverage", "remediation", "remediations", "p1", "p2",
            "which", "that", "give", "list", "top", "most", "their", "owns"}
    return [w for w in words if w.lower() not in stop and len(w) >= 2][:6]


# --------------------------------------------------------------------------- #
# Chain narration delegates to the dedicated Chain Narrator Agent (Role 3).
# Kept as a thin wrapper here so existing call sites stay stable. Returns a
# narrative string; the agent itself also exposes the method (llm|deterministic).
# --------------------------------------------------------------------------- #
def narrate_chain(chain_id: str) -> str:
    c = ENGINE.chain(chain_id)
    if not c:
        return ""
    from app.agent.chain_narrator import narrate
    fmap = {f.finding_id: f for f in ENGINE.findings}
    return narrate(c, fmap, ENGINE.assets)["narrative"]


def narrate_chain_full(chain_id: str) -> dict:
    """Same as narrate_chain but returns {narrative, method, model?}."""
    c = ENGINE.chain(chain_id)
    if not c:
        return {"narrative": "", "method": "none"}
    from app.agent.chain_narrator import narrate
    fmap = {f.finding_id: f for f in ENGINE.findings}
    return narrate(c, fmap, ENGINE.assets)
