"""VulnIQ FastAPI server. Builds the engine on startup and serves the dashboard."""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel

from app.engine import ENGINE
from app.agent.dashboard_agent import ask, narrate_chain, narrate_chain_full
from app.agent.chain_narrator import narrate as narrate_chain_cheap
from app.reports.brief import generate_brief
from app.ai_config import status as ai_status, MODEL, configure_tls, has_credentials
from app.ingestion.upload_pipeline import process_upload


# Make VulnIQ's own progress logs visible in the uvicorn terminal. Without this,
# the named "vulniq.*" loggers inherit uvicorn's root config (WARNING) and the
# upload phase logs never print — which is why an upload looked like it silently
# "hung" with no output. Own handler + INFO + no propagation = reliable output.
_vlog = logging.getLogger("vulniq")
if not _vlog.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s",
                                      datefmt="%H:%M:%S"))
    _vlog.addHandler(_h)
_vlog.setLevel(logging.INFO)
_vlog.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Trust the OS/corporate trust store FIRST, so the startup engine build (and
    # every later Claude call) survives behind an HTTPS-inspecting proxy/VPN like
    # Zscaler instead of failing with CERTIFICATE_VERIFY_FAILED.
    _vlog.info("startup: TLS — %s", configure_tls())
    use_llm = has_credentials()
    _vlog.info("startup: building engine (use_llm=%s)...", use_llm)
    ENGINE.build(use_llm=use_llm)
    _vlog.info("startup: engine ready — %d findings, %d chains",
               len(ENGINE.findings), len(ENGINE.chains))
    # Persistence (opt-in via DATABASE_URL): first-boot seed, then hydrate the
    # engine from the latest persisted run so data survives restarts.
    try:
        from app.db.seed import bootstrap_persistence
        bootstrap_persistence()
        _vlog.info("startup: persistence ready — %d findings, %d chains (post-hydrate)",
                   len(ENGINE.findings), len(ENGINE.chains))
    except Exception:
        _vlog.exception("startup: persistence bootstrap failed; continuing in-memory")
    # Native Snyk is NOT fetched at startup (keeps boot fast). Only start the
    # optional scheduled-sync loop when explicitly enabled; its first run waits
    # one full interval.
    import asyncio
    from app.ingestion.snyk_sync import scheduled_sync_loop
    from app.ingestion.tenable_sync import scheduled_sync_loop as tenable_sched_loop
    sched_task = asyncio.create_task(scheduled_sync_loop())
    tns_sched_task = asyncio.create_task(tenable_sched_loop())
    try:
        yield
    finally:
        sched_task.cancel()
        tns_sched_task.cancel()


app = FastAPI(title="VulnIQ API", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

from app.ingestion.routes_snyk import router as snyk_router
app.include_router(snyk_router)

from app.ingestion.routes_tenable import router as tenable_router
app.include_router(tenable_router)

from app.db.routes_history import router as history_router
app.include_router(history_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "built": ENGINE._built,
            "llm": has_credentials(),
            "model": MODEL}


@app.get("/api/ai-status")
def get_ai_status():
    """Reveals the AI architecture: one model, four agentic roles."""
    return ai_status()


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    """
    Upload a scan/findings file in any supported format (JSON, XML, CSV, XLSX,
    PDF). The Extraction Agent normalizes it into the unified schema, then the
    engine recomputes the attack graph so the new findings participate in
    chaining immediately. Returns the extraction summary + review queue.
    """
    content = await file.read()
    use_llm = has_credentials()
    # process_upload makes blocking (synchronous) LLM HTTP calls. Running it
    # directly in this async handler would block the whole event loop, freezing
    # every other request (including the /api/health poll) until the upload
    # finishes. Offload it to a worker thread so the server stays responsive.
    try:
        return await run_in_threadpool(
            process_upload, file.filename, content, use_llm=use_llm)
    except Exception as e:
        return {"ok": False, "filename": file.filename, "error": str(e)}


@app.get("/api/stats")
def stats():
    return ENGINE.stats()


@app.get("/api/findings")
def findings(priority: str = None, layer: str = None, limit: int = 200):
    res = ENGINE.findings
    if priority:
        res = [f for f in res if f.priority and f.priority.value == priority]
    if layer:
        res = [f for f in res if f.layer.value == layer]
    res = sorted(res, key=lambda x: -x.final_score)[:limit]
    return [f.to_dict() for f in res]


@app.get("/api/findings/{fid}")
def finding_detail(fid: str):
    f = ENGINE.finding(fid)
    if not f:
        return {"error": "not found"}
    d = f.to_dict()
    # which chains it sits on
    d["chains"] = [{"chain_id": c.chain_id, "risk": c.chain_risk}
                   for c in ENGINE.chains if fid in c.finding_ids]
    return d


@app.get("/api/chains")
def chains(limit: int = 20):
    out = []
    for c in ENGINE.chains[:limit]:
        d = c.to_dict()
        narr = narrate_chain_full(c.chain_id)
        d["narrative"] = narr["narrative"]
        d["narrative_method"] = narr.get("method", "deterministic")
        out.append(d)
    return out


@app.get("/api/chains/{cid}")
def chain_detail(cid: str):
    c = ENGINE.chain(cid)
    if not c:
        return {"error": "not found"}
    d = c.to_dict()
    narr = narrate_chain_full(cid)
    d["narrative"] = narr["narrative"]
    d["narrative_method"] = narr.get("method", "deterministic")
    d["findings"] = [ENGINE.finding(fid).to_dict() for fid in c.finding_ids
                     if ENGINE.finding(fid)]
    return d


@app.get("/api/graph")
def graph(top_chains: int = 12):
    """Export the attack graph restricted to the top chains, for visualization."""
    G = ENGINE.graph
    chain_fids, chain_edges = set(), []
    for c in ENGINE.chains[:top_chains]:
        chain_fids.update(c.finding_ids)
        for u, v in zip(c.finding_ids, c.finding_ids[1:]):
            chain_edges.append((u, v))

    nodes, assets_seen = [], set()
    for fid in chain_fids:
        f = ENGINE.finding(fid)
        if not f:
            continue
        nodes.append({"id": fid, "kind": "finding", "label": f.title,
                      "layer": f.layer.value, "tool": f.source_tool,
                      "priority": f.priority.value if f.priority else None,
                      "asset": f.affected_asset_id, "cvss": f.cvss,
                      "in_kev": f.in_kev})
        assets_seen.add(f.affected_asset_id)
    for aid in assets_seen:
        a = ENGINE.assets.get(aid)
        if a:
            nodes.append({"id": aid, "kind": "crown_jewel" if a.is_crown_jewel else "asset",
                          "label": a.name, "tier": a.tier,
                          "is_crown_jewel": a.is_crown_jewel})

    edges = []
    seen = set()
    for u, v in chain_edges:
        key = (u, v, "ENABLES")
        if key in seen:
            continue
        seen.add(key)
        conf = 0.6
        rationale = ""
        for e in ENGINE.enable_edges:
            if e["a"] == u and e["b"] == v:
                conf, rationale = e["confidence"], e["rationale"]
                break
        edges.append({"source": u, "target": v, "kind": "ENABLES",
                      "confidence": conf, "rationale": rationale})
    # finding -> asset EXPOSES edges
    for fid in chain_fids:
        f = ENGINE.finding(fid)
        if f and f.affected_asset_id in assets_seen:
            edges.append({"source": fid, "target": f.affected_asset_id,
                          "kind": "EXPOSES", "confidence": 1.0})
    return {"nodes": nodes, "edges": edges}


class AskBody(BaseModel):
    message: str
    history: list[dict] | None = None


@app.post("/api/agent")
def agent(body: AskBody):
    return ask(body.message, body.history)


@app.get("/api/ownership")
def ownership(scope: str | None = None):
    """Engineering ownership: the live per-head/per-BU table, or a single owner/
    team/application's detailed posture when `scope` is given."""
    from app.agent import context as ctx
    if scope:
        return ctx.owner_view(scope, limit=10)
    return ctx.owner_dashboard()


class PatchBody(BaseModel):
    finding_ids: list[str]


@app.post("/api/simulate-patch")
def simulate_patch(body: PatchBody):
    return ENGINE.simulate_patch(body.finding_ids)


@app.get("/api/brief")
def brief(scope: str = "all"):
    return generate_brief(scope)


@app.get("/api/golden-chains")
def golden_chains():
    return ENGINE.golden_chains


@app.get("/api/snapshot")
def snapshot(chain_limit: int = 24):
    """
    One-shot view of the ENTIRE live engine state, in the same shape as the
    dashboard's baked-in VULNIQ_DATA. The frontend calls this on load and after
    every upload so all pages (overview, priorities, chains, graph, brief)
    reflect the cumulative result of every file uploaded this session.

    Chain narratives use the cheap path (cached LLM text if present, otherwise
    the deterministic narrative) so a full refresh never spends tokens — the
    on-demand /api/chains endpoint still produces fresh LLM narration per chain.
    """
    fmap = {f.finding_id: f for f in ENGINE.findings}
    chains_out = []
    for c in ENGINE.chains[:chain_limit]:
        d = c.to_dict()
        narr = narrate_chain_cheap(c, fmap, ENGINE.assets, use_llm=False)
        d["narrative"] = narr["narrative"]
        d["narrative_method"] = narr.get("method", "deterministic")
        chains_out.append(d)

    return {
        "ai_status": ai_status(),
        "stats": ENGINE.stats(),
        "findings": [f.to_dict() for f in
                     sorted(ENGINE.findings, key=lambda x: -x.final_score)],
        "chains": chains_out,
        "graph": graph(top_chains=chain_limit),
        "brief": generate_brief(),
        "assets": [a.to_dict() for a in ENGINE.assets.values()],
    }
