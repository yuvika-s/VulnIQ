"""
Chain Narrator Agent (Role 3 of 3) — turns a structured attack chain into a
plain-English breach story written from the perspective of a senior offensive-
security analyst.

This is one of three Claude agentic roles in VulnIQ:
  Role 1: edge_agent.py        - semantic ENABLES edge inference
  Role 2: dashboard_agent.py   - conversational copilot with tool calls
  Role 3: chain_narrator.py    - this file - per-chain narrative generation

One model (claude-opus-4-7), three system prompts, three tool surfaces. Picked
over a multi-model architecture because (a) Claude is strong enough alone for
all three jobs, (b) integration/key management/latency costs of multi-model are
not justified by any measurable quality gain on these tasks.

Each role gets a deterministic fallback so the whole pipeline runs offline.
"""
from __future__ import annotations

import json
import os
import hashlib

CACHE_FILE = os.path.join(os.path.dirname(__file__), "_narrator_cache.json")
from app.ai_config import MODEL, make_client, has_credentials  # single source of truth

try:
    import anthropic
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False


SYSTEM = (
    "You are a senior offensive-security analyst at a stockbroker, writing a "
    "concise attack-chain narrative for the CISO. Given a sequence of security "
    "findings discovered by different tools across different OSI layers and the "
    "asset path they traverse, write 2-3 sentences describing how a real "
    "attacker would chain them, in the order given, to reach the crown jewel. "
    "Lead with what the attacker does first, end with the impact. Use the "
    "attacker's perspective ('an attacker would...'). Be specific to the actual "
    "findings — name the technology and technique. Do not editorialize, do not "
    "recommend remediation, do not mention CVSS. Return ONLY the narrative text."
)


def _cache_load() -> dict:
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def _cache_save(c: dict):
    with open(CACHE_FILE, "w") as f:
        json.dump(c, f)


def _chain_key(chain) -> str:
    sig = "|".join(chain.finding_ids) + ">" + chain.crown_jewel
    return hashlib.sha1(sig.encode()).hexdigest()[:16]


def _build_user_prompt(chain, findings_map, assets) -> str:
    cj = assets.get(chain.crown_jewel)
    lines = [f"Crown jewel target: {cj.name if cj else chain.crown_jewel} "
             f"({cj.data_classification if cj else 'unknown classification'})\n",
             "Attack steps in order:"]
    for i, fid in enumerate(chain.finding_ids, 1):
        f = findings_map.get(fid)
        if not f:
            continue
        a = assets.get(f.affected_asset_id)
        lines.append(
            f"  {i}. [{f.source_tool} | {f.layer.value}] {f.title}\n"
            f"     on asset '{f.affected_asset_id}' "
            f"({a.data_classification if a else '?'})\n"
            f"     details: {f.description}"
        )
    lines.append(f"\nChain risk score: {chain.chain_risk}/100")
    return "\n".join(lines)


def _deterministic_narrative(chain, findings_map, assets) -> str:
    """Offline fallback: produces a serviceable narrative without an API call."""
    steps = []
    for fid in chain.finding_ids:
        f = findings_map.get(fid)
        if f:
            steps.append(f"{f.title} ({f.source_tool}, {f.layer.value}) on "
                         f"{f.affected_asset_id}")
    a = assets.get(chain.crown_jewel)
    cj_name = a.name if a else chain.crown_jewel
    cj_class = a.data_classification if a else ""
    chain_txt = " → then ".join(steps)
    return (f"An attacker starts by exploiting {chain_txt}, ultimately reaching "
            f"{cj_name} ({cj_class}). Individually these are lower-severity "
            f"findings from different tools; chained, they form a critical path "
            f"(risk {chain.chain_risk}).")


def narrate(chain, findings_map, assets, use_llm: bool | None = None) -> dict:
    """
    Returns {"narrative": str, "method": "llm"|"deterministic"}.
    The method field is surfaced in the UI so the audience can see when the
    text is genuinely model-generated.
    """
    if use_llm is None:
        use_llm = _HAS_SDK and has_credentials()

    cache = _cache_load()
    key = _chain_key(chain)
    if key in cache:
        return cache[key]

    if not use_llm:
        result = {"narrative": _deterministic_narrative(chain, findings_map, assets),
                  "method": "deterministic"}
        cache[key] = result
        _cache_save(cache)
        return result

    try:
        client = make_client()
        if client is None:
            raise RuntimeError("no Anthropic client (missing SDK or API key)")
        prompt = _build_user_prompt(chain, findings_map, assets)
        resp = client.messages.create(
            model=MODEL, max_tokens=300, system=SYSTEM,
            messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        result = {"narrative": text, "method": "llm", "model": MODEL}
    except Exception as e:
        result = {"narrative": _deterministic_narrative(chain, findings_map, assets),
                  "method": "deterministic", "fallback_reason": str(e)[:120]}

    cache[key] = result
    _cache_save(cache)
    return result
