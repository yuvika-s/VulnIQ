"""
Edge-Inference Agent (Pass 2): the semantic brain of correlation.

For each candidate (A -> B) edge from the deterministic pass, we ask: does the
capability A grants plausibly ENABLE exploitation of B, given the asset context?
The LLM reads the unstructured finding descriptions and answers with a
confidence (0-1) and a one-sentence rationale.

Design:
  - ONE model (Claude), used here purely for semantic edge scoring.
  - Batched: many candidate pairs per call to control cost/latency.
  - Cached by (A,B) hash so re-runs are free.
  - Deterministic fallback (heuristic) when no API key is present, so the whole
    pipeline runs offline for development and demos.
"""
from __future__ import annotations

import json
import os
import hashlib

CACHE_FILE = os.path.join(os.path.dirname(__file__), "_edge_cache.json")
from app.ai_config import MODEL, make_client, has_credentials  # single source of truth

try:
    import anthropic  # noqa: F401
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False


def _cache_load() -> dict:
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def _cache_save(c: dict):
    with open(CACHE_FILE, "w") as f:
        json.dump(c, f)


def _pair_key(a_id, b_id, a_desc, b_desc) -> str:
    return hashlib.sha1(f"{a_id}|{b_id}|{a_desc}|{b_desc}".encode()).hexdigest()[:16]


def _heuristic(a, b, reason) -> tuple[float, str]:
    """Deterministic fallback when the LLM is unavailable.
    Uses capability/type signals to approximate the LLM's semantic judgment.
    Cross-asset handoffs are held to a stricter bar (only credential/secret/
    lateral-movement style pivots), since an unrelated RCE on a reachable host
    is not, by itself, a plausible continuation of a specific chain — that
    semantic judgment is exactly what the LLM layer adds in production."""
    from app.models import Capability
    a_grants = set(a.grants)
    conf = 0.0
    rationale_bits = []

    if Capability.CODE_EXECUTION in a_grants and b.finding_type in (
            "hardcoded_credentials", "secret_leak"):
        conf = 0.85
        rationale_bits.append("code execution allows reading committed secrets")
    elif Capability.CREDENTIAL_ACCESS in a_grants and b.finding_type == "overprivileged_role":
        conf = 0.8
        rationale_bits.append("stolen credentials assume the over-privileged role")
    elif Capability.INITIAL_ACCESS in a_grants and b.finding_type in ("SSRF",):
        conf = 0.72
        rationale_bits.append("foothold enables internal server-side request forgery")
    elif (Capability.DATA_READ in a_grants or Capability.LATERAL_MOVE in a_grants) \
            and b.finding_type == "misconfig":
        conf = 0.6
        rationale_bits.append("read/lateral access reaches the misconfigured resource")
    elif a.finding_type == "exposed_endpoint" and b.cve and b.finding_type == "CVE" \
            and a.affected_asset_id == b.affected_asset_id:
        conf = 0.78
        rationale_bits.append("exposed surface is the delivery vector for the co-located CVE")
    elif Capability.CODE_EXECUTION in a_grants and b.finding_type == "SSRF":
        conf = 0.7
        rationale_bits.append("code execution enables pivoting via server-side requests")
    # --- host / infra handoffs (Tenable/Nessus/Qualys) — same-host primitives a
    #     human AppSec engineer would accept; cross-asset is gated below so these
    #     only deepen a chain that already has a foothold on the host. ---
    elif Capability.CODE_EXECUTION in a_grants and b.finding_type == "privilege_escalation":
        conf = 0.78
        rationale_bits.append("code execution on the host enables local privilege escalation")
    elif Capability.INITIAL_ACCESS in a_grants and b.finding_type == "privilege_escalation":
        conf = 0.68
        rationale_bits.append("a foothold on the host enables local privilege escalation")
    elif Capability.INITIAL_ACCESS in a_grants and b.finding_type == "info_disclosure":
        conf = 0.6
        rationale_bits.append("a foothold enables reading exposed information on the host")
    elif (Capability.DATA_READ in a_grants
          and b.finding_type in ("hardcoded_credentials", "secret_leak")):
        conf = 0.65
        rationale_bits.append("read access to the application surfaces stored credentials")

    if conf == 0.0:
        return 0.0, "no plausible capability handoff"

    # Cross-asset edges: only credential/secret/lateral pivots survive.
    if reason == "reaches":
        if b.finding_type in ("hardcoded_credentials", "secret_leak",
                              "overprivileged_role", "misconfig"):
            conf *= 0.9
            rationale_bits.append("pivots across a network/dependency reachability edge")
        else:
            return 0.0, "cross-asset handoff not semantically supported (LLM layer required)"

    rationale = "; ".join(rationale_bits)
    return round(min(conf, 0.95), 2), rationale


def _build_batch_prompt(batch, fmap, assets) -> str:
    lines = ["You are a senior offensive-security analyst evaluating whether one "
             "security finding ENABLES exploitation of another, forming an attack "
             "chain. For each pair, judge plausibility.\n"]
    for idx, (a_id, b_id, reason) in enumerate(batch):
        a, b = fmap[a_id], fmap[b_id]
        aa = assets.get(a.affected_asset_id)
        ba = assets.get(b.affected_asset_id)
        lines.append(f"PAIR {idx}:")
        lines.append(f"  A [{a_id}] ({a.layer.value}, grants={[c.value for c in a.grants]}): "
                     f"{a.title} on asset '{a.affected_asset_id}' "
                     f"({aa.data_classification if aa else '?'}). {a.description}")
        lines.append(f"  B [{b_id}] ({b.layer.value}, type={b.finding_type}): "
                     f"{b.title} on asset '{b.affected_asset_id}' "
                     f"({ba.data_classification if ba else '?'}). {b.description}")
        lines.append(f"  Reachability: {reason}")
    lines.append(
        "\nReturn ONLY a JSON array, one object per pair, no prose:\n"
        '[{"pair": 0, "enables": true, "confidence": 0.0-1.0, '
        '"rationale": "one sentence"}]')
    return "\n".join(lines)


def infer_edges(candidates, findings, assets, batch_size: int = 12,
                use_llm: bool | None = None,
                max_llm_batches: int | None = None) -> list[dict]:
    """
    Returns a list of confirmed edges:
      {a, b, confidence, rationale, method}
    Only edges with confidence >= 0.5 are returned.

    max_llm_batches caps how many batches are sent to the LLM in this call.
    Uncached pairs beyond the cap fall back to the deterministic heuristic so a
    single rebuild (e.g. triggered by an upload) can't fan out unbounded LLM
    calls. None means no cap.
    """
    fmap = {f.finding_id: f for f in findings}
    cache = _cache_load()
    results = []

    if use_llm is None:
        use_llm = _HAS_SDK and has_credentials()

    client = make_client() if use_llm else None
    if client is None:
        use_llm = False  # SDK/key unavailable — heuristic path

    # split into cached vs to-query
    pending = []
    for (a_id, b_id, reason) in candidates:
        a, b = fmap[a_id], fmap[b_id]
        key = _pair_key(a_id, b_id, a.description, b.description)
        if key in cache:
            c = cache[key]
            if c["confidence"] >= 0.5:
                results.append({"a": a_id, "b": b_id, **c})
        else:
            pending.append((a_id, b_id, reason, key))

    # Split pending into the slice the LLM will handle and the rest. When a cap
    # is set, only the first (max_llm_batches * batch_size) pairs go to the LLM;
    # everything past that falls back to the heuristic so the call stays bounded.
    llm_pending, heur_pending = pending, []
    if use_llm and max_llm_batches is not None and max_llm_batches >= 0:
        cutoff = max_llm_batches * batch_size
        llm_pending, heur_pending = pending[:cutoff], pending[cutoff:]
    elif not use_llm:
        llm_pending, heur_pending = [], pending

    def _heur(a_id, b_id, reason, key):
        conf, rat = _heuristic(fmap[a_id], fmap[b_id], reason)
        rec = {"confidence": conf, "rationale": rat,
               "method": "heuristic", "enables": conf >= 0.5}
        cache[key] = rec
        if conf >= 0.5:
            results.append({"a": a_id, "b": b_id, **rec})

    # LLM pass (bounded)
    for i in range(0, len(llm_pending), batch_size):
        batch_full = llm_pending[i:i + batch_size]
        batch = [(x[0], x[1], x[2]) for x in batch_full]
        prompt = _build_batch_prompt(batch, fmap, assets)
        try:
            resp = client.messages.create(
                model=MODEL, max_tokens=2000,
                messages=[{"role": "user", "content": prompt}])
            text = "".join(b.text for b in resp.content if b.type == "text")
            text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
            parsed = json.loads(text)
            for obj in parsed:
                pidx = obj["pair"]
                a_id, b_id, reason, key = batch_full[pidx]
                rec = {"confidence": float(obj.get("confidence", 0.0)),
                       "rationale": obj.get("rationale", ""),
                       "method": "llm",
                       "enables": bool(obj.get("enables", False))}
                cache[key] = rec
                if rec["enables"] and rec["confidence"] >= 0.5:
                    results.append({"a": a_id, "b": b_id, **rec})
        except Exception:
            # fall back to heuristic for this batch
            for (a_id, b_id, reason, key) in batch_full:
                _heur(a_id, b_id, reason, key)

    # Heuristic pass (no API key, or pairs beyond the per-call LLM cap)
    for (a_id, b_id, reason, key) in heur_pending:
        _heur(a_id, b_id, reason, key)

    _cache_save(cache)
    return results
