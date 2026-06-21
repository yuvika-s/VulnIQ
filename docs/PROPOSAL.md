# VulnIQ — Proposal

## Executive Summary

VulnIQ is a unified, multi-layer, attack-chain-aware vulnerability prioritization engine. It ingests findings from every security tool Angel One operates — SAST, DAST, SCA, infra scanners, container scanners, cloud-config scanners, IAM scanners — normalizes them into one schema, fuses them with live threat intelligence (NVD / EPSS / CISA KEV) and Angel One's asset context, then builds an **attack graph** and ranks findings by their role in viable breach paths to crown-jewel assets.

The result: a 94%+ reduction in noise, the surfacing of cross-layer attack chains that no single tool can see, and an audit-ready prioritization aligned with SEBI CSCRF, ISO 27001, and RBI mandates.

## Problem

| | |
|---|---|
| Today's scanners produce | ~10,000–50,000 open findings at any moment |
| Each tool's view | only its own layer; no cross-tool correlation |
| CVSS-based triage | overweights isolated criticals, underweights chains |
| Result | engineers spend 60–70% of time on findings that aren't on any real breach path, while genuine multi-layer chains sit unaddressed |
| Compliance | SEBI CSCRF & RBI mandate *risk-based* prioritization, with audit trail — current process produces neither |

## Solution architecture

```
   8 simulated tools                    NVD · EPSS · CISA KEV         CMDB-style asset graph
        ↓                                       ↓                              ↓
 ┌────────────────────────────────────────────────────────────────────────────────────┐
 │              INGESTION — Unified Finding Schema (Layer × Capability)               │
 └────────────────────────────────────────────────────────────────────────────────────┘
                                          ↓
 ┌────────────────────────────────────────────────────────────────────────────────────┐
 │  GRAPH BUILDER                                                                     │
 │  Pass 1 (deterministic):  EXPLOITS · EXPOSES · CORRELATES · REACHES               │
 │  Pass 2 (LLM agent):      ENABLES (semantic capability handoff, scored 0–1)       │
 └────────────────────────────────────────────────────────────────────────────────────┘
                                          ↓
 ┌────────────────────────────────────────────────────────────────────────────────────┐
 │  CHAIN ANALYSIS                                                                    │
 │  paths = all simple paths (entry → crown jewel, depth ≤ 6)                         │
 │  ChainRisk = EntryExposure × ExploitLikelihood × PathFeasibility ×                 │
 │              CrownJewelValue × ControlGap                                          │
 │  finding tier = betweenness centrality on union of top-N chain paths               │
 └────────────────────────────────────────────────────────────────────────────────────┘
                                          ↓
                Dashboard · Embedded Agent (Q&A + actions) · Executive Brief
```

**Why this design wins:** the graph is the right data structure for chains, the LLM is used only where semantics matter (not for graph traversal), and the whole system is fully auditable — every chain is traceable to specific findings, intelligence signals, and edge confidences.

## Success metrics

| Metric | Baseline (today, tool-siloed) | VulnIQ v1 (verified on prototype) | Phase-2 target (real data) |
|---|---:|---:|---:|
| Findings shown to engineers | ~50,000 | **9** on chains + ~36 noise sample | top ~50 |
| Cross-layer attack chains surfaced | 0 | **11** | all viable to crown jewels |
| Noise-cut rate | 0% | **94.1%** | ≥95% |
| Hidden criticals (low-CVSS findings on critical chains) | invisible | **4 surfaced** as Break-Chain Critical | all surfaced |
| Single-fix max impact | n/a | **−74.8% org risk in one patch** | proven on real data |
| Mean time to patch true-critical | ~60 days | n/a (prototype) | <10 days |
| Triage hours / engineer / week | ~25 | n/a | ~8 |
| Audit trail completeness | manual, partial | **100% — every ranking traceable** | 100% regulator-mapped |
| Time to "what's our worst exposure" answer | hours | **seconds** via embedded agent | seconds |

## Measurement plan (Phase 2 pilot)

- **Shadow-mode pilot:** run VulnIQ alongside the current SecOps workflow for 30 days. Capture agreement-rate between VulnIQ top-50 and analyst-confirmed top-50.
- **A/B on time-to-patch:** two pods, one on VulnIQ ranking, one on current ranking. Measure days-to-closure on critical findings.
- **Engineer-time survey:** before/after on hours/week spent on triage.
- **Compliance audit dry-run:** present the auto-generated brief to internal audit; score on completeness/justifiability.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucination on semantic edges | Layer 1 deterministic scores always shown; LLM only confirms candidates; every edge has confidence + rationale audit-logged; offline heuristic fallback validates LLM judgments |
| Stale threat intel | EPSS/KEV refreshed hourly; NVD daily; intel cache invalidated on scan ingest |
| Asset-context inaccuracy | CMDB integration in Phase 2; manual override + analyst feedback loop in v1 |
| LLM cost at scale | Deterministic pre-filter reduces N² candidate pairs to a few hundred; batched calls; pair-hash cache; LLM optional (offline heuristic delivers full pipeline) |
| Adversarial CVE descriptions (prompt injection) | Strict prompt boundaries; tool-call schema validation; LLM output validated against deterministic graph |
| Cross-tool finding deduplication | `CORRELATES` clusters by shared CVE/component; 24 clusters surfaced in prototype |

## Differentiation vs. alternatives

| Option | Cost | Limitation |
|---|---|---|
| **CVSS-only triage** (today) | $0 | No context; misses chains; produces noise |
| **Commercial vuln-mgmt platform** (Vulcan, Brinqa, Nucleus) | $200K+/yr | Slow integration; vendor's risk model; opaque |
| **A RAG chatbot on policies** | low | Answers questions but takes no action; doesn't rank |
| **VulnIQ** | internal build; LLM API only | Custom to Angel One assets; agentic; explainable; ours |
