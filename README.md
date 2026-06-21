# VulnIQ — Unified Multi-Layer Attack-Chain Correlation & Prioritization Engine

Every security tool screams in isolation. SAST finds a SQL injection. DAST finds an exposed admin endpoint. The infra scanner finds an unpatched library. The IAM scanner finds an over-privileged service account. Today, four different engineers triage these as four unrelated "Medium" findings — and none gets patched urgently.

**Chained together, they're a critical breach path.**

VulnIQ ingests findings from every OSI layer and every tool, builds an **attack graph**, finds the **chains** that connect low-severity findings into high-impact breach paths, and prioritizes the findings that *unlock the most dangerous chains*.

---

## AI architecture — one model, four agentic roles

**Model: `claude-opus-4-7`** (Anthropic). Used in four distinct agentic roles, each with its own system prompt, scope, and deterministic fallback.

| # | Role | File | What it does | Agentic pattern |
|---|---|---|---|---|
| 1 | **Extraction & Normalization Agent** *(the most crucial)* | `backend/app/ingestion/extraction_agent.py` | Deep-reads findings uploaded in **any format** (JSON, XML, CSV, XLSX, PDF) and **any documentation style**, and maps each into the unified schema. Infers OSI layer, finding type, and the attacker **capabilities** each finding grants — the basis for all chaining. Fills missing fields by reasoning, assigns an extraction-confidence, and flags low-confidence items for human review. | Deep-reading extraction + schema mapping + confidence scoring |
| 2 | **Edge Inference Agent** | `backend/app/graph/edge_agent.py` | For every candidate finding-pair, judges whether A's granted capability plausibly **ENABLES** exploitation of B. Returns confidence + rationale. Builds the semantic layer of the attack graph. | Batched (12 pairs/call) semantic classification with rationale |
| 3 | **Chain Narrator Agent** | `backend/app/agent/chain_narrator.py` | For each ranked attack chain, writes a 2–3 sentence attacker-perspective breach story shown under every chain card. | Structured prompt → natural language |
| 4 | **Dashboard Copilot Agent** | `backend/app/agent/dashboard_agent.py` | True ReAct-style tool-calling agent powering "Ask VulnIQ". Six tools, bounded loop, runs counterfactuals (`simulate_patch`). | True tool-calling agent |

**Why one model and not multi-model?** Claude is strong enough alone for all four jobs. A multi-model architecture would add integration cost, key management, latency, and failure surface for no measurable quality gain on these tasks. The right answer is one strong model in four well-scoped agentic roles, each with a deterministic fallback so the pipeline runs end-to-end even offline.

## File ingestion — the crucial front door

Teams submit findings in different formats and styles. The flow:

```
upload (JSON/XML/CSV/XLSX/PDF)
   → extractors.py            format → LLM-readable records
   → Extraction Agent (Role 1) records → normalized Findings + confidence + review queue
   → engine.ingest_uploads()  merge + recompute graph/chains/priorities
   → new findings chain immediately alongside everything else
```

Ambiguous/messy inputs (e.g. a hand-written observation with no CVE or severity) are **not** rejected — the agent infers the missing fields, lowers the confidence score, and adds the item to a **human review queue** surfaced in the dashboard. Upload via the **Upload Findings** tab (`POST /api/upload`).

See **`docs/SETUP.md`** for how to get an Anthropic key and run the whole thing.

---

## What works in this prototype

- **Unified finding schema** normalizing output from 11 simulated tools (Semgrep, Checkmarx, OWASP ZAP, Burp, Qualys, Nessus, Wiz, Trivy, Snyk, Prowler, ScoutSuite) across 7 OSI layers
- **Two-pass attack graph**
  - Pass 1 — deterministic edges: `EXPLOITS`, `EXPOSES`, `CORRELATES` (same root cause), `REACHES` (asset dependencies)
  - Pass 2 — LLM-inferred `ENABLES` edges (semantic capability handoffs), with a deterministic heuristic fallback so the demo runs offline
- **ChainRisk scoring** = EntryExposure × ExploitLikelihood × PathFeasibility × CrownJewelValue × ControlGap
- **Centrality-based finding priority** — a finding's tier reflects how many high-risk chains it sits on, not raw CVSS
- **Live threat intel** — NVD, FIRST.org EPSS, CISA KEV (with cached offline fallbacks for real CVEs in the dataset)
- **Embedded conversational agent** — Claude with 6 tools (read + action), including `simulate_patch` showstopper
- **Executive Brief generator** mapped to SEBI CSCRF, ISO 27001 A.8.8, RBI cyber-resilience
- **Interactive dashboard** with priority list, attack-chain narratives, force-directed graph visualization, posture stats, and the embedded agent

## Verified outcomes on the synthetic dataset

| Metric | Result |
|---|---|
| Total findings ingested | **153** |
| Across OSI layers | **7** |
| From tools | **11** |
| Cross-layer attack chains discovered | **11** |
| Findings correctly deferred as noise | **144 (94.1%)** |
| Top break-chain critical finding (F-00003) | **on 7 of 11 chains** |
| Patching that one finding | **collapses 7 chains, drops org risk 74.8%** |
| Top chain risk | **78.0** (Spring Actuator → Spring4Shell → hardcoded creds → ledger write) |

---

## Repository layout

```
vulniq/
├── README.md                          ← this file
├── backend/
│   ├── requirements.txt
│   ├── data/
│   │   ├── assets.json                
│   │   ├── synthetic_findings.json    ← 153 findings with 4 planted golden chains
│   │   └── generate_data.py
│   └── app/
│       ├── main.py                    ← FastAPI server (10 endpoints)
│       ├── models.py                  ← Finding / Asset / AttackChain / enums
│       ├── engine.py                  ← orchestrator (build pipeline + state)
│       ├── ingestion/
│       │   └── loader.py
│       ├── context/intel/
│       │   └── threat_intel.py        ← NVD / EPSS / KEV with cache + fallback
│       ├── graph/
│       │   ├── builder.py             ← deterministic edges + candidate ENABLES
│       │   ├── cwe_capability_map.py  ← CWE / finding-type → capability table
│       │   ├── edge_agent.py          ← LLM semantic edge inference (Pass 2)
│       │   └── chains.py              ← path-finding, ChainRisk, prioritization
│       ├── agent/
│       │   └── dashboard_agent.py     ← Claude agent + 6 tools + offline router
│       └── reports/
│           └── brief.py               ← executive brief w/ control mapping
├── frontend/
│   ├── dashboard.html                 ← standalone, runs in a browser
│   ├── dashboard_shell.html           ← HTML + CSS scaffold
│   ├── app.js                         ← dashboard logic, graph viz, agent
│   ├── data.js                        ← embedded data bundle
│   ├── bundle.json                    ← compact data
│   └── snapshot.json                  ← full engine snapshot
└── docs/
    ├── PROPOSAL.md
    ├── ARCHITECTURE.md
    ├── ROADMAP.md
    └── DEMO_SCRIPT.md
```

---

## Running the prototype

### Frontend (zero setup — for the demo)
Just open `frontend/dashboard.html` in any modern browser. It is fully self-contained: data is embedded, the agent and patch-simulator run locally in JS. No backend required for the demo.

### Backend (for live, real-data mode)
```bash
cd backend
pip install -r requirements.txt          # fastapi, networkx, anthropic, httpx
export ANTHROPIC_API_KEY=...             # optional — enables LLM edge inference + agent
uvicorn app.main:app --reload --port 8000
```
Endpoints:
- `GET  /api/health` · `GET /api/stats` · `GET /api/findings[?priority=&layer=]`
- `GET  /api/findings/{id}` · `GET /api/chains[?limit=]` · `GET /api/chains/{id}`
- `GET  /api/graph[?top_chains=]` — visualization payload
- `POST /api/agent` `{message, history}` — the embedded conversational agent
- `POST /api/simulate-patch` `{finding_ids: []}` — the showstopper
- `GET  /api/brief` — executive brief

The engine builds on startup. Without an API key, it uses the deterministic heuristic for semantic edges — the whole pipeline still runs, just with simpler edge confidences.

---

## Why this is differentiated

1. **It is the only approach that sees cross-tool chains.** Every existing scanner ranks within its own silo. CVSS, EPSS, KEV — none of them know about your other findings or your asset graph. VulnIQ is the missing layer between tools.
2. **The graph is real, not LLM-imagined.** Deterministic edges (capability handoffs from a transparent CWE table, asset reachability from CMDB-style data) form the skeleton. The LLM only refines semantic edges where the deterministic pass already says "plausibly connectable." Every chain is fully auditable — no black box.
3. **It produces actions, not just rankings.** The embedded agent can simulate a patch and tell the CISO "fix F-00003 — collapses 7 chains, −74.8% org risk." That is a board-level insight delivered in seconds.
4. **Compliance is baked in.** Every prioritization decision maps to SEBI CSCRF, ISO 27001 A.8.8, RBI cyber-resilience controls. The brief is regulator-ready by default.

---