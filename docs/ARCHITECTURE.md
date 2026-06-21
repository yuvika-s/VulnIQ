# VulnIQ — Architecture

## The core idea

Every security tool emits findings in a different format and lives in its own silo. Real attacks ignore silos — they chain a SAST bug to a runtime exposure to an unpatched library to an over-privileged identity, walking through the asset graph until they touch something valuable.

VulnIQ is the layer that finally makes all those tools talk to each other.

## Three design principles

1. **Graph for structure and math. LLM for semantics and explanation.** Don't make the LLM do graph traversal. Make it build and narrate the graph; let `networkx` compute paths and centrality.
2. **Deterministic skeleton, LLM refinement.** The CWE → capability table is a transparent, auditable lookup. The asset reachability graph is data from your CMDB. Only the *semantic* "does A really enable B?" judgment uses the LLM, and only on pre-filtered candidates.
3. **Run offline if needed.** A demo at a conference cannot break on a flaky API. Threat-intel APIs cache aggressively + have offline fallbacks for real CVEs. The edge agent has a deterministic heuristic. The dashboard ships with all its data embedded.

## The unified finding schema

```python
Finding(
  finding_id, source_tool, layer, finding_type, title, description,
  raw_severity, cvss, cwe, cve, affected_asset_id, component, location,
  network_exposure,                # internet | internal | isolated
  evidence,
  # enriched at runtime:
  epss, in_kev,
  # computed by the engine:
  grants: [Capability],            # what the attacker gains
  priority,                        # break_chain_critical | this_week | this_month | defer
  chain_count, centrality, final_score
)
```

`Layer` ∈ {source_code, appsec_runtime, dependency, infra_host, container, cloud_config, iam_identity, network, data}

`Capability` ∈ {initial_access, code_execution, credential_access, data_read, data_write, priv_escalation, lateral_move, funds_access}

The Capability vocabulary is the *bridge* between findings from different tools. A SAST SQLi grants `data_read + credential_access`. A DAST exposed endpoint grants `initial_access`. Chains form where the **grants** of one finding satisfy the **requires** of the next.

## The attack graph

Built in `networkx.MultiDiGraph`. Node `kind` ∈ {finding, asset, crown_jewel}. Edge `kind`:

| Edge | Built by | Meaning |
|---|---|---|
| EXPOSES | deterministic | finding sits on this asset |
| EXPLOITS | deterministic | finding grants this capability (from CWE/type map) |
| CORRELATES | deterministic | two findings share a CVE or component (same root cause) |
| REACHES | deterministic | asset depends on / can reach another asset |
| ENABLES | **LLM-inferred + heuristic** | A's grants plausibly enable exploitation of B |

### Cost control on the LLM pass

We never ask the LLM about all N² pairs. The deterministic pass produces *candidates* only where:
- B's `requires` capabilities are non-empty AND
- A grants at least one of those capabilities AND
- B's asset is either the same as A's, or REACHES-connected to it

In the prototype this reduces N²≈23,000 pairs to a few hundred candidates. Batch size 12 pairs/call. Pair-hash cache. The LLM verdict is `{enables: bool, confidence: 0–1, rationale: str}`.

## Chain analysis

```
1. add ENABLES edges (confidence ≥ 0.5) to the graph
2. find_chains():
     for each EXPOSED, capability-granting entry finding,
       for each finding that reaches a crown jewel,
         enumerate all_simple_paths through ENABLES (depth ≤ 6)
3. score each chain:
     ChainRisk = EntryExposure × ExploitLikelihood
                × PathFeasibility × CrownJewelValue × ControlGap
4. prioritize_findings():
     build subgraph of top-20 chains
     centrality = nx.betweenness_centrality(subgraph)
     tier by (centrality, chain_count, KEV, EPSS, exposure)
```

Tiers:
- 🔴 **Break-Chain Critical** — high centrality, on ≥ 3 chains
- 🟠 **Patch This Week** — on a chain, internet-facing or in KEV or EPSS ≥ 0.5
- 🟡 **Patch This Month** — on a chain, contained
- ⚪ **Defer** — not on any viable chain (the 94% noise)

## The embedded agent

Claude with six tools:
- `get_top_chains(n)` — read
- `query_findings(priority, layer, internet_only, limit)` — read
- `get_stats(dimension)` — read
- `get_asset_risk(asset_id)` — read
- `best_single_fix()` — read with computation
- `simulate_patch(finding_ids)` — **action**: removes findings, recomputes chains, returns delta

Bounded agentic loop (≤6 tool calls). When no API key is present, a deterministic intent router gives the same tool access so the demo runs offline. The router uses the same tool functions, returning identical answers.

## What runs where

| Component | Backend (Python) | Frontend (browser) |
|---|---|---|
| Ingestion + graph build | ✅ | — |
| LLM edge inference | ✅ | — |
| Chain enumeration & scoring | ✅ | — |
| Threat intel | ✅ | (data baked in) |
| Embedded agent | ✅ (Claude + tools) | ✅ (offline JS port) |
| `simulate_patch` | ✅ (full recompute) | ✅ (chain-subset, identical results on this data) |
| Executive brief | ✅ | (rendered from snapshot) |

The frontend can run standalone for the demo by loading the prebuilt snapshot. In production, it would call the FastAPI endpoints.

---

# Persistence & Historical Intelligence Layer

Persistence sits **underneath** the attack-path engine — the chaining, evidence,
objective, leverage and P1–P5 logic is unchanged. When `DATABASE_URL` is unset
the whole layer is a no-op and VulnIQ runs in its original in-memory/JSON mode.

```
                ┌─────────────────────────── nginx ───────────────────────────┐
                │  /  -> dashboard (frontend/)      /api/* -> reverse proxy     │
                └───────────────────────────┬──────────────────────────────────┘
                                             │
┌──────────────────────────── FastAPI (api) ─┴───────────────────────────────┐
│  Routes: /api/upload, /api/sync/snyk, /api/snapshot, /api/history/*         │
│                                                                             │
│  Attack-path ENGINE (unchanged)        Persistence layer (additive)         │
│   build → graph → chains → evidence     app/db/                             │
│   → objectives → leverage → P1–P5        ├── database.py  (engine/session)  │
│        │                                 ├── orm.py       (SQLAlchemy models)│
│        │ after every sync/upload         ├── repository.py(snapshot/query/   │
│        └────────── persist_run() ───────►│                 compare/trends)   │
│                                          ├── seed.py      (seed + hydrate)   │
│  on startup: build → bootstrap_persistence│└── routes_history.py (API)       │
│   (seed once, then hydrate latest run)   │                                   │
└──────────────────────────────────────────┴──── Alembic ──► PostgreSQL ──────┘
                                                              (postgres_data vol)
```

## Layers
- **FastAPI layer** — unchanged routes plus `/api/history`, `/api/history/{id}`,
  `/api/history/compare`, `/api/history/trends`, `/api/history/executive`.
- **Repository layer** (`app/db/repository.py`) — the only code that reads/writes
  the DB. Snapshots the live engine into a run, serves runs in `/api/snapshot`
  shape, computes comparisons and trend series.
- **SQLAlchemy ORM** (`app/db/orm.py`) — `ScanRun`, `FindingRow`, `ChainRow`,
  `GraphSnapshot`, `SeedMeta`. Heavy nested data is stored as JSON columns with
  high-signal fields promoted to indexed columns.
- **Alembic** — schema migrations; `alembic upgrade head` runs on deploy (via
  `deploy/setup_ec2.sh`), with a `create_all` fallback for SQLite/dev.
- **PostgreSQL** — durable store (AWS RDS in production; any SQLAlchemy URL locally).

## Historical run model (immutable snapshots)
```
ScanRun (one per sync/upload — a full posture snapshot, never overwritten)
  ├── FindingRow[]    findings as they were that run (+ stable fingerprint)
  ├── ChainRow[]      attack chains as computed that run (+ stable signature)
  ├── GraphSnapshot   nodes + edges for that run
  └── metrics (JSON)  severity/source/asset/objective/confidence/leverage dists,
                      risk + crown-jewel + internet-exposure scores
```
Chain snapshots are **stored, not recalculated** on demand — viewing run #41 shows
exactly what was computed then.

## Trend-analysis architecture (accuracy)
Trends compare **unique state**, not execution count:
- a finding's identity is a content **fingerprint** (asset+type+cwe+cve+title+
  component) — independent of volatile run-local ids;
- a chain's identity is a **signature** (objective + member fingerprints).

So re-running an identical scan yields identical fingerprints → 0 new / 0
resolved → no false trend movement. Comparison (`compare_runs`) diffs the
fingerprint/signature sets between two runs to produce new/resolved findings,
new/removed chains, P1/risk/objective deltas, and most-improved / most-regressed
assets for executive reporting.

## Attack-graph persistence
Each run stores a compact node/edge `GraphSnapshot` built from that run's chains,
so historical graphs are redrawn from storage without rebuilding old graphs.

## Restart behaviour
On startup the engine builds from JSON (empty in real-data mode), then
`bootstrap_persistence()` seeds run #1 on first boot and otherwise **hydrates the
live engine from the latest run** (`Finding.from_dict` → `_rebuild`) so all live
endpoints reflect persisted data immediately after a restart.
