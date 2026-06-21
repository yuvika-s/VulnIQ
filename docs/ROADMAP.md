# VulnIQ — Roadmap

## Phase 1 — Buildathon prototype (now)

- Synthetic dataset, ~150 findings across 7 OSI layers and 11 simulated tools
- 4 planted golden chains demonstrating cross-layer attack paths
- Deterministic + LLM-inferred attack graph in `networkx`
- ChainRisk scoring and centrality-based priority tiering
- Embedded conversational agent with action tools (`simulate_patch`, brief generation)
- Standalone dashboard rendering the full picture
- All code on GitHub, runs offline, fully verified

## Phase 2 — Internal pilot (Q3 2026)

- **Real scanner connectors** — Semgrep, Checkmarx (SAST), OWASP ZAP, Burp Suite (DAST), Snyk, Trivy (SCA), Qualys, Nessus, Wiz (infra/cloud), Prowler (cloud-config), custom IAM scanner
- **CMDB integration** — pull real asset graph (criticality, exposure, data classification, dependency graph) from Angel One's CMDB / service catalog
- **Shadow-mode 30 days** alongside current SecOps prioritization
- Measure agreement rate; tune scoring weights based on analyst feedback
- Migrate from in-memory `networkx` to **Neo4j** for persistence and scale

## Phase 3 — Workflow integration (Q4 2026)

- **Auto-Jira ticketing** with SLA timer + auto-assignment from CMDB owner data
- **Slack notifications** to asset owners with chain context
- **Closed-loop learning** — when analyst overrides a priority, capture as training signal; auto-tune scoring weights
- **Engineer attribution** — track who patches what; identify training gaps
- **API for security review** — partner teams query VulnIQ ("is this service safe to launch?") and get a chain-aware answer

## Phase 4 — Predictive layer (Q1 2027)

- Forecast which currently-low-priority vulnerabilities will spike based on:
  - EPSS trend (rate of change, not just current value)
  - Public exploit publication (GitHub PoCs, ExploitDB, X/Twitter chatter)
  - Dark-web telemetry (industry-specific exploit kits)
- Pre-emptively elevate dormant chains before they activate
- **Time-decay model** — older patches without compensating controls bubble up

## Phase 5 — Cross-domain fusion (Q2 2027)

- **Fusion with AI-SOC Copilot** — when SOC detects an attack technique (MITRE ATT&CK), VulnIQ instantly answers "which of our chains does this activate?" The SOC can preempt by isolating those assets.
- **TPRM integration** — generate vendor vulnerability scorecards using the same chain model on partner-exposed services
- **Threat-modelling automation** — for new service launches, VulnIQ pre-models the would-be chains based on planned architecture

## Phase 6 — Partner & Sub-broker extension (Q3 2027)

This is the bridge to the brief's "AI for Partners & Sub Brokers" opportunity area. Sub-brokers connect to Angel One systems; their hygiene is Angel One's risk.

- **Hygiene scorecards** for connected third parties — chain-aware, not just CVSS
- **Onboarding gate** — partners must clear a chain-risk threshold before connecting
- **Continuous monitoring** of partner-facing chains
- **Regulatory reporting** for sub-broker exposure aggregated up to SEBI CSCRF reporting

## What we explicitly will not do

- **Replace human analysts.** VulnIQ ranks; humans decide and patch. The agent never auto-applies patches in production.
- **Train a custom model.** Off-the-shelf Claude with tool-calling is more than enough; bespoke models add cost without quality.
- **Build a SOC product.** VulnIQ is for vulnerability management. It hands off to SOC tools, doesn't replace them.
- **Add features that erode the audit trail.** Every prioritization decision must remain traceable. We will refuse upgrades that black-box the reasoning.
