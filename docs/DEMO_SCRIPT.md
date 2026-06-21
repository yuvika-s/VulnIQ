# VulnIQ — Demo Script (Demo Day, 19 June)

**Format:** 5 minutes, org-wide audience. One presenter (rotate), two backups ready to answer Q&A.

---

## [0:00–0:30] The Hook

> *"Your SAST tool found a Medium. Your DAST tool found a Medium. Your infra scanner found a Medium. Your IAM scanner found a Medium. Nobody patched any of them — they were all Medium. Tonight I'll show you they were a single funds-tampering breach path to the trading ledger, and no tool you own could ever have seen it."*

Open the dashboard. Hover on the topbar numbers: **11 chains · org risk 489.9 · 153 findings · 94% noise cut**.

---

## [0:30–1:30] The Problem — siloed tools

Click **Priorities** → click **🟠 Patch This Week** filter. Show the small handful of items.

> *"These are the only findings that actually matter this week — out of 153 findings from 11 different tools. The rest are noise on isolated systems."*

Click **🔴 Break-Chain Critical**. Four items appear, none of them CVSS-Critical.

> *"This 'Medium 6.5' on the partner portal is more dangerous than every Critical in our environment. Why? Because of what's downstream."*

---

## [1:30–3:00] The Solution — live attack-chain reveal

Click **Attack Chains** tab. Top chain expands automatically.

> *"Here's the most dangerous breach path right now, CH-0003, risk 78."*

Read the chain visually left-to-right:

1. **OWASP ZAP** found an exposed Spring Boot actuator on the partner portal (Medium)
2. **Trivy** found a vulnerable Spring framework on the same host (Spring4Shell RCE, CISA KEV)
3. **Semgrep** found hardcoded DB credentials in the settlement service code (Medium)
4. **IAM scan** found that DB user has write access to the trading ledger (Medium)

> *"Four tools, four 'Mediums', one critical funds-tampering path. The attacker hits the actuator, weaponizes the RCE, walks across the dependency graph to settlement-svc, reads the hardcoded creds, writes to the trading ledger. Nobody patches this today because no tool sees the whole picture."*

Click **Attack Graph** tab. The force-directed graph lays out. Drag a node to show interactivity.

> *"This is the unified graph — every finding from every tool, the assets, the crown jewels, the ENABLES handoffs in yellow. The shape of risk."*

---

## [3:00–4:00] The Showstopper — agentic action

Click **Ask VulnIQ** tab.

Tap suggestion: **"If I fix one thing, what breaks the most chains?"**

Agent responds in seconds:

> *"Patch **F-00003** (Hardcoded database credentials in settlement service) first. It collapses **7 of 11** attack chains and drops org risk by **74.8%** (from 489.9 to 123.6)."*

A green `−74.8%` simulation card animates in.

> *"That's the agentic answer. Not 'here's a list, good luck' — it ran a counterfactual across our entire graph and gave the CISO the one fix with the biggest blast radius. Twelve seconds, not four hours."*

Type: **"Generate a board brief for the trading ledger exposures"**

Agent answer + click **Exec Brief** tab.

---

## [4:00–4:45] The Brief — compliance baked in

The brief renders: headline KPIs, recommended first action with the -74.8% number, top 5 chains with narratives, break-chain critical findings, and at the bottom — **SEBI CSCRF, ISO 27001 A.8.8, RBI cyber-resilience** control mappings.

> *"Audit-ready by default. Every ranking traceable to a finding, an intel signal, an asset context. The CISO can sign this and our regulators get the answer they want — risk-based, justified, mapped."*

---

## [4:45–5:30] The Numbers + The Ask

Back to overview.

| Metric | Result |
|---|---|
| Cross-layer chains discovered | **11** |
| Noise cut | **94.1%** |
| Single-fix max impact | **−74.8% org risk** |
| Hidden criticals surfaced | **4** |
| Time from question to board answer | **seconds** |

> *"VulnIQ doesn't replace your engineers. It gives them their week back. It doesn't replace your tools. It makes them finally talk to each other. Phase 2 is a shadow pilot in Q3. We're ready."*

> *"The Triage, signing off."*

---

## Backup answers (when Q&A starts)

**Q: Why not just buy Vulcan / Brinqa / Nucleus?**
> Because their model is generic, and they'd need 9 months to integrate against our scanners and CMDB. VulnIQ is bespoke to Angel One's asset graph and ships with a working agent. Cost: an LLM API budget vs. $200K+/yr per vendor.

**Q: How do you handle LLM hallucination?**
> The LLM only refines semantic edges that the deterministic pass already flagged as plausible. Every edge carries a confidence score and a rationale, both audit-logged. The deterministic skeleton is fully transparent — no black box, no trust required.

**Q: What about LLM cost at scale?**
> The deterministic pre-filter cuts N² pairs down to a few hundred candidates. We batch 12 pairs per call. We cache by pair-hash so unchanged scans don't re-query. And the heuristic fallback means we can run zero-LLM if we want — the pipeline still works, just with simpler edge confidences.

**Q: What if a scanner's missing?**
> Coverage degrades gracefully — fewer findings, fewer chains, but everything that's there still ranks correctly. Adding a new tool is a new connector + adding any new finding types to the CWE→capability map. Hours, not weeks.

**Q: Does it work for non-CVE findings?**
> Yes. Misconfigs, IAM issues, hardcoded secrets — these are first-class citizens in the schema. CVSS is just one signal among many.

**Q: How do you keep this from being yet another dashboard nobody opens?**
> The embedded agent. Engineers don't need to open the dashboard — they ask it questions in Slack, get answers, take action. The dashboard exists for the moment when someone needs to see the picture.
