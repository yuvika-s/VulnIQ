"""
VulnIQ engine orchestrator.

Runs the full pipeline once and holds the resulting state in memory:
  load -> base graph -> correlation -> candidate edges -> LLM inference
       -> enable edges -> chains -> finding prioritization

Everything (API, agent) reads from the singleton `ENGINE`.
"""
from __future__ import annotations

import networkx as nx

from app.ingestion.loader import load_findings, load_assets, load_golden_chains
from app.graph.builder import (build_base_graph, add_correlation_edges,
                               candidate_enable_edges)
from app.graph.edge_agent import infer_edges
from app.graph.chains import (add_enable_edges, find_chains, prioritize_findings)
from app.models import AttackChain


class Engine:
    def __init__(self):
        self.findings = []
        self.assets = {}
        self.graph: nx.MultiDiGraph | None = None
        self.chains: list[AttackChain] = []
        self.golden_chains = {}
        self.enable_edges = []
        self.correlation_clusters = 0
        self._built = False

    def build(self, use_llm: bool | None = None):
        self.assets = load_assets()
        self.findings = load_findings(do_enrich=True)
        self.golden_chains = load_golden_chains()
        self._use_llm = use_llm
        self._rebuild(use_llm=use_llm)
        self._built = True
        return self

    def _ensure_assets_for_findings(self):
        """Register a standalone low-tier asset for any finding whose asset isn't
        in the inventory. Happens when a repo couldn't be mapped to an
        application (no app-name token in the repo). These still show on the
        dashboard, just at low priority — never silently dropped."""
        from app.models import Asset
        for f in self.findings:
            aid = f.affected_asset_id
            if aid and aid not in self.assets:
                self.assets[aid] = Asset(
                    asset_id=aid, name=aid, tier=3, internet_facing=False,
                    data_classification="unknown",
                    business_function="auto-registered (unmapped repo)",
                    is_crown_jewel=False)

    def _dedup_exact(self):
        """Merge exact-duplicate findings (the same scanner result emitted twice)
        so they don't inflate chain counts, org risk or leverage. Two findings
        are the same only when asset, type, CWE/CVE, package and file location all
        match. Near-duplicates (same fix, different file) are kept and grouped for
        display instead. The survivor records how many were merged."""
        for f in self.findings:                          # every finding has a source
            if not f.sources:
                f.sources = [f.source_tool]
        seen, out = {}, []
        for f in self.findings:
            key = (f.affected_asset_id, f.finding_type, f.cwe, f.cve,
                   (f.component or "").strip().lower(),
                   (f.title or "").strip().lower(),
                   (f.location or "").strip().lower())
            if key in seen:
                s = seen[key]
                s.duplicate_count += f.duplicate_count   # accumulate exact dupes
                for src in f.sources:                    # preserve all origins
                    if src not in s.sources:
                        s.sources.append(src)
            else:
                seen[key] = f
                out.append(f)
        self.findings = out

    def _merge_cross_source(self):
        """Merge the SAME issue reported by different source systems (e.g. Snyk
        Code SQLi + a manual AppSec VAPT SQLi) into one finding that records both
        sources. Conservative: only collapses across *different* systems (Snyk vs
        manual), keyed by (asset, CVE) or (asset, CWE, type). Same-system
        instances are left for remediation grouping."""
        def system(f):
            return "snyk" if (f.source_tool or "").lower().startswith("snyk") else "manual"

        groups: dict = {}
        for f in self.findings:
            key = (f.affected_asset_id, f.cve) if f.cve \
                else (f.affected_asset_id, f.cwe, f.finding_type)
            groups.setdefault(key, []).append(f)

        removed = set()
        for key, items in groups.items():
            if len({system(f) for f in items}) < 2:
                continue                                  # single system — leave it
            items.sort(key=lambda x: -(x.cvss or 0))      # keep the most severe
            survivor = items[0]
            for f in items[1:]:
                for src in f.sources:
                    if src not in survivor.sources:
                        survivor.sources.append(src)
                survivor.duplicate_count += f.duplicate_count
                if not survivor.external_id and f.external_id:
                    survivor.external_id = f.external_id
                removed.add(f.finding_id)
        if removed:
            self.findings = [f for f in self.findings if f.finding_id not in removed]

    def _tag_remediation(self):
        """One remediation group per (asset, thing-you-fix): a package@version for
        dependency/container findings, otherwise the rule (CWE/type). The
        prioritized list collapses each group into a single actionable row."""
        for f in self.findings:
            comp = (f.component or "").strip()
            if comp:
                f.remediation_group = f"{f.affected_asset_id}|pkg:{comp.lower()}"
                f.remediation_action = f"Upgrade {comp}"
            else:
                rule = f.cwe or f.finding_type or "issue"
                f.remediation_group = f"{f.affected_asset_id}|rule:{rule.lower()}"
                f.remediation_action = f"Fix {f.finding_type or f.cwe or 'issue'}"

    def _rebuild(self, use_llm: bool | None = None,
                 max_llm_batches: int | None = None):
        """(Re)build graph -> edges -> chains -> priorities from self.findings."""
        self._dedup_exact()
        self._merge_cross_source()
        self._ensure_assets_for_findings()
        self._tag_remediation()
        self.graph = build_base_graph(self.findings, self.assets)
        self.correlation_clusters = add_correlation_edges(self.graph, self.findings)

        from app.ai_config import MAX_ENABLE_CANDIDATES
        # Scale the candidate budget by how many SOURCE SYSTEMS are present, so
        # integrating a new source (Tenable) never starves another source's chains
        # by crowding the shared budget. Single-source inventories keep the exact
        # base budget, so a Snyk-only (or manual-only) run stays byte-for-byte
        # reproducible — critical for the content-fingerprinted trend/compare logic.
        max_cand = MAX_ENABLE_CANDIDATES
        if max_cand:
            systems = set()
            for f in self.findings:
                st = (f.source_tool or "").lower()
                systems.add("snyk" if st.startswith("snyk")
                            else "tenable" if st.startswith("tenable") else "manual")
            max_cand = MAX_ENABLE_CANDIDATES * max(1, len(systems))
        candidates = candidate_enable_edges(self.graph, self.findings, self.assets,
                                            max_candidates=max_cand)
        self.enable_edges = infer_edges(candidates, self.findings, self.assets,
                                        use_llm=use_llm,
                                        max_llm_batches=max_llm_batches)
        add_enable_edges(self.graph, self.enable_edges)

        self.chains = find_chains(self.graph, self.findings, self.assets)
        prioritize_findings(self.findings, self.chains, self.assets)

        # Engineering ownership: deterministically stamp owner_head/business_unit
        # on every finding and primary_owner/secondary_owners on every chain. Runs
        # AFTER chains so chain-endpoint inheritance (tier 4) can apply. Never
        # touches chaining logic — it only annotates the resolved state.
        from app.ownership.resolver import resolve_all
        resolve_all(self.findings, self.chains, self.assets)

    def ingest_uploads(self, new_findings: list, use_llm: bool | None = None):
        """
        Merge freshly-extracted uploaded findings into the live model and
        recompute the entire attack graph + chains + priorities so the new
        findings participate in chaining alongside everything already loaded.
        Returns a summary of what changed.
        """
        from app.context.intel.threat_intel import enrich
        from app.graph.cwe_capability_map import grants_for

        chains_before = len(self.chains)
        # de-dupe by id, enrich, ensure capabilities present
        existing_ids = {f.finding_id for f in self.findings}
        added = 0
        for f in new_findings:
            if f.finding_id in existing_ids:
                continue
            if not f.grants:
                f.grants = grants_for(f)
            try:
                enrich(f)  # add EPSS / KEV where a CVE exists
            except Exception:
                pass
            self.findings.append(f)
            existing_ids.add(f.finding_id)
            added += 1

        if use_llm is None:
            use_llm = getattr(self, "_use_llm", None)
        # Cap LLM edge calls for uploads: existing pairs are already cached from
        # the startup build, so only the new finding's pairs are uncached. The
        # cap stops a high-fan-out upload from re-querying the LLM across the
        # whole graph (the cause of slow, token-hungry uploads). Set <0 to lift.
        from app.ai_config import UPLOAD_MAX_EDGE_BATCHES
        cap = UPLOAD_MAX_EDGE_BATCHES if UPLOAD_MAX_EDGE_BATCHES >= 0 else None
        self._rebuild(use_llm=use_llm, max_llm_batches=cap)

        # which new findings landed on a chain
        new_on_chains = [f.finding_id for f in new_findings
                         if f.chain_count and f.chain_count > 0]
        return {
            "added": added,
            "chains_before": chains_before,
            "chains_after": len(self.chains),
            "new_chains_formed": max(0, len(self.chains) - chains_before),
            "uploaded_findings_on_chains": new_on_chains,
            "total_findings": len(self.findings),
        }

    def ingest_snyk(self, snyk_findings: list, use_llm: bool | None = None) -> dict:
        """Incremental native-Snyk ingest. Replaces the previously-synced Snyk
        set with the fresh one (tracked by external_id), then recomputes the
        whole unified graph so Snyk findings chain alongside manual uploads.
        Returns added/updated/removed counts."""
        prior = {f.external_id: f for f in self.findings
                 if f.external_id and (f.source_tool or "").lower().startswith("snyk")}
        incoming = {f.external_id: f for f in snyk_findings if f.external_id}
        added = [e for e in incoming if e not in prior]
        updated = [e for e in incoming if e in prior]
        removed = [e for e in prior if e not in incoming]

        # keep everything that isn't a previously-synced Snyk finding, add fresh
        self.findings = [f for f in self.findings
                         if not (f.external_id and f.external_id in prior)]
        self.findings.extend(snyk_findings)

        if use_llm is None:
            use_llm = getattr(self, "_use_llm", None)
        from app.ai_config import UPLOAD_MAX_EDGE_BATCHES
        cap = UPLOAD_MAX_EDGE_BATCHES if UPLOAD_MAX_EDGE_BATCHES >= 0 else None
        self._rebuild(use_llm=use_llm, max_llm_batches=cap)
        return {
            "findings_added": len(added),
            "findings_updated": len(updated),
            "findings_removed": len(removed),
            "total_findings": len(self.findings),
            "by_source": self.counts_by_source(),
        }

    def ingest_tenable(self, tenable_findings: list, use_llm: bool | None = None) -> dict:
        """Incremental native-Tenable ingest. Identical contract to ingest_snyk:
        replace the previously-synced Tenable set (tracked by external_id), add
        the fresh one, then recompute the ONE unified graph so Tenable host
        findings chain alongside Snyk + manual findings. Returns add/update/remove
        counts. No Tenable-specific chaining anywhere — same engine for all."""
        def is_tenable(f):
            return (f.source_tool or "").lower().startswith("tenable")

        prior = {f.external_id: f for f in self.findings
                 if f.external_id and is_tenable(f)}
        incoming = {f.external_id: f for f in tenable_findings if f.external_id}
        added = [e for e in incoming if e not in prior]
        updated = [e for e in incoming if e in prior]
        removed = [e for e in prior if e not in incoming]

        # keep everything that isn't a previously-synced Tenable finding, add fresh
        self.findings = [f for f in self.findings
                         if not (f.external_id and f.external_id in prior)]
        self.findings.extend(tenable_findings)

        if use_llm is None:
            use_llm = getattr(self, "_use_llm", None)
        from app.ai_config import UPLOAD_MAX_EDGE_BATCHES
        cap = UPLOAD_MAX_EDGE_BATCHES if UPLOAD_MAX_EDGE_BATCHES >= 0 else None
        self._rebuild(use_llm=use_llm, max_llm_batches=cap)
        return {
            "findings_added": len(added),
            "findings_updated": len(updated),
            "findings_removed": len(removed),
            "total_findings": len(self.findings),
            "by_source": self.counts_by_source(),
        }

    def counts_by_source(self) -> dict:
        """Findings grouped by originating source (a finding can have several)."""
        out: dict[str, int] = {}
        for f in self.findings:
            for s in (f.sources or [f.source_tool]):
                out[s] = out.get(s, 0) + 1
        return out

    # --- query helpers used by API + agent ---
    def finding(self, fid):
        return next((f for f in self.findings if f.finding_id == fid), None)

    def chain(self, cid):
        return next((c for c in self.chains if c.chain_id == cid), None)

    def stats(self):
        by_layer, by_priority, by_tool = {}, {}, {}
        by_owner, by_bu = {}, {}
        for f in self.findings:
            by_layer[f.layer.value] = by_layer.get(f.layer.value, 0) + 1
            p = f.priority.value if f.priority else "unset"
            by_priority[p] = by_priority.get(p, 0) + 1
            by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
            oh = getattr(f, "owner_head", None) or "Miscellaneous"
            by_owner[oh] = by_owner.get(oh, 0) + 1
            bu = getattr(f, "business_unit", None) or "Miscellaneous"
            by_bu[bu] = by_bu.get(bu, 0) + 1
        chains_by_owner: dict = {}
        for c in self.chains:
            po = getattr(c, "primary_owner", None) or "Miscellaneous"
            chains_by_owner[po] = chains_by_owner.get(po, 0) + 1
        cj = sum(1 for a in self.assets.values() if a.is_crown_jewel)
        # Org risk = total risk across ALL chains, not just the top 10. The
        # top-10 form was simpler but it makes patching simulations look like
        # a no-op when the collapsed chains live outside the top 10 (e.g. fix
        # breaks 4 of 336 chains but org risk reads unchanged). Summing the
        # whole portfolio keeps stats.org_risk_score, simulate_patch, and the
        # brief's recommended-first-action % aligned on the same metric.
        org_risk = round(sum(c.chain_risk for c in self.chains), 1)
        return {
            "total_findings": len(self.findings),
            "total_assets": len(self.assets),
            "crown_jewels": cj,
            "total_chains": len(self.chains),
            "correlation_clusters": self.correlation_clusters,
            "by_layer": by_layer,
            "by_priority": by_priority,
            "by_tool": by_tool,
            "by_source": self.counts_by_source(),
            "by_owner": by_owner,
            "by_business_unit": by_bu,
            "chains_by_owner": chains_by_owner,
            "org_risk_score": org_risk,
            "top_chain_risk": self.chains[0].chain_risk if self.chains else 0,
        }

    def simulate_patch(self, finding_ids: list[str]):
        """Remove findings, recompute chains, return the delta. The showstopper."""
        before_chains = len(self.chains)
        # Sum over ALL chains (matches stats.org_risk_score). Top-10-only made
        # the drop% read 0 when the collapsed chains were outside the top tier.
        before_risk = round(sum(c.chain_risk for c in self.chains), 1)

        remaining = [f for f in self.findings if f.finding_id not in finding_ids]
        G = build_base_graph(remaining, self.assets)
        add_correlation_edges(G, remaining)
        # reuse already-inferred enable edges that don't touch removed findings
        edges = [e for e in self.enable_edges
                 if e["a"] not in finding_ids and e["b"] not in finding_ids]
        add_enable_edges(G, edges)
        new_chains = find_chains(G, remaining, self.assets)

        after_chains = len(new_chains)
        after_risk = round(sum(c.chain_risk for c in new_chains), 1)
        collapsed = before_chains - after_chains
        risk_drop_pct = round((before_risk - after_risk) / before_risk * 100, 1) if before_risk else 0
        return {
            "patched": finding_ids,
            "chains_before": before_chains,
            "chains_after": after_chains,
            "chains_collapsed": collapsed,
            "org_risk_before": before_risk,
            "org_risk_after": after_risk,
            "risk_drop_pct": risk_drop_pct,
        }


ENGINE = Engine()
