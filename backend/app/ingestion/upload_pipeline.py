"""
Upload pipeline — orchestrates the full ingest of a user-uploaded file:

  raw bytes
    -> extractors.extract()        (format -> LLM-readable records)
    -> extraction_agent            (records -> normalized Findings + review queue)
    -> ENGINE.ingest_uploads()     (merge + recompute graph/chains/priorities)
    -> summary

This is what the dashboard's upload button calls.
"""
from __future__ import annotations

import logging
import time

from app.ingestion import extractors
from app.ingestion.extraction_agent import extract_findings_from_records
from app.ai_config import MAX_UPLOAD_RECORDS
from app.engine import ENGINE

log = logging.getLogger("vulniq.upload")


# running counter so uploaded finding IDs stay unique across multiple uploads
_UPLOAD_COUNTER = {"n": 1000}


def process_upload(filename: str, content: bytes,
                   use_llm: bool | None = None) -> dict:
    t0 = time.time()
    log.info("upload received: %s (%d bytes, use_llm=%s)",
             filename, len(content), use_llm)

    # 0) Tenable export detection. A Tenable/Nessus CSV is normalized DETERMINIST-
    #    ically through the SAME tenable pipeline as a native API sync (source
    #    stays "Tenable"), not the LLM extraction path — so host findings get
    #    proper capabilities, IP→app correlation, ownership and chaining.
    is_tns = False
    try:
        from app.ingestion.tenable_csv import is_tenable_csv
        is_tns = is_tenable_csv(content)
    except Exception:
        log.exception("tenable-csv detection failed; treating as a generic upload")
    if is_tns:
        # Processing errors here surface (not silently downgraded to LLM extraction).
        return _process_tenable_export(filename, content, use_llm, t0)

    # 1) format extraction (no LLM — pure parsing)
    ex = extractors.extract(filename, content)
    log.info("phase 1/3 format extraction done: format=%s, %d record(s) in %.2fs",
             ex["format"], ex["record_count"], time.time() - t0)
    if not ex["records"]:
        return {"ok": False, "filename": filename, "format": ex["format"],
                "error": "No extractable content found.",
                "warnings": ex["warnings"]}

    # Bound the LLM work: a small file can still hold hundreds of records, each
    # of which would fan out into a sequential LLM call. Process at most
    # MAX_UPLOAD_RECORDS and report the rest rather than draining the budget.
    records = ex["records"]
    skipped = 0
    if MAX_UPLOAD_RECORDS > 0 and len(records) > MAX_UPLOAD_RECORDS:
        skipped = len(records) - MAX_UPLOAD_RECORDS
        log.warning("capping extraction at %d/%d records (set "
                    "VULNIQ_MAX_UPLOAD_RECORDS to change); %d deferred",
                    MAX_UPLOAD_RECORDS, len(records), skipped)
        records = records[:MAX_UPLOAD_RECORDS]

    # 2) AI normalization into the unified schema
    log.info("phase 2/3 AI normalization starting on %d record(s)...", len(records))
    t1 = time.time()
    result = extract_findings_from_records(
        records, ENGINE.assets, use_llm=use_llm,
        id_start=_UPLOAD_COUNTER["n"])
    _UPLOAD_COUNTER["n"] += max(len(result["findings"]), len(records)) + 1
    log.info("phase 2/3 normalization done: %d finding(s) via %s in %.2fs",
             len(result["findings"]), result["method"], time.time() - t1)

    # 3) merge into the live model and recompute everything
    log.info("phase 3/3 merge + recompute attack graph...")
    t2 = time.time()
    merge = ENGINE.ingest_uploads(result["findings"], use_llm=use_llm)
    log.info("phase 3/3 merge done in %.2fs; total upload %.2fs",
             time.time() - t2, time.time() - t0)

    # Persist a historical snapshot of this upload (no-op without DATABASE_URL).
    try:
        from app.db.repository import persist_run
        persist_run(source=f"Upload:{filename}", run_type="upload",
                    sync_metadata={"records": ex["record_count"],
                                   "extracted": result["stats"]["extracted"]})
    except Exception:
        log.exception("persistence: upload snapshot failed (engine unaffected)")

    return {
        "ok": True,
        "filename": filename,
        "format": ex["format"],
        "extractor_warnings": ex["warnings"],
        "records_found": ex["record_count"],
        "records_processed": len(records),
        "records_skipped": skipped,
        "extraction_method": result["method"],
        "extracted": result["stats"]["extracted"],
        "auto_accepted": result["stats"]["auto_accepted"],
        "needs_review": result["stats"]["needs_review"],
        "review_queue": result["review_queue"],
        "by_layer": result["stats"]["by_layer"],
        "merge": merge,
        "new_findings": [f.to_dict() for f in result["findings"]],
    }


def _process_tenable_export(filename: str, content: bytes,
                            use_llm: bool | None, t0: float) -> dict:
    """Ingest an uploaded Tenable CSV export via the unified Tenable pipeline."""
    from app.ingestion.tenable_csv import parse_tenable_csv
    from app.ingestion.tenable_normalize import normalize_tenable_records
    from app.ingestion.ip_match import load_ip_assets
    from app.context.intel.threat_intel import enrich_many
    from app.ai_config import (TENABLE_MAX_FINDINGS, TENABLE_SEVERITY, has_credentials)

    log.info("upload is a Tenable export — routing through the unified Tenable pipeline")
    raw = parse_tenable_csv(content, max_findings=TENABLE_MAX_FINDINGS,
                            severity=TENABLE_SEVERITY)
    if not raw:
        return {"ok": False, "filename": filename, "format": "tenable_csv",
                "error": "No Tenable findings matched the severity filter."}
    ip_map = load_ip_assets()
    findings = normalize_tenable_records(raw, ENGINE.assets, ip_map, do_enrich=False)
    enrich_many(findings)
    res = ENGINE.ingest_tenable(findings, use_llm=has_credentials() if use_llm is None else use_llm)

    try:
        from app.db.repository import persist_run
        persist_run(source="Tenable", run_type="tenable_upload",
                    sync_metadata={"file": filename, "raw_records": len(raw),
                                   "added": res["findings_added"],
                                   "updated": res["findings_updated"]})
    except Exception:
        log.exception("persistence: tenable upload snapshot failed (engine unaffected)")

    log.info("tenable export ingested: +%d findings in %.2fs",
             res["findings_added"], time.time() - t0)
    return {
        "ok": True, "filename": filename, "format": "tenable_csv",
        "source": "Tenable",
        "records_found": len(raw), "records_processed": len(findings),
        "extraction_method": "tenable_csv_deterministic",
        "extracted": len(findings),
        "merge": res,
        "by_source": res.get("by_source", {}),
    }
