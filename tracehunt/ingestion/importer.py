"""Batch telemetry importer for JSON, JSON Lines, and CSV formats.

Parses records independently, calculates SHA-256 idempotency fingerprints,
persists raw event evidence, normalizes supported schemas, isolates malformed
records into ingestion_errors, and returns an IngestionSummary.
"""

import csv
import io
import json
import time
from pathlib import Path
from typing import Any
from sqlalchemy.orm import Session

from tracehunt.exceptions import NormalizationError, ValidationError
from tracehunt.ingestion.dedup import IdempotencyManager, compute_sha256_fingerprint
from tracehunt.ingestion.normalizer import normalize_event
from tracehunt.ingestion.validators import SupportedFormat, validate_input_file
from tracehunt.logging_config import get_logger
from tracehunt.models import EndpointEvent, IngestionError, RawEvent
from tracehunt.schemas.event import IngestionSummary, RawIngestedRecord

logger = get_logger("importer")


def extract_records(content: str, file_format: SupportedFormat, source_name: str) -> tuple[list[RawIngestedRecord], list[dict[str, Any]]]:
    """Parse text content into a list of RawIngestedRecord objects and extraction errors."""
    records: list[RawIngestedRecord] = []
    extraction_errors: list[dict[str, Any]] = []

    if file_format == "json":
        try:
            parsed = json.loads(content)
            if not isinstance(parsed, list):
                if isinstance(parsed, dict):
                    # Single object JSON
                    parsed = [parsed]
                else:
                    raise ValidationError(f"JSON root must be an array or object, got {type(parsed).__name__}")

            for idx, item in enumerate(parsed, start=1):
                if isinstance(item, dict):
                    records.append(RawIngestedRecord(record_index=idx, source_name=source_name, payload=item))
                else:
                    extraction_errors.append({
                        "record_index": idx,
                        "error_type": "JSON_SCHEMA_ERROR",
                        "details": f"Expected dictionary object in JSON array at index {idx}, got {type(item).__name__}",
                        "snippet": str(item)[:200],
                    })
        except json.JSONDecodeError as e:
            extraction_errors.append({
                "record_index": 0,
                "error_type": "JSON_PARSE_ERROR",
                "details": f"Failed to parse JSON file: {e}",
                "snippet": content[:300],
            })

    elif file_format == "jsonl":
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue  # Skip empty lines
            try:
                item = json.loads(line_str)
                if isinstance(item, dict):
                    records.append(RawIngestedRecord(record_index=idx, source_name=source_name, payload=item))
                else:
                    extraction_errors.append({
                        "record_index": idx,
                        "error_type": "JSONL_SCHEMA_ERROR",
                        "details": f"Expected JSON dictionary on line {idx}, got {type(item).__name__}",
                        "snippet": line_str[:200],
                    })
            except json.JSONDecodeError as e:
                extraction_errors.append({
                    "record_index": idx,
                    "error_type": "JSONL_PARSE_ERROR",
                    "details": f"Invalid JSON on line {idx}: {e}",
                    "snippet": line_str[:200],
                })

    elif file_format == "csv":
        try:
            # Use csv.Sniffer to check dialect / delimiter if possible
            sample = content[:4096]
            delimiter = ","
            if ";" in sample and sample.count(";") > sample.count(","):
                delimiter = ";"

            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
            if not reader.fieldnames:
                extraction_errors.append({
                    "record_index": 1,
                    "error_type": "CSV_HEADER_ERROR",
                    "details": "CSV file is missing a valid header row.",
                    "snippet": content[:200],
                })
            else:
                for idx, row in enumerate(reader, start=2):  # Line 1 is header
                    # Filter out None or empty keys
                    clean_row = {str(k).strip(): v for k, v in row.items() if k is not None}
                    records.append(RawIngestedRecord(record_index=idx, source_name=source_name, payload=clean_row))
        except Exception as e:
            extraction_errors.append({
                "record_index": 0,
                "error_type": "CSV_PARSE_ERROR",
                "details": f"Failed to parse CSV: {e}",
                "snippet": content[:200],
            })

    return records, extraction_errors


def import_telemetry_content(
    content: str,
    file_format: SupportedFormat,
    source_name: str,
    session: Session,
) -> IngestionSummary:
    """Ingest raw telemetry content string into raw_events and normalized endpoint_events."""
    start_time = time.perf_counter()
    summary = IngestionSummary(source_file=source_name)

    # 1. Parse raw content into records
    records, extraction_errors = extract_records(content, file_format, source_name)
    summary.records_read = len(records) + len(extraction_errors)

    # 2. Persist extraction-level errors (e.g. malformed JSON lines)
    for err in extraction_errors:
        ingest_err = IngestionError(
            source=source_name,
            error_type=err["error_type"],
            details=err["details"],
            raw_record_snippet=err.get("snippet"),
        )
        session.add(ingest_err)
        summary.records_rejected += 1
        summary.errors.append(err)

    if not records and extraction_errors:
        session.commit()
        summary.duration_seconds = round(time.perf_counter() - start_time, 4)
        return summary

    idempotency = IdempotencyManager(session)
    seen_in_batch_hashes: set[str] = set()

    # 3. Process each record independently
    for rec in records:
        # Savepoint for isolating per-record transaction errors
        sp = session.begin_nested()
        try:
            # Deterministic fingerprint of raw payload
            sha256_hash = compute_sha256_fingerprint(rec.payload)

            # Check for duplicates (both in DB and earlier in current batch)
            if sha256_hash in seen_in_batch_hashes or idempotency.is_hash_existing(sha256_hash):
                summary.duplicates_skipped += 1
                sp.rollback()
                continue

            seen_in_batch_hashes.add(sha256_hash)

            # Store RawEvent evidence
            raw_payload_json = json.dumps(rec.payload, sort_keys=True, default=str)
            source_eid = str(rec.payload.get("EventID") or rec.payload.get("event_id") or "") or None

            raw_event = RawEvent(
                source=source_name,
                source_event_id=source_eid,
                raw_payload=raw_payload_json,
                sha256_hash=sha256_hash,
                parse_status="PENDING",
            )
            session.add(raw_event)
            session.flush()  # Obtain raw_event.id

            # Attempt normalization
            try:
                norm_schema = normalize_event(rec.payload, raw_event_id=raw_event.id)

                endpoint_event = EndpointEvent(
                    raw_event_id=raw_event.id,
                    event_time=norm_schema.event_time,
                    host=norm_schema.host,
                    user=norm_schema.user,
                    event_id=norm_schema.event_id,
                    event_type=norm_schema.event_type,
                    process_id=norm_schema.process_id,
                    parent_process_id=norm_schema.parent_process_id,
                    image=norm_schema.image,
                    command_line=norm_schema.command_line,
                    parent_image=norm_schema.parent_image,
                    parent_command_line=norm_schema.parent_command_line,
                    logon_id=norm_schema.logon_id,
                    logon_type=norm_schema.logon_type,
                    ip_address=norm_schema.ip_address,
                    port=norm_schema.port,
                    hashes=norm_schema.hashes,
                )
                session.add(endpoint_event)
                raw_event.parse_status = "PARSED"
                summary.records_parsed += 1
                summary.events_normalized += 1

            except (NormalizationError, Exception) as norm_err:
                raw_event.parse_status = "FAILED"
                ingest_err = IngestionError(
                    source=f"{source_name}:line_{rec.record_index}",
                    error_type="NORMALIZATION_ERROR",
                    details=str(norm_err),
                    raw_record_snippet=raw_payload_json[:500],
                )
                session.add(ingest_err)
                summary.records_rejected += 1
                summary.errors.append({
                    "record_index": rec.record_index,
                    "error_type": "NORMALIZATION_ERROR",
                    "details": str(norm_err),
                })

            sp.commit()

        except Exception as e:
            sp.rollback()
            logger.warning(f"Failed processing record {rec.record_index} in {source_name}: {e}")
            summary.records_rejected += 1
            summary.errors.append({
                "record_index": rec.record_index,
                "error_type": "RECORD_PROCESSING_ERROR",
                "details": str(e),
            })

    # Final transaction commit
    session.commit()
    summary.duration_seconds = round(time.perf_counter() - start_time, 4)
    logger.info(
        f"Ingestion complete for {source_name}: {summary.records_read} read, "
        f"{summary.events_normalized} normalized, {summary.duplicates_skipped} duplicates, "
        f"{summary.records_rejected} errors in {summary.duration_seconds}s"
    )
    return summary


def import_telemetry_file(file_path: Path | str, session: Session) -> IngestionSummary:
    """Validate, decode, and import an endpoint telemetry file from disk."""
    path = Path(file_path)
    content, file_format = validate_input_file(path)
    return import_telemetry_content(content, file_format, path.name, session)
