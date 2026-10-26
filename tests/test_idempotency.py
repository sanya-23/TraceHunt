"""Tests for SHA-256 fingerprinting, deduplication, and idempotent batch imports."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.ingestion.dedup import (
    IdempotencyManager,
    canonicalize_payload,
    compute_event_fingerprint,
    compute_sha256_fingerprint,
)
from tracehunt.ingestion.importer import import_telemetry_content
from tracehunt.models import EndpointEvent, RawEvent


def test_canonicalize_payload_key_order_insensitivity():
    """Verify canonicalize_payload is key-order and whitespace insensitive."""
    dict1 = {"event": 1, "host": "srv01", "cmd": "whoami"}
    dict2 = {"cmd": "whoami", "event": 1, "host": "srv01"}

    hash1 = compute_sha256_fingerprint(dict1)
    hash2 = compute_sha256_fingerprint(dict2)

    assert hash1 == hash2, "Identical payloads with different key ordering must yield identical hashes"


def test_duplicate_records_within_single_batch(test_session: Session):
    """Verify duplicate records inside the same batch are skipped without errors."""
    jsonl_content = (
        '{"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 100, "Computer": "HOST-A"}\n'
        '{"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 100, "Computer": "HOST-A"}\n'
        '{"EventID": 1, "UtcTime": "2026-10-21 14:00:05", "ProcessId": 200, "Computer": "HOST-A"}\n'
    )
    summary = import_telemetry_content(jsonl_content, "jsonl", "batch_test.jsonl", test_session)

    assert summary.records_read == 3
    assert summary.events_normalized == 2
    assert summary.duplicates_skipped == 1

    # Verify database counts
    raw_count = test_session.query(RawEvent).count()
    norm_count = test_session.query(EndpointEvent).count()
    assert raw_count == 2
    assert norm_count == 2


def test_reimporting_same_file_is_idempotent(test_session: Session):
    """Verify re-importing the identical file produces zero duplicate database rows."""
    json_content = (
        '[\n'
        '  {"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 500, "Computer": "HOST-B"},\n'
        '  {"EventID": 1, "UtcTime": "2026-10-21 14:00:10", "ProcessId": 600, "Computer": "HOST-B"}\n'
        ']'
    )

    # First import
    summary1 = import_telemetry_content(json_content, "json", "reimport.json", test_session)
    assert summary1.events_normalized == 2
    assert summary1.duplicates_skipped == 0

    initial_raw_count = test_session.query(RawEvent).count()
    initial_norm_count = test_session.query(EndpointEvent).count()

    # Second import with identical content
    summary2 = import_telemetry_content(json_content, "json", "reimport.json", test_session)
    assert summary2.records_read == 2
    assert summary2.events_normalized == 0
    assert summary2.duplicates_skipped == 2

    # Database count must remain strictly unchanged
    assert test_session.query(RawEvent).count() == initial_raw_count
    assert test_session.query(EndpointEvent).count() == initial_norm_count


def test_distinct_events_sharing_some_fields_are_not_merged(test_session: Session):
    """Verify distinct events sharing timestamp and host but having different PIDs or commands are preserved."""
    jsonl_content = (
        '{"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 701, "Image": "notepad.exe", "Computer": "HOST-C"}\n'
        '{"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 702, "Image": "calc.exe", "Computer": "HOST-C"}\n'
    )
    summary = import_telemetry_content(jsonl_content, "jsonl", "concurrency.jsonl", test_session)

    assert summary.records_read == 2
    assert summary.events_normalized == 2
    assert summary.duplicates_skipped == 0

    events = test_session.scalars(select(EndpointEvent).where(EndpointEvent.host == "HOST-C")).all()
    assert len(events) == 2
    images = {e.image for e in events}
    assert images == {"notepad.exe", "calc.exe"}


def test_idempotency_manager_hash_lookup(test_session: Session):
    """Verify IdempotencyManager correctly detects persisted hashes."""
    raw = RawEvent(
        source="manual_test",
        raw_payload='{"test": 123}',
        sha256_hash="deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
        parse_status="PARSED",
    )
    test_session.add(raw)
    test_session.flush()

    mgr = IdempotencyManager(test_session)
    assert mgr.is_hash_existing("deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678") is True
    assert mgr.is_hash_existing("non_existent_hash") is False
