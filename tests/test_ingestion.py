"""Tests for file validation, multi-format parsing, error isolation, and evidence persistence."""

from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.exceptions import ValidationError
from tracehunt.ingestion.importer import (
    extract_records,
    import_telemetry_content,
    import_telemetry_file,
)
from tracehunt.ingestion.validators import (
    detect_encoding,
    detect_file_format,
    validate_input_file,
)
from tracehunt.models import EndpointEvent, IngestionError, RawEvent


def test_format_detection_and_empty_file_rejection(tmp_path):
    """Verify format detection handles JSON array, JSONL, and CSV, and rejects empty files."""
    assert detect_file_format('[{"EventID": 1}]') == "json"
    assert detect_file_format('{"EventID": 1}\n{"EventID": 3}') == "jsonl"
    assert detect_file_format("EventID,UtcTime,Computer\n1,2026-10-21,HOST1") == "csv"

    # Empty string rejection
    with pytest.raises(ValidationError):
        detect_file_format("   \n  ")

    # Empty file rejection
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("")
    with pytest.raises(ValidationError) as exc:
        validate_input_file(empty_file)
    assert "0 bytes" in str(exc.value)


def test_import_valid_json_array_fixture(test_session: Session):
    """Verify importing a valid JSON array creates raw and normalized events."""
    fixture_path = Path("fixtures/benign/sysmon_proc_creation.json")
    summary = import_telemetry_file(fixture_path, test_session)

    assert summary.records_read == 3
    assert summary.records_parsed == 3
    assert summary.events_normalized == 3
    assert summary.duplicates_skipped == 0
    assert summary.records_rejected == 0
    assert summary.success_rate == 100.0

    # Verify database persistence
    raw_count = test_session.query(RawEvent).count()
    norm_count = test_session.query(EndpointEvent).count()
    assert raw_count == 3
    assert norm_count == 3

    # Check evidence lineage
    event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.process_id == 1024)).first()
    assert event is not None
    assert event.raw_event_id is not None
    assert event.raw_event.source == "sysmon_proc_creation.json"
    assert "services.exe" in event.raw_event.raw_payload


def test_import_valid_jsonl_fixture(test_session: Session):
    """Verify importing a valid JSONL file creates both network and termination events."""
    fixture_path = Path("fixtures/benign/sysmon_network.jsonl")
    summary = import_telemetry_file(fixture_path, test_session)

    assert summary.records_read == 2
    assert summary.events_normalized == 2
    assert summary.records_rejected == 0

    net_event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.event_id == 3)).first()
    assert net_event is not None
    assert net_event.ip_address == "192.168.1.50"
    assert net_event.port == 445

    term_event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.event_id == 5)).first()
    assert term_event is not None
    assert term_event.event_type == "PROCESS_TERMINATE"


def test_import_valid_csv_fixture(test_session: Session):
    """Verify importing CSV with headers correctly normalizes logon and process events."""
    fixture_path = Path("fixtures/benign/windows_security_logons.csv")
    summary = import_telemetry_file(fixture_path, test_session)

    assert summary.records_read == 3
    assert summary.events_normalized == 3

    logon_event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.event_id == 4624)).first()
    assert logon_event is not None
    assert logon_event.user == "alice"
    assert logon_event.ip_address == "10.0.0.15"

    proc_event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.event_id == 4688)).first()
    assert proc_event is not None
    assert proc_event.process_id == 420  # 0x1a4 parsed to decimal
    assert proc_event.parent_process_id == 1008  # 0x3f0 parsed to decimal


def test_malformed_records_continue_batch_and_record_errors(test_session: Session):
    """Verify malformed records do not terminate batch; valid records persist, errors isolate into ingestion_errors."""
    fixture_path = Path("fixtures/edge_cases/malformed_records.jsonl")
    summary = import_telemetry_file(fixture_path, test_session)

    # malformed_records.jsonl contains:
    # 1 valid record (PID 5001)
    # 1 malformed JSON line
    # 1 unsupported EventID 9999
    # 1 invalid timestamp
    # 1 corrupt PID
    # 1 valid record (PID 5004)
    # Total = 6 records read, 2 valid, 4 rejected
    assert summary.records_read == 6
    assert summary.events_normalized == 2
    assert summary.records_rejected == 4

    # Verify valid records persisted
    pids = [e.process_id for e in test_session.scalars(select(EndpointEvent)).all()]
    assert 5001 in pids
    assert 5004 in pids

    # Verify ingestion errors were logged in database
    errors = test_session.scalars(select(IngestionError)).all()
    assert len(errors) >= 4
    error_types = {e.error_type for e in errors}
    assert "JSONL_PARSE_ERROR" in error_types
    assert "NORMALIZATION_ERROR" in error_types


def test_unsupported_file_extension_and_content(tmp_path):
    """Verify unsupported file content is rejected with clear error message."""
    bad_file = tmp_path / "unknown.bin"
    bad_file.write_bytes(b"\x00\x01\x02\x03\x04BINARYDATA\xff\xfe")
    with pytest.raises(ValidationError) as exc:
        validate_input_file(bad_file)
    assert "Unsupported or unrecognized file format" in str(exc.value)


def test_encoding_detection_utf16_and_bom(tmp_path, test_session: Session):
    """Verify UTF-8 with BOM and UTF-16 files decode and import properly."""
    content = '[{"EventID": 1, "UtcTime": "2026-10-21 14:00:00", "ProcessId": 8000, "Computer": "HOST-BOM"}]'

    # UTF-8 with BOM
    bom_file = tmp_path / "sysmon_bom.json"
    bom_file.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))

    summary = import_telemetry_file(bom_file, test_session)
    assert summary.events_normalized == 1

    event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.process_id == 8000)).first()
    assert event is not None
    assert event.host == "HOST-BOM"
