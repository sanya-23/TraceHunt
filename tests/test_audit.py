"""Unit tests for Evidence Linking and Analyst Audit Logging Services.

Tests:
- Attaching findings, endpoint events, and raw events as evidence.
- Cross-host boundary enforcement (rejecting cross-host evidence unless explicitly allowed).
- Duplicate evidence attachment prevention (idempotent behavior).
- Invalid evidence entity references.
- Evidence removal preserving underlying telemetry and recording audit logs.
- Evidence retrieval ordered by sequence number.
- Append-only audit trail enforcement.
- Transactional consistency between case/evidence modifications and audit records.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import uuid
from tracehunt.exceptions import CaseManagementError
from tracehunt.investigation.audit_service import (
    get_case_audit_trail,
    get_recent_audit_logs,
    record_audit,
)
from tracehunt.investigation.case_service import (
    create_investigation,
    transition_case_status,
)
from tracehunt.investigation.evidence_service import (
    attach_evidence,
    get_case_evidence,
    remove_evidence,
)
from tracehunt.models import (
    AnalystAudit,
    EndpointEvent,
    Finding,
    Investigation,
    InvestigationEvidence,
    RawEvent,
)


def _setup_telemetry(session: Session, host: str = "WKSTN-FIN01"):
    raw = RawEvent(
        source="SYSMON",
        source_event_id="1",
        raw_payload=f'{{"Event": {{"System": {{"Computer": "{host}", "EventID": 1}}}}}}',
        sha256_hash=uuid.uuid4().hex + uuid.uuid4().hex[:32],
        parse_status="PARSED",
    )
    session.add(raw)
    session.flush()

    ev = EndpointEvent(
        raw_event_id=raw.id,
        host=host,
        event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=3000,
        parent_process_id=1000,
        image=r"C:\Windows\System32\powershell.exe",
        command_line="powershell.exe -enc AAAAA==",
    )
    session.add(ev)
    session.flush()

    finding = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=ev.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="PowerShell encoded command detected",
        matched_fields={"command_line": ev.command_line},
    )
    session.add(finding)
    session.flush()

    return raw, ev, finding


def test_attach_and_retrieve_evidence(test_session: Session) -> None:
    """Verify attaching raw events, endpoint events, and findings to an investigation."""
    raw, ev, finding = _setup_telemetry(test_session, host="WKSTN-FIN01")
    case = create_investigation(test_session, title="Financial Workstation Case", host="WKSTN-FIN01")

    # 1. Attach Finding
    ev_item1 = attach_evidence(
        test_session,
        investigation_id=case.id,
        finding_id=finding.id,
        reviewer="analyst_1",
        notes="Primary alert trigger",
    )
    assert ev_item1.sequence_number == 1
    assert ev_item1.finding_id == finding.id

    # 2. Attach EndpointEvent
    ev_item2 = attach_evidence(
        test_session,
        investigation_id=case.id,
        endpoint_event_id=ev.id,
        reviewer="analyst_1",
        notes="Correlated parent process execution",
    )
    assert ev_item2.sequence_number == 2
    assert ev_item2.endpoint_event_id == ev.id

    # 3. Attach RawEvent
    ev_item3 = attach_evidence(
        test_session,
        investigation_id=case.id,
        raw_event_id=raw.id,
        reviewer="analyst_1",
        notes="Original Sysmon JSON payload",
    )
    assert ev_item3.sequence_number == 3
    assert ev_item3.raw_event_id == raw.id

    # Retrieve all evidence
    evidence_list = get_case_evidence(test_session, case.id)
    assert len(evidence_list) == 3
    assert [e.sequence_number for e in evidence_list] == [1, 2, 3]

    # Verify audit trail contains all 3 evidence attachment entries + 1 case creation entry
    audit_trail = get_case_audit_trail(case.id, test_session)
    assert len(audit_trail) == 4
    attach_audits = [a for a in audit_trail if a.action == "EVIDENCE_ATTACHED"]
    assert len(attach_audits) == 3


def test_cross_host_boundary_protection(test_session: Session) -> None:
    """Verify attaching evidence from a different host is rejected without explicit authorization."""
    _, _, finding_host_b = _setup_telemetry(test_session, host="SRV-DATABASE")
    case_host_a = create_investigation(test_session, title="Host A Investigation", host="WKSTN-DESKTOP")

    # Attempting to attach finding from SRV-DATABASE to WKSTN-DESKTOP without flag must fail
    with pytest.raises(CaseManagementError, match="Cross-host evidence rejected"):
        attach_evidence(
            test_session,
            investigation_id=case_host_a.id,
            finding_id=finding_host_b.id,
            allow_cross_host=False,
        )

    # With explicit allow_cross_host=True, it succeeds
    item = attach_evidence(
        test_session,
        investigation_id=case_host_a.id,
        finding_id=finding_host_b.id,
        allow_cross_host=True,
        notes="Cross-host lateral pivot approved by SOC lead",
    )
    assert item is not None
    assert item.finding_id == finding_host_b.id


def test_duplicate_evidence_attachment_idempotence(test_session: Session) -> None:
    """Verify attaching the same evidence repeatedly returns the existing record without duplicating rows."""
    _, ev, _ = _setup_telemetry(test_session, host="WKSTN-IDEMP")
    case = create_investigation(test_session, title="Idempotent Case", host="WKSTN-IDEMP")

    ev1 = attach_evidence(test_session, case.id, endpoint_event_id=ev.id, notes="First attach")
    ev2 = attach_evidence(test_session, case.id, endpoint_event_id=ev.id, notes="Second attach attempt")

    assert ev1.id == ev2.id

    # Verify table has exactly 1 row for this case
    evidence_rows = get_case_evidence(test_session, case.id)
    assert len(evidence_rows) == 1


def test_invalid_evidence_references(test_session: Session) -> None:
    """Verify attempting to attach nonexistent case, finding, event, or raw event raises CaseManagementError."""
    _, ev, finding = _setup_telemetry(test_session, host="WKSTN-VALID")
    case = create_investigation(test_session, title="Valid Case", host="WKSTN-VALID")

    # Nonexistent case
    with pytest.raises(CaseManagementError, match="does not exist"):
        attach_evidence(test_session, "INV-NONEXISTENT", finding_id=finding.id)

    # No evidence specified
    with pytest.raises(CaseManagementError, match="At least one evidence entity"):
        attach_evidence(test_session, case.id)

    # Nonexistent finding
    with pytest.raises(CaseManagementError, match="Finding ID 999999 does not exist"):
        attach_evidence(test_session, case.id, finding_id=999999)

    # Nonexistent endpoint event
    with pytest.raises(CaseManagementError, match="EndpointEvent ID 999999 does not exist"):
        attach_evidence(test_session, case.id, endpoint_event_id=999999)

    # Nonexistent raw event
    with pytest.raises(CaseManagementError, match="RawEvent ID 999999 does not exist"):
        attach_evidence(test_session, case.id, raw_event_id=999999)


def test_remove_evidence_preserves_telemetry_and_audits(test_session: Session) -> None:
    """Verify removing an evidence link deletes junction row, keeps telemetry, and logs audit."""
    _, ev, finding = _setup_telemetry(test_session, host="WKSTN-DEL")
    case = create_investigation(test_session, title="Delete Link Case", host="WKSTN-DEL")

    ev_item = attach_evidence(test_session, case.id, finding_id=finding.id)
    evidence_id = ev_item.id

    # Remove evidence link
    removed = remove_evidence(
        test_session,
        case.id,
        evidence_id,
        reviewer="senior_analyst",
        reason="Finding deemed false positive during triage",
    )
    assert removed is True

    # Junction row deleted
    assert test_session.get(InvestigationEvidence, evidence_id) is None
    assert len(get_case_evidence(test_session, case.id)) == 0

    # Underlying finding and event are PRESERVED
    assert test_session.get(Finding, finding.id) is not None
    assert test_session.get(EndpointEvent, ev.id) is not None

    # Audit trail recorded removal
    trail = get_case_audit_trail(case.id, test_session)
    remove_audits = [a for a in trail if a.action == "EVIDENCE_REMOVED"]
    assert len(remove_audits) == 1
    assert "Finding deemed false positive" in remove_audits[0].comment


def test_append_only_audit_validation_and_recent_logs(test_session: Session) -> None:
    """Verify audit log validation prevents invalid actions, empty comments, and supports global logs."""
    case = create_investigation(test_session, title="Audit Validation Case", host="WKSTN-AUD")

    # Invalid action
    with pytest.raises(CaseManagementError, match="Invalid audit action"):
        record_audit(test_session, action="UNAUTHORIZED_ACTION", reviewer="r", comment="test")

    # Empty comment
    with pytest.raises(CaseManagementError, match="comment must not be empty"):
        record_audit(test_session, action="NOTE_ADDED", reviewer="r", comment="   ")

    # Recent global audit logs retrieval
    recent = get_recent_audit_logs(test_session, limit=10)
    assert len(recent) >= 1
    assert any(a.investigation_id == case.id for a in recent)


def test_transactional_consistency_between_case_and_audit(test_session: Session) -> None:
    """Verify atomicity: if an operation fails or rolls back, neither case state nor audit entry persists."""
    case = create_investigation(test_session, title="Rollback Case", host="WKSTN-RB")
    test_session.flush()
    case_id = case.id

    initial_audit_count = len(get_case_audit_trail(case_id, test_session))
    assert case.status == "OPEN"

    # Simulate a transaction that transitions status and creates audit, then encounters failure and rolls back
    try:
        with test_session.begin_nested():
            transition_case_status(
                test_session,
                case_id,
                new_status="INVESTIGATING",
                reviewer="analyst_test",
                rationale="Starting investigation",
            )
            # Deliberately raise exception before commit
            raise RuntimeError("Simulated mid-transaction failure")
    except RuntimeError:
        pass

    # Re-fetch case: status must still be OPEN, audit count must not have grown
    test_session.expire_all()
    refetched = test_session.get(Investigation, case_id)
    assert refetched is not None
    assert refetched.status == "OPEN"
    trail_after_rollback = get_case_audit_trail(case_id, test_session)
    assert len(trail_after_rollback) == initial_audit_count
