"""Unit tests for Host Investigation Timeline Service.

Tests:
- Chronological ordering and deterministic tie-breaking.
- Multi-field filtering (host, time range, event types, process ID, user).
- Correlation with detection findings and severity filtering.
- Elimination of duplicate timeline entries from joins.
- Parameterized text search.
- Bounded pagination and limit enforcement.
- Handling of missing optional fields, empty results, and invalid time ranges.
- Host summary metrics calculation.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from tracehunt.exceptions import ValidationError
from tracehunt.investigation.timeline_service import (
    get_host_timeline,
    get_timeline_summary,
)
from tracehunt.models import EndpointEvent, Finding


def _create_event(
    session: Session,
    host: str = "WKSTN-01",
    event_time: datetime | None = None,
    event_id: int = 1,
    event_type: str = "PROCESS_CREATE",
    process_id: int | None = 1000,
    parent_process_id: int | None = 500,
    image: str | None = r"C:\Windows\System32\cmd.exe",
    command_line: str | None = "cmd.exe /c whoami",
    user: str | None = "CORP\\analyst",
    ip_address: str | None = None,
    port: int | None = None,
) -> EndpointEvent:
    ev = EndpointEvent(
        host=host,
        event_time=event_time or datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_id=event_id,
        event_type=event_type,
        process_id=process_id,
        parent_process_id=parent_process_id,
        image=image,
        command_line=command_line,
        user=user,
        ip_address=ip_address,
        port=port,
    )
    session.add(ev)
    session.flush()
    return ev


def test_timeline_chronological_ordering_and_deterministic_tie_breaking(test_session: Session) -> None:
    """Verify events are sorted by event_time ASC with deterministic tie-breaking on id ASC."""
    # Out of order insertion
    ev3 = _create_event(test_session, event_time=datetime(2026, 3, 30, 10, 5, 0, tzinfo=timezone.utc), image="p3.exe")
    ev1 = _create_event(test_session, event_time=datetime(2026, 3, 30, 9, 50, 0, tzinfo=timezone.utc), image="p1.exe")
    ev2a = _create_event(test_session, event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc), image="p2a.exe")
    ev2b = _create_event(test_session, event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc), image="p2b.exe")

    timeline = get_host_timeline(test_session, host="WKSTN-01")

    assert len(timeline) == 4
    # Expected order: ev1 (09:50), ev2a (10:00, lower ID), ev2b (10:00, higher ID), ev3 (10:05)
    assert [item.id for item in timeline] == [ev1.id, ev2a.id, ev2b.id, ev3.id]
    assert timeline[1].image == "p2a.exe"
    assert timeline[2].image == "p2b.exe"


def test_timeline_filtering_by_host_time_range_event_type_process_and_user(test_session: Session) -> None:
    """Verify independent and combined filtering across host, time, event_type, pid, and user."""
    _create_event(
        test_session,
        host="WKSTN-01",
        event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_type="PROCESS_CREATE",
        process_id=101,
        user="CORP\\alice",
    )
    _create_event(
        test_session,
        host="WKSTN-01",
        event_time=datetime(2026, 3, 30, 11, 0, 0, tzinfo=timezone.utc),
        event_type="NETWORK_CONNECT",
        process_id=102,
        user="CORP\\bob",
    )
    _create_event(
        test_session,
        host="SRV-DC01",
        event_time=datetime(2026, 3, 30, 11, 30, 0, tzinfo=timezone.utc),
        event_type="USER_LOGON",
        process_id=103,
        user="CORP\\alice",
    )

    # 1. Host filter isolates WKSTN-01
    w1_items = get_host_timeline(test_session, host="WKSTN-01")
    assert len(w1_items) == 2
    assert all(i.host == "WKSTN-01" for i in w1_items)

    # 2. Time range filter
    time_filtered = get_host_timeline(
        test_session,
        host="WKSTN-01",
        start_time=datetime(2026, 3, 30, 10, 30, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 3, 30, 11, 30, 0, tzinfo=timezone.utc),
    )
    assert len(time_filtered) == 1
    assert time_filtered[0].event_type == "NETWORK_CONNECT"

    # 3. Event type filter
    type_filtered = get_host_timeline(test_session, host="WKSTN-01", event_types=["PROCESS_CREATE"])
    assert len(type_filtered) == 1
    assert type_filtered[0].event_type == "PROCESS_CREATE"

    # 4. Process ID filter
    pid_filtered = get_host_timeline(test_session, host="WKSTN-01", process_id=102)
    assert len(pid_filtered) == 1
    assert pid_filtered[0].process_id == 102

    # 5. User filter
    user_filtered = get_host_timeline(test_session, host="WKSTN-01", user="alice")
    assert len(user_filtered) == 1
    assert user_filtered[0].user == "CORP\\alice"


def test_timeline_finding_correlation_and_severity_filtering(test_session: Session) -> None:
    """Verify findings are correctly joined without Cartesian product and severity filters work."""
    ev_clean = _create_event(test_session, image="clean.exe")
    ev_high = _create_event(test_session, image="suspicious.exe")
    ev_multi = _create_event(test_session, image="attack.exe")

    # Attach findings
    f1 = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=ev_high.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="PowerShell encoded execution",
        matched_fields={"command_line": "powershell -enc"},
    )
    f2 = Finding(
        rule_id="RULE-003-RECON",
        endpoint_event_id=ev_multi.id,
        severity="MEDIUM",
        confidence="MEDIUM",
        rationale="Discovery command execution",
        matched_fields={"command_line": "whoami"},
    )
    f3 = Finding(
        rule_id="RULE-004-EVASION",
        endpoint_event_id=ev_multi.id,
        severity="CRITICAL",
        confidence="HIGH",
        rationale="Masqueraded binary in Temp",
        matched_fields={"image": r"C:\Windows\Temp\malware.exe"},
    )
    test_session.add_all([f1, f2, f3])
    test_session.flush()

    # 1. Total events on host
    all_items = get_host_timeline(test_session, host="WKSTN-01")
    assert len(all_items) == 3

    # 2. Filter has_findings=True
    flagged = get_host_timeline(test_session, host="WKSTN-01", has_findings=True)
    assert len(flagged) == 2
    assert {i.id for i in flagged} == {ev_high.id, ev_multi.id}

    # 3. Filter has_findings=False
    unflagged = get_host_timeline(test_session, host="WKSTN-01", has_findings=False)
    assert len(unflagged) == 1
    assert unflagged[0].id == ev_clean.id

    # 4. Filter by severity="CRITICAL"
    crit = get_host_timeline(test_session, host="WKSTN-01", severity="CRITICAL")
    assert len(crit) == 1
    assert crit[0].id == ev_multi.id
    assert crit[0].max_severity == "CRITICAL"
    assert len(crit[0].findings) == 2  # Contains both MEDIUM and CRITICAL findings

    # 5. Filter by severity list ["HIGH", "CRITICAL"]
    high_crit = get_host_timeline(test_session, host="WKSTN-01", severity=["HIGH", "CRITICAL"])
    assert len(high_crit) == 2


def test_timeline_no_duplicate_events_caused_by_joins(test_session: Session) -> None:
    """Ensure that an event with multiple findings is represented exactly ONCE in timeline."""
    ev = _create_event(test_session, image="multi_hit.exe")

    # Add 3 distinct findings for this event
    rule_ids = ["RULE-001-LOLBIN", "RULE-002-PROC-SPAWN", "RULE-003-RECON"]
    for i, sev in enumerate(["LOW", "MEDIUM", "HIGH"]):
        f = Finding(
            rule_id=rule_ids[i],
            endpoint_event_id=ev.id,
            severity=sev,
            confidence="HIGH",
            rationale=f"Rationale {i+1}",
            matched_fields={"test": i},
        )
        test_session.add(f)
    test_session.flush()

    timeline = get_host_timeline(test_session, host="WKSTN-01")
    assert len(timeline) == 1
    item = timeline[0]
    assert item.id == ev.id
    assert len(item.findings) == 3
    assert item.max_severity == "HIGH"
    assert item.has_detection is True


def test_timeline_text_search(test_session: Session) -> None:
    """Verify safe parameterized text search across process names, command lines, and IPs."""
    _create_event(test_session, image=r"C:\Tools\mimikatz.exe", command_line="mimikatz.exe privilege::debug")
    _create_event(test_session, image=r"C:\Windows\System32\svchost.exe", command_line="svchost.exe -k netsvcs")
    _create_event(test_session, ip_address="192.168.1.50")

    # Search for "mimikatz"
    res1 = get_host_timeline(test_session, search_query="mimikatz")
    assert len(res1) == 1
    assert "mimikatz" in res1[0].image

    # Search for IP
    res2 = get_host_timeline(test_session, search_query="192.168.1")
    assert len(res2) == 1
    assert res2[0].ip_address == "192.168.1.50"

    # Search non-matching query
    res3 = get_host_timeline(test_session, search_query="nonexistent_string_12345")
    assert len(res3) == 0


def test_timeline_pagination_and_bounded_limits(test_session: Session) -> None:
    """Verify pagination limits, offsets, and bounding to max 1000 items."""
    for i in range(12):
        _create_event(
            test_session,
            event_time=datetime(2026, 3, 30, 10, i, 0, tzinfo=timezone.utc),
            command_line=f"cmd_{i}.exe",
        )

    # Page 1: limit 5, offset 0
    page1 = get_host_timeline(test_session, host="WKSTN-01", limit=5, offset=0)
    assert len(page1) == 5
    assert page1[0].command_line == "cmd_0.exe"
    assert page1[4].command_line == "cmd_4.exe"

    # Page 2: limit 5, offset 5
    page2 = get_host_timeline(test_session, host="WKSTN-01", limit=5, offset=5)
    assert len(page2) == 5
    assert page2[0].command_line == "cmd_5.exe"
    assert page2[4].command_line == "cmd_9.exe"

    # Page 3: limit 5, offset 10
    page3 = get_host_timeline(test_session, host="WKSTN-01", limit=5, offset=10)
    assert len(page3) == 2
    assert page3[0].command_line == "cmd_10.exe"
    assert page3[1].command_line == "cmd_11.exe"


def test_timeline_missing_optional_fields_and_invalid_ranges(test_session: Session) -> None:
    """Verify graceful handling of nullable telemetry and detection of invalid filter ranges."""
    # Create event with sparse fields
    ev = EndpointEvent(
        host="WKSTN-MIN",
        event_time=datetime(2026, 3, 30, 12, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=None,
        parent_process_id=None,
        image=None,
        command_line=None,
        user=None,
    )
    test_session.add(ev)
    test_session.flush()

    timeline = get_host_timeline(test_session, host="WKSTN-MIN")
    assert len(timeline) == 1
    item = timeline[0]
    assert item.image is None
    assert item.command_line is None
    assert item.user is None
    assert item.has_detection is False
    assert item.to_dict()["image"] is None

    # Empty result on unknown host
    unknown = get_host_timeline(test_session, host="NONEXISTENT-HOST")
    assert unknown == []

    # Invalid time range raises ValidationError
    with pytest.raises(ValidationError, match="is after end_time"):
        get_host_timeline(
            test_session,
            start_time=datetime(2026, 3, 30, 15, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        )


def test_timeline_summary_metrics(test_session: Session) -> None:
    """Verify get_timeline_summary correctly computes event and severity aggregations."""
    ev1 = _create_event(test_session, host="HOST-METRIC", event_type="PROCESS_CREATE")
    ev2 = _create_event(test_session, host="HOST-METRIC", event_type="NETWORK_CONNECT")

    f = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=ev1.id,
        severity="CRITICAL",
        confidence="HIGH",
        rationale="Critical hit",
        matched_fields={},
    )
    test_session.add(f)
    test_session.flush()

    summary = get_timeline_summary(test_session, host="HOST-METRIC")
    assert summary["host"] == "HOST-METRIC"
    assert summary["total_events"] == 2
    assert summary["total_findings"] == 1
    assert summary["event_counts"]["PROCESS_CREATE"] == 1
    assert summary["event_counts"]["NETWORK_CONNECT"] == 1
    assert summary["severity_counts"]["CRITICAL"] == 1
    assert summary["severity_counts"]["LOW"] == 0
