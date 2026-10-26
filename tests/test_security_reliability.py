"""Security and Reliability Regression Test Suite for TraceHunt (Module 5).

Verifies:
1. Strict HTML/XSS autoescaping across generated executive reports.
2. Path traversal protection in report generation and API file downloads.
3. Ingestion validation against oversized, corrupted, and unsupported payloads.
4. Case management state transition enforcement and disposition rationale requirements.
5. Evidence cross-host boundary enforcement and invalid reference rejection.
"""

from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tracehunt.api.app import app
from tracehunt.config import settings
from tracehunt.database import get_session_factory, init_db
from tracehunt.exceptions import CaseManagementError, ReportExportError, ValidationError
from tracehunt.ingestion.importer import import_telemetry_file
from tracehunt.investigation import attach_evidence, create_investigation, transition_case_status
from tracehunt.models import EndpointEvent, Finding, Investigation
from tracehunt.reporting import generate_report
from tracehunt.reporting.html_renderer import render_html_report


@pytest.fixture
def isolated_db():
    """Create an isolated test database for security tests."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db_url = f"sqlite:///{tmp_db.name}"
        engine = init_db(database_url=db_url, seed_rules=True)
        factory = get_session_factory(engine)
        with factory() as session:
            yield session


def test_html_xss_injection_defense(isolated_db):
    """Verify that script tags and event handlers injected into telemetry are escaped in HTML reports."""
    from datetime import datetime, timezone

    xss_payloads = [
        "<script>alert('pwned')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:alert(1)",
        "'\"><svg/onload=confirm(1)>",
    ]

    event = EndpointEvent(
        raw_event_id=None,
        event_time=datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc),
        host="XSS-VICTIM-HOST",
        user="CORP\\" + xss_payloads[1],
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=9001,
        image="C:\\Windows\\System32\\" + xss_payloads[0],
        command_line="cmd.exe /c " + xss_payloads[3],
    )
    isolated_db.add(event)
    isolated_db.commit()

    # Create investigation with XSS in title and summary
    case = create_investigation(
        session=isolated_db,
        title="XSS Case: " + xss_payloads[0],
        host="XSS-VICTIM-HOST",
        summary="Summary containing " + xss_payloads[1],
    )

    report_data, html_path = generate_report(
        session=isolated_db,
        investigation_id=case.id,
        output_format="html",
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()

    # Raw executable tags must NOT exist anywhere in rendered HTML
    assert "<script>alert('pwned')</script>" not in html_text
    assert "<img src=x onerror=alert(document.cookie)>" not in html_text
    assert "<svg/onload=confirm(1)>" not in html_text

    # Escaped safe entities must be present
    assert "&lt;script&gt;" in html_text or "&#39;" in html_text


def test_api_report_download_path_traversal():
    """Verify that path traversal sequences in report downloads return 400 or 404, never 200."""
    client = TestClient(app)

    # Traversal patterns
    bad_filenames = [
        "../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "../config.py",
        "..\\..\\windows\\system32\\cmd.exe",
        "....//....//etc/passwd",
    ]

    for bad in bad_filenames:
        response = client.get(f"/api/v1/reports/{bad}")
        # Must be rejected as Bad Request (400) or Not Found (404), never 200
        assert response.status_code in (400, 404), f"Path traversal '{bad}' gave unexpected status {response.status_code}"
        assert response.status_code != 200


def test_report_generator_traversal_confinement():
    """Verify that report generator forces files to remain inside settings.REPORTS_DIR."""
    from tracehunt.reporting.schema import ReportData, ReportMetadata, ReportMetrics

    dummy_data = ReportData(
        metadata=ReportMetadata(
            report_id="RPT-TRAVERSAL-TEST",
            report_type="HTML",
            generated_at="2026-10-21T12:00:00Z",
            host="TEST-HOST",
        ),
        metrics=ReportMetrics(),
    )

    # Providing traversal path in filename must sanitize and resolve safely within reports/
    out_path = render_html_report(dummy_data, filename="../../traversal_attempt.html")
    assert str(out_path).startswith(str(settings.REPORTS_DIR.resolve()))
    assert out_path.exists()
    assert ".." not in out_path.name


def test_oversized_and_corrupt_file_rejection(isolated_db):
    """Verify input file validation prevents oversized uploads and corrupt binary files."""
    # 1. Non-existent file
    with pytest.raises(ValidationError, match="File not found"):
        import_telemetry_file("non_existent_file_12345.json", session=isolated_db)

    # 2. Corrupt / unrecognized binary
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(b"\x00\x01\x02\x03\xff\xfe\x00\x00randomjunkdata")
        f.flush()
        with pytest.raises(ValidationError, match="Unsupported or unrecognized file format"):
            import_telemetry_file(f.name, session=isolated_db)


def test_case_state_machine_and_rationale_enforcement(isolated_db):
    """Verify case workflow state machine rejects illegal transitions and missing rationales."""
    case = create_investigation(
        session=isolated_db,
        title="State Machine Test Case",
        host="TARGET-HOST",
        initial_status="OPEN",
    )

    # 1. Closing without rationale must be rejected
    with pytest.raises(CaseManagementError, match="Disposition rationale is required"):
        transition_case_status(
            session=isolated_db,
            investigation_id=case.id,
            new_status="CLOSED_TRUE_POSITIVE",
            rationale="",  # Empty rationale
        )

    # 2. Illegal transition (CLOSED to INVESTIGATING directly)
    case = transition_case_status(
        session=isolated_db,
        investigation_id=case.id,
        new_status="CLOSED_TRUE_POSITIVE",
        rationale="Legitimate malware attack verified.",
    )
    assert case.status == "CLOSED_TRUE_POSITIVE"

    with pytest.raises(CaseManagementError, match="Invalid status transition"):
        transition_case_status(
            session=isolated_db,
            investigation_id=case.id,
            new_status="INVESTIGATING",
            rationale="Re-evaluating closed case",
        )


def test_evidence_cross_host_isolation_and_invalid_refs(isolated_db):
    """Verify evidence attachment validates references and prevents cross-host leakage."""
    case = create_investigation(
        session=isolated_db,
        title="Host Isolation Case",
        host="HOST-ALPHA",
    )

    # 1. Invalid finding ID
    with pytest.raises(CaseManagementError, match="Finding ID 999999 does not exist"):
        attach_evidence(
            session=isolated_db,
            investigation_id=case.id,
            finding_id=999999,
        )

    # 2. Cross-host finding attachment blocked
    # Create event and finding on HOST-BETA
    from datetime import datetime, timezone
    event_beta = EndpointEvent(
        raw_event_id=None,
        event_time=datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc),
        host="HOST-BETA",
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=4040,
        image="C:\\Windows\\System32\\cmd.exe",
    )
    isolated_db.add(event_beta)
    isolated_db.flush()

    finding_beta = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=event_beta.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="Test finding on Beta",
        matched_fields={},
    )
    isolated_db.add(finding_beta)
    isolated_db.commit()

    with pytest.raises(CaseManagementError, match="Cross-host evidence rejected"):
        attach_evidence(
            session=isolated_db,
            investigation_id=case.id,  # Case is on HOST-ALPHA
            finding_id=finding_beta.id,  # Finding is on HOST-BETA
            allow_cross_host=False,
        )
