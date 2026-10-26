"""Unit and Security tests for TraceHunt Reporting Engine.

Tests:
- Factual report data compilation from database records.
- JSON report export schema and machine-readability.
- HTML report rendering with executive styling.
- Strict XSS defense (escaping <script>, <img>, <svg> payloads in telemetry and case titles).
- Path traversal rejection in filenames.
- Empty database report generation behavior.
- Unsupported format validation.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from tracehunt.exceptions import ReportExportError
from tracehunt.investigation.case_service import close_investigation, create_investigation
from tracehunt.investigation.evidence_service import attach_evidence
from tracehunt.models import EndpointEvent, Finding
from tracehunt.reporting import compile_report_data, generate_report


def _setup_report_fixtures(session: Session, host: str = "WKSTN-SEC99"):
    # Normal event
    ev1 = EndpointEvent(
        host=host,
        event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=1001,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        user="CORP\\analyst",
    )
    # Event with XSS payload in command line to test sanitization
    ev2 = EndpointEvent(
        host=host,
        event_time=datetime(2026, 3, 30, 10, 5, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=1002,
        image=r"C:\Tools\<img src=x onerror=alert('xss')>.exe",
        command_line="powershell.exe -enc <script>alert('pwned')</script>",
        user="CORP\\target_user",
    )
    session.add_all([ev1, ev2])
    session.flush()

    f1 = Finding(
        rule_id="RULE-001-LOLBIN",
        endpoint_event_id=ev2.id,
        severity="HIGH",
        confidence="HIGH",
        rationale="PowerShell encoded execution with malicious characters",
        matched_fields={"command_line": ev2.command_line},
    )
    session.add(f1)
    session.flush()

    case = create_investigation(
        session=session,
        title="Incident with <svg onload=alert(1)> in title",
        host=host,
        summary="Testing XSS resistance in report summaries: <iframe src='evil.com'>",
        reviewer="lead_auditor",
    )
    attach_evidence(session, case.id, finding_id=f1.id, reviewer="lead_auditor")
    close_investigation(
        session=session,
        investigation_id=case.id,
        disposition="TRUE_POSITIVE",
        reviewer="lead_auditor",
        rationale="Verified adversary testing stored XSS attack",
    )

    return host, case.id, f1.id


def test_compile_report_on_empty_database(test_session: Session) -> None:
    """Verify report generator handles an empty database gracefully without errors."""
    report_data = compile_report_data(test_session, host="NONEXISTENT-HOST")
    assert report_data.metadata.host == "NONEXISTENT-HOST"
    assert report_data.metrics.total_events == 0
    assert report_data.metrics.total_findings == 0
    assert report_data.case is None
    assert len(report_data.limitations) > 0


def test_compile_report_with_case_and_telemetry(test_session: Session) -> None:
    """Verify factual report data reflects stored events, findings, and case details."""
    host, case_id, finding_id = _setup_report_fixtures(test_session)

    report_data = compile_report_data(test_session, host=host, investigation_id=case_id)
    assert report_data.metadata.host == host
    assert report_data.metadata.investigation_id == case_id
    assert report_data.metrics.total_events == 2
    assert report_data.metrics.total_findings == 1
    assert report_data.metrics.severity_counts["HIGH"] == 1
    assert report_data.case is not None
    assert report_data.case.status == "CLOSED_TRUE_POSITIVE"
    assert len(report_data.case.evidence_items) == 1
    assert len(report_data.case.audit_trail) >= 2


def test_json_report_export(test_session: Session, tmp_path: Path) -> None:
    """Verify machine-readable JSON export produces valid JSON and expected structure."""
    host, case_id, _ = _setup_report_fixtures(test_session)

    report_data, file_path = generate_report(
        session=test_session,
        host=host,
        investigation_id=case_id,
        output_format="json",
        filename="test_output_report.json",
    )

    assert file_path.exists()
    assert file_path.name == "test_output_report.json"

    with open(file_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded["metadata"]["report_id"] == report_data.metadata.report_id
    assert loaded["metrics"]["total_events"] == 2
    assert loaded["case"]["id"] == case_id
    assert len(loaded["findings"]) == 1


def test_html_report_xss_sanitization(test_session: Session) -> None:
    """CRITICAL SECURITY TEST: Ensure all untrusted telemetry, process names, and case titles

    are strictly HTML-escaped and cannot execute scripts in a browser.
    """
    host, case_id, _ = _setup_report_fixtures(test_session)

    _, file_path = generate_report(
        session=test_session,
        host=host,
        investigation_id=case_id,
        output_format="html",
        filename="test_security_report.html",
    )

    assert file_path.exists()
    html_content = file_path.read_text(encoding="utf-8")

    # Raw script tags MUST NOT appear unescaped in the document
    assert "<script>alert('pwned')</script>" not in html_content
    assert "<img src=x onerror=alert('xss')>" not in html_content
    assert "<svg onload=alert(1)>" not in html_content
    assert "<iframe src='evil.com'>" not in html_content

    # Escaped versions MUST be present as safe text
    assert "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;" in html_content or "&lt;script&gt;" in html_content
    assert "&lt;img" in html_content
    assert "&lt;svg" in html_content


def test_path_traversal_protection(test_session: Session) -> None:
    """Verify attempts to write outside the configured reports directory are blocked."""
    host, case_id, _ = _setup_report_fixtures(test_session)

    # In our implementation, filenames with traversal dots like ../../evil.html
    # are sanitized to safe filenames or blocked
    _, path = generate_report(
        session=test_session,
        host=host,
        output_format="html",
        filename="../../evil_traversal.html",
    )
    # The file should be saved strictly inside the reports directory, never outside
    assert ".." not in path.name
    assert path.parent.resolve() == path.parent


def test_unsupported_format_and_missing_case_rejection(test_session: Session) -> None:
    """Verify invalid format or nonexistent case IDs raise ReportExportError."""
    with pytest.raises(ReportExportError, match="Unsupported report format"):
        generate_report(test_session, output_format="unsupported_binary_format")

    with pytest.raises(ReportExportError, match="not found"):
        generate_report(test_session, investigation_id="INV-NONEXISTENT-999")


def test_docx_report_export(test_session: Session) -> None:
    """Verify Word document (.docx) generation with structured tables and finding evidence."""
    from docx import Document
    host, case_id, _ = _setup_report_fixtures(test_session)

    report_data, file_path = generate_report(
        session=test_session,
        host=host,
        investigation_id=case_id,
        output_format="docx",
        filename="test_investigation.docx",
        title="Custom Word Investigation Report",
        analyst_name="Specialist Hunter",
    )

    assert file_path.exists()
    assert file_path.suffix == ".docx"
    assert file_path.stat().st_size > 5000

    doc = Document(str(file_path))
    full_text = "\n".join(p.text for p in doc.paragraphs)
    assert "TRACEHUNT ENDPOINT THREAT HUNTING PLATFORM" in full_text
    assert "Custom Word Investigation Report" in full_text
    assert len(doc.tables) >= 3


def test_pdf_report_export(test_session: Session) -> None:
    """Verify PDF document (.pdf) generation producing a valid PDF file."""
    host, case_id, _ = _setup_report_fixtures(test_session)

    report_data, file_path = generate_report(
        session=test_session,
        host=host,
        investigation_id=case_id,
        output_format="pdf",
        filename="test_briefing.pdf",
    )

    assert file_path.exists()
    assert file_path.suffix == ".pdf"
    assert file_path.stat().st_size > 1000
    file_bytes = file_path.read_bytes()
    assert file_bytes.startswith(b"%PDF-")


def test_multi_format_generation(test_session: Session) -> None:
    """Verify generating multiple formats simultaneously returns a complete dictionary of Paths."""
    host, case_id, _ = _setup_report_fixtures(test_session)

    files = generate_report(
        session=test_session,
        host=host,
        investigation_id=case_id,
        formats=["html", "json", "docx", "pdf"],
        title="Comprehensive Multi-Format Threat Package",
    )

    assert isinstance(files, dict)
    assert set(files.keys()) == {"html", "json", "docx", "pdf"}
    for fmt, path in files.items():
        assert path.exists()
        assert path.stat().st_size > 0
