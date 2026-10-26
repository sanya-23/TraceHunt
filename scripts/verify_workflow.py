"""End-to-End Live Workflow Verification Script for TraceHunt REST API."""

import json
from pathlib import Path
import httpx

API_BASE = "http://127.0.0.1:8000/api/v1"
ROOT_DIR = Path(__file__).resolve().parent.parent


def run_e2e_workflow() -> None:
    client = httpx.Client(base_url=API_BASE, timeout=30.0)

    print("=== Step 1: Health & System Status Check ===")
    r_health = client.get("/health")
    assert r_health.status_code == 200, f"Health check failed: {r_health.text}"
    health_data = r_health.json()
    print(f"Health OK: version={health_data['version']}, db_connected={health_data['database_connected']}")
    print(f"Tables verified ({len(health_data['tables_verified'])}): {health_data['tables_verified']}")

    print("\n=== Step 2: Telemetry Ingestion (Synthetic Fixture) ===")
    fixture_path = ROOT_DIR / "fixtures" / "benign" / "sysmon_proc_creation.json"
    assert fixture_path.exists(), f"Fixture {fixture_path} not found"
    with open(fixture_path, "rb") as f:
        files = {"file": (fixture_path.name, f, "application/json")}
        r_ingest = client.post("/ingest", files=files)
    assert r_ingest.status_code == 201, f"Ingestion failed: {r_ingest.text}"

    ingest_res = r_ingest.json()
    print(f"Ingestion Summary: source_file={ingest_res['source_file']}, total={ingest_res['total_records']}, successful={ingest_res['successful_records']}, dupes={ingest_res['duplicates_skipped']}, errors={ingest_res['errors_encountered']}")


    print("\n=== Step 3: Run Detection Engine & Inspect Findings ===")
    r_eval = client.post("/detections/evaluate", json={})
    assert r_eval.status_code == 200, f"Detection evaluation failed: {r_eval.text}"
    eval_res = r_eval.json()
    print(f"Detection Evaluation: examined={eval_res['evaluated_events']}, rules={eval_res['active_rules']}, findings_created={eval_res['findings_generated']}, dupes={eval_res['duplicates_skipped']}")


    r_findings = client.get("/detections/findings", params={"limit": 5})
    assert r_findings.status_code == 200
    findings = r_findings.json()
    print(f"Retrieved {len(findings)} sample findings:")
    for f in findings:
        print(f"  - [{f['severity']}] Finding #{f['id']} | Rule: {f['rule_id']} | Host: {f.get('host', 'N/A')} | Rationale: {f['rationale']}")

    print("\n=== Step 4: Host Telemetry & Process Tree Inspection ===")
    r_hosts = client.get("/hosts")
    assert r_hosts.status_code == 200
    hosts_list = r_hosts.json()
    print(f"Observed Hosts ({len(hosts_list)}): {[h['host'] for h in hosts_list]}")

    target_host = hosts_list[0]["host"]
    r_tree = client.get(f"/hosts/{target_host}/tree")
    assert r_tree.status_code == 200
    tree_data = r_tree.json()
    print(f"Process Tree on {target_host}: total_trees={tree_data['total_trees']}, total_processes={tree_data['total_processes']}")

    r_timeline = client.get(f"/hosts/{target_host}/timeline", params={"limit": 5})
    assert r_timeline.status_code == 200
    timeline_data = r_timeline.json()
    print(f"Host Timeline on {target_host}: returned {len(timeline_data)} events (most recent: {timeline_data[0]['event_type'] if timeline_data else 'None'})")

    print("\n=== Step 5: Case Investigation & Evidence Linking ===")
    case_payload = {
        "title": f"Live E2E Investigation on {target_host}",
        "host": target_host,
        "summary": "Automated verification of case lifecycle and audit trail.",
        "reviewer": "e2e_verifier",
        "initial_status": "OPEN",
    }
    r_case = client.post("/cases", json=case_payload)
    assert r_case.status_code == 201, f"Case creation failed: {r_case.text}"
    case_data = r_case.json()
    case_id = case_data["id"]
    print(f"Created Investigation: {case_id} (Status: {case_data['status']})")

    # Transition to INVESTIGATING
    r_trans = client.post(
        f"/cases/{case_id}/transition",
        json={"new_status": "INVESTIGATING", "reviewer": "e2e_verifier", "rationale": "Beginning active triage."},
    )
    assert r_trans.status_code == 200
    print(f"Transitioned Case to INVESTIGATING.")

    # Attach evidence if finding available
    if findings:
        sample_finding = findings[0]
        ev_payload = {
            "finding_id": sample_finding["id"],
            "notes": "Attached during E2E verification test.",
            "reviewer": "e2e_verifier",
        }
        r_ev = client.post(f"/cases/{case_id}/evidence", json=ev_payload)
        assert r_ev.status_code == 201, f"Evidence attach failed: {r_ev.text}"
        ev_data = r_ev.json()
        print(f"Attached Evidence #{ev_data['id']} (Seq: {ev_data['sequence_number']}, Finding #{ev_data['finding_id']})")

    # Fetch audit history
    r_audit = client.get(f"/cases/{case_id}/audit")
    assert r_audit.status_code == 200
    audits = r_audit.json()
    print(f"Audit Log for {case_id} ({len(audits)} records):")
    for a in audits:
        print(f"  - [{a['action']}] by {a['reviewer']} ({a['created_at']}): {a.get('comment')}")

    print("\n=== Step 6: Generate JSON & Executive HTML Reports ===")
    rep_payload = {
        "investigation_id": case_id,
        "format": "html",
    }
    r_rep = client.post("/reports/generate", json=rep_payload)
    assert r_rep.status_code == 201, f"Report generation failed: {r_rep.text}"
    rep_res = r_rep.json()
    print(f"Report Generation Successful:")
    print(f"  - Report ID: {rep_res['report_id']}")
    print(f"  - Filename: {rep_res['filename']}")
    print(f"  - Download URL: {rep_res['download_url']}")

    # Download HTML report to verify download endpoint
    html_filename = rep_res["filename"]
    r_down = client.get(f"/reports/{html_filename}")
    assert r_down.status_code == 200
    assert "TraceHunt" in r_down.text
    assert rep_res["report_id"] in r_down.text
    print(f"Downloaded HTML Report: {len(r_down.text)} characters verified.")


    # Also generate JSON report
    rep_payload_json = {
        "investigation_id": case_id,
        "format": "json",
    }
    r_rep_json = client.post("/reports/generate", json=rep_payload_json)
    assert r_rep_json.status_code == 201
    rep_res_json = r_rep_json.json()
    r_down_json = client.get(f"/reports/{rep_res_json['filename']}")
    assert r_down_json.status_code == 200
    json_data = r_down_json.json()
    print(f"Downloaded JSON Report: {len(json_data)} keys verified (report_id={json_data['metadata']['report_id']}).")


    print("\n✅ ALL 6 WORKFLOW VERIFICATION STEPS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_e2e_workflow()
