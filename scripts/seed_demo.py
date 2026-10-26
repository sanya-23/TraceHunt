"""Seed database with realistic telemetry, process trees, detections, and a sample investigation."""

import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tracehunt.database import init_db, get_session_factory
from tracehunt.ingestion import import_telemetry_file
from tracehunt.graph import reconstruct_and_persist_host_graph
from tracehunt.detection import DetectionEngine
from tracehunt.investigation.case_service import create_investigation, transition_case_status
from tracehunt.investigation.evidence_service import attach_evidence
from sqlalchemy import distinct, select
from tracehunt.models import EndpointEvent, Finding


def seed_demo() -> None:
    print("Initializing TraceHunt database schema...")
    engine = init_db(seed_rules=True)
    factory = get_session_factory(engine)

    with factory() as session:
        # Ingest attack tree
        attack_tree_path = ROOT_DIR / "fixtures" / "suspicious" / "attack_tree.json"
        if attack_tree_path.exists():
            print(f"Ingesting {attack_tree_path.name}...")
            res1 = import_telemetry_file(str(attack_tree_path), session=session)
            print(f"  Imported {res1.events_normalized} events ({res1.duplicates_skipped} duplicates).")

        # Ingest detection scenarios
        scenarios_path = ROOT_DIR / "fixtures" / "suspicious" / "detection_scenarios.json"
        if scenarios_path.exists():
            print(f"Ingesting {scenarios_path.name}...")
            res2 = import_telemetry_file(str(scenarios_path), session=session)
            print(f"  Imported {res2.events_normalized} events ({res2.duplicates_skipped} duplicates).")

        # Reconstruct process graphs
        hosts = [h for h in session.scalars(select(EndpointEvent.host).distinct()).all() if h]
        print(f"Reconstructing process trees for hosts: {hosts}")
        for host in hosts:
            g, new_rels = reconstruct_and_persist_host_graph(host=host, session=session)
            print(f"  Host {host}: Graph has {g.number_of_nodes()} processes, {g.number_of_edges()} relationships ({len(new_rels)} newly persisted).")

        # Evaluate detections
        all_events = list(session.scalars(select(EndpointEvent)).all())
        engine = DetectionEngine()
        d_summary = engine.evaluate_events(events=all_events, session=session, persist=True)
        print(f"Evaluated {d_summary.events_examined} events: Generated {d_summary.findings_created} findings.")

        # Create sample investigation case on THREAT-HOST or first host with findings
        findings = list(session.scalars(select(Finding)).all())
        target_host = "THREAT-HOST" if any(f.endpoint_event and f.endpoint_event.host == "THREAT-HOST" for f in findings) else hosts[0]
        host_findings = [f for f in findings if f.endpoint_event and f.endpoint_event.host == target_host]
        f_ids = [f.id for f in host_findings[:3]]

        case = create_investigation(
            session=session,
            title=f"Active Triage: Malicious Execution & Recon on {target_host}",
            host=target_host,
            summary="Host exhibited LOLBIN downloads via certutil and subsequent reconnaissance via powershell.",
            reviewer="lead_hunter",
            initial_status="OPEN",
            initial_finding_ids=f_ids,
        )

        transition_case_status(
            session=session,
            investigation_id=case.id,
            new_status="INVESTIGATING",
            reviewer="lead_hunter",
            rationale="Verified suspicious parent-child process tree originating from WINWORD.EXE.",
        )
        session.commit()
        print(f"Created demo investigation: {case.id} (Status: {case.status})")

    print("Demo seeding complete!")


if __name__ == "__main__":
    seed_demo()
