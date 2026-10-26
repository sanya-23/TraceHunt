"""Tests for benchmark module to ensure benchmark metrics run reliably and meet baseline criteria."""

import tempfile
from pathlib import Path
from scripts.benchmark_performance import (
    benchmark_deduplication,
    benchmark_detection_engine,
    benchmark_ingestion_format,
    benchmark_process_graph,
    benchmark_reporting_engine,
    generate_synthetic_telemetry,
    write_fixtures,
)


def test_benchmark_ingestion_and_deduplication_execution():
    """Verify ingestion benchmark executes accurately and achieves deduplication."""
    records = generate_synthetic_telemetry(num_records=50, host="TEST-BENCH-HOST")
    assert len(records) == 50

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fixtures = write_fixtures(records, tmp_path)

        for fmt in ["json", "jsonl", "csv"]:
            res = benchmark_ingestion_format(fixtures[fmt], repetitions=1)
            assert res["records_read"] == 50
            assert res["events_normalized"] == 50
            assert res["events_per_second"] > 0

        # Verify deduplication
        dedup_res = benchmark_deduplication(fixtures["json"])
        assert dedup_res["initial_normalized"] == 50
        assert dedup_res["reimport_duplicates_skipped"] == 50
        assert dedup_res["reimport_normalized"] == 0
        assert dedup_res["dedup_success_rate"] == 1.0


def test_benchmark_graph_and_detection_execution():
    """Verify process graph and detection engine benchmarks execute with expected outputs."""
    graph_res = benchmark_process_graph(records_count=100)
    assert graph_res["events_in_graph"] == 100
    assert graph_res["dag_nodes"] > 0
    assert graph_res["reconstruction_latency_ms"] >= 0

    det_res = benchmark_detection_engine(records_count=100)
    assert det_res["events_evaluated"] == 100
    assert det_res["active_rules"] == 5
    assert det_res["events_per_second"] > 0


def test_benchmark_reporting_execution():
    """Verify reporting benchmark produces JSON and HTML metrics."""
    rep_res = benchmark_reporting_engine()
    assert rep_res["events_in_report"] > 0
    assert rep_res["json_generation_ms"] > 0
    assert rep_res["html_generation_ms"] > 0
    assert rep_res["html_file_size_bytes"] > 0
