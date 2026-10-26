"""Full End-to-End Workflow Integration Test."""

from scripts.verify_e2e_full import run_full_e2e_verification


def test_full_e2e_workflow():
    """Verify that all 11 stages of the end-to-end workflow execute successfully."""
    results = run_full_e2e_verification()
    assert results["step_1_db_init"] == "SUCCESS"
    assert results["step_2_3_ingestion"]["dedup_verified"] is True
    assert results["step_2_3_ingestion"]["norm_count"] > 0
    assert results["step_4_process_graph"]["nodes"] > 0
    assert results["step_4_process_graph"]["lineage_depth"] >= 2
    assert results["step_5_detection"]["findings_count"] > 0
    assert results["step_6_timeline"]["total_timeline_events"] > 0
    assert results["step_7_8_case_management"]["final_status"] == "CLOSED_TRUE_POSITIVE"
    assert results["step_9_evidence"]["sequence_number"] == 1
    assert results["step_10_reports"]["html_size_bytes"] > 0
    assert results["step_11_security"]["xss_autoescaping_verified"] is True
