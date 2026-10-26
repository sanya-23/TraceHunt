"""Tests for Detection Accuracy Evaluation module and metrics calculation."""

from tracehunt.detection.engine import DetectionEngine
from tracehunt.evaluation.evaluator import (
    ComprehensiveEvaluationReport,
    RuleEvaluationResult,
    evaluate_dataset,
    evaluate_detection_performance,
)
from scripts.evaluate_detections import run_evaluation


def test_rule_evaluation_result_metrics():
    """Verify confusion matrix calculations in RuleEvaluationResult."""
    res = RuleEvaluationResult(
        rule_id="RULE-TEST",
        rule_name="Test Rule",
        mitre_technique="T0000",
        true_positives=8,
        false_positives=2,
        true_negatives=18,
        false_negatives=2,
    )
    res.compute_metrics()

    # Precision = 8 / (8 + 2) = 0.80
    assert res.precision == 0.8
    # Recall = 8 / (8 + 2) = 0.80
    assert res.recall == 0.8
    # F1 = 0.80
    assert res.f1_score == 0.8
    # FPR = 2 / (2 + 18) = 0.10
    assert res.false_positive_rate == 0.10


def test_run_evaluation_module():
    """Verify full evaluation suite runs and outputs a valid ComprehensiveEvaluationReport."""
    report = run_evaluation()
    assert isinstance(report, ComprehensiveEvaluationReport)
    assert report.total_events_evaluated > 0
    assert report.ground_truth_positives > 0
    assert report.ground_truth_negatives > 0
    assert report.true_positives > 0
    assert report.true_negatives > 0
    assert len(report.rule_metrics) == 5
    assert all(r in report.rule_metrics for r in [
        "RULE-001-LOLBIN",
        "RULE-002-PROC-SPAWN",
        "RULE-003-RECON",
        "RULE-004-EVASION",
        "RULE-005-AUTH-ANOMALY",
    ])
    assert report.accuracy > 0
    assert len(report.limitations) >= 4
