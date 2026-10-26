"""Detection Accuracy Evaluation Engine for TraceHunt.

Computes standard information retrieval and classification metrics:
- True Positives (TP)
- False Positives (FP)
- True Negatives (TN)
- False Negatives (FN)
- Precision (Positive Predictive Value)
- Recall (True Positive Rate / Sensitivity)
- F1-Score (Harmonic Mean of Precision and Recall)
- False Positive Rate (FPR = FP / (FP + TN))
- Overall Accuracy ((TP + TN) / Total)

Supports evaluation at the Event Classification unit level and per-rule breakdown.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from tracehunt.detection.base import DetectionSummary
from tracehunt.detection.engine import DetectionEngine
from tracehunt.models import EndpointEvent, Finding


@dataclass
class RuleEvaluationResult:
    """Confusion matrix and accuracy statistics for an individual detection rule."""

    rule_id: str
    rule_name: str
    mitre_technique: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0

    def compute_metrics(self) -> None:
        """Calculate derived classification metrics from confusion counts."""
        tp_fp = self.true_positives + self.false_positives
        tp_fn = self.true_positives + self.false_negatives
        fp_tn = self.false_positives + self.true_negatives

        self.precision = round(self.true_positives / tp_fp, 4) if tp_fp > 0 else 0.0
        self.recall = round(self.true_positives / tp_fn, 4) if tp_fn > 0 else 0.0
        
        pr_sum = self.precision + self.recall
        self.f1_score = round(2 * self.precision * self.recall / pr_sum, 4) if pr_sum > 0 else 0.0
        self.false_positive_rate = round(self.false_positives / fp_tn, 4) if fp_tn > 0 else 0.0


@dataclass
class ComprehensiveEvaluationReport:
    """Complete evaluation report covering event-level and rule-level detection performance."""

    evaluation_unit: str = "Individual Telemetry Event (Binary Classification: Suspicious vs Benign)"
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_events_evaluated: int = 0
    ground_truth_positives: int = 0
    ground_truth_negatives: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    accuracy: float = 0.0
    duration_ms: float = 0.0
    rule_metrics: dict[str, dict[str, Any]] = field(default_factory=dict)
    detailed_findings: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_dataset(
    engine: DetectionEngine,
    events: list[EndpointEvent],
    ground_truth: dict[int, dict[str, Any]],
    duration_ms: float = 0.0,
) -> ComprehensiveEvaluationReport:
    """Evaluate detection engine against an independent ground-truth labeled event dataset.

    Args:
        engine: DetectionEngine instance with loaded rules.
        events: List of normalized EndpointEvents to evaluate.
        ground_truth: Mapping of event.id -> {
            "is_suspicious": bool,
            "expected_rules": list[str],
            "description": str,
        }
        duration_ms: Optional execution runtime in milliseconds.

    Returns:
        ComprehensiveEvaluationReport with complete confusion matrix and metrics.
    """
    summary: DetectionSummary = engine.evaluate_events(events=events, persist=False)

    # Index findings by endpoint_event_id
    findings_by_event: dict[int, list[Finding]] = {}
    for f in summary.findings:
        findings_by_event.setdefault(f.endpoint_event_id, []).append(f)

    # Prepare rule metric trackers
    rule_tracker: dict[str, RuleEvaluationResult] = {}
    for r in engine.rules:
        rule_tracker[r.id] = RuleEvaluationResult(
            rule_id=r.id,
            rule_name=r.name,
            mitre_technique=getattr(r, "mitre_technique", "N/A"),
        )

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    positives = 0
    negatives = 0

    detailed_findings_log = []

    for event in events:
        gt = ground_truth.get(event.id, {"is_suspicious": False, "expected_rules": [], "description": "Unlabeled"})
        is_suspicious = gt["is_suspicious"]
        expected_rules = set(gt.get("expected_rules", []))
        event_findings = findings_by_event.get(event.id, [])
        fired_rules = {f.rule_id for f in event_findings}

        if is_suspicious:
            positives += 1
            if len(event_findings) > 0:
                tp += 1
            else:
                fn += 1
        else:
            negatives += 1
            if len(event_findings) > 0:
                fp += 1
            else:
                tn += 1

        # Track per-rule outcomes
        for rule_id, tracker in rule_tracker.items():
            rule_expected = rule_id in expected_rules
            rule_fired = rule_id in fired_rules

            if rule_expected and rule_fired:
                tracker.true_positives += 1
            elif not rule_expected and rule_fired:
                tracker.false_positives += 1
            elif rule_expected and not rule_fired:
                tracker.false_negatives += 1
            else:
                tracker.true_negatives += 1

        if event_findings:
            for f in event_findings:
                detailed_findings_log.append({
                    "endpoint_event_id": event.id,
                    "host": event.host,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "rationale": f.rationale,
                    "ground_truth_suspicious": is_suspicious,
                })

    for tracker in rule_tracker.values():
        tracker.compute_metrics()

    # Overall event classification metrics
    total = len(events)
    tp_fp = tp + fp
    tp_fn = tp + fn
    fp_tn = fp + tn

    precision = round(tp / tp_fp, 4) if tp_fp > 0 else 0.0
    recall = round(tp / tp_fn, 4) if tp_fn > 0 else 0.0
    pr_sum = precision + recall
    f1 = round(2 * precision * recall / pr_sum, 4) if pr_sum > 0 else 0.0
    fpr = round(fp / fp_tn, 4) if fp_tn > 0 else 0.0
    acc = round((tp + tn) / total, 4) if total > 0 else 0.0

    limitations = [
        "Benchmark evaluation is performed on synthetic and curated security fixtures (N=42 events).",
        "Enterprise noise (millions of daily events from benign enterprise software) is not simulated in this lab environment.",
        "Rule-005 requires correlated preceding Event 4625 records on the same host within 300 seconds; distributed slow brute-force across hosts is out of scope.",
        "Obfuscation detection in Rule-004 focuses on temporary directory paths; in-memory reflection or process hollowing requires Sysmon Event 8/10 or kernel ETW.",
    ]

    report = ComprehensiveEvaluationReport(
        total_events_evaluated=total,
        ground_truth_positives=positives,
        ground_truth_negatives=negatives,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        accuracy=acc,
        duration_ms=round(duration_ms, 2),
        rule_metrics={rid: asdict(rm) for rid, rm in rule_tracker.items()},
        detailed_findings=detailed_findings_log,
        limitations=limitations,
    )

    return report


def evaluate_detection_performance(
    engine: DetectionEngine,
    benign_events: list[EndpointEvent],
    suspicious_events: list[EndpointEvent],
    expected_suspicious_matches: int = 10,
) -> dict[str, Any]:
    """Evaluate detection engine performance across benign and suspicious telemetry."""
    import time
    start_time = time.perf_counter()

    benign_summary = engine.evaluate_events(benign_events, persist=False)
    fp = benign_summary.findings_created

    suspicious_summary = engine.evaluate_events(suspicious_events, persist=False)
    tp = suspicious_summary.findings_created

    fn = max(0, expected_suspicious_matches - tp)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    duration_ms = (time.perf_counter() - start_time) * 1000

    findings_by_rule: dict[str, int] = {}
    for f in suspicious_summary.findings:
        findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "total_benign_evaluated": len(benign_events),
        "total_suspicious_evaluated": len(suspicious_events),
        "findings_by_rule": findings_by_rule,
        "evaluation_duration_ms": round(duration_ms, 2),
    }
