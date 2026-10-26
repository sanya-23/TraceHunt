# Skill: Test Fixtures & Detection Evaluation

## 1. Purpose
Create realistic benign and suspicious fixtures to measure TP, FP, FN, parser accuracy, and latency.

## 2. When to Use
During Stage 4 detection testing and Stage 7 performance evaluation.

## 3. Prerequisites
Detection rules and ingestion engine implemented.

## 4. Implementation Steps
1. Create fixtures/benign/ with normal Windows activity (explorer spawning notepad, updates, typical logons).
2. Create fixtures/suspicious/ with labelled threat hunting scenarios (macro spawning powershell downloading payload).
3. Create fixtures/edge_cases/ with PID reuse, missing parents, out-of-order timestamps, and malformed rows.
4. Implement evaluation script tracehunt/evaluation/evaluator.py calculating Precision, Recall, TP, FP, FN.
5. Measure parser throughput (records/sec) and rule evaluation latency (ms/event).
6. Output structured metrics JSON for reporting.

## 5. Expected Outputs
fixtures/* and tracehunt/evaluation/evaluator.py.

## 6. Verification Criteria
Verify metrics match expected labels without unexplained false positives.

## 7. Common Failures & Troubleshooting
Overfitting rules to test fixtures; unlabelled test data; failing to test benign traffic.

## 8. Safety & Ethical Considerations
Ensure test payloads in fixtures are inert command strings, not live exploit code.

## 9. Documentation Updates
Append evaluation metrics to docs/TEST_LOG.md.
