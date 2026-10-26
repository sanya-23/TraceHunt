# Skill: Unit, Integration, and End-to-End Testing

## 1. Purpose
Maintain rigorous test coverage using pytest across parsing, graph, rules, API, and report generation.

## 2. When to Use
Throughout all development stages; mandatory before marking any checklist item VERIFIED.

## 3. Prerequisites
pytest installed; fixtures available in fixtures/.

## 4. Implementation Steps
1. Structure tests under tests/: test_ingestion.py, test_normalizer.py, test_idempotency.py, test_process_graph.py, test_detections.py, test_timeline.py, test_case_management.py, test_reporting.py, test_api.py.
2. Use SQLite in-memory or temporary database fixtures for isolated test runs.
3. Test positive paths, negative paths, and deliberate edge cases (empty files, corrupted JSON, missing fields).
4. Execute pytest -v --tb=short and capture complete output.
5. Append actual command and output to docs/TEST_LOG.md.

## 5. Expected Outputs
tests/*.py and recorded results in docs/TEST_LOG.md.

## 6. Verification Criteria
100% of test suite passing with zero unhandled exceptions.

## 7. Common Failures & Troubleshooting
Writing tests without assertions; skipping negative test cases; modifying tests to fit broken code.

## 8. Safety & Ethical Considerations
Tests must run locally without external network dependencies.

## 9. Documentation Updates
Append test output to docs/TEST_LOG.md and update IMPLEMENTATION_CHECKLIST.md.
