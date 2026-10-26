# Skill: JSON & HTML Investigation Report Generation

## 1. Purpose
Generate reproducible, structured JSON and XSS-sanitized HTML executive investigation reports.

## 2. When to Use
During Stage 6 reporting module development.

## 3. Prerequisites
Investigation case, findings, process relationships, and raw evidence available.

## 4. Implementation Steps
1. Define report data structure in tracehunt/reporting/schema.py.
2. Implement JSON report serializer in tracehunt/reporting/exporter.py with full event metadata.
3. Implement HTML report renderer in tracehunt/reporting/html_renderer.py with clean CSS styling.
4. Apply html.escape() to all command lines, usernames, computer names, and analyst notes.
5. Include Executive Summary, Incident Scope, Process Tree, Finding Breakdown, Timeline of Key Events, and Limitations.
6. Provide one-click download in Streamlit and /api/reports endpoint.

## 5. Expected Outputs
tracehunt/reporting/exporter.py, tracehunt/reporting/html_renderer.py.

## 6. Verification Criteria
Generate report with malicious payload in command line (<script>alert(1)</script>); verify escaped in HTML output.

## 7. Common Failures & Troubleshooting
Unescaped HTML injection vulnerabilities; omitting evidence links in report.

## 8. Safety & Ethical Considerations
Strict XSS defense via output encoding.

## 9. Documentation Updates
Add sample exported report to reports/ and update checklist.
