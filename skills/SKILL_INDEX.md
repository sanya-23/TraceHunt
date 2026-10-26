# TraceHunt — Skill Library Index

This directory contains standardized, reusable engineering skills tailored for the **TraceHunt Endpoint Threat Hunting Platform**. Each skill provides detailed operational instructions, prerequisites, step-by-step procedures, verification criteria, failure modes, safety rules, and documentation updates.

Any AI agent or developer resuming work on TraceHunt must consult the relevant skill before executing tasks in that domain.

---

## Skill Inventory

| # | Skill Directory | Name & Purpose | Primary Stage |
|---|---|---|---|
| 01 | [`repository-inspection-and-session-continuity`](file:///Users/sanyakumari/Desktop/Project/skills/repository-inspection-and-session-continuity/SKILL.md) | Inspect environment, read continuity docs, and verify repo state before starting work. | All Stages |
| 02 | [`rnd-requirement-traceability`](file:///Users/sanyakumari/Desktop/Project/skills/rnd-requirement-traceability/SKILL.md) | Map code and tests directly to TraceHunt R&D Proposal objectives and deliverables. | All Stages |
| 03 | [`python-architecture`](file:///Users/sanyakumari/Desktop/Project/skills/python-architecture/SKILL.md) | Enforce modular package structure, typing, separation of concerns, and clean service layers. | Stages 1–6 |
| 04 | [`configuration-logging-error-handling`](file:///Users/sanyakumari/Desktop/Project/skills/configuration-logging-error-handling/SKILL.md) | Manage Pydantic settings, structured logging, and non-fatal error isolation. | Stage 1 |
| 05 | [`sqlalchemy-database-design`](file:///Users/sanyakumari/Desktop/Project/skills/sqlalchemy-database-design/SKILL.md) | Design models, indexes, transactions, and foreign-key integrity for SQLite and PostgreSQL. | Stage 1 |
| 06 | [`windows-event-logs-sysmon-data`](file:///Users/sanyakumari/Desktop/Project/skills/windows-event-logs-sysmon-data/SKILL.md) | Understand Sysmon (1, 3, 5) and Windows Security (4624, 4625, 4688) telemetry schemas. | Stage 2 |
| 07 | [`json-csv-ingestion-validation`](file:///Users/sanyakumari/Desktop/Project/skills/json-csv-ingestion-validation/SKILL.md) | Ingest, parse, and validate JSON/CSV event exports with size/encoding verification. | Stage 2 |
| 08 | [`event-normalization-utc-timestamps`](file:///Users/sanyakumari/Desktop/Project/skills/event-normalization-utc-timestamps/SKILL.md) | Transform heterogeneous event fields into unified schema with UTC timestamps and null preservation. | Stage 2 |
| 09 | [`idempotent-ingestion-data-integrity`](file:///Users/sanyakumari/Desktop/Project/skills/idempotent-ingestion-data-integrity/SKILL.md) | Deduplicate records using SHA-256 fingerprints to ensure safe re-imports. | Stage 2 |
| 10 | [`process-graph-reconstruction`](file:///Users/sanyakumari/Desktop/Project/skills/process-graph-reconstruction/SKILL.md) | Reconstruct parent-child process DAGs via NetworkX with PID reuse and missing-parent handling. | Stage 3 |
| 11 | [`explainable-detection-engineering`](file:///Users/sanyakumari/Desktop/Project/skills/explainable-detection-engineering/SKILL.md) | Develop explainable behavioral detection rules with severity, confidence, and source links. | Stage 4 |
| 12 | [`test-fixtures-detection-evaluation`](file:///Users/sanyakumari/Desktop/Project/skills/test-fixtures-detection-evaluation/SKILL.md) | Build labelled benign/suspicious fixtures and evaluate TP, FP, FN, and detection latency. | Stage 4, 7 |
| 13 | [`fastapi-pydantic`](file:///Users/sanyakumari/Desktop/Project/skills/fastapi-pydantic/SKILL.md) | Implement REST API endpoints with request/response validation and OpenAPI specs. | Stage 6 |
| 14 | [`streamlit-dashboard-development`](file:///Users/sanyakumari/Desktop/Project/skills/streamlit-dashboard-development/SKILL.md) | Construct responsive, security-analyst UI with dynamic metrics, process tree, and timeline. | Stage 6 |
| 15 | [`investigation-timelines-audit-workflows`](file:///Users/sanyakumari/Desktop/Project/skills/investigation-timelines-audit-workflows/SKILL.md) | Interleave chronological host events, manage investigation cases, and persist analyst audit logs. | Stage 5 |
| 16 | [`json-html-report-generation`](file:///Users/sanyakumari/Desktop/Project/skills/json-html-report-generation/SKILL.md) | Generate reproducible JSON and secure, XSS-sanitized HTML executive reports. | Stage 6 |
| 17 | [`testing-unit-integration-e2e`](file:///Users/sanyakumari/Desktop/Project/skills/testing-unit-integration-e2e/SKILL.md) | Execute pytest suites across unit, integration, edge-case, and end-to-end workflows. | Stages 1–7 |
| 18 | [`screenshot-capture-visual-qa`](file:///Users/sanyakumari/Desktop/Project/skills/screenshot-capture-visual-qa/SKILL.md) | Capture, name, and index visual verification screenshots (`01-dashboard.png` – `09-tests.png`). | Stage 7 |
| 19 | [`application-security-privacy`](file:///Users/sanyakumari/Desktop/Project/skills/application-security-privacy/SKILL.md) | Enforce XSS sanitization, secret hygiene, telemetry privacy, and harmless lab constraints. | All Stages |
| 20 | [`documentation-cross-account-handoff`](file:///Users/sanyakumari/Desktop/Project/skills/documentation-cross-account-handoff/SKILL.md) | Update `PROJECT_STATE.md`, `TEST_LOG.md`, and handover notes for session continuity. | All Stages |
| 21 | [`antigravity-agent-workflow`](file:///Users/sanyakumari/Desktop/Project/skills/antigravity-agent-workflow/SKILL.md) | Operate within Antigravity IDE using tool execution, background task handling, and reactive flow. | All Stages |
| 22 | [`release-readiness-demonstration`](file:///Users/sanyakumari/Desktop/Project/skills/release-readiness-demonstration/SKILL.md) | Validate Definition of Done, run complete end-to-end walkthrough, and verify demo readiness. | Stage 7 |

---

## Operating Instructions
1. **Always read the relevant skill** before starting work on a new feature or stage.
2. **Follow the required template** for all skills: Purpose, When to Use, Prerequisites, Implementation Steps, Expected Outputs, Verification Criteria, Common Failures, Safety Considerations, and Documentation Updates.
3. If an automated skill loader is not active in the current AI environment, open and view the skill markdown file explicitly using `view_file`.
