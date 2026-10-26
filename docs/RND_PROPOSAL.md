# TraceHunt: Research & Development (R&D) Proposal

TraceHunt

Research & Development (R&D) Proposal

Endpoint Threat Hunting & Behavioral Investigation Lab | Python

Proposal status: planned proof of concept. Performance claims and detection metrics must be measured after implementation.


## 1. Executive Summary

TraceHunt is a Python-based endpoint investigation and threat-hunting prototype. It ingests Windows Sysmon and selected Windows Security events, reconstructs parent-child process relationships, applies transparent behavioral detection rules, and presents an analyst with a process tree, event timeline, and evidence-backed findings.


## 2. Problem Statement

Endpoint logs contain useful details about process creation, accounts, and host activity, but raw events can be difficult to investigate at speed. A process command line may look suspicious without context, while the parent process, user, timestamp, and surrounding events can change the interpretation. TraceHunt aims to convert raw endpoint telemetry into a structured host investigation view that supports—not replaces—analyst judgment.


## 3. Objectives

Collect or import Windows Sysmon process-creation events and selected Windows Security events from an authorized lab.

Parse source events and normalize timestamps, host names, user identities, process IDs, parent process IDs, command lines, and event IDs.

Reconstruct process trees using host identity, process identifiers, parent identifiers, and timestamp context.

Implement transparent detection rules for selected suspicious process patterns and account behaviors.

Show why each finding triggered, including the matched rule, source event, command-line evidence, severity, and confidence.

Provide a chronological host timeline that links process activity with related authentication events where available.

Store raw events, normalized events, process relationships, findings, and analyst review actions in a database.

Provide filters by host, user, process, time, rule, and severity, plus JSON/HTML investigation export.

Test suspicious and benign scenarios to identify false positives, missing telemetry, and parser limitations.


## 4. Research Gap and Proposed Contribution

These are proposed operational gaps to investigate rather than claims that existing EDR products lack the listed capabilities. Validate novelty through a review of existing endpoint investigation tools and research.

Research / operational gap

Solution provided

Final output / picture

Technology stack

Raw process events lack an easy parent-child view.

Build a process graph using host, process ID, parent ID, and time.

Expandable process tree with suspicious nodes highlighted.

Python, NetworkX, Sysmon

Command-line detections can be noisy without user and process context.

Include parent process, user, host, time, and surrounding event context in rule evaluation.

Finding card with rule match and evidence explanation.

Python rule engine, Pydantic

Analysts need to reconstruct what happened on a host over time.

Combine process and authentication events into a searchable timeline.

Chronological endpoint investigation timeline.

Python, FastAPI, SQLite/PostgreSQL

Detection findings can be hard to trace to original records.

Preserve raw events and link findings to source event IDs.

Evidence-backed finding and exportable report.

SQLAlchemy, database foreign keys

Rules may be presented without testing against normal activity.

Create labelled benign and suspicious fixtures and evaluate each rule.

Test results with false-positive and false-negative observations.

pytest, Python, pandas

Endpoint investigation results may be scattered across separate files.

Persist events, process relationships, findings, and analyst disposition.

Searchable host case history and audit trail.

SQLite/PostgreSQL, FastAPI


## 5. Proposed Architecture

Pipeline: Windows endpoint telemetry → Python ingestion → parsing/normalization → process-tree reconstruction and rule engine → database persistence → process tree, timeline, and findings dashboard.


## 6. Complete Workflow: Ingestion to Database


## 1. Endpoint telemetry — Sysmon provides configured process and related event records. Windows Security logs provide selected logon/account events. For an early MVP, use exported JSON/CSV or synthetic fixtures.


## 2. Collection/import — A Python batch importer or FastAPI upload endpoint reads the records. For native Windows Event Logs, use an appropriate Windows event export or a compatible collector; do not assume arbitrary JSON parsing reads EVTX directly.


## 3. Raw-event storage — Save original payload, source, ingestion time, and parse status before transformation so findings can be traced to source evidence.


## 4. Parsing and normalization — Extract event time, host, user, event ID, process ID, parent process ID, image/path, command line, and relevant logon fields. Preserve nulls for unavailable fields and record parse failures.


## 5. Process-tree reconstruction — Group process records by host and link child process IDs to parent process IDs, checking time context and PID reuse. Store parent-child relationships separately or derive them from normalized events.


## 6. Behavioral detections — Evaluate transparent rules against process metadata and context. Store rule ID/version, severity, confidence, explanation, matched fields, and source event references.


## 7. Database persistence — Save findings and relationships with foreign keys. Use stable source IDs or idempotency keys to avoid duplicate records when a file is re-imported.


## 8. Analyst view — Dashboard queries events and relationships to display process trees, suspicious nodes, host timelines, filters, and finding details. Export reports with evidence references.


## 9. Analyst feedback and evaluation — Record dispositions and comments in an audit table. Run known benign and suspicious test cases and document observed false positives and false negatives.


## 7. Database Design

Table

Purpose

Illustrative fields

raw_events

Original event evidence

id, source, source_event_id, ingested_at, raw_payload, parse_status

endpoint_events

Normalized endpoint records

id, raw_event_id, event_time, host, user, event_id, process_id, parent_process_id, image, command_line

process_relationships

Parent-child links

id, host, parent_event_id, child_event_id, relationship_type, confidence

detection_rules

Versioned detection rules

id, name, version, description, severity, enabled

findings

Rule matches

id, rule_id, endpoint_event_id, severity, confidence, rationale, created_at

investigations

Host investigation/case

id, host, title, status, summary, created_at, updated_at

investigation_evidence

Evidence linked to case

investigation_id, raw_event_id, finding_id, sequence_number

analyst_audit

Disposition and review

id, investigation_id, action, reviewer, comment, created_at

ingestion_errors

Malformed input records

id, source, error_type, details, created_at

Use SQLite for the MVP and PostgreSQL if needed later. Keep raw and normalized records separate, use UTC timestamps, index host/event_time/process_id/parent_process_id, and use transactions and foreign keys to preserve relationships.


## 8. Python Technology Stack

Python 3.11+ for ingestion, normalization, process graph building, detection, and reports.

Sysmon and Windows Security Event Logs as primary telemetry.

Python JSON/CSV parser; optional Windows event export/collector for native logs.

NetworkX for process-tree and relationship graph construction.

FastAPI and Pydantic for upload and query APIs.

SQLAlchemy with SQLite for MVP or PostgreSQL for an expanded deployment.

Streamlit for rapid dashboard development.

pytest for detection tests; pandas optional for evaluation and metrics.

Docker is optional; native Windows event collection may require Windows-specific permissions and setup.


## 9. MVP and Deliverables

Import process creation events and selected authentication events.

Normalize host, user, time, process ID, parent process ID, image, and command-line fields.

Reconstruct and display parent-child process trees.

Implement three to five transparent behavioral rules with evidence-backed explanations.

Provide host timeline and finding filters.

Persist raw events, normalized events, process relationships, findings, and analyst audit actions.

Export an investigation report and provide labelled benign/suspicious test fixtures.

Document setup, event coverage, limitations, and a short recorded demo.


## 10. Evaluation Plan

Measure the percentage of valid input records parsed successfully.

Measure process-tree link accuracy on fixtures with known parent-child relationships.

Record true positives, false positives, and false negatives for labelled test cases.

Measure rule execution time and dashboard query responsiveness on the documented dataset.

Check that every finding links to a source event and contains an explanation.

Test PID reuse, missing parent events, malformed records, duplicate imports, and out-of-order timestamps.


## 11. Two-Week Schedule

Days

Work

Deliverable

1–2

Set up Sysmon/exported fixtures and schema

Sample logs and schema

3–4

Build importer and parser

Normalized endpoint records

5–6

Database and process relationships

Persistent events and process graph

7–9

Detection rules and context enrichment

Findings with evidence

10–11

Process tree/timeline dashboard

Analyst investigation view

12–13

Test benign/suspicious fixtures and fix bugs

Measured test report

14

Documentation and demo

Portfolio-ready MVP


## 12. Security, Ethics, and Limitations

Collect telemetry only from devices you own or are authorized to monitor.

Use safe, controlled test programs and curated events; avoid harmful payloads or unauthorized testing.

Suspicious command lines are indicators, not automatic proof of malicious intent.

Process IDs can be reused and parent events may be missing; include time and host context and show unresolved links.

Rule-based detection will miss behaviors outside its coverage and can produce false positives.

Endpoint logs can contain usernames and command lines; protect access and define retention.

TraceHunt is a learning and investigation prototype, not a replacement for a production EDR.


## 13. Expected Final Output

An analyst can import endpoint telemetry, select a host, inspect its process tree and chronological activity, review rule matches with source evidence, filter findings, record a disposition, and export a report. The key contribution is a compact and explainable endpoint investigation workflow built in Python.


## 14. Suggested Resume Description (after implementation)

TraceHunt — Python-Based Endpoint Threat Hunting & Investigation Lab• Parsed and normalized Sysmon and Windows security events into structured endpoint telemetry.• Reconstructed parent-child process relationships and implemented rule-based behavioral detections with evidence-linked findings.• Built a host timeline and investigation dashboard, storing events and analyst review history in a relational database.


## 15. References and Tools

Microsoft Sysmon — https://learn.microsoft.com/sysinternals/downloads/sysmon

Windows Event Logging — https://learn.microsoft.com/windows/win32/wes/windows-event-log

MITRE ATT&CK — https://attack.mitre.org/

Sigma — https://sigmahq.io/

FastAPI — https://fastapi.tiangolo.com/

SQLAlchemy — https://docs.sqlalchemy.org/

NetworkX — https://networkx.org/documentation/stable/

