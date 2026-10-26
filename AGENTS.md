# AGENTS.md — Permanent Project Instructions for TraceHunt

## 1. Project Mission & Identity
**TraceHunt** is an enterprise-style endpoint threat-hunting and behavioral investigation platform built in Python. It ingests Windows Sysmon process-creation events and selected Windows Security events, normalizes telemetry, reconstructs parent-child process execution trees, evaluates explainable behavioral detection rules, provides host timelines and case management with analyst audit trails, and exports reproducible reports in JSON and HTML.

The primary source of truth is the **TraceHunt R&D Proposal** ([docs/RND_PROPOSAL.md](file:///Users/sanyakumari/Desktop/Project/docs/RND_PROPOSAL.md)).

## 2. Cross-Account Continuity Protocols
This repository must remain completely self-contained and maintainable across different AI accounts and development sessions without reliance on ephemeral chat history.

### Core Continuity Files
The following files must be read at the start of every session and maintained after every meaningful change:
1. `AGENTS.md` — Permanent operational guidelines and project constraints (this file).
2. `PROJECT_STATE.md` — Current stage, completed work, blockers, and single exact next action.
3. `docs/IMPLEMENTATION_CHECKLIST.md` — Granular acceptance criteria with strict status vocabulary: `NOT STARTED`, `IN PROGRESS`, `BLOCKED`, `VERIFIED`.
4. `docs/RND_TRACEABILITY.md` — Traceability matrix mapping R&D Proposal requirements to code, tests, and evidence.
5. `docs/DECISIONS.md` — Architectural Decision Records (ADRs).
6. `docs/TEST_LOG.md` — Verifiable command execution outputs and test results.
7. `docs/SCREENSHOT_INDEX.md` — Visual QA registry mapping screenshots to verified capabilities.
8. `skills/SKILL_INDEX.md` — Reusable engineering skill procedures.

### Status Update Rules
After completing any implementation or verification step:
- Update `PROJECT_STATE.md` with files changed, tests run, test results, blockers, and the exact next step.
- Update `docs/IMPLEMENTATION_CHECKLIST.md` and `docs/RND_TRACEABILITY.md`. Only mark items `VERIFIED` when backed by recorded test execution or screenshot evidence.
- Append real command output to `docs/TEST_LOG.md`. Never claim verification without captured output.

## 3. Technology Stack & Constraints
- **Language:** Python 3.11+ (Active: Python 3.14.3)
- **API Framework:** FastAPI with Pydantic v2 schemas
- **Database & ORM:** SQLAlchemy with SQLite for MVP (designed for PostgreSQL portability)
- **Process Graph:** NetworkX for directed process tree graph operations
- **Dashboard:** Streamlit (clean, analyst-focused, dark/light compatible, responsive)
- **Testing:** pytest with high coverage of parsing, graph reconstruction, rules, API, and export
- **Data Analysis / Evaluation:** pandas
- **Telemetry Formats:** Sysmon JSON/CSV and Windows Security Event JSON/CSV exports, plus synthetic fixtures. (Do not claim native EVTX parsing unless a real EVTX parser is implemented and tested).

## 4. Architectural Principles
1. **Idempotence & Deduplication:** Re-importing the same telemetry file or records must never duplicate raw events, normalized events, or findings. Use SHA-256 event fingerprinting / idempotency keys.
2. **Raw vs. Normalized Separation:** Raw events are preserved verbatim in `raw_events` before normalization. Malformed records are stored in `ingestion_errors` without aborting batch processing.
3. **Evidence Traceability:** Every finding must link to its source `endpoint_event_id` and rule metadata, explaining exactly why it fired and highlighting matched fields.
4. **Graph Integrity:** Process trees handle PID reuse, missing parent events, and out-of-order timestamps gracefully, exposing unresolved parents explicitly.
5. **No Hardcoded Metrics:** Dashboards must calculate real statistics dynamically from the database.
6. **Safe Rendering:** Any untrusted event fields (command lines, usernames, file paths) rendered in HTML reports or UI must be strictly escaped against XSS.

## 5. Development Staging Rule
Development must strictly follow the defined stages. Do not build future stages ahead of completing and verifying current stage prerequisites:
- **Stage 0:** Inspection, project initialization, skill library, continuity files, and traceability matrix.
- **Stage 1:** Core foundation, configuration, logging, database models, and migration/init scripts.
- **Stage 2:** Telemetry ingestion engine, schema validation, normalization, and idempotency tests.
- **Stage 3:** NetworkX process tree graph reconstruction and edge case handling (PID reuse, orphan processes).
- **Stage 4:** Versioned behavioral detection rules and evidence-linked findings generation.
- **Stage 5:** Host investigation timeline, case management, and analyst audit trail.
- **Stage 6:** Streamlit analyst dashboard, interactive visual graph, filterable timeline, and report generator (JSON/HTML).
- **Stage 7:** End-to-end verification, test execution, metric evaluation, screenshot capture, and documentation wrap-up.

## 6. Safety, Privacy, and Ethical Boundaries
- TraceHunt is an analytical defense tool and educational threat-hunting platform.
- Do not implement offensive tools, credential extractors, payload generators, or unauthorized live endpoint response capabilities.
- Sanitize or generate synthetic test telemetry to prevent accidental leakage of real organizational secrets, credentials, or PII.
