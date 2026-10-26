# Architectural Decision Records (ADRs) — TraceHunt

## ADR-001: Technology Stack Selection
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** TraceHunt requires a robust, maintainable architecture for ingesting telemetry, normalizing data, building execution graphs, running behavioral detection rules, and presenting an analyst interface.
- **Decision:**
  - **Language:** Python 3.11+ (running Python 3.14.3).
  - **Database & ORM:** SQLAlchemy 2.0 with SQLite for the standalone MVP. SQLite provides zero-configuration portability while SQLAlchemy models and standard SQL queries ensure full portability to PostgreSQL.
  - **API:** FastAPI with Pydantic v2 schemas for typed validation, REST endpoints, and OpenAPI documentation.
  - **Graph Engine:** NetworkX for in-memory directed acyclic graph (DAG) operations, tree traversals, and root discovery.
  - **Analyst Dashboard:** Streamlit for rapid, interactive, cybersecurity-focused data visualization and case management.
  - **Testing & Verification:** pytest with fixtures for benign and malicious telemetry datasets.
- **Consequences:** Avoids heavy containerization overhead while delivering a fully functional, testable application.

---

## ADR-002: Ingestion Format and EVTX Scope
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** The R&D Proposal specifies Windows Sysmon and Windows Security event telemetry. In enterprise environments, Windows Event Logs (`.evtx`) are often exported to structured JSON or CSV via tools like `Get-WinEvent`, `nxlog`, `winlogbeat`, or Python scripts.
- **Decision:** TraceHunt MVP will natively ingest exported JSON and CSV formats representing Sysmon Event IDs (1, 3, 5) and Windows Security Event IDs (4624, 4625, 4688). We explicitly do *not* claim native binary `.evtx` support until a dedicated binary parser library (such as `python-evtx`) is integrated and verified with actual `.evtx` test files.
- **Consequences:** Transparent, truthful claims. Reliable cross-platform testing without requiring a Windows host OS.

---

## ADR-003: Idempotency, Deduplication, and Raw vs. Normalized Separation
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Ingesting logs multiple times must not produce duplicate records, corrupt counts, or trigger duplicate findings. Furthermore, forensic evidence must remain tamper-evident and traceable to the exact raw record.
- **Decision:**
  - `raw_events` stores original verbatim payloads, ingested timestamp, source filename, and a SHA-256 hash of the normalized raw payload.
  - An idempotency check checks this hash prior to insertion. Repeated imports flag duplicates and update counters without raising unhandled exceptions.
  - `endpoint_events` stores structured, typed fields normalized from `raw_events`.
  - `ingestion_errors` records any malformed lines or unparseable JSON without failing the entire batch import.
- **Consequences:** Complete data integrity, idempotent batch uploads, and 100% forensic auditability.

---

## ADR-004: Process Graph Edge Case Resolution
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** In real-world telemetry, parent process creation events may be missed (started before logging began, or collector dropped an event). Furthermore, Windows PIDs are reused over time, and events may arrive slightly out of chronological order.
- **Decision:**
  - Build directed graphs using `(host, process_id, parent_process_id, event_time)`.
  - When a parent process ID cannot be resolved to an existing `endpoint_events` record within a reasonable temporal window, TraceHunt will create an explicit **Unresolved Parent Node** rather than silently omitting the child process or fabricating a fictitious root.
  - PID reuse is disambiguated by matching the closest parent process start time strictly prior to the child's start time.
- **Consequences:** Realistic graph modeling that accurately reflects real-world endpoint forensic challenges.

---

## ADR-005: Explainable Behavioral Detection Rule Design
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Machine learning black boxes or opaque boolean flags undermine analyst trust. Threat hunting requires explainable rules that present the matched pattern, severity, confidence level, and rationale.
- **Decision:**
  - Implement versioned rule classes conforming to a common `BaseRule` interface.
  - Each rule emits structured `Finding` objects containing: Rule ID, Version, Name, Description, Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), Confidence (`LOW`, `MEDIUM`, `HIGH`), Matched Fields (dictionary of exact key-value evidence), Human-readable Rationale, and specific Caveats/Limitations.
  - Findings link directly to `endpoint_events.id`.
- **Consequences:** Explainable findings empower analyst validation and reduce alert fatigue.

---

## ADR-006: Analyst Disposition & Audit Trail Immutability
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Investigations require audit logging of all reviewer conclusions, comments, and disposition changes (e.g. `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN_ANOMALY`).
- **Decision:**
  - Maintain an append-only `analyst_audit` table.
  - Updating an investigation case's status or adding a comment creates a new record in `analyst_audit` with the reviewer username, timestamp, action, and comment text.
  - Investigation cases have a foreign key relationship to audit logs and linked evidence.
- **Consequences:** Full compliance-grade auditability for SOC investigations.

---

## ADR-007: Safe Report Generation & XSS Defense
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Investigation reports exported in HTML display untrusted command lines, filenames, and usernames, which could contain malicious payloads (e.g., HTML/JS injection).
- **Decision:**
  - All values rendered in HTML reports must pass through strict HTML escaping (`html.escape` or Jinja2 auto-escaping).
  - Reports export in both structured machine-readable JSON and formatted, printable HTML.
- **Consequences:** Complete defense against stored XSS when reviewing hostile command lines.

---

## ADR-008: SQLite Foreign Key Enforcement & DeclarativeBase Conventions
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** SQLite does not enforce foreign keys by default, risking orphaned rows or inconsistent cascade behavior during tests and local runtime unless explicitly enabled.
- **Decision:**
  - Attach an engine event listener in `tracehunt/database.py` connecting `PRAGMA foreign_keys = ON;` on every new connection.
  - Adopt SQLAlchemy 2.0 `Mapped` and `mapped_column` typed declarative syntax across all 9 models.
  - Configure `ondelete="CASCADE"` on `raw_events` -> `endpoint_events` and `investigations` -> `investigation_evidence` / `analyst_audit`.
  - Configure `ondelete="SET NULL"` for `process_relationships.parent_event_id` to cleanly model unresolved parent processes.
- **Consequences:** Strict referential integrity verified in unit tests with zero schema drifts between SQLite and PostgreSQL.

---

## ADR-009: Telemetry Normalization Pipeline & Idempotent Ingestion Strategy
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Ingesting JSON, JSONL, and CSV exports from various Windows versions requires handling diverse casing, nested structures (`EventData`/`System`), hexadecimal PIDs (`0x1a4`), and non-UTC timezone offsets while preserving raw evidence and preventing batch import halts.
- **Decision:**
  - **Savepoints for Independent Processing:** Each raw record is processed inside an isolated transaction savepoint (`session.begin_nested()`). A malformed or unparseable record writes an entry to `ingestion_errors` without terminating the batch.
  - **Deterministic Canonicalization:** Payloads are canonicalized with sorted keys and whitespace normalization before SHA-256 fingerprinting. Repeated imports skip duplicates cleanly.
  - **Timezone-Aware UTC Enforcement:** Timestamps with offsets (e.g. `+02:00`, `-04:00`) are mathematically converted to UTC (`datetime.astimezone(timezone.utc)`). Naive timestamps are assigned UTC without corrupting original local hour numbers.
  - **Hexadecimal PID Support:** `parse_int_field` supports decimal and `0x`-prefixed hex strings, mapping Windows Security 4688 `NewProcessId` and `CreatorProcessId` into standard integers.
- **Consequences:** Highly resilient, reproducible ingestion that maintains 100% forensic auditability.

---

## ADR-010: Process Execution DAG Reconstruction & Edge-Case Disambiguation with NetworkX
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Reconstructing parent-child trees from endpoint events faces real-world forensic challenges: processes may terminate before a new child spawns with a recycled PID, events may arrive out-of-order, parent telemetry may be missing entirely, and corrupt logs might present self-parenting loops (PID == PPID).
- **Decision:**
  - **Temporal Ordering:** Events for each host are strictly sorted by UTC `event_time ASC` (and tie-broken by `id ASC`) before graph evaluation.
  - **Termination Window Filtering:** When evaluating candidate parent instances for a child PPID, candidate processes that terminated before `child.event_time` (via Sysmon Event ID 5 telemetry) are excluded from candidate parent sets.
  - **PID Reuse Disambiguation:** When multiple candidate parent instances of the same PID are valid, the reconstructor selects the candidate parent created closest in time prior to the child's start (`max(event_time) <= child_time`).
  - **Explicit Unresolved Parent Modeling:** Missing parents and self-loops are never assigned fictitious root parents; they are assigned `parent_event_id=None`, `relationship_type="UNRESOLVED_PARENT"`, and `confidence="UNRESOLVED"`.
  - **Cycle Prevention:** Before adding an edge `P -> C`, `nx.is_directed_acyclic_graph` is validated. If a cycle would be introduced, the edge is discarded and recorded as `relationship_type="CYCLE_PREVENTED"`.
- **Consequences:** Mathematically verified DAG structure guaranteeing termination and preventing infinite loops in UI or recursive traversals.

---

## ADR-011: Explainable Behavioral Detection Engine, Modular Rules & Idempotent Findings
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Endpoint behavioral detection must provide transparent, analyst-explainable findings rather than black-box labels. Rules must evaluate process trees, command lines, and authentication bursts without crashing on missing data, and repeated evaluation across batches must never generate duplicate findings.
- **Decision:**
  - **Modular BaseRule Interface:** Each rule inherits from `BaseRule`, declaring stable `id`, `name`, `version`, `severity`, `confidence_level`, `mitre_technique`, and `description`. Rules implement `evaluate(event, context)` and can override `evaluate_batch`.
  - **Path Normalization for Cross-Platform Reliability:** Windows executable paths are parsed with `extract_process_name` normalizing `\\` and `/` separators to ensure consistent detection across Linux/macOS runtimes.
  - **Explainability & Caveats:** Every `RuleMatch` requires a human-readable `rationale`, structured `matched_fields`, and an operational `caveats` string explaining legitimate administrator or developer scenarios.
  - **Idempotent Findings Persistence:** Database enforces `UniqueConstraint("rule_id", "endpoint_event_id", name="uq_findings_rule_event")`. In addition, `DetectionEngine` pre-queries existing database findings and maintains an in-batch set, skipping duplicate detections cleanly and reporting `duplicates_skipped` in `DetectionSummary`.
  - **Fault-Isolated Execution:** Each rule runs within an exception handler. A crashing rule logs a detailed error and registers it in `summary.errors` without halting evaluation of remaining rules.
- **Consequences:** Production-grade detection architecture supporting arbitrary new rules, transparent forensic audit trails, and zero false-positive duplicate pollution.

---

## ADR-012: Unified Host Timeline Aggregation, Investigation State Machine & Audit Atomicity
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Analysts investigating threat hypotheses require an integrated chronological timeline of endpoint telemetry (process execution, network connections, authentication, terminations) correlated with detection findings. Case management requires strict lifecycle state validation, boundary protection against cross-host evidence contamination, and provably immutable, atomically committed audit logs.
- **Decision:**
  - **Deterministic Timeline Ordering & Zero-Duplicate Joins:** Timeline events are ordered by normalized UTC timestamp (`event_time ASC`) with deterministic tie-breaking on `id ASC`. Rather than performing SQL outer joins that produce duplicate rows when an event has multiple findings, events are queried with SQLAlchemy `selectinload(EndpointEvent.findings)` and filtered via `EndpointEvent.findings.any(...)` (SQL `EXISTS` subqueries). Each timeline entry represents exactly one event, embedding its correlated finding summaries.
  - **Parameterized Text Search & Bounded Limits:** Timeline text search across process images, command lines, users, and IP addresses uses parameterized SQLAlchemy `.ilike()` filters, preventing SQL injection. Results are strictly bounded (`min(limit, 1000)`).
  - **Strict Case Lifecycle State Machine:** Permitted statuses are restricted to `OPEN`, `INVESTIGATING`, `CLOSED_FALSE_POSITIVE`, and `CLOSED_TRUE_POSITIVE`. Transitions are validated against a strict state machine: direct transitions between closed statuses are prohibited (reopening to `OPEN` is required). Case closure and reopening require a non-empty analyst rationale.
  - **Cross-Host Evidence Boundary & Provenance Preservation:** Attaching evidence validates that referenced cases, findings, endpoint events, and raw events physically exist. If the evidence host differs from the investigation host, attachment is rejected unless explicit cross-host authorization (`allow_cross_host=True`) is provided. Removing an evidence link deletes only the junction row in `investigation_evidence`, preserving underlying telemetry and findings intact.
  - **Append-Only Audit Logging with Transactional Atomicity:** Reviewer actions (`CASE_CREATED`, `CASE_UPDATED`, `STATUS_CHANGED`, `CASE_CLOSED`, `CASE_REOPENED`, `EVIDENCE_ATTACHED`, `EVIDENCE_REMOVED`, `NOTE_ADDED`) are recorded in `analyst_audit`. No update or delete operations are exposed for audit records. Case modifications and their corresponding audit entries are flushed within the same database transaction, ensuring atomicity (a rolled-back case update leaves no orphaned audit log, and vice versa).
- **Consequences:** Provides an enterprise-grade forensic investigation workflow with verifiable chain of custody, bulletproof state transitions, and high-performance, injection-safe timeline queries.

---

## ADR-013: Modular REST API Architecture, Reporting Engine with XSS Defense, and Streamlit SOC Analyst Dashboard Integration
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** To make TraceHunt usable and demonstrable for security analysts and external systems, the platform requires a validated REST API, an exportable reporting engine supporting both machine-readable and human-readable formats, and an interactive analyst dashboard. The reporting engine must render untrusted telemetry (e.g. malicious command lines, payloads) safely without XSS risk, and the dashboard must present a clean, professional SOC interface calculating real metrics dynamically.
- **Decision:**
  - **Modular FastAPI REST API (`tracehunt/api/`):** Versioned under `/api/v1/` with sub-routers for `health`, `ingest`, `hosts`, `detections`, `cases`, and `reports`. All requests and responses are strictly validated via Pydantic v2 schemas. Database access uses a dependency-injected session generator (`get_db`) with automatic commit and rollback. Synchronous database operations are executed cleanly without blocking event loops.
  - **Defense-in-Depth Reporting Engine (`tracehunt/reporting/`):** Produces machine-readable JSON reports and human-readable executive HTML reports from factual database records. To prevent stored and reflected XSS, Jinja2 is configured with `select_autoescape(enabled_extensions=('html', 'xml'), default_for_string=True)`. Filenames are strictly sanitized to prevent path traversal, and reports are saved to a configurable directory (`settings.REPORTS_DIR`).
  - **Direct Service Integration in Streamlit (`tracehunt/dashboard/`):** The dashboard directly invokes the shared backend service layer (`tracehunt.ingestion`, `tracehunt.graph`, `tracehunt.detection`, `tracehunt.investigation`, `tracehunt.reporting`) using transactional sessions (`get_session_factory`). This architectural choice avoids the unnecessary latency, network failure modes, and synchronization overhead of an intermediate HTTP loopback, while reusing 100% of the underlying business logic.
  - **Professional Blue-and-White SOC Aesthetic:** Streamlit UI utilizes custom CSS tokens (`SOC_THEME_CSS`) inspired by modern enterprise security dashboards (Inter and JetBrains Mono typography, crisp metric cards, color-coded threat badges, and responsive tables).
- **Consequences:** Highly maintainable, responsive, and robust application architecture with zero code duplication, complete testability, and enterprise-grade security against untrusted inputs.

---

## ADR-014: Independent Ground-Truth Evaluation Methodology, Multi-Batch Benchmarking Protocol, and Security Boundary Enforcement
- **Status:** ACCEPTED
- **Date:** 2026-10-21
- **Context:** Stage 7 requires rigorous scientific evaluation: calculating detection accuracy (TP, FP, TN, FN, Precision, Recall, F1, FPR) without circular dependency on detector output, measuring empirical throughput across multiple batch sizes and telemetry formats without test state distortion, and ensuring complete end-to-end workflow verification with security boundary testing (XSS injection, path traversal, and format validation).
- **Decision:**
  - **Unit of Evaluation Disambiguation:** The primary unit of detection evaluation is formally defined as an **individual normalized endpoint telemetry event** (Binary Classification: Suspicious vs. Benign). Ground-truth labels (`is_suspicious`, `expected_rules`) are curated independently from telemetry fixtures and mapped before detector invocation.
  - **Isolated Temporary Databases for Benchmarks:** Ingestion and detection performance benchmarks are executed inside clean, isolated temporary SQLite databases (`tempfile.NamedTemporaryFile`) with WAL pragmas enabled. This eliminates measurement distortion caused by leftover database state, duplicate indexes, or disk cache warmups.
  - **Per-Rule Confusion Breakdown:** In addition to overall event classification metrics, each behavioral rule tracks its independent TP, FP, TN, FN, Precision, Recall, and F1 metrics, exposing domain-specific boundary behaviors and rule coverage overlaps.
  - **Defensive Security Hardening:** Strict path traversal rejection (`..`, `/`, `\`) is enforced at the REST API report download route. Jinja2 strict autoescaping is validated against realistic multi-vector XSS payloads (`<script>`, `<img onerror=...>`, `<svg onload=...>`). Oversized uploads are rejected prior to reading memory.
- **Consequences:** Transparent, scientifically defensible evaluation backed by reproducible scripts (`benchmark_performance.py`, `evaluate_detections.py`, `verify_e2e_full.py`) and persistent JSON result artifacts in `reports/`.



