# TraceHunt — Project Defense & Technical Interview Guide

This guide prepares developers, researchers, and security analysts to defend and articulate the design, architecture, implementation decisions, and evaluation results of **TraceHunt**.

---

## 1. Project Mission & Problem Statement

### What is TraceHunt?
**TraceHunt** is an endpoint threat-hunting and behavioral investigation platform built in Python. It ingests Windows Sysmon and Windows Security event telemetry, normalizes disparate log schemas into a unified data model, reconstructs directed acyclic parent-child process execution trees (DAGs), evaluates explainable behavioral detection rules mapped to MITRE ATT&CK, provides chronological forensic host timelines, tracks investigations through a formal case lifecycle with immutable audit trails, and exports reproducible reports in machine-readable JSON and executive HTML.

### What Problem Does It Solve?
Modern SOC analysts face three critical operational bottlenecks when investigating endpoint threats:
1. **Telemetry Silos & Schema Fragmentation:** Windows Sysmon (Events 1, 3, 5) and Windows Security Event Logs (Events 4624, 4625, 4688) format process IDs, usernames, timestamps, and image paths inconsistently (e.g., hexadecimal `0x1a4` in 4688 vs. integer `420` in Sysmon; inconsistent UTC vs. local offsets).
2. **Loss of Process Execution Context:** Modern malware uses living-off-the-land techniques (e.g., weaponized Word documents spawning PowerShell, which spawns CertUtil). Isolated log search tools show single command lines but lose the ancestral lineage tree, making it difficult to distinguish an administrative script from a compromised Office process.
3. **Black-Box Alerts & Lack of Case Traceability:** Traditional SIEM alerts often state that an anomaly occurred without preserving the exact matched fields, rule version, or link to raw event evidence, leading to high alert fatigue and unverified incident closures.

TraceHunt solves these challenges with an end-to-end, deterministic, explainable, and reproducible investigative pipeline.

---

## 2. Architecture & Data Flow

```
                                    ┌─────────────────────────────────┐
                                    │  Windows Telemetry Logs         │
                                    │  Sysmon (1, 3, 5) / Sec (4624+) │
                                    │  JSON, JSONL, CSV exports       │
                                    └────────────────┬────────────────┘
                                                     │
                                                     ▼
                                    ┌─────────────────────────────────┐
                                    │  Ingestion & Deduplication Engine│
                                    │  SHA-256 fingerprinting         │
                                    └───────┬─────────────────┬───────┘
                                            │                 │
                         Raw Verbatim       ▼                 ▼ Normalized Typed
                       ┌───────────────────────┐   ┌───────────────────────────┐
                       │   raw_events          │   │   endpoint_events         │
                       │   ingestion_errors    │   └─────────────┬─────────────┘
                       └───────────────────────┘                 │
                                                                 ▼
                                                   ┌───────────────────────────┐
                                                   │  Process Tree Reconstruct │
                                                   │  NetworkX DAG / PID Reuse │
                                                   │  Parent.time <= Child.time│
                                                   └─────────────┬─────────────┘
                                                                 │
                                                                 ▼
                                                   ┌───────────────────────────┐
                                                   │  Behavioral Detection     │
                                                   │  RULE-001 - RULE-005      │
                                                   │  Evidence Linkage (1-to-1)│
                                                   └─────────────┬─────────────┘
                                                                 │
                                                                 ▼
                                                   ┌───────────────────────────┐
                                                   │  Case Management & Audit  │
                                                   │  State Machine & Evidence │
                                                   │  Append-Only Audit Log    │
                                                   └─────────────┬─────────────┘
                                                                 │
                                    ┌────────────────────────────┴───────────────────────────┐
                                    ▼                                                         ▼
                     ┌──────────────────────────────┐                         ┌──────────────────────────────┐
                     │  FastAPI REST API (/api/v1/) │                         │  Streamlit SOC Dashboard     │
                     │  OpenAPI / Swagger at /docs  │                         │  Blue/White Operations UI    │
                     └──────────────────────────────┘                         └──────────────────────────────┘
                                                                 │
                                                                 ▼
                                                   ┌───────────────────────────┐
                                                   │  Reporting Engine         │
                                                   │  JSON & XSS-Safe HTML     │
                                                   └───────────────────────────┘
```

### The Ingestion-to-Report Pipeline
1. **Raw Ingestion:** File payload is parsed line-by-line (or record-by-record). A canonicalized JSON SHA-256 fingerprint is generated. If already in `raw_events`, the record is skipped immediately.
2. **Schema Normalization:** Raw fields are mapped to strongly-typed `EndpointEvent` records with ISO-8601 UTC timestamps, integer PIDs, normalized usernames, and event types (`PROCESS_CREATE`, `PROCESS_TERMINATE`, `NETWORK_CONNECT`, `AUTHENTICATION_SUCCESS`, `AUTHENTICATION_FAILURE`).
3. **Error Isolation:** Malformed records are intercepted and written to `ingestion_errors` via sub-transactions (`session.begin_nested()`), ensuring that bad lines do not crash the batch.
4. **Graph Reconstruction:** Processes are partitioned by `host`. NetworkX constructs a directed graph where directed edges point from parent process to child process.
5. **Detection Evaluation:** Detection rules inspect normalized events and the reconstructed graph DAG to trigger evidence-linked findings in `findings`.
6. **Timeline & Case Management:** Analysts query chronological timelines across all event categories, create hunt cases (`investigations`), transition cases through a state machine, attach evidence (`investigation_evidence`), and record audit entries (`analyst_audit`).
7. **Report Compilation:** An executive HTML or JSON report is generated and sanitized against XSS.

---

## 3. Telemetry Ingestion & Deduplication

### How Does Ingestion Work?
The ingestion engine (`tracehunt/ingestion/importer.py`) dynamically detects file format from content headers:
- **JSON:** Deserialized as an array of event dictionaries.
- **JSONL:** Processed line-by-line in streaming fashion to minimize memory footprint.
- **CSV:** Headers are normalized to lowercase standard Windows telemetry column names.

### How Does Deduplication Work?
TraceHunt uses deterministic event fingerprinting:
1. Raw event key-value pairs are canonicalized (sorted alphabetically, null values normalized).
2. A SHA-256 hash is computed: `hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()`.
3. In `raw_events`, a unique index enforces `payload_hash` uniqueness.
4. In-memory set lookup during batch ingestion enables deduplication throughput of **8,393 events/second**, skipping pre-existing records in ~0.11 ms without database write overhead.

---

## 4. Process Tree Reconstruction & PID Reuse

### How Does TraceHunt Reconstruct Process Trees?
Process execution in Windows is modeled as a Directed Acyclic Graph (DAG) using NetworkX (`tracehunt/graph/reconstructor.py`).
Edges represent process creation: $Parent \rightarrow Child$.

### How Does TraceHunt Handle Windows PID Reuse?
On Windows operating systems, Process IDs (PIDs) are non-unique numbers recycled by the kernel over time (typically integers from 4 to 65,535). Two distinct processes can share the exact same PID on the same host if one terminates before the other spawns.

TraceHunt resolves this through **four strict temporal disambiguation rules**:
1. **Temporal Precedence:** A candidate parent must have been created before the child: `parent.event_time <= child.event_time`.
2. **Termination Filtering:** If a `PROCESS_TERMINATE` event exists for candidate parent PID $P$ at $T_{term}$, and $T_{term} < child.event\_time$, that instance of PID $P$ is disqualified.
3. **Closest Temporal Proximity:** If multiple candidate parent instances satisfy the time window, TraceHunt selects the instance created closest in time to the child spawn: $\min(child.event\_time - parent.event\_time)$.
4. **Explicit Unresolved Parent Nodes:** If a process specifies a parent PID ($PPID$) for which no creation event exists in the ingested telemetry (e.g., system root processes or collection started mid-execution), TraceHunt does not drop the node. Instead, it marks the parent as `UNRESOLVED_PARENT` with confidence `UNRESOLVED`.
5. **Cycle Prevention:** Self-referencing PIDs ($PPID == PID$) and circular execution chains are trapped and flagged as `CYCLE_PREVENTED`.

---

## 5. The Five Behavioral Detection Rules & MITRE ATT&CK Mapping

Each behavioral rule is versioned, transparent, and produces evidence-linked findings:

| Rule ID | Rule Name | MITRE ATT&CK | Logic & Trigger Criteria | Known Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **`RULE-001-LOLBIN`** | Suspicious LOLBIN Execution | **T1218** (System Binary Proxy Execution) | Evaluates execution of trusted Windows binaries (`certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `powershell.exe`) with adversarial flags: download flags (`-urlcache`, `-split`, `/transfer`), script decoders (`-enc`, `base64`), or direct URL arguments. | Legitimate enterprise administrative scripts using PowerShell with encoded commands or CertUtil for corporate CA verification require whitelist tuning. |
| **`RULE-002-PROC-SPAWN`** | Suspicious Office/Browser Child Process | **T1059** (Command and Scripting Interpreter) | Evaluates whether Microsoft Office (`winword.exe`, `excel.exe`, `powerpnt.exe`) or browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`) spawn command shells (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`). Inspects both normalized event fields and process graph ancestors. | Legitimate browser helper extensions or automated developer testing scripts (e.g., Selenium) can trigger false positives if not configured in exclusion lists. |
| **`RULE-003-RECON`** | Discovery & Credential Reconnaissance | **T1087** (Account Discovery) / **T1082** (System Info) | Detects invocation of enumeration utilities: `whoami /all`, `net user /domain`, `net group`, `nltest /dclist`, or `reg save HKLM\SAM` for credential hive extraction. | IT helpdesk administrators routinely run `whoami /all` or `net user` during manual workstation troubleshooting. |
| **`RULE-004-EVASION`** | Defense Evasion via Temp Execution | **T1027** (Obfuscated Files) / **T1070** (Indicator Removal) | Detects direct process execution from world-writable temporary paths: `\AppData\Local\Temp\` or `\Windows\Temp\`. | Legitimate third-party software installers and updaters frequently unpack and execute setup stubs from `%TEMP%`. |
| **`RULE-005-AUTH-ANOMALY`** | Rapid Authentication Anomaly | **T1110** (Brute Force) | Correlates bursts of $\ge 3$ failed logons (Windows Security Event 4625) within a 300-second window on the same host, immediately followed by process execution. | Distributed slow brute-force attacks across multiple hosts or spanning hours exceed the single-host 300s temporal correlation window. |

---

## 6. Evaluation Methodology & Metrics

### What Was the Evaluation Unit?
The evaluation unit is the **Individual Telemetry Event** under binary classification:
- **Suspicious (Positive):** The event represents confirmed adversarial or malicious tradecraft.
- **Benign (Negative):** The event represents legitimate system, administrative, or user activity.

### Measured Metrics on Curated Ground-Truth Dataset ($N = 43$):
- **True Positives (TP):** **12** (12 attack scenarios correctly flagged)
- **False Positives (FP):** **0** (0 benign baselines flagged)
- **True Negatives (TN):** **31** (31 benign events correctly ignored)
- **False Negatives (FN):** **0** (0 attack scenarios missed)
- **Precision:** $\frac{TP}{TP + FP} = \frac{12}{12 + 0} =$ **1.0000 (100%)**
- **Recall (Sensitivity):** $\frac{TP}{TP + FN} = \frac{12}{12 + 0} =$ **1.0000 (100%)**
- **F1-Score:** $2 \cdot \frac{Precision \cdot Recall}{Precision + Recall} =$ **1.0000**
- **False Positive Rate (FPR):** $\frac{FP}{FP + TN} = \frac{0}{0 + 31} =$ **0.0000 (0%)**

### Why Are These Metrics Preliminary?
As documented in [docs/EVALUATION_REPORT.md](file:///Users/sanyakumari/Desktop/Project/docs/EVALUATION_REPORT.md):
1. **Dataset Scale ($N=43$):** The benchmark dataset represents synthetic, curated laboratory fixtures designed to test specific attack behaviors and benign baseline controls.
2. **Enterprise Noise:** In real enterprise networks, millions of events occur daily. Legitimate administrative automation (SCCM, Ansible, third-party software updaters) frequently executes from temporary directories or uses encoded PowerShell commands. In enterprise production, the False Positive Rate will naturally be higher than 0.0%, requiring organization-specific baseline exclusions.

---

## 7. Architectural Decisions & Trade-Offs

### Why SQLite for the Prototype?
- **Portability & Zero External Dependencies:** SQLite requires zero daemon configuration, container orchestration, or network setup, making the research prototype 100% reproducible on any analyst laptop.
- **ACID Compliance & Foreign Keys:** With `PRAGMA foreign_keys = ON`, SQLite enforces relational constraints and transaction rollback guarantees identically to enterprise SQL.
- **PostgreSQL Portability:** All 9 models use pure SQLAlchemy 2.0 ORM declarations without dialect-specific hacks. Switching to PostgreSQL requires only updating `DATABASE_URL` in `.env`.

### Security Controls & Safe Rendering
1. **XSS Defense:** Security events contain adversary-controlled strings (e.g., malicious command lines like `<script>alert('pwn')</script>`). In [tracehunt/reporting/html.py](file:///Users/sanyakumari/Desktop/Project/tracehunt/reporting/html.py), Jinja2 is initialized with `select_autoescape(enabled_extensions=('html', 'xml'), default_for_string=True)` to convert all raw strings into inert HTML entities (`&lt;script&gt;`).
2. **Path Traversal Defense:** Report download and generation endpoints strictly validate filenames against `^[A-Za-z0-9._-]+$` and explicitly reject path separators (`..`, `/`, `\`), confining all file operations to `reports/`.
3. **Immutable Audit Trails:** Every case creation, status transition, and evidence attachment automatically writes to `analyst_audit`. The audit table has no update or delete routes, preserving an unalterable chain of custody.

---

## 8. Current Limitations & Future Roadmap

| Limitation | Technical Reason | Future Roadmap Solution |
| :--- | :--- | :--- |
| **Native EVTX Ingestion** | Binary `.evtx` files require complex binary chunk parsing and template table decompression. | Integrate the Rust-based `python-evtx` library for native direct EVTX ingestion. |
| **Single-Host Correlation** | SQLite prototype correlates events partitioned per host. | Implement distributed message streaming (Kafka) and graph database (Neo4j) for lateral movement detection across thousands of hosts. |
| **Process Memory Telemetry** | MVP relies on Windows Event Logs (Sysmon 1/3/5 and Security 4688). In-memory DLL injection without process creation is invisible. | Ingest Sysmon Event 8 (CreateRemoteThread) and Sysmon Event 10 (ProcessAccess) or kernel ETW streams. |
| **Authentication & RBAC** | Local lab mode operates without user login. | Add OAuth2 / JWT authentication middleware with role-based access control (SOC Tier 1 Analyst vs. Lead Investigator). |

---

## 9. Five Realistic Interviewer Questions & Model Spoken Answers

### Question 1: "Why did you build process trees with NetworkX instead of storing parent-child relationships solely in SQL foreign keys?"
> **Model Answer:**
> *"In SQL, querying multi-generational process ancestry—such as determining whether `certutil.exe` descended from `WINWORD.EXE` three generations earlier—requires recursive Common Table Expressions (CTEs). Recursive SQL queries become computationally expensive and fragile when handling PID reuse and missing telemetry. By reconstructing the process DAG in NetworkX, graph operations like ancestry traversal, finding common ancestors, cycle detection, and topological sorting become $O(V + E)$ in-memory operations. We persist the resulting verified relationships into `process_relationships` for fast indexing, giving us the analytical power of graph algorithms alongside relational database integrity."*

### Question 2: "How does your ingestion pipeline handle a corrupted or malformed telemetry file without dropping valid events?"
> **Model Answer:**
> *"We implemented sub-transaction isolation using SQLAlchemy's `session.begin_nested()`. During batch processing, each event line is validated inside an isolated database savepoint. If a line contains invalid JSON, corrupt hexadecimal PIDs, or missing mandatory fields, an exception is caught, the savepoint rolls back only that single record, and a detailed diagnostic entry is written to the `ingestion_errors` table with the raw line and error context. The batch then continues processing remaining valid records without interruption. This ensures high availability and forensic accountability for damaged log streams."*

### Question 3: "If your detection engine achieves 100% precision and recall in testing, why do you characterize these metrics as preliminary?"
> **Model Answer:**
> *"In defensive cybersecurity engineering, claiming 100% accuracy in production is unrealistic. Our 100% score was achieved on a curated, deterministic ground-truth evaluation dataset of 43 events designed to validate that the rule logic fires on genuine attack indicators and remains silent on benign administrative baseline controls. In an enterprise environment with hundreds of thousands of endpoints, benign software installers frequently execute from `%TEMP%`, and administrators run base64-encoded PowerShell scripts. We explicitly document this in `docs/EVALUATION_REPORT.md` as a preliminary baseline, and we design every finding with explainable matched fields so analysts can quickly filter and tune rules for their specific environment."*

### Question 4: "Why did you separate `raw_events` from `endpoint_events` instead of normalizing immediately into a single table?"
> **Model Answer:**
> *"In digital forensics and incident response, preserving an unalterable chain of custody is a foundational principle. Normalization is an interpretive process—parsing timestamps to UTC, converting hex strings to integers, and standardizing image paths. If a normalization bug occurs, or if future rules require an unparsed raw field (such as specific Sysmon XML attributes), having the raw event payload stored verbatim in `raw_events` allows lossless re-parsing. Furthermore, calculating the SHA-256 hash on the raw payload enables instantaneous deduplication before expensive schema normalization runs."*

### Question 5: "How does your case management system enforce forensic accountability during an investigation?"
> **Model Answer:**
> *"We built an immutable audit service and a strict finite state machine into case management. Hunt cases can only transition through validated states: `OPEN` to `INVESTIGATING`, and from `INVESTIGATING` to `CLOSED_TRUE_POSITIVE` or `CLOSED_FALSE_POSITIVE`. Any closure or reopening requires a mandatory analyst rationale. Every state change, note creation, and evidence attachment commits an atomic record to `analyst_audit`. Because the audit service has no edit or delete methods, no analyst can alter the historical audit trail, ensuring compliance with forensic integrity standards."*
