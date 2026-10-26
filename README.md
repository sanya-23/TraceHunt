# TraceHunt — Enterprise Behavioral Endpoint Threat-Hunting Platform

**TraceHunt** is an endpoint threat-hunting and behavioral investigation platform built in Python. It ingests Windows Sysmon process-creation and Windows Security event telemetry, normalizes data, reconstructs parent-child execution process trees, evaluates explainable behavioral detection rules mapped to MITRE ATT&CK, provides chronological host timelines and case management with analyst audit trails, and exports reproducible reports in machine-readable JSON and executive HTML.

---

## Architecture Overview

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
                                                     └─────────────┬─────────────┘
                                                                   │
                                                                   ▼
                                                     ┌───────────────────────────┐
                                                     │  Behavioral Detection     │
                                                     │  RULE-001 - RULE-005      │
                                                     └─────────────┬─────────────┘
                                                                   │
                                                                   ▼
                                                     ┌───────────────────────────┐
                                                     │  Case Management & Audit  │
                                                     │  State Machine & Evidence │
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

---

## Key Features

1. **Deterministic Telemetry Normalization & Deduplication:**
   - Ingests Sysmon process creation, termination, and network events, plus Windows Security logons and process executions.
   - Preserves raw event payloads verbatim with SHA-256 idempotency keys.
   - Isolates malformed records into `ingestion_errors` without aborting batch processing.

2. **NetworkX Process Graph Reconstruction:**
   - Reconstructs parent-child execution forests with directed acyclic graph (DAG) cycle prevention.
   - Resolves PID reuse windows temporally (`max(event_time) <= child_time`).
   - Explicitly flags unparented or missing roots as `UNRESOLVED_PARENT`.

3. **Explainable Behavioral Detections:**
   - **RULE-001-LOLBIN:** Living-off-the-land binary executions (certutil, bitsadmin, mshta, powershell) with download/decode flags.
   - **RULE-002-PROC-SPAWN:** Anomalous process spawning from Office applications or web browsers.
   - **RULE-003-RECON:** Discovery and enumeration commands (`whoami /all`, `net user /domain`, `nltest`, `reg save`).
   - **RULE-004-EVASION:** Direct process execution out of user-writable temporary directories (`AppData\Local\Temp`).
   - **RULE-005-AUTH-ANOMALY:** Bursts of authentication failures followed immediately by process execution.

4. **Forensic Host Timeline & Case Management:**
   - Chronological interleaving of process, network, and logon events with deterministic tie-breaking.
   - Multi-field parameterized search and bounded pagination.
   - Strict lifecycle state transitions (`OPEN` → `INVESTIGATING` → `CLOSED_TRUE_POSITIVE` / `CLOSED_FALSE_POSITIVE`).
   - Cross-host evidence boundary protection and immutable, append-only analyst audit history.

5. **REST API & Executive Reporting:**
   - Modular FastAPI v1 REST API with Pydantic v2 schemas and OpenAPI documentation.
   - Reproducible JSON reports and executive HTML reports rendered with Jinja2 autoescaping against XSS.

---

## Technology Stack

- **Language:** Python 3.11+ (Tested on Python 3.14.3)
- **Database:** SQLAlchemy 2.0 with SQLite (production-portable to PostgreSQL)
- **Graph Engine:** NetworkX
- **API Framework:** FastAPI & Uvicorn
- **Analyst Dashboard:** Streamlit
- **Testing:** pytest with 114 passing tests (100% pass rate)

---

## Empirical Benchmarks & Evaluation Summary

### 1. Ingestion & Processing Throughput (Empirical Measurements)
Measured in isolated test runs on macOS Apple Silicon (Python 3.14.3):

| Component / Pipeline Stage | Batch Size ($N$) | Latency (ms) | Throughput / Rate | Reliability / Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **JSON Ingestion** | 100 / 1,000 | 119 ms / 1,186 ms | **843.4 eps** | 100% valid records accepted |
| **JSONL Ingestion** | 100 / 1,000 | 129 ms / 1,295 ms | **772.1 eps** | 100% valid records accepted |
| **CSV Ingestion** | 100 / 1,000 | 123 ms / 1,202 ms | **832.0 eps** | 100% valid records accepted |
| **SHA-256 Deduplication** | 1,000 | 119 ms | **8,393.1 eps** | **100% duplicate skip rate** |
| **Graph DAG Reconstruction** | 1,000 nodes | 302.39 ms | 3,306.9 nodes/sec | DAG integrity validated |
| **Process Lineage Lookup** | 1,000 nodes | **312.03 ms** (median) | Ancestry path resolved | Root-to-leaf traversal |
| **Behavioral Detections** | 1,000 events | 550.45 ms | **1,816.7 eps** | 5 rules evaluated |
| **Executive HTML Report** | Full Case | **2.91 ms** | ~343 reports/sec | XSS sanitized, 14 KB HTML |

### 2. Independent Ground-Truth Detection Accuracy Evaluation
Evaluated across 43 independent labeled telemetry records (12 suspicious attack scenarios, 31 benign admin/system baseline scenarios):

| Metric | Measured Value | Formula / Standard Definition |
| :--- | :--- | :--- |
| **True Positives (TP)** | **12** | Suspicious events correctly alerted |
| **False Positives (FP)** | **0** | Benign events incorrectly alerted |
| **True Negatives (TN)** | **31** | Benign events correctly ignored |
| **False Negatives (FN)** | **0** | Suspicious events missed |
| **Precision** | **1.0000 (100%)** | $TP / (TP + FP)$ |
| **Recall (Sensitivity)** | **1.0000 (100%)** | $TP / (TP + FN)$ |
| **F1-Score** | **1.0000** | $2 \cdot (Precision \cdot Recall) / (Precision + Recall)$ |
| **False Positive Rate (FPR)** | **0.0000 (0%)** | $FP / (FP + TN)$ |

Detailed evaluations and methodology are documented in:
- [docs/FINAL_DEMO_CHECKLIST.md](file:///Users/sanyakumari/Desktop/Project/docs/FINAL_DEMO_CHECKLIST.md) — Rapid 5–10 minute step-by-step evaluation and demonstration guide.
- [docs/PROJECT_DEFENSE_GUIDE.md](file:///Users/sanyakumari/Desktop/Project/docs/PROJECT_DEFENSE_GUIDE.md) — Technical defense guide with 5 model spoken interview answers.
- [docs/EVALUATION_REPORT.md](file:///Users/sanyakumari/Desktop/Project/docs/EVALUATION_REPORT.md) — Hardware environment, benchmark tables, confusion matrix, limitations.
- [docs/FINAL_VERIFICATION_REPORT.md](file:///Users/sanyakumari/Desktop/Project/docs/FINAL_VERIFICATION_REPORT.md) — Quality gate audit, test suite output, and verification results.
- [docs/DEMO_GUIDE.md](file:///Users/sanyakumari/Desktop/Project/docs/DEMO_GUIDE.md) — Comprehensive operator walkthrough from CLI to Streamlit UI.



---

## Installation & Setup

### 1. Prerequisites
- Python 3.11 or higher
- Git

### 2. Clone and Setup Virtual Environment
```bash
git clone https://github.com/organization/tracehunt.git
cd tracehunt

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the template configuration file:
```bash
cp .env.example .env
```
Default configuration values:
- `ENVIRONMENT`: `development`
- `DATABASE_URL`: `sqlite:///./data/tracehunt.db`
- `API_HOST`: `127.0.0.1`
- `API_PORT`: `8000`
- `DASHBOARD_PORT`: `8501`
- `REPORTS_DIR`: `./reports`

---

## Quickstart & Launch Commands

### 1. Initialize Database Schema & Seed Detection Rules
```bash
python3 -c "from tracehunt.database import init_db; init_db(seed_rules=True)"
```

### 2. Seed Demo Attack Data (Optional)
To pre-populate the database with realistic attack trees, detections, and a sample investigation case:
```bash
python3 scripts/seed_demo.py
```

### 3. Run FastAPI Backend Server
```bash
python3 -m uvicorn tracehunt.api.app:app --host 127.0.0.1 --port 8000
```
- **API Base:** `http://127.0.0.1:8000/api/v1`
- **Interactive Swagger Documentation:** `http://127.0.0.1:8000/docs`
- **ReDoc Documentation:** `http://127.0.0.1:8000/redoc`

### 4. Run Streamlit Analyst Dashboard
```bash
python3 -m streamlit run tracehunt/dashboard/app.py --server.port 8501
```
- Open browser at `http://localhost:8501` to access the SOC Analyst Dashboard.

---

## Running the Verification Test Suite & Benchmarks

Run the full pytest suite (114 tests):
```bash
python3 -m pytest -v
```

Execute the reproducible performance benchmarking module:
```bash
python3 scripts/benchmark_performance.py
```

Execute the independent ground-truth detection accuracy evaluation:
```bash
python3 scripts/evaluate_detections.py
```

Execute the comprehensive 11-step end-to-end workflow verification:
```bash
python3 scripts/verify_e2e_full.py
```

Execute the live API & UI verification script:
```bash
python3 scripts/verify_workflow.py
```


---

## Supported Telemetry Formats

| Format | Extensions | Event Sources Supported | Notes |
| :--- | :--- | :--- | :--- |
| **JSON Array** | `.json` | Sysmon Event 1, 3, 5; Security 4624, 4625, 4688 | Formatted array of event dictionaries |
| **JSON Lines** | `.jsonl` | Sysmon Event 1, 3, 5; Security 4624, 4625, 4688 | One JSON object per line (streaming friendly) |
| **CSV** | `.csv` | Sysmon & Windows Security exports | Header row mapping standard Windows field names |

> **EVTX Scope Note:** Binary `.evtx` files must be exported to JSON, JSONL, or CSV format prior to ingestion. TraceHunt deliberately does not claim native binary EVTX parsing until a verified EVTX parser library is added.

---

## Demonstration Workflow

1. **Ingest Telemetry:**
   - In Streamlit, navigate to **📥 Telemetry Ingestion**.
   - Upload `fixtures/suspicious/attack_tree.json`.
   - Inspect the Ingestion Summary (Total read, normalized, duplicates skipped, errors).

2. **Reconstruct & Explore Process Trees:**
   - Navigate to **🌳 Host & Process Explorer**.
   - Select host `THREAT-HOST`.
   - Inspect the parent-child tree originating from `WINWORD.EXE` → `powershell.exe` → `certutil.exe`.
   - Inspect child processes, command lines, and parent linkage.

3. **Analyze Timeline & Behavioral Detections:**
   - Navigate to **⏱️ Host Timeline** to view chronological events with search filters.
   - Navigate to **🚨 Findings & Detections** and click **Evaluate Telemetry** to trigger behavioral rules.
   - Inspect rule rationales, confidence scores, and matched indicators.

4. **Case Investigation & Evidence Linking:**
   - Navigate to **📁 Investigation Cases**.
   - Create a new case or inspect the pre-seeded case.
   - Attach findings and endpoint events as formal evidence.
   - Transition status from `OPEN` → `INVESTIGATING` → `CLOSED_TRUE_POSITIVE` with mandatory rationale.
   - Review the immutable audit log.

5. **Generate Threat Report:**
   - Navigate to **📑 Report Generator**.
   - Select the investigation case and choose **JSON** and **HTML** formats.
   - Click **Generate Investigation Report**.
   - Download the machine-readable JSON and view the executive HTML briefing inline.

---

## Known Limitations

- **Binary EVTX:** Native binary Windows Event Log files (`.evtx`) require export to JSON/CSV before ingestion.
- **Process Memory Artifacts:** Memory dumps or raw DLL injection artifacts outside of process creation/termination telemetry are not captured in the MVP.
- **Single-Node SQLite Deployment:** The default local database is SQLite with foreign keys enforced; multi-tenant enterprise deployments should configure PostgreSQL via `DATABASE_URL`.

---

## License

TraceHunt is an educational and defensive cybersecurity analytical platform developed under the Apache 2.0 License.
