# Skill: Explainable Behavioral Detection Engineering

## 1. Purpose
Design transparent, versioned behavioral detection rules with severity, confidence, and source links.

## 2. When to Use
During Stage 4 detection engine development.

## 3. Prerequisites
Normalized events and process relationships available.

## 4. Implementation Steps
1. Define BaseRule abstract class with id, name, version, severity, confidence, description, and evaluate(event, context).
2. Implement Rule 1: Suspicious Lolbin Execution (e.g. certutil -urlcache, bitsadmin, mshta, powershell -enc).
3. Implement Rule 2: Suspicious Process Spawning (e.g. WINWORD.EXE or chrome.exe spawning cmd.exe or powershell.exe).
4. Implement Rule 3: Reconnaissance & Credential Discovery (e.g. whoami /all, nltest /dclist, reg save HKLM\SAM).
5. Implement Rule 4: Defense Evasion & Temporary Folder Execution (e.g. execution from %TEMP% or %APPDATA%).
6. Implement Rule 5: Authentication Anomalies (rapid failed logons followed by privileged process execution).
7. Each rule match returns Finding containing exact matched fields, human explanation, and caveats.
8. Save findings to findings table linked to endpoint_event_id.

## 5. Expected Outputs
tracehunt/detection/engine.py, tracehunt/detection/rules/*.py.

## 6. Verification Criteria
Run rule engine against benign fixtures (0 FP) and attack fixtures (100% TP).

## 7. Common Failures & Troubleshooting
Hardcoding opaque string searches; missing matched fields explanation; generating duplicate findings.

## 8. Safety & Ethical Considerations
Ensure rules are read-only and perform no active intervention on the host system.

## 9. Documentation Updates
Document detection rules and MITRE ATT&CK mappings in README.md.
