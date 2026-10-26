# Skill: Streamlit Dashboard Development & UX

## 1. Purpose
Construct an analyst-first, interactive threat-hunting dashboard with real dynamic metrics.

## 2. When to Use
During Stage 6 UI development.

## 3. Prerequisites
Streamlit installed; tracehunt backend services accessible.

## 4. Implementation Steps
1. Configure Streamlit page layout in tracehunt/dashboard/app.py (wide layout, cybersecurity dark theme).
2. Implement Navigation Bar: Overview Metrics, Telemetry Ingestion, Host Process Tree, Timeline, Findings, Cases, Reports.
3. Bind metrics directly to database queries (count(events), count(hosts), count(findings), count(cases)). Zero hardcoded stats.
4. Build interactive process tree viewer displaying parent-child hierarchy with suspicious badges.
5. Build searchable host timeline with date range, user, process, and severity filters.
6. Build case management controls allowing analysts to update case status and record audit dispositions.
7. Add report generation and download buttons.

## 5. Expected Outputs
tracehunt/dashboard/app.py and components under tracehunt/dashboard/components/.

## 6. Verification Criteria
Launch Streamlit and test all interactive widgets, filters, and forms.

## 7. Common Failures & Troubleshooting
Hardcoding numbers in UI; slow page re-runs due to unmemoized queries (use st.cache_data where appropriate).

## 8. Safety & Ethical Considerations
Sanitize user inputs before displaying in Streamlit markdown to prevent markdown injection.

## 9. Documentation Updates
Index screenshots of the dashboard in docs/SCREENSHOT_INDEX.md.
