# Skill: Screenshot Capture & Visual QA Verification

## 1. Purpose
Capture, label, and catalog visual verification screenshots from the running Streamlit dashboard.

## 2. When to Use
During Stage 7 verification and whenever introducing UI changes.

## 3. Prerequisites
Streamlit app running locally; browser agent or automated capture available.

## 4. Implementation Steps
1. Launch Streamlit dashboard on localhost:8501 with populated test database.
2. Navigate to each of the 9 required views: Dashboard (01), Import (02), Malformed (03), Process Tree (04), Timeline (05), Finding (06), Investigation (07), Report (08), Terminal Tests (09).
3. Capture clean screenshot and save to evidence/screenshots/<number>-<name>.png.
4. Inspect image to ensure no broken layout, overlapping text, or error banners.
5. Record screenshot in docs/SCREENSHOT_INDEX.md with feature verified and fixture used.

## 5. Expected Outputs
evidence/screenshots/01-dashboard.png through 09-tests.png.

## 6. Verification Criteria
Verify all 9 images exist, are readable, and accurately represent the described application state.

## 7. Common Failures & Troubleshooting
Using dummy/placeholder images; capturing screens with visible uncaught exceptions.

## 8. Safety & Ethical Considerations
Ensure no sensitive corporate data or secrets are visible in screenshots.

## 9. Documentation Updates
Update docs/SCREENSHOT_INDEX.md with capture timestamps and notes.
