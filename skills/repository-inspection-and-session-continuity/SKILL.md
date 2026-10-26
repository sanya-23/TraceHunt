# Skill: Repository Inspection and Session Continuity

## 1. Purpose
Standardize procedure for inspecting repository state, environment variables, and active continuity files at session start.

## 2. When to Use
At the start of every AI session or after any context window reset/account switch.

## 3. Prerequisites
Access to repository root directory /Users/sanyakumari/Desktop/Project.

## 4. Implementation Steps
1. Check git status and list files in workspace.
2. Read AGENTS.md, PROJECT_STATE.md, docs/IMPLEMENTATION_CHECKLIST.md, and docs/TEST_LOG.md.
3. Verify Python version (python3 --version >= 3.11).
4. Identify the active stage and the single exact next task specified in PROJECT_STATE.md.
5. Verify that prior verification statuses are backed by real entries in TEST_LOG.md or SCREENSHOT_INDEX.md.

## 5. Expected Outputs
Accurate mental model of project progress and confirmed immediate next action.

## 6. Verification Criteria
Report active stage, last verified milestone, and next action without hallucinations.

## 7. Common Failures & Troubleshooting
Assuming files exist without checking; ignoring PROJECT_STATE.md; proceeding with wrong stage.

## 8. Safety & Ethical Considerations
Never execute destructive commands or discard existing uncommitted work without confirmation.

## 9. Documentation Updates
Update PROJECT_STATE.md if repository state differs from recorded state.
