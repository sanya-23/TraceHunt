# Skill: Documentation & Cross-Account Session Handoff

## 1. Purpose
Ensure zero knowledge loss across AI accounts, resets, and development handoffs.

## 2. When to Use
At the conclusion of every stage, before session termination, or when switching tasks.

## 3. Prerequisites
All stage changes tested and committed/saved.

## 4. Implementation Steps
1. Review all modified files and confirm code integrity.
2. Update PROJECT_STATE.md with: current stage, completed work, files changed, test results, blockers, and single exact next task.
3. Update docs/IMPLEMENTATION_CHECKLIST.md with exact status changes (NOT STARTED, IN PROGRESS, BLOCKED, VERIFIED).
4. Append newly executed command outputs to docs/TEST_LOG.md.
5. Update docs/RND_TRACEABILITY.md if new requirements were implemented or verified.
6. Ensure README.md remains synchronized with current execution instructions.

## 5. Expected Outputs
Fully synchronized repository documentation ready for any successor agent.

## 6. Verification Criteria
A fresh agent inspecting only repository files can immediately resume work without asking clarifying questions.

## 7. Common Failures & Troubleshooting
Vague next steps; leaving checklist items out of sync; failing to record actual test logs.

## 8. Safety & Ethical Considerations
Maintain full auditability of project changes.

## 9. Documentation Updates
All continuity files updated.
