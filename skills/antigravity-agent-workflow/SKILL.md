# Skill: Antigravity Agent Workflow & Tool Utilization

## 1. Purpose
Maximize efficiency when operating inside Google Antigravity AI environment.

## 2. When to Use
Continuously throughout project execution.

## 3. Prerequisites
Understanding of Antigravity tools (run_command, write_to_file, view_file, etc.).

## 4. Implementation Steps
1. Use run_command for shell operations, respecting Cwd within workspace.
2. Use write_to_file and replace_file_content for code edits with accurate line targeting.
3. For background tasks (e.g. servers), monitor via manage_task or reactive notifications.
4. Maintain file link formatting [file.ext](file:///abs/path) in markdown reports.
5. Avoid polling loops; leverage system event notifications.
6. Check skill index and relevant skills before beginning multi-step implementations.

## 5. Expected Outputs
Smooth, error-free tool interactions and proactive task completion.

## 6. Verification Criteria
All tool calls succeed with clean outputs and zero syntax or path errors.

## 7. Common Failures & Troubleshooting
Using cd commands; writing outside workspace; hardcoding relative links without file:// scheme.

## 8. Safety & Ethical Considerations
Never propose commands outside workspace or run unauthorized long-running external processes.

## 9. Documentation Updates
Maintain continuity documentation after each agent turn.
