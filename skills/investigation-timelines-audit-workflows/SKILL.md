# Skill: Investigation Timelines & Audit Workflows

## 1. Purpose
Interleave host events chronologically, manage investigations, and persist immutable analyst audit history.

## 2. When to Use
During Stage 5 timeline and investigation service development.

## 3. Prerequisites
Normalized events, findings, and audit models implemented.

## 4. Implementation Steps
1. Implement timeline query service in tracehunt/investigation/timeline_service.py ordering events by event_time ASC.
2. Interleave process start, process stop, and logon/logoff events into unified chronological sequence.
3. Implement case management in tracehunt/investigation/case_service.py: create, update status, attach findings/evidence.
4. Implement audit service in tracehunt/investigation/audit_service.py: append record to analyst_audit on every action.
5. Enforce audit fields: action_type, reviewer, comment, timestamp, previous_status, new_status.

## 5. Expected Outputs
tracehunt/investigation/timeline_service.py, case_service.py, audit_service.py.

## 6. Verification Criteria
Create investigation, add disposition, and verify immutable audit record in analyst_audit table.

## 7. Common Failures & Troubleshooting
Allowing audit log deletion or tampering; losing chronological ordering across millisecond events.

## 8. Safety & Ethical Considerations
Audit logs must be append-only to preserve legal and operational integrity.

## 9. Documentation Updates
Document investigation lifecycle in README.md.
