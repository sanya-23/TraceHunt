# Skill: Process Graph Reconstruction with NetworkX

## 1. Purpose
Reconstruct parent-child process execution trees, handling PID reuse, missing parents, and out-of-order events.

## 2. When to Use
During Stage 3 graph reconstruction service development.

## 3. Prerequisites
Normalized endpoint_events available in database.

## 4. Implementation Steps
1. Query endpoint_events for a specific host, filtering on process creation events (Sysmon 1, Security 4688).
2. Instantiate a NetworkX DiGraph.
3. Add nodes with process metadata (PID, image, command_line, user, event_time, event_id).
4. Match child (PID, PPID, event_time) to candidate parent (PID == PPID, parent_time < child_time).
5. If candidate parent is found, add directed edge (parent -> child) with confidence HIGH.
6. If no parent event exists in dataset, create an Unresolved Parent Node with confidence UNRESOLVED.
7. Disambiguate PID reuse by selecting parent with max(event_time) < child_time within temporal threshold.
8. Persist links into process_relationships table.

## 5. Expected Outputs
tracehunt/graph/reconstructor.py, tracehunt/graph/tree_service.py.

## 6. Verification Criteria
Test with multi-stage execution tree fixtures; verify orphan processes are explicitly marked.

## 7. Common Failures & Troubleshooting
Infinite cycles in DAG (NetworkX is_directed_acyclic_graph); connecting child to parent started after child.

## 8. Safety & Ethical Considerations
Never fabricate fictitious parent processes without explicit unresolved tagging.

## 9. Documentation Updates
Update docs/IMPLEMENTATION_CHECKLIST.md Stage 3 items.
