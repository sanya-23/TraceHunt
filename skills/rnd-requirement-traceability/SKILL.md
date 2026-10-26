# Skill: R&D Requirement Traceability

## 1. Purpose
Ensure 100% bidirectional traceability between TraceHunt R&D Proposal requirements and implemented code/tests.

## 2. When to Use
When designing new modules, writing tests, or updating the implementation checklist.

## 3. Prerequisites
docs/RND_PROPOSAL.md must be present and verified.

## 4. Implementation Steps
1. Reference the specific section in docs/RND_PROPOSAL.md (e.g., Section 6 Workflow, Section 7 Database Design).
2. Confirm corresponding schema, module name, and function signature.
3. Write unit/integration tests that directly test the proposal specification.
4. Update docs/RND_TRACEABILITY.md with module path, database tables, test file, and evidence artifact.
5. Mark checklist items as VERIFIED only after tests pass.

## 5. Expected Outputs
Updated docs/RND_TRACEABILITY.md and docs/IMPLEMENTATION_CHECKLIST.md.

## 6. Verification Criteria
All proposal features (ingestion, normalization, graph, rules, timeline, cases, export) have mapped entries.

## 7. Common Failures & Troubleshooting
Building features not in proposal; claiming verification without test mapping.

## 8. Safety & Ethical Considerations
Adhere strictly to proposal scope and constraints (e.g. no fake EVTX claims).

## 9. Documentation Updates
Update docs/RND_TRACEABILITY.md and docs/IMPLEMENTATION_CHECKLIST.md.
