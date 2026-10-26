# Skill: Idempotent Ingestion & Data Integrity

## 1. Purpose
Prevent duplicate records and maintain tamper-evident event integrity upon repeated imports.

## 2. When to Use
When writing batch ingestion and database persistence logic.

## 3. Prerequisites
Database models and raw event schemas established.

## 4. Implementation Steps
1. Compute SHA-256 fingerprint for each raw record based on (source, source_event_id, timestamp, host, raw_payload_str).
2. Query raw_events for existing fingerprint before inserting.
3. If fingerprint exists, mark as duplicate in import summary and skip inserting duplicate endpoint_events.
4. Execute inserts within a single database transaction; rollback on unexpected database failure.
5. Verify foreign key integrity between raw_events and endpoint_events.

## 5. Expected Outputs
tracehunt/ingestion/dedup.py and idempotent transaction helpers.

## 6. Verification Criteria
Run ingestion test twice with identical file; verify database count remains unchanged.

## 7. Common Failures & Troubleshooting
Silent duplicate creation; hash collisions due to unstable field ordering (use json.dumps sort_keys=True).

## 8. Safety & Ethical Considerations
Maintain immutable audit trail of what was ingested and when.

## 9. Documentation Updates
Document idempotency design in docs/DECISIONS.md.
