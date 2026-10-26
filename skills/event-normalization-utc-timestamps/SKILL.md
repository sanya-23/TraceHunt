# Skill: Event Normalization & UTC Timestamp Handling

## 1. Purpose
Normalize heterogeneous telemetry into unified schema with strict UTC ISO-8601 timestamps.

## 2. When to Use
During Stage 2 normalization pipeline implementation.

## 3. Prerequisites
Raw events successfully stored in raw_events table.

## 4. Implementation Steps
1. Parse timestamp strings (ISO-8601, Windows Event Viewer format, UNIX epoch) into timezone-aware UTC datetime.
2. Clean hostname (strip domain suffix or normalize to uppercase).
3. Normalize username (extract DOMAIN\user or user@domain into canonical forms).
4. Normalize process IDs from decimal or hex string into integers.
5. Normalize executable paths (convert backslashes, preserve original case).
6. Write normalized record to endpoint_events linked to raw_event_id.
7. Update raw_event parse_status to PARSED.

## 5. Expected Outputs
tracehunt/ingestion/normalizer.py.

## 6. Verification Criteria
Verify normalized records match expected types; confirm UTC timezone offset is +00:00.

## 7. Common Failures & Troubleshooting
Timezone naive datetime mixing; loss of command-line arguments during string normalization.

## 8. Safety & Ethical Considerations
Never truncate command lines or alter forensic evidence during normalization.

## 9. Documentation Updates
Update docs/RND_TRACEABILITY.md for normalization.
