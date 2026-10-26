# Skill: JSON & CSV Ingestion and Validation

## 1. Purpose
Ingest and validate endpoint telemetry files, verifying file format, encoding, and size.

## 2. When to Use
When implementing Stage 2 file ingestion endpoints and CLI batch loaders.

## 3. Prerequisites
tracehunt/config.py for MAX_UPLOAD_SIZE_MB; models ready.

## 4. Implementation Steps
1. Check file size against configured limit (e.g. 50MB).
2. Detect encoding (UTF-8, UTF-16, ASCII) and decode safely with error handling.
3. Parse JSON arrays, JSON Lines (jsonl), or CSV rows into raw dictionaries.
4. Store raw payload verbatim in raw_events table with status PENDING.
5. If row fails structural validation, write to ingestion_errors and continue batch.
6. Return IngestionSummary with total, accepted, rejected, and duplicate counts.

## 5. Expected Outputs
tracehunt/ingestion/importer.py, tracehunt/ingestion/validators.py.

## 6. Verification Criteria
Test with valid JSON, CSV, oversized files, corrupted JSON, and mixed encodings.

## 7. Common Failures & Troubleshooting
Crashing on single malformed line; dropping unparseable lines without logging.

## 8. Safety & Ethical Considerations
Prevent zip-bomb or out-of-memory denial of service via strict stream length limits.

## 9. Documentation Updates
Log import test results in docs/TEST_LOG.md.
