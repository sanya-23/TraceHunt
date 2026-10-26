"""TraceHunt Telemetry Ingestion Package.

Provides file validation, batch importing, deduplication, and schema normalization
for Windows Sysmon and Windows Security event telemetry exports.
"""

from tracehunt.ingestion.importer import (
    import_telemetry_file,
    import_telemetry_content,
    extract_records,
)
from tracehunt.ingestion.normalizer import (
    normalize_event,
    parse_timestamp,
    parse_int_field,
    SUPPORTED_EVENT_IDS,
)
from tracehunt.ingestion.validators import (
    validate_input_file,
    detect_encoding,
    detect_file_format,
)
from tracehunt.ingestion.dedup import (
    compute_sha256_fingerprint,
    compute_event_fingerprint,
    IdempotencyManager,
)

__all__ = [
    "import_telemetry_file",
    "import_telemetry_content",
    "extract_records",
    "normalize_event",
    "parse_timestamp",
    "parse_int_field",
    "SUPPORTED_EVENT_IDS",
    "validate_input_file",
    "detect_encoding",
    "detect_file_format",
    "compute_sha256_fingerprint",
    "compute_event_fingerprint",
    "IdempotencyManager",
]
