"""JSON Report Exporter.

Serializes factual ReportData to machine-readable JSON with path traversal
protection and forensic integrity.
"""

import json
from pathlib import Path
import re

from tracehunt.config import settings
from tracehunt.exceptions import ReportExportError
from tracehunt.logging_config import get_logger
from tracehunt.reporting.schema import ReportData

logger = get_logger("reporting.json")


def _sanitize_filename(name: str) -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    clean = re.sub(r"[^\w\-.]", "_", name)
    clean = clean.strip("._")
    if not clean:
        clean = "tracehunt_report"
    return clean


def export_json_report(report_data: ReportData, filename: str | None = None) -> Path:
    """Serialize ReportData to a JSON file in the configured reports directory."""
    settings.ensure_directories()

    default_name = f"{report_data.metadata.report_id}.json"
    raw_name = filename or default_name
    safe_name = _sanitize_filename(raw_name)
    if not safe_name.endswith(".json"):
        safe_name += ".json"

    target_path = (settings.REPORTS_DIR / safe_name).resolve()

    # Path traversal protection
    if not str(target_path).startswith(str(settings.REPORTS_DIR.resolve())):
        raise ReportExportError("Path traversal detected in report filename.")

    try:
        report_dict = report_data.to_dict()
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        logger.info(f"Exported JSON report to {target_path}")
        return target_path
    except Exception as e:
        logger.error(f"Failed to export JSON report: {e}", exc_info=True)
        raise ReportExportError(f"Failed to export JSON report: {e}") from e
