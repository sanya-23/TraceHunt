"""TraceHunt Reporting Package.

Provides structured, reproducible JSON, executive HTML, Microsoft Word (.docx),
and print-ready PDF report generation with strict XSS sanitization and forensic traceability.
"""

from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from tracehunt.exceptions import ReportExportError
from tracehunt.reporting.docx_exporter import export_docx_report
from tracehunt.reporting.generator import compile_report_data
from tracehunt.reporting.html_renderer import render_html_report
from tracehunt.reporting.json_exporter import export_json_report
from tracehunt.reporting.pdf_exporter import export_pdf_report
from tracehunt.reporting.schema import (
    ReportCase,
    ReportData,
    ReportFinding,
    ReportMetadata,
    ReportMetrics,
    ReportTimelineItem,
)

SUPPORTED_FORMATS = {"html", "json", "docx", "pdf"}


def generate_report(
    session: Session,
    host: str | None = None,
    investigation_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    output_format: str = "html",
    filename: str | None = None,
    title: str | None = None,
    analyst_name: str | None = None,
    formats: list[str] | None = None,
) -> tuple[ReportData, Path] | dict[str, Path]:
    """Generate and export an investigation report in HTML, JSON, DOCX, or PDF format.

    - If `formats` is a list (e.g. `['html', 'docx', 'pdf']`), exports all requested formats
      and returns a dictionary mapping format name to absolute Path: `{'html': path1, ...}`.
    - Otherwise, generates the single format in `output_format` and returns `(ReportData, Path)`.
    """
    report_data = compile_report_data(
        session=session,
        host=host,
        investigation_id=investigation_id,
        start_time=start_time,
        end_time=end_time,
        title=title,
        analyst_name=analyst_name,
    )

    # Multi-format generation mode (e.g. from Dashboard or batch workflows)
    if formats is not None:
        clean_fmts = [f.strip().lower() for f in formats if f and f.strip()]
        if not clean_fmts:
            raise ReportExportError("At least one report format must be specified.")
        for fmt in clean_fmts:
            if fmt not in SUPPORTED_FORMATS:
                raise ReportExportError(
                    f"Unsupported report format '{fmt}'. Use one of: {sorted(SUPPORTED_FORMATS)}."
                )

        generated_files: dict[str, Path] = {}
        for fmt in clean_fmts:
            if fmt == "json":
                generated_files["json"] = export_json_report(report_data, filename=filename)
            elif fmt == "html":
                generated_files["html"] = render_html_report(report_data, filename=filename)
            elif fmt == "docx":
                generated_files["docx"] = export_docx_report(report_data, filename=filename)
            elif fmt == "pdf":
                generated_files["pdf"] = export_pdf_report(report_data, filename=filename)

        return generated_files

    # Single-format generation mode (default)
    clean_fmt = (output_format or "html").strip().lower()
    if clean_fmt not in SUPPORTED_FORMATS:
        raise ReportExportError(
            f"Unsupported report format '{output_format}'. Use one of: {sorted(SUPPORTED_FORMATS)}."
        )

    if clean_fmt == "json":
        path = export_json_report(report_data, filename=filename)
    elif clean_fmt == "docx":
        path = export_docx_report(report_data, filename=filename)
    elif clean_fmt == "pdf":
        path = export_pdf_report(report_data, filename=filename)
    else:
        path = render_html_report(report_data, filename=filename)

    return report_data, path


__all__ = [
    "generate_report",
    "compile_report_data",
    "render_html_report",
    "export_json_report",
    "export_docx_report",
    "export_pdf_report",
    "ReportData",
    "ReportMetadata",
    "ReportMetrics",
    "ReportFinding",
    "ReportTimelineItem",
    "ReportCase",
    "SUPPORTED_FORMATS",
]
