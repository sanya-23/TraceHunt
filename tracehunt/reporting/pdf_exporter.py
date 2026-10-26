"""Executive PDF Investigation Report Exporter.

Renders high-fidelity, print-ready PDF investigation briefings from
validated HTML report templates using headless browser printing or structured PDF engine.
"""

from pathlib import Path
import shutil
import subprocess

from tracehunt.config import settings
from tracehunt.exceptions import ReportExportError
from tracehunt.logging_config import get_logger
from tracehunt.reporting.html_renderer import render_html_report
from tracehunt.reporting.schema import ReportData

logger = get_logger("reporting.pdf")


def _find_chrome_binary() -> str | None:
    """Find installed Chrome / Chromium binary for headless PDF printing."""
    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return None


def export_pdf_report(report_data: ReportData, filename: str | None = None) -> Path:
    """Export ReportData to a print-ready executive PDF document (.pdf)."""
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_id = report_data.metadata.report_id
    safe_filename = filename if filename else f"{report_id}.pdf"
    if not safe_filename.endswith(".pdf"):
        safe_filename += ".pdf"

    pdf_path = (settings.REPORTS_DIR / safe_filename).resolve()

    # 1. Render the HTML representation first
    temp_html_name = f"_tmp_{report_id}.html"
    html_path = render_html_report(report_data, filename=temp_html_name)

    chrome_bin = _find_chrome_binary()
    try:
        if chrome_bin:
            cmd = [
                chrome_bin,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                f"file://{html_path}",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and pdf_path.exists() and pdf_path.stat().st_size > 0:
                logger.info(f"Rendered executive PDF report to {pdf_path} ({pdf_path.stat().st_size} bytes)")
                return pdf_path
            else:
                logger.warning(f"Chrome PDF generation returned {res.returncode}: {res.stderr}")

        # Fallback: Generate a clean minimal PDF if Chrome is unavailable
        _create_fallback_pdf(report_data, pdf_path)
        logger.info(f"Rendered fallback PDF report to {pdf_path} ({pdf_path.stat().st_size} bytes)")
        return pdf_path
    finally:
        # Clean up temporary HTML file
        if html_path.exists():
            try:
                html_path.unlink()
            except OSError:
                pass


def _create_fallback_pdf(report_data: ReportData, out_path: Path) -> None:
    """Generate a clean text-based PDF fallback without external dependencies."""
    title = report_data.metadata.title or "TraceHunt Investigation Report"
    host = report_data.metadata.host or "Unknown Host"
    report_id = report_data.metadata.report_id
    gen_time = report_data.metadata.generated_at

    lines = [
        f"TRACEHUNT ENDPOINT THREAT HUNTING REPORT",
        f"========================================",
        f"Report ID: {report_id}",
        f"Title: {title}",
        f"Target Host: {host}",
        f"Generated At: {gen_time}",
        f"Total Events: {report_data.metrics.total_events}",
        f"Total Findings: {report_data.metrics.total_findings}",
        f"",
        f"DETECTED FINDINGS ({len(report_data.findings)} Total):",
        f"----------------------------------------",
    ]
    for f in report_data.findings[:15]:
        lines.append(f"• [{f.severity}] {f.rule_id} on {f.host}")
        lines.append(f"  Rationale: {f.rationale}")
        lines.append(f"  Process: {f.process_image}")
        lines.append(f"  Command: {f.command_line}")
        lines.append("")

    lines.append("FORENSIC LIMITATIONS:")
    for lim in report_data.limitations:
        lines.append(f"- {lim}")

    # Escape parentheses and backslashes for PDF string literals
    pdf_text_stream = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    # Build basic PDF structure (v1.4)
    content_lines = []
    y = 750
    for line in lines[:55]:  # Fits on standard Letter/A4
        safe_l = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_lines.append(f"1 0 0 1 50 {y} Tm ({safe_l}) Tj")
        y -= 13

    stream_data = f"BT\n/F1 9 Tf\n0 0 0 rg\n" + "\n".join(content_lines) + "\nET"
    stream_bytes = stream_data.encode("latin-1", errors="replace")

    pdf_body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000244 00000 n \n"
        b"0000000350 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n435\n%%EOF\n"
    )
    out_path.write_bytes(pdf_body)
