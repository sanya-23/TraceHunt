"""Investigation Reports API endpoints."""

from datetime import datetime
from pathlib import Path
import re
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from tracehunt.api.schemas import ReportGenerateRequest, ReportGenerateResponse
from tracehunt.config import settings
from tracehunt.database import get_db
from tracehunt.exceptions import ReportExportError
from tracehunt.reporting import generate_report

router = APIRouter(prefix="/reports", tags=["Investigation Reports"])


def _sanitize_report_name(name: str) -> str:
    clean = re.sub(r"[^\w\-.]", "_", name)
    return clean.strip("._")


@router.post("/generate", response_model=ReportGenerateResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportGenerateRequest,
    session: Session = Depends(get_db),
) -> ReportGenerateResponse:
    """Generate an executive HTML or machine-readable JSON report with XSS defense."""
    parsed_start = None
    parsed_end = None
    if payload.start_time:
        try:
            parsed_start = datetime.fromisoformat(payload.start_time)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid start_time format: {e}",
            ) from e
    if payload.end_time:
        try:
            parsed_end = datetime.fromisoformat(payload.end_time)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid end_time format: {e}",
            ) from e

    try:
        report_data, file_path = generate_report(
            session=session,
            host=payload.host,
            investigation_id=payload.investigation_id,
            start_time=parsed_start,
            end_time=parsed_end,
            output_format=payload.format,
            title=payload.title,
            analyst_name=payload.analyst_name,
        )

        filename = file_path.name
        download_url = f"/api/v1/reports/{filename}"

        return ReportGenerateResponse(
            report_id=report_data.metadata.report_id,
            format=payload.format.lower(),
            filename=filename,
            download_url=download_url,
            generated_at=report_data.metadata.generated_at,
            total_events=report_data.metrics.total_events,
            total_findings=report_data.metrics.total_findings,
        )
    except ReportExportError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.get("/{report_filename}")
def download_report(report_filename: str) -> FileResponse:
    """Download a generated report file with path traversal protection."""
    if ".." in report_filename or "/" in report_filename or "\\" in report_filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal detected in report filename.",
        )

    safe_name = _sanitize_report_name(report_filename)
    target_path = (settings.REPORTS_DIR / safe_name).resolve()

    if not str(target_path).startswith(str(settings.REPORTS_DIR.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal detected in report filename.",
        )

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file '{report_filename}' not found.",
        )

    if safe_name.endswith(".html"):
        media_type = "text/html; charset=utf-8"
    elif safe_name.endswith(".json"):
        media_type = "application/json"
    elif safe_name.endswith(".docx"):
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif safe_name.endswith(".pdf"):
        media_type = "application/pdf"
    else:
        media_type = "application/octet-stream"
    return FileResponse(
        path=target_path,
        media_type=media_type,
        filename=safe_name,
    )
