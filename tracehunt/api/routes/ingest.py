"""Telemetry Ingestion API endpoint."""

import os
from pathlib import Path
import tempfile
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from tracehunt.api.schemas import IngestionResponse
from tracehunt.config import settings
from tracehunt.database import get_db
from tracehunt.exceptions import IngestionError, ValidationError
from tracehunt.ingestion.importer import import_telemetry_file
from tracehunt.logging_config import get_logger

logger = get_logger("api.ingest")
router = APIRouter(tags=["Telemetry Ingestion"])

SUPPORTED_EXTENSIONS = {".json", ".jsonl", ".csv"}


@router.post(
    "/ingest",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest Windows Sysmon or Security telemetry file",
)
def ingest_telemetry_file(
    file: UploadFile = File(..., description="Telemetry export file (.json, .jsonl, .csv)"),
    session: Session = Depends(get_db),
) -> IngestionResponse:
    """Ingest, validate, normalize, deduplicate, and persist endpoint telemetry.

    Supports JSON array, JSON Lines, and CSV formats.
    Re-importing identical records is completely idempotent.
    """
    filename = file.filename or "unknown_file"
    ext = Path(filename).suffix.lower()

    if ext == ".evtx":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Native binary EVTX files are not directly supported. "
                "Please export EVTX logs to JSON, JSONL, or CSV format before importing."
            ),
        )

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Supported formats: {sorted(SUPPORTED_EXTENSIONS)}",
        )

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    bytes_read = 0

    # Write uploaded stream to temporary file safely
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
        tmp_path = Path(tmp_file.name)
        try:
            while chunk := file.file.read(1024 * 1024):
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum allowed limit of {settings.MAX_UPLOAD_SIZE_MB} MB.",
                    )
                tmp_file.write(chunk)
        except Exception:
            tmp_file.close()
            if tmp_path.exists():
                os.unlink(tmp_path)
            raise

    try:
        summary = import_telemetry_file(tmp_path, session)
        return IngestionResponse(
            source_file=filename,
            total_records=summary.records_read,
            successful_records=summary.events_normalized,
            duplicates_skipped=summary.duplicates_skipped,
            errors_encountered=summary.records_rejected,
            duration_seconds=summary.duration_seconds,
            message=(
                f"Successfully ingested {summary.events_normalized} events from {filename} "
                f"({summary.duplicates_skipped} duplicates skipped, {summary.records_rejected} errors isolated)."
            ),
        )
    except IngestionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        ) from e
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=e.message,
        ) from e
    finally:
        if tmp_path.exists():
            os.unlink(tmp_path)
