"""Health and system status API endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from tracehunt.api.schemas import HealthResponse, StatusResponse
from tracehunt.config import settings
from tracehunt.database import get_db
from tracehunt.models import (
    AnalystAudit,
    Base,
    EndpointEvent,
    Finding,
    Investigation,
    RawEvent,
)

router = APIRouter(tags=["System Health & Status"])


@router.get("/health", response_model=HealthResponse)
def get_health(session: Session = Depends(get_db)) -> HealthResponse:
    """Verify application operational status and database connectivity."""
    db_connected = False
    try:
        session.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    table_names = sorted(Base.metadata.tables.keys())

    return HealthResponse(
        status="ok" if db_connected else "degraded",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
        database_connected=db_connected,
        tables_verified=table_names,
    )


@router.get("/status", response_model=StatusResponse)
def get_system_status(session: Session = Depends(get_db)) -> StatusResponse:
    """Retrieve dynamic global metrics across telemetry, detections, and cases."""
    raw_count = session.scalar(select(func.count(RawEvent.id))) or 0
    endpoint_count = session.scalar(select(func.count(EndpointEvent.id))) or 0
    host_count = session.scalar(select(func.count(func.distinct(EndpointEvent.host)))) or 0
    finding_count = session.scalar(select(func.count(Finding.id))) or 0
    inv_count = session.scalar(select(func.count(Investigation.id))) or 0
    open_inv_count = (
        session.scalar(
            select(func.count(Investigation.id)).where(Investigation.status == "OPEN")
        )
        or 0
    )
    audit_count = session.scalar(select(func.count(AnalystAudit.id))) or 0

    return StatusResponse(
        total_raw_events=raw_count,
        total_endpoint_events=endpoint_count,
        total_hosts=host_count,
        total_findings=finding_count,
        total_investigations=inv_count,
        open_investigations=open_inv_count,
        total_audit_records=audit_count,
    )
