"""Host Explorer, Process Tree, and Timeline API endpoints."""

from datetime import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tracehunt.api.schemas import (
    FindingSummarySchema,
    HostMetricsResponse,
    HostSummary,
    ProcessTreeResponse,
    TimelineItemSchema,
)
from tracehunt.database import get_db
from tracehunt.exceptions import ValidationError
from tracehunt.graph.tree_service import (
    get_host_process_trees,
    get_process_lineage,
)
from tracehunt.investigation.timeline_service import (
    get_host_timeline,
    get_timeline_summary,
)
from tracehunt.models import EndpointEvent, Finding

router = APIRouter(prefix="/hosts", tags=["Hosts & Telemetry Exploration"])


@router.get("", response_model=list[HostSummary])
def list_hosts(session: Session = Depends(get_db)) -> list[HostSummary]:
    """List all distinct endpoint hosts with event counts and time ranges."""
    stmt = (
        select(
            EndpointEvent.host,
            func.count(EndpointEvent.id).label("event_count"),
            func.min(EndpointEvent.event_time).label("first_seen"),
            func.max(EndpointEvent.event_time).label("last_seen"),
        )
        .group_by(EndpointEvent.host)
        .order_by(EndpointEvent.host.asc())
    )
    rows = session.execute(stmt).all()

    # Pre-fetch finding counts per host
    finding_counts_stmt = (
        select(EndpointEvent.host, func.count(Finding.id))
        .join(Finding, Finding.endpoint_event_id == EndpointEvent.id)
        .group_by(EndpointEvent.host)
    )
    finding_counts = dict(session.execute(finding_counts_stmt).all())

    summaries: list[HostSummary] = []
    for r in rows:
        summaries.append(
            HostSummary(
                host=r.host,
                event_count=r.event_count,
                finding_count=finding_counts.get(r.host, 0),
                first_seen=r.first_seen.isoformat() if r.first_seen else None,
                last_seen=r.last_seen.isoformat() if r.last_seen else None,
            )
        )
    return summaries


@router.get("/{host}/metrics", response_model=HostMetricsResponse)
def get_host_metrics(host: str, session: Session = Depends(get_db)) -> HostMetricsResponse:
    """Retrieve aggregate telemetry and severity metrics for a host."""
    try:
        summary = get_timeline_summary(session, host)
        return HostMetricsResponse(
            host=summary["host"],
            total_events=summary["total_events"],
            total_findings=summary["total_findings"],
            event_counts=summary["event_counts"],
            severity_counts=summary["severity_counts"],
        )
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.get("/{host}/timeline", response_model=list[TimelineItemSchema])
def query_host_timeline(
    host: str,
    start_time: datetime | None = Query(None, description="Start of time window (ISO 8601 UTC)"),
    end_time: datetime | None = Query(None, description="End of time window (ISO 8601 UTC)"),
    event_types: list[str] | None = Query(None, description="Filter by event types"),
    event_ids: list[int] | None = Query(None, description="Filter by Windows event IDs"),
    process_id: int | None = Query(None, description="Filter by process ID"),
    user: str | None = Query(None, description="Filter by username substring"),
    severity: list[str] | None = Query(None, description="Filter by finding severity"),
    has_findings: bool | None = Query(None, description="Filter only events with findings"),
    search: str | None = Query(None, description="Parameterized text search query"),
    limit: int = Query(100, ge=1, le=1000, description="Page limit (max 1000)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    session: Session = Depends(get_db),
) -> list[TimelineItemSchema]:
    """Retrieve chronological endpoint telemetry and correlated findings for a host."""
    try:
        items = get_host_timeline(
            session=session,
            host=host,
            start_time=start_time,
            end_time=end_time,
            event_types=event_types,
            event_ids=event_ids,
            process_id=process_id,
            user=user,
            severity=severity,
            has_findings=has_findings,
            search_query=search,
            limit=limit,
            offset=offset,
        )
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e

    results: list[TimelineItemSchema] = []
    for item in items:
        finding_schemas = [
            FindingSummarySchema(
                id=f.id,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                rationale=f.rationale,
                matched_fields=f.matched_fields,
                caveats=f.caveats,
            )
            for f in item.findings
        ]
        results.append(
            TimelineItemSchema(
                id=item.id,
                event_time=item.event_time.isoformat() if item.event_time else "",
                host=item.host,
                event_id=item.event_id,
                event_type=item.event_type,
                user=item.user,
                process_id=item.process_id,
                parent_process_id=item.parent_process_id,
                image=item.image,
                command_line=item.command_line,
                parent_image=item.parent_image,
                parent_command_line=item.parent_command_line,
                ip_address=item.ip_address,
                port=item.port,
                logon_id=item.logon_id,
                logon_type=item.logon_type,
                raw_event_id=item.raw_event_id,
                findings=finding_schemas,
                has_detection=item.has_detection,
                max_severity=item.max_severity,
            )
        )
    return results


@router.get("/{host}/tree", response_model=ProcessTreeResponse)
def get_host_trees(host: str, session: Session = Depends(get_db)) -> ProcessTreeResponse:
    """Retrieve the reconstructed parent-child execution forest for a host."""
    trees = get_host_process_trees(host, session)
    total_procs = sum(t.get("process_count", 0) for t in trees)
    unresolved_count = sum(1 for t in trees if t.get("relationship_type") == "UNRESOLVED_PARENT")

    return ProcessTreeResponse(
        host=host,
        total_trees=len(trees),
        total_processes=total_procs,
        unresolved_parents_count=unresolved_count,
        trees=trees,
    )


@router.get("/{host}/processes/{process_id}/lineage", response_model=list[dict[str, Any]])
def get_process_ancestry(
    host: str,
    process_id: int,
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Retrieve root-to-leaf process execution lineage for a specific process ID."""
    target_event = session.scalars(
        select(EndpointEvent)
        .where(
            EndpointEvent.host == host,
            (EndpointEvent.process_id == process_id) | (EndpointEvent.id == process_id),
        )
        .order_by(EndpointEvent.event_time.desc())
    ).first()

    if not target_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Process ID {process_id} not found on host '{host}'.",
        )

    lineage = get_process_lineage(target_event.id, session)
    if not lineage:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Process lineage for ID {process_id} not found on host '{host}'.",
        )
    return lineage

