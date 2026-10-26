"""Host Investigation Timeline Service.

Provides chronological event aggregation across process creations, terminations,
network connections, logons, and correlated detection findings with deterministic
tie-breaking, multi-dimensional filtering, parameterized text search, and bounded pagination.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from tracehunt.exceptions import ValidationError
from tracehunt.logging_config import get_logger
from tracehunt.models import EndpointEvent, Finding

logger = get_logger("investigation.timeline")

SEVERITY_WEIGHTS: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class FindingSummary:
    """Compact summary of a detection finding attached to an event."""

    id: int
    rule_id: str
    severity: str
    confidence: str
    rationale: str
    matched_fields: dict[str, Any]
    caveats: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineItem:
    """A single normalized chronological entry in the host timeline."""

    id: int
    event_time: datetime
    host: str
    event_id: int
    event_type: str
    user: str | None
    process_id: int | None
    parent_process_id: int | None
    image: str | None
    command_line: str | None
    parent_image: str | None
    parent_command_line: str | None
    ip_address: str | None
    port: int | None
    logon_id: str | None
    logon_type: int | None
    raw_event_id: int | None
    findings: list[FindingSummary] = field(default_factory=list)
    has_detection: bool = False
    max_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["event_time"] = self.event_time.isoformat() if self.event_time else None
        return data


def get_host_timeline(
    session: Session,
    host: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    event_types: list[str] | str | None = None,
    event_ids: list[int] | int | None = None,
    process_id: int | None = None,
    user: str | None = None,
    severity: list[str] | str | None = None,
    has_findings: bool | None = None,
    search_query: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[TimelineItem]:
    """Retrieve chronological endpoint telemetry and correlated findings.

    Guarantees:
    - Chronological ordering by `event_time ASC` with deterministic `id ASC` tie-breaking.
    - Zero duplicate event entries caused by joins (eager-loads correlated findings via selectinload).
    - Multi-field parameterized search without SQL injection risk.
    - Bounded pagination with limits capped at 1000 items.
    """
    if start_time and end_time and start_time > end_time:
        raise ValidationError(
            f"Invalid time range: start_time ({start_time.isoformat()}) is after end_time ({end_time.isoformat()})."
        )

    stmt = select(EndpointEvent).options(
        selectinload(EndpointEvent.findings).selectinload(Finding.rule)
    )

    # 1. Host filter
    if host and host.strip():
        stmt = stmt.where(EndpointEvent.host.ilike(host.strip()))

    # 2. Time range filters
    if start_time:
        stmt = stmt.where(EndpointEvent.event_time >= start_time)
    if end_time:
        stmt = stmt.where(EndpointEvent.event_time <= end_time)

    # 3. Event types filter
    if event_types:
        if isinstance(event_types, str):
            types_list = [t.strip().upper() for t in event_types.split(",") if t.strip()]
        else:
            types_list = [t.strip().upper() for t in event_types if t and t.strip()]
        if types_list:
            stmt = stmt.where(EndpointEvent.event_type.in_(types_list))

    # 4. Event IDs filter
    if event_ids is not None:
        if isinstance(event_ids, int):
            ids_list = [event_ids]
        else:
            ids_list = list(event_ids)
        if ids_list:
            stmt = stmt.where(EndpointEvent.event_id.in_(ids_list))

    # 5. Process ID filter
    if process_id is not None:
        stmt = stmt.where(EndpointEvent.process_id == process_id)

    # 6. User filter
    if user and user.strip():
        stmt = stmt.where(EndpointEvent.user.ilike(f"%{user.strip()}%"))

    # 7. Detection findings filters (using EXISTS subqueries to prevent duplicate rows)
    if severity:
        if isinstance(severity, str):
            sev_list = [s.strip().upper() for s in severity.split(",") if s.strip()]
        else:
            sev_list = [s.strip().upper() for s in severity if s and s.strip()]
        if sev_list:
            stmt = stmt.where(
                EndpointEvent.findings.any(Finding.severity.in_(sev_list))
            )

    if has_findings is True:
        stmt = stmt.where(EndpointEvent.findings.any())
    elif has_findings is False:
        stmt = stmt.where(~EndpointEvent.findings.any())

    # 8. Text search across relevant textual attributes (safe parameterized ilike)
    if search_query and search_query.strip():
        q = f"%{search_query.strip()}%"
        stmt = stmt.where(
            or_(
                EndpointEvent.image.ilike(q),
                EndpointEvent.command_line.ilike(q),
                EndpointEvent.parent_image.ilike(q),
                EndpointEvent.parent_command_line.ilike(q),
                EndpointEvent.user.ilike(q),
                EndpointEvent.ip_address.ilike(q),
            )
        )

    # 9. Deterministic ordering: event_time ASC, id ASC
    stmt = stmt.order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())

    # 10. Bounded pagination
    bounded_limit = max(1, min(limit, 1000))
    stmt = stmt.limit(bounded_limit).offset(offset)

    events = session.scalars(stmt).all()

    timeline_items: list[TimelineItem] = []
    for ev in events:
        findings_summaries: list[FindingSummary] = []
        max_sev: str | None = None
        max_sev_weight = 0

        for f in ev.findings:
            findings_summaries.append(
                FindingSummary(
                    id=f.id,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    confidence=f.confidence,
                    rationale=f.rationale,
                    matched_fields=f.matched_fields or {},
                    caveats=f.caveats,
                )
            )
            weight = SEVERITY_WEIGHTS.get(f.severity.upper(), 0)
            if weight > max_sev_weight:
                max_sev_weight = weight
                max_sev = f.severity.upper()

        item = TimelineItem(
            id=ev.id,
            event_time=ev.event_time,
            host=ev.host,
            event_id=ev.event_id,
            event_type=ev.event_type,
            user=ev.user,
            process_id=ev.process_id,
            parent_process_id=ev.parent_process_id,
            image=ev.image,
            command_line=ev.command_line,
            parent_image=ev.parent_image,
            parent_command_line=ev.parent_command_line,
            ip_address=ev.ip_address,
            port=ev.port,
            logon_id=ev.logon_id,
            logon_type=ev.logon_type,
            raw_event_id=ev.raw_event_id,
            findings=findings_summaries,
            has_detection=bool(findings_summaries),
            max_severity=max_sev,
        )
        timeline_items.append(item)

    return timeline_items


def get_timeline_summary(
    session: Session,
    host: str,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict[str, Any]:
    """Calculate aggregate summary metrics for a host timeline."""
    if not host or not host.strip():
        raise ValidationError("Host must be provided for timeline summary.")

    items = get_host_timeline(
        session=session,
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=1000,
    )

    event_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    total_findings = 0

    for item in items:
        event_counts[item.event_type] = event_counts.get(item.event_type, 0) + 1
        for f in item.findings:
            total_findings += 1
            s = f.severity.upper()
            if s in severity_counts:
                severity_counts[s] += 1

    return {
        "host": host.strip(),
        "total_events": len(items),
        "total_findings": total_findings,
        "event_counts": event_counts,
        "severity_counts": severity_counts,
    }
