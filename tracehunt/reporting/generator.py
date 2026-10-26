"""Investigation Report Generator.

Compiles actual database records into structured ReportData with complete
forensic lineage, case details, audit history, and explicit limitation disclosures.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from tracehunt.exceptions import ReportExportError
from tracehunt.investigation.audit_service import get_case_audit_trail
from tracehunt.investigation.case_service import get_investigation
from tracehunt.investigation.evidence_service import get_case_evidence
from tracehunt.investigation.timeline_service import get_host_timeline
from tracehunt.logging_config import get_logger
from tracehunt.models import EndpointEvent, Finding
from tracehunt.reporting.schema import (
    ReportCase,
    ReportData,
    ReportFinding,
    ReportMetadata,
    ReportMetrics,
    ReportTimelineItem,
)

logger = get_logger("reporting.generator")

STANDARD_LIMITATIONS: list[str] = [
    "Telemetry is derived strictly from imported Sysmon and Windows Security log exports. Endpoint activity occurring outside monitored channels or purged prior to collection is not reflected.",
    "Parent-child execution lineage is reconstructed using deterministic temporal heuristics. Recycled PIDs without preceding termination telemetry or missing parent events are explicitly flagged as UNRESOLVED_PARENT.",
    "Behavioral detection matches represent suspicious heuristic indicators mapped to MITRE ATT&CK techniques; they provide threat hypotheses and require analyst corroboration rather than automated proof of compromise.",
    "Audit trails reflect recorded actions by authenticated or system analyst identifiers within the platform's immutable audit log.",
]


def compile_report_data(
    session: Session,
    host: str | None = None,
    investigation_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    title: str | None = None,
    analyst_name: str | None = None,
) -> ReportData:
    """Compile a complete, factual ReportData object from the database."""
    now_utc = datetime.now(timezone.utc)
    report_id = f"RPT-{now_utc.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    target_host = host.strip() if host and host.strip() else None
    case_obj: ReportCase | None = None

    # 1. Load Investigation Case if requested
    if investigation_id and investigation_id.strip():
        clean_inv_id = investigation_id.strip()
        inv = get_investigation(session, clean_inv_id)
        if not inv:
            raise ReportExportError(f"Investigation case '{clean_inv_id}' not found.")

        # Default host to investigation host if not explicitly given
        if not target_host:
            target_host = inv.host

        evidence_items = get_case_evidence(session, clean_inv_id)
        evidence_dicts = [
            {
                "id": ev.id,
                "sequence_number": ev.sequence_number,
                "finding_id": ev.finding_id,
                "endpoint_event_id": ev.endpoint_event_id,
                "raw_event_id": ev.raw_event_id,
                "notes": ev.notes,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
            for ev in evidence_items
        ]

        audit_records = get_case_audit_trail(clean_inv_id, session)
        audit_dicts = [
            {
                "id": a.id,
                "action": a.action,
                "reviewer": a.reviewer,
                "comment": a.comment,
                "previous_status": a.previous_status,
                "new_status": a.new_status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in audit_records
        ]

        case_obj = ReportCase(
            id=inv.id,
            title=inv.title,
            status=inv.status,
            host=inv.host,
            summary=inv.summary,
            created_at=inv.created_at.isoformat() if inv.created_at else "",
            updated_at=inv.updated_at.isoformat() if inv.updated_at else "",
            evidence_items=evidence_dicts,
            audit_trail=audit_dicts,
        )

    # 2. Query timeline events
    timeline_items = get_host_timeline(
        session=session,
        host=target_host,
        start_time=start_time,
        end_time=end_time,
        limit=500,
    )

    report_timeline: list[ReportTimelineItem] = []
    event_type_counts: dict[str, int] = {}

    for item in timeline_items:
        event_type_counts[item.event_type] = event_type_counts.get(item.event_type, 0) + 1
        report_timeline.append(
            ReportTimelineItem(
                id=item.id,
                event_time=item.event_time.isoformat() if item.event_time else "",
                host=item.host,
                event_type=item.event_type,
                user=item.user,
                process_id=item.process_id,
                image=item.image,
                command_line=item.command_line,
                ip_address=item.ip_address,
                has_detection=item.has_detection,
                max_severity=item.max_severity,
                findings_count=len(item.findings),
            )
        )

    # 3. Query Findings
    finding_stmt = (
        select(Finding)
        .join(Finding.endpoint_event)
        .options(selectinload(Finding.endpoint_event))
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    )
    if target_host:
        finding_stmt = finding_stmt.where(EndpointEvent.host.ilike(target_host))
    if start_time:
        finding_stmt = finding_stmt.where(EndpointEvent.event_time >= start_time)
    if end_time:
        finding_stmt = finding_stmt.where(EndpointEvent.event_time <= end_time)

    db_findings = session.scalars(finding_stmt).all()

    report_findings: list[ReportFinding] = []
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    rules_triggered: set[str] = set()

    for f in db_findings:
        s = f.severity.upper()
        if s in severity_counts:
            severity_counts[s] += 1
        rules_triggered.add(f.rule_id)

        ev = f.endpoint_event
        report_findings.append(
            ReportFinding(
                id=f.id,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                rationale=f.rationale,
                matched_fields=f.matched_fields or {},
                host=ev.host if ev else (target_host or "UNKNOWN"),
                event_time=ev.event_time.isoformat() if ev and ev.event_time else None,
                process_image=ev.image if ev else None,
                command_line=ev.command_line if ev else None,
                caveats=f.caveats,
            )
        )

    # 4. Assemble Report Metadata & Metrics
    metadata = ReportMetadata(
        report_id=report_id,
        generated_at=now_utc.isoformat(),
        report_type="INVESTIGATION_EXECUTIVE_SUMMARY" if case_obj else "HOST_THREAT_SUMMARY",
        host=target_host,
        investigation_id=investigation_id,
        time_range_start=start_time.isoformat() if start_time else None,
        time_range_end=end_time.isoformat() if end_time else None,
        title=title.strip() if title and title.strip() else (case_obj.title if case_obj else f"Endpoint Threat Analysis: {target_host or 'Enterprise Network'}"),
        analyst_name=analyst_name.strip() if analyst_name and analyst_name.strip() else "analyst_ui",
    )

    metrics = ReportMetrics(
        total_events=len(report_timeline),
        total_findings=len(report_findings),
        severity_counts=severity_counts,
        event_type_counts=event_type_counts,
        detection_rules_triggered=sorted(rules_triggered),
    )

    logger.info(
        f"Compiled report '{report_id}' for host '{target_host}': {len(report_timeline)} events, "
        f"{len(report_findings)} findings."
    )

    return ReportData(
        metadata=metadata,
        metrics=metrics,
        case=case_obj,
        findings=report_findings,
        timeline=report_timeline,
        limitations=STANDARD_LIMITATIONS,
    )
