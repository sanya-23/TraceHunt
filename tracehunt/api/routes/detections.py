"""Detection Rules and Findings API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from tracehunt.api.schemas import (
    DetectionRuleSchema,
    EvaluateDetectionsRequest,
    EvaluateDetectionsResponse,
    FindingDetailSchema,
    RuleToggleRequest,
)
from tracehunt.database import get_db
from tracehunt.detection.engine import DetectionEngine
from tracehunt.models import DetectionRule, EndpointEvent, Finding

router = APIRouter(prefix="/detections", tags=["Behavioral Detections & Findings"])


@router.get("/rules", response_model=list[DetectionRuleSchema])
def list_rules(session: Session = Depends(get_db)) -> list[DetectionRuleSchema]:
    """List all registered behavioral detection rules with severity and MITRE mappings."""
    stmt = select(DetectionRule).order_by(DetectionRule.id.asc())
    rules = session.scalars(stmt).all()
    return [
        DetectionRuleSchema(
            id=r.id,
            name=r.name,
            version=r.version,
            severity=r.severity,
            confidence_level=r.confidence_level,
            mitre_technique=r.mitre_technique,
            enabled=r.enabled,
            description=r.description,
        )
        for r in rules
    ]


@router.post("/rules/{rule_id}/toggle", response_model=DetectionRuleSchema)
def toggle_rule(
    rule_id: str,
    payload: RuleToggleRequest,
    session: Session = Depends(get_db),
) -> DetectionRuleSchema:
    """Enable or disable a specific detection rule."""
    rule = session.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    rule.enabled = payload.enabled
    session.flush()

    return DetectionRuleSchema(
        id=rule.id,
        name=rule.name,
        version=rule.version,
        severity=rule.severity,
        confidence_level=rule.confidence_level,
        mitre_technique=rule.mitre_technique,
        enabled=rule.enabled,
        description=rule.description,
    )


@router.post("/evaluate", response_model=EvaluateDetectionsResponse)
def evaluate_detections(
    payload: EvaluateDetectionsRequest,
    session: Session = Depends(get_db),
) -> EvaluateDetectionsResponse:
    """Execute behavioral detection rules across stored endpoint events.

    Findings are generated explainably and persisted idempotently without duplication.
    """
    stmt = select(EndpointEvent)
    if payload.host:
        stmt = stmt.where(EndpointEvent.host.ilike(payload.host.strip()))
    stmt = stmt.order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())

    events = session.scalars(stmt).all()

    engine = DetectionEngine()
    summary = engine.evaluate_events(events=list(events), session=session, persist=True)

    return EvaluateDetectionsResponse(
        evaluated_events=summary.events_examined,
        active_rules=summary.rules_evaluated,
        findings_generated=summary.findings_created,
        duplicates_skipped=summary.duplicates_skipped,
        errors=summary.errors,
    )


@router.get("/findings", response_model=list[FindingDetailSchema])
def list_findings(
    host: str | None = Query(None, description="Filter findings by host"),
    rule_id: str | None = Query(None, description="Filter findings by rule ID"),
    severity: str | None = Query(None, description="Filter findings by severity"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> list[FindingDetailSchema]:
    """List detection findings with associated event context."""
    stmt = (
        select(Finding)
        .join(Finding.endpoint_event)
        .options(selectinload(Finding.endpoint_event))
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    )

    if host:
        stmt = stmt.where(EndpointEvent.host.ilike(host.strip()))
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id.strip())
    if severity:
        stmt = stmt.where(Finding.severity == severity.strip().upper())

    stmt = stmt.limit(limit).offset(offset)
    findings = session.scalars(stmt).all()

    results: list[FindingDetailSchema] = []
    for f in findings:
        ev = f.endpoint_event
        results.append(
            FindingDetailSchema(
                id=f.id,
                rule_id=f.rule_id,
                endpoint_event_id=f.endpoint_event_id,
                severity=f.severity,
                confidence=f.confidence,
                rationale=f.rationale,
                matched_fields=f.matched_fields or {},
                caveats=f.caveats,
                created_at=f.created_at.isoformat() if f.created_at else "",
                host=ev.host if ev else None,
                event_time=ev.event_time.isoformat() if ev and ev.event_time else None,
                process_image=ev.image if ev else None,
                command_line=ev.command_line if ev else None,
            )
        )
    return results


@router.get("/findings/{finding_id}", response_model=FindingDetailSchema)
def get_finding(finding_id: int, session: Session = Depends(get_db)) -> FindingDetailSchema:
    """Retrieve detailed explainable evidence and event context for a specific finding."""
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.endpoint_event))
    )
    finding = session.scalars(stmt).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding ID {finding_id} not found.",
        )

    ev = finding.endpoint_event
    return FindingDetailSchema(
        id=finding.id,
        rule_id=finding.rule_id,
        endpoint_event_id=finding.endpoint_event_id,
        severity=finding.severity,
        confidence=finding.confidence,
        rationale=finding.rationale,
        matched_fields=finding.matched_fields or {},
        caveats=finding.caveats,
        created_at=finding.created_at.isoformat() if finding.created_at else "",
        host=ev.host if ev else None,
        event_time=ev.event_time.isoformat() if ev and ev.event_time else None,
        process_image=ev.image if ev else None,
        command_line=ev.command_line if ev else None,
    )
