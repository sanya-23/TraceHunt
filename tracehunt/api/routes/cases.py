"""Investigation Cases, Evidence, and Audit API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from tracehunt.api.schemas import (
    AuditEntryResponse,
    CaseCloseRequest,
    CaseCreateRequest,
    CaseNoteRequest,
    CaseReopenRequest,
    CaseResponse,
    CaseTransitionRequest,
    CaseUpdateRequest,
    EvidenceAttachRequest,
    EvidenceResponse,
)
from tracehunt.database import get_db
from tracehunt.exceptions import CaseManagementError
from tracehunt.investigation.audit_service import (
    get_case_audit_trail,
    get_recent_audit_logs,
)
from tracehunt.investigation.case_service import (
    add_case_note,
    close_investigation,
    create_investigation,
    get_investigation,
    list_investigations,
    reopen_investigation,
    transition_case_status,
    update_investigation,
)
from tracehunt.investigation.evidence_service import (
    attach_evidence,
    get_case_evidence,
    remove_evidence,
)

router = APIRouter(tags=["Investigation Cases & Evidence Management"])


@router.post("/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreateRequest,
    session: Session = Depends(get_db),
) -> CaseResponse:
    """Create a new threat hunting case with optional initial findings and audit trail."""
    try:
        case = create_investigation(
            session=session,
            title=payload.title,
            host=payload.host,
            summary=payload.summary,
            investigation_id=payload.investigation_id,
            reviewer=payload.reviewer,
            initial_status=payload.initial_status,
            initial_finding_ids=payload.initial_finding_ids,
        )
        return CaseResponse(
            id=case.id,
            title=case.title,
            status=case.status,
            host=case.host,
            summary=case.summary,
            created_at=case.created_at.isoformat() if case.created_at else "",
            updated_at=case.updated_at.isoformat() if case.updated_at else "",
            evidence_count=len(case.evidence_items) if hasattr(case, "evidence_items") else 0,
            audit_count=len(case.audit_records) if hasattr(case, "audit_records") else 1,
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.get("/cases", response_model=list[CaseResponse])
def list_cases(
    status_filter: str | None = Query(None, alias="status"),
    host: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> list[CaseResponse]:
    """List investigation cases with pagination and status/host filters."""
    try:
        cases = list_investigations(
            session=session,
            status=status_filter,
            host=host,
            limit=limit,
            offset=offset,
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e

    return [
        CaseResponse(
            id=c.id,
            title=c.title,
            status=c.status,
            host=c.host,
            summary=c.summary,
            created_at=c.created_at.isoformat() if c.created_at else "",
            updated_at=c.updated_at.isoformat() if c.updated_at else "",
            evidence_count=len(c.evidence_items) if hasattr(c, "evidence_items") else 0,
            audit_count=len(c.audit_records) if hasattr(c, "audit_records") else 0,
        )
        for c in cases
    ]


@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, session: Session = Depends(get_db)) -> CaseResponse:
    """Retrieve details for a specific investigation case."""
    case = get_investigation(session, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation case '{case_id}' not found.",
        )
    return CaseResponse(
        id=case.id,
        title=case.title,
        status=case.status,
        host=case.host,
        summary=case.summary,
        created_at=case.created_at.isoformat() if case.created_at else "",
        updated_at=case.updated_at.isoformat() if case.updated_at else "",
        evidence_count=len(case.evidence_items) if hasattr(case, "evidence_items") else 0,
        audit_count=len(case.audit_records) if hasattr(case, "audit_records") else 0,
    )


@router.patch("/cases/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    session: Session = Depends(get_db),
) -> CaseResponse:
    """Update mutable investigation details (title, summary) and record audit entry."""
    try:
        case = update_investigation(
            session=session,
            investigation_id=case_id,
            title=payload.title,
            summary=payload.summary,
            reviewer=payload.reviewer,
        )
        return CaseResponse(
            id=case.id,
            title=case.title,
            status=case.status,
            host=case.host,
            summary=case.summary,
            created_at=case.created_at.isoformat() if case.created_at else "",
            updated_at=case.updated_at.isoformat() if case.updated_at else "",
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.post("/cases/{case_id}/transition", response_model=CaseResponse)
def transition_status(
    case_id: str,
    payload: CaseTransitionRequest,
    session: Session = Depends(get_db),
) -> CaseResponse:
    """Transition case status adhering to valid state machine transitions."""
    try:
        case = transition_case_status(
            session=session,
            investigation_id=case_id,
            new_status=payload.new_status,
            reviewer=payload.reviewer,
            rationale=payload.rationale,
        )
        return CaseResponse(
            id=case.id,
            title=case.title,
            status=case.status,
            host=case.host,
            summary=case.summary,
            created_at=case.created_at.isoformat() if case.created_at else "",
            updated_at=case.updated_at.isoformat() if case.updated_at else "",
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.post("/cases/{case_id}/close", response_model=CaseResponse)
def close_case(
    case_id: str,
    payload: CaseCloseRequest,
    session: Session = Depends(get_db),
) -> CaseResponse:
    """Close an investigation with mandatory FALSE_POSITIVE or TRUE_POSITIVE rationale."""
    try:
        case = close_investigation(
            session=session,
            investigation_id=case_id,
            disposition=payload.disposition,
            reviewer=payload.reviewer,
            rationale=payload.rationale,
        )
        return CaseResponse(
            id=case.id,
            title=case.title,
            status=case.status,
            host=case.host,
            summary=case.summary,
            created_at=case.created_at.isoformat() if case.created_at else "",
            updated_at=case.updated_at.isoformat() if case.updated_at else "",
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.post("/cases/{case_id}/reopen", response_model=CaseResponse)
def reopen_case(
    case_id: str,
    payload: CaseReopenRequest,
    session: Session = Depends(get_db),
) -> CaseResponse:
    """Reopen a closed case back to OPEN status with mandatory reopening rationale."""
    try:
        case = reopen_investigation(
            session=session,
            investigation_id=case_id,
            reviewer=payload.reviewer,
            rationale=payload.rationale,
        )
        return CaseResponse(
            id=case.id,
            title=case.title,
            status=case.status,
            host=case.host,
            summary=case.summary,
            created_at=case.created_at.isoformat() if case.created_at else "",
            updated_at=case.updated_at.isoformat() if case.updated_at else "",
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.post("/cases/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    case_id: str,
    payload: CaseNoteRequest,
    session: Session = Depends(get_db),
) -> dict[str, str]:
    """Append an analyst note to the case's immutable audit history."""
    try:
        add_case_note(
            session=session,
            investigation_id=case_id,
            note=payload.note,
            reviewer=payload.reviewer,
        )
        return {"message": "Analyst note recorded successfully in audit trail."}
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceResponse])
def list_case_evidence(case_id: str, session: Session = Depends(get_db)) -> list[EvidenceResponse]:
    """Retrieve all evidence attached to an investigation, sorted by sequence number."""
    evidence = get_case_evidence(session, case_id)
    return [
        EvidenceResponse(
            id=ev.id,
            investigation_id=ev.investigation_id,
            finding_id=ev.finding_id,
            endpoint_event_id=ev.endpoint_event_id,
            raw_event_id=ev.raw_event_id,
            sequence_number=ev.sequence_number,
            notes=ev.notes,
            created_at=ev.created_at.isoformat() if ev.created_at else "",
        )
        for ev in evidence
    ]


@router.post("/cases/{case_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
def attach_case_evidence(
    case_id: str,
    payload: EvidenceAttachRequest,
    session: Session = Depends(get_db),
) -> EvidenceResponse:
    """Attach a finding, endpoint event, or raw event to a case with boundary validation."""
    try:
        ev = attach_evidence(
            session=session,
            investigation_id=case_id,
            finding_id=payload.finding_id,
            endpoint_event_id=payload.endpoint_event_id,
            raw_event_id=payload.raw_event_id,
            notes=payload.notes,
            reviewer=payload.reviewer,
            allow_cross_host=payload.allow_cross_host,
        )
        return EvidenceResponse(
            id=ev.id,
            investigation_id=ev.investigation_id,
            finding_id=ev.finding_id,
            endpoint_event_id=ev.endpoint_event_id,
            raw_event_id=ev.raw_event_id,
            sequence_number=ev.sequence_number,
            notes=ev.notes,
            created_at=ev.created_at.isoformat() if ev.created_at else "",
        )
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.delete("/cases/{case_id}/evidence/{evidence_id}", status_code=status.HTTP_200_OK)
def remove_case_evidence(
    case_id: str,
    evidence_id: int,
    reviewer: str = Query("system_analyst"),
    reason: str | None = Query(None),
    session: Session = Depends(get_db),
) -> dict[str, str]:
    """Remove an evidence link from a case without modifying or deleting underlying telemetry."""
    try:
        remove_evidence(
            session=session,
            investigation_id=case_id,
            evidence_id=evidence_id,
            reviewer=reviewer,
            reason=reason,
        )
        return {"message": f"Evidence link #{evidence_id} removed successfully."}
    except CaseManagementError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e


@router.get("/cases/{case_id}/audit", response_model=list[AuditEntryResponse])
def list_case_audit(case_id: str, session: Session = Depends(get_db)) -> list[AuditEntryResponse]:
    """Retrieve chronological audit trail for an investigation case."""
    trail = get_case_audit_trail(case_id, session)
    return [
        AuditEntryResponse(
            id=a.id,
            investigation_id=a.investigation_id,
            action=a.action,
            reviewer=a.reviewer,
            comment=a.comment,
            previous_status=a.previous_status,
            new_status=a.new_status,
            created_at=a.created_at.isoformat() if a.created_at else "",
        )
        for a in trail
    ]


@router.get("/audit", response_model=list[AuditEntryResponse], tags=["Analyst Audit Trail"])
def list_recent_audit(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> list[AuditEntryResponse]:
    """Retrieve global recent analyst actions across all cases."""
    logs = get_recent_audit_logs(session, limit=limit, offset=offset)
    return [
        AuditEntryResponse(
            id=a.id,
            investigation_id=a.investigation_id,
            action=a.action,
            reviewer=a.reviewer,
            comment=a.comment,
            previous_status=a.previous_status,
            new_status=a.new_status,
            created_at=a.created_at.isoformat() if a.created_at else "",
        )
        for a in logs
    ]
