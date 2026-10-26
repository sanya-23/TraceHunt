"""Investigation Case Management Service.

Provides complete lifecycle management for threat-hunting cases, including
creation, status transitions with strict state machine validation, disposition
rationale recording, case reopening, and integrated audit logging.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from tracehunt.exceptions import CaseManagementError
from tracehunt.logging_config import get_logger
from tracehunt.models import Investigation
from tracehunt.models.base import utc_now
from tracehunt.investigation.audit_service import record_audit
from tracehunt.investigation.evidence_service import attach_evidence

logger = get_logger("investigation.cases")

# Permitted investigation lifecycle statuses
VALID_CASE_STATUSES: set[str] = {
    "OPEN",
    "INVESTIGATING",
    "CLOSED_FALSE_POSITIVE",
    "CLOSED_TRUE_POSITIVE",
}

# Strict state transition matrix
PERMITTED_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"INVESTIGATING", "CLOSED_FALSE_POSITIVE", "CLOSED_TRUE_POSITIVE"},
    "INVESTIGATING": {"OPEN", "CLOSED_FALSE_POSITIVE", "CLOSED_TRUE_POSITIVE"},
    "CLOSED_FALSE_POSITIVE": {"OPEN"},
    "CLOSED_TRUE_POSITIVE": {"OPEN"},
}


def _generate_case_id() -> str:
    """Generate a readable, timestamped investigation case identifier."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"INV-{date_str}-{unique_suffix}"


def create_investigation(
    session: Session,
    title: str,
    host: str,
    summary: str | None = None,
    investigation_id: str | None = None,
    reviewer: str = "system_analyst",
    initial_status: str = "OPEN",
    initial_finding_ids: list[int] | None = None,
) -> Investigation:
    """Create a new threat-hunting investigation case with audit trail."""
    clean_title = (title or "").strip()
    if not clean_title:
        raise CaseManagementError("Investigation title must not be empty.")

    clean_host = (host or "").strip()
    if not clean_host:
        raise CaseManagementError("Investigation host must not be empty.")

    clean_status = (initial_status or "OPEN").strip().upper()
    if clean_status not in VALID_CASE_STATUSES:
        raise CaseManagementError(
            f"Invalid initial status '{initial_status}'. Permitted: {sorted(VALID_CASE_STATUSES)}"
        )

    cid = (investigation_id or "").strip() or _generate_case_id()

    # Verify ID uniqueness
    existing = session.get(Investigation, cid)
    if existing:
        raise CaseManagementError(f"Investigation with ID '{cid}' already exists.")

    case = Investigation(
        id=cid,
        host=clean_host,
        title=clean_title,
        status=clean_status,
        summary=summary.strip() if summary else None,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    session.add(case)
    session.flush()

    # Record case creation in audit trail
    record_audit(
        session=session,
        action="CASE_CREATED",
        reviewer=reviewer,
        comment=f"Created case '{cid}' on host '{clean_host}': {clean_title}",
        investigation_id=cid,
        new_status=clean_status,
    )

    # Attach initial findings if supplied
    if initial_finding_ids:
        for finding_id in initial_finding_ids:
            attach_evidence(
                session=session,
                investigation_id=cid,
                finding_id=finding_id,
                reviewer=reviewer,
                notes="Initial finding attached upon case creation",
            )

    logger.info(f"Created investigation '{cid}' on host '{clean_host}' by '{reviewer}'.")
    return case


def get_investigation(
    session: Session,
    investigation_id: str,
    load_relations: bool = True,
) -> Investigation | None:
    """Retrieve an investigation by ID, optionally eager-loading evidence and audit items."""
    if not investigation_id or not investigation_id.strip():
        return None

    clean_id = investigation_id.strip()
    if load_relations:
        stmt = (
            select(Investigation)
            .where(Investigation.id == clean_id)
            .options(
                selectinload(Investigation.evidence_items),
                selectinload(Investigation.audit_records),
            )
        )
        return session.scalars(stmt).first()
    return session.get(Investigation, clean_id)


def list_investigations(
    session: Session,
    status: str | None = None,
    host: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Investigation]:
    """List and filter investigations with pagination."""
    stmt = select(Investigation)

    if status:
        clean_status = status.strip().upper()
        if clean_status not in VALID_CASE_STATUSES:
            raise CaseManagementError(
                f"Invalid filter status '{status}'. Permitted: {sorted(VALID_CASE_STATUSES)}"
            )
        stmt = stmt.where(Investigation.status == clean_status)

    if host:
        stmt = stmt.where(Investigation.host.ilike(host.strip()))

    if created_after:
        stmt = stmt.where(Investigation.created_at >= created_after)

    if created_before:
        stmt = stmt.where(Investigation.created_at <= created_before)

    bounded_limit = max(1, min(limit, 1000))
    stmt = stmt.order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(
        bounded_limit
    ).offset(offset)

    return list(session.scalars(stmt).all())


def update_investigation(
    session: Session,
    investigation_id: str,
    title: str | None = None,
    summary: str | None = None,
    reviewer: str = "system_analyst",
) -> Investigation:
    """Update mutable details of an investigation (title, summary) and record audit log."""
    case = session.get(Investigation, investigation_id)
    if not case:
        raise CaseManagementError(f"Investigation '{investigation_id}' does not exist.")

    changes: list[str] = []

    if title is not None:
        clean_title = title.strip()
        if not clean_title:
            raise CaseManagementError("Title cannot be empty.")
        if clean_title != case.title:
            changes.append(f"Title changed from '{case.title}' to '{clean_title}'")
            case.title = clean_title

    if summary is not None:
        clean_summary = summary.strip()
        if clean_summary != (case.summary or ""):
            changes.append("Summary updated")
            case.summary = clean_summary

    if not changes:
        return case

    case.updated_at = utc_now()
    session.flush()

    record_audit(
        session=session,
        action="CASE_UPDATED",
        reviewer=reviewer,
        comment="; ".join(changes),
        investigation_id=case.id,
    )
    logger.info(f"Updated case '{case.id}': {'; '.join(changes)}")
    return case


def transition_case_status(
    session: Session,
    investigation_id: str,
    new_status: str,
    reviewer: str = "system_analyst",
    rationale: str | None = None,
) -> Investigation:
    """Transition investigation case status adhering strictly to allowed state transitions."""
    case = session.get(Investigation, investigation_id)
    if not case:
        raise CaseManagementError(f"Investigation '{investigation_id}' does not exist.")

    clean_new_status = (new_status or "").strip().upper()
    if clean_new_status not in VALID_CASE_STATUSES:
        raise CaseManagementError(
            f"Invalid target status '{new_status}'. Permitted: {sorted(VALID_CASE_STATUSES)}"
        )

    current_status = case.status
    if current_status == clean_new_status:
        # Status already matches; return without error
        return case

    allowed = PERMITTED_TRANSITIONS.get(current_status, set())
    if clean_new_status not in allowed:
        raise CaseManagementError(
            f"Invalid status transition from '{current_status}' to '{clean_new_status}'. "
            f"Permitted next statuses: {sorted(allowed) if allowed else 'None (Terminal state)'}"
        )

    clean_rationale = (rationale or "").strip()

    # Closing transitions require mandatory rationale
    if clean_new_status in {"CLOSED_FALSE_POSITIVE", "CLOSED_TRUE_POSITIVE"}:
        if not clean_rationale:
            raise CaseManagementError(
                f"Disposition rationale is required when closing a case as '{clean_new_status}'."
            )
        audit_action = "CASE_CLOSED"
        audit_comment = f"Closed case as {clean_new_status}. Rationale: {clean_rationale}"
    elif current_status in {"CLOSED_FALSE_POSITIVE", "CLOSED_TRUE_POSITIVE"} and clean_new_status == "OPEN":
        # Reopening
        if not clean_rationale:
            raise CaseManagementError("Rationale is required when reopening a closed investigation.")
        audit_action = "CASE_REOPENED"
        audit_comment = f"Reopened case from {current_status}. Rationale: {clean_rationale}"
    else:
        audit_action = "STATUS_CHANGED"
        audit_comment = (
            f"Status changed from {current_status} to {clean_new_status}."
            + (f" Rationale: {clean_rationale}" if clean_rationale else "")
        )

    case.status = clean_new_status
    case.updated_at = utc_now()
    session.flush()

    record_audit(
        session=session,
        action=audit_action,
        reviewer=reviewer,
        comment=audit_comment,
        investigation_id=case.id,
        previous_status=current_status,
        new_status=clean_new_status,
    )

    logger.info(
        f"Case '{case.id}' transitioned from '{current_status}' to '{clean_new_status}' by '{reviewer}'."
    )
    return case


def close_investigation(
    session: Session,
    investigation_id: str,
    disposition: str,
    reviewer: str = "system_analyst",
    rationale: str = "",
) -> Investigation:
    """Close an investigation with FALSE_POSITIVE or TRUE_POSITIVE disposition."""
    clean_disp = (disposition or "").strip().upper()
    if clean_disp in {"FALSE_POSITIVE", "CLOSED_FALSE_POSITIVE"}:
        target_status = "CLOSED_FALSE_POSITIVE"
    elif clean_disp in {"TRUE_POSITIVE", "CLOSED_TRUE_POSITIVE"}:
        target_status = "CLOSED_TRUE_POSITIVE"
    else:
        raise CaseManagementError(
            f"Invalid closure disposition '{disposition}'. Must be FALSE_POSITIVE or TRUE_POSITIVE."
        )

    return transition_case_status(
        session=session,
        investigation_id=investigation_id,
        new_status=target_status,
        reviewer=reviewer,
        rationale=rationale,
    )


def reopen_investigation(
    session: Session,
    investigation_id: str,
    reviewer: str = "system_analyst",
    rationale: str = "",
) -> Investigation:
    """Reopen a previously closed investigation case back to OPEN status."""
    return transition_case_status(
        session=session,
        investigation_id=investigation_id,
        new_status="OPEN",
        reviewer=reviewer,
        rationale=rationale,
    )


def add_case_note(
    session: Session,
    investigation_id: str,
    note: str,
    reviewer: str = "system_analyst",
) -> None:
    """Append an analyst note to the case's immutable audit history."""
    clean_note = (note or "").strip()
    if not clean_note:
        raise CaseManagementError("Analyst note cannot be empty.")

    case = session.get(Investigation, investigation_id)
    if not case:
        raise CaseManagementError(f"Investigation '{investigation_id}' does not exist.")

    record_audit(
        session=session,
        action="NOTE_ADDED",
        reviewer=reviewer,
        comment=clean_note,
        investigation_id=case.id,
    )
