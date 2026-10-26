"""Investigation Evidence Service.

Provides secure linking, cross-host isolation, duplicate prevention, and retrieval
of telemetry, findings, and raw events associated with investigation cases.
"""

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from tracehunt.exceptions import CaseManagementError
from tracehunt.logging_config import get_logger
from tracehunt.models import (
    EndpointEvent,
    Finding,
    Investigation,
    InvestigationEvidence,
    RawEvent,
)
from tracehunt.investigation.audit_service import record_audit

logger = get_logger("investigation.evidence")


def attach_evidence(
    session: Session,
    investigation_id: str,
    finding_id: int | None = None,
    endpoint_event_id: int | None = None,
    raw_event_id: int | None = None,
    notes: str | None = None,
    reviewer: str = "system_analyst",
    allow_cross_host: bool = False,
) -> InvestigationEvidence:
    """Attach a finding, normalized endpoint event, or raw event to an investigation case.

    Validates entity existence, verifies host alignment (cross-host boundary protection),
    prevents duplicate evidence attachments idempotently, assigns sequence numbers,
    and logs an immutable audit entry atomically.
    """
    if not investigation_id or not investigation_id.strip():
        raise CaseManagementError("Investigation ID must be provided.")

    clean_inv_id = investigation_id.strip()
    investigation = session.get(Investigation, clean_inv_id)
    if not investigation:
        raise CaseManagementError(f"Investigation '{clean_inv_id}' does not exist.")

    if finding_id is None and endpoint_event_id is None and raw_event_id is None:
        raise CaseManagementError(
            "At least one evidence entity (finding_id, endpoint_event_id, or raw_event_id) must be specified."
        )

    # 1. Validate referenced entities and extract host context for boundary verification
    detected_hosts: set[str] = set()

    if finding_id is not None:
        finding = session.get(
            Finding,
            finding_id,
            options=[selectinload(Finding.endpoint_event)],
        )
        if not finding:
            raise CaseManagementError(f"Referenced Finding ID {finding_id} does not exist.")
        if finding.endpoint_event and finding.endpoint_event.host:
            detected_hosts.add(finding.endpoint_event.host)

    if endpoint_event_id is not None:
        endpoint_event = session.get(EndpointEvent, endpoint_event_id)
        if not endpoint_event:
            raise CaseManagementError(
                f"Referenced EndpointEvent ID {endpoint_event_id} does not exist."
            )
        if endpoint_event.host:
            detected_hosts.add(endpoint_event.host)

    if raw_event_id is not None:
        raw_event = session.get(RawEvent, raw_event_id)
        if not raw_event:
            raise CaseManagementError(f"Referenced RawEvent ID {raw_event_id} does not exist.")
        if hasattr(raw_event, "host") and getattr(raw_event, "host"):
            detected_hosts.add(getattr(raw_event, "host"))

    # 2. Cross-host boundary enforcement
    for ev_host in detected_hosts:
        if ev_host.lower() != investigation.host.lower() and not allow_cross_host:
            raise CaseManagementError(
                f"Cross-host evidence rejected: Evidence host '{ev_host}' does not match "
                f"investigation host '{investigation.host}'. Explicit authorization required."
            )

    # 3. Duplicate prevention: Check if identical evidence link already exists
    dup_stmt = select(InvestigationEvidence).where(
        InvestigationEvidence.investigation_id == clean_inv_id,
        InvestigationEvidence.finding_id == finding_id,
        InvestigationEvidence.endpoint_event_id == endpoint_event_id,
        InvestigationEvidence.raw_event_id == raw_event_id,
    )
    existing_evidence = session.scalars(dup_stmt).first()
    if existing_evidence:
        logger.info(
            f"Evidence already linked to case '{clean_inv_id}' (ID {existing_evidence.id}); returning existing record."
        )
        return existing_evidence

    # 4. Determine next sequence number
    seq_stmt = select(func.coalesce(func.max(InvestigationEvidence.sequence_number), 0)).where(
        InvestigationEvidence.investigation_id == clean_inv_id
    )
    current_max_seq = session.scalar(seq_stmt) or 0
    next_seq = current_max_seq + 1

    # 5. Persist evidence junction row
    evidence = InvestigationEvidence(
        investigation_id=clean_inv_id,
        finding_id=finding_id,
        endpoint_event_id=endpoint_event_id,
        raw_event_id=raw_event_id,
        sequence_number=next_seq,
        notes=notes.strip() if notes else None,
    )
    session.add(evidence)
    session.flush()

    # 6. Record audit entry atomically
    audit_comment = (
        f"Attached evidence #{evidence.id} (Seq {next_seq}): "
        f"finding={finding_id}, event={endpoint_event_id}, raw={raw_event_id}."
    )
    if notes:
        audit_comment += f" Notes: {notes.strip()}"

    record_audit(
        session=session,
        action="EVIDENCE_ATTACHED",
        reviewer=reviewer,
        comment=audit_comment,
        investigation_id=clean_inv_id,
    )

    logger.info(
        f"Attached evidence #{evidence.id} to case '{clean_inv_id}' by '{reviewer}'."
    )
    return evidence


def remove_evidence(
    session: Session,
    investigation_id: str,
    evidence_id: int,
    reviewer: str = "system_analyst",
    reason: str | None = None,
) -> bool:
    """Remove an evidence link from an investigation case.

    Deletes the junction row in `investigation_evidence` without modifying or deleting
    the underlying telemetry, raw events, or findings. Records the action in the audit trail.
    """
    if not investigation_id or not investigation_id.strip():
        raise CaseManagementError("Investigation ID must be provided.")

    clean_inv_id = investigation_id.strip()
    evidence = session.get(InvestigationEvidence, evidence_id)
    if not evidence or evidence.investigation_id != clean_inv_id:
        raise CaseManagementError(
            f"Evidence item {evidence_id} not found in investigation '{clean_inv_id}'."
        )

    finding_ref = evidence.finding_id
    event_ref = evidence.endpoint_event_id
    raw_ref = evidence.raw_event_id

    session.delete(evidence)
    session.flush()

    audit_comment = (
        f"Removed evidence #{evidence_id} (finding={finding_ref}, event={event_ref}, raw={raw_ref}). "
        f"Reason: {reason.strip() if reason else 'No reason specified'}"
    )
    record_audit(
        session=session,
        action="EVIDENCE_REMOVED",
        reviewer=reviewer,
        comment=audit_comment,
        investigation_id=clean_inv_id,
    )

    logger.info(f"Removed evidence #{evidence_id} from case '{clean_inv_id}' by '{reviewer}'.")
    return True


def get_case_evidence(
    session: Session,
    investigation_id: str,
) -> list[InvestigationEvidence]:
    """Retrieve all evidence attached to an investigation, sorted chronologically by sequence number."""
    if not investigation_id or not investigation_id.strip():
        return []

    clean_inv_id = investigation_id.strip()
    stmt = (
        select(InvestigationEvidence)
        .where(InvestigationEvidence.investigation_id == clean_inv_id)
        .options(
            selectinload(InvestigationEvidence.finding),
            selectinload(InvestigationEvidence.endpoint_event),
            selectinload(InvestigationEvidence.raw_event),
        )
        .order_by(InvestigationEvidence.sequence_number.asc(), InvestigationEvidence.id.asc())
    )
    return list(session.scalars(stmt).all())
