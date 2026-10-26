"""Analyst Audit Trail Service for investigation operations.

Provides append-only recording and retrieval of reviewer actions, case transitions,
dispositions, and evidence modifications.
"""

from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.exceptions import CaseManagementError
from tracehunt.logging_config import get_logger
from tracehunt.models import AnalystAudit

logger = get_logger("investigation.audit")

# Permitted audit actions
VALID_AUDIT_ACTIONS: set[str] = {
    "CASE_CREATED",
    "CASE_UPDATED",
    "STATUS_CHANGED",
    "CASE_CLOSED",
    "CASE_REOPENED",
    "EVIDENCE_ATTACHED",
    "EVIDENCE_REMOVED",
    "DISPOSITION_RECORDED",
    "NOTE_ADDED",
}


def record_audit(
    session: Session,
    action: str,
    reviewer: str,
    comment: str,
    investigation_id: str | None = None,
    previous_status: str | None = None,
    new_status: str | None = None,
) -> AnalystAudit:
    """Record an immutable audit log entry within the current transaction."""
    clean_action = (action or "").strip().upper()
    if clean_action not in VALID_AUDIT_ACTIONS:
        raise CaseManagementError(
            f"Invalid audit action '{action}'. Permitted actions: {sorted(VALID_AUDIT_ACTIONS)}"
        )

    clean_reviewer = (reviewer or "").strip() or "system_analyst"
    clean_comment = (comment or "").strip()
    if not clean_comment:
        raise CaseManagementError("Audit log comment must not be empty.")

    entry = AnalystAudit(
        investigation_id=investigation_id,
        action=clean_action,
        reviewer=clean_reviewer,
        comment=clean_comment,
        previous_status=previous_status,
        new_status=new_status,
    )
    session.add(entry)
    session.flush()
    logger.info(
        f"Audit recorded [{clean_action}] by '{clean_reviewer}' on case '{investigation_id}': {clean_comment}"
    )
    return entry


def get_case_audit_trail(investigation_id: str, session: Session) -> list[AnalystAudit]:
    """Retrieve the full chronological, append-only audit trail for an investigation case."""
    if not investigation_id:
        return []

    stmt = (
        select(AnalystAudit)
        .where(AnalystAudit.investigation_id == investigation_id)
        .order_by(AnalystAudit.created_at.asc(), AnalystAudit.id.asc())
    )
    return list(session.scalars(stmt).all())


def get_recent_audit_logs(
    session: Session, limit: int = 100, offset: int = 0
) -> list[AnalystAudit]:
    """Retrieve global recent audit entries across all investigations."""
    bounded_limit = max(1, min(limit, 1000))
    stmt = (
        select(AnalystAudit)
        .order_by(AnalystAudit.created_at.desc(), AnalystAudit.id.desc())
        .limit(bounded_limit)
        .offset(offset)
    )
    return list(session.scalars(stmt).all())
