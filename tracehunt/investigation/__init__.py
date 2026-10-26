"""TraceHunt Investigation Package.

Provides host investigation timeline reconstruction, case management with strict
lifecycle state transitions, evidence linking with cross-host boundary checks,
and append-only analyst audit tracking.
"""

from tracehunt.investigation.audit_service import (
    VALID_AUDIT_ACTIONS,
    get_case_audit_trail,
    get_recent_audit_logs,
    record_audit,
)
from tracehunt.investigation.case_service import (
    PERMITTED_TRANSITIONS,
    VALID_CASE_STATUSES,
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
from tracehunt.investigation.timeline_service import (
    FindingSummary,
    TimelineItem,
    get_host_timeline,
    get_timeline_summary,
)

__all__ = [
    # Audit
    "record_audit",
    "get_case_audit_trail",
    "get_recent_audit_logs",
    "VALID_AUDIT_ACTIONS",
    # Case Management
    "create_investigation",
    "get_investigation",
    "list_investigations",
    "update_investigation",
    "transition_case_status",
    "close_investigation",
    "reopen_investigation",
    "add_case_note",
    "VALID_CASE_STATUSES",
    "PERMITTED_TRANSITIONS",
    # Evidence
    "attach_evidence",
    "remove_evidence",
    "get_case_evidence",
    # Timeline
    "get_host_timeline",
    "get_timeline_summary",
    "TimelineItem",
    "FindingSummary",
]
