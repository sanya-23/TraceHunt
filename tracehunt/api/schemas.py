"""Pydantic request and response schemas for TraceHunt REST API."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    environment: str = "development"
    database_connected: bool = True
    tables_verified: list[str] = Field(default_factory=list)


class StatusResponse(BaseModel):
    total_raw_events: int = 0
    total_endpoint_events: int = 0
    total_hosts: int = 0
    total_findings: int = 0
    total_investigations: int = 0
    open_investigations: int = 0
    total_audit_records: int = 0


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

class IngestionResponse(BaseModel):
    source_file: str
    total_records: int
    successful_records: int
    duplicates_skipped: int
    errors_encountered: int
    duration_seconds: float
    message: str


# ---------------------------------------------------------------------------
# Hosts & Metrics
# ---------------------------------------------------------------------------

class HostSummary(BaseModel):
    host: str
    event_count: int
    finding_count: int
    first_seen: str | None = None
    last_seen: str | None = None


class HostMetricsResponse(BaseModel):
    host: str
    total_events: int
    total_findings: int
    event_counts: dict[str, int]
    severity_counts: dict[str, int]


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

class FindingSummarySchema(BaseModel):
    id: int
    rule_id: str
    severity: str
    confidence: str
    rationale: str
    matched_fields: dict[str, Any]
    caveats: str | None = None


class TimelineItemSchema(BaseModel):
    id: int
    event_time: str
    host: str
    event_id: int
    event_type: str
    user: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    ip_address: str | None = None
    port: int | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    raw_event_id: int | None = None
    findings: list[FindingSummarySchema] = Field(default_factory=list)
    has_detection: bool = False
    max_severity: str | None = None


# ---------------------------------------------------------------------------
# Process Trees
# ---------------------------------------------------------------------------

class ProcessTreeNodeSchema(BaseModel):
    id: int
    process_id: int | None
    parent_process_id: int | None
    image: str | None
    command_line: str | None
    user: str | None
    event_time: str
    has_findings: bool = False
    max_severity: str | None = None
    children: list["ProcessTreeNodeSchema"] = Field(default_factory=list)


class ProcessTreeResponse(BaseModel):
    host: str
    total_trees: int
    total_processes: int
    unresolved_parents_count: int
    trees: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Detections & Findings
# ---------------------------------------------------------------------------

class DetectionRuleSchema(BaseModel):
    id: str
    name: str
    version: str
    severity: str
    confidence_level: str
    mitre_technique: str
    enabled: bool
    description: str


class RuleToggleRequest(BaseModel):
    enabled: bool


class EvaluateDetectionsRequest(BaseModel):
    host: str | None = None
    rule_ids: list[str] | None = None


class EvaluateDetectionsResponse(BaseModel):
    evaluated_events: int
    active_rules: int
    findings_generated: int
    duplicates_skipped: int
    errors: list[str] = Field(default_factory=list)


class FindingDetailSchema(BaseModel):
    id: int
    rule_id: str
    endpoint_event_id: int
    severity: str
    confidence: str
    rationale: str
    matched_fields: dict[str, Any]
    caveats: str | None = None
    created_at: str
    host: str | None = None
    event_time: str | None = None
    process_image: str | None = None
    command_line: str | None = None


# ---------------------------------------------------------------------------
# Cases & Evidence
# ---------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    host: str = Field(..., min_length=1, max_length=128)
    summary: str | None = None
    investigation_id: str | None = None
    reviewer: str = "system_analyst"
    initial_status: str = "OPEN"
    initial_finding_ids: list[int] | None = None


class CaseUpdateRequest(BaseModel):
    title: str | None = None
    summary: str | None = None
    reviewer: str = "system_analyst"


class CaseTransitionRequest(BaseModel):
    new_status: str
    reviewer: str = "system_analyst"
    rationale: str | None = None


class CaseCloseRequest(BaseModel):
    disposition: str = Field(..., description="FALSE_POSITIVE or TRUE_POSITIVE")
    reviewer: str = "system_analyst"
    rationale: str = Field(..., min_length=1, description="Mandatory closing rationale")


class CaseReopenRequest(BaseModel):
    reviewer: str = "system_analyst"
    rationale: str = Field(..., min_length=1, description="Mandatory reopening rationale")


class CaseNoteRequest(BaseModel):
    note: str = Field(..., min_length=1)
    reviewer: str = "system_analyst"


class CaseResponse(BaseModel):
    id: str
    title: str
    status: str
    host: str
    summary: str | None = None
    created_at: str
    updated_at: str
    evidence_count: int = 0
    audit_count: int = 0


class EvidenceAttachRequest(BaseModel):
    finding_id: int | None = None
    endpoint_event_id: int | None = None
    raw_event_id: int | None = None
    notes: str | None = None
    reviewer: str = "system_analyst"
    allow_cross_host: bool = False


class EvidenceResponse(BaseModel):
    id: int
    investigation_id: str
    finding_id: int | None = None
    endpoint_event_id: int | None = None
    raw_event_id: int | None = None
    sequence_number: int
    notes: str | None = None
    created_at: str


class AuditEntryResponse(BaseModel):
    id: int
    investigation_id: str | None = None
    action: str
    reviewer: str
    comment: str
    previous_status: str | None = None
    new_status: str | None = None
    created_at: str


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportGenerateRequest(BaseModel):
    host: str | None = None
    investigation_id: str | None = None
    format: str = Field(default="html", description="'html', 'json', 'docx', or 'pdf'")
    title: str | None = None
    analyst_name: str | None = None
    start_time: str | None = None
    end_time: str | None = None


class ReportGenerateResponse(BaseModel):
    report_id: str
    format: str
    filename: str
    download_url: str
    generated_at: str
    total_events: int
    total_findings: int


# ---------------------------------------------------------------------------
# Generic Error
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    error: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
