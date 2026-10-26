"""Schemas for TraceHunt Machine-Readable and Executive Reports.

Provides strongly-typed data structures for report generation, serialization,
and rendering with forensic traceability and explicit limitation disclosures.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ReportMetadata:
    """Core provenance and generation metadata for a report."""

    report_id: str
    generated_at: str
    report_type: str
    generator_version: str = "1.0.0"
    host: str | None = None
    investigation_id: str | None = None
    time_range_start: str | None = None
    time_range_end: str | None = None
    title: str | None = None
    analyst_name: str | None = "analyst_ui"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportMetrics:
    """Summary metrics and threat distribution for the report period."""

    total_events: int = 0
    total_findings: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    )
    event_type_counts: dict[str, int] = field(default_factory=dict)
    detection_rules_triggered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportFinding:
    """A detected threat finding with rule explainability and event lineage."""

    id: int
    rule_id: str
    severity: str
    confidence: str
    rationale: str
    matched_fields: dict[str, Any]
    host: str
    event_time: str | None = None
    process_image: str | None = None
    command_line: str | None = None
    caveats: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportTimelineItem:
    """Key chronological endpoint event included in the executive report."""

    id: int
    event_time: str
    host: str
    event_type: str
    user: str | None
    process_id: int | None
    image: str | None
    command_line: str | None
    ip_address: str | None
    has_detection: bool = False
    max_severity: str | None = None
    findings_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportCase:
    """Investigation case details, disposition rationale, evidence, and audit logs."""

    id: str
    title: str
    status: str
    host: str
    summary: str | None = None
    created_at: str = ""
    updated_at: str = ""
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    audit_trail: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportData:
    """Complete structured investigation report package."""

    metadata: ReportMetadata
    metrics: ReportMetrics
    case: ReportCase | None = None
    findings: list[ReportFinding] = field(default_factory=list)
    timeline: list[ReportTimelineItem] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "metrics": self.metrics.to_dict(),
            "case": self.case.to_dict() if self.case else None,
            "findings": [f.to_dict() for f in self.findings],
            "timeline": [t.to_dict() for t in self.timeline],
            "limitations": self.limitations,
        }
