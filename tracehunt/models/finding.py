"""Finding model representing an evidence-linked behavioral detection match."""

from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class Finding(Base):
    """An explainable threat detection finding with direct lineage to its source endpoint event."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    endpoint_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("endpoint_events.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Risk Metrics
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )  # LOW, MEDIUM, HIGH

    # Explainable Evidence Fields
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    matched_fields: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    caveats: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    # Relationships
    rule: Mapped["DetectionRule"] = relationship("DetectionRule", back_populates="findings")
    endpoint_event: Mapped["EndpointEvent"] = relationship("EndpointEvent", back_populates="findings")
    investigation_evidence: Mapped[list["InvestigationEvidence"]] = relationship(
        "InvestigationEvidence", back_populates="finding"
    )

    __table_args__ = (
        UniqueConstraint("rule_id", "endpoint_event_id", name="uq_findings_rule_event"),
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} rule='{self.rule_id}' event_id={self.endpoint_event_id} sev='{self.severity}'>"
