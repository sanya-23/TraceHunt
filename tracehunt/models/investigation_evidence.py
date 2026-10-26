"""Investigation Evidence junction model associating telemetry and findings with a case."""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class InvestigationEvidence(Base):
    """Links specific raw events, normalized endpoint events, or findings as evidence in an investigation."""

    __tablename__ = "investigation_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Optional references to various levels of evidence
    raw_event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("raw_events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    endpoint_event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("endpoint_events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )

    sequence_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="evidence_items")
    raw_event: Mapped["RawEvent | None"] = relationship("RawEvent")
    endpoint_event: Mapped["EndpointEvent | None"] = relationship("EndpointEvent")
    finding: Mapped["Finding | None"] = relationship("Finding", back_populates="investigation_evidence")

    def __repr__(self) -> str:
        return f"<InvestigationEvidence id={self.id} inv='{self.investigation_id}' finding={self.finding_id}>"
