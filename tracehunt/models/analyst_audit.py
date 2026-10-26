"""Analyst Audit model providing an immutable audit trail for case reviews."""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class AnalystAudit(Base):
    """Immutable audit entry recording analyst dispositions, hypotheses, comments, and review actions."""

    __tablename__ = "analyst_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # STATUS_CHANGE, NOTE_ADDED, EVIDENCE_ATTACHED, DISPOSITION_RECORDED
    reviewer: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    # Relationships
    investigation: Mapped["Investigation | None"] = relationship(
        "Investigation", back_populates="audit_records"
    )

    def __repr__(self) -> str:
        return f"<AnalystAudit id={self.id} reviewer='{self.reviewer}' action='{self.action}'>"
