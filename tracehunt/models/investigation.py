"""Investigation model representing a host threat-hunting case."""

from datetime import datetime
from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class Investigation(Base):
    """A threat-hunting investigation case tracking evidence, hypotheses, and dispositions."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g., INV-2026-001
    host: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="OPEN", nullable=False, index=True
    )  # OPEN, INVESTIGATING, CLOSED_FALSE_POSITIVE, CLOSED_TRUE_POSITIVE, CLOSED_BENIGN
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships
    evidence_items: Mapped[list["InvestigationEvidence"]] = relationship(
        "InvestigationEvidence", back_populates="investigation", cascade="all, delete-orphan"
    )
    audit_records: Mapped[list["AnalystAudit"]] = relationship(
        "AnalystAudit", back_populates="investigation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Investigation id='{self.id}' host='{self.host}' status='{self.status}'>"
