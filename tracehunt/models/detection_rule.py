"""Detection Rule model storing versioned behavioral detection logic metadata."""

from datetime import datetime
from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class DetectionRule(Base):
    """Catalog of transparent, versioned behavioral threat-hunting rules."""

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g., RULE-001-LOLBIN
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_level: Mapped[str] = mapped_column(
        String(16), default="HIGH", nullable=False
    )  # LOW, MEDIUM, HIGH
    mitre_technique: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="rule")

    def __repr__(self) -> str:
        return f"<DetectionRule id='{self.id}' name='{self.name}' v='{self.version}' sev='{self.severity}'>"
