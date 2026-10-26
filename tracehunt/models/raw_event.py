"""Raw Event model preserving original unmodified telemetry."""

from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class RawEvent(Base):
    """Stores verbatim ingested telemetry prior to normalization."""

    __tablename__ = "raw_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    parse_status: Mapped[str] = mapped_column(
        String(32), default="PENDING", nullable=False, index=True
    )  # PENDING, PARSED, FAILED, DUPLICATE

    # Relationships
    endpoint_events: Mapped[list["EndpointEvent"]] = relationship(
        "EndpointEvent", back_populates="raw_event", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<RawEvent id={self.id} source='{self.source}' status='{self.parse_status}'>"
