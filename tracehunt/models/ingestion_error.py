"""Ingestion Error model recording malformed, unparseable, or schema-violating records."""

from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from tracehunt.models.base import Base, utc_now


class IngestionError(Base):
    """Records malformed telemetry lines or validation failures without aborting batch imports."""

    __tablename__ = "ingestion_errors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    error_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # JSON_PARSE_ERROR, SCHEMA_VALIDATION_ERROR, ENCODING_ERROR, CORRUPTED_ROW
    details: Mapped[str] = mapped_column(Text, nullable=False)
    raw_record_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<IngestionError id={self.id} type='{self.error_type}' source='{self.source}'>"
