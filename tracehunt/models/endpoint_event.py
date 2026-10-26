"""Normalized Endpoint Event model for process, network, and logon telemetry."""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class EndpointEvent(Base):
    """Normalized representation of Windows Sysmon and Security events."""

    __tablename__ = "endpoint_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    raw_event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Core Temporal & Identity Fields
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Telemetry Identifiers
    event_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # PROCESS_CREATE, PROCESS_TERMINATE, NETWORK_CONNECT, USER_LOGON, LOGON_FAILURE

    # Process Execution Telemetry
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    parent_process_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    image: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_image: Mapped[str | None] = mapped_column(String(512), nullable=True)
    parent_command_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Authentication & Network Context (Sysmon 3, Sec 4624/4625)
    logon_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    logon_type: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hashes: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    raw_event: Mapped["RawEvent | None"] = relationship("RawEvent", back_populates="endpoint_events")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="endpoint_event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_endpoint_events_host_time", "host", "event_time"),
        Index("ix_endpoint_events_host_pid", "host", "process_id"),
        Index("ix_endpoint_events_pid_ppid", "process_id", "parent_process_id"),
    )

    def __repr__(self) -> str:
        return f"<EndpointEvent id={self.id} host='{self.host}' eid={self.event_id} pid={self.process_id}>"
