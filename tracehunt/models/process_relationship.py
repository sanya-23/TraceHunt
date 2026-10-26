"""Process Relationship model capturing parent-child execution links."""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from tracehunt.models.base import Base, utc_now


class ProcessRelationship(Base):
    """Represents a reconstructed directed parent-child edge in the process execution graph."""

    __tablename__ = "process_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # Foreign Keys to Endpoint Events
    parent_event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("endpoint_events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    child_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("endpoint_events.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Process Identifiers
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    child_pid: Mapped[int] = mapped_column(Integer, nullable=False)

    # Relationship Semantics & Confidence
    relationship_type: Mapped[str] = mapped_column(
        String(64), default="PARENT_CHILD", nullable=False
    )  # PARENT_CHILD, UNRESOLVED_PARENT, INFERRED
    confidence: Mapped[str] = mapped_column(
        String(32), default="HIGH", nullable=False
    )  # HIGH, MEDIUM, LOW, UNRESOLVED

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    parent_event: Mapped["EndpointEvent | None"] = relationship(
        "EndpointEvent", foreign_keys=[parent_event_id]
    )
    child_event: Mapped["EndpointEvent"] = relationship(
        "EndpointEvent", foreign_keys=[child_event_id]
    )

    __table_args__ = (
        Index("ix_proc_rel_host_pids", "host", "parent_pid", "child_pid"),
    )

    def __repr__(self) -> str:
        return f"<ProcessRelationship id={self.id} host='{self.host}' {self.parent_pid}->{self.child_pid} conf='{self.confidence}'>"
