"""Pydantic schemas for telemetry event validation, normalization, and ingestion summaries."""

from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEndpointEvent(BaseModel):
    """Pydantic validation model for a normalized endpoint telemetry event."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    event_time: datetime = Field(description="Normalized UTC ISO-8601 timestamp")
    host: str = Field(min_length=1, max_length=128, description="Target host / computer name")
    user: str | None = Field(default=None, max_length=128, description="User identity")
    event_id: int = Field(description="Windows / Sysmon Event ID")
    event_type: Literal[
        "PROCESS_CREATE",
        "PROCESS_TERMINATE",
        "NETWORK_CONNECT",
        "USER_LOGON",
        "LOGON_FAILURE",
        "SYSTEM_EVENT",
    ] = Field(description="Normalized event category")

    process_id: int | None = Field(default=None, description="Numeric Process ID (PID)")
    parent_process_id: int | None = Field(default=None, description="Numeric Parent PID (PPID)")
    image: str | None = Field(default=None, max_length=512, description="Executable image path")
    command_line: str | None = Field(default=None, description="Complete process command line")
    parent_image: str | None = Field(default=None, max_length=512, description="Parent executable image path")
    parent_command_line: str | None = Field(default=None, description="Parent command line")

    logon_id: str | None = Field(default=None, max_length=64, description="Logon session identifier")
    logon_type: int | None = Field(default=None, description="Windows logon type integer")
    ip_address: str | None = Field(default=None, max_length=64, description="Network IP address")
    port: int | None = Field(default=None, description="Network port integer")
    hashes: str | None = Field(default=None, max_length=512, description="File hashes (MD5/SHA256/IMPHASH)")
    raw_event_id: int | None = Field(default=None, description="Foreign key to source raw_event")

    @field_validator("event_time")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        """Enforce timezone-aware UTC datetime."""
        if v.tzinfo is None:
            # Explicitly require timezone or raise error in normalization
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("port")
    @classmethod
    def validate_port_range(cls, v: int | None) -> int | None:
        """Ensure network port is within valid TCP/UDP range."""
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"Port {v} is outside valid range 0-65535")
        return v


class RawIngestedRecord(BaseModel):
    """Encapsulates an unparsed input record extracted from an imported file."""

    model_config = ConfigDict(extra="allow")

    record_index: int = Field(description="Record index or line number in source file")
    source_name: str = Field(description="Name or path of imported telemetry file")
    payload: dict[str, Any] = Field(description="Unprocessed key-value dictionary")


class IngestionSummary(BaseModel):
    """Detailed summary of batch telemetry ingestion results."""

    model_config = ConfigDict(extra="ignore")

    source_file: str
    records_read: int = 0
    records_parsed: int = 0
    events_normalized: int = 0
    duplicates_skipped: int = 0
    records_rejected: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Return percentage of read records successfully parsed and persisted."""
        if self.records_read == 0:
            return 100.0
        return round((self.events_normalized / self.records_read) * 100, 2)
