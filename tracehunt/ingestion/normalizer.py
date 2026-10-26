"""Event Normalizer for Windows Sysmon and Windows Security Event Telemetry.

Translates raw heterogenous event records into canonical NormalizedEndpointEvent
instances with timezone-aware UTC timestamps, validated PIDs/ports, and explicit nulls.
"""

from datetime import datetime, timezone
import re
from typing import Any
from dateutil import parser as dt_parser

from tracehunt.exceptions import NormalizationError
from tracehunt.schemas.event import NormalizedEndpointEvent

# Supported Event IDs
SUPPORTED_EVENT_IDS = {1, 3, 5, 4624, 4625, 4688}


def _get_nested_field(payload: dict[str, Any], *candidate_keys: str) -> Any:
    """Search for candidate keys in payload, checking top-level and nested EventData/System objects."""
    # Check top-level with exact and case-insensitive matching
    payload_lower = {k.lower(): v for k, v in payload.items()}
    for key in candidate_keys:
        if key in payload:
            return payload[key]
        if key.lower() in payload_lower:
            return payload_lower[key.lower()]

    # Check inside nested dictionaries (EventData, System, event_data, system)
    for parent in ("EventData", "event_data", "System", "system", "data"):
        nested = payload.get(parent)
        if isinstance(nested, dict):
            nested_lower = {k.lower(): v for k, v in nested.items()}
            for key in candidate_keys:
                if key in nested:
                    return nested[key]
                if key.lower() in nested_lower:
                    return nested_lower[key.lower()]

    return None


def parse_timestamp(raw_val: Any, is_utc_hint: bool = True) -> datetime:
    """Parse a timestamp into a timezone-aware UTC datetime.

    Supports ISO-8601, Sysmon standard formats ('YYYY-MM-DD HH:MM:SS.mmm'),
    Windows Event Viewer formats, and numeric epoch timestamps.
    """
    if raw_val is None or (isinstance(raw_val, str) and not raw_val.strip()):
        raise NormalizationError("Missing required event timestamp")

    # Numeric epoch timestamps (seconds or milliseconds)
    if isinstance(raw_val, (int, float)):
        try:
            # If > 1e11 it's likely milliseconds
            if raw_val > 1e11:
                return datetime.fromtimestamp(raw_val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(float(raw_val), tz=timezone.utc)
        except Exception as e:
            raise NormalizationError(f"Invalid numeric epoch timestamp '{raw_val}': {e}") from e

    if not isinstance(raw_val, str):
        raise NormalizationError(f"Unsupported timestamp format of type {type(raw_val).__name__}")

    val = raw_val.strip()
    try:
        # Check numeric epoch in string format
        if val.isdigit() or (val.replace(".", "", 1).isdigit() and len(val) >= 10):
            num = float(val)
            if num > 1e11:
                return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(num, tz=timezone.utc)

        # Parse string using dateutil
        parsed = dt_parser.parse(val)
        if parsed.tzinfo is None:
            # If no timezone offset is explicitly provided in string:
            # For UtcTime or when is_utc_hint is True, assign UTC directly
            if is_utc_hint:
                return parsed.replace(tzinfo=timezone.utc)
            # Default naive strings to UTC as standard practice for endpoint logs
            return parsed.replace(tzinfo=timezone.utc)

        # Convert timezone-aware datetime to UTC
        return parsed.astimezone(timezone.utc)
    except Exception as e:
        raise NormalizationError(f"Unable to parse timestamp '{val}': {e}") from e


def parse_int_field(raw_val: Any, field_name: str, allow_hex: bool = True) -> int | None:
    """Parse and validate an integer field (e.g. PID, Port), supporting hex strings like '0x1a4'."""
    if raw_val is None:
        return None

    if isinstance(raw_val, int):
        return raw_val

    if isinstance(raw_val, float):
        if raw_val.is_integer():
            return int(raw_val)
        raise NormalizationError(f"Non-integer float provided for {field_name}: {raw_val}")

    if isinstance(raw_val, str):
        val = raw_val.strip()
        if not val or val.lower() == "null" or val == "-":
            return None

        # Handle Hexadecimal notation (common in Windows Event ID 4688 NewProcessId / CreatorProcessId)
        if allow_hex and (val.startswith("0x") or val.startswith("0X")):
            try:
                return int(val, 16)
            except ValueError as e:
                raise NormalizationError(f"Invalid hexadecimal integer for {field_name}: '{val}'") from e

        # Handle decimal notation
        try:
            return int(val, 10)
        except ValueError as e:
            raise NormalizationError(f"Invalid integer value for {field_name}: '{val}'") from e

    raise NormalizationError(f"Unexpected type {type(raw_val).__name__} for integer field {field_name}")


def clean_string(raw_val: Any) -> str | None:
    """Clean string values, returning None for empty or '-' placeholder strings."""
    if raw_val is None:
        return None
    s = str(raw_val).strip()
    if not s or s == "-" or s.lower() == "null":
        return None
    return s


def normalize_event(payload: dict[str, Any], raw_event_id: int | None = None) -> NormalizedEndpointEvent:
    """Normalize a raw telemetry dictionary into a NormalizedEndpointEvent.

    Raises NormalizationError if the event ID is unsupported, mandatory fields
    are missing, or field parsing fails.
    """
    # 1. Extract and validate Event ID
    raw_event_id_val = _get_nested_field(payload, "EventID", "event_id", "EventId", "Id")
    if raw_event_id_val is None:
        raise NormalizationError("Missing mandatory Event ID field")

    event_id = parse_int_field(raw_event_id_val, "event_id", allow_hex=False)
    if event_id not in SUPPORTED_EVENT_IDS:
        raise NormalizationError(f"Unsupported Event ID: {event_id}. Supported: {sorted(SUPPORTED_EVENT_IDS)}")

    # 2. Extract and validate Host
    raw_host = _get_nested_field(payload, "Computer", "ComputerName", "host", "hostname", "Host")
    host = clean_string(raw_host)
    if not host:
        raise NormalizationError("Missing mandatory host / computer name")
    # Clean domain suffix if present e.g. WIN-01.corp.local -> WIN-01
    host = host.split(".")[0].upper()

    # 3. Extract and parse Timestamp
    raw_time = _get_nested_field(payload, "UtcTime", "TimeCreated", "Timestamp", "@timestamp", "EventTime", "time")
    # UtcTime key indicates source was already UTC
    is_utc_hint = bool(_get_nested_field(payload, "UtcTime") is not None)
    event_time = parse_timestamp(raw_time, is_utc_hint=is_utc_hint)

    # 4. Extract common process/user/auth fields
    user = clean_string(_get_nested_field(payload, "User", "user", "TargetUserName", "SubjectUserName", "AccountName"))
    image = clean_string(_get_nested_field(payload, "Image", "image", "NewProcessName", "ProcessName"))
    cmdline = clean_string(_get_nested_field(payload, "CommandLine", "command_line", "ProcessCommandLine"))
    parent_image = clean_string(_get_nested_field(payload, "ParentImage", "parent_image"))
    parent_cmdline = clean_string(_get_nested_field(payload, "ParentCommandLine", "parent_command_line"))
    hashes = clean_string(_get_nested_field(payload, "Hashes", "hashes", "FileHashes"))

    # Map Event Types and Specific Telemetry per Event ID
    event_type: str
    process_id: int | None = None
    parent_process_id: int | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    ip_address: str | None = None
    port: int | None = None

    if event_id == 1:
        # Sysmon Event ID 1: Process Creation
        event_type = "PROCESS_CREATE"
        process_id = parse_int_field(_get_nested_field(payload, "ProcessId", "ProcessID", "PID"), "ProcessId")
        parent_process_id = parse_int_field(
            _get_nested_field(payload, "ParentProcessId", "ParentProcessID", "PPID"), "ParentProcessId"
        )

    elif event_id == 3:
        # Sysmon Event ID 3: Network Connection
        event_type = "NETWORK_CONNECT"
        process_id = parse_int_field(_get_nested_field(payload, "ProcessId", "ProcessID", "PID"), "ProcessId")
        ip_address = clean_string(_get_nested_field(payload, "DestinationIp", "DestinationIP", "IpAddress"))
        port = parse_int_field(_get_nested_field(payload, "DestinationPort", "Port"), "port")

    elif event_id == 5:
        # Sysmon Event ID 5: Process Termination
        event_type = "PROCESS_TERMINATE"
        process_id = parse_int_field(_get_nested_field(payload, "ProcessId", "ProcessID", "PID"), "ProcessId")

    elif event_id == 4624:
        # Windows Security Event ID 4624: Successful Logon
        event_type = "USER_LOGON"
        logon_id = clean_string(_get_nested_field(payload, "TargetLogonId", "SubjectLogonId", "LogonId"))
        logon_type = parse_int_field(_get_nested_field(payload, "LogonType"), "LogonType")
        ip_address = clean_string(_get_nested_field(payload, "IpAddress", "SourceNetworkAddress", "WorkstationName"))
        port = parse_int_field(_get_nested_field(payload, "IpPort", "SourcePort"), "port")

    elif event_id == 4625:
        # Windows Security Event ID 4625: Failed Logon
        event_type = "LOGON_FAILURE"
        logon_type = parse_int_field(_get_nested_field(payload, "LogonType"), "LogonType")
        ip_address = clean_string(_get_nested_field(payload, "IpAddress", "SourceNetworkAddress"))
        port = parse_int_field(_get_nested_field(payload, "IpPort", "SourcePort"), "port")

    elif event_id == 4688:
        # Windows Security Event ID 4688: Process Creation
        event_type = "PROCESS_CREATE"
        # 4688 uses NewProcessId and CreatorProcessId, frequently in hexadecimal notation (0x1a4)
        process_id = parse_int_field(
            _get_nested_field(payload, "NewProcessId", "ProcessId", "PID"), "NewProcessId", allow_hex=True
        )
        parent_process_id = parse_int_field(
            _get_nested_field(payload, "CreatorProcessId", "ParentProcessId", "PPID"),
            "CreatorProcessId",
            allow_hex=True,
        )
        logon_id = clean_string(_get_nested_field(payload, "TargetLogonId", "SubjectLogonId"))

    else:
        raise NormalizationError(f"Unhandled supported event ID: {event_id}")

    return NormalizedEndpointEvent(
        event_time=event_time,
        host=host,
        user=user,
        event_id=event_id,
        event_type=event_type,
        process_id=process_id,
        parent_process_id=parent_process_id,
        image=image,
        command_line=cmdline,
        parent_image=parent_image,
        parent_command_line=parent_cmdline,
        logon_id=logon_id,
        logon_type=logon_type,
        ip_address=ip_address,
        port=port,
        hashes=hashes,
        raw_event_id=raw_event_id,
    )
