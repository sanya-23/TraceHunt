"""Tests for event schema normalization and timestamp handling."""

from datetime import datetime, timezone
import pytest
from tracehunt.exceptions import NormalizationError
from tracehunt.ingestion.normalizer import (
    normalize_event,
    parse_int_field,
    parse_timestamp,
)


def test_sysmon_process_creation_normalization():
    """Verify Sysmon Event ID 1 normalization into PROCESS_CREATE schema."""
    raw = {
        "EventID": 1,
        "UtcTime": "2026-10-21 14:30:15.123",
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentProcessId": 2040,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\alice",
        "Computer": "DESKTOP-TH01.corp.local",
        "Hashes": "SHA256=abcdef1234567890",
    }
    norm = normalize_event(raw)

    assert norm.event_id == 1
    assert norm.event_type == "PROCESS_CREATE"
    assert norm.host == "DESKTOP-TH01"
    assert norm.process_id == 4120
    assert norm.parent_process_id == 2040
    assert norm.image == "C:\\Windows\\System32\\cmd.exe"
    assert norm.command_line == "cmd.exe /c whoami"
    assert norm.user == "CORP\\alice"
    assert norm.hashes == "SHA256=abcdef1234567890"
    assert norm.event_time.tzinfo == timezone.utc
    assert norm.event_time.hour == 14
    assert norm.event_time.minute == 30


def test_sysmon_network_and_termination_normalization():
    """Verify Sysmon Event ID 3 (Network) and 5 (Termination) normalization."""
    raw_net = {
        "EventID": 3,
        "UtcTime": "2026-10-21 14:35:00.000",
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\curl.exe",
        "DestinationIp": "198.51.100.42",
        "DestinationPort": 443,
        "Computer": "DESKTOP-TH01",
    }
    norm_net = normalize_event(raw_net)
    assert norm_net.event_type == "NETWORK_CONNECT"
    assert norm_net.ip_address == "198.51.100.42"
    assert norm_net.port == 443

    raw_term = {
        "EventID": 5,
        "UtcTime": "2026-10-21 14:40:00.000",
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\curl.exe",
        "Computer": "DESKTOP-TH01",
    }
    norm_term = normalize_event(raw_term)
    assert norm_term.event_type == "PROCESS_TERMINATE"
    assert norm_term.process_id == 4120


def test_windows_security_logons_normalization():
    """Verify Security Event 4624 (Logon) and 4625 (Logon Failure)."""
    raw_success = {
        "EventID": 4624,
        "TimeCreated": "2026-10-21T10:00:00Z",
        "Computer": "SRV-DC01",
        "TargetUserName": "admin_bob",
        "TargetLogonId": "0x3e7",
        "LogonType": 2,
        "IpAddress": "10.0.1.5",
        "IpPort": 55432,
    }
    norm_success = normalize_event(raw_success)
    assert norm_success.event_type == "USER_LOGON"
    assert norm_success.user == "admin_bob"
    assert norm_success.logon_type == 2
    assert norm_success.ip_address == "10.0.1.5"
    assert norm_success.port == 55432

    raw_fail = {
        "EventID": 4625,
        "TimeCreated": "2026-10-21T10:05:00Z",
        "Computer": "SRV-DC01",
        "TargetUserName": "bad_actor",
        "LogonType": 3,
        "IpAddress": "192.168.1.200",
    }
    norm_fail = normalize_event(raw_fail)
    assert norm_fail.event_type == "LOGON_FAILURE"
    assert norm_fail.user == "bad_actor"
    assert norm_fail.ip_address == "192.168.1.200"


def test_windows_security_4688_with_hex_pids():
    """Verify Security Event 4688 with hexadecimal Process IDs (0x1a4)."""
    raw = {
        "EventID": 4688,
        "TimeCreated": "2026-10-21T14:15:00Z",
        "Computer": "WIN-TEST",
        "NewProcessId": "0x1a4",        # Hex 420
        "CreatorProcessId": "0x3f0",    # Hex 1008
        "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
        "CommandLine": "whoami /all",
        "SubjectUserName": "tester",
    }
    norm = normalize_event(raw)
    assert norm.event_type == "PROCESS_CREATE"
    assert norm.process_id == 420
    assert norm.parent_process_id == 1008
    assert norm.command_line == "whoami /all"
    assert norm.user == "tester"


def test_utc_timestamp_handling_and_offsets():
    """Verify timestamp parsing converts non-UTC offsets accurately to UTC."""
    # Paris time: 14:00 +02:00 -> 12:00 UTC
    dt_paris = parse_timestamp("2026-10-21T14:00:00+02:00")
    assert dt_paris.tzinfo == timezone.utc
    assert dt_paris.hour == 12

    # New York time: 14:00 -04:00 -> 18:00 UTC
    dt_ny = parse_timestamp("2026-10-21T14:00:00-04:00")
    assert dt_ny.tzinfo == timezone.utc
    assert dt_ny.hour == 18

    # Epoch timestamp
    dt_epoch = parse_timestamp(1729512000)
    assert dt_epoch.tzinfo == timezone.utc


def test_invalid_timestamps_raise_normalization_error():
    """Verify that unparseable or corrupted timestamps fail normalization."""
    with pytest.raises(NormalizationError):
        parse_timestamp("not_a_valid_date")

    with pytest.raises(NormalizationError):
        parse_timestamp(None)

    with pytest.raises(NormalizationError):
        parse_timestamp("")


def test_invalid_pids_and_ports_raise_error():
    """Verify invalid numeric values fail without silent corruption."""
    with pytest.raises(NormalizationError):
        parse_int_field("not_a_pid", "ProcessId")

    with pytest.raises(NormalizationError):
        parse_int_field("0xZ99", "ProcessId")  # Malformed hex

    # Port out of bounds in schema validation
    raw_bad_port = {
        "EventID": 3,
        "UtcTime": "2026-10-21 14:00:00.000",
        "Computer": "HOST1",
        "ProcessId": 1234,
        "DestinationPort": 70000,  # Invalid port > 65535
    }
    with pytest.raises(Exception):
        normalize_event(raw_bad_port)


def test_unsupported_event_id_raises_error():
    """Verify unsupported Event IDs are explicitly rejected."""
    raw = {
        "EventID": 9999,
        "UtcTime": "2026-10-21 14:00:00.000",
        "Computer": "HOST1",
    }
    with pytest.raises(NormalizationError) as exc_info:
        normalize_event(raw)
    assert "Unsupported Event ID" in str(exc_info.value)


def test_missing_mandatory_host_raises_error():
    """Verify event missing host / computer name raises NormalizationError."""
    raw = {
        "EventID": 1,
        "UtcTime": "2026-10-21 14:00:00.000",
    }
    with pytest.raises(NormalizationError) as exc_info:
        normalize_event(raw)
    assert "Missing mandatory host" in str(exc_info.value)


def test_nested_eventdata_structure():
    """Verify parser extracts fields from nested EventData / System XML-like JSON objects."""
    raw_nested = {
        "System": {
            "EventID": 1,
            "TimeCreated": "2026-10-21T14:30:00Z",
            "Computer": "NESTED-DC",
        },
        "EventData": {
            "ProcessId": "5000",
            "Image": "C:\\Windows\\notepad.exe",
            "CommandLine": "notepad.exe",
            "ParentProcessId": "1000",
            "User": "CORP\\analyst",
        },
    }
    norm = normalize_event(raw_nested)
    assert norm.event_id == 1
    assert norm.host == "NESTED-DC"
    assert norm.process_id == 5000
    assert norm.image == "C:\\Windows\\notepad.exe"
