"""Tests for Configuration, Logging, and Error Handling modules."""

import json
import logging
import os
from pathlib import Path
from tracehunt.config import Settings
from tracehunt.exceptions import (
    DatabaseError,
    IngestionError,
    TraceHuntError,
    ValidationError,
)
from tracehunt.logging_config import ConsoleFormatter, JSONFormatter, get_logger
from tracehunt.database import init_db
from sqlalchemy import inspect


def test_settings_default_and_environment_override(monkeypatch, tmp_path):
    """Verify settings defaults and environment variable overrides."""
    db_path = tmp_path / "custom.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("MAX_UPLOAD_SIZE_MB", "100")

    custom_settings = Settings()
    assert custom_settings.DATABASE_URL == f"sqlite:///{db_path}"
    assert custom_settings.LOG_LEVEL == "DEBUG"
    assert custom_settings.MAX_UPLOAD_SIZE_MB == 100


def test_exceptions_hierarchy_and_serialization():
    """Verify domain exception hierarchy and structured serialization."""
    err = IngestionError("Corrupted CSV header", details={"line": 1, "found": "unknown"})
    assert isinstance(err, TraceHuntError)
    err_dict = err.to_dict()
    assert err_dict["error_type"] == "IngestionError"
    assert err_dict["message"] == "Corrupted CSV header"
    assert err_dict["details"]["line"] == 1


def test_json_and_console_logging_formatters():
    """Verify JSONFormatter and ConsoleFormatter produce valid outputs."""
    record = logging.LogRecord(
        name="tracehunt.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=42,
        msg="Suspicious process detected: %s",
        args=("certutil.exe",),
        exc_info=None,
    )

    # Test JSON formatter
    json_formatter = JSONFormatter()
    json_output = json_formatter.format(record)
    parsed = json.loads(json_output)
    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "tracehunt.test"
    assert "Suspicious process detected: certutil.exe" in parsed["message"]
    assert "timestamp" in parsed

    # Test Console formatter
    console_formatter = ConsoleFormatter()
    console_output = console_formatter.format(record)
    assert "WARNING" in console_output
    assert "tracehunt.test" in console_output
    assert "Suspicious process detected: certutil.exe" in console_output


def test_init_db_creates_physical_sqlite_database(tmp_path):
    """Verify init_db initializes a physical SQLite database file with all tables."""
    db_file = tmp_path / "test_init.db"
    db_url = f"sqlite:///{db_file}"

    engine = init_db(database_url=db_url, seed_rules=True)
    assert db_file.exists()

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "endpoint_events" in tables
    assert "detection_rules" in tables
    assert "raw_events" in tables
