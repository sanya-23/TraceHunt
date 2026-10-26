"""Structured logging configuration for TraceHunt.

Provides formatted console logs for analysts and JSON structured logs
for automated SIEM integration, honoring application settings.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any
from tracehunt.config import settings


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_data.update(record.extra_fields)
        return json.dumps(log_data)


class ConsoleFormatter(logging.Formatter):
    """Human-readable colored/structured console formatter for security analysts."""

    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        time_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{time_str}] [{color}{record.levelname:<8}{self.RESET}] [{record.name}]"
        msg = f"{prefix} {record.getMessage()}"
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"
        return msg


def setup_logging() -> None:
    """Initialize root logger handler based on application configuration."""
    root_logger = logging.getLogger("tracehunt")
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if settings.LOG_FORMAT == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(ConsoleFormatter())

    root_logger.addHandler(handler)
    root_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Retrieve a namespaced child logger under tracehunt."""
    return logging.getLogger(f"tracehunt.{name}")


# Initialize logging upon module import
setup_logging()
