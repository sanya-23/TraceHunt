"""Custom exception hierarchy for TraceHunt.

Enables precise error categorization, structured logging, and non-fatal
error recovery during ingestion and processing.
"""


class TraceHuntError(Exception):
    """Base exception for all TraceHunt domain errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(TraceHuntError):
    """Raised when environment or settings configuration is invalid."""


class DatabaseError(TraceHuntError):
    """Raised on database connection, constraint violation, or transaction failure."""


class IngestionError(TraceHuntError):
    """Raised when an imported file is unreadable, oversized, or fundamentally corrupted."""


class ValidationError(TraceHuntError):
    """Raised when record data violates schema constraints."""


class NormalizationError(TraceHuntError):
    """Raised when field normalization fails for an event record."""


class GraphReconstructionError(TraceHuntError):
    """Raised on invalid process tree graph reconstruction state."""


class RuleEvaluationError(TraceHuntError):
    """Raised when a behavioral detection rule encounters an unrecoverable evaluation error."""


class CaseManagementError(TraceHuntError):
    """Raised when case transitions, evidence linking, or audit logging fails."""


class ReportExportError(TraceHuntError):
    """Raised when JSON or HTML report generation encounters an error."""
