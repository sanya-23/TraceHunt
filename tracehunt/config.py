"""Configuration management for TraceHunt.

Loads settings from environment variables and optional .env file with
strongly-typed defaults and directory auto-creation.
"""

from pathlib import Path
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """TraceHunt global application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite:///./data/tracehunt.db",
        description="SQLAlchemy database URI (SQLite for MVP, PostgreSQL compatible)",
    )

    # Ingestion Constraints
    MAX_UPLOAD_SIZE_MB: int = Field(
        default=50,
        description="Maximum upload size in megabytes for telemetry batch files",
    )
    INGESTION_BATCH_SIZE: int = Field(
        default=500,
        description="Number of events processed per database commit batch",
    )

    # Logging Configuration
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["console", "json"] = "console"

    # API & Dashboard Networking
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    DASHBOARD_PORT: int = 8501

    # Storage Paths
    BASE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data")
    REPORTS_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "reports")

    def ensure_directories(self) -> None:
        """Ensure necessary runtime directories exist on the filesystem."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# Global settings singleton
settings = Settings()
settings.ensure_directories()
