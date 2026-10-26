"""Database engine factory, session management, and schema initialization.

Supports SQLite (with strict foreign keys enabled) and PostgreSQL portability,
transaction management with rollback on error, and detection rule pre-seeding.
"""

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from tracehunt.config import settings
from tracehunt.logging_config import get_logger
from tracehunt.models import (
    Base,
    DetectionRule,
)

logger = get_logger("database")

# Global engine and session factory singletons
_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine(database_url: str | None = None) -> Engine:
    """Retrieve or create the SQLAlchemy database engine."""
    global _engine
    url = database_url or settings.DATABASE_URL

    if _engine is not None and str(_engine.url) == url:
        return _engine

    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        url,
        connect_args=connect_args,
        echo=(settings.ENVIRONMENT == "development" and settings.LOG_LEVEL == "DEBUG"),
    )

    # Enforce SQLite foreign key constraints
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _engine = engine
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Retrieve or create session factory bound to current engine."""
    global _SessionFactory
    eng = engine or get_engine()
    if _SessionFactory is None or _SessionFactory.kw.get("bind") != eng:
        _SessionFactory = sessionmaker(bind=eng, autoflush=False, autocommit=False)
    return _SessionFactory


@contextmanager
def get_db_session(engine: Engine | None = None) -> Generator[Session, None, None]:
    """Transactional context manager with automatic commit on success and rollback on exception."""
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database transaction rolled back due to error: {e}", exc_info=True)
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI route dependency yielding a transactional database session."""
    with get_db_session() as session:
        yield session


def seed_default_rules(session: Session) -> int:
    """Seed default behavioral detection rules if not already present."""
    default_rules = [
        DetectionRule(
            id="RULE-001-LOLBIN",
            name="Suspicious LOLBIN Execution",
            version="1.0.0",
            description="Detects living-off-the-land binaries (certutil, bitsadmin, mshta, powershell) executed with suspicious download or encoding flags.",
            severity="HIGH",
            confidence_level="HIGH",
            mitre_technique="T1218",
            enabled=True,
        ),
        DetectionRule(
            id="RULE-002-PROC-SPAWN",
            name="Suspicious Office/Browser Child Process",
            version="1.0.0",
            description="Detects Microsoft Office applications or web browsers spawning command shells (cmd.exe, powershell.exe).",
            severity="HIGH",
            confidence_level="HIGH",
            mitre_technique="T1059",
            enabled=True,
        ),
        DetectionRule(
            id="RULE-003-RECON",
            name="Reconnaissance & Credential Discovery",
            version="1.0.0",
            description="Detects discovery commands typically used by adversaries for system enumeration or credential targeting.",
            severity="MEDIUM",
            confidence_level="MEDIUM",
            mitre_technique="T1087",
            enabled=True,
        ),
        DetectionRule(
            id="RULE-004-EVASION",
            name="Defense Evasion & Temp Execution",
            version="1.0.0",
            description="Detects execution of binaries or scripts from world-writable temporary paths (AppData\\Local\\Temp, C:\\Windows\\Temp).",
            severity="MEDIUM",
            confidence_level="MEDIUM",
            mitre_technique="T1027",
            enabled=True,
        ),
        DetectionRule(
            id="RULE-005-AUTH-ANOMALY",
            name="Rapid Authentication Anomaly",
            version="1.0.0",
            description="Detects anomalous logon patterns such as multiple logon failures followed by privileged process execution.",
            severity="HIGH",
            confidence_level="MEDIUM",
            mitre_technique="T1110",
            enabled=True,
        ),
    ]

    count = 0
    for rule in default_rules:
        existing = session.get(DetectionRule, rule.id)
        if not existing:
            session.add(rule)
            count += 1
    if count > 0:
        session.commit()
        logger.info(f"Seeded {count} default detection rules into database.")
    return count


def init_db(database_url: str | None = None, seed_rules: bool = True) -> Engine:
    """Create all tables defined in metadata and optionally seed default rules."""
    settings.ensure_directories()
    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database schema initialized successfully at {engine.url}")

    if seed_rules:
        factory = get_session_factory(engine)
        with factory() as session:
            seed_default_rules(session)

    return engine
