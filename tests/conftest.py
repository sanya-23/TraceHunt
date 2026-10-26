"""Pytest configuration and shared fixtures for TraceHunt test suite."""

from collections.abc import Generator
import pytest
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from tracehunt.models import Base
from tracehunt.database import seed_default_rules


@pytest.fixture(scope="session")
def test_engine() -> Engine:
    """Create an in-memory SQLite engine with foreign key enforcement for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def test_session(test_engine: Engine) -> Generator[Session, None, None]:
    """Provide an isolated database session per test with automatic rollback or clean tables."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection, autoflush=False, autocommit=False)
    session = session_factory()

    # Pre-seed default detection rules in test session
    seed_default_rules(session)

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()
