"""Deterministic SHA-256 event fingerprinting and idempotency management.

Ensures that re-importing the same file or identical records does not create
duplicate raw or normalized events, while preventing false-positive merges
of distinct events.
"""

import hashlib
import json
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from tracehunt.models import RawEvent


def canonicalize_payload(payload: dict[str, Any] | list[Any] | str) -> str:
    """Produce a deterministic, whitespace-normalized JSON string for hashing.

    Dictionaries have keys sorted recursively, and floating/datetime values
    are string-converted consistently.
    """
    if isinstance(payload, str):
        try:
            # Parse and re-serialize to normalize whitespace and formatting
            parsed = json.loads(payload)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            # Raw string fallback
            return payload.strip()

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_sha256_fingerprint(data: dict[str, Any] | str) -> str:
    """Compute SHA-256 hex digest of canonicalized event data."""
    canonical = canonicalize_payload(data)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_event_fingerprint(
    host: str,
    event_id: int,
    event_time_iso: str,
    process_id: int | None = None,
    parent_process_id: int | None = None,
    image: str | None = None,
    command_line: str | None = None,
    user: str | None = None,
    record_id: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
) -> str:
    """Compute a forensic fingerprint representing a distinct endpoint event occurrence.

    Combines temporal, process, identity, and record fields to ensure distinct
    events occurring at the same second are not incorrectly merged.
    """
    signature = {
        "host": host.upper().strip(),
        "event_id": event_id,
        "time": event_time_iso,
        "pid": process_id,
        "ppid": parent_process_id,
        "image": image.lower().strip() if image else None,
        "cmd": command_line.strip() if command_line else None,
        "user": user.lower().strip() if user else None,
        "rec_id": str(record_id).strip() if record_id else None,
        "dst_ip": destination_ip.strip() if destination_ip else None,
        "dst_port": destination_port,
    }
    return compute_sha256_fingerprint(signature)


class IdempotencyManager:
    """Tracks and checks event fingerprints against database records to prevent duplicate ingestion."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._cached_hashes: set[str] = set()

    def filter_existing_hashes(self, candidate_hashes: set[str]) -> set[str]:
        """Return the subset of candidate_hashes that already exist in raw_events."""
        if not candidate_hashes:
            return set()

        stmt = select(RawEvent.sha256_hash).where(RawEvent.sha256_hash.in_(candidate_hashes))
        results = self.session.scalars(stmt).all()
        existing = set(results)
        self._cached_hashes.update(existing)
        return existing

    def is_hash_existing(self, sha256_hash: str) -> bool:
        """Check if a specific SHA-256 hash already exists in raw_events."""
        if sha256_hash in self._cached_hashes:
            return True
        stmt = select(RawEvent.id).where(RawEvent.sha256_hash == sha256_hash).limit(1)
        exists = self.session.scalar(stmt) is not None
        if exists:
            self._cached_hashes.add(sha256_hash)
        return exists
