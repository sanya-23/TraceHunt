"""Base definitions, contracts, and interfaces for behavioral detection rules.

Defines the BaseRule abstract class, RuleMatch schema, DetectionContext
for contextual event and process-graph access, and DetectionSummary for run telemetry.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
import networkx as nx

from tracehunt.models import EndpointEvent, Finding


def extract_process_name(image_path: str | None) -> str:
    """Extract lowercase process binary name supporting both Windows (\\) and POSIX (/) path separators."""
    if not image_path:
        return ""
    # Normalize forward slashes to backslashes and extract tail component
    cleaned = image_path.replace("/", "\\").strip()
    parts = [p for p in cleaned.split("\\") if p]
    return parts[-1].lower() if parts else ""


@dataclass
class RuleMatch:
    """Structure returned by a rule when a behavioral detection criteria is met."""

    rule_id: str
    endpoint_event_id: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: str  # LOW, MEDIUM, HIGH
    rationale: str
    matched_fields: dict[str, Any]
    caveats: str | None = None

    def to_finding(self) -> Finding:
        """Convert this match into an unpersisted SQLAlchemy Finding instance."""
        return Finding(
            rule_id=self.rule_id,
            endpoint_event_id=self.endpoint_event_id,
            severity=self.severity,
            confidence=self.confidence,
            rationale=self.rationale,
            matched_fields=self.matched_fields,
            caveats=self.caveats,
        )


class DetectionContext:
    """Provides contextual execution data (process graph, surrounding events) to detection rules."""

    def __init__(
        self,
        events: list[EndpointEvent] | None = None,
        process_graph: nx.DiGraph | None = None,
    ) -> None:
        self.events: list[EndpointEvent] = events or []
        self.process_graph: nx.DiGraph | None = process_graph
        self._events_by_id: dict[int, EndpointEvent] = {
            e.id: e for e in self.events if e.id is not None
        }

    def get_event_by_id(self, event_id: int) -> EndpointEvent | None:
        """Retrieve an endpoint event by primary key ID."""
        return self._events_by_id.get(event_id)

    def get_parent_event(self, child_event: EndpointEvent) -> EndpointEvent | None:
        """Retrieve parent EndpointEvent using process graph predecessors or direct lookup."""
        if child_event.id is None:
            return None

        # 1. Attempt lookup via process graph predecessor edge
        if self.process_graph and child_event.id in self.process_graph:
            predecessors = list(self.process_graph.predecessors(child_event.id))
            if predecessors:
                parent_id = predecessors[0]
                if parent_id in self._events_by_id:
                    return self._events_by_id[parent_id]

        # 2. Fallback to matching child's parent_process_id on same host prior to child
        if child_event.parent_process_id:
            candidates = [
                e
                for e in self.events
                if e.host == child_event.host
                and e.process_id == child_event.parent_process_id
                and e.event_time <= child_event.event_time
                and e.id != child_event.id
            ]
            if candidates:
                return max(candidates, key=lambda c: (c.event_time, c.id or 0))

        return None

    def get_prior_events(
        self,
        current_event: EndpointEvent,
        lookback_seconds: int = 300,
        event_types: list[str] | None = None,
    ) -> list[EndpointEvent]:
        """Retrieve events on the same host preceding current_event within lookback window."""
        window_start = current_event.event_time - timedelta(seconds=lookback_seconds)
        matching = []
        for e in self.events:
            if e.host != current_event.host:
                continue
            if window_start <= e.event_time <= current_event.event_time:
                if event_types is None or e.event_type in event_types:
                    matching.append(e)
        return matching


class BaseRule(ABC):
    """Abstract base class for all explainable behavioral detection rules."""

    id: str
    name: str
    version: str = "1.0.0"
    description: str
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    mitre_technique: str | None = None
    enabled: bool = True

    @abstractmethod
    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate a single endpoint event within the provided detection context."""
        pass

    def evaluate_batch(
        self, events: list[EndpointEvent], context: DetectionContext
    ) -> list[RuleMatch]:
        """Evaluate a batch of endpoint events. Can be overridden for multi-event correlation rules."""
        matches: list[RuleMatch] = []
        for event in events:
            result = self.evaluate(event, context)
            if result:
                matches.extend(result)
        return matches

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id='{self.id}' v='{self.version}' enabled={self.enabled}>"


@dataclass
class DetectionSummary:
    """Summary of a detection engine evaluation run."""

    events_examined: int = 0
    rules_evaluated: int = 0
    findings_created: int = 0
    duplicates_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to JSON-compatible dictionary."""
        return {
            "events_examined": self.events_examined,
            "rules_evaluated": self.rules_evaluated,
            "findings_created": self.findings_created,
            "duplicates_skipped": self.duplicates_skipped,
            "error_count": len(self.errors),
            "errors": self.errors,
            "finding_ids": [f.id for f in self.findings if f.id is not None],
        }
