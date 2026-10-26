"""Behavioral Detection Engine orchestrating rule registration, evaluation, and finding persistence."""

from collections import defaultdict
from typing import Any
import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.detection.base import (
    BaseRule,
    DetectionContext,
    DetectionSummary,
    RuleMatch,
)
from tracehunt.detection.rules import get_default_rules
from tracehunt.graph.reconstructor import build_host_process_graph
from tracehunt.logging_config import get_logger
from tracehunt.models import EndpointEvent, Finding

logger = get_logger("detection.engine")


class DetectionEngine:
    """Manages and executes behavioral threat hunting detection rules against endpoint telemetry."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self._rules: dict[str, BaseRule] = {}
        initial_rules = rules if rules is not None else get_default_rules()
        for r in initial_rules:
            self.register_rule(r)

    def register_rule(self, rule: BaseRule) -> None:
        """Register or update a detection rule."""
        self._rules[rule.id] = rule
        logger.debug(f"Registered detection rule: {rule.id} ({rule.name}) v{rule.version}")

    def get_rule(self, rule_id: str) -> BaseRule | None:
        """Retrieve a registered rule by its rule ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseRule]:
        """Return all registered detection rules."""
        return list(self._rules.values())

    @property
    def rules(self) -> list[BaseRule]:
        """Property returning all registered detection rules."""
        return self.list_rules()

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID. Returns True if rule was found and enabled."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = True
            logger.info(f"Enabled detection rule '{rule_id}'.")
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID. Returns True if rule was found and disabled."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = False
            logger.info(f"Disabled detection rule '{rule_id}'.")
            return True
        return False

    def evaluate_events(
        self,
        events: list[EndpointEvent],
        process_graph: nx.DiGraph | None = None,
        session: Session | None = None,
        persist: bool = True,
    ) -> DetectionSummary:
        """Evaluate all enabled rules across a list of endpoint events.

        Performs:
        1. Context construction (chronological sorting, process graph resolution).
        2. Filter to enabled rules.
        3. Isolated evaluation per rule with error capture.
        4. Idempotent finding generation (checks database & in-batch duplicates).
        5. Transactional persistence in findings table.
        """
        summary = DetectionSummary()
        if not events:
            return summary

        # 1. Sort events chronologically by UTC event_time ASC (and id ASC)
        sorted_events = sorted(events, key=lambda e: (e.event_time, e.id or 0))
        summary.events_examined = len(sorted_events)

        # 2. Build or verify detection context
        context = DetectionContext(events=sorted_events, process_graph=process_graph)

        # 3. Collect enabled rules
        enabled_rules = [r for r in self._rules.values() if r.enabled]
        summary.rules_evaluated = len(enabled_rules)

        raw_matches: list[RuleMatch] = []
        for rule in enabled_rules:
            try:
                matches = rule.evaluate_batch(sorted_events, context)
                if matches:
                    raw_matches.extend(matches)
            except Exception as exc:
                error_msg = f"Rule '{rule.id}' encountered evaluation error: {exc}"
                logger.error(error_msg, exc_info=True)
                summary.errors.append(error_msg)

        if not raw_matches:
            return summary

        # 4. Idempotent Deduplication
        # Query existing findings in database for candidate events to avoid duplicates
        existing_pairs: set[tuple[str, int]] = set()
        candidate_event_ids = [m.endpoint_event_id for m in raw_matches if m.endpoint_event_id]

        if session and candidate_event_ids:
            stmt = select(Finding.rule_id, Finding.endpoint_event_id).where(
                Finding.endpoint_event_id.in_(candidate_event_ids)
            )
            for r_id, ev_id in session.execute(stmt):
                existing_pairs.add((r_id, ev_id))

        in_batch_pairs: set[tuple[str, int]] = set()
        persisted_findings: list[Finding] = []

        for match in raw_matches:
            pair = (match.rule_id, match.endpoint_event_id)
            if pair in existing_pairs or pair in in_batch_pairs:
                summary.duplicates_skipped += 1
                continue

            in_batch_pairs.add(pair)
            finding = match.to_finding()

            if session and persist:
                session.add(finding)

            persisted_findings.append(finding)
            summary.findings_created += 1

        if session and persist and persisted_findings:
            session.commit()
            logger.info(
                f"Persisted {len(persisted_findings)} new findings to database "
                f"({summary.duplicates_skipped} duplicates skipped)."
            )

        summary.findings = persisted_findings
        return summary

    def evaluate_host(
        self,
        host: str,
        session: Session,
        persist: bool = True,
    ) -> DetectionSummary:
        """Query all events for a host, build process graph, and execute detection rules."""
        stmt = (
            select(EndpointEvent)
            .where(EndpointEvent.host == host)
            .order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())
        )
        events = list(session.scalars(stmt).all())
        if not events:
            return DetectionSummary()

        # Reconstruct process graph for context
        graph, _ = build_host_process_graph(events)

        return self.evaluate_events(
            events=events,
            process_graph=graph,
            session=session,
            persist=persist,
        )
