"""RULE-005-AUTH-ANOMALY: Authentication anomaly followed by process execution."""

from datetime import timedelta
from tracehunt.detection.base import BaseRule, DetectionContext, RuleMatch
from tracehunt.models import EndpointEvent


def normalize_username(user: str | None) -> str:
    """Normalize username by stripping domain prefixes (CORP\\admin) or UPN suffixes (admin@corp)."""
    if not user:
        return ""
    cleaned = user.replace("/", "\\").split("\\")[-1].strip().lower()
    return cleaned.split("@")[0]


class Rule005AuthAnomaly(BaseRule):
    """Detects repeated authentication failures on a host followed rapidly by process execution."""

    id = "RULE-005-AUTH-ANOMALY"
    name = "Rapid Authentication Anomaly"
    version = "1.0.0"
    description = (
        "Detects a threshold of authentication failures (Event 4625 / LOGON_FAILURE) on a host "
        "rapidly followed by process execution within a configurable temporal window (default: 300 seconds)."
    )
    severity = "HIGH"
    confidence_level = "MEDIUM"
    mitre_technique = "T1110"
    enabled = True

    # Correlation parameters
    DEFAULT_LOOKBACK_SECONDS: int = 300  # 5 minutes
    FAILURE_THRESHOLD: int = 3  # Minimum 3 failures required

    def __init__(
        self,
        lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
        failure_threshold: int = FAILURE_THRESHOLD,
    ) -> None:
        self.lookback_seconds = lookback_seconds
        self.failure_threshold = failure_threshold

    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate if a process creation event was immediately preceded by repeated logon failures."""
        if event.event_type != "PROCESS_CREATE" or not event.host:
            return []

        # Find preceding logon failure events on the same host within the temporal window
        prior_events = context.get_prior_events(
            current_event=event,
            lookback_seconds=self.lookback_seconds,
            event_types=["LOGON_FAILURE"],
        )

        # Filter: if event has a specific user, check matching user failures or failures with same host
        matching_failures: list[EndpointEvent] = []
        event_norm_user = normalize_username(event.user)

        for fail in prior_events:
            fail_norm_user = normalize_username(fail.user)
            # If both have user information, require normalized user matching
            if event_norm_user and fail_norm_user:
                if event_norm_user == fail_norm_user:
                    matching_failures.append(fail)
            else:
                # If either lacks user identity, correlate on host boundary
                matching_failures.append(fail)

        if len(matching_failures) < self.failure_threshold:
            return []

        failure_timestamps = [f.event_time.isoformat() for f in matching_failures]
        failure_ips = list({f.ip_address for f in matching_failures if f.ip_address})

        rationale = (
            f"Host '{event.host}' experienced {len(matching_failures)} authentication failures within "
            f"{self.lookback_seconds} seconds immediately prior to process '{event.image or event.process_id}' execution. "
            f"Target account: '{event.user or 'Unspecified'}'. This pattern indicates potential brute-force, password guessing, "
            f"or compromised credential abuse leading directly to execution."
        )

        match = RuleMatch(
            rule_id=self.id,
            endpoint_event_id=event.id,
            severity=self.severity,
            confidence=self.confidence_level,
            rationale=rationale,
            matched_fields={
                "host": event.host,
                "user": event.user,
                "failure_count": len(matching_failures),
                "failure_threshold": self.failure_threshold,
                "lookback_seconds": self.lookback_seconds,
                "failure_timestamps": failure_timestamps,
                "source_ip_addresses": failure_ips,
                "executed_image": event.image,
                "executed_command_line": event.command_line,
                "executed_pid": event.process_id,
            },
            caveats=(
                "Users occasionally mistype expired passwords repeatedly before successfully authenticating, "
                "followed by regular application startup. Correlate with source IP and user logon history."
            ),
        )
        return [match]
