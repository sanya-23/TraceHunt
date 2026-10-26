"""RULE-004-EVASION: Suspicious process execution from temporary directories."""

import os
import re
from tracehunt.detection.base import (
    BaseRule,
    DetectionContext,
    RuleMatch,
    extract_process_name,
)
from tracehunt.models import EndpointEvent


class Rule004Evasion(BaseRule):
    """Detects binaries or scripts executed from writable temporary directories (Temp, AppData\\Local\\Temp)."""

    id = "RULE-004-EVASION"
    name = "Defense Evasion & Temp Execution"
    version = "1.0.0"
    description = (
        "Detects executable binaries or scripts running out of world-writable user or system "
        "temporary folders (e.g. AppData\\Local\\Temp, Windows\\Temp, %TEMP%)."
    )
    severity = "MEDIUM"
    confidence_level = "MEDIUM"
    mitre_technique = "T1027"
    enabled = True

    # Common temporary path patterns in normalized Windows format (lowercase, backslashes)
    TEMP_PATTERNS: list[tuple[str, str]] = [
        (r"\\appdata\\local\\temp\\", "User Local AppData Temp folder"),
        (r"\\windows\\temp\\", "System Windows Temp folder"),
        (r"\\users\\[^\\]+\\temp\\", "User Profile Temp folder"),
        (r"\\temp\\", "Root or custom Temp directory"),
        (r"%temp%", "Environment variable Temp path"),
    ]

    # Monitored executable extensions
    EXECUTABLE_EXTENSIONS: set[str] = {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".vbs",
        ".ps1",
        ".scr",
        ".hta",
        ".js",
    }

    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate if process image is executing from a suspicious temporary directory."""
        if event.event_type != "PROCESS_CREATE" or not event.image:
            return []

        # Normalize path: convert forward slashes to backslashes and lowercase
        norm_path = event.image.replace("/", "\\").lower()

        _, ext = os.path.splitext(norm_path)
        if ext and ext not in self.EXECUTABLE_EXTENSIONS:
            return []

        matched_pattern_desc: str | None = None
        matched_regex: str | None = None

        for pattern, desc in self.TEMP_PATTERNS:
            if re.search(pattern, norm_path):
                matched_pattern_desc = desc
                matched_regex = pattern
                break

        if not matched_pattern_desc:
            return []

        binary_name = extract_process_name(event.image)
        rationale = (
            f"Process '{binary_name}' was executed from a temporary directory: {matched_pattern_desc} "
            f"('{event.image}'). Threat actors frequently drop unstaged payloads or staging scripts into "
            f"user-writable temp directories to bypass directory permissions and evade standard monitoring."
        )

        match = RuleMatch(
            rule_id=self.id,
            endpoint_event_id=event.id,
            severity=self.severity,
            confidence=self.confidence_level,
            rationale=rationale,
            matched_fields={
                "binary": binary_name,
                "image": event.image,
                "command_line": event.command_line,
                "matched_temp_location": matched_pattern_desc,
                "matched_pattern": matched_regex,
                "host": event.host,
                "user": event.user,
            },
            caveats=(
                "Legitimate software installers and updater packages (e.g. MSI helpers, Chrome installers) "
                "frequently unpack setup binaries into Temp. Verify whether the process is signed or part of a recognized installer."
            ),
        )
        return [match]
