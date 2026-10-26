"""RULE-001-LOLBIN: Suspicious use of legitimate system binaries (Living-Off-The-Land)."""

import os
import re
from tracehunt.detection.base import (
    BaseRule,
    DetectionContext,
    RuleMatch,
    extract_process_name,
)
from tracehunt.models import EndpointEvent


class Rule001Lolbin(BaseRule):
    """Detects living-off-the-land binaries (certutil, bitsadmin, mshta, powershell) with suspicious flags."""

    id = "RULE-001-LOLBIN"
    name = "Suspicious LOLBIN Execution"
    version = "1.0.0"
    description = (
        "Detects legitimate Windows system utilities (certutil, bitsadmin, mshta, powershell) "
        "executed with suspicious download, staging, or encoded-execution command-line flags."
    )
    severity = "HIGH"
    confidence_level = "HIGH"
    mitre_technique = "T1218"
    enabled = True

    # Utility definitions and their specific suspicious command-line patterns
    # Each entry maps process binary name to list of required indicators
    PATTERNS: dict[str, list[str]] = {
        "certutil.exe": ["-urlcache", "-split", "-f", "-decode"],
        "certutil": ["-urlcache", "-split", "-f", "-decode"],
        "bitsadmin.exe": ["/transfer", "/create", "/addfile", "/download"],
        "bitsadmin": ["/transfer", "/create", "/addfile", "/download"],
        "powershell.exe": [
            "-enc",
            "-encodedcommand",
            "-e ",
            "-en ",
            "-encoded ",
        ],
        "powershell": [
            "-enc",
            "-encodedcommand",
            "-e ",
            "-en ",
            "-encoded ",
        ],
        "pwsh.exe": [
            "-enc",
            "-encodedcommand",
            "-e ",
            "-en ",
            "-encoded ",
        ],
        "pwsh": [
            "-enc",
            "-encodedcommand",
            "-e ",
            "-en ",
            "-encoded ",
        ],
        "mshta.exe": [
            "http://",
            "https://",
            "javascript:",
            "vbscript:",
            "about:",
        ],
        "mshta": [
            "http://",
            "https://",
            "javascript:",
            "vbscript:",
            "about:",
        ],
    }

    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate if process creation event executes a LOLBin with suspicious flags."""
        if event.event_type != "PROCESS_CREATE" or not event.image or not event.command_line:
            return []

        binary_name = extract_process_name(event.image)
        if binary_name not in self.PATTERNS:
            return []

        cmd_lower = event.command_line.lower()
        required_patterns = self.PATTERNS[binary_name]

        matched_indicators = [
            pat for pat in required_patterns if pat in cmd_lower
        ]

        if not matched_indicators:
            return []

        rationale = (
            f"Legitimate binary '{binary_name}' was executed with suspicious command-line flag(s): "
            f"{', '.join(matched_indicators)}. Adversaries frequently abuse these built-in utilities "
            f"to download payloads, decode hidden scripts, or evade defensive controls."
        )

        match = RuleMatch(
            rule_id=self.id,
            endpoint_event_id=event.id,
            severity=self.severity,
            confidence=self.confidence_level,
            rationale=rationale,
            matched_fields={
                "utility": binary_name,
                "image": event.image,
                "command_line": event.command_line,
                "matched_indicators": matched_indicators,
                "host": event.host,
                "user": event.user,
            },
            caveats=(
                "Administrative scripts occasionally use certutil for certificate validation or bitsadmin "
                "for background patch distribution. Confirm whether the target URL or decode output is authorized."
            ),
        )
        return [match]
