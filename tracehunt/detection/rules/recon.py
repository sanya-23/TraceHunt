"""RULE-003-RECON: Reconnaissance and Credential Discovery."""

import os
import re
from tracehunt.detection.base import (
    BaseRule,
    DetectionContext,
    RuleMatch,
    extract_process_name,
)
from tracehunt.models import EndpointEvent


class Rule003Recon(BaseRule):
    """Detects system enumeration, active directory discovery, and registry hive dumping commands."""

    id = "RULE-003-RECON"
    name = "Reconnaissance & Credential Discovery"
    version = "1.0.0"
    description = (
        "Detects command-line discovery tools (whoami /all, net user, nltest /dclist, reg save) "
        "commonly used during adversary post-exploitation reconnaissance or credential harvesting."
    )
    severity = "MEDIUM"
    confidence_level = "MEDIUM"
    mitre_technique = "T1087"
    enabled = True

    # Sensitive registry hives targeted for credential extraction
    SENSITIVE_HIVES: list[str] = ["sam", "system", "security"]

    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate if process creation executed reconnaissance or discovery commands."""
        if event.event_type != "PROCESS_CREATE" or not event.image or not event.command_line:
            return []

        binary_name = extract_process_name(event.image)
        cmd_lower = event.command_line.lower()

        matched_command: str | None = None
        matched_indicators: list[str] = []
        technique_detail: str = ""

        # 1. whoami with privileges / groups enumeration
        if binary_name in ("whoami.exe", "whoami"):
            flags = ["/all", "/priv", "/groups", "-all", "-priv", "-groups"]
            found = [f for f in flags if f in cmd_lower]
            if found:
                matched_command = "whoami"
                matched_indicators = found
                technique_detail = "Local account privileges and security group enumeration"

        # 2. net / net1 user or group enumeration
        elif binary_name in ("net.exe", "net", "net1.exe", "net1"):
            # Avoid matching net start / net stop / net use / etc.
            recon_keywords = ["user", "group", "localgroup", "accounts", "share", "view"]
            tokens = cmd_lower.split()
            found_recon = [k for k in recon_keywords if k in tokens]
            if found_recon:
                matched_command = "net"
                matched_indicators = found_recon
                if "/domain" in cmd_lower or "-domain" in cmd_lower:
                    matched_indicators.append("/domain")
                    technique_detail = "Domain user and group enumeration against Active Directory"
                else:
                    technique_detail = "Local user, group, or share enumeration"

        # 3. nltest domain / DC discovery
        elif binary_name in ("nltest.exe", "nltest"):
            nltest_flags = ["/dclist", "/dsgetdc", "/domain_trusts", "/user", "/server", "/parentdomain"]
            found = [f for f in nltest_flags if f in cmd_lower]
            if found:
                matched_command = "nltest"
                matched_indicators = found
                technique_detail = "Domain Controller and trust relationship discovery via NetLogon"

        # 4. reg save / reg export targeting SAM or SYSTEM hives
        elif binary_name in ("reg.exe", "reg"):
            if "save" in cmd_lower or "export" in cmd_lower:
                hives_found = [h for h in self.SENSITIVE_HIVES if re.search(rf"\b(hklm\\)?{h}\b", cmd_lower)]
                if hives_found:
                    matched_command = "reg"
                    matched_indicators = ["save/export", *hives_found]
                    technique_detail = f"Dumping sensitive registry hive ({', '.join(hives_found).upper()}) for offline password hash extraction"

        if not matched_command:
            return []

        rationale = (
            f"Discovery command detected: '{binary_name}' was invoked with indicator(s) "
            f"{matched_indicators}. Activity category: {technique_detail}. Adversaries execute these "
            f"commands during discovery to map accounts and locate credential material."
        )

        match = RuleMatch(
            rule_id=self.id,
            endpoint_event_id=event.id,
            severity=self.severity,
            confidence=self.confidence_level,
            rationale=rationale,
            matched_fields={
                "command": matched_command,
                "binary": binary_name,
                "image": event.image,
                "command_line": event.command_line,
                "matched_indicators": matched_indicators,
                "technique_detail": technique_detail,
                "host": event.host,
                "user": event.user,
            },
            caveats=(
                "System administrators and deployment scripts legitimately run net, whoami, or nltest "
                "for troubleshooting and auditing. Correlate with parent process context and user privileges."
            ),
        )
        return [match]
