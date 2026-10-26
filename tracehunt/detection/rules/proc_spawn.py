"""RULE-002-PROC-SPAWN: Suspicious Office or Browser child process spawning."""

import os
from tracehunt.detection.base import (
    BaseRule,
    DetectionContext,
    RuleMatch,
    extract_process_name,
)
from tracehunt.models import EndpointEvent


class Rule002ProcSpawn(BaseRule):
    """Detects Microsoft Office applications or web browsers spawning command interpreters."""

    id = "RULE-002-PROC-SPAWN"
    name = "Suspicious Office/Browser Child Process"
    version = "1.0.0"
    description = (
        "Detects productivity software (Word, Excel, PowerPoint, Outlook) or web browsers "
        "(Chrome, Edge, Firefox) directly spawning command shells (cmd.exe, powershell.exe, wscript.exe)."
    )
    severity = "HIGH"
    confidence_level = "HIGH"
    mitre_technique = "T1059"
    enabled = True

    OFFICE_PARENTS: set[str] = {
        "winword.exe",
        "winword",
        "excel.exe",
        "excel",
        "powerpnt.exe",
        "powerpnt",
        "outlook.exe",
        "outlook",
        "msaccess.exe",
        "msaccess",
        "eqnedt32.exe",
        "eqnedt32",
    }

    BROWSER_PARENTS: set[str] = {
        "chrome.exe",
        "chrome",
        "msedge.exe",
        "msedge",
        "firefox.exe",
        "firefox",
        "brave.exe",
        "brave",
        "iexplore.exe",
        "iexplore",
        "opera.exe",
        "opera",
    }

    SUSPICIOUS_CHILDREN: set[str] = {
        "cmd.exe",
        "cmd",
        "powershell.exe",
        "powershell",
        "pwsh.exe",
        "pwsh",
        "wscript.exe",
        "wscript",
        "cscript.exe",
        "cscript",
        "mshta.exe",
        "mshta",
        "bash.exe",
        "bash",
    }

    def evaluate(self, event: EndpointEvent, context: DetectionContext) -> list[RuleMatch]:
        """Evaluate if child command interpreter was spawned by an Office application or browser."""
        if event.event_type != "PROCESS_CREATE" or not event.image:
            return []

        child_binary = extract_process_name(event.image)
        if child_binary not in self.SUSPICIOUS_CHILDREN:
            return []

        # Determine parent binary name from event.parent_image or from process graph / context
        parent_binary: str | None = None
        parent_source = "event_parent_image"

        if event.parent_image:
            parent_binary = extract_process_name(event.parent_image)
        else:
            parent_event = context.get_parent_event(event)
            if parent_event and parent_event.image:
                parent_binary = extract_process_name(parent_event.image)
                parent_source = "process_graph_predecessor"

        if not parent_binary:
            return []

        parent_category: str | None = None
        if parent_binary in self.OFFICE_PARENTS:
            parent_category = "Microsoft Office Application"
        elif parent_binary in self.BROWSER_PARENTS:
            parent_category = "Web Browser"

        if not parent_category:
            return []

        rationale = (
            f"Suspicious child process '{child_binary}' was spawned by {parent_category} "
            f"'{parent_binary}' (identified via {parent_source}). Office documents and web browsers "
            f"rarely legitimately spawn command shells; this execution pattern strongly indicates "
            f"weaponized document macro execution, payload delivery, or browser exploit breakout."
        )

        match = RuleMatch(
            rule_id=self.id,
            endpoint_event_id=event.id,
            severity=self.severity,
            confidence=self.confidence_level,
            rationale=rationale,
            matched_fields={
                "child_binary": child_binary,
                "child_image": event.image,
                "child_command_line": event.command_line,
                "child_pid": event.process_id,
                "parent_binary": parent_binary,
                "parent_category": parent_category,
                "parent_pid": event.parent_process_id,
                "parent_resolution_method": parent_source,
                "host": event.host,
                "user": event.user,
            },
            caveats=(
                "Some internal developer tools or browser automation frameworks (e.g. Selenium, Puppeteer) "
                "may launch helper shells. Verify whether developer activity was active on the host."
            ),
        )
        return [match]
