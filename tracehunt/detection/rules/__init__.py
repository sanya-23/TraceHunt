"""Behavioral detection rule library for TraceHunt."""

from tracehunt.detection.base import BaseRule
from tracehunt.detection.rules.auth_anomaly import Rule005AuthAnomaly
from tracehunt.detection.rules.evasion import Rule004Evasion
from tracehunt.detection.rules.lolbin import Rule001Lolbin
from tracehunt.detection.rules.proc_spawn import Rule002ProcSpawn
from tracehunt.detection.rules.recon import Rule003Recon

__all__ = [
    "Rule001Lolbin",
    "Rule002ProcSpawn",
    "Rule003Recon",
    "Rule004Evasion",
    "Rule005AuthAnomaly",
    "get_default_rules",
]


def get_default_rules() -> list[BaseRule]:
    """Instantiate and return the suite of default explainable behavioral detection rules."""
    return [
        Rule001Lolbin(),
        Rule002ProcSpawn(),
        Rule003Recon(),
        Rule004Evasion(),
        Rule005AuthAnomaly(),
    ]
