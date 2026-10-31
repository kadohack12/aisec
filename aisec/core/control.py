"""Niveau 2: controle de l'IA.

L'IA pilote l'outil (elle choisit la commande), mais l'humain pilote l'IA.
Chaque commande proposee passe par une politique de controle qui la classe par
risque et decide: executer (allow), demander confirmation (confirm) ou refuser
(deny). La politique borne aussi le comportement de l'IA (outils autorises,
nombre de cibles, plafond de risque auto-approuve).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .models import CommandPlan


class Risk(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def parse(cls, value: str | "Risk") -> "Risk":
        if isinstance(value, Risk):
            return value
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


class Decision(IntEnum):
    ALLOW = 0
    CONFIRM = 1
    DENY = 2


@dataclass
class ControlPolicy:
    """Politique de controle appliquee a chaque commande proposee par l'IA."""

    # Risque maximal execute sans confirmation.
    max_auto_risk: Risk = Risk.LOW
    # Listes blanches/noires d'outils (nom de binaire). Vide = pas de contrainte.
    allowed_tools: set[str] = field(default_factory=set)
    denied_tools: set[str] = field(default_factory=set)
    # Nombre maximal de cibles par commande (borne le rayon d'action).
    max_targets: int = 16
    # Refuser tout ce qui touche une cible privee/interne ?
    deny_private_targets: bool = False


@dataclass
class ControlVerdict:
    decision: Decision
    risk: Risk
    reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.decision is not Decision.DENY

    @property
    def needs_confirmation(self) -> bool:
        return self.decision is Decision.CONFIRM


# Risque intrinseque par outil (surchargeable par l'attribut `risk` du plugin).
_DEFAULT_TOOL_RISK = {
    "nmap": Risk.MEDIUM,
    "tshark": Risk.LOW,
    "dig": Risk.LOW,
    "host": Risk.LOW,
    "whois": Risk.LOW,
}

# Mots-cles d'arguments qui font monter le risque d'un cran.
_ESCALATORS = (
    "axfr",
    "exploit",
    "brute",
    "bruteforce",
    "spoof",
    "inject",
    "shell",
    "--script",
    "-sU",
)


def _tool_risk(tool) -> Risk:
    declared = getattr(tool, "risk", None)
    if declared is not None:
        return Risk.parse(declared)
    return _DEFAULT_TOOL_RISK.get(tool.binary, Risk.MEDIUM)


def evaluate(plan: CommandPlan, tool, policy: ControlPolicy) -> ControlVerdict:
    """Classe une commande et rend une decision de controle."""
    reasons: list[str] = []
    binary = plan.argv[0] if plan.argv else ""

    if binary in policy.denied_tools:
        return ControlVerdict(Decision.DENY, Risk.CRITICAL, [f"outil refuse: {binary}"])
    if policy.allowed_tools and binary not in policy.allowed_tools:
        return ControlVerdict(
            Decision.DENY, Risk.HIGH, [f"outil hors liste autorisee: {binary}"]
        )

    risk = _tool_risk(tool)
    for arg in plan.argv[1:]:
        low = arg.lower()
        if any(kw in low for kw in _ESCALATORS):
            risk = Risk(min(Risk.CRITICAL, risk + 1))
            reasons.append(f"argument sensible: {arg}")

    targets = plan.params.get("targets") or []
    if len(targets) > policy.max_targets:
        return ControlVerdict(
            Decision.DENY,
            risk,
            [f"trop de cibles ({len(targets)} > {policy.max_targets})"],
        )

    if policy.deny_private_targets:
        for target in targets:
            if _is_private(target):
                return ControlVerdict(
                    Decision.DENY, risk, [f"cible privee interdite: {target}"]
                )

    if risk > policy.max_auto_risk:
        reasons.append(
            f"risque {risk.label} > plafond auto-approuve {policy.max_auto_risk.label}"
        )
        return ControlVerdict(Decision.CONFIRM, risk, reasons)

    return ControlVerdict(Decision.ALLOW, risk, reasons or [f"risque {risk.label}"])


def _is_private(target: str) -> bool:
    import ipaddress

    host = target.split("/", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local
