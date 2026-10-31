"""Types partages du moteur aisec."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParameterSpec:
    """Decrit un parametre accepte par un outil.

    Sert a la fois a documenter l'outil et a construire le prompt envoye au LLM.
    """

    name: str
    description: str
    type: str = "string"  # string | int | float | bool | list
    required: bool = False
    default: Any = None

    def to_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "type": self.type,
        }
        if self.required:
            schema["required"] = True
        if self.default is not None:
            schema["default"] = self.default
        return schema


@dataclass
class Finding:
    """Un constat issu de l'analyse d'une sortie d'outil."""

    title: str
    severity: str = "info"  # info | low | medium | high | critical
    detail: str = ""
    evidence: str = ""


@dataclass
class AnalysisResult:
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    source: str = "heuristic"  # llm | heuristic


@dataclass
class CommandPlan:
    """Le resultat de la traduction intention -> commande."""

    tool: str
    params: dict[str, Any]
    argv: list[str]
    reasoning: str = ""
    source: str = "heuristic"  # llm | heuristic | merged
    risk: str = ""  # niveau de risque attribue par la politique de controle
    reasons: list[str] = field(default_factory=list)  # motifs de la decision

    def render(self) -> str:
        import shlex

        return " ".join(shlex.quote(part) for part in self.argv)


@dataclass
class ExecResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float = 0.0
    timed_out: bool = False
