"""Base declarative pour les outils a commande simple.

La plupart des outils de securite se decrivent comme un jeu de drapeaux, d'options
a valeur, d'arguments positionnels, et d'une sortie texte a cribler. `SpecTool`
couvre ce cas: un outil declare ses parametres, ses arguments et ses motifs
d'analyse, et herite des methodes du contrat (`build_argv`, `parse_intent`,
`analyze`). Un outil peut toujours surcharger l'une d'elles pour un cas
particulier (ex: `testssl.sh` qui attend `cible:port`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from .base import Tool, extract_hosts

# Valeurs considerees comme "parametre absent".
_EMPTY = (None, "", [], ())


@dataclass(frozen=True)
class Flag:
    """Drapeau booleen: ajoute `flag` quand `param` est vrai."""

    param: str
    flag: str


@dataclass(frozen=True)
class Option:
    """Option a valeur: `flag valeur` (ou `flagvaleur` si `joined`)."""

    param: str
    flag: str
    joined: bool = False


@dataclass(frozen=True)
class Positional:
    """Argument positionnel. Un parametre de type liste produit N arguments."""

    param: str


@dataclass(frozen=True)
class Rule:
    """Regle de parse_intent: mots-cles -> valeur pour un parametre."""

    param: str
    keywords: tuple[str, ...]
    value: Any = True


@dataclass(frozen=True)
class Number:
    """Regle de parse_intent: capture numerique par expression reguliere."""

    param: str
    regex: str
    cast: str = "int"  # int | str
    group: int = 1


@dataclass(frozen=True)
class Pattern:
    """Regle d'analyse: une correspondance -> un constat.

    `title` peut referencer les groupes de capture (`{0}`, `{1}`, ...).
    """

    regex: str
    title: str
    severity: str = "info"  # info | low | medium | high | critical
    detail: str = ""
    ignore_case: bool = True
    once: bool = True


def _kw_match(keyword: str, low: str) -> bool:
    if re.fullmatch(r"[a-z0-9 ]+", keyword):
        return re.search(rf"\b{re.escape(keyword)}\b", low) is not None
    return keyword in low


class SpecTool(Tool):
    """Outil decl aratif: drapeaux, options, positionnels, regles, motifs."""

    flags: tuple[Flag, ...] = ()
    options: tuple[Option, ...] = ()
    positionals: tuple[Positional, ...] = ()
    rules: tuple[Rule, ...] = ()
    numbers: tuple[Number, ...] = ()
    patterns: tuple[Pattern, ...] = ()
    # Ordre des sections dans argv. Par defaut options, drapeaux, positionnels.
    order: tuple[str, ...] = ("options", "flags", "positionals")
    # Parametres qui designent une cible (alimentes par extract_hosts).
    target_params: tuple[str, ...] = ()

    # ---- Construction de la commande --------------------------------------

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = [self.binary]
        for section in self.order:
            if section == "options":
                argv += self._options_argv(params)
            elif section == "flags":
                argv += self._flags_argv(params)
            elif section == "positionals":
                argv += self._positionals_argv(params)
        return argv

    def _options_argv(self, params: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for opt in self.options:
            value = params.get(opt.param)
            if value in _EMPTY:
                continue
            if isinstance(value, bool):
                if value:
                    out.append(opt.flag)
                continue
            if isinstance(value, (list, tuple)):
                for item in value:
                    out += [opt.flag, str(item)]
                continue
            out.append(f"{opt.flag}{value}" if opt.joined else opt.flag)
            if not opt.joined:
                out.append(str(value))
        return out

    def _flags_argv(self, params: dict[str, Any]) -> list[str]:
        return [flag.flag for flag in self.flags if params.get(flag.param)]

    def _positionals_argv(self, params: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for pos in self.positionals:
            value = params.get(pos.param)
            if value in _EMPTY:
                continue
            if isinstance(value, (list, tuple)):
                out += [str(v) for v in value]
            else:
                out.append(str(value))
        return out

    # ---- Traduction heuristique intention -> params ------------------------

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}

        if self.target_params:
            hosts = extract_hosts(text)
            if hosts:
                first = self.target_params[0]
                spec = {p.name: p for p in self.parameters}.get(first)
                params[first] = hosts if (spec and spec.type == "list") else hosts[0]

        # Premier match gagne: l'ordre des regles porte la priorite.
        for rule in self.rules:
            if rule.param in params:
                continue
            if any(_kw_match(k, low) for k in rule.keywords):
                params[rule.param] = rule.value

        for number in self.numbers:
            match = re.search(number.regex, low)
            if match:
                raw = match.group(number.group)
                params[number.param] = int(raw) if number.cast == "int" else raw

        return params

    # ---- Analyse heuristique ----------------------------------------------

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for pattern in self.patterns:
            flags = re.IGNORECASE if pattern.ignore_case else 0
            matches = list(re.finditer(pattern.regex, stdout, flags))
            if pattern.once:
                matches = matches[:1]
            for match in matches:
                title = pattern.title
                if match.groups():
                    try:
                        title = title.format(*match.groups())
                    except (IndexError, KeyError):
                        pass
                findings.append(
                    Finding(
                        title=title,
                        severity=pattern.severity,
                        detail=pattern.detail,
                        evidence=match.group(0).strip()[:200],
                    )
                )
        lines = sum(1 for line in stdout.splitlines() if line.strip())
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) sur {lines} ligne(s) d'analyse.",
            findings=findings,
            source="heuristic",
        )
