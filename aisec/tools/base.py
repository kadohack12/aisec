"""Base commune a tous les outils aisec.

Un `Tool` sait:
  - se decrire (parametres) pour le LLM
  - traduire une intention en parametres (heuristique de repli)
  - construire un argv sur a partir des parametres
  - analyser sa propre sortie (heuristique de repli)
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from ..core.models import AnalysisResult, CommandPlan, ParameterSpec


class Tool(ABC):
    name: str = ""
    aliases: tuple[str, ...] = ()
    binary: str = ""
    description: str = ""
    parameters: tuple[ParameterSpec, ...] = ()
    # Quelques exemples few-shot pour guider le LLM (intention -> params).
    examples: tuple[str, ...] = ()
    # Risque intrinseque: low | medium | high | critical (politique de controle).
    risk: str = "medium"

    def __init__(self) -> None:
        if not self.name or not self.binary:
            raise ValueError("Un Tool doit definir 'name' et 'binary'")

    # ---- Contrat principal -------------------------------------------------

    @abstractmethod
    def build_argv(self, params: dict[str, Any]) -> list[str]:
        """Construit la liste d'arguments a partir des parametres valides."""

    @abstractmethod
    def parse_intent(self, text: str) -> dict[str, Any]:
        """Traduction heuristique intention -> parametres (sans LLM)."""

    @abstractmethod
    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        """Analyse heuristique de la sortie (sans LLM)."""

    # ---- Aides -------------------------------------------------------------

    def build_plan(
        self, params: dict[str, Any], reasoning: str = "", source: str = "heuristic"
    ) -> CommandPlan:
        argv = self.build_argv(params)
        return CommandPlan(
            tool=self.name, params=params, argv=argv, reasoning=reasoning, source=source
        )

    def param_schema(self) -> list[dict[str, Any]]:
        return [p.to_schema() for p in self.parameters]

    def defaults(self) -> dict[str, Any]:
        return {p.name: p.default for p in self.parameters if p.default is not None}

    def coerce(self, params: dict[str, Any]) -> dict[str, Any]:
        """Filtre/convertit les parametres selon le schema declare."""
        specs = {p.name: p for p in self.parameters}
        clean: dict[str, Any] = {}
        for key, value in params.items():
            spec = specs.get(key)
            if spec is None or value is None:
                continue
            clean[key] = _coerce_value(value, spec.type)
        return clean


def _coerce_value(value: Any, type_name: str) -> Any:
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    if type_name == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "oui", "on"}
    if type_name == "list":
        if isinstance(value, (list, tuple)):
            return list(value)
        return [part.strip() for part in str(value).split(",") if part.strip()]
    return str(value)


_HOST_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+)\b",
    re.IGNORECASE,
)


def extract_hosts(text: str) -> list[str]:
    """Extrait les domaines/IPs d'un texte, sans doublon ni bruit."""
    ignore = {"http", "https", "tcp", "udp", "com", "net", "org"}
    found: list[str] = []
    for cand in _HOST_RE.findall(text):
        low = cand.lower()
        if low in ignore or low.endswith((".pcap", ".pcapng", ".cap")):
            continue
        if cand not in found:
            found.append(cand)
    return found


# Binaires et paquets manipules par les outils de reverse engineering.
_BINARY_EXT = (
    "exe|dll|sys|so|dylib|elf|bin|o|obj|class|jar|apk|dex|smali|"
    "pyc|pyo|wasm|a|lib|ko|hex|rom|com|elf"
)
_BINARY_RE = re.compile(
    rf"(?<![\w./-])([\w./-]*[\w-]+\.(?:{_BINARY_EXT}))\b", re.IGNORECASE
)
# Offset / adresse: 0x1A2B ou decimal >= 4 chiffres.
_OFFSET_RE = re.compile(r"0x[0-9A-Fa-f]+|\b\d{4,}\b")
# Symbole/fonction: "sym.main", "main", "func_00401a2b".
_SYMBOL_RE = re.compile(r"\b(?:sym\.|fcn\.|func_|sub_)?([A-Za-z_][\w.]{1,80})\b")
_SYMBOL_STOP = {
    "le", "la", "les", "un", "une", "des", "du", "de", "dans", "avec", "pour",
    "sur", "par", "et", "ou", "the", "a", "an", "of", "in", "to", "with",
    "analyse", "analyser", "desassemble", "desassembler", "decompile",
    "decompiler", "extrait", "extraire", "liste", "lister", "trouve",
    "trouver", "cherche", "chercher", "montre", "affiche", "bin", "file",
}


def extract_binary(text: str) -> str:
    """Extrait le chemin d'un binaire/paquet (exe, elf, apk, dex, jar...)."""
    match = _BINARY_RE.search(text)
    return match.group(1) if match else ""


def extract_offset(text: str) -> str:
    """Extrait un offset/adresse (hexadecimal ou decimal) d'un texte."""
    match = _OFFSET_RE.search(text)
    return match.group(0) if match else ""


def extract_symbol(text: str) -> str:
    """Extrait un nom de fonction/symbole probable (main, sym.foo, fcn.0040)."""
    for cand in _SYMBOL_RE.findall(text):
        if cand.lower() in _SYMBOL_STOP or len(cand) < 2:
            continue
        if _BINARY_RE.search(cand):
            continue
        return cand
    return ""
