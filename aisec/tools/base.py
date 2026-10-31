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


_TARGET_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+(?:/\d{1,2})?)\b",
    re.IGNORECASE,
)


def extract_targets(text: str) -> list[str]:
    """Comme extract_hosts, mais conserve le prefixe CIDR (ex: 10.0.0.0/24)."""
    ignore = {"http", "https", "tcp", "udp", "com", "net", "org"}
    found: list[str] = []
    for cand in _TARGET_RE.findall(text):
        low = cand.lower()
        if low in ignore or low.endswith((".pcap", ".pcapng", ".cap")):
            continue
        if cand not in found:
            found.append(cand)
    return found


_URL_RE = re.compile(
    r"\b(https?://[^\s\"']+|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+(?::\d+)?(?:/[^\s\"']*)?)",
    re.IGNORECASE,
)


def extract_url(text: str) -> str:
    """Extrait une URL (schema + domaine + chemin) ou un domaine d'un texte."""
    match = _URL_RE.search(text)
    return match.group(1).rstrip(".,;") if match else ""


def url_host(url: str) -> str:
    """Hote d'une URL: sans schema, sans chemin, sans port."""
    value = url.split("://", 1)[-1]
    return value.split("/", 1)[0].split(":", 1)[0]


def extract_ports(text: str, default: str = "80,443") -> str:
    """Extrait une liste de ports ('22,80,8080' ou '1-1024') d'un texte."""
    explicit = re.search(r"\bports?\s*([\d,\s]+\d)", text, re.IGNORECASE)
    if explicit:
        ports = ",".join(re.findall(r"\d+", explicit.group(1)))
        if ports:
            return ports
    found = re.findall(r"\bports?\s*[:=]?\s*(\d{1,5})\b", text, re.IGNORECASE)
    if found:
        return ",".join(dict.fromkeys(found))
    return default
