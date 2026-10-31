"""Outils automotive (classe `13-automotive`).

can-utils regroupe les utilitaires SocketCAN en espace utilisateur: lecture et
ecriture de trames (`candump`, `cansend`, `cangen`), configuration d'interface
(`canconfig`), conversion de formats (`canconvert`, `candump2asc`) et outils
specialises (`isotpdump`, `j1939*`, `log2asc`, `asc2log`). Chaque binaire est
un plugin `Tool` (argv sans shell). Les operations d'ecriture sur le bus
(`cansend`, `cangen`, `canconfig up`) sont en risque `medium`; la lecture est
en `low`.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_any_path

_IFACE_RE = re.compile(r"\b(can\d+|vcan\d+|slcan\d+|can_if\w*|eth\d+)\b", re.IGNORECASE)
_FRAME_RE = re.compile(r"\b([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)\b")
_BITRATE_RE = re.compile(r"\b(\d{2,6})\b")


class _CanBase(Tool):
    """Base commune: interface SocketCAN et fichier optionnel."""

    def _iface(self, text: str) -> str:
        match = _IFACE_RE.search(text)
        return match.group(1) if match else "can0"

    def _bits(self, text: str) -> str:
        match = re.search(r"(\d{2,6})\s*(?:bits?|bitrate|kbit|kb/s)", text, re.IGNORECASE)
        return match.group(1) if match else ""


class CandumpTool(_CanBase):
    name = "candump"
    binary = "candump"
    risk = "low"
    description = "Lit et affiche les trames CAN d'une interface SocketCAN."
    examples = ("capture les trames can sur can0 avec candump",)
    parameters = (
        ParameterSpec("interface", "Interface CAN, ex: can0", "string", required=True),
        ParameterSpec("log", "Journaliser dans un fichier (-l)", "string"),
        ParameterSpec("absolute", "Horodatage absolu (-a)", "bool", default=False),
        ParameterSpec("timestamp", "Horodatage (-t)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["candump"]
        if params.get("absolute"):
            argv.append("-a")
        if params.get("timestamp"):
            argv += ["-t", str(params["timestamp"])]
        if params.get("log"):
            argv += ["-l", str(params["log"])]
        argv.append(str(params["interface"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": self._iface(text)}
        path = extract_any_path(text)
        if path:
            params["log"] = path
        if "absolu" in low or "horodatage absolu" in low:
            params["absolute"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        frames = _FRAME_RE.findall(stdout)
        ids = sorted({frame[0].upper() for frame in frames})
        if len(frames) > 200:
            findings.append(
                Finding(
                    title="Volume de trafic CAN eleve",
                    severity="medium",
                    detail=f"{len(frames)} trames capturees: possible tempete de bus ou injection.",
                )
            )
        if ids:
            findings.append(
                Finding(
                    title="Identifiants CAN observes",
                    severity="info",
                    detail=f"{len(ids)} ID distincts: {', '.join(ids[:20])}",
                )
            )
        return AnalysisResult(
            summary=f"{len(frames)} trame(s) CAN, {len(ids)} identifiant(s) distinct(s).",
            findings=findings,
            source="heuristic",
        )


class CansendTool(_CanBase):
    name = "cansend"
    binary = "cansend"
    risk = "medium"
    description = "Emet une trame CAN sur le bus (ecriture)."
    examples = ("envoie la trame 123#deadbeef sur can0",)
    parameters = (
        ParameterSpec("interface", "Interface CAN, ex: can0", "string", required=True),
        ParameterSpec("frame", "Trame au format <id>#<donnees>, ex: 123#DEADBEEF", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["cansend", str(params["interface"]), str(params["frame"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"interface": self._iface(text)}
        match = _FRAME_RE.search(text)
        if match:
            params["frame"] = match.group(0).upper()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if not stdout.strip() or "error" in stdout.lower() or "failed" in stdout.lower():
            findings.append(
                Finding(
                    title="Trame non transmise",
                    severity="low",
                    detail=stdout.strip()[:160] or "aucune confirmation d'emission",
                )
            )
        return AnalysisResult(
            summary="Emission d'une trame CAN (action d'ecriture sur le bus).",
            findings=findings,
            source="heuristic",
        )


class CangenTool(_CanBase):
    name = "cangen"
    binary = "cangen"
    risk = "medium"
    description = "Genere un flux de trames CAN (test de charge du bus)."
    examples = ("genere du trafic can sur can0 pendant 100 trames",)
    parameters = (
        ParameterSpec("interface", "Interface CAN, ex: can0", "string", required=True),
        ParameterSpec("count", "Nombre de trames a generer (-n)", "int"),
        ParameterSpec("gap", "Intervalle entre trames en ms (-g)", "int"),
        ParameterSpec("id", "Identifiant a utiliser (-I)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["cangen", str(params["interface"])]
        if params.get("count"):
            argv += ["-n", str(params["count"])]
        if params.get("gap"):
            argv += ["-g", str(params["gap"])]
        if params.get("id"):
            argv += ["-I", str(params["id"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": self._iface(text)}
        count = re.search(r"(\d+)\s*(?:trames?|frames?)", low)
        if count:
            params["count"] = int(count.group(1))
        gap = re.search(r"(\d+)\s*(?:ms|millisecondes?)", low)
        if gap:
            params["gap"] = int(gap.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("count") and int(params["count"]) > 1000:
            findings.append(
                Finding(
                    title="Generation de trafic importante",
                    severity="medium",
                    detail="Un flux massif peut saturer le bus CAN (deni de service).",
                )
            )
        return AnalysisResult(
            summary="Generation de trafic CAN (test de charge du bus).",
            findings=findings,
            source="heuristic",
        )


class CanconfigTool(_CanBase):
    name = "canconfig"
    aliases = ("ip link",)
    binary = "canconfig"
    risk = "medium"
    description = "Configure une interface CAN (debit, mode, activation)."
    examples = ("configure can0 a 500000 bits et active l'interface",)
    parameters = (
        ParameterSpec("interface", "Interface CAN, ex: can0", "string", required=True),
        ParameterSpec("bitrate", "Debit en bits/s (-b)", "string"),
        ParameterSpec("action", "Action: up, down, restart", "string"),
        ParameterSpec("loopback", "Mode loopback (test local)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["canconfig", str(params["interface"])]
        if params.get("bitrate"):
            argv += ["bitrate", str(params["bitrate"])]
        if params.get("loopback"):
            argv += ["loopback", "on"]
        action = params.get("action") or "up"
        argv.append(str(action))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": self._iface(text)}
        bits = self._bits(text)
        if bits:
            params["bitrate"] = bits
        if "down" in low or "desactive" in low or "arrete" in low:
            params["action"] = "down"
        elif "restart" in low or "redemarre" in low:
            params["action"] = "restart"
        if "loopback" in low:
            params["loopback"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("loopback"):
            findings.append(
                Finding(
                    title="Mode loopback active",
                    severity="info",
                    detail="L'interface ne communique plus avec le bus physique.",
                )
            )
        return AnalysisResult(
            summary="Configuration de l'interface CAN (action d'administration).",
            findings=findings,
            source="heuristic",
        )


class CanconvertTool(_CanBase):
    name = "canconvert"
    aliases = ("candump2asc", "asc2log", "log2asc")
    binary = "canconvert"
    risk = "low"
    description = "Convertit un journal CAN entre formats (candump, asc, log)."
    examples = ("convertit le journal candump.log au format asc",)
    parameters = (
        ParameterSpec("input", "Fichier d'entree", "string", required=True),
        ParameterSpec("output", "Fichier de sortie", "string"),
        ParameterSpec("format", "Format cible: asc, log, candump", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["canconvert"]
        if params.get("format"):
            argv += ["-f", str(params["format"])]
        argv.append(str(params["input"]))
        if params.get("output"):
            argv.append(str(params["output"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        paths = re.findall(r"(?<![\w./-])([\w./-]*[\w-]+\.(?:log|asc|txt|blf))", text, re.IGNORECASE)
        if paths:
            params["input"] = paths[0]
            if len(paths) > 1:
                params["output"] = paths[1]
        for fmt in ("asc", "log", "candump"):
            if fmt in low:
                params["format"] = fmt
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        return AnalysisResult(
            summary="Conversion d'un journal CAN.",
            source="heuristic",
        )


class IsotpdumpTool(_CanBase):
    name = "isotpdump"
    binary = "isotpdump"
    risk = "low"
    description = "Decode les trames ISO-TP (transport diagnostic) sur un bus CAN."
    examples = ("decode les trames isotp sur can0",)
    parameters = (
        ParameterSpec("interface", "Interface CAN, ex: can0", "string", required=True),
        ParameterSpec("address", "Adresse ISO-TP a filtrer", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["isotpdump", str(params["interface"])]
        if params.get("address"):
            argv.append(str(params["address"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"interface": self._iface(text)}
        addr = re.search(r"0x([0-9A-Fa-f]{3})", text)
        if addr:
            params["address"] = f"0x{addr.group(1)}"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"\b(7F|NRC|negative)\b", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Reponse diagnostic negative (NRC)",
                    severity="low",
                    detail="Un ECU a refuse une requete de diagnostic ISO-TP.",
                )
            )
        return AnalysisResult(
            summary="Decodage ISO-TP du bus CAN.",
            findings=findings,
            source="heuristic",
        )


register(CandumpTool())
register(CansendTool())
register(CangenTool())
register(CanconfigTool())
register(CanconvertTool())
register(IsotpdumpTool())
