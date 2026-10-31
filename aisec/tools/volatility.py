"""Outil volatility3: analyse de la memoire vive (processus, connexions, injections)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# Plugins les plus utilises (intention -> plugin volatility3).
_PLUGINS = {
    "processus": "windows.pslist",
    "process": "windows.pslist",
    "pslist": "windows.pslist",
    "arbre des processus": "windows.pstree",
    "pstree": "windows.pstree",
    "connexions": "windows.netscan",
    "reseau": "windows.netscan",
    "netscan": "windows.netscan",
    "lignes de commande": "windows.cmdline",
    "cmdline": "windows.cmdline",
    "dll": "windows.dlllist",
    "injections": "windows.malfind",
    "malfind": "windows.malfind",
    "malware": "windows.malfind",
    "services": "windows.svcscan",
    "registre": "windows.registry.hivelist",
    "hash": "windows.hashdump",
    "mots de passe": "windows.hashdump",
}
# Processus legitimes usuels (pour reperer les noms suspects).
_SUSPICIOUS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin")


class VolatilityTool(Tool):
    name = "volatility3"
    aliases = ("volatility", "vol")
    binary = "volatility3"
    risk = "low"
    description = "Analyse de la memoire vive: processus, connexions, injections, registre."
    examples = (
        "liste les processus de dump.mem avec volatility3",
        "cherche les injections dans memory.raw",
    )
    parameters = (
        ParameterSpec("plugin", "Plugin a executer, ex: windows.pslist", "string", required=True),
        ParameterSpec("memory", "Fichier de memoire (dump)", "string", required=True),
        ParameterSpec("output_dir", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("output", "Fichier de sortie (-r)", "string"),
        ParameterSpec("format", "Format de sortie (-f): json, csv, pretty", "string"),
        ParameterSpec("pid", "Filtrer sur un PID (--pid)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["volatility3", "-f", str(params["memory"])]
        if params.get("output_dir"):
            argv += ["-o", str(params["output_dir"])]
        if params.get("output"):
            argv += ["-r", str(params["output"])]
        if params.get("format"):
            argv += ["-r", str(params["format"])]
        argv.append(str(params["plugin"]))
        if params.get("pid"):
            argv += ["--pid", str(params["pid"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["memory"] = path
        for key, plugin in _PLUGINS.items():
            if key in low:
                params["plugin"] = plugin
                break
        pid = re.search(r"pid\s+(\d+)", low)
        if pid:
            params["pid"] = pid.group(1)
        if "json" in low:
            params["format"] = "json"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        suspicious = [
            ln for ln in lines if any(name in ln.lower() for name in _SUSPICIOUS)
        ]
        for line in suspicious[:15]:
            findings.append(
                Finding(
                    title="Processus a verifier",
                    severity="medium",
                    detail=line.strip()[:160],
                )
            )
        if params.get("plugin") == "windows.malfind" and len(lines) > 1:
            findings.append(
                Finding(
                    title="Zones memoire injectables detectees (malfind)",
                    severity="high",
                    detail="Des regions memoire suspectes ont ete trouvees.",
                )
            )
        if params.get("plugin") == "windows.hashdump" and len(lines) > 1:
            findings.append(
                Finding(
                    title="Hashes d'utilisateurs extraits de la memoire",
                    severity="critical",
                    detail="Les hashes NT peuvent etre casses hors ligne.",
                )
            )
        return AnalysisResult(
            summary=f"{len(lines)} ligne(s) de sortie volatility3, {len(findings)} constat(s).",
            findings=findings,
            source="heuristic",
        )


register(VolatilityTool())
