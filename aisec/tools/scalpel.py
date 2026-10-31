"""Outil scalpel: carving de fichiers pilote par configuration."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

_CARVED_RE = re.compile(r"^(\S+?)\s+(\d+)\s+(0x[0-9A-Fa-f]+|\d+)\s+(\S+\.\w+)\s*$", re.MULTILINE)


class ScalpelTool(Tool):
    name = "scalpel"
    binary = "scalpel"
    risk = "medium"
    description = "Carving de fichiers a partir d'une configuration de signatures."
    examples = (
        "extrait les fichiers de disk.img avec scalpel",
        "carving avec scalpel et le fichier scalpel.conf",
    )
    parameters = (
        ParameterSpec("input", "Image ou fichier source", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("pattern", "Types a extraire (-p)", "string"),
        ParameterSpec("preview", "Mode apercu, n'ecrit rien (-P)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["scalpel"]
        if params.get("config"):
            argv += ["-c", str(params["config"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        if params.get("pattern"):
            argv += ["-p", str(params["pattern"])]
        if params.get("preview"):
            argv.append("-P")
        argv.append(str(params["input"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["input"] = path
        if "apercu" in text.lower() or "preview" in text.lower():
            params["preview"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for name, size, offset, out in _CARVED_RE.findall(stdout):
            findings.append(
                Finding(title=f"{out} ({size} octets)", severity="info", evidence=f"offset {offset}")
            )
        summary = f"{len(findings)} fichier(s) extrait(s) par scalpel."
        return AnalysisResult(summary=summary, findings=findings[:50], source="heuristic")


register(ScalpelTool())
