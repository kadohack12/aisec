"""Outil detect-it-easy (DIE): identification de type, packer et compilateur d'un binaire."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_binary

# Signatures de packers/protecteurs a signaler.
_PACKERS = (
    "upx", "aspack", "pecompact", "mpress", "themida", "vmprotect", "enigma",
    "petite", "fsg", "mew", "nspack", "pebundle", "yoda", "obsidium",
)


class DetectItEasyTool(Tool):
    name = "die"
    aliases = ("detect-it-easy",)
    binary = "diec"
    risk = "low"
    description = "Identifie le type, le compilateur et le packer d'un fichier (detect-it-easy)."
    examples = (
        "identifie sample.exe avec detect-it-easy",
        "detecte le packer de malware.dll",
    )
    parameters = (
        ParameterSpec("file", "Fichier a identifier", "string", required=True),
        ParameterSpec("json", "Sortie JSON (-j)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
        ParameterSpec("recursive", "Analyse recursive (-r)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["diec"]
        if params.get("json"):
            argv.append("-j")
        if params.get("verbose"):
            argv.append("-v")
        if params.get("recursive"):
            argv.append("-r")
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_binary(text)
        if path:
            params["file"] = path
        if "json" in text.lower():
            params["json"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        low = stdout.lower()
        for packer in _PACKERS:
            if packer in low:
                findings.append(
                    Finding(
                        title=f"Packer/protecteur detecte: {packer.upper()}",
                        severity="medium",
                        detail="Le binaire est compresse/protege: l'analyse statique est limitee.",
                    )
                )
        for line in stdout.splitlines():
            stripped = line.strip()
            if re.match(r"(PE|ELF|Mach-O|MS-DOS|Binary|Format)", stripped):
                findings.append(Finding(title=stripped[:140], severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) d'identification.",
            findings=findings[:60],
            source="heuristic",
        )


register(DetectItEasyTool())
