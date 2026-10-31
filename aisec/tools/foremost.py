"""Outil foremost: recuperation de fichiers par signature (carving)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# Sortie: "Num  Name  (Size)  Start  End" puis des lignes d'entete par type.
_TABLE_RE = re.compile(r"^\s*(\d+)\s+([A-Za-z0-9_]+)\s+(\d+)\s+(0x[0-9A-Fa-f]+|\d+)\s+(0x[0-9A-Fa-f]+|\d+)", re.MULTILINE)


class ForemostTool(Tool):
    name = "foremost"
    binary = "foremost"
    risk = "medium"
    description = "Recupere des fichiers a partir de leurs signatures (jpg, pdf, exe, ...)."
    examples = (
        "recupere les fichiers de disk.img avec foremost",
        "carving des images jpeg dans capture.dd",
    )
    parameters = (
        ParameterSpec("input", "Image ou fichier source (-i)", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("types", "Types a extraire (-t), ex: 'jpg,pdf,doc'", "string"),
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["foremost"]
        if params.get("config"):
            argv += ["-c", str(params["config"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        if params.get("types"):
            argv += ["-t", str(params["types"])]
        if params.get("quiet"):
            argv.append("-q")
        if params.get("verbose"):
            argv.append("-v")
        argv += ["-i", str(params["input"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["input"] = path
        types = re.search(r"\b(jpg|jpeg|pdf|doc|docx|exe|png|gif|zip|html|txt)\b", low)
        if types:
            params["types"] = types.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        by_type: dict[str, int] = {}
        for _num, name, size, start, _end in _TABLE_RE.findall(stdout):
            by_type[name] = by_type.get(name, 0) + 1
            findings.append(
                Finding(
                    title=f"{name} recupere ({size} octets)",
                    severity="info",
                    evidence=f"offset {start}",
                )
            )
        for name, count in sorted(by_type.items()):
            findings.append(Finding(title=f"{count} fichier(s) de type {name}", severity="info"))
        summary = (
            f"{len(findings)} fichier(s) recupere(s) par carving."
            if findings
            else "Aucun fichier recupere."
        )
        return AnalysisResult(
            summary=summary, findings=findings[:50], data={"by_type": by_type}, source="heuristic"
        )


register(ForemostTool())
