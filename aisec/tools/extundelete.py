"""Outil extundelete: recuperation de fichiers supprimes sur un systeme ext3/ext4."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

_RECOVERED_RE = re.compile(r"Successfully restored file (\S+)")
_DELETED_RE = re.compile(r"^(\d+)\s+(\w+)\s+(\d+)\s+(.+)$", re.MULTILINE)


class ExtundeleteTool(Tool):
    name = "extundelete"
    binary = "extundelete"
    risk = "high"
    description = "Recupere des fichiers supprimes sur une partition ext3/ext4 (montee en lecture seule)."
    examples = (
        "recupere les fichiers supprimes de /dev/sda1 avec extundelete",
        "restaure le fichier /home/user/doc.txt depuis /dev/sdb1",
    )
    parameters = (
        ParameterSpec("device", "Partition ext3/ext4 (ex: /dev/sda1)", "string", required=True),
        ParameterSpec("restore_file", "Fichier a restaurer (--restore-file)", "string"),
        ParameterSpec("restore_all", "Restaurer tous les fichiers (--restore-all)", "bool", default=False),
        ParameterSpec("output", "Repertoire de sortie (--output-dir)", "string"),
        ParameterSpec("after", "Fichiers supprimes apres cette date (--after)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["extundelete"]
        if params.get("output"):
            argv += ["--output-dir", str(params["output"])]
        if params.get("after"):
            argv += ["--after", str(params["after"])]
        if params.get("restore_all"):
            argv.append("--restore-all")
        elif params.get("restore_file"):
            argv += ["--restore-file", str(params["restore_file"])]
        argv.append(str(params["device"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        device = re.search(r"(/dev/\w+)", text)
        if device:
            params["device"] = device.group(1)
        restore = re.search(r"fichier\s+(/[\w./\-]+)", text, re.IGNORECASE)
        if restore:
            params["restore_file"] = restore.group(1)
        if "tous" in low or "restore-all" in low:
            params["restore_all"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for path in _RECOVERED_RE.findall(stdout):
            findings.append(Finding(title=f"Fichier restaure: {path}", severity="info"))
        for inode, ftype, size, name in _DELETED_RE.findall(stdout)[:20]:
            findings.append(
                Finding(title=f"Entree recuperable: {name.strip()[:100]}", severity="low", detail=f"inode {inode}")
            )
        summary = f"{len(findings)} fichier(s)/entree(s) recuperable(s)."
        return AnalysisResult(summary=summary, findings=findings[:40], source="heuristic")


register(ExtundeleteTool())
