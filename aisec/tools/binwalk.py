"""Outil binwalk: analyse et extraction de donnees embarquees (firmware, archives)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_offset, extract_path

# Ligne: "DECIMAL   HEXADECIMAL   DESCRIPTION"
_ENTRY_RE = re.compile(
    r"^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+?)\s*$", re.MULTILINE
)
_SUSPICIOUS = ("squashfs", "cramfs", "jffs2", "ubi", "gzip", "lzma", "xz", "openssl", "certificate", "private key", "password")


class BinwalkTool(Tool):
    name = "binwalk"
    binary = "binwalk"
    risk = "low"
    description = "Analyse de firmware/binaire: detecte et extrait les systemes de fichiers embarques."
    examples = (
        "analyse le firmware firmware.bin avec binwalk",
        "extrait les donnees embarquees de rootfs.img",
    )
    parameters = (
        ParameterSpec("input", "Fichier a analyser", "string", required=True),
        ParameterSpec("extract", "Extraire les donnees reconnues (-e)", "bool", default=False),
        ParameterSpec("entropy", "Analyse d'entropie (-E)", "bool", default=False),
        ParameterSpec("signature", "Scan de signatures (-B)", "bool", default=False),
        ParameterSpec("offset", "Offset de depart (-o)", "string"),
        ParameterSpec("length", "Longueur a analyser (-l)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["binwalk"]
        if params.get("extract"):
            argv.append("-e")
        if params.get("entropy"):
            argv.append("-E")
        if params.get("signature"):
            argv.append("-B")
        if params.get("offset"):
            argv += ["-o", str(params["offset"])]
        if params.get("length"):
            argv += ["-l", str(params["length"])]
        if params.get("verbose"):
            argv.append("-v")
        argv.append(str(params["input"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["input"] = path
        if "extrait" in low or "extract" in low or "decompresse" in low:
            params["extract"] = True
        if "entropie" in low or "entropy" in low:
            params["entropy"] = True
        offset = extract_offset(low)
        if "offset" in low and offset:
            params["offset"] = offset
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        entries = 0
        for decimal, hexa, description in _ENTRY_RE.findall(stdout):
            desc = description.strip()
            if not desc or desc.startswith("-----"):
                continue
            entries += 1
            low = desc.lower()
            severity = "medium" if any(k in low for k in _SUSPICIOUS) else "info"
            findings.append(
                Finding(
                    title=f"{desc[:100]} @ {hexa}",
                    severity=severity,
                    evidence=f"offset {decimal}",
                )
            )
        return AnalysisResult(
            summary=f"{entries} entree(s) detectee(s) par binwalk.",
            findings=findings[:50],
            source="heuristic",
        )


register(BinwalkTool())
