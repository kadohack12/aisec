"""Outil hashid: identification du type d'un hash (md5, sha1, bcrypt, ...)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Un hash: suite hexadecimale/base64-ish, ou hash modulaire ($id$...).
_HASH_RE = re.compile(r"(\$[A-Za-z0-9]+\$[^\s]+|[A-Fa-f0-9]{16,}|[A-Za-z0-9+/]{20,}={0,2})")
_CANDIDATE_RE = re.compile(r"^\[\+\]\s*(.+?)\s*$", re.MULTILINE)


class HashidTool(Tool):
    name = "hashid"
    binary = "hashid"
    risk = "low"
    description = "Identifie le type probable d'un hash (MD5, SHA-1/2, bcrypt, NTLM, ...)."
    examples = (
        "identifie le hash 5f4dcc3b5aa765d61d8327deb882cf99",
        "quel type de hash est $2y$10$...",
    )
    parameters = (
        ParameterSpec("hash", "Hash a identifier", "string", required=True),
        ParameterSpec("mode", "Sortie pour outil: hashcat (-m) ou john (-j)", "string"),
        ParameterSpec("extended", "Liste etendue de correspondances (-e)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hashid"]
        mode = str(params.get("mode") or "").lower()
        if mode == "hashcat":
            argv.append("-m")
        elif mode == "john":
            argv.append("-j")
        if params.get("extended"):
            argv.append("-e")
        argv.append(str(params["hash"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = _HASH_RE.search(text)
        if match:
            params["hash"] = match.group(1)
        if "hashcat" in low:
            params["mode"] = "hashcat"
        elif "john" in low:
            params["mode"] = "john"
        if "etendu" in low or "extended" in low:
            params["extended"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for candidate in _CANDIDATE_RE.findall(stdout):
            findings.append(Finding(title=candidate, severity="info"))
        summary = (
            f"{len(findings)} type(s) de hash possible(s)."
            if findings
            else "Type de hash non identifie."
        )
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(HashidTool())
