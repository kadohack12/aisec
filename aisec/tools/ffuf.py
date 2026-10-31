"""Outil ffuf: fuzzing web rapide (repertoires, parametres, vhosts)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Ligne de resultat: chemin   [Status: 200, Size: 1234, Words: 12, ...]
_RESULT_RE = re.compile(
    r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)(?:,\s*Words:\s*(\d+))?",
    re.MULTILINE,
)
_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403}

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FfufTool(Tool):
    name = "ffuf"
    binary = "ffuf"
    risk = "medium"
    description = "Fuzzing web tres rapide (repertoires, fichiers, parametres, vhosts)."
    examples = (
        "fuzz les repertoires de https://example.com/FUZZ avec ffuf",
        "fuzz les parametres de example.com avec ffuf",
    )
    parameters = (
        ParameterSpec("url", "URL contenant le mot-cle FUZZ", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string", required=True),
        ParameterSpec("threads", "Nombre de threads (-t)", "int", default=40),
        ParameterSpec("match_codes", "Codes HTTP a garder (-mc)", "string", default="200,204,301,302,307,401,403"),
        ParameterSpec("filter_size", "Taille a exclure (-fs)", "string"),
        ParameterSpec("method", "Methode HTTP (-X)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("format", "Format de sortie (-of): json, csv, html", "string"),
        ParameterSpec("silent", "Mode silencieux (-s)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ffuf", "-u", str(params["url"]), "-w", str(params.get("wordlist") or _DEFAULT_WORDLIST)]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        if params.get("match_codes"):
            argv += ["-mc", str(params["match_codes"])]
        if params.get("filter_size"):
            argv += ["-fs", str(params["filter_size"])]
        if params.get("method"):
            argv += ["-X", str(params["method"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        if params.get("format"):
            argv += ["-of", str(params["format"])]
        if params.get("silent"):
            argv.append("-s")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"(https?://\S*FUZZ\S*|https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
        if match:
            url = match.group(1)
            if "FUZZ" not in url.upper():
                url = url.rstrip("/") + "/FUZZ"
            params["url"] = url
        wordlist = re.search(r"(?:dictionnaire|wordlist)\s+([\w./\-]+)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        method = re.search(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\b", text)
        if method:
            params["method"] = method.group(1)
        if "silencieux" in low or "silent" in low:
            params["silent"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for path, status, size, words in _RESULT_RE.findall(stdout):
            code = int(status)
            severity = "medium" if code in _INTERESTING else "info"
            detail = f"Size: {size}" + (f", Words: {words}" if words else "")
            findings.append(Finding(title=f"{path} [{code}]", severity=severity, detail=detail))
        return AnalysisResult(
            summary=f"{len(findings)} resultat(s) trouve(s) par ffuf.",
            findings=findings[:60],
            source="heuristic",
        )


register(FfufTool())
