"""Outil nikto: scanner de vulnerabilites de serveur web."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts, url_host


class NiktoTool(Tool):
    name = "nikto"
    binary = "nikto"
    risk = "medium"
    description = "Scanner de serveur web: fichiers dangereux, logiciels obsoletes, mauvaises configs."
    examples = (
        "scanne le serveur web https://example.com avec nikto",
        "cherche les vulnerabilites web sur example.com port 8080",
    )
    parameters = (
        ParameterSpec("host", "Hote ou URL cible", "string", required=True),
        ParameterSpec("port", "Port du serveur web (-p)", "int"),
        ParameterSpec("ssl", "Forcer SSL/TLS (-ssl)", "bool", default=False),
        ParameterSpec("tuning", "Categories de tests (-Tuning), ex: '123b'", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("format", "Format de sortie (-Format): txt, html, json, csv", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nikto", "-h", url_host(str(params["host"]))]
        if params.get("port"):
            argv += ["-p", str(params["port"])]
        if params.get("ssl"):
            argv.append("-ssl")
        if params.get("tuning"):
            argv += ["-Tuning", str(params["tuning"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        if params.get("format"):
            argv += ["-Format", str(params["format"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hosts = extract_hosts(text)
        if hosts:
            params["host"] = hosts[0]
        port = re.search(r"port\s+(\d{2,5})", low)
        if port:
            params["port"] = int(port.group(1))
        if "https" in low or "ssl" in low or "tls" in low:
            params["ssl"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped.startswith("+"):
                continue
            detail = stripped.lstrip("+ ").strip()
            low = detail.lower()
            if any(k in low for k in ("vulnerab", "osvdb", "cve-", "exploit")):
                severity = "high"
            elif any(k in low for k in ("outdated", "obsolete", "default", "allowed", "disclos")):
                severity = "medium"
            else:
                severity = "low"
            findings.append(Finding(title=detail[:120], severity=severity, evidence=stripped))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) nikto.",
            findings=findings[:40],
            source="heuristic",
        )


register(NiktoTool())
