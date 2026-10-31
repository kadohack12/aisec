"""Outil testssl: audit complet de la configuration TLS/SSL d'un service."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

# Lignes de constat: "  HIGH  ...  " ou "  VULNERABLE  ...".
_FINDING_RE = re.compile(
    r"^\s*(CRITICAL|HIGH|MEDIUM|LOW|WARN|INFO|OK|VULNERABLE|NOT\s+VULNERABLE|NOT\s+ok)\s+(.+)$",
    re.MULTILINE,
)


class TestsslTool(Tool):
    name = "testssl"
    binary = "testssl"
    aliases = ("testssl.sh",)
    risk = "medium"
    description = "Audit TLS/SSL: protocoles, chiffrements, vulnerabilites (Heartbleed, ROBOT, ...)."
    examples = (
        "audit TLS complet de example.com:443 avec testssl",
        "teste les vulnerabilites TLS de 10.0.0.1:8443",
    )
    parameters = (
        ParameterSpec("target", "Hote:port ou URL a tester", "string", required=True),
        ParameterSpec("severity", "Severite minimale affichee (--severity)", "string"),
        ParameterSpec("protocols", "Tester les protocoles (-p)", "bool", default=False),
        ParameterSpec("vulnerabilities", "Tester les vulnerabilites (-U)", "bool", default=False),
        ParameterSpec("full", "Audit complet (--full)", "bool", default=False),
        ParameterSpec("json", "Sortie JSON (--json)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["testssl"]
        if params.get("severity"):
            argv += ["--severity", str(params["severity"])]
        if params.get("full"):
            argv.append("--full")
        if params.get("protocols"):
            argv.append("-p")
        if params.get("vulnerabilities"):
            argv.append("-U")
        if params.get("json"):
            argv.append("--json")
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"([a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?::\d{2,5})?|\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?)", text, re.IGNORECASE)
        if match:
            target = match.group(1)
            if ":" not in target:
                target = f"{target}:443"
            params["target"] = target
        if "vulnerabilit" in low:
            params["vulnerabilities"] = True
        if "protocole" in low:
            params["protocols"] = True
        if "complet" in low or "full" in low:
            params["full"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for level, detail in _FINDING_RE.findall(stdout):
            level = level.upper()
            low = detail.lower()
            if level in {"CRITICAL", "VULNERABLE"} or "vulnerable" in low and "not" not in low:
                severity = "critical" if level in {"CRITICAL", "VULNERABLE"} else "high"
            elif level == "HIGH":
                severity = "high"
            elif level in {"MEDIUM", "WARN"}:
                severity = "medium"
            elif level == "LOW":
                severity = "low"
            else:
                severity = "info"
            findings.append(Finding(title=detail.strip()[:120], severity=severity, evidence=detail.strip()))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) TLS/SSL.",
            findings=findings[:50],
            source="heuristic",
        )


register(TestsslTool())
