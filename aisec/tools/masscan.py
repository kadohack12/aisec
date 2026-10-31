"""Outil masscan: scanner de ports tres rapide (classe Information Gathering)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_targets

_LINE_RE = re.compile(
    r"Discovered open port (\d+)/(tcp|udp) on (\d{1,3}(?:\.\d{1,3}){3})"
)
_RATE_RE = re.compile(r"rate:\s*(\d+)")


class MasscanTool(Tool):
    name = "masscan"
    binary = "masscan"
    risk = "medium"
    description = "Scanner de ports asynchrone, tres rapide sur de larges plages."
    examples = (
        "scanne les ports 80,443 sur 10.0.0.0/24 tres rapidement",
        "scan masscan des 100 ports les plus courants sur 192.168.1.0/24",
    )
    parameters = (
        ParameterSpec("targets", "Cibles: IP ou CIDR", "list", required=True),
        ParameterSpec("ports", "Ports a scanner. Ex: '80,443' ou '1-1024'", "string", default="80,443"),
        ParameterSpec("rate", "Paquets par seconde (--rate)", "int", default=1000),
        ParameterSpec("interface", "Interface reseau (-e)", "string"),
        ParameterSpec("banners", "Recuperer les bannieres (--banners)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["masscan"]
        if params.get("ports"):
            argv += ["-p", str(params["ports"])]
        if params.get("rate"):
            argv += ["--rate", str(params["rate"])]
        if params.get("interface"):
            argv += ["-e", str(params["interface"])]
        if params.get("banners"):
            argv.append("--banners")
        argv += [str(t) for t in params.get("targets", [])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        targets = extract_targets(text)
        if targets:
            params["targets"] = targets
        ports = re.search(r"\bports?\s*([\d,\s]+\d)", low)
        if ports:
            params["ports"] = ",".join(re.findall(r"\d+", ports.group(1)))
        if "banniere" in low or "banner" in low:
            params["banners"] = True
        rate = re.search(r"(\d+)\s*(?:paquets|pps|par seconde)", low)
        if rate:
            params["rate"] = int(rate.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for port, proto, host in _LINE_RE.findall(stdout):
            findings.append(
                Finding(
                    title=f"{host}:{port}/{proto} ouvert",
                    severity="info",
                    evidence=f"Discovered open port {port}/{proto} on {host}",
                )
            )
        rate = _RATE_RE.search(stdout)
        summary = f"{len(findings)} port(s) ouvert(s) decouvert(s)."
        if rate:
            summary += f" Debit: {rate.group(1)} paquets/s."
        return AnalysisResult(
            summary=summary,
            findings=findings,
            data={"open_ports": len(findings)},
            source="heuristic",
        )


register(MasscanTool())
