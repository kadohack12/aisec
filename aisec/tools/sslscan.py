"""Outil sslscan: analyse de la configuration TLS/SSL d'un service."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts, url_host

# Protocoles/problemes considere comme faibles s'ils sont acceptes.
_WEAK_PROTOCOLS = {"SSLv2": "high", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium"}


class SslscanTool(Tool):
    name = "sslscan"
    binary = "sslscan"
    risk = "low"
    description = "Analyse TLS/SSL: protocoles supportes, chiffrements faibles, certificat."
    examples = (
        "analyse le SSL de example.com:443",
        "verifie les protocoles TLS supportes par 10.0.0.1 sur le port 8443",
    )
    parameters = (
        ParameterSpec("target", "Hote ou URL a analyser", "string", required=True),
        ParameterSpec("port", "Port TLS (defaut 443)", "int"),
        ParameterSpec("no_heartbleed", "Ne pas tester Heartbleed (--no-heartbleed)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (--verbose)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        host = url_host(str(params["target"]))
        argv = ["sslscan"]
        if params.get("no_heartbleed"):
            argv.append("--no-heartbleed")
        if params.get("verbose"):
            argv.append("--verbose")
        if params.get("port"):
            argv.append(f"{host}:{params['port']}")
        else:
            argv.append(host)
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hosts = extract_hosts(text)
        if hosts:
            params["target"] = hosts[0]
        port = re.search(r"(?:port|:)\s*(\d{2,5})", low)
        if port:
            params["port"] = int(port.group(1))
        if "heartbleed" in low and "no" in low.split():
            params["no_heartbleed"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for proto in re.findall(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+enabled", stdout, re.MULTILINE):
            severity = _WEAK_PROTOCOLS.get(proto, "info")
            findings.append(
                Finding(
                    title=f"Protocole active: {proto}",
                    severity=severity,
                    detail="Protocole obsolete: a desactiver." if severity != "info" else "",
                )
            )
        if "Heartbleed" in stdout and "vulnerable" in stdout.lower():
            findings.append(
                Finding(
                    title="Vulnerable a Heartbleed (CVE-2014-0160)",
                    severity="critical",
                    detail="OpenSSL vulnerable a la fuite memoire Heartbleed.",
                )
            )
        if re.search(r"certificate expired|expired", stdout, re.IGNORECASE):
            findings.append(Finding(title="Certificat expire", severity="high"))
        weak = re.findall(r"Accepted\s+(.*?)\s+(?:DES|RC4|MD5|NULL|EXPORT|anon)", stdout, re.IGNORECASE)
        if weak:
            findings.append(
                Finding(
                    title=f"{len(weak)} suite(s) de chiffrement faible(s) acceptee(s)",
                    severity="medium",
                    detail="Chiffrements obsoletes (RC4/DES/NULL/export) acceptes.",
                )
            )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) TLS/SSL.",
            findings=findings,
            source="heuristic",
        )


register(SslscanTool())
