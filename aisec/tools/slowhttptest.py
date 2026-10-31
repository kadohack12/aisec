"""Outil slowhttptest: test de resistance aux attaques lentes (Slowloris, ...)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

_MODES = {
    "slowloris": "H",
    "entetes lentes": "H",
    "slow headers": "H",
    "corps lent": "B",
    "slow body": "B",
    "lecture lente": "X",
    "slow read": "X",
    "apache": "A",
    "range": "A",
}


class SlowhttptestTool(Tool):
    name = "slowhttptest"
    binary = "slowhttptest"
    risk = "high"
    description = "Test de deni de service lent (Slowloris, slow POST, slow read) sur un serveur web."
    examples = (
        "teste la resistance slowloris de https://example.com",
        "test de slow read sur example.com avec 1000 connexions",
    )
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("mode", "Mode: H (slowloris), B (slow body), X (slow read), A (range)", "string", default="H"),
        ParameterSpec("connections", "Nombre de connexions (-c)", "int", default=1000),
        ParameterSpec("rate", "Connexions par seconde (-r)", "int", default=200),
        ParameterSpec("interval", "Intervalle entre envois, en secondes (-i)", "int", default=10),
        ParameterSpec("timeout", "Timeout de suivi, en secondes (-t)", "int", default=30),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = str(params.get("mode") or "H").upper()
        if mode not in {"H", "B", "X", "A"}:
            mode = "H"
        argv = ["slowhttptest", f"-{mode}", "-u", str(params["url"])]
        if params.get("connections"):
            argv += ["-c", str(params["connections"])]
        if params.get("rate"):
            argv += ["-r", str(params["rate"])]
        if params.get("interval"):
            argv += ["-i", str(params["interval"])]
        if params.get("timeout"):
            argv += ["-t", str(params["timeout"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"(https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
        if match:
            url = match.group(1)
            if "://" not in url:
                url = "https://" + url
            params["url"] = url
        for key, mode in _MODES.items():
            if key in low:
                params["mode"] = mode
                break
        connections = re.search(r"(\d+)\s*connexions", low)
        if connections:
            params["connections"] = int(connections.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"service\s+is\s+not\s+vulnerable|no\s+vulnerab", stdout, re.IGNORECASE):
            findings.append(
                Finding(title="Serveur resistant aux attaques lentes", severity="info")
            )
        elif re.search(r"service\s+is\s+vulnerable|vulnerable", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Serveur VULNERABLE aux attaques lentes",
                    severity="high",
                    detail="Le serveur ne protege pas les connexions lentes: risque de DoS.",
                )
            )
        closed = re.findall(r"(\d+)\s+closed", stdout)
        if closed:
            findings.append(
                Finding(title=f"{closed[0]} connexion(s) fermee(s) durant le test", severity="low")
            )
        summary = f"Test slowhttptest sur {url_host(str(params.get('url', '')))}: {len(findings)} constat(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(SlowhttptestTool())
