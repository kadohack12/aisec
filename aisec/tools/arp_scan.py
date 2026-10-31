"""Outil arp-scan: decouverte d'hotes sur le reseau local via ARP."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_targets

_LINE_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*(.*)$",
    re.IGNORECASE | re.MULTILINE,
)


class ArpScanTool(Tool):
    name = "arp-scan"
    binary = "arp-scan"
    risk = "low"
    description = "Decouverte ARP des hotes du reseau local (IP + adresse MAC + constructeur)."
    examples = (
        "decouvre les hotes sur 192.168.1.0/24",
        "liste les machines du reseau local",
    )
    parameters = (
        ParameterSpec("targets", "Plage CIDR ou interface a scanner", "list", required=True),
        ParameterSpec("interface", "Interface reseau (--interface)", "string"),
        ParameterSpec("localnet", "Utiliser le reseau local (--localnet)", "bool", default=False),
        ParameterSpec("retry", "Nombre de tentatives (--retry)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["arp-scan"]
        if params.get("interface"):
            argv += ["--interface", str(params["interface"])]
        if params.get("retry"):
            argv += ["--retry", str(params["retry"])]
        if params.get("localnet"):
            argv.append("--localnet")
        argv += [str(t) for t in params.get("targets", [])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "reseau local" in low or "localnet" in low:
            params["localnet"] = True
        targets = extract_targets(text)
        if targets:
            params["targets"] = targets
        iface = re.search(r"interface\s+([a-z]+\d+)", low)
        if iface:
            params["interface"] = iface.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for ip, mac, vendor in _LINE_RE.findall(stdout):
            vendor = vendor.strip()
            findings.append(
                Finding(
                    title=f"{ip} ({mac})",
                    severity="info",
                    detail=vendor,
                    evidence=f"{ip} {mac} {vendor}".strip(),
                )
            )
        return AnalysisResult(
            summary=f"{len(findings)} hote(s) decouvert(s) via ARP.",
            findings=findings,
            data={"hosts": len(findings)},
            source="heuristic",
        )


register(ArpScanTool())
