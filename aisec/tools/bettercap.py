"""Outil bettercap: framework de reconnaissance et MITM reseau."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Commandes caplet usuelles associees a une intention.
_ACTIONS = {
    "probe": "net.probe on",
    "decouverte": "net.probe on",
    "sniff": "net.sniff on",
    "espion": "net.sniff on",
    "arp": "set arp.spoof.targets {target}; arp.spoof on",
    "spoof": "set arp.spoof.targets {target}; arp.spoof on",
    "dns": "set dns.spoof.domains {target}; dns.spoof on",
    "https": "set http.proxy.sslstrip true; http.proxy on",
    "sslstrip": "set http.proxy.sslstrip true; http.proxy on",
    "mitm": "set arp.spoof.targets {target}; arp.spoof on; net.sniff on",
}
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")


class BettercapTool(Tool):
    name = "bettercap"
    binary = "bettercap"
    risk = "high"
    description = "Reconnaissance reseau et MITM (ARP/DNS spoofing, sniffing, sslstrip)."
    examples = (
        "decouvre les hotes du reseau avec bettercap sur eth0",
        "sniff le trafic avec bettercap sur wlan0",
        "arp spoof de 192.168.1.50 avec bettercap",
    )
    parameters = (
        ParameterSpec("interface", "Interface reseau (-iface)", "string"),
        ParameterSpec("eval", "Commandes a executer (-eval)", "string"),
        ParameterSpec("caplet", "Caplet a charger (-caplet)", "string"),
        ParameterSpec("target", "Cible du spoof (IP)", "string"),
        ParameterSpec("no_history", "Ne pas journaliser (-no-history)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bettercap"]
        if params.get("interface"):
            argv += ["-iface", str(params["interface"])]
        if params.get("caplet"):
            argv += ["-caplet", str(params["caplet"])]
        eval_cmds = params.get("eval")
        if eval_cmds:
            argv += ["-eval", str(eval_cmds)]
        if params.get("no_history"):
            argv.append("-no-history")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        iface = re.search(r"(?:interface|sur)\s+([a-z]+\d+)", low)
        if iface:
            params["interface"] = iface.group(1)
        target = _IP_RE.search(text)
        if target:
            params["target"] = target.group(1)
        action = next((cmd for key, cmd in _ACTIONS.items() if key in low), "net.probe on")
        if "{target}" in action:
            action = action.replace("{target}", str(params.get("target", "")))
        params["eval"] = action
        if "historique" in low or "history" in low:
            params["no_history"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        hosts = set()
        for line in stdout.splitlines():
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s*:?\s*([0-9a-f:]{17})?", line)
            if match and ("endpoint" in line.lower() or "host" in line.lower()):
                hosts.add(match.group(1))
                findings.append(
                    Finding(title=f"Hote: {match.group(1)}", severity="info", detail=match.group(2) or "")
                )
        if re.search(r"credential|password|login", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Identifiants captures dans le trafic",
                    severity="critical",
                    detail="Du trafic a mis en evidence des identifiants (sniffing MITM).",
                )
            )
        if "arp.spoof" in stdout.lower() and "spoofing" in stdout.lower():
            findings.append(Finding(title="ARP spoofing actif", severity="high"))
        return AnalysisResult(
            summary=f"{len(hosts)} hote(s) observe(s) par bettercap.",
            findings=findings[:40],
            source="heuristic",
        )


register(BettercapTool())
