"""Outil dnsrecon: enumeration DNS avancee (classe Information Gathering)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts

# Mode d'enumeration (-t) reconnu par les mots-cles.
_SCAN_HINTS = {
    "zone transfer": "axfr",
    "transfert de zone": "axfr",
    "axfr": "axfr",
    "brute force": "brt",
    "bruteforce": "brt",
    "brute": "brt",
    "reverse lookup": "rvl",
    "resolution inverse": "rvl",
    "reverse": "rvl",
    "cache snoop": "snoop",
    "spf": "spf",
    "srv": "srv",
    "tld": "tld",
    "google": "goo",
    "bing": "bin",
    "enumeration standard": "std",
    "standard": "std",
}


class DnsreconTool(Tool):
    name = "dnsrecon"
    binary = "dnsrecon"
    risk = "medium"
    description = "Enumeration DNS: transfert de zone, force brute, reverse lookup, SPF/SRV."
    examples = (
        "enumere le DNS de example.com avec un transfert de zone",
        "force brute des sous-domaines de example.com",
        "enumeration DNS standard de example.com",
    )
    parameters = (
        ParameterSpec("target", "Domaine ou plage CIDR", "string", required=True),
        ParameterSpec(
            "scan_type",
            "Mode: std, axfr, brt, rvl, snoop, spf, srv, tld, goo, bin",
            "string",
            default="std",
        ),
        ParameterSpec("dictionary", "Dictionnaire pour le force brute (-D)", "string"),
        ParameterSpec("nameserver", "Serveur DNS a utiliser (-n)", "string"),
        ParameterSpec("threads", "Nombre de threads (--threads)", "int"),
        ParameterSpec("json", "Sortie JSON (-j)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dnsrecon", "-d", str(params["target"])]
        if params.get("scan_type"):
            argv += ["-t", str(params["scan_type"])]
        if params.get("dictionary"):
            argv += ["-D", str(params["dictionary"])]
        if params.get("nameserver"):
            argv += ["-n", str(params["nameserver"])]
        if params.get("threads"):
            argv += ["--threads", str(params["threads"])]
        if params.get("json"):
            argv.append("-j")
        if params.get("verbose"):
            argv.append("-v")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hosts = extract_hosts(text)
        if hosts:
            params["target"] = hosts[0]
        for key, mode in _SCAN_HINTS.items():
            if key in low:
                params["scan_type"] = mode
                break
        dictionary = re.search(r"(?:dictionnaire|wordlist)\s+([\w./\-]+)", text, re.IGNORECASE)
        if dictionary:
            params["dictionary"] = dictionary.group(1)
        nameserver = re.search(r"serveur dns\s+([\w.\-]+)", low)
        if nameserver:
            params["nameserver"] = nameserver.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for name, rtype, value in re.findall(r"\[\*\]\s+(\S+)\s+(\w+)\s+(\S+)", stdout)[:30]:
            findings.append(Finding(title=f"{rtype} {name} -> {value}", severity="info"))
        if "Zone Transfer" in stdout and "Successful" in stdout:
            findings.append(
                Finding(
                    title="Transfert de zone REUSSI (AXFR)",
                    severity="high",
                    detail="Le serveur autorise les transferts de zone: fuite d'inventaire DNS.",
                )
            )
        if re.search(r"\[-\]\s+.*not found", stdout, re.IGNORECASE):
            findings.append(Finding(title="Aucun enregistrement trouve", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} enregistrement(s) DNS recupere(s).",
            findings=findings,
            source="heuristic",
        )


register(DnsreconTool())
