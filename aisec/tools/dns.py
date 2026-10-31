"""Outils DNS: dig, host, whois (classe Information Gathering / DNS Analysis)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts

# Types d'enregistrement DNS reconnus par les mots-cles.
_RECORD_HINTS = {
    "a": "A",
    "aaaa": "AAAA",
    "mx": "MX",
    "mail": "MX",
    "ns": "NS",
    "serveur de noms": "NS",
    "serveurs de noms": "NS",
    "nameserver": "NS",
    "nameservers": "NS",
    "txt": "TXT",
    "spf": "TXT",
    "soa": "SOA",
    "cname": "CNAME",
    "alias": "CNAME",
    "ptr": "PTR",
    "reverse": "PTR",
    "caa": "CAA",
    "srv": "SRV",
    "any": "ANY",
}


class DigTool(Tool):
    name = "dig"
    aliases = ()
    binary = "dig"
    description = "Interrogation DNS: enregistrements A, MX, NS, TXT, zone transfer."
    examples = (
        "resous les enregistrements A et MX de example.com",
        "recupere les serveurs de noms de example.com",
        "tente un transfert de zone AXFR sur example.com",
    )
    parameters = (
        ParameterSpec("target", "Domaine a interroger", "string", required=True),
        ParameterSpec("record_type", "Type: A, AAAA, MX, NS, TXT, SOA, CNAME, ANY", "string", default="A"),
        ParameterSpec("server", "Serveur DNS a utiliser (@serveur)", "string"),
        ParameterSpec("short", "Sortie courte (+short)", "bool", default=False),
        ParameterSpec("axfr", "Tenter un transfert de zone (AXFR)", "bool", default=False),
        ParameterSpec("trace", "Tracer la resolution (+trace)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dig"]
        if params.get("axfr"):
            argv.append("AXFR")
        else:
            argv.append(str(params.get("record_type") or "A").upper())
        argv.append(str(params["target"]))
        if params.get("server"):
            argv.append(f"@{params['server']}")
        if params.get("short"):
            argv.append("+short")
        if params.get("trace"):
            argv.append("+trace")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hosts = extract_hosts(text)
        if hosts:
            params["target"] = hosts[0]
        for key, rtype in _RECORD_HINTS.items():
            if re.search(rf"\b{re.escape(key)}\b", low):
                params["record_type"] = rtype
                break
        if any(k in low for k in ("transfert de zone", "axfr", "zone transfer")):
            params["axfr"] = True
        if any(k in low for k in ("court", "short", "juste l ip", "juste l'adresse")):
            params["short"] = True
        if "trace" in low:
            params["trace"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        answers = re.findall(r"^\S+\s+\d+\s+IN\s+(A|AAAA|MX|NS|TXT|CNAME|SOA)\s+(.+)$", stdout, re.MULTILINE)
        status = re.search(r"status:\s*(\w+)", stdout)
        if status and status.group(1).upper() != "NOERROR":
            findings.append(
                Finding(
                    title=f"Reponse DNS: {status.group(1).upper()}",
                    severity="low" if status.group(1).upper() == "NXDOMAIN" else "info",
                    detail="Le domaine n'existe pas (NXDOMAIN)." if status.group(1).upper() == "NXDOMAIN" else "",
                )
            )
        for rtype, value in answers[:20]:
            findings.append(Finding(title=f"{rtype} -> {value.strip()}", severity="info"))
        if "XFR size" in stdout:
            findings.append(
                Finding(
                    title="Transfert de zone REUSSI (AXFR)",
                    severity="high",
                    detail="Le serveur autorise les transferts de zone: fuite d'inventaire DNS.",
                )
            )
        summary = f"{len(answers)} enregistrement(s) DNS recupere(s)."
        return AnalysisResult(summary=summary, findings=findings, data={"answers": answers}, source="heuristic")


class HostTool(Tool):
    name = "host"
    aliases = ()
    binary = "host"
    description = "Resolution DNS simple (A, PTR, MX)."
    examples = (
        "trouve l ip de example.com",
        "resolution inverse de 8.8.8.8",
    )
    parameters = (
        ParameterSpec("target", "Domaine ou IP", "string", required=True),
        ParameterSpec("record_type", "Type d'enregistrement", "string"),
        ParameterSpec("reverse", "Resolution inverse (PTR)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["host"]
        if params.get("record_type"):
            argv.append("-t")
            argv.append(str(params["record_type"]).upper())
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hosts = extract_hosts(text)
        if hosts:
            params["target"] = hosts[0]
        if any(k in low for k in ("inverse", "reverse", "ptr")):
            params["reverse"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = []
        for addr in re.findall(r"has address (\S+)", stdout):
            findings.append(Finding(title=f"Adresse: {addr}", severity="info"))
        for name in re.findall(r"domain name pointer (\S+)", stdout):
            findings.append(Finding(title=f"PTR -> {name.rstrip('.')}", severity="info"))
        for mx in re.findall(r"mail is handled by \d+ (\S+)", stdout):
            findings.append(Finding(title=f"MX -> {mx.rstrip('.')}", severity="info"))
        if "not found" in stdout.lower():
            findings.append(Finding(title="Aucun enregistrement trouve", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} resultat(s).",
            findings=findings,
            source="heuristic",
        )


class WhoisTool(Tool):
    name = "whois"
    aliases = ()
    binary = "whois"
    description = "Informations d'enregistrement de domaine (proprietaire, dates, serveurs)."
    examples = (
        "qui possede example.com",
        "date d expiration de example.com",
    )
    parameters = (ParameterSpec("target", "Domaine ou IP", "string", required=True),)

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["whois", str(params["target"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        hosts = extract_hosts(text)
        return {"target": hosts[0]} if hosts else {}

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        fields = {
            "registrar": "Registrar",
            "creation date": "Date de creation",
            "registry expiry date": "Date d'expiration",
            "expiry date": "Date d'expiration",
            "name server": "Serveur de noms",
        }
        for key, label in fields.items():
            match = re.search(rf"^\s*{key}\s*:\s*(.+)$", stdout, re.IGNORECASE | re.MULTILINE)
            if match:
                findings.append(Finding(title=f"{label}: {match.group(1).strip()}", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} champ(s) d'enregistrement recupere(s).",
            findings=findings,
            source="heuristic",
        )


register(DigTool())
register(HostTool())
register(WhoisTool())
