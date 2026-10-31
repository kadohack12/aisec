"""Plugin nmap: traduit une intention en commande nmap et analyse la sortie."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Ports/services notoirement sensibles: utilises pour le scoring d'analyse.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP en clair", "medium"),
    23: ("Telnet en clair", "high"),
    25: ("SMTP", "low"),
    135: ("MSRPC", "medium"),
    139: ("NetBIOS", "medium"),
    445: ("SMB", "high"),
    1433: ("MSSQL", "medium"),
    3306: ("MySQL expose", "medium"),
    3389: ("RDP expose", "high"),
    5432: ("PostgreSQL expose", "medium"),
    5900: ("VNC expose", "high"),
    6379: ("Redis expose", "high"),
    27017: ("MongoDB expose", "high"),
}

_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>open|closed|filtered|open\|filtered)\s+"
    r"(?P<service>\S+)?\s*(?P<version>.*)$",
    re.MULTILINE,
)
_HOST_RE = re.compile(r"Nmap scan report for (\S+)")
_DONE_RE = re.compile(r"Nmap done: (\d+) IP address.*?(\d+) host.*?up", re.DOTALL)


class NmapTool(Tool):
    name = "nmap"
    aliases = ("nmapAI",)
    binary = "nmap"
    risk = "medium"
    description = (
        "Scanner reseau: decouverte d'hotes, de ports ouverts et de services."
    )
    examples = (
        "scanne les ports 22, 80, 8080 sur target.com et detecte les versions",
        "decouverte des hotes vivants sur 192.168.1.0/24",
        "scan udp rapide des 100 ports les plus courants sur 10.0.0.5",
    )
    parameters = (
        ParameterSpec("targets", "Cibles: IP, CIDR ou hostname(s)", "list", required=True),
        ParameterSpec(
            "ports",
            "Ports a scanner. Ex: '22,80,8080', '1-1024', 'top100', 'top1000'",
            "string",
        ),
        ParameterSpec(
            "scan_type",
            "Type de scan: syn, connect, udp, ping, ack, fin, null, xmas",
            "string",
        ),
        ParameterSpec("service_detection", "Detection de version (-sV)", "bool", default=False),
        ParameterSpec("os_detection", "Detection d'OS (-O)", "bool", default=False),
        ParameterSpec("default_scripts", "Scripts par defaut (-sC)", "bool", default=False),
        ParameterSpec("scripts", "Scripts NSE specifiques (--script)", "list"),
        ParameterSpec("aggressive", "Mode agressif (-A)", "bool", default=False),
        ParameterSpec("fast", "Scan rapide des ports courants (-F)", "bool", default=False),
        ParameterSpec("no_ping", "Ne pas faire de ping (-Pn)", "bool", default=False),
        ParameterSpec("timing", "Timing template: T0..T5", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    # ---- Construction de la commande --------------------------------------

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nmap"]

        scan_type = (params.get("scan_type") or "").lower()
        scan_flag = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "ping": "-sn",
            "ack": "-sA",
            "fin": "-sF",
            "null": "-sN",
            "xmas": "-sX",
        }.get(scan_type)
        if scan_flag:
            argv.append(scan_flag)

        if params.get("aggressive"):
            argv.append("-A")
        else:
            if params.get("service_detection"):
                argv.append("-sV")
            if params.get("os_detection"):
                argv.append("-O")
            if params.get("default_scripts"):
                argv.append("-sC")

        for script in params.get("scripts", []) or []:
            argv += ["--script", str(script)]

        if params.get("fast"):
            argv.append("-F")

        if params.get("no_ping"):
            argv.append("-Pn")

        timing = params.get("timing")
        if timing:
            t = str(timing).upper()
            if not t.startswith("T"):
                t = "T" + t
            argv.append("-" + t)

        if params.get("verbose"):
            argv.append("-v")

        ports = params.get("ports")
        if ports:
            argv += _ports_to_args(str(ports))

        argv += [str(t) for t in params.get("targets", [])]
        return argv

    # ---- Traduction heuristique intention -> params ------------------------

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}

        targets = _extract_targets(text)
        if targets:
            params["targets"] = targets

        ports = _extract_ports(low)
        if ports:
            params["ports"] = ports

        if any(k in low for k in ("udp",)):
            params["scan_type"] = "udp"
        elif any(k in low for k in ("syn", "furtif", "stealth", "demi-ouvert")):
            params["scan_type"] = "syn"
        elif any(k in low for k in ("connect", "tcp connect")):
            params["scan_type"] = "connect"
        elif any(k in low for k in ("ping", "decouverte", "decouvrir", "hotes vivants", "live hosts")):
            params["scan_type"] = "ping"

        if any(k in low for k in ("version", "service", "banniere", "banner")):
            params["service_detection"] = True
        if any(k in low for k in ("os", "systeme", "operating")):
            params["os_detection"] = True
        if any(k in low for k in ("vuln", "vulnerabilite", "script", "nse")):
            params["default_scripts"] = True
        if any(k in low for k in ("agressif", "aggressive")):
            params["aggressive"] = True
        if any(k in low for k in ("rapide", "fast")):
            params["fast"] = True
        if any(k in low for k in ("sans ping", "no ping", "-pn", "no_ping")):
            params["no_ping"] = True

        timing = _extract_timing(low)
        if timing:
            params["timing"] = timing

        if "verbose" in low or "-v" in low:
            params["verbose"] = True

        return params

    # ---- Analyse heuristique ----------------------------------------------

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        hosts: dict[str, list[dict[str, str]]] = {}
        current_host = None

        for line in stdout.splitlines():
            host_match = _HOST_RE.search(line)
            if host_match:
                current_host = host_match.group(1)
                hosts.setdefault(current_host, [])
                continue
            port_match = _LINE_RE.match(line.strip())
            if port_match and current_host:
                entry = port_match.groupdict()
                hosts[current_host].append(entry)

        open_count = 0
        for host, ports in hosts.items():
            open_ports = [p for p in ports if p["state"] == "open"]
            open_count += len(open_ports)
            if open_ports:
                listing = ", ".join(
                    f"{p['port']}/{p['proto']} {p['service'] or ''}".strip()
                    for p in open_ports
                )
                findings.append(
                    Finding(
                        title=f"{host}: {len(open_ports)} port(s) ouvert(s)",
                        severity="info",
                        detail=listing,
                    )
                )
            for p in open_ports:
                try:
                    port_num = int(p["port"])
                except (TypeError, ValueError):
                    continue
                if port_num in RISKY_PORTS:
                    label, severity = RISKY_PORTS[port_num]
                    findings.append(
                        Finding(
                            title=f"Service sensible sur {host}:{port_num} ({label})",
                            severity=severity,
                            detail=(
                                f"Le port {port_num}/{p['proto']} expose un service "
                                f"a restreindre ({p['service'] or 'inconnu'})."
                            ),
                            evidence=f"{p['port']}/{p['proto']} {p['state']} {p['service']}",
                        )
                    )

        done = _DONE_RE.search(stdout)
        summary = (
            f"{len(hosts)} hote(s) analyse(s), {open_count} port(s) ouvert(s)."
        )
        if done:
            summary = (
                f"{done.group(2)} hote(s) up sur {done.group(1)} adresse(s), "
                f"{open_count} port(s) ouvert(s)."
            )

        return AnalysisResult(
            summary=summary,
            findings=findings,
            data={"hosts": hosts},
            source="heuristic",
        )


# ---- Fonctions utilitaires ------------------------------------------------


def _ports_to_args(ports: str) -> list[str]:
    low = ports.lower().replace(" ", "")
    if low in {"top100", "top-100", "100"}:
        return ["--top-ports", "100"]
    if low in {"top1000", "top-1000", "1000"}:
        return ["--top-ports", "1000"]
    return ["-p", ports]


def _extract_targets(text: str) -> list[str]:
    # On ignore les nombres isoles qui ressemblent a des ports.
    candidates = re.findall(
        r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/\d{1,2})?)\b",
        text,
        re.IGNORECASE,
    )
    seen: list[str] = []
    for cand in candidates:
        if cand.lower() in {"http", "https", "tcp", "udp"}:
            continue
        if cand not in seen:
            seen.append(cand)
    return seen


def _extract_ports(low: str) -> str:
    if "top1000" in low or "top 1000" in low:
        return "top1000"
    if "top100" in low or "top 100" in low:
        return "top100"
    range_match = re.search(r"\bports?\b[^\d]*(\d+\s*-\s*\d+)", low)
    if range_match:
        return range_match.group(1).replace(" ", "")
    explicit = re.search(r"\bports?\b([\d,\s]+)", low)
    if explicit:
        return ",".join(re.findall(r"\d+", explicit.group(1)))
    return ""


def _extract_timing(low: str) -> str:
    match = re.search(r"\bt([0-5])\b", low)
    if match:
        return "T" + match.group(1)
    if "paranoid" in low:
        return "T0"
    if "sneaky" in low:
        return "T1"
    if "polite" in low:
        return "T2"
    if "normal" in low:
        return "T3"
    if "agressif" in low or "aggressive" in low:
        return "T4"
    if "insane" in low:
        return "T5"
    return ""


register(NmapTool())
