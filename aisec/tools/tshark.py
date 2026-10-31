"""Plugin tshark: capture et analyse de trafic reseau en langage naturel."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool


class TsharkTool(Tool):
    name = "tshark"
    aliases = ("tsharkAI", "wireshark")
    binary = "tshark"
    risk = "low"
    description = (
        "Analyse de trafic: capture live ou lecture de pcap, filtres d'affichage."
    )
    examples = (
        "capture le trafic http sur eth0 pendant 100 paquets",
        "lis capture.pcap et affiche les requetes dns",
        "filtre les paquets tcp vers le port 443 dans traffic.pcap",
    )
    parameters = (
        ParameterSpec("interface", "Interface reseau (ex: eth0, any)", "string"),
        ParameterSpec("read_file", "Fichier pcap a lire (-r)", "string"),
        ParameterSpec("write_file", "Fichier pcap de sortie (-w)", "string"),
        ParameterSpec(
            "capture_filter",
            "Filtre de capture BPF (-f), ex: 'tcp port 80'",
            "string",
        ),
        ParameterSpec(
            "display_filter",
            "Filtre d'affichage Wireshark (-Y), ex: 'http.request'",
            "string",
        ),
        ParameterSpec("count", "Nombre de paquets a capturer (-c)", "int"),
        ParameterSpec("duration", "Duree de capture en secondes (-a duration:N)", "int"),
        ParameterSpec("fields", "Champs a extraire (-e ...)", "list"),
        ParameterSpec("output_format", "Format de sortie: fields, json, pdml, text", "string"),
        ParameterSpec("verbose", "Verbeux (-V)", "bool", default=False),
    )

    # ---- Construction de la commande --------------------------------------

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["tshark"]

        if params.get("interface"):
            argv += ["-i", str(params["interface"])]
        if params.get("read_file"):
            argv += ["-r", str(params["read_file"])]
        if params.get("write_file"):
            argv += ["-w", str(params["write_file"])]
        if params.get("capture_filter"):
            argv += ["-f", str(params["capture_filter"])]
        if params.get("count"):
            argv += ["-c", str(params["count"])]
        if params.get("duration"):
            argv += ["-a", f"duration:{params['duration']}"]

        fmt = (params.get("output_format") or "").lower()
        if fmt == "fields" or params.get("fields"):
            argv += ["-T", "fields"]
            for field in params.get("fields", []) or []:
                argv += ["-e", str(field)]
        elif fmt in {"json", "pdml", "text"}:
            argv += ["-T", fmt]

        if params.get("display_filter"):
            argv += ["-Y", str(params["display_filter"])]

        if params.get("verbose"):
            argv.append("-V")

        return argv

    # ---- Traduction heuristique intention -> params ------------------------

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}

        pcap = re.search(r"([\w./\-]+\.pcap(?:ng)?|[\w./\-]+\.cap)", text, re.IGNORECASE)
        if pcap:
            params["read_file"] = pcap.group(1)
        else:
            iface = re.search(r"\b(?:sur|on|interface)\s+([a-z]+\d+|\w+)\b", low)
            if iface and iface.group(1) not in {"le", "la", "les"}:
                params["interface"] = iface.group(1)

        count = re.search(r"(\d+)\s*(?:paquets|packets)", low)
        if count:
            params["count"] = int(count.group(1))

        duration = re.search(r"(\d+)\s*(?:secondes|second|sec|s)\b", low)
        if duration:
            params["duration"] = int(duration.group(1))

        display = _guess_display_filter(low)
        if display:
            params["display_filter"] = display

        port = re.search(r"\bport\s+(\d+)", low)
        if port and "display_filter" not in params:
            params["capture_filter"] = f"tcp port {port.group(1)}"

        fields = _guess_fields(low)
        if fields:
            params["fields"] = fields
            params["output_format"] = "fields"

        return params

    # ---- Analyse heuristique ----------------------------------------------

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        packet_count = len(lines)

        ip_pairs: dict[tuple[str, str], int] = {}
        for line in lines:
            ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            if len(ips) >= 2:
                key = (ips[0], ips[1])
                ip_pairs[key] = ip_pairs.get(key, 0) + 1

        for (src, dst), n in sorted(ip_pairs.items(), key=lambda kv: -kv[1])[:5]:
            if n >= 5:
                findings.append(
                    Finding(
                        title=f"Flux dense {src} -> {dst}",
                        severity="low",
                        detail=f"{n} paquets observes; a verifier.",
                    )
                )

        for pattern, title, severity in (
            (r"\b(?:password|passwd|pwd)=(\S+)", "Mot de passe en clair", "critical"),
            (r"Authorization:\s*Basic\s+\S+", "Auth Basic en clair", "high"),
            (r"\.onion\b", "Trafic Tor detecte", "medium"),
        ):
            if re.search(pattern, stdout, re.IGNORECASE):
                findings.append(Finding(title=title, severity=severity))

        return AnalysisResult(
            summary=f"{packet_count} ligne(s) de sortie analysee(s).",
            findings=findings,
            data={"packets": packet_count},
            source="heuristic",
        )


def _guess_display_filter(low: str) -> str:
    mapping = {
        "http": "http",
        "dns": "dns",
        "tls": "tls",
        "ssl": "tls",
        "dhcp": "dhcp",
        "arp": "arp",
        "icmp": "icmp",
        "ftp": "ftp",
    }
    for key, value in mapping.items():
        if re.search(rf"\b{key}\b", low):
            return value
    return ""


def _guess_fields(low: str) -> list[str]:
    if "ip" in low and any(k in low for k in ("source", "destination", "src", "dst")):
        return ["ip.src", "ip.dst"]
    return []


register(TsharkTool())
