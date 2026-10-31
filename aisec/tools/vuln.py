"""Outils d'analyse de vulnerabilites (classe `02-vulnerability-analysis`).

Couvre l'audit TLS, les scanners de vulnerabilites, le fuzzing, le stress
testing et l'audit d'equipements Cisco de la classe `02-vulnerability-analysis`.
Chaque outil est un plugin `Tool` (argv sans shell, risque declare).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts

_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_HOST_PORT_RE = re.compile(
    r"\b([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+):(\d{1,5})\b", re.IGNORECASE
)


def _extract_target(text: str) -> str:
    url = _URL_RE.search(text)
    if url:
        return url.group(0).rstrip(".,;)")
    host_port = _HOST_PORT_RE.search(text)
    if host_port:
        return f"{host_port.group(1)}:{host_port.group(2)}"
    hosts = extract_hosts(text)
    return hosts[0] if hosts else ""


class TestsslTool(Tool):
    name = "testssl"
    binary = "testssl.sh"
    aliases = ("testssl.sh",)
    risk = "medium"
    description = "Audit de configuration TLS/SSL: protocoles, ciphers, certificats, CVE."
    examples = (
        "audite le tls de example.com:443",
        "verifie les ciphers et certificats de https://example.com",
    )
    parameters = (
        ParameterSpec("target", "Hote:port ou URL", "string", required=True),
        ParameterSpec("protocols", "Tester les protocoles (-p)", "bool", default=False),
        ParameterSpec("cipher_suites", "Tester les suites de chiffrement (-s)", "bool", default=False),
        ParameterSpec("vulnerabilities", "Tester les vulnerabilites connues (-U)", "bool", default=False),
        ParameterSpec("certificates", "Inspecter le certificat (-S)", "bool", default=False),
        ParameterSpec("full", "Scan complet (-U -p -s -S)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["testssl.sh"]
        if params.get("full"):
            argv += ["-U", "-p", "-s", "-S"]
        else:
            if params.get("protocols"):
                argv.append("-p")
            if params.get("cipher_suites"):
                argv.append("-s")
            if params.get("vulnerabilities"):
                argv.append("-U")
            if params.get("certificates"):
                argv.append("-S")
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        if any(k in low for k in ("complet", "tout", "full")):
            params["full"] = True
        if any(k in low for k in ("protocole", "tls", "ssl version", "version de tls")):
            params["protocols"] = True
        if any(k in low for k in ("cipher", "chiffrement", "suite")):
            params["cipher_suites"] = True
        if any(k in low for k in ("vulnerabilite", "vulnerabilites", "cve", "heartbleed", "poodle")):
            params["vulnerabilities"] = True
        if any(k in low for k in ("certificat", "certificate", "chaine")):
            params["certificates"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"\b(?:VULNERABLE|CRITICAL)\b", line):
                findings.append(Finding(title=line.strip()[:160], severity="high"))
            elif re.search(r"\b(?:WARN|MEDIUM)\b", line):
                findings.append(Finding(title=line.strip()[:160], severity="medium"))
            elif re.search(r"\b(?:NOT ok|offered)\b", line, re.IGNORECASE) and "TLS" in line:
                findings.append(Finding(title=line.strip()[:160], severity="low"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) TLS/SSL.", findings=findings, source="heuristic")


class UnixPrivescCheckTool(Tool):
    name = "unix-privesc-check"
    binary = "unix-privesc-check"
    risk = "high"
    description = "Audit local de privilege escalation sur systemes Unix."
    examples = ("verifie les vecteurs de privilege escalation en local",)
    parameters = (
        ParameterSpec("mode", "Mode: standard, detailed, suid", "string", default="standard"),
        ParameterSpec("output_file", "Fichier de rapport", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["unix-privesc-check", str(params.get("mode") or "standard")]
        if params.get("output_file"):
            argv.append(str(params["output_file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"mode": "standard"}
        if "detailed" in low or "detaille" in low:
            params["mode"] = "detailed"
        if "suid" in low:
            params["mode"] = "suid"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="medium")
            for line in stdout.splitlines()
            if re.search(r"WARNING|WRITABLE|SUID", line, re.IGNORECASE)
        ]
        return AnalysisResult(summary=f"{len(findings)} piste(s) de privilege escalation.", findings=findings, source="heuristic")


class BanditTool(Tool):
    name = "bandit"
    binary = "bandit"
    aliases = ("python3-bandit",)
    risk = "low"
    description = "Analyse statique de securite du code Python (SAST)."
    examples = ("analyse la securite du code python dans ./src avec bandit",)
    parameters = (
        ParameterSpec("targets", "Fichiers ou repertoires a analyser (-r)", "list", required=True),
        ParameterSpec("recursive", "Analyse recursive (-r)", "bool", default=True),
        ParameterSpec("severity", "Niveau minimal (-ll / -lll)", "string"),
        ParameterSpec("format", "Format de rapport (-f)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bandit"]
        if params.get("recursive"):
            argv.append("-r")
        argv += [str(t) for t in params["targets"]]
        severity = (params.get("severity") or "").lower()
        if severity == "medium":
            argv.append("-ll")
        elif severity == "high":
            argv.append("-lll")
        if params.get("format"):
            argv += ["-f", str(params["format"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"recursive": True}
        paths = re.findall(r"(\.{0,2}/[\w./\-]+|[\w.\-]+\.py)", text)
        if paths:
            params["targets"] = paths
        else:
            params["targets"] = ["."]
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"Issue:\s*\[(\w+)\]\s*(.+)", stdout):
            sev = match.group(1).lower()
            severity = "high" if sev == "high" else ("medium" if sev == "medium" else "low")
            findings.append(Finding(title=match.group(2).strip()[:160], severity=severity))
        total = re.search(r"Total issues.*?:\s*(\d+)", stdout)
        summary = f"{len(findings)} probleme(s) de securite detecte(s)."
        if total:
            summary = f"{total.group(1)} probleme(s) de securite detecte(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


class SfuzzTool(Tool):
    name = "sfuzz"
    binary = "sfuzz"
    risk = "high"
    description = "Fuzzer simple oriente protocoles reseau et fichiers."
    examples = ("fuzz le service sur example.com:80 avec sfuzz",)
    parameters = (
        ParameterSpec("target", "Hote cible (-i)", "string", required=True),
        ParameterSpec("port", "Port cible (-p)", "int"),
        ParameterSpec("payload", "Fichier de payload (-f)", "string"),
        ParameterSpec("protocol", "Protocole (tcp, udp)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["sfuzz"]
        if params.get("protocol"):
            argv += ["-t", str(params["protocol"])]
        argv += ["-i", str(params["target"])]
        if params.get("port"):
            argv += ["-p", str(params["port"])]
        if params.get("payload"):
            argv += ["-f", str(params["payload"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        port = re.search(r"\bport\s+(\d+)", low)
        if port:
            params["port"] = int(port.group(1))
        if "udp" in low:
            params["protocol"] = "udp"
        elif "tcp" in low:
            params["protocol"] = "tcp"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"crash|overflow|segfault", stdout, re.IGNORECASE):
            findings.append(Finding(title="Crash possible detecte au fuzzing", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) fuzzing.", findings=findings, source="heuristic")


class SlowhttptestTool(Tool):
    name = "slowhttptest"
    binary = "slowhttptest"
    risk = "high"
    description = "Test de resistance aux attaques slow HTTP (Slowloris, R-U-Dead-Yet)."
    examples = ("teste la resistance slowloris de http://example.com",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("mode", "Mode (-H slowloris, -B body, -R range, -X slow read)", "string"),
        ParameterSpec("connections", "Connexions (-c)", "int"),
        ParameterSpec("duration", "Duree en secondes (-l)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["slowhttptest"]
        mode = (params.get("mode") or "slowloris").lower()
        flag = {"slowloris": "-H", "body": "-B", "range": "-R", "read": "-X"}.get(mode)
        if flag:
            argv.append(flag)
        argv += ["-u", str(params["url"])]
        if params.get("connections"):
            argv += ["-c", str(params["connections"])]
        if params.get("duration"):
            argv += ["-l", str(params["duration"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["url"] = target
        if "slowloris" in low:
            params["mode"] = "slowloris"
        elif "slow read" in low:
            params["mode"] = "read"
        elif "range" in low:
            params["mode"] = "range"
        elif "body" in low or "post" in low:
            params["mode"] = "body"
        duration = re.search(r"(\d+)\s*(?:secondes|second|sec|s)\b", low)
        if duration:
            params["duration"] = int(duration.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        match = re.search(r"service available:?\s*(\w+)", stdout, re.IGNORECASE)
        if match and match.group(1).lower() in {"no", "false"}:
            findings.append(Finding(title="Serveur vulnerable au slow HTTP (devenu indisponible)", severity="high"))
        elif match:
            findings.append(Finding(title="Serveur resistant au slow HTTP", severity="info"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) slow HTTP.", findings=findings, source="heuristic")


class SiegeTool(Tool):
    name = "siege"
    binary = "siege"
    risk = "high"
    description = "Test de charge HTTP (benchmark de disponibilite)."
    examples = ("teste la charge de http://example.com avec 50 utilisateurs",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("concurrent", "Utilisateurs concurrents (-c)", "int"),
        ParameterSpec("time", "Duree du test (-t)", "string"),
        ParameterSpec("repetitions", "Nombre de repetitions (-r)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["siege"]
        if params.get("concurrent"):
            argv += ["-c", str(params["concurrent"])]
        if params.get("time"):
            argv += ["-t", str(params["time"])]
        if params.get("repetitions"):
            argv += ["-r", str(params["repetitions"])]
        argv += ["-u", str(params["url"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["url"] = target
        conc = re.search(r"(\d+)\s*(?:utilisateurs|users|connexions|concurrents)", low)
        if conc:
            params["concurrent"] = int(conc.group(1))
        duration = re.search(r"(\d+)\s*(?:secondes|second|sec|s)\b", low)
        if duration:
            params["time"] = f"{duration.group(1)}S"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        avail = re.search(r"Availability:\s*([\d.]+)", stdout)
        if avail:
            value = float(avail.group(1))
            findings.append(
                Finding(
                    title=f"Disponibilite sous charge: {value}%",
                    severity="high" if value < 99 else "info",
                )
            )
        return AnalysisResult(summary=f"{len(findings)} constat(s) de charge.", findings=findings, source="heuristic")


class YersiniaTool(Tool):
    name = "yersinia"
    binary = "yersinia"
    risk = "high"
    description = "Attaques de niveau 2 (VLAN hopping, STP, DHCP, DTP)."
    examples = ("lance une attaque stp avec yersinia sur eth0",)
    parameters = (
        ParameterSpec("protocol", "Protocole (stp, cdp, dhcp, dtp, vtp)", "string"),
        ParameterSpec("interface", "Interface reseau (-I)", "string"),
        ParameterSpec("attack", "Type d'attaque (-attack)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["yersinia"]
        if params.get("interface"):
            argv += ["-I", str(params["interface"])]
        if params.get("attack"):
            argv += ["-attack", str(params["attack"])]
        if params.get("protocol"):
            argv.append(str(params["protocol"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        for proto in ("stp", "cdp", "dhcp", "dtp", "vtp"):
            if proto in low:
                params["protocol"] = proto
                break
        iface = re.search(r"\b(eth\d+|wlan\d+|ens\d+)\b", low)
        if iface:
            params["interface"] = iface.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"attack.*(?:sent|done|success)", stdout, re.IGNORECASE):
            findings.append(Finding(title="Attaque niveau 2 envoyee", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) niveau 2.", findings=findings, source="heuristic")


class T50Tool(Tool):
    name = "t50"
    binary = "t50"
    risk = "critical"
    description = "Injecteur de paquets multi-protocoles (test de stress reseau)."
    examples = ("injecte du trafic tcp vers example.com avec t50",)
    parameters = (
        ParameterSpec("target", "Cible", "string", required=True),
        ParameterSpec("protocol", "Protocole (tcp, udp, icmp)", "string"),
        ParameterSpec("port", "Port cible", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["t50", str(params["target"])]
        if params.get("protocol"):
            argv += ["--protocol", str(params["protocol"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        for proto in ("tcp", "udp", "icmp"):
            if proto in low:
                params["protocol"] = proto
                break
        port = re.search(r"\bport\s+(\d+)", low)
        if port:
            params["port"] = int(port.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        sent = re.search(r"(\d+)\s+packets?\s+sent", stdout, re.IGNORECASE)
        if sent:
            findings.append(Finding(title=f"{sent.group(1)} paquet(s) injecte(s)", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) d'injection.", findings=findings, source="heuristic")


class DhcpigTool(Tool):
    name = "dhcpig"
    binary = "dhcpig"
    risk = "critical"
    description = "Test de stress DHCP (epuisement du pool d'adresses)."
    examples = ("epuise le pool dhcp du reseau avec dhcpig sur eth0",)
    parameters = (ParameterSpec("interface", "Interface reseau", "string", required=True),)

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["dhcpig", str(params["interface"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        iface = re.search(r"\b(eth\d+|wlan\d+|ens\d+)\b", text.lower())
        if iface:
            params["interface"] = iface.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"exhaust|pool.*(?:empty|full)", stdout, re.IGNORECASE):
            findings.append(Finding(title="Pool DHCP epuise", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) DHCP.", findings=findings, source="heuristic")


class CiscoTorchTool(Tool):
    name = "cisco-torch"
    binary = "cisco-torch"
    risk = "high"
    description = "Audit d'equipements Cisco: decouverte, enumeration, tests de securite."
    examples = ("audite l'equipement cisco 192.168.1.1",)
    parameters = (
        ParameterSpec("target", "Adresse de l'equipement Cisco", "string", required=True),
        ParameterSpec("fingerprint", "Fingerprint du type d'equipement (-f)", "bool", default=False),
        ParameterSpec("dict_attack", "Attaque par dictionnaire (-a)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["cisco-torch"]
        if params.get("fingerprint"):
            argv.append("-f")
        if params.get("dict_attack"):
            argv.append("-a")
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        if "fingerprint" in low or "identifie" in low:
            params["fingerprint"] = True
        if "dictionnaire" in low or "dictionary" in low:
            params["dict_attack"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"password|community|snmp", stdout, re.IGNORECASE):
            findings.append(Finding(title="Information sensible Cisco exposee", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) Cisco.", findings=findings, source="heuristic")


class NipperTool(Tool):
    name = "nipper-ng"
    binary = "nipper-ng"
    risk = "medium"
    description = "Audit de configuration d'equipements reseau (Cisco, Juniper...)."
    examples = ("audite la configuration cisco depuis config.txt avec nipper",)
    parameters = (
        ParameterSpec("input", "Fichier de configuration a analyser", "string", required=True),
        ParameterSpec("output_format", "Format de sortie: html, text", "string"),
        ParameterSpec("output_file", "Fichier de sortie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nipper-ng"]
        fmt = params.get("output_format")
        if fmt == "html":
            argv.append("--html")
        else:
            argv.append("--text")
        if params.get("output_file"):
            argv.append(str(params["output_file"]))
        argv.append(str(params["input"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = re.search(r"([\w./\-]+\.(?:cfg|conf|txt))", text, re.IGNORECASE)
        if path:
            params["input"] = path.group(1)
        if "html" in text.lower():
            params["output_format"] = "html"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="medium")
            for line in stdout.splitlines()
            if re.search(r"\b(?:Security|Vulnerability|Warning)\b", line)
        ]
        return AnalysisResult(summary=f"{len(findings)} constat(s) de configuration.", findings=findings, source="heuristic")


register(TestsslTool())
register(UnixPrivescCheckTool())
register(BanditTool())
register(SfuzzTool())
register(SlowhttptestTool())
register(SiegeTool())
register(YersiniaTool())
register(T50Tool())
register(DhcpigTool())
register(CiscoTorchTool())
register(NipperTool())
