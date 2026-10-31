"""Outil hydra: attaque de mots de passe en ligne (multi-protocoles)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

_PROTOCOLS = {
    "ssh": "ssh",
    "ftp": "ftp",
    "rdp": "rdp",
    "smb": "smb",
    "telnet": "telnet",
    "vnc": "vnc",
    "mysql": "mysql",
    "postgres": "postgres",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imap",
    "http": "http-get",
    "https": "https-get",
    "http-post": "http-post-form",
    "formulaire": "http-post-form",
    "web": "http-get",
}
_HOST_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9\-]*\.[a-z]{2,})\b", re.IGNORECASE)


class HydraTool(Tool):
    name = "hydra"
    binary = "hydra"
    aliases = ("hydraAI",)
    risk = "high"
    description = "Attaque de mots de passe en ligne sur un service (ssh, ftp, rdp, http, ...)."
    examples = (
        "teste les mots de passe ssh sur 10.0.0.1 avec la liste users.txt et rockyou.txt",
        "brute force ftp sur example.com",
    )
    parameters = (
        ParameterSpec("target", "Cible (IP ou domaine)", "string", required=True),
        ParameterSpec("protocol", "Protocole: ssh, ftp, rdp, smb, mysql, http-get, ...", "string", required=True),
        ParameterSpec("userlist", "Liste d'utilisateurs (-L)", "string"),
        ParameterSpec("username", "Utilisateur unique (-l)", "string"),
        ParameterSpec("passlist", "Liste de mots de passe (-P)", "string"),
        ParameterSpec("password", "Mot de passe unique (-p)", "string"),
        ParameterSpec("port", "Port du service (-s)", "int"),
        ParameterSpec("threads", "Nombre de taches paralleles (-t)", "int", default=4),
        ParameterSpec("tasks", "Nombre d'hotes en parallele (-M)", "int"),
        ParameterSpec("verbose", "Verbeux (-V)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hydra"]
        if params.get("userlist"):
            argv += ["-L", str(params["userlist"])]
        elif params.get("username"):
            argv += ["-l", str(params["username"])]
        if params.get("passlist"):
            argv += ["-P", str(params["passlist"])]
        elif params.get("password"):
            argv += ["-p", str(params["password"])]
        if params.get("port"):
            argv += ["-s", str(params["port"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        if params.get("tasks"):
            argv += ["-M", str(params["tasks"])]
        if params.get("verbose"):
            argv.append("-V")
        argv.append(str(params["target"]))
        argv.append(str(params["protocol"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        host = _HOST_RE.search(text)
        if host:
            params["target"] = host.group(1)
        for key, proto in _PROTOCOLS.items():
            if re.search(rf"\b{re.escape(key)}\b", low):
                params["protocol"] = proto
                break
        userlist = re.search(r"(?:liste d'utilisateurs|userlist|users)\s+([\w./\-]+)", text, re.IGNORECASE)
        if userlist:
            params["userlist"] = userlist.group(1)
        username = re.search(r"utilisateur\s+(\w+)", low)
        if username:
            params["username"] = username.group(1)
        passlist = re.search(r"(?:liste de mots de passe|passlist|rockyou[\w./\-]*)", text, re.IGNORECASE)
        if passlist:
            value = passlist.group(0).split()[-1]
            params["passlist"] = value if value.lower().startswith(("/", ".")) or "." in value else "/usr/share/wordlists/rockyou.txt"
        port = re.search(r"port\s+(\d{2,5})", low)
        if port:
            params["port"] = int(port.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            match = re.search(
                r"\[(\d+)\]\[(\w[\w\-]*)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
                line,
            )
            if match:
                _, proto, host, login, password = match.groups()
                findings.append(
                    Finding(
                        title=f"Identifiants trouves: {login}:{password}",
                        severity="critical",
                        detail=f"{proto} sur {host}",
                        evidence=line.strip(),
                    )
                )
        summary = (
            f"{len(findings)} identifiant(s) valide(s) trouve(s)."
            if findings
            else "Aucun identifiant valide trouve."
        )
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(HydraTool())
