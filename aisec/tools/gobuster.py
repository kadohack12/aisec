"""Outil gobuster: force brute de repertoires, DNS, vhosts et fichiers."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts

# Sortie dir/vhost: chemin (Status: 200) [Size: 1234]
_FOUND_RE = re.compile(
    r"^(/?\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?", re.MULTILINE
)
# Sortie dns: Found: sub.example.com
_DNS_RE = re.compile(r"Found:\s*(\S+)", re.MULTILINE)

_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403}

# Dictionnaire par defaut (chemin standard Parrot/Kali).
_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_DEFAULT_DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


class GobusterTool(Tool):
    name = "gobuster"
    binary = "gobuster"
    risk = "medium"
    description = "Force brute de repertoires/fichiers web, sous-domaines DNS et vhosts."
    examples = (
        "brute force les repertoires de https://example.com avec gobuster",
        "enumere les sous-domaines de example.com par brute force",
    )
    parameters = (
        ParameterSpec("mode", "Mode: dir, dns, vhost, fuzz", "string", default="dir"),
        ParameterSpec("url", "URL cible (mode dir/vhost/fuzz)", "string"),
        ParameterSpec("domain", "Domaine cible (mode dns)", "string"),
        ParameterSpec("wordlist", "Chemin du dictionnaire (-w)", "string", required=True),
        ParameterSpec("threads", "Nombre de threads (-t)", "int", default=10),
        ParameterSpec("extensions", "Extensions de fichiers (-x), ex: 'php,html'", "list"),
        ParameterSpec("status_codes", "Codes a afficher (--status-codes)", "string"),
        ParameterSpec("no_error", "Masquer les erreurs (-q)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = str(params.get("mode") or "dir").lower()
        argv = ["gobuster", mode]
        if mode == "dns":
            argv += ["-d", str(params["domain"])]
        else:
            argv += ["-u", str(params["url"])]
        default_list = _DEFAULT_DNS_WORDLIST if mode == "dns" else _DEFAULT_WORDLIST
        argv += ["-w", str(params.get("wordlist") or default_list)]
        argv += ["-t", str(params.get("threads") or 10)]
        extensions = params.get("extensions") or []
        if extensions:
            argv += ["-x", ",".join(str(e) for e in extensions)]
        if params.get("status_codes"):
            argv += ["--status-codes", str(params["status_codes"])]
        if params.get("no_error"):
            argv.append("-q")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        wordlist = re.search(r"(?:dictionnaire|wordlist)\s+([\w./\-]+)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        if "sous-domaine" in low or "subdomain" in low or "dns" in low:
            params["mode"] = "dns"
            hosts = extract_hosts(text)
            if hosts:
                params["domain"] = hosts[0]
        else:
            params["mode"] = "dir"
            match = re.search(r"(https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
            if match:
                params["url"] = match.group(1)
        extensions = re.search(r"extensions?\s+([\w,]+)", low)
        if extensions:
            params["extensions"] = extensions.group(1).split(",")
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for path, status, size in _FOUND_RE.findall(stdout):
            code = int(status)
            severity = "medium" if code in _INTERESTING else "info"
            detail = f"Taille: {size} octets" if size else ""
            findings.append(
                Finding(title=f"{path} [{code}]", severity=severity, detail=detail)
            )
        for name in _DNS_RE.findall(stdout):
            findings.append(Finding(title=f"Sous-domaine: {name}", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} ressource(s) trouvee(s) par gobuster.",
            findings=findings[:60],
            source="heuristic",
        )


register(GobusterTool())
