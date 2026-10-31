"""Outil john: cassage de mots de passe hors ligne (John the Ripper)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Formats de hash -> nom de format John.
_FORMATS = {
    "ntlm": "nt",
    "ntlmv2": "netntlmv2",
    "lm": "lm",
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "bcrypt": "bcrypt",
    "sha512crypt": "sha512crypt",
    "md5crypt": "md5crypt",
    "descrypt": "descrypt",
    "zip": "zip",
    "rar": "rar",
    "pdf": "pdf",
    "ssh": "ssh",
    "keepass": "keepass",
}
_CRACKED_RE = re.compile(r"^(\S+):(.*?):?(.*)$", re.MULTILINE)


class JohnTool(Tool):
    name = "john"
    binary = "john"
    aliases = ("johnAI",)
    risk = "high"
    description = "Cassage hors ligne de hashes (John the Ripper): NT, md5crypt, zip, pdf, ssh..."
    examples = (
        "casse le fichier hashes.txt au format ntlm avec rockyou",
        "crack les hashes sha512crypt avec john",
    )
    parameters = (
        ParameterSpec("hashfile", "Fichier de hashes (ou --format avant)", "string", required=True),
        ParameterSpec("format", "Format de hash (--format): nt, raw-md5, bcrypt, ...", "string"),
        ParameterSpec("wordlist", "Dictionnaire (--wordlist)", "string"),
        ParameterSpec("rules", "Regles de mutation (--rules)", "bool", default=False),
        ParameterSpec("incremental", "Mode incremental (--incremental)", "bool", default=False),
        ParameterSpec("show", "Afficher les hashes deja casses (--show)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["john"]
        if params.get("format"):
            argv += ["--format", str(params["format"])]
        if params.get("wordlist"):
            argv += ["--wordlist", str(params["wordlist"])]
        if params.get("rules"):
            argv.append("--rules")
        if params.get("incremental"):
            argv.append("--incremental")
        if params.get("show"):
            argv.append("--show")
        argv.append(str(params["hashfile"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hashfile = re.search(r"([\w./\-]+\.(?:txt|hash|hashes|ntds|pot))", text, re.IGNORECASE)
        if hashfile:
            params["hashfile"] = hashfile.group(1)
        for key, fmt in _FORMATS.items():
            if re.search(rf"\b{re.escape(key)}\b", low):
                params["format"] = fmt
                break
        wordlist = re.search(r"(?:dictionnaire|wordlist|rockyou[\w./\-]*)", text, re.IGNORECASE)
        if wordlist:
            value = wordlist.group(0).split()[-1]
            params["wordlist"] = value if value.lower().startswith(("/", ".")) else "/usr/share/wordlists/rockyou.txt"
        if "regle" in low or "rules" in low:
            params["rules"] = True
        if "incremental" in low:
            params["incremental"] = True
        if "affiche" in low or "show" in low or "deja" in low:
            params["show"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if "No password hashes loaded" in stdout:
            findings.append(Finding(title="Aucun hash charge", severity="info"))
        for match in re.finditer(r"^(\S+):(.*)$", stdout, re.MULTILINE):
            user, value = match.groups()
            if user.startswith("Loaded") or "(" in user:
                continue
            findings.append(
                Finding(
                    title=f"Hash casse: {user} -> {value}",
                    severity="critical",
                    evidence=match.group(0).strip(),
                )
            )
        summary = (
            f"{len(findings)} hash(es) casse(s)."
            if findings
            else "Aucun hash casse pour l'instant."
        )
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(JohnTool())
