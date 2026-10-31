"""Suite Rizin: analyse, desassemblage, hachage et recherche dans un binaire."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_binary


class RizinTool(Tool):
    name = "rizin"
    aliases = ("rz-bin",)
    binary = "rizin"
    risk = "low"
    description = "Desassemble et analyse un binaire en mode batch (commandes rizin via -c)."
    examples = (
        "desassemble la fonction main de sample.elf avec rizin",
        "analyse les fonctions de sample.exe avec rizin",
    )
    parameters = (
        ParameterSpec("file", "Binaire a analyser", "string", required=True),
        ParameterSpec("commands", "Commandes rizin a executer (-c)", "string"),
        ParameterSpec("analysis", "Analyse complete (-A)", "bool", default=False),
        ParameterSpec("function", "Fonction a desassembler (pdf)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rizin"]
        if params.get("analysis"):
            argv.append("-A")
        commands = params.get("commands")
        if not commands and params.get("function"):
            commands = f"aaa;pdf @ {params['function']}"
        # Une option -c par commande: le ';' est interdit par les garde-fous.
        for cmd in str(commands or "").split(";"):
            if cmd.strip():
                argv += ["-c", cmd.strip()]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_binary(text)
        if path:
            params["file"] = path
        fn = re.search(r"fonction\s+(\w+)", low)
        if fn:
            params["function"] = fn.group(1)
        elif "fonctions" in low:
            params["analysis"] = True
            params["commands"] = "aaa; afl"
        elif "desassembl" in low:
            params["analysis"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        functions = re.findall(r"^\s*0x[0-9a-fA-F]+\s+\d+\s+\d+\s+(\S+)", stdout, re.MULTILINE)
        for name in functions[:40]:
            findings.append(Finding(title=f"Fonction: {name}", severity="info"))
        if re.search(r"\b(call|sym\.imp\.)(\S+)", stdout):
            findings.append(Finding(title="Appels externes detectes", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) rizin.",
            findings=findings[:60],
            source="heuristic",
        )


class RizinHashTool(Tool):
    name = "rz-hash"
    binary = "rz-hash"
    risk = "low"
    description = "Calcule les empreintes d'un fichier ou d'un flux avec la suite Rizin."
    examples = (
        "calcule le hash de sample.elf avec rz-hash",
        "empreinte md5 de firmware.bin",
    )
    parameters = (
        ParameterSpec("file", "Fichier a hacher", "string", required=True),
        ParameterSpec("algorithm", "Algorithme (-a), ex: md5, sha256, all", "string", default="sha256"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["rz-hash", "-a", str(params.get("algorithm") or "sha256"), str(params["file"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_binary(text)
        if path:
            params["file"] = path
        for algo in ("md5", "sha1", "sha256", "sha512", "crc32"):
            if algo in low:
                params["algorithm"] = algo
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=f"Empreinte {algo.upper()}", severity="info", evidence=digest)
            for algo, digest in re.findall(r"([a-z0-9]+)-([0-9a-f]{8,})", stdout, re.IGNORECASE)
        ]
        return AnalysisResult(
            summary=f"{len(findings)} empreinte(s) calculee(s).", findings=findings, source="heuristic"
        )


class RizinFindTool(Tool):
    name = "rz-find"
    binary = "rz-find"
    risk = "low"
    description = "Recherche un motif (chaine, octets, symbole) dans un binaire."
    examples = (
        "cherche la chaine password dans sample.exe avec rz-find",
        "recherche le motif 0xdeadbeef dans firmware.bin",
    )
    parameters = (
        ParameterSpec("file", "Binaire a analyser", "string", required=True),
        ParameterSpec("pattern", "Motif a rechercher (-s chaine, -x hex)", "string"),
        ParameterSpec("strings", "Chercher des chaines (-s)", "string"),
        ParameterSpec("hex", "Chercher des octets hexadecimaux (-x)", "string"),
        ParameterSpec("symbol", "Chercher un symbole (-S)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rz-find"]
        if params.get("strings"):
            argv += ["-s", str(params["strings"])]
        elif params.get("hex"):
            argv += ["-x", str(params["hex"])]
        elif params.get("symbol"):
            argv += ["-S", str(params["symbol"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_binary(text)
        if path:
            params["file"] = path
        quoted = re.search(r"[\"']([^\"']+)[\"']", text)
        if quoted:
            params["strings"] = quoted.group(1)
        else:
            word = re.search(r"(?:chaine|motif|pattern|recherche)\s+(\w+)", low)
            if word:
                params["strings"] = word.group(1)
            else:
                hexm = re.search(r"(0x[0-9a-fA-F]+)", text)
                if hexm:
                    params["hex"] = hexm.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        hits = re.findall(r"0x[0-9a-fA-F]+", stdout)
        findings = [Finding(title=f"Motif trouve a {addr}", severity="info") for addr in hits[:40]]
        return AnalysisResult(
            summary=f"{len(hits)} occurrence(s) du motif.",
            findings=findings,
            source="heuristic",
        )


register(RizinTool())
register(RizinHashTool())
register(RizinFindTool())
