"""Suite Radare2: analyse statique, desassemblage, hachage, diff de binaires."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_binary

# rabin2 -I : "arch      x86"
_INFO_RE = re.compile(r"^\s*(\w[\w ]*?)\s{2,}(.+?)\s*$", re.MULTILINE)
# rabin2 -i/-s : "nth vaddr      bind   type   lib name"
_SYMBOL_RE = re.compile(r"^\d+\s+(0x[0-9a-fA-F]+|\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$", re.MULTILINE)
# rabin2 -z : "nth paddr      vaddr      len size section type  string"
_STRING_RE = re.compile(r"^\d+\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$", re.MULTILINE)
# Caracteristiques sensibles a signaler.
_SUSPICIOUS_STRINGS = ("http://", "https://", "password", "passwd", "token", "secret", "api_key", "cmd.exe", "/bin/sh", "chmod", "wget", "curl")


class Rabin2Tool(Tool):
    name = "rabin2"
    binary = "rabin2"
    risk = "low"
    description = "Extrait les metadonnees d'un binaire (en-tetes, sections, symboles, chaines, imports)."
    examples = (
        "extrait les infos de sample.exe avec rabin2",
        "liste les imports de malware.dll",
        "liste les chaines de sample.elf",
    )
    parameters = (
        ParameterSpec("file", "Binaire a analyser", "string", required=True),
        ParameterSpec("info", "Afficher les en-tetes (-I)", "bool", default=False),
        ParameterSpec("sections", "Lister les sections (-S)", "bool", default=False),
        ParameterSpec("imports", "Lister les imports (-i)", "bool", default=False),
        ParameterSpec("exports", "Lister les exports (-E)", "bool", default=False),
        ParameterSpec("symbols", "Lister les symboles (-s)", "bool", default=False),
        ParameterSpec("strings", "Lister les chaines (-z)", "bool", default=False),
        ParameterSpec("json", "Sortie JSON (-j)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rabin2"]
        for flag, key in (
            ("-I", "info"),
            ("-S", "sections"),
            ("-i", "imports"),
            ("-E", "exports"),
            ("-s", "symbols"),
            ("-z", "strings"),
        ):
            if params.get(key):
                argv.append(flag)
        if params.get("json"):
            argv.append("-j")
        if not any(params.get(k) for k in ("info", "sections", "imports", "exports", "symbols", "strings")):
            argv.append("-I")
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_binary(text)
        if path:
            params["file"] = path
        if "section" in low:
            params["sections"] = True
        if "import" in low:
            params["imports"] = True
        if "export" in low:
            params["exports"] = True
        if "symbole" in low or "symbol" in low:
            params["symbols"] = True
        if "chaine" in low or "string" in low:
            params["strings"] = True
        if "info" in low or "en-tete" in low or "entete" in low or "header" in low:
            params["info"] = True
        if "json" in low:
            params["json"] = True
        if not any(k in params for k in ("info", "sections", "imports", "exports", "symbols", "strings")):
            params["info"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        info = dict(_INFO_RE.findall(stdout))
        for key in ("arch", "bits", "bintype", "os", "machine", "lang", "stripped", "packer"):
            for k, v in info.items():
                if k.strip().lower() == key:
                    findings.append(Finding(title=f"{k.strip()}: {v}", severity="info"))
        symbols = _SYMBOL_RE.findall(stdout)
        if symbols:
            findings.append(
                Finding(title=f"{len(symbols)} symbole(s)/import(s)", severity="info")
            )
        for paddr, vaddr, _ln, _sz, _sec, _type, value in _STRING_RE.findall(stdout):
            low = value.lower()
            if any(k in low for k in _SUSPICIOUS_STRINGS):
                findings.append(
                    Finding(
                        title="Chaine interessante",
                        severity="medium",
                        detail=value.strip()[:160],
                        evidence=f"vaddr {vaddr}",
                    )
                )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) sur le binaire.",
            findings=findings[:60],
            source="heuristic",
        )


class Radare2Tool(Tool):
    name = "radare2"
    aliases = ("r2",)
    binary = "radare2"
    risk = "low"
    description = "Desassemble et analyse un binaire en mode batch (commandes r2 via -c)."
    examples = (
        "desassemble la fonction main de sample.exe avec radare2",
        "analyse les fonctions de sample.elf",
    )
    parameters = (
        ParameterSpec("file", "Binaire a analyser", "string", required=True),
        ParameterSpec("commands", "Commandes r2 a executer (-c), separees par ';'", "string"),
        ParameterSpec("analysis", "Analyse complete avant commandes (-A)", "bool", default=False),
        ParameterSpec("function", "Fonction a desassembler (pdf @)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["radare2"]
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
        calls = re.findall(r"\b(call|sym\.imp\.)(\S+)", stdout)
        if calls:
            findings.append(Finding(title=f"{len(calls)} appel(s) detecte(s)", severity="info"))
        if re.search(r"mov\s+.*(strcpy|gets|sprintf|system)", stdout):
            findings.append(
                Finding(
                    title="Fonctions a risque dans le desassemblage",
                    severity="medium",
                    detail="Presence d'appels potentiellement dangereux (strcpy/gets/system).",
                )
            )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) de desassemblage.",
            findings=findings[:60],
            source="heuristic",
        )


class Rahash2Tool(Tool):
    name = "rahash2"
    binary = "rahash2"
    risk = "low"
    description = "Calcule les empreintes (hash) d'un fichier ou d'une plage d'octets."
    examples = (
        "calcule le hash de sample.exe avec rahash2",
        "empreinte sha256 de firmware.bin",
    )
    parameters = (
        ParameterSpec("file", "Fichier a hacher", "string", required=True),
        ParameterSpec("algorithm", "Algorithme (-a), ex: md5, sha256, all", "string", default="sha256"),
        ParameterSpec("blocks", "Hacher par blocs (-b)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rahash2", "-a", str(params.get("algorithm") or "sha256")]
        if params.get("blocks"):
            argv += ["-b", str(params["blocks"])]
        argv.append(str(params["file"]))
        return argv

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
            summary=f"{len(findings)} empreinte(s) calculee(s).",
            findings=findings,
            source="heuristic",
        )


class Rasm2Tool(Tool):
    name = "rasm2"
    binary = "rasm2"
    risk = "low"
    description = "Assemble et desassemble des instructions (mode -d) pour une architecture donnee."
    examples = (
        "desassemble les octets 9090 avec rasm2",
        "assemble 'nop; ret' en x86-64 avec rasm2",
    )
    parameters = (
        ParameterSpec("code", "Octets (hex) ou instructions a traiter", "string", required=True),
        ParameterSpec("disassemble", "Desassembler (-d)", "bool", default=False),
        ParameterSpec("architecture", "Architecture (-a), ex: x86", "string"),
        ParameterSpec("bits", "Taille (-b): 32, 64", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rasm2"]
        if params.get("disassemble"):
            argv.append("-d")
        if params.get("architecture"):
            argv += ["-a", str(params["architecture"])]
        if params.get("bits"):
            argv += ["-b", str(params["bits"])]
        argv.append(str(params["code"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "desassembl" in low:
            params["disassemble"] = True
        hexes = re.search(r"\b([0-9a-fA-F]{2,})\b", text)
        if hexes:
            params["code"] = hexes.group(1)
        if "64" in low:
            params["bits"] = "64"
        elif "32" in low:
            params["bits"] = "32"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        findings = [Finding(title=f"Instruction: {ln.strip()[:100]}", severity="info") for ln in lines[:40]]
        return AnalysisResult(
            summary=f"{len(lines)} instruction(s) traitee(s).",
            findings=findings,
            source="heuristic",
        )


class Radiff2Tool(Tool):
    name = "radiff2"
    binary = "radiff2"
    risk = "low"
    description = "Compare deux binaires (diff de code, de donnees ou de symboles)."
    examples = (
        "compare sample_v1.exe et sample_v2.exe avec radiff2",
        "diff binaire entre deux versions",
    )
    parameters = (
        ParameterSpec("file1", "Premier binaire", "string", required=True),
        ParameterSpec("file2", "Second binaire", "string", required=True),
        ParameterSpec("mode", "Mode de diff (-C code, -g graphe, -s symboles)", "string", default="-C"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["radiff2", str(params.get("mode") or "-C")]
        argv += [str(params["file1"]), str(params["file2"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        binaries = re.findall(r"[\w./-]+\.(?:exe|dll|elf|so|bin|dylib|o|ko)", text, re.IGNORECASE)
        params: dict[str, Any] = {}
        if len(binaries) >= 2:
            params["file1"] = binaries[0]
            params["file2"] = binaries[1]
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        diffs = re.findall(r"^\s*(\d+)\s+(0x[0-9a-fA-F]+)", stdout, re.MULTILINE)
        if diffs:
            findings.append(Finding(title=f"{len(diffs)} difference(s) de code", severity="info"))
        ratio = re.search(r"similarity:\s*([\d.]+)", stdout, re.IGNORECASE)
        if ratio:
            findings.append(
                Finding(title=f"Similarite: {ratio.group(1)}", severity="info")
            )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) de comparaison.",
            findings=findings,
            source="heuristic",
        )


register(Rabin2Tool())
register(Radare2Tool())
register(Rahash2Tool())
register(Rasm2Tool())
register(Radiff2Tool())
