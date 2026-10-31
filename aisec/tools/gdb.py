"""Debogueur GDB (et GEF): inspection d'un programme en execution (batch)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_binary


class GdbTool(Tool):
    name = "gdb"
    aliases = ("gdb-gef",)
    binary = "gdb"
    risk = "medium"
    description = "Debogue un programme en mode batch (commandes via -ex) pour l'analyser."
    examples = (
        "desassemble main de sample.exe avec gdb",
        "affiche les fonctions de sample.elf avec gdb",
    )
    parameters = (
        ParameterSpec("file", "Programme a deboguer", "string", required=True),
        ParameterSpec("commands", "Commandes GDB a executer (-ex)", "string"),
        ParameterSpec("disassemble", "Desassembler une fonction (disassemble)", "string"),
        ParameterSpec("symbols", "Lister les fonctions (info functions)", "bool", default=False),
        ParameterSpec("batch", "Mode batch (--batch)", "bool", default=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["gdb"]
        if params.get("batch", True):
            argv.append("--batch")
        commands: list[str] = []
        if params.get("disassemble"):
            commands.append(f"disassemble {params['disassemble']}")
        if params.get("symbols"):
            commands.append("info functions")
        if params.get("commands"):
            commands.append(str(params["commands"]))
        if not commands:
            commands.append("info functions")
        for cmd in commands:
            argv += ["-ex", cmd]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"batch": True}
        path = extract_binary(text)
        if path:
            params["file"] = path
        if "desassembl" in low:
            fn = re.search(r"(?:fonction|de)\s+(\w+)", low)
            params["disassemble"] = fn.group(1) if fn else "main"
        elif "fonction" in low:
            params["symbols"] = True
        else:
            params["symbols"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        functions = re.findall(r"^\s*\d+:\s+(0x[0-9a-fA-F]+)\s+(\S+)", stdout, re.MULTILINE)
        for _addr, name in functions[:40]:
            findings.append(Finding(title=f"Fonction: {name}", severity="info"))
        disasm = re.findall(r"0x[0-9a-fA-F]+\s+<([^>+]+)(?:\+\d+)?>:\s+(.*)", stdout)
        if disasm:
            findings.append(Finding(title=f"{len(disasm)} instruction(s) desassemblee(s)", severity="info"))
            if any(re.search(r"\b(call|jmp)\b.*<(system|strcpy|gets|exec)", instr) for _f, instr in disasm):
                findings.append(
                    Finding(
                        title="Appel a une fonction sensible",
                        severity="medium",
                        detail="Appel vers system/strcpy/gets/exec dans le desassemblage.",
                    )
                )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) GDB.",
            findings=findings[:60],
            source="heuristic",
        )


class BddisasmTool(Tool):
    name = "bddisasm"
    binary = "bddisasm"
    risk = "low"
    description = "Desassembleur x86/x64 d'octets bruts (ligne de commande)."
    examples = (
        "desassemble les octets 4889e5 avec bddisasm",
        "decode les instructions 90 90 c3 en x86-64",
    )
    parameters = (
        ParameterSpec("bytes", "Octets hexadecimaux a desassembler", "string", required=True),
        ParameterSpec("bits", "Mode (--64 ou --32)", "string", default="--64"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bddisasm", str(params.get("bits") or "--64")]
        argv.append(str(params["bytes"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        octets = re.findall(r"(?<![\w-])[0-9a-fA-F]{2}(?![\w-])", text)
        if octets:
            params["bytes"] = " ".join(octets)
        if "32" in low:
            params["bits"] = "--32"
        elif "64" in low:
            params["bits"] = "--64"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        findings = [Finding(title=ln.strip()[:120], severity="info") for ln in lines[:40]]
        return AnalysisResult(
            summary=f"{len(lines)} instruction(s) decodee(s).",
            findings=findings,
            source="heuristic",
        )


register(GdbTool())
register(BddisasmTool())
