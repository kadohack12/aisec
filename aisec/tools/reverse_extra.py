"""Classe 07 - Reverse Engineering : outils complementaires.

Sous-categories couvertes:
  - 07-reverseengineer (direct): android-sdk, ghidra, rizin-cutter
  - 07-02-debuggers            : edb-debugger, javasnoop, ollydbg
  - 07-03-decompilers          : bytecode-viewer, jd-gui, recstudio

Plusieurs de ces entrees sont des lanceurs graphiques: on expose la commande
reelle quand elle existe (ghidra -> analyzeHeadless, android-sdk -> sdkmanager),
sinon le lanceur lui-meme. Aucun desassemblage n'est intrusif: risque `low`.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Option, Pattern, Positional, SpecTool


class GhidraTool(SpecTool):
    name = "ghidra"
    binary = "analyzeHeadless"
    risk = "low"
    description = "Suite de reverse engineering (desassemblage/decompilation en lot)."
    examples = ("analyse le binaire sample.exe avec ghidra",)
    parameters = (
        ParameterSpec("project", "Repertoire de projet", "string", required=True),
        ParameterSpec("name", "Nom du projet", "string", required=True),
        ParameterSpec("binary", "Binaire a analyser (-import)", "string"),
    )
    positionals = (Positional("project"), Positional("name"))
    options = (Option("binary", "-import"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Decompiling|analyzed", "Fonction analyse: {0}", "info"),
        Pattern(r"symbol|FUN_", "Symbole detecte: {0}", "info"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:exe|elf|bin|so|dll)\b", text, re.IGNORECASE)
        if m:
            params["binary"] = m.group(0)
        return params


class AndroidSdkTool(SpecTool):
    name = "android-sdk"
    aliases = ("sdkmanager",)
    binary = "sdkmanager"
    risk = "low"
    description = "Outils Android SDK (gestion des plateformes et emulateurs)."
    examples = ("liste les composants android sdk avec android-sdk",)
    parameters = (ParameterSpec("action", "Action (--list, --install)", "string"),)
    positionals = (Positional("action"),)
    patterns = (Pattern(r"(\S+)\s+\|", "Composant: {0}", "info"),)


class RizinCutterTool(SpecTool):
    name = "rizin-cutter"
    aliases = ("cutter",)
    binary = "cutter"
    risk = "low"
    description = "Interface graphique d'analyse binaire basee sur Rizin."
    examples = ("ouvre cutter sur le binaire sample.bin",)
    parameters = (ParameterSpec("binary", "Binaire a analyser", "string", required=True),)
    positionals = (Positional("binary"),)
    patterns = (Pattern(r"function|sym\.", "Fonction detectee: {0}", "info"),)


class EdbDebuggerTool(SpecTool):
    name = "edb-debugger"
    aliases = ("edb",)
    binary = "edb"
    risk = "low"
    description = "Debogueur graphique (Evan's Debugger)."
    examples = ("lance edb-debugger sur le binaire sample",)
    parameters = (ParameterSpec("binary", "Binaire a deboguer", "string", required=True),)
    positionals = (Positional("binary"),)
    patterns = (Pattern(r"breakpoint|0x[0-9a-f]+", "Point d'arret: {0}", "info"),)


class JavasnoopTool(SpecTool):
    name = "javasnoop"
    binary = "javasnoop"
    risk = "medium"
    description = "Instrumente et espionne des applications Java (bytecode)."
    examples = ("instrumente l'application java avec javasnoop",)
    parameters = (ParameterSpec("target", "Classe ou jar a instrumenter", "string", required=True),)
    positionals = (Positional("target"),)
    patterns = (Pattern(r"intercept|hooked", "Methode interceptee: {0}", "medium"),)


class OllydbgTool(SpecTool):
    name = "ollydbg"
    binary = "ollydbg"
    risk = "low"
    description = "Debogueur Windows 32 bits (analyse de binaires PE)."
    examples = ("lance ollydbg sur sample.exe",)
    parameters = (ParameterSpec("binary", "Binaire PE", "string", required=True),)
    positionals = (Positional("binary"),)
    patterns = (Pattern(r"0x[0-9a-f]+", "Adresse: {0}", "info"),)


class BytecodeViewerTool(SpecTool):
    name = "bytecode-viewer"
    binary = "bytecode-viewer"
    risk = "low"
    description = "Decompilateur Java multi-moteurs (interface graphique)."
    examples = ("decompile application.jar avec bytecode-viewer",)
    parameters = (ParameterSpec("jar", "Archive Java", "string", required=True),)
    positionals = (Positional("jar"),)
    patterns = (Pattern(r"class|method", "Classe decompilee: {0}", "info"),)


class JdGuiTool(SpecTool):
    name = "jd-gui"
    binary = "jd-gui"
    risk = "low"
    description = "Decompilateur Java graphique (jd-gui)."
    examples = ("decompile application.jar avec jd-gui",)
    parameters = (ParameterSpec("jar", "Archive Java", "string", required=True),)
    positionals = (Positional("jar"),)
    patterns = (Pattern(r"public|private|class", "Methode decompilee: {0}", "info"),)


class RecstudioTool(SpecTool):
    name = "recstudio"
    binary = "recstudio"
    risk = "low"
    description = "Decompilateur interactif multi-architectures."
    examples = ("decompile sample.bin avec recstudio",)
    parameters = (ParameterSpec("binary", "Binaire", "string", required=True),)
    positionals = (Positional("binary"),)
    patterns = (Pattern(r"function|sub_", "Fonction decompilee: {0}", "info"),)


for _tool in (
    GhidraTool(), AndroidSdkTool(), RizinCutterTool(), EdbDebuggerTool(),
    JavasnoopTool(), OllydbgTool(), BytecodeViewerTool(), JdGuiTool(), RecstudioTool(),
):
    register(_tool)
