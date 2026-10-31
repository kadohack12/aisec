"""Outils de reverse Android/Java: apktool, dex2jar, jadx, androguard, smali."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

# Permissions Android interessantes a signaler.
_DANGEROUS_PERMS = (
    "SEND_SMS",
    "READ_SMS",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "READ_CALL_LOG",
    "CALL_PHONE",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
)
_APK_PATH_RE = re.compile(r"[\w./-]+\.(?:apk|dex|jar|smali)", re.IGNORECASE)


class ApktoolTool(Tool):
    name = "apktool"
    binary = "apktool"
    risk = "low"
    description = "Decode/encode une application Android (ressources et smali)."
    examples = (
        "decode app.apk avec apktool",
        "extrait les ressources de app.apk",
    )
    parameters = (
        ParameterSpec("file", "Fichier APK a decoder", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("decode", "Decoder (d)", "bool", default=True),
        ParameterSpec("no_src", "Ne pas decoder les sources (-s)", "bool", default=False),
        ParameterSpec("no_res", "Ne pas decoder les ressources (-r)", "bool", default=False),
        ParameterSpec("force", "Ecraser la sortie (-f)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["apktool", "d"]
        if params.get("force"):
            argv.append("-f")
        if params.get("no_src"):
            argv.append("-s")
        if params.get("no_res"):
            argv.append("-r")
        argv.append(str(params["file"]))
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = _APK_PATH_RE.search(text)
        if match:
            params["file"] = match.group(0)
        if "ressources" in low or "sans source" in low:
            params["no_src"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for perm in _DANGEROUS_PERMS:
            if perm in stdout:
                findings.append(
                    Finding(title=f"Permission sensible: {perm}", severity="medium")
                )
        files = re.findall(r"^\s*([\w./-]+\.(?:smali|xml|png|json))", stdout, re.MULTILINE)
        if files:
            findings.append(Finding(title=f"{len(files)} fichier(s) decode(s)", severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) apktool.",
            findings=findings[:60],
            source="heuristic",
        )


class Dex2jarTool(Tool):
    name = "dex2jar"
    aliases = ("d2j-dex2jar",)
    binary = "d2j-dex2jar"
    risk = "low"
    description = "Convertit un fichier dex/APK en archive jar lisible par un decompileur Java."
    examples = (
        "convertit classes.dex en jar avec dex2jar",
        "dex2jar sur app.apk",
    )
    parameters = (
        ParameterSpec("file", "Fichier dex/APK a convertir", "string", required=True),
        ParameterSpec("output", "Jar de sortie (-o)", "string"),
        ParameterSpec("force", "Ecraser la sortie (-f)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["d2j-dex2jar"]
        if params.get("force"):
            argv.append("-f")
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        match = _APK_PATH_RE.search(text)
        if match:
            params["file"] = match.group(0)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = []
        jar = re.search(r"([\w./-]+\.jar)", stdout)
        if jar:
            findings.append(Finding(title=f"Jar genere: {jar.group(1)}", severity="info"))
        if re.search(r"error|exception", stdout, re.IGNORECASE):
            findings.append(Finding(title="Erreurs de conversion dex2jar", severity="low"))
        return AnalysisResult(
            summary=f"Conversion dex2jar: {len(findings)} constat(s).",
            findings=findings,
            source="heuristic",
        )


class JadxTool(Tool):
    name = "jadx"
    binary = "jadx"
    risk = "low"
    description = "Decompilateur dex/APK vers du code Java (CLI)."
    examples = (
        "decompile app.apk avec jadx",
        "jadx sur classes.dex vers le repertoire out",
    )
    parameters = (
        ParameterSpec("file", "APK/dex/jar a decompiler", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-d)", "string"),
        ParameterSpec("no_res", "Ne pas decompiler les ressources (--no-res)", "bool", default=False),
        ParameterSpec("deobf", "Activer la deobfuscation (--deobf)", "bool", default=False),
        ParameterSpec("threads", "Nombre de threads (-j)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["jadx"]
        if params.get("output"):
            argv += ["-d", str(params["output"])]
        if params.get("no_res"):
            argv.append("--no-res")
        if params.get("deobf"):
            argv.append("--deobf")
        if params.get("threads"):
            argv += ["-j", str(params["threads"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = _APK_PATH_RE.search(text)
        if match:
            params["file"] = match.group(0)
        if "deobfusc" in low or "obfusqu" in low:
            params["deobf"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        classes = re.findall(r"([\w.]+)\.java", stdout)
        if classes:
            findings.append(Finding(title=f"{len(set(classes))} classe(s) decompilee(s)", severity="info"))
        for perm in _DANGEROUS_PERMS:
            if perm in stdout:
                findings.append(Finding(title=f"Permission sensible: {perm}", severity="medium"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) jadx.",
            findings=findings[:60],
            source="heuristic",
        )


class AndroguardTool(Tool):
    name = "androguard"
    binary = "androguard"
    risk = "low"
    description = "Analyse statique d'une application Android (permissions, activites, API)."
    examples = (
        "analyse les permissions de app.apk avec androguard",
        "androguard sur app.apk",
    )
    parameters = (
        ParameterSpec("file", "APK a analyser", "string", required=True),
        ParameterSpec("action", "Sous-commande: apk, axml, arsc", "string", default="apk"),
        ParameterSpec("list", "Lister les informations (list)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["androguard", str(params.get("action") or "apk")]
        if params.get("list"):
            argv.append(str(params["list"]))
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        match = _APK_PATH_RE.search(text)
        if match:
            params["file"] = match.group(0)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for perm in _DANGEROUS_PERMS:
            if perm in stdout:
                findings.append(Finding(title=f"Permission sensible: {perm}", severity="medium"))
        for line in stdout.splitlines():
            if "package" in line.lower() or "main activity" in line.lower():
                findings.append(Finding(title=line.strip()[:140], severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) androguard.",
            findings=findings[:60],
            source="heuristic",
        )


class BaksmaliTool(Tool):
    name = "baksmali"
    aliases = ("libsmali-java",)
    binary = "baksmali"
    risk = "low"
    description = "Desassemble un fichier dex en code smali lisible."
    examples = (
        "desassemble classes.dex avec baksmali",
        "baksmali sur app.dex",
    )
    parameters = (
        ParameterSpec("file", "Fichier dex a desassembler", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["baksmali", "disassemble"]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        match = _APK_PATH_RE.search(text)
        if match:
            params["file"] = match.group(0)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = []
        classes = re.findall(r"([\w/]+\.smali)", stdout)
        if classes:
            findings.append(Finding(title=f"{len(classes)} fichier(s) smali genere(s)", severity="info"))
        return AnalysisResult(
            summary=f"Desassemblage smali: {len(findings)} constat(s).",
            findings=findings,
            source="heuristic",
        )


class SmaliTool(Tool):
    name = "smali"
    binary = "smali"
    risk = "medium"
    description = "Assemble du code smali en un fichier dex (modification d'application)."
    examples = (
        "assemble le repertoire smali/ en app.dex avec smali",
        "smali assemble out/ vers classes.dex",
    )
    parameters = (
        ParameterSpec("input", "Repertoire ou fichier smali", "string", required=True),
        ParameterSpec("output", "Dex de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["smali", "assemble"]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        argv.append(str(params["input"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        match = re.search(r"[\w./-]+/?\b", text)
        directory = re.search(r"(?:repertoire|dossier|de)\s+([\w./-]+)", text, re.IGNORECASE)
        if directory:
            params["input"] = directory.group(1)
        elif match and "smali" in text.lower():
            params["input"] = "smali"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = []
        if re.search(r"\.dex", stdout):
            findings.append(Finding(title="Dex assemble genere", severity="info"))
        if re.search(r"error|exception", stdout, re.IGNORECASE):
            findings.append(Finding(title="Erreurs d'assemblage smali", severity="medium"))
        return AnalysisResult(
            summary=f"Assemblage smali: {len(findings)} constat(s).",
            findings=findings,
            source="heuristic",
        )


register(ApktoolTool())
register(Dex2jarTool())
register(JadxTool())
register(AndroguardTool())
register(BaksmaliTool())
register(SmaliTool())
