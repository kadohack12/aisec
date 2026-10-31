"""Outils de forensique PDF: pdfid et pdf-parser."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# pdfid: "  /JS                 2" (mot-cle + nombre).
_KEYWORD_RE = re.compile(r"^\s*/([A-Za-z0-9]+)\s+(\d+)\s*$", re.MULTILINE)
# Mots-cles PDF dangereux (execution de code, actions automatiques).
_DANGEROUS = {
    "js": ("JavaScript embarque", "high"),
    "javascript": ("JavaScript embarque", "high"),
    "aa": ("Action automatique (AutoAction)", "high"),
    "openaction": ("Action a l'ouverture (OpenAction)", "high"),
    "launch": ("Action de lancement (Launch)", "high"),
    "embeddedfile": ("Fichier embarque", "medium"),
    "richmedia": ("Contenu RichMedia", "medium"),
    "xfa": ("Formulaire XFA", "medium"),
    "acroform": ("Formulaire AcroForm", "low"),
    "objstm": ("Flux d'objets (obfuscation possible)", "medium"),
}


class PdfidTool(Tool):
    name = "pdfid"
    binary = "pdfid"
    risk = "low"
    description = "Repere les mots-cles dangereux d'un PDF (JavaScript, Launch, OpenAction)."
    examples = (
        "analyse suspect.pdf avec pdfid",
        "repere le javascript dans document.pdf",
    )
    parameters = (
        ParameterSpec("file", "Fichier PDF a analyser", "string", required=True),
        ParameterSpec("all", "Afficher tous les mots-cles (-a)", "bool", default=False),
        ParameterSpec("extra", "Mots-cles supplementaires (-e)", "string"),
        ParameterSpec("json", "Sortie JSON (-j)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["pdfid"]
        if params.get("all"):
            argv.append("-a")
        if params.get("extra"):
            argv += ["-e", str(params["extra"])]
        if params.get("json"):
            argv.append("-j")
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["file"] = path
        if "tous" in low or "all" in low:
            params["all"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for keyword, count in _KEYWORD_RE.findall(stdout):
            if count == "0":
                continue
            key = keyword.lower()
            if key in _DANGEROUS:
                label, severity = _DANGEROUS[key]
                findings.append(
                    Finding(title=f"{label}: {count}", severity=severity, evidence=f"/{keyword} {count}")
                )
        summary = f"{len(findings)} mot(s)-cle(s) a risque dans le PDF."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


class PdfParserTool(Tool):
    name = "pdf-parser"
    binary = "pdf-parser"
    risk = "low"
    description = "Explore la structure d'un PDF et en extrait des objets (streams, JavaScript)."
    examples = (
        "extrait les objets javascript de suspect.pdf",
        "cherche l'objet 12 dans document.pdf",
    )
    parameters = (
        ParameterSpec("file", "Fichier PDF", "string", required=True),
        ParameterSpec("search", "Chercher un mot-cle (-s), ex: JavaScript", "string"),
        ParameterSpec("object", "Numero d'objet a afficher (-o)", "string"),
        ParameterSpec("dump", "Extraire les streams (-d)", "bool", default=False),
        ParameterSpec("filter", "Appliquer les filtres de decodage (-f)", "bool", default=False),
        ParameterSpec("raw", "Sortie brute (-r)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["pdf-parser"]
        if params.get("search"):
            argv += ["-s", str(params["search"])]
        if params.get("object"):
            argv += ["-o", str(params["object"])]
        if params.get("dump"):
            argv.append("-d")
        if params.get("filter"):
            argv.append("-f")
        if params.get("raw"):
            argv.append("-r")
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["file"] = path
        if "javascript" in low or "js" in low:
            params["search"] = "JavaScript"
        obj = re.search(r"objet\s+(\d+)", low)
        if obj:
            params["object"] = obj.group(1)
        if "stream" in low or "extrait" in low or "dump" in low:
            params["dump"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        obj_matches = re.findall(r"obj\s+(\d+)\s+(\d+)", stdout)
        if obj_matches:
            findings.append(
                Finding(title=f"{len(obj_matches)} objet(s) trouve(s)", severity="info")
            )
        if re.search(r"javascript", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Code JavaScript present dans le PDF",
                    severity="high",
                    detail="Du JavaScript peut executer du code a l'ouverture du document.",
                )
            )
        if re.search(r"/(OpenAction|/AA|/Launch)", stdout):
            findings.append(
                Finding(title="Action automatique detectee (/OpenAction, /AA ou /Launch)", severity="high")
            )
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) structurel(s).",
            findings=findings,
            source="heuristic",
        )


register(PdfidTool())
register(PdfParserTool())
