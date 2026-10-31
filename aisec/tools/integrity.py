"""Outils d'integrite et de detection de rootkits: hashdeep, ssdeep, rkhunter, chkrootkit."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_any_path

# hashdeep: "hash,hash,size,path"
_HASHDEEP_RE = re.compile(r"^([0-9a-f]{16,}),([0-9a-f]{16,}),(\d+),(.+)$", re.IGNORECASE)
# ssdeep: "ssdeep,1.1--blocksize:hash:hash,filename"
_SSDEEP_RE = re.compile(r"^ssdeep[^\s,]*,[\w:+-]+,(.+)$")
# rkhunter: "[ Warning ]" / "[ Rootkit ]" / "[ Info ]"
_RKHUNTER_RE = re.compile(r"^\[\s*(Warning|Rootkit|Infected|Info)\s*\]\s*(.*)$", re.IGNORECASE)


class HashdeepTool(Tool):
    name = "hashdeep"
    binary = "hashdeep"
    risk = "low"
    description = "Hachage recursif de fichiers pour verifier l'integrite d'un volume (audit)."
    examples = (
        "calcule les empreintes de /mnt/image avec hashdeep",
        "audit d'integrite de /evidence avec hashdeep",
    )
    parameters = (
        ParameterSpec("target", "Fichier ou repertoire a hasher", "string", required=True),
        ParameterSpec("algorithms", "Algorithmes (-c), ex: md5,sha256", "string", default="md5,sha256"),
        ParameterSpec("recursive", "Recursif (-r)", "bool", default=True),
        ParameterSpec("audit", "Mode audit (-a)", "bool", default=False),
        ParameterSpec("known", "Fichier de hashes connus (-k)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hashdeep"]
        if params.get("recursive"):
            argv.append("-r")
        if params.get("audit"):
            argv.append("-a")
        argv += ["-c", str(params.get("algorithms") or "md5,sha256")]
        if params.get("known"):
            argv += ["-k", str(params["known"])]
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_any_path(text)
        if path:
            params["target"] = path
        if "audit" in text.lower():
            params["audit"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        count = 0
        for md5, sha256, size, path in _HASHDEEP_RE.findall(stdout):
            count += 1
            if count <= 10:
                findings.append(
                    Finding(title=path.strip()[:120], severity="info", detail=f"{size} octets", evidence=md5)
                )
        return AnalysisResult(
            summary=f"{count} fichier(s) hashe(s).",
            findings=findings,
            data={"files": count},
            source="heuristic",
        )


class SsdeepTool(Tool):
    name = "ssdeep"
    binary = "ssdeep"
    risk = "low"
    description = "Empreintes floues (fuzzy hashing) pour rapprocher des fichiers similaires."
    examples = (
        "calcule les empreintes floues de /samples avec ssdeep",
        "compare les similarites entre deux fichiers avec ssdeep",
    )
    parameters = (
        ParameterSpec("target", "Fichier ou repertoire", "string", required=True),
        ParameterSpec("recursive", "Recursif (-r)", "bool", default=False),
        ParameterSpec("compare", "Comparer deux fichiers", "bool", default=False),
        ParameterSpec("second", "Second fichier a comparer", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ssdeep"]
        if params.get("recursive"):
            argv.append("-r")
        argv.append(str(params["target"]))
        if params.get("compare") and params.get("second"):
            argv.append(str(params["second"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_any_path(text)
        if path:
            params["target"] = path
        if "recursif" in low or "recursive" in low:
            params["recursive"] = True
        if "compare" in low or "similair" in low:
            params["compare"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for path in _SSDEEP_RE.findall(stdout):
            findings.append(Finding(title=f"Empreinte floue: {path.strip()[:120]}", severity="info"))
        matches = re.findall(r"(\d+)\s*%", stdout)
        if matches:
            findings.append(
                Finding(
                    title=f"Similarite: {matches[0]}%",
                    severity="medium" if int(matches[0]) >= 50 else "info",
                    detail="Deux fichiers partagent une structure commune.",
                )
            )
        return AnalysisResult(
            summary=f"{len(findings)} empreinte(s)/comparaison(s) ssdeep.",
            findings=findings[:40],
            source="heuristic",
        )


class RkhunterTool(Tool):
    name = "rkhunter"
    binary = "rkhunter"
    risk = "medium"
    description = "Detecte rootkits, portes derobees et fichiers systeme modifies."
    examples = (
        "verifie la presence de rootkits avec rkhunter",
        "rkhunter check sur le systeme",
    )
    parameters = (
        ParameterSpec("check", "Effectuer les verifications (--check)", "bool", default=True),
        ParameterSpec("update", "Mettre a jour les bases (--update)", "bool", default=False),
        ParameterSpec("skip_keypress", "Ne pas attendre une touche (--skip-keypress)", "bool", default=True),
        ParameterSpec("report_warnings", "Rapport des avertissements (--report-warnings-only)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rkhunter"]
        if params.get("update"):
            argv.append("--update")
        if params.get("check", True):
            argv.append("--check")
        if params.get("skip_keypress", True):
            argv.append("--skip-keypress")
        if params.get("report_warnings"):
            argv.append("--report-warnings-only")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"check": True, "skip_keypress": True}
        if "mise a jour" in low or "update" in low:
            params["update"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for level, detail in _RKHUNTER_RE.findall(stdout):
            low = level.lower()
            severity = {"rootkit": "critical", "infected": "critical", "warning": "medium"}.get(low, "info")
            findings.append(Finding(title=detail.strip()[:140], severity=severity, evidence=level))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) rkhunter.",
            findings=findings[:40],
            source="heuristic",
        )


class ChkrootkitTool(Tool):
    name = "chkrootkit"
    binary = "chkrootkit"
    risk = "medium"
    description = "Recherche des rootkits connus et des intrusions locales sur le systeme."
    examples = (
        "detecte les rootkits avec chkrootkit",
        "chkrootkit -q pour une sortie concise",
    )
    parameters = (
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
        ParameterSpec("directory", "Analyser un repertoire monte (-r)", "string"),
        ParameterSpec("expert", "Mode expert (-x)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["chkrootkit"]
        if params.get("quiet"):
            argv.append("-q")
        if params.get("expert"):
            argv.append("-x")
        if params.get("directory"):
            argv += ["-r", str(params["directory"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "silencieux" in low or "-q" in low:
            params["quiet"] = True
        if "expert" in low:
            params["expert"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            low = line.lower()
            if "infected" in low:
                findings.append(Finding(title=line.strip()[:140], severity="critical"))
            elif "warning" in low or "suspicious" in low:
                findings.append(Finding(title=line.strip()[:140], severity="medium"))
        return AnalysisResult(
            summary=f"{len(findings)} alerte(s) chkrootkit.",
            findings=findings[:40],
            source="heuristic",
        )


register(HashdeepTool())
register(SsdeepTool())
register(RkhunterTool())
register(ChkrootkitTool())
