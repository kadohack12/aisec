"""Outil yara: detection de motifs (malware) par regles sur fichiers et processus."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# yara: "nom_regle fichier" ou "nom_regle [tags] fichier".
_MATCH_RE = re.compile(r"^(\S+)(?:\s+\[([^\]]+)\])?\s+(\S.*)$")


class YaraTool(Tool):
    name = "yara"
    binary = "yara"
    risk = "low"
    description = "Detecte des motifs (malware) avec des regles YARA sur des fichiers."
    examples = (
        "scanne sample.bin avec les regles malware.yar",
        "cherche le motif avec yara rules.yar sur dossier/",
    )
    parameters = (
        ParameterSpec("rules", "Fichier ou repertoire de regles", "string", required=True),
        ParameterSpec("target", "Fichier, repertoire ou PID a scanner", "string", required=True),
        ParameterSpec("recursive", "Parcours recursif des repertoires (-r)", "bool", default=False),
        ParameterSpec("tags", "Filtrer par tags (-t)", "string"),
        ParameterSpec("negate", "Afficher les regles non matchees (-n)", "bool", default=False),
        ParameterSpec("count", "Afficher le nombre de correspondances (-c)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["yara"]
        if params.get("recursive"):
            argv.append("-r")
        if params.get("tags"):
            argv += ["-t", str(params["tags"])]
        if params.get("negate"):
            argv.append("-n")
        if params.get("count"):
            argv.append("-c")
        argv += [str(params["rules"]), str(params["target"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        rules = re.search(r"([\w./\-]+\.yar[a]?)", text, re.IGNORECASE)
        if rules:
            params["rules"] = rules.group(1)
        path = extract_path(text)
        if path and path != params.get("rules"):
            params["target"] = path
        if "recursif" in low or "recursive" in low:
            params["recursive"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            match = _MATCH_RE.match(line.strip())
            if not match:
                continue
            rule, tags, target = match.groups()
            findings.append(
                Finding(
                    title=f"Regle YARA matchee: {rule}",
                    severity="high",
                    detail=tags or "",
                    evidence=target.strip(),
                )
            )
        summary = (
            f"{len(findings)} correspondance(s) de regle YARA."
            if findings
            else "Aucune regle YARA n'a matche."
        )
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(YaraTool())
