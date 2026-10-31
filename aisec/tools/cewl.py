"""Outil cewl: generation de dictionnaires a partir d'un site web."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


class CewlTool(Tool):
    name = "cewl"
    binary = "cewl"
    risk = "medium"
    description = "Genere un dictionnaire de mots a partir du contenu d'un site (profiling)."
    examples = (
        "genere un dictionnaire a partir de https://example.com",
        "collecte les mots de example.com sur 3 niveaux et ecris-les dans mots.txt",
    )
    parameters = (
        ParameterSpec("url", "URL a parcourir", "string", required=True),
        ParameterSpec("depth", "Profondeur de crawl (-d)", "int", default=2),
        ParameterSpec("min_length", "Longueur minimale des mots (-m)", "int", default=3),
        ParameterSpec("output", "Fichier de sortie (-w)", "string"),
        ParameterSpec("emails", "Collecter aussi les emails (-e)", "bool", default=False),
        ParameterSpec("count", "Afficher le nombre d'occurrences (-c)", "bool", default=False),
        ParameterSpec("with_numbers", "Inclure les mots avec chiffres (--with-numbers)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["cewl", str(params["url"])]
        if params.get("depth"):
            argv += ["-d", str(params["depth"])]
        argv += ["-m", str(params.get("min_length") or 3)]
        if params.get("output"):
            argv += ["-w", str(params["output"])]
        if params.get("emails"):
            argv.append("-e")
        if params.get("count"):
            argv.append("-c")
        if params.get("with_numbers"):
            argv.append("--with-numbers")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"(https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
        if match:
            params["url"] = match.group(1)
        depth = re.search(r"(\d+)\s*(?:niveaux|profondeur|depth)", low)
        if depth:
            params["depth"] = int(depth.group(1))
        output = re.search(r"dans\s+([\w./\-]+\.txt)", text, re.IGNORECASE)
        if output:
            params["output"] = output.group(1)
        if "email" in low or "mail" in low:
            params["emails"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        words = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        emails = sorted(set(_EMAIL_RE.findall(stdout)))
        for email in emails[:20]:
            findings.append(Finding(title=f"Email: {email}", severity="info"))
        summary = f"{len(words)} mot(s) collecte(s) pour le dictionnaire."
        if emails:
            summary += f" {len(emails)} email(s) trouve(s)."
        return AnalysisResult(
            summary=summary,
            findings=findings,
            data={"words": len(words), "emails": emails, "host": url_host(str(params.get('url', '')))},
            source="heuristic",
        )


register(CewlTool())
