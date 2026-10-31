"""Outil wafw00f: detection du pare-feu applicatif (WAF) devant un site."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

_WAF_RE = re.compile(r"is behind (.+?)\s*(?:\(([^)]+)\))?\s*(?:WAF)?\.?\s*$", re.IGNORECASE)
_NOWAF_RE = re.compile(r"No WAF detected", re.IGNORECASE)


class Wafw00fTool(Tool):
    name = "wafw00f"
    binary = "wafw00f"
    risk = "low"
    description = "Identifie le WAF qui protege un site (Cloudflare, AWS, ModSecurity, ...)."
    examples = (
        "detecte le waf devant https://example.com",
        "quel waf protege example.com",
    )
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("all", "Tester tous les WAF (sans sortie anticipee) (-a)", "bool", default=False),
        ParameterSpec("findall", "Continuer apres le premier WAF (-f)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        url = str(params["url"])
        if "://" not in url:
            url = "https://" + url
        argv = ["wafw00f"]
        if params.get("all"):
            argv.append("-a")
        if params.get("findall"):
            argv.append("-f")
        if params.get("verbose"):
            argv.append("-v")
        argv.append(url)
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"(https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
        if match:
            params["url"] = match.group(1)
        if "tous" in low or "all" in low:
            params["all"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            match = _WAF_RE.search(line.strip())
            if match and "is behind" in line.lower():
                name = match.group(1).strip()
                findings.append(
                    Finding(
                        title=f"WAF detecte: {name}",
                        severity="info",
                        detail=match.group(2) or "",
                        evidence=line.strip(),
                    )
                )
            elif _NOWAF_RE.search(line):
                findings.append(
                    Finding(
                        title="Aucun WAF detecte",
                        severity="low",
                        detail="Le site ne semble pas protege par un WAF.",
                    )
                )
        if findings:
            summary = f"{len(findings)} resultat(s) de detection WAF."
        else:
            summary = f"Aucun WAF identifie (hote: {url_host(str(params.get('url', '')))})."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(Wafw00fTool())
