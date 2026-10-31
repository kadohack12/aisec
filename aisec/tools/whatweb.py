"""Outil whatweb: empreinte des technologies web d'un site."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, url_host

# Technologies souvent synonymes de surface d'attaque.
_RISKY = {
    "wordpress": "medium",
    "joomla": "medium",
    "drupal": "medium",
    "php": "low",
    "tomcat": "medium",
    "jenkins": "high",
    "gitlab": "medium",
    "phpmyadmin": "medium",
}
_TAG_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]*)\[([^\]]*)\]")
_URL_LINE = re.compile(r"^(https?://\S+)\s+\[([^\]]*)\]\s*(.*)$")


class WhatwebTool(Tool):
    name = "whatweb"
    binary = "whatweb"
    risk = "low"
    description = "Empreinte web: serveur, CMS, frameworks, librairies JavaScript, en-tetes."
    examples = (
        "identifie les technologies de https://example.com",
        "empreinte agressive de example.com",
    )
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("aggression", "Niveau d'agressivite: 1 (furtif) a 4 (agressif)", "string"),
        ParameterSpec("user_agent", "User-Agent a utiliser", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
        ParameterSpec("no_errors", "Masquer les erreurs (--no-errors)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["whatweb"]
        if params.get("aggression"):
            argv += ["-a", str(params["aggression"])]
        if params.get("user_agent"):
            argv += ["--user-agent", str(params["user_agent"])]
        if params.get("verbose"):
            argv.append("-v")
        if params.get("no_errors"):
            argv.append("--no-errors")
        argv.append(str(params["url"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        match = re.search(r"(https?://[^\s]+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/[^\s]*)?)", text, re.IGNORECASE)
        if match:
            params["url"] = match.group(1)
        if "agressif" in low or "aggressive" in low:
            params["aggression"] = "4"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        detected: list[str] = []
        for line in stdout.splitlines():
            match = _URL_LINE.match(line.strip())
            if not match:
                continue
            tags = _TAG_RE.findall(match.group(3))
            for name, value in tags:
                detected.append(name)
                severity = _RISKY.get(name.lower(), "info")
                if severity != "info":
                    findings.append(
                        Finding(
                            title=f"Technologie a risque: {name}",
                            severity=severity,
                            detail=value,
                        )
                    )
            if match.group(2):
                findings.append(Finding(title=f"Code HTTP: {match.group(2)}", severity="info"))
        summary = f"{len(set(detected))} technologie(s) identifiee(s) sur {url_host(str(params.get('url', '')))}."
        return AnalysisResult(
            summary=summary,
            findings=findings,
            data={"technologies": sorted(set(detected))},
            source="heuristic",
        )


register(WhatwebTool())
