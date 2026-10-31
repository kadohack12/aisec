"""Analyse de la sortie d'un outil.

On combine l'analyse heuristique (toujours disponible, deterministe) avec un
enrichissement LLM optionnel (resume + constats) quand un provider est actif.
"""

from __future__ import annotations

import json
import re

from ..providers.base import Provider
from ..tools.base import Tool
from .models import AnalysisResult, Finding

SYSTEM_PROMPT = (
    "Tu es un analyste en cybersecurite. Tu resumes une sortie d'outil et tu "
    "releves les points importants. Reponds en JSON strict avec les cles "
    "'summary' (chaine) et 'findings' (liste d'objets {title, severity, detail}). "
    "severity vaut info|low|medium|high|critical."
)

_MAX_OUTPUT = 8000


def analyze(
    tool: Tool, stdout: str, params: dict, provider: Provider | None
) -> AnalysisResult:
    result = tool.analyze(stdout, params)
    if provider is None or not provider.available() or not stdout.strip():
        return result

    try:
        raw = provider.complete(_prompt(tool, stdout, params), system=SYSTEM_PROMPT)
        data = _extract_json(raw)
    except Exception:
        return result

    if not isinstance(data, dict):
        return result

    if data.get("summary"):
        result.summary = str(data["summary"])
    for item in data.get("findings", []) or []:
        if isinstance(item, dict) and item.get("title"):
            result.findings.append(
                Finding(
                    title=str(item["title"]),
                    severity=str(item.get("severity", "info")),
                    detail=str(item.get("detail", "")),
                )
            )
    result.source = "llm"
    return result


def _prompt(tool: Tool, stdout: str, params: dict) -> str:
    excerpt = stdout[:_MAX_OUTPUT]
    return (
        f"Outil: {tool.name}\n"
        f"Parametres: {json.dumps(params, ensure_ascii=False)}\n\n"
        f"Sortie brute:\n{excerpt}\n\n"
        "Analyse cette sortie."
    )


def _extract_json(raw: str):
    raw = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        raw = fence.group(1)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        brace = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace:
            try:
                return json.loads(brace.group(0))
            except json.JSONDecodeError:
                return None
    return None
