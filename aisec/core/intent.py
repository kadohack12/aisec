"""Traduction langage naturel -> parametres d'outil.

Strategie:
  1. On demande au LLM (local par defaut) de renvoyer un JSON de parametres.
  2. On fusionne avec le resultat heuristique de l'outil (repli robuste).
  3. On valide les parametres contre le schema de l'outil.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..providers.base import Provider
from ..tools.base import Tool

SYSTEM_PROMPT = (
    "Tu es un moteur de traduction pour une suite d'outils de securite. "
    "A partir d'une demande en langage naturel, tu extrais les parametres de l'outil. "
    "Tu reponds UNIQUEMENT par un objet JSON valide, sans texte autour, sans balises."
)


def _prompt(tool: Tool, text: str) -> str:
    schema = json.dumps(tool.param_schema(), ensure_ascii=False, indent=2)
    examples = "\n".join(f"- {ex}" for ex in tool.examples)
    return (
        f"Outil: {tool.name} ({tool.description})\n"
        f"Parametres disponibles (JSON):\n{schema}\n\n"
        f"Exemples d'intentions:\n{examples}\n\n"
        f"Intention de l'utilisateur:\n\"{text}\"\n\n"
        "Renvoie le JSON des parametres a utiliser."
    )


def parse_intent(tool: Tool, text: str, provider: Provider | None) -> tuple[dict[str, Any], str]:
    """Renvoie (params, source)."""
    heuristic = tool.parse_intent(text)
    if provider is None or not provider.available():
        return tool.coerce(heuristic), "heuristic"

    try:
        raw = provider.complete(_prompt(tool, text), system=SYSTEM_PROMPT)
        llm_params = _extract_json(raw)
    except Exception:
        return tool.coerce(heuristic), "heuristic"

    if not isinstance(llm_params, dict):
        return tool.coerce(heuristic), "heuristic"

    merged = {**heuristic, **llm_params}
    return tool.coerce(merged), "merged" if heuristic else "llm"


def _extract_json(raw: str) -> Any:
    raw = raw.strip()
    # Retire d'eventuelles cloture markdown ```json ... ```
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
