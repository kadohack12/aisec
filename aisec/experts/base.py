"""Experts: un domaine de specialite = une IA dediee + ses outils.

Chaque expert regroupe:
  - un domaine et un prompt systeme specialise (son metier)
  - un sous-ensemble d'outils de sa classe (mappe depuis la taxonomie Parrot)
  - un modele LLM optionnel dedie (pour brancher une IA entrainee par classe)
  - des mots-cles pour le routage

L'objectif: livrer un expert = une IA qui maitrise deja les patterns de ses outils.
A terme, un orchestrateur unique peut router vers tous les experts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..catalog import CatalogTool, get_catalog
from ..core.models import AnalysisResult, CommandPlan, ExecResult
from ..core.registry import get as get_tool
from ..providers.base import Provider


@dataclass
class Expert:
    name: str
    description: str
    system_prompt: str
    tool_names: list[str] = field(default_factory=list)
    keywords: tuple[str, ...] = ()
    model: str | None = None  # IA dediee (ex: modele entraine pour cette classe)
    # Regles de routage ordonnees: (outil, mots-cles). Premier match gagne.
    routing_rules: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def available_tools(self) -> list[str]:
        return [n for n in self.tool_names if _known(n)]

    def prompt(self, text: str) -> str:
        lines = [self.system_prompt, "", "Outils de ton domaine:"]
        for name in self.tool_names:
            tool = get_tool(name)
            flags = ", ".join(p.name for p in tool.parameters)
            lines.append(f"- {name}: {tool.description} | parametres: {flags}")
        lines += ["", f"Demande de l'utilisateur: \"{text}\""]
        return "\n".join(lines)

    def analyze(
        self, tool_name: str, stdout: str, params: dict, provider: Provider | None
    ) -> AnalysisResult:
        from ..core.analyzer import analyze as run_analysis

        return run_analysis(get_tool(tool_name), stdout, params, provider)

    def catalog_tools(self) -> list[CatalogTool]:
        """Outils du catalogue Parrot rattaches a cette classe (contexte)."""
        catalog = get_catalog()
        found: list[CatalogTool] = []
        for name in self.tool_names:
            entry = catalog.by_name(name)
            if entry:
                found.append(entry)
        return found


def _known(name: str) -> bool:
    try:
        get_tool(name)
        return True
    except KeyError:
        return False


def _extract_json(raw: str) -> dict | None:
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


def route(expert: Expert, text: str, provider: Provider | None) -> tuple[str, dict[str, Any], str]:
    """Choisit l'outil et les parametres au sein d'un expert.

    Renvoie (tool_name, params, source). Repli heuristique si pas de LLM.
    """
    fallback_tool, fallback_params = _heuristic_route(expert, text)
    if provider is None or not provider.available() or not expert.tool_names:
        return fallback_tool, fallback_params, "heuristic"

    system = (
        f"Tu es l'expert '{expert.name}' ({expert.description}). "
        "Tu choisis l'outil le plus adapte et tu extrais ses parametres. "
        'Reponds en JSON strict: {"tool": "<nom>", "params": {...}}.'
    )
    try:
        raw = provider.complete(expert.prompt(text), system=system)
        data = _extract_json(raw)
    except Exception:
        return fallback_tool, fallback_params, "heuristic"

    if not isinstance(data, dict) or data.get("tool") not in expert.tool_names:
        return fallback_tool, fallback_params, "heuristic"

    tool_name = data["tool"]
    params = data.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    tool = get_tool(tool_name)
    merged = tool.coerce({**tool.parse_intent(text), **params})
    return tool_name, merged, "llm"


def _heuristic_route(expert: Expert, text: str) -> tuple[str, dict[str, Any]]:
    """Choisit l'outil par mots-cles puis extrait les parametres (sans LLM)."""
    low = text.lower()

    # 1. Nom d'outil cite explicitement.
    for name in expert.tool_names:
        tool = get_tool(name)
        if name in low or any(alias in low for alias in tool.aliases):
            return name, tool.coerce(tool.parse_intent(text))

    # 2. Regles de routage ordonnees de l'expert (premier match gagne).
    for tool_name, keywords in expert.routing_rules:
        if tool_name not in expert.tool_names:
            continue
        if any(_kw_match(kw, low) for kw in keywords):
            return tool_name, get_tool(tool_name).coerce(get_tool(tool_name).parse_intent(text))

    # 3. Repli: score par recouvrement de description.
    scores: dict[str, int] = {}
    for name in expert.tool_names:
        tool = get_tool(name)
        scores[name] = sum(
            1 for kw in tool.description.lower().split() if len(kw) > 4 and kw in low
        )
    best = max(scores, key=scores.get) if scores else expert.tool_names[0]
    return best, get_tool(best).coerce(get_tool(best).parse_intent(text))


def _kw_match(keyword: str, low: str) -> bool:
    """Match sur mot entier si possible, sinon sous-chaine.

    Tolere le pluriel simple pour les mots-cles en minuscules
    (repertoire/repertoires, utilisateur/utilisateurs).
    """
    if re.fullmatch(r"[a-z0-9 ]+", keyword):
        return re.search(rf"\b{re.escape(keyword)}(?:s|es)?\b", low) is not None
    return keyword in low


def run_expert(
    expert: Expert, text: str, provider: Provider | None, config, assume_yes: bool | None = None
) -> tuple[CommandPlan, ExecResult | None, AnalysisResult | None, str]:
    """Route, construit, valide, controle, execute et analyse.

    Renvoie (plan, result, analysis, tool_name).
    """
    from ..core.control import Decision, Risk, evaluate as evaluate_control
    from ..core.executor import ConfirmationRequired, ExecutionError, run as run_argv
    from ..core.safety import validate_argv

    tool_name, params, source = route(expert, text, provider)
    tool = get_tool(tool_name)
    argv = tool.build_argv(params)
    plan = tool.build_plan(params, source=source)

    report = validate_argv(argv, tool.binary)
    if not report.ok:
        raise ExecutionError(
            "Commande refusee par les garde-fous: " + "; ".join(report.errors)
        )

    # Controle de l'IA (niveau 2): politique de risque + confirmation.
    from ..core.control import ControlPolicy

    policy = ControlPolicy(
        max_auto_risk=Risk.parse(config.auto_approve_risk),
        max_targets=config.max_targets,
        deny_private_targets=config.deny_private_targets,
    )
    verdict = evaluate_control(plan, tool, policy)
    plan.risk = verdict.risk.label
    plan.reasons = list(verdict.reasons)
    if verdict.decision is Decision.DENY:
        raise ExecutionError(
            "Commande refusee par la politique: " + "; ".join(verdict.reasons)
        )
    # En dry-run rien ne s'execute: pas besoin de confirmer.
    if config.dry_run:
        return plan, None, None, tool_name
    if verdict.decision is Decision.CONFIRM:
        yes = config.assume_yes if assume_yes is None else assume_yes
        if not yes:
            raise ConfirmationRequired(
                "Confirmation requise: " + "; ".join(verdict.reasons), verdict, plan
            )

    result = run_argv(argv, allowed_binary=tool.binary, timeout=config.timeout)
    analysis = expert.analyze(tool_name, result.stdout, plan.params, provider)
    return plan, result, analysis, tool_name
