"""Registre d'experts + routeur de domaine.

Chaque classe de la taxonomie Parrot devient un expert (une IA dediee + ses
outils). Le routeur choisit l'expert a partir de la demande; a terme, un
orchestrateur unique pourra router vers tous les experts.
"""

from __future__ import annotations

from .base import Expert, route, run_expert
from .dns import DNS_EXPERT

_EXPERTS: dict[str, Expert] = {}


def register(expert: Expert) -> Expert:
    _EXPERTS[expert.name] = expert
    return expert


def get(name: str) -> Expert:
    try:
        return _EXPERTS[name]
    except KeyError:
        raise KeyError(
            f"expert inconnu '{name}'. Disponibles: {', '.join(sorted(_EXPERTS))}"
        ) from None


def all_experts() -> list[Expert]:
    return list(_EXPERTS.values())


def select(text: str, provider=None) -> Expert:
    """Choisit l'expert le plus pertinent pour une demande libre.

    Heuristique par mots-cles (deterministe). Un LLM de routage pourra etre
    branche plus tard pour affiner.
    """
    low = text.lower()
    scores: dict[str, int] = {}
    for expert in _EXPERTS.values():
        scores[expert.name] = sum(1 for kw in expert.keywords if kw in low)
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        # Aucun mot-cle: on prend le premier expert (DNS) comme defaut.
        return next(iter(_EXPERTS.values()))
    return _EXPERTS[best]


register(DNS_EXPERT)

__all__ = ["Expert", "register", "get", "all_experts", "select", "route", "run_expert"]
