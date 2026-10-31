"""Registre d'experts + routeur de domaine.

Chaque classe de la taxonomie Parrot devient un expert (une IA dediee + ses
outils). Le routeur choisit l'expert a partir de la demande; a terme, un
orchestrateur unique pourra router vers tous les experts.
"""

from __future__ import annotations

from .ai import AI_EXPERT
from .automotive import AUTOMOTIVE_EXPERT
from .base import Expert, _kw_match, route, run_expert
from .dns import DNS_EXPERT
from .exploitation import EXPLOITATION_EXPERT
from .forensics import FORENSICS_EXPERT
from .info import INFO_EXPERT
from .misc import MISC_EXPERT
from .passwords import PASSWORDS_EXPERT
from .post_exploit import POST_EXPLOIT_EXPERT
from .reporting import REPORTING_EXPERT
from .sniffing import SNIFFING_EXPERT
from .vulnerability import VULNERABILITY_EXPERT
from .webapp import WEBAPP_EXPERT
from .reverse import REVERSE_EXPERT
from .wireless import WIRELESS_EXPERT

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

    Heuristique par mots-cles (deterministe) : match sur mot entier (comme le
    routage interne), pondere par la longueur du mot-cle. Un mot-cle qui est
    aussi un nom d'outil de l'expert (invocation explicite, ex. "mimikatz")
    pese plus qu'un terme generique (ex. "mots de passe"). Un LLM de routage
    pourra etre branche plus tard pour affiner.
    """
    low = text.lower()
    scores: dict[str, int] = {}
    for expert in _EXPERTS.values():
        total = 0
        for kw in expert.keywords:
            if _kw_match(kw, low):
                total += len(kw) * (3 if kw in expert.tool_names else 1)
        scores[expert.name] = total
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        # Aucun mot-cle: on prend l'expert de reconnaissance (info) par defaut.
        return _EXPERTS.get("info") or next(iter(_EXPERTS.values()))
    return _EXPERTS[best]


register(DNS_EXPERT)
register(INFO_EXPERT)
register(VULNERABILITY_EXPERT)
register(WEBAPP_EXPERT)
register(PASSWORDS_EXPERT)
register(SNIFFING_EXPERT)
register(EXPLOITATION_EXPERT)
register(FORENSICS_EXPERT)
register(REVERSE_EXPERT)
register(POST_EXPLOIT_EXPERT)
register(REPORTING_EXPERT)
register(WIRELESS_EXPERT)
register(AI_EXPERT)
register(AUTOMOTIVE_EXPERT)
register(MISC_EXPERT)

__all__ = ["Expert", "register", "get", "all_experts", "select", "route", "run_expert"]
