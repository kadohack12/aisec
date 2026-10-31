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


def select(text: str, provider=None, routing: str | None = None) -> Expert:
    """Choisit l'expert le plus pertinent pour une demande libre.

    Deux modes :
      - `heuristic` (defaut, deterministe) : match sur mot entier (comme le
        routage interne), pondere par la longueur du mot-cle. Un mot-cle qui est
        aussi un nom d'outil de l'expert (invocation explicite, ex. "mimikatz")
        pese plus qu'un terme generique (ex. "mots de passe").
      - `llm` : le LLM choisit la classe parmi les experts disponibles ; en cas
        d'echec (provider absent, reponse invalide), repli sur l'heuristique.

    `routing` vaut "heuristic" ou "llm" (defaut: heuristique). Un provider actif
    est requis pour le mode `llm`.
    """
    if routing == "llm" and provider is not None:
        expert = _select_llm(text, provider)
        if expert is not None:
            return expert
    return _select_heuristic(text)


def _select_heuristic(text: str) -> Expert:
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


def _select_llm(text: str, provider) -> Expert | None:
    """Routage LLM: le modele choisit la classe la plus adaptee.

    Renvoie None si le provider est indisponible ou si la reponse ne designe pas
    un expert connu (l'appelant retombe alors sur l'heuristique).
    """
    if not provider.available():
        return None
    catalog = "\n".join(f"- {e.name}: {e.description}" for e in _EXPERTS.values())
    system = (
        "Tu es un routeur. Choisis la classe d'outils de securite la plus adaptee "
        "a la demande de l'utilisateur. Reponds en JSON strict: {\"expert\": \"<nom>\"}."
    )
    prompt = f"Classes disponibles:\n{catalog}\n\nDemande: \"{text}\""
    try:
        from .base import _extract_json

        data = _extract_json(provider.complete(prompt, system=system))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    name = data.get("expert") or data.get("class") or data.get("classe")
    if isinstance(name, str):
        name = name.strip().lower()
        if name in _EXPERTS:
            return _EXPERTS[name]
    return None


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
