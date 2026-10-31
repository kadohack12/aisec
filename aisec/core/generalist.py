"""IA generaliste: l'etage au-dessus des experts.

Les 16 experts sont des IA *specialistes* (une par classe): chacune connait ses
outils et produit la commande adaptee a sa demande. L'IA *generaliste* est leur
chef d'orchestre. Elle recoit un objectif libre et :

  1. le **decompose** en etapes (chaque etape vise un expert) ;
  2. **questionne** le ou les experts pertinents (chacun repond par une commande
     et une analyse) ;
  3. **synthetise** le tout en une reponse coherente.

Chaque etape passe par l'`Orchestrator`: les garde-fous, la politique de risque
et le rapport d'audit restent identiques a une execution directe (rien de special
n'est contourne).

Deux modes, comme les experts:
  - `llm` (provider actif) : le modele choisit les experts et redige la synthese.
  - heuristique (defaut, sans LLM) : decomposition par connecteurs + routeur
    existant, synthese = concatenation des reponses. Deterministe et testable.

Sa place est reservee comme celle des experts : `Config.generalist_model` permet
de brancher une IA generaliste entrainee (cf. `docs/AI_TRAINING.md`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..report import RunRecord
from .config import Config
from .orchestrator import Orchestrator

# Prompts source unique: reutilises par l'inference ET par la generation du jeu
# d'entrainement (`scripts/build_dataset.py`), comme les routeurs d'expert.
GENERALIST_SYSTEM = (
    "Tu es l'IA generaliste d'une suite d'outils de securite. Tu recois un "
    "objectif et tu le decomposes en etapes, chacune confiee a l'expert (classe) "
    "le plus adapte. Reponds en JSON strict: "
    '{"steps": [{"expert": "<nom>", "request": "<sous-demande>"}]}.'
)

GENERALIST_SYNTHESIS_SYSTEM = (
    "Tu es l'IA generaliste d'une suite d'outils de securite. A partir de "
    "l'objectif et des reponses des experts, redige une synthese claire et "
    "actionnable: constats, commandes lancees, prochaines etapes. Reponds en "
    "texte, sans JSON."
)

def generalist_user_prompt(goal: str) -> str:
    """Prompt utilisateur de la decomposition (source unique inference/entrainement)."""
    from ..experts import router_catalog

    return (
        f"Experts disponibles:\n{router_catalog()}\n\n"
        f"Objectif: \"{goal}\"\n\nRenvoie le JSON des etapes."
    )


# Connecteurs qui separent deux sous-demandes dans un objectif compose.
_SPLIT_RE = re.compile(
    r"\s*(?:;|\bpuis\b|\bensuite\b|\bet ensuite\b|\bet apres\b|\bapres ca\b)\s*",
    re.IGNORECASE,
)


@dataclass
class Step:
    """Une etape de l'objectif confiee a un expert."""

    expert: str
    request: str
    rationale: str = ""


@dataclass
class Consultation:
    """La reponse d'un expert a une etape (sa trace + sa reponse lisible)."""

    step: Step
    record: RunRecord
    reply: str


@dataclass
class GeneralistAnswer:
    """La reponse finale de l'IA generaliste."""

    goal: str
    steps: list[Step] = field(default_factory=list)
    consultations: list[Consultation] = field(default_factory=list)
    synthesis: str = ""
    source: str = "heuristic"  # llm | heuristic

    def to_dict(self) -> dict:
        return {
            "goal": self.goal,
            "source": self.source,
            "steps": [
                {"expert": s.expert, "request": s.request, "rationale": s.rationale}
                for s in self.steps
            ],
            "consultations": [
                {
                    "expert": c.step.expert,
                    "request": c.step.request,
                    "command": c.record.command,
                    "risk": c.record.risk,
                    "executed": c.record.executed,
                    "reply": c.reply,
                }
                for c in self.consultations
            ],
            "synthesis": self.synthesis,
        }


@dataclass
class Generalist:
    """Decompose un objectif, questionne les experts, synthetise."""

    config: Config = field(default_factory=Config.load)
    provider: object | None = None
    orchestrator: Orchestrator | None = None

    def __post_init__(self) -> None:
        # L'IA generaliste a son propre modele (place reservee, comme les experts),
        # applique a ses appels de decomposition/synthese. Les experts gardent les
        # leurs via `expert_models`.
        model = self.config.generalist_model or self.config.model
        self._config = self.config.with_model(model) if model else self.config
        if self.orchestrator is None:
            self.orchestrator = Orchestrator(self._config)
        if self.provider is None:
            self.provider = self.orchestrator.provider

    # ---- Decomposition ----------------------------------------------------

    def plan(self, goal: str) -> list[Step]:
        """Decompose un objectif en etapes (LLM si dispo, sinon heuristique)."""
        steps = self._plan_llm(goal)
        return steps if steps else self._plan_heuristic(goal)

    def _plan_llm(self, goal: str) -> list[Step] | None:
        provider = self.provider
        if provider is None or not provider.available():
            return None

        from ..experts import get as get_expert
        from ..experts.base import _extract_json

        prompt = generalist_user_prompt(goal)
        try:
            data = _extract_json(provider.complete(prompt, system=GENERALIST_SYSTEM))
        except Exception:
            return None
        if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
            return None

        steps: list[Step] = []
        for item in data["steps"]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("expert", "")).strip().lower()
            try:
                get_expert(name)
            except KeyError:
                continue
            request = str(item.get("request", "")).strip() or goal
            steps.append(Step(expert=name, request=request, rationale=str(item.get("rationale", ""))))
        return steps or None

    def _plan_heuristic(self, goal: str) -> list[Step]:
        from ..experts import select

        steps: list[Step] = []
        for clause in _split_clauses(goal):
            expert = select(clause, provider=self.provider, routing=self.config.routing)
            steps.append(Step(expert=expert.name, request=clause))
        return steps

    # ---- Consultation des experts -----------------------------------------

    def consult(self, step: Step, *, assume_yes: bool | None = None) -> Consultation:
        """Questionne un expert (execute son plan via l'orchestrateur)."""
        record = self.orchestrator.run(
            step.request, expert_name=step.expert, assume_yes=assume_yes
        )
        return Consultation(step=step, record=record, reply=_reply_of(record))

    def answer(self, goal: str, *, assume_yes: bool | None = None) -> GeneralistAnswer:
        """Decompose, questionne les experts puis synthetise."""
        steps = self.plan(goal)
        consultations = [self.consult(step, assume_yes=assume_yes) for step in steps]
        synthesis, source = self.synthesize(goal, consultations)
        return GeneralistAnswer(
            goal=goal, steps=steps, consultations=consultations, synthesis=synthesis, source=source
        )

    # ---- Synthese ---------------------------------------------------------

    def synthesize(
        self, goal: str, consultations: list[Consultation]
    ) -> tuple[str, str]:
        """Redige la synthese (LLM si dispo) et renvoie (texte, source)."""
        text = self._synthesize_llm(goal, consultations)
        if text:
            return text, "llm"
        return _synthesize_heuristic(goal, consultations), "heuristic"

    def _synthesize_llm(self, goal: str, consultations: list[Consultation]) -> str | None:
        provider = self.provider
        if provider is None or not provider.available():
            return None
        lines = [f"Objectif: {goal}", "", "Reponses des experts:"]
        for c in consultations:
            lines.append(f"- {c.step.expert} (demande: {c.step.request}) -> {c.reply}")
        try:
            return provider.complete("\n".join(lines), system=GENERALIST_SYNTHESIS_SYSTEM).strip() or None
        except Exception:
            return None

    # ---- Rapport ----------------------------------------------------------

    @property
    def report(self):
        """Rapport d'audit agregeant toutes les consultations."""
        return self.orchestrator.report


def _split_clauses(goal: str) -> list[str]:
    """Decoupe un objectif compose en sous-demandes (connecteurs uniquement)."""
    parts = [part.strip() for part in _SPLIT_RE.split(goal) if part.strip()]
    return parts or [goal.strip()]


def _reply_of(record: RunRecord) -> str:
    """Rend lisible la reponse d'un expert (commande + resume + constats)."""
    parts: list[str] = []
    if record.command:
        parts.append(f"commande: {record.command}")
    if record.summary:
        parts.append(record.summary)
    for finding in record.findings:
        parts.append(f"[{finding.severity}] {finding.title}: {finding.detail}")
    return " | ".join(parts) or "(aucune reponse)"


def _synthesize_heuristic(goal: str, consultations: list[Consultation]) -> str:
    lines = [f"Objectif: {goal}", ""]
    for c in consultations:
        lines.append(f"[{c.step.expert}] {c.record.command or '(apercu)'}")
        if c.record.summary:
            lines.append(f"  {c.record.summary}")
    return "\n".join(lines)


__all__ = [
    "Consultation",
    "GENERALIST_SYSTEM",
    "GENERALIST_SYNTHESIS_SYSTEM",
    "Generalist",
    "GeneralistAnswer",
    "Step",
    "generalist_user_prompt",
]
