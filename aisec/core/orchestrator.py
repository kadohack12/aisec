"""Orchestrateur unique: une intention -> l'expert -> l'outil -> l'execution.

C'est le point d'entree haut niveau de la suite. Il enchaine:

  1. **Selection d'expert** : choisit la classe la plus adaptee a la demande
     (heuristique deterministe, ou LLM si `routing = "llm"`).
  2. **Routage interne** : l'expert choisit l'outil et extrait les parametres
     (heuristique, ou LLM si un provider est actif).
  3. **Controle** : politique de risque (niveau 2) + politique de classe
     (niveau 3) -> allow / confirm / deny.
  4. **Execution** : argv, jamais de shell.
  5. **Analyse** : constats heuristiques + enrichissement LLM.

Chaque etape produit un `RunRecord`, ce qui permet a l'orchestrateur de
construire un `Report` au fil de l'audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..report import Report, RunRecord, record_from_run
from .config import Config
from .engine import Engine
from .models import CommandPlan


@dataclass
class Orchestrator:
    """Pilote une demande de bout en bout et en garde la trace."""

    config: Config = field(default_factory=Config.load)
    provider: object | None = None
    report: Report = field(default_factory=Report)

    def __post_init__(self) -> None:
        if self.provider is None:
            self.provider = Engine(self.config).provider

    # ---- API principale ---------------------------------------------------

    def select_expert(self, text: str):
        from ..experts import select

        routing = getattr(self.config, "routing", "heuristic")
        return select(text, provider=self.provider, routing=routing)

    def run(
        self,
        text: str,
        *,
        expert_name: str | None = None,
        assume_yes: bool | None = None,
        dry_run: bool | None = None,
    ) -> RunRecord:
        """Execute une demande et renvoie sa trace.

        Si `expert_name` est fourni, l'expert est impose ; sinon il est choisi
        par le routeur. `dry_run` force (ou non) l'apercu sans execution.
        """
        from ..experts import get as get_expert
        from ..experts.base import run_expert

        expert = get_expert(expert_name) if expert_name else self.select_expert(text)
        config = self._config_for(expert, dry_run)

        plan, result, analysis, tool_name = run_expert(
            expert, text, self.provider, config, assume_yes=assume_yes
        )
        record = record_from_run(expert.name, tool_name, plan, result, analysis)
        self.report.add(record)
        return record

    def plan(self, text: str, *, expert_name: str | None = None) -> CommandPlan:
        """Route et construit la commande sans l'executer (apercu)."""
        from ..core.registry import get as get_tool
        from ..experts import get as get_expert
        from ..experts.base import route

        expert = get_expert(expert_name) if expert_name else self.select_expert(text)
        tool_name, params, source = route(expert, text, self.provider)
        return get_tool(tool_name).build_plan(params, source=source)

    def run_many(
        self,
        requests: list[tuple[str, str | None]],
        *,
        assume_yes: bool | None = None,
    ) -> list[RunRecord]:
        """Execute plusieurs demandes (expert impose ou route) et les agrege."""
        records: list[RunRecord] = []
        for text, expert_name in requests:
            records.append(self.run(text, expert_name=expert_name, assume_yes=assume_yes))
        return records

    # ---- Utilitaires ------------------------------------------------------

    def _config_for(self, expert, dry_run: bool | None = None) -> Config:
        """Config effective pour un expert (IA dediee + apercu eventuel)."""
        model = self.config.model_for(expert.name, expert.model)
        config = self.config.with_model(model) if model else self.config
        if dry_run is not None:
            config = config.with_dry_run(dry_run)
        return config


__all__ = ["Orchestrator"]
