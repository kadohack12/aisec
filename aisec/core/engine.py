"""Orchestrateur: intention -> plan -> execution -> analyse."""

from __future__ import annotations

from typing import Any

from ..providers.base import get_provider
from ..tools.base import Tool
from . import analyzer, intent, registry
from .config import Config
from .control import ControlPolicy, Decision, Risk, evaluate as evaluate_control
from .executor import ConfirmationRequired, ExecutionError, run as run_argv
from .models import AnalysisResult, CommandPlan, ExecResult
from .safety import scan_guardrails, validate_argv


class Engine:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.load()
        self.provider = get_provider(self.config)

    # ---- Etapes publiques --------------------------------------------------

    def plan(self, tool_name: str, text: str) -> CommandPlan:
        tool = registry.get(tool_name)
        params, source = intent.parse_intent(tool, text, self.provider)
        argv = tool.build_argv(params)
        plan = tool.build_plan(params, source=source)

        report = validate_argv(argv, tool.binary)
        if not report.ok:
            raise ExecutionError("Commande refusee par les garde-fous: " + "; ".join(report.errors))

        targets = params.get("targets") or []
        if targets:
            guard = scan_guardrails(list(targets))
            if not guard.ok:
                raise ExecutionError("Cibles refusees: " + "; ".join(guard.errors))
            plan.reasoning = "; ".join(guard.warnings) if guard.warnings else plan.reasoning

        return plan

    def run(
        self,
        tool_name: str,
        text: str,
        dry_run: bool | None = None,
        assume_yes: bool | None = None,
    ) -> tuple[CommandPlan, ExecResult | None, AnalysisResult | None]:
        tool = registry.get(tool_name)
        plan = self.plan(tool_name, text)
        effective_dry = self.config.dry_run if dry_run is None else dry_run

        self._control(plan, tool, assume_yes, effective_dry)

        if effective_dry:
            return plan, None, None

        result = run_argv(
            plan.argv,
            allowed_binary=tool.binary,
            timeout=self.config.timeout,
        )
        analysis = analyzer.analyze(tool, result.stdout, plan.params, self.provider)
        return plan, result, analysis

    # ---- Controle de l'IA (niveau 2) ---------------------------------------

    def policy(self) -> ControlPolicy:
        return ControlPolicy(
            max_auto_risk=Risk.parse(self.config.auto_approve_risk),
            max_targets=self.config.max_targets,
            deny_private_targets=self.config.deny_private_targets,
        )

    def _control(
        self, plan: CommandPlan, tool, assume_yes: bool | None, dry_run: bool
    ) -> None:
        """Applique la politique de controle a une commande proposee."""
        verdict = evaluate_control(plan, tool, self.policy())
        plan.risk = verdict.risk.label
        plan.reasons = list(verdict.reasons)
        if verdict.decision is Decision.DENY:
            raise ExecutionError(
                "Commande refusee par la politique: " + "; ".join(verdict.reasons)
            )
        # En dry-run rien ne s'execute: pas besoin de confirmer.
        if dry_run:
            return
        if verdict.decision is Decision.CONFIRM:
            yes = self.config.assume_yes if assume_yes is None else assume_yes
            if not yes:
                raise ConfirmationRequired(
                    "Confirmation requise: " + "; ".join(verdict.reasons), verdict, plan
                )

    # ---- Utilitaires -------------------------------------------------------

    def tool(self, name: str) -> Tool:
        return registry.get(name)

    def describe_tool(self, name: str) -> dict[str, Any]:
        tool = registry.get(name)
        return {
            "name": tool.name,
            "aliases": list(tool.aliases),
            "binary": tool.binary,
            "description": tool.description,
            "parameters": tool.param_schema(),
        }
