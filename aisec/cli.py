"""Interface en ligne de commande d'aisec.

Usages:
  - expert (recommande): aisec ask "resous les MX de example.com"
  - expert force        : aisec dns "..."      (IA dediee a la classe DNS)
  - outil direct        : aisec nmap "..."     (ou alias nmapAI)
  - catalogue           : aisec tools [--search X] [--installed]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, render
from .catalog import get_catalog
from .core import registry
from .core.config import Config
from .core.engine import Engine
from .core.executor import ConfirmationRequired, ExecutionError
from .experts import all_experts, get as get_expert, run_expert, select

_PROVIDERS = ["ollama", "openai", "groq", "none"]


def _add_common(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    # `suppress=True` sur les sous-parseurs: leurs defauts ne doivent pas ecraser
    # les options placees avant la sous-commande (ex: `aisec --dry-run dns ...`).
    default = argparse.SUPPRESS if suppress else False
    parser.add_argument("--provider", choices=_PROVIDERS, help="Backend LLM (defaut: ollama).")
    parser.add_argument("--model", help="Modele LLM a utiliser.")
    parser.add_argument("--dry-run", action="store_true", default=default, help="Afficher sans executer.")
    parser.add_argument("--json", action="store_true", default=default, help="Sortie d'analyse en JSON.")
    parser.add_argument(
        "--yes", action="store_true", default=default,
        help="Auto-approuver les actions (confirmation).",
    )
    parser.add_argument(
        "--auto-approve-risk",
        choices=["low", "medium", "high", "critical"],
        help="Risque maximal execute sans confirmation.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisec",
        description="Suite d'outils de securite pilotes en langage naturel (experts par classe).",
    )
    parser.add_argument("--version", action="version", version=f"aisec {__version__}")
    _add_common(parser)

    sub = parser.add_subparsers(dest="command")

    ask = sub.add_parser("ask", help="Demande libre: le routeur choisit l'expert.")
    ask.add_argument("prompt", nargs="+")
    _add_common(ask, suppress=True)

    experts_cmd = sub.add_parser("experts", help="Lister les experts (classes) disponibles.")
    experts_cmd.add_argument("--json", action="store_true")

    tools_cmd = sub.add_parser("tools", help="Explorer le catalogue d'outils (445 outils).")
    tools_cmd.add_argument("--search", help="Filtrer par mot-cle.")
    tools_cmd.add_argument("--installed", action="store_true", help="Seulement les outils installes.")
    tools_cmd.add_argument("--json", action="store_true")

    for expert in all_experts():
        ep = sub.add_parser(expert.name, help=f"Expert: {expert.description}")
        ep.add_argument("prompt", nargs="+")
        _add_common(ep, suppress=True)

    for name in registry.all_names():
        tool = registry.get(name)
        sp = sub.add_parser(name, help=tool.description)
        sp.add_argument("prompt", nargs="+")
        _add_common(sp, suppress=True)

    return parser


def _emit_json(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _cmd_experts(args) -> int:
    if args.json:
        _emit_json(
            [
                {
                    "name": e.name,
                    "description": e.description,
                    "tools": e.tool_names,
                    "available": e.available_tools(),
                    "model": e.model,
                }
                for e in all_experts()
            ]
        )
        return 0
    for e in all_experts():
        ready = ", ".join(e.available_tools()) or "aucun binaire installe"
        print(f"{e.name:10} {e.description}")
        print(f"           outils: {', '.join(e.tool_names)}")
        print(f"           dispo : {ready}")
    return 0


def _cmd_tools(args) -> int:
    catalog = get_catalog()
    entries = catalog.installed() if args.installed else (catalog.search(args.search) if args.search else catalog.tools)
    if args.json:
        _emit_json(
            [
                {
                    "name": t.name,
                    "category": t.category,
                    "installed": t.installed,
                    "binaries": t.binaries,
                    "description": t.description[:200],
                }
                for t in entries
            ]
        )
        return 0
    for t in entries:
        mark = "*" if t.installed else " "
        print(f"[{mark}] {t.name:18} {t.category:34} {t.description[:70]}")
    print(f"\n{len(entries)} outil(s). '*' = installe. Source: {catalog.source}")
    return 0


def _apply_control_overrides(config: Config, args) -> Config:
    if getattr(args, "auto_approve_risk", None):
        config.auto_approve_risk = args.auto_approve_risk
    if getattr(args, "yes", False):
        config.assume_yes = True
    if getattr(args, "dry_run", False):
        config.dry_run = True
    return config


def _confirm_interactive(exc) -> bool:
    """Demande confirmation a l'utilisateur (TTY uniquement)."""
    import sys

    if not sys.stdin.isatty():
        return False
    plan = getattr(exc, "plan", None)
    if plan is not None:
        print(f"$ {plan.render()}  [risk: {plan.risk}]")
        for reason in plan.reasons:
            print(f"  - {reason}")
    try:
        answer = input("Executer cette commande ? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes", "o", "oui"}


def _run_expert_cmd(expert_name: str, args, prompt: str) -> int:
    expert = get_expert(expert_name)
    config = Config.load().apply_overrides(provider=args.provider, model=args.model)
    config = _apply_control_overrides(config, args)
    model = config.model_for(expert.name, expert.model)
    if model:
        config = config.with_model(model)
    provider = Engine(config).provider

    assume_yes = None
    while True:
        try:
            plan, result, analysis, tool_name = run_expert(
                expert, prompt, provider, config, assume_yes=assume_yes
            )
            break
        except ConfirmationRequired as exc:
            if _confirm_interactive(exc):
                assume_yes = True
                continue
            print(f"Annule: {exc}", file=sys.stderr)
            return 3
        except (ExecutionError, KeyError) as exc:
            print(f"Erreur: {exc}", file=sys.stderr)
            return 1

    if args.json:
        _emit_json(_plan_payload(expert.name, tool_name, plan, result, analysis))
        return 0

    print(f"[expert: {expert.name} -> outil: {tool_name}]")
    render.render_plan(plan)
    if result is not None:
        render.render_result(result)
        if result.stdout.strip():
            print(result.stdout)
    if analysis is not None:
        render.render_analysis(analysis)
    return 0


def _plan_payload(expert_name, tool_name, plan, result, analysis) -> dict:
    payload = {
        "expert": expert_name,
        "tool": tool_name,
        "command": plan.render(),
        "params": plan.params,
        "source": plan.source,
    }
    if result is not None:
        payload["result"] = {
            "returncode": result.returncode,
            "duration_s": result.duration_s,
            "timed_out": result.timed_out,
        }
    if analysis is not None:
        payload["analysis"] = {
            "summary": analysis.summary,
            "source": analysis.source,
            "findings": [
                {"title": f.title, "severity": f.severity, "detail": f.detail}
                for f in analysis.findings
            ],
        }
    return payload


def run_cli(tool_name: str | None, argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "experts":
        return _cmd_experts(args)
    if args.command == "tools":
        return _cmd_tools(args)

    expert_names = {e.name for e in all_experts()}
    if tool_name is not None:
        command = tool_name
    elif args.command in expert_names:
        command = args.command
    else:
        command = args.command

    if not command:
        parser.print_help()
        return 2

    prompt = " ".join(args.prompt)

    if command == "ask":
        expert = select(prompt)
        return _run_expert_cmd(expert.name, args, prompt)
    if command in expert_names:
        return _run_expert_cmd(command, args, prompt)

    # Outil direct
    config = Config.load().apply_overrides(provider=args.provider, model=args.model)
    config = _apply_control_overrides(config, args)
    engine = Engine(config)
    assume_yes = None
    while True:
        try:
            plan, result, analysis = engine.run(
                command, prompt, dry_run=args.dry_run, assume_yes=assume_yes
            )
            break
        except ConfirmationRequired as exc:
            if _confirm_interactive(exc):
                assume_yes = True
                continue
            print(f"Annule: {exc}", file=sys.stderr)
            return 3
        except (ExecutionError, KeyError) as exc:
            print(f"Erreur: {exc}", file=sys.stderr)
            return 1
    if args.json:
        _emit_json(_plan_payload(None, command, plan, result, analysis))
        return 0
    render.render_plan(plan)
    if result is not None:
        render.render_result(result)
        if result.stdout.strip():
            print(result.stdout)
    if analysis is not None:
        render.render_analysis(analysis)
    return 0


def main() -> int:
    return run_cli(None, sys.argv[1:])


def main_nmap() -> int:
    return run_cli("nmap", ["nmap", *sys.argv[1:]])


def main_tshark() -> int:
    return run_cli("tshark", ["tshark", *sys.argv[1:]])


def main_dns() -> int:
    return run_cli("dns", ["dns", *sys.argv[1:]])


def main_webapp() -> int:
    return run_cli("webapp", ["webapp", *sys.argv[1:]])


def main_vuln() -> int:
    return run_cli("vuln", ["vuln", *sys.argv[1:]])


def main_passwords() -> int:
    return run_cli("passwords", ["passwords", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
