"""Interface en ligne de commande d'aisec.

Deux usages:
  - generique :  aisec nmap "scanne les ports 22,80,8080 sur target.com"
  - dedie     :  nmapAI "..."      (equivalent a `aisec nmap "..."`)
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, render
from .core import registry
from .core.config import Config
from .core.engine import Engine
from .core.executor import ExecutionError

_PROVIDERS = ["ollama", "openai", "groq", "none"]


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider", choices=_PROVIDERS, help="Backend LLM (defaut: ollama).")
    parser.add_argument("--model", help="Modele LLM a utiliser.")
    parser.add_argument("--dry-run", action="store_true", help="Afficher sans executer.")
    parser.add_argument("--json", action="store_true", help="Sortie d'analyse en JSON.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisec",
        description="Suite d'outils de securite pilotes en langage naturel.",
    )
    parser.add_argument("--version", action="version", version=f"aisec {__version__}")
    _add_common(parser)

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("tools", help="Lister les outils disponibles.")

    for name in registry.all_names():
        tool = registry.get(name)
        sp = sub.add_parser(name, help=tool.description)
        sp.add_argument("prompt", nargs="+", help="Demande en langage naturel.")
        _add_common(sp)

    return parser


def _emit_json(plan, result, analysis) -> None:
    payload = {
        "tool": plan.tool,
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
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def run_cli(tool_name: str | None, argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "tools" and tool_name is None:
        for tool in registry.all_tools():
            print(f"{tool.name:10} {tool.binary:12} {tool.description}")
        return 0

    if tool_name is None:
        tool_name = args.command
    if not tool_name:
        parser.print_help()
        return 2

    prompt = " ".join(args.prompt)
    config = Config.load().apply_overrides(provider=args.provider, model=args.model)
    engine = Engine(config)

    try:
        plan, result, analysis = engine.run(tool_name, prompt, dry_run=args.dry_run)
    except (ExecutionError, KeyError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _emit_json(plan, result, analysis)
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


if __name__ == "__main__":
    raise SystemExit(main())
