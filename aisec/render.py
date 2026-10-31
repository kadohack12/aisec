"""Rendu console (sans dependance obligatoire).

Si `rich` est installe, on l'utilise pour un affichage agreable; sinon on
retombe sur du texte simple. L'API publique reste la meme.
"""

from __future__ import annotations

from .core.models import AnalysisResult, CommandPlan, ExecResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rich():
    try:
        import rich  # noqa: F401

        return True
    except ImportError:
        return False


def render_plan(plan: CommandPlan, console=None) -> None:
    line = f"$ {plan.render()}"
    if _rich():
        from rich.console import Console

        console = console or Console()
        console.print("[bold green]$[/]", plan.render())
        if plan.reasoning:
            console.print(f"[yellow]{plan.reasoning}[/]")
        if plan.source != "heuristic":
            console.print(f"[dim]params via {plan.source}[/]")
        return
    print(line)
    if plan.reasoning:
        print(plan.reasoning)


def render_result(result: ExecResult, console=None) -> None:
    if _rich():
        from rich.console import Console

        console = console or Console()
        status = "[red]echec[/]" if result.returncode != 0 else "[green]ok[/]"
        console.print(
            f"[dim]{result.duration_s}s, code={result.returncode} ({status})[/]"
        )
        if result.stderr.strip():
            console.print(f"[yellow]{result.stderr.strip()}[/]")
        return
    print(f"[{result.duration_s}s, code={result.returncode}]")
    if result.stderr.strip():
        print(result.stderr.strip())


def render_analysis(analysis: AnalysisResult, console=None) -> None:
    if _rich():
        from rich.console import Console
        from rich.table import Table

        console = console or Console()
        console.print(f"\n[bold]Resume[/] ({analysis.source}): {analysis.summary}")
        if analysis.findings:
            table = Table(title="Constats")
            table.add_column("Severite")
            table.add_column("Titre")
            table.add_column("Detail")
            for finding in sorted(
                analysis.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9)
            ):
                color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "dim",
                }.get(finding.severity, "white")
                table.add_row(f"[{color}]{finding.severity}[/]", finding.title, finding.detail)
            console.print(table)
        return

    print(f"\nResume ({analysis.source}): {analysis.summary}")
    for finding in sorted(analysis.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9)):
        print(f"  [{finding.severity}] {finding.title} - {finding.detail}")
