"""Rapport d'audit: agregation des executions et export JSON / Markdown / HTML.

Un `Report` rassemble une suite de `RunRecord` (une commande pilotee par un
expert: outil, commande, risque, decision, sortie, constats) et sait s'exporter
en plusieurs formats. Aucune dependance externe: le HTML est autonome (CSS
inline) et le Markdown est du texte simple.

L'objectif: a la fin d'un audit, produire un livrable partageable a partir de
tout ce que la suite a execute.
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .core.models import AnalysisResult, CommandPlan, ExecResult, Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity.lower(), 9)


@dataclass
class RunRecord:
    """Trace d'une commande pilotee par un expert."""

    expert: str
    tool: str
    command: str
    params: dict[str, Any] = field(default_factory=dict)
    source: str = "heuristic"
    risk: str = ""
    reasons: list[str] = field(default_factory=list)
    # None tant que la commande n'a pas ete executee (dry-run).
    returncode: int | None = None
    duration_s: float = 0.0
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    timestamp: str = ""

    @property
    def executed(self) -> bool:
        return self.returncode is not None

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["executed"] = self.executed
        data["ok"] = self.ok
        return data

    def add_findings(self, analysis: AnalysisResult | None) -> None:
        if analysis is None:
            return
        if analysis.summary:
            self.summary = analysis.summary
        self.findings.extend(analysis.findings)


def record_from_run(
    expert_name: str,
    tool_name: str,
    plan: CommandPlan,
    result: ExecResult | None,
    analysis: AnalysisResult | None,
) -> RunRecord:
    """Construit un `RunRecord` a partir d'une execution d'expert."""
    record = RunRecord(
        expert=expert_name or "",
        tool=tool_name,
        command=plan.render(),
        params=dict(plan.params),
        source=plan.source,
        risk=plan.risk,
        reasons=list(plan.reasons),
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    if result is not None:
        record.returncode = result.returncode
        record.duration_s = result.duration_s
        record.timed_out = result.timed_out
        record.stdout = result.stdout
        record.stderr = result.stderr
    record.add_findings(analysis)
    return record


@dataclass
class Report:
    """Rapport d'audit: une suite d'executions + metadonnees."""

    title: str = "Rapport d'audit aisec"
    target: str = ""
    tool: str = "aisec"
    generated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    records: list[RunRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def add(self, record: RunRecord) -> RunRecord:
        self.records.append(record)
        return record

    def extend(self, records: Iterable[RunRecord]) -> None:
        self.records.extend(records)

    # ---- Agregation -------------------------------------------------------

    def all_findings(self) -> list[Finding]:
        findings = [f for r in self.records for f in r.findings]
        return sorted(findings, key=lambda f: _severity_rank(f.severity))

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.all_findings():
            key = finding.severity.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def executed_count(self) -> int:
        return sum(1 for r in self.records if r.executed)

    # ---- Exports ----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "target": self.target,
            "tool": self.tool,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
            "summary": {
                "records": len(self.records),
                "executed": self.executed_count(),
                "findings": len(self.all_findings()),
                "severity_counts": self.severity_counts(),
            },
            "records": [r.to_dict() for r in self.records],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        lines: list[str] = [f"# {self.title}", ""]
        if self.target:
            lines.append(f"**Cible :** {self.target}")
        lines.append(f"**Genere le :** {self.generated_at}")
        lines.append(f"**Executions :** {self.executed_count()}/{len(self.records)}")
        counts = self.severity_counts()
        if counts:
            summary = ", ".join(
                f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: _severity_rank(kv[0]))
            )
            lines.append(f"**Constats :** {summary}")
        lines.append("")

        if self.all_findings():
            lines.append("## Constats")
            lines.append("")
            lines.append("| Severite | Titre | Detail |")
            lines.append("|----------|-------|--------|")
            for finding in self.all_findings():
                detail = finding.detail.replace("|", "\\|")
                lines.append(f"| {finding.severity} | {finding.title} | {detail} |")
            lines.append("")

        lines.append("## Executions")
        for index, record in enumerate(self.records, 1):
            lines.append("")
            status = "execute" if record.executed else "dry-run"
            lines.append(f"### {index}. {record.tool} ({record.expert or 'outil direct'})")
            lines.append("")
            lines.append(f"- Commande : `{record.command}`")
            lines.append(f"- Risque : {record.risk or 'n/a'} ({status})")
            if record.reasons:
                lines.append(f"- Motifs : {'; '.join(record.reasons)}")
            if record.summary:
                lines.append(f"- Resume : {record.summary}")
            if record.findings:
                lines.append("- Constats :")
                for finding in sorted(record.findings, key=lambda f: _severity_rank(f.severity)):
                    lines.append(
                        f"  - [{finding.severity}] {finding.title}"
                        + (f" - {finding.detail}" if finding.detail else "")
                    )
        lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        esc = html.escape
        rows = []
        for finding in self.all_findings():
            rows.append(
                f"<tr><td><span class='sev sev-{esc(finding.severity.lower())}'>"
                f"{esc(finding.severity)}</span></td>"
                f"<td>{esc(finding.title)}</td><td>{esc(finding.detail)}</td></tr>"
            )
        findings_table = (
            "<table><thead><tr><th>Severite</th><th>Titre</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            if rows
            else "<p class='muted'>Aucun constat.</p>"
        )

        blocks = []
        for index, record in enumerate(self.records, 1):
            status = "execute" if record.executed else "dry-run"
            findings = "".join(
                f"<li><span class='sev sev-{esc(f.severity.lower())}'>{esc(f.severity)}</span> "
                f"{esc(f.title)}"
                + (f" <span class='muted'>{esc(f.detail)}</span>" if f.detail else "")
                + "</li>"
                for f in sorted(record.findings, key=lambda f: _severity_rank(f.severity))
            )
            reasons = "".join(f"<li>{esc(r)}</li>" for r in record.reasons)
            output = esc(record.stdout.strip())
            blocks.append(
                "<section class='run'>"
                f"<h3>{index}. {esc(record.tool)} "
                f"<span class='muted'>({esc(record.expert or 'outil direct')})</span></h3>"
                f"<pre class='cmd'>{esc(record.command)}</pre>"
                f"<p><strong>Risque :</strong> {esc(record.risk or 'n/a')} "
                f"<span class='muted'>({status})</span></p>"
                + (f"<ul class='reasons'>{reasons}</ul>" if reasons else "")
                + (f"<p><strong>Resume :</strong> {esc(record.summary)}</p>" if record.summary else "")
                + (f"<ul class='findings'>{findings}</ul>" if findings else "")
                + (f"<details><summary>Sortie brute</summary><pre>{output}</pre></details>" if output else "")
                + "</section>"
            )

        counts = self.severity_counts()
        chips = "".join(
            f"<span class='chip sev-{esc(k)}'>{esc(k)} : {v}</span>"
            for k, v in sorted(counts.items(), key=lambda kv: _severity_rank(kv[0]))
        )
        target = f"<p><strong>Cible :</strong> {esc(self.target)}</p>" if self.target else ""

        return _HTML_TEMPLATE.format(
            title=esc(self.title),
            generated_at=esc(self.generated_at),
            target=target,
            executed=self.executed_count(),
            total=len(self.records),
            chips=chips or "<span class='muted'>Aucun constat</span>",
            findings_table=findings_table,
            blocks="".join(blocks),
        )

    def save(self, path: str | Path, fmt: str | None = None) -> Path:
        """Ecrit le rapport sur disque. Le format est deduit de l'extension."""
        path = Path(path)
        fmt = (fmt or path.suffix.lstrip(".") or "html").lower()
        renderers = {
            "json": self.to_json,
            "md": self.to_markdown,
            "markdown": self.to_markdown,
            "html": self.to_html,
            "htm": self.to_html,
        }
        if fmt not in renderers:
            raise ValueError(f"format de rapport inconnu: {fmt!r} (json|md|html)")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(renderers[fmt](), encoding="utf-8")
        return path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0 auto; max-width: 60rem; padding: 2rem 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: .25rem; }}
  .muted {{ color: #777; font-size: .9em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ccc; padding: .4rem .6rem; text-align: left;
            vertical-align: top; }}
  th {{ background: #f0f0f0; color: #111; }}
  .sev {{ font-weight: 600; padding: .05rem .4rem; border-radius: .3rem;
          font-size: .85em; white-space: nowrap; }}
  .sev-critical, .sev-high {{ background: #b00020; color: #fff; }}
  .sev-medium {{ background: #ffb300; color: #111; }}
  .sev-low {{ background: #0288d1; color: #fff; }}
  .sev-info {{ background: #e0e0e0; color: #222; }}
  .chip {{ display: inline-block; margin: .15rem .3rem .15rem 0; padding: .15rem .5rem;
           border-radius: 1rem; font-size: .8em; }}
  .run {{ border: 1px solid #ddd; border-radius: .5rem; padding: .5rem 1rem;
          margin: 1rem 0; }}
  pre {{ background: #f5f5f5; color: #111; padding: .6rem; border-radius: .3rem;
         overflow-x: auto; }}
  pre.cmd {{ background: #1e1e1e; color: #7CFC00; }}
  ul {{ margin: .3rem 0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p><strong>Genere le :</strong> {generated_at}</p>
{target}
<p><strong>Executions :</strong> {executed}/{total}</p>
<p>{chips}</p>
<h2>Constats</h2>
{findings_table}
<h2>Executions</h2>
{blocks}
<footer><p class="muted">Rapport genere par aisec.</p></footer>
</body>
</html>
"""


__all__ = ["Report", "RunRecord", "record_from_run"]
