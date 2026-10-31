"""Rapport d'audit: agregation et export JSON / Markdown / HTML."""

from __future__ import annotations

import json
from pathlib import Path

from aisec.core.models import AnalysisResult, CommandPlan, ExecResult, Finding
from aisec.report import Report, record_from_run


def _record(expert="info", tool="nmap", argv=("nmap", "-p", "22", "10.0.0.1")):
    plan = CommandPlan(tool=tool, params={"ports": "22"}, argv=list(argv), source="heuristic", risk="medium")
    result = ExecResult(argv=list(argv), returncode=0, stdout="22/tcp open ssh\n", stderr="", duration_s=0.1)
    analysis = AnalysisResult(
        summary="Un service SSH expose.",
        findings=[Finding("Port 22 ouvert", "medium", "SSH expose")],
        source="heuristic",
    )
    return record_from_run(expert, tool, plan, result, analysis)


def test_record_from_run_captures_command_and_findings():
    record = _record()
    assert record.expert == "info"
    assert record.tool == "nmap"
    assert record.command == "nmap -p 22 10.0.0.1"
    assert record.executed is True
    assert record.ok is True
    assert record.summary == "Un service SSH expose."
    assert [f.title for f in record.findings] == ["Port 22 ouvert"]


def test_record_dry_run_is_not_executed():
    plan = CommandPlan(tool="nmap", params={}, argv=["nmap", "host"], risk="medium")
    record = record_from_run("info", "nmap", plan, None, None)
    assert record.executed is False
    assert record.returncode is None


def test_report_aggregates_and_sorts_findings():
    report = Report(title="Audit")
    report.add(_record())
    report.add(
        record_from_run(
            "vulnerability",
            "nikto",
            CommandPlan(tool="nikto", params={}, argv=["nikto", "-h", "x"]),
            ExecResult(argv=["nikto"], returncode=0, stdout="", stderr=""),
            AnalysisResult(summary="s", findings=[Finding("Critique", "critical", "RCE")], source="heuristic"),
        )
    )
    titles = [f.title for f in report.all_findings()]
    assert titles[0] == "Critique"  # critical avant medium
    assert report.severity_counts() == {"critical": 1, "medium": 1}
    assert report.executed_count() == 2


def test_report_to_json_is_valid_and_structured():
    report = Report(title="Audit", target="10.0.0.1")
    report.add(_record())
    data = json.loads(report.to_json())
    assert data["title"] == "Audit"
    assert data["target"] == "10.0.0.1"
    assert data["summary"]["records"] == 1
    assert data["records"][0]["tool"] == "nmap"


def test_report_to_markdown_contains_key_sections():
    report = Report(title="Audit")
    report.add(_record())
    md = report.to_markdown()
    assert "# Audit" in md
    assert "## Constats" in md
    assert "Port 22 ouvert" in md
    assert "nmap -p 22 10.0.0.1" in md


def test_report_to_html_escapes_output():
    report = Report(title="Audit")
    plan = CommandPlan(tool="nmap", params={}, argv=["nmap", "x"])
    result = ExecResult(argv=["nmap"], returncode=0, stdout="<script>alert(1)</script>", stderr="")
    report.add(record_from_run("info", "nmap", plan, result, None))
    html = report.to_html()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_report_save_detects_format_from_extension(tmp_path: Path):
    report = Report(title="Audit")
    report.add(_record())
    for ext in ("json", "md", "html"):
        path = report.save(tmp_path / f"r.{ext}")
        assert path.exists() and path.stat().st_size > 0
    assert json.loads((tmp_path / "r.json").read_text())["title"] == "Audit"


def test_report_save_rejects_unknown_format(tmp_path: Path):
    report = Report()
    try:
        report.save(tmp_path / "r.txt")
        assert False, "aurait du lever ValueError"
    except ValueError as exc:
        assert "format" in str(exc)


def test_empty_report_is_valid():
    report = Report()
    assert report.executed_count() == 0
    assert report.all_findings() == []
    assert "Aucun constat" in report.to_html() or "aucun constat" in report.to_html().lower()
    assert json.loads(report.to_json())["summary"]["records"] == 0
