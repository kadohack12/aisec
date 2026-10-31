"""Tests du chemin LLM et du moteur, via un provider stub.

Le provider est une dependance externe (serveur Ollama/API): on le remplace
par un stub deterministe. Le reste du code (fusion, validation, moteur,
garde-fous) est le vrai code de production.
"""

from __future__ import annotations

from aisec.core import analyzer, intent
from aisec.core.config import Config
from aisec.core.engine import Engine
from aisec.core import registry
from aisec.providers.base import Provider


class StubProvider(Provider):
    """Provider deterministe: renvoie une reponse JSON predefinie."""

    name = "stub"

    def __init__(self, response: str) -> None:
        super().__init__(Config(provider="none"))
        self._response = response
        self.calls = 0

    def available(self) -> bool:
        return True

    def complete(self, prompt: str, system: str = "") -> str:
        self.calls += 1
        return self._response


def test_intent_merges_llm_params():
    tool = registry.get("nmap")
    stub = StubProvider('{"targets": ["api.example.com"], "ports": "443", "timing": "T4"}')
    params, source = intent.parse_intent(tool, "verifie api.example.com", stub)
    assert source == "merged"
    assert params["ports"] == "443"
    assert params["targets"] == ["api.example.com"]


def test_intent_falls_back_when_llm_invalid():
    tool = registry.get("nmap")
    stub = StubProvider("desole je ne sais pas")
    params, source = intent.parse_intent(tool, "analyse les ports 22 sur host.local", stub)
    assert source == "heuristic"
    assert params["ports"] == "22"


def test_intent_handles_markdown_fenced_json():
    tool = registry.get("nmap")
    stub = StubProvider('```json\n{"targets": ["h.local"], "ports": "top100"}\n```')
    params, _ = intent.parse_intent(tool, "top ports sur h.local", stub)
    assert params["ports"] == "top100"


def test_analyzer_enriches_with_llm():
    tool = registry.get("nmap")
    stub = StubProvider(
        '{"summary": "Un service critique expose.", '
        '"findings": [{"title": "RDP expose", "severity": "high", "detail": "3389"}]}'
    )
    output = "Nmap scan report for h.local (10.0.0.1)\n3389/tcp open ms-wbt-server\n"
    result = analyzer.analyze(tool, output, {}, stub)
    assert result.source == "llm"
    assert result.summary == "Un service critique expose."
    assert any(f.severity == "high" for f in result.findings)


def test_engine_dry_run_does_not_execute():
    engine = Engine(Config(provider="none", dry_run=True))
    plan, result, analysis = engine.run("nmap", "ports 22,80 sur 127.0.0.1")
    assert result is None
    assert analysis is None
    assert plan.argv[0] == "nmap"


def test_engine_blocks_abusive_cidr():
    engine = Engine(Config(provider="none"))
    try:
        engine.plan("nmap", "scanne 0.0.0.0/0")
        assert False, "aurait du lever une erreur"
    except Exception as exc:  # ExecutionError
        assert "plage trop large" in str(exc)


def test_describe_tool_exposes_schema():
    engine = Engine(Config(provider="none"))
    info = engine.describe_tool("nmap")
    assert info["binary"] == "nmap"
    names = [p["name"] for p in info["parameters"]]
    assert "targets" in names and "ports" in names
