"""Tests de la classe AI Tools (expert `ai`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

AI_TOOLS = {"hexstrike-ai", "mcpwn", "opencode", "pi-dev", "unsloth"}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("ai")
    assert AI_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in AI_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("lance le serveur mcpwn sur le port 1337", "mcpwn", ["mcpwn", "--server", "--port", "1337"]),
        (
            "lance le serveur hexstrike-ai sur 0.0.0.0:8888",
            "hexstrike-ai",
            ["hexstrike-ai", "--server", "--host", "0.0.0.0", "--port", "8888"],
        ),
        ("entraine un modele unsloth sur dataset.jsonl", "unsloth", ["unsloth", "train", "--dataset", "dataset.jsonl"]),
        ("lance opencode en mode non interactif", "opencode", ["opencode", "-p"]),
    ],
)
def test_route_and_argv(text, tool, expected):
    name, params, _source = route(get_expert("ai"), text, provider=None)
    assert name == tool
    assert registry.get(name).build_argv(params) == expected


def test_mcpwn_high_risk_requires_confirmation():
    verdict = evaluate(_plan(["mcpwn", "--server"]), registry.get("mcpwn"), ControlPolicy())
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_mcpwn_exposed_on_all_interfaces_is_flagged():
    analysis = registry.get("mcpwn").analyze("listening on 0.0.0.0:1337\n", {"host": "0.0.0.0"})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_hexstrike_flags_public_binding():
    analysis = registry.get("hexstrike-ai").analyze("started\n", {"host": "0.0.0.0"})
    assert any(f.severity == "high" for f in analysis.findings)


def test_opencode_flags_destructive_command():
    analysis = registry.get("opencode").analyze("running: rm -rf /\n", {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_pi_dev_flags_auto_approve():
    analysis = registry.get("pi-dev").analyze("ok\n", {"yes": True})
    assert any(f.severity == "medium" for f in analysis.findings)


def test_router_selects_ai_for_mcpwn():
    assert select("lance le serveur mcpwn").name == "ai"


def test_engine_plans_mcpwn_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("mcpwn", "lance le serveur mcpwn sur le port 1337", dry_run=True)
    assert plan.argv == ["mcpwn", "--server", "--port", "1337"]
    assert result is None and analysis is None
