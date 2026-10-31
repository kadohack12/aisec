"""Tests de la classe Automotive (expert `automotive`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

AUTOMOTIVE_TOOLS = {"candump", "cansend", "cangen", "canconfig", "canconvert", "isotpdump"}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("automotive")
    assert AUTOMOTIVE_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in AUTOMOTIVE_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("capture les trames can sur can0", "candump", ["candump", "can0"]),
        ("envoie la trame 123#DEADBEEF sur can0", "cansend", ["cansend", "can0", "123#DEADBEEF"]),
        ("genere du trafic can sur can0 pendant 100 trames", "cangen", ["cangen", "can0", "-n", "100"]),
        (
            "configure can0 a 500000 bits et active l'interface",
            "canconfig",
            ["canconfig", "can0", "bitrate", "500000", "up"],
        ),
        ("decode les trames isotp sur can0", "isotpdump", ["isotpdump", "can0"]),
    ],
)
def test_route_and_argv(text, tool, expected):
    name, params, _source = route(get_expert("automotive"), text, provider=None)
    assert name == tool
    assert registry.get(name).build_argv(params) == expected


def test_candump_is_low_and_allowed():
    verdict = evaluate(_plan(["candump", "can0"]), registry.get("candump"), ControlPolicy())
    assert verdict.risk is Risk.LOW
    assert verdict.decision is Decision.ALLOW


def test_cansend_is_medium():
    verdict = evaluate(_plan(["cansend", "can0", "123#DEADBEEF"]), registry.get("cansend"), ControlPolicy())
    assert verdict.risk is Risk.MEDIUM
    assert verdict.decision is Decision.CONFIRM


def test_router_selects_automotive_for_can():
    assert select("capture les trames can sur can0").name == "automotive"


def test_engine_plans_candump_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("candump", "capture les trames can sur can0", dry_run=True)
    assert plan.argv == ["candump", "can0"]
    assert result is None and analysis is None


def test_candump_flags_bus_flood():
    frames = "\n".join(f"(1600000000.000000) can0 {i:03X}#11223344" for i in range(300))
    analysis = registry.get("candump").analyze(frames, {})
    assert any("Volume" in f.title for f in analysis.findings)


def test_isotpdump_flags_negative_response():
    analysis = registry.get("isotpdump").analyze("can0 7F 10 12\n", {})
    assert any("diagnostic" in f.title.lower() for f in analysis.findings)
