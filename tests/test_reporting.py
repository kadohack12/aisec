"""Tests de l'expert Reporting Tools (classe `12-reporting`)."""

from __future__ import annotations

from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.models import CommandPlan
from aisec.core.registry import get
from aisec.experts import get as get_expert, select
from aisec.experts.base import route


def test_reporting_expert_registered():
    expert = get_expert("reporting")
    assert set(expert.tool_names) == {"dradis", "faraday", "eyewitness", "neo4j"}


def test_reporting_tools_are_registered():
    for name in ("dradis", "faraday", "eyewitness", "neo4j"):
        assert get(name).binary


def test_router_selects_reporting_for_report():
    expert = select("redige le rapport de l'audit")
    assert expert.name == "reporting"


def test_router_prefers_eyewitness_for_screenshots():
    tool_name, params, source = route(get_expert("reporting"), "prends des captures des services web depuis urls.txt", None)
    assert tool_name == "eyewitness"
    assert source == "heuristic"


def test_router_prefers_dradis_for_reporting_platform():
    tool_name, _, _ = route(get_expert("reporting"), "centralise les resultats dans dradis", None)
    assert tool_name == "dradis"


def test_router_prefers_neo4j_for_graph():
    tool_name, _, _ = route(get_expert("reporting"), "stocke les relations dans neo4j", None)
    assert tool_name == "neo4j"


def test_eyewitness_build_argv():
    argv = get("eyewitness").build_argv({"targets": "urls.txt", "output": "./shots", "web": True})
    assert argv == ["eyewitness", "-f", "urls.txt", "-d", "./shots", "--web"]


def test_faraday_build_argv_start():
    argv = get("faraday").build_argv({"mode": "start", "port": 5985})
    assert argv == ["faraday", "-p", "5985", "start"]


def test_reporting_tools_are_low_risk_allowed():
    for name in ("dradis", "faraday", "neo4j"):
        tool = get(name)
        plan = CommandPlan(tool=name, params={}, argv=tool.build_argv({"action": "start", "mode": "start"}))
        verdict = evaluate(plan, tool, ControlPolicy(max_auto_risk=Risk.LOW))
        assert verdict.decision is Decision.ALLOW, name


def test_reporting_expert_tools_all_available():
    expert = get_expert("reporting")
    assert set(expert.available_tools()) == set(expert.tool_names)
