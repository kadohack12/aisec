"""Tests de l'expert Vulnerability Analysis (classe `02-vulnerability-analysis`).

Verifie l'enregistrement des outils, le routage heuristique et la construction
d'argv, ainsi que la montee de risque via la politique de controle (niveau 2).
"""

from __future__ import annotations

from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.models import CommandPlan
from aisec.core.registry import get
from aisec.experts import get as get_expert, select
from aisec.experts.base import route


def test_vuln_expert_registered():
    expert = get_expert("vuln")
    assert "testssl" in expert.tool_names
    assert "bandit" in expert.tool_names
    assert "slowhttptest" in expert.tool_names


def test_vuln_tools_are_registered():
    for name in ("testssl", "bandit", "unix-privesc-check", "sfuzz", "siege", "yersinia", "t50"):
        assert get(name).binary


def test_router_selects_vuln_for_tls_audit():
    expert = select("audite le tls de example.com")
    assert expert.name == "vuln"


def test_router_prefers_testssl_for_tls():
    tool_name, params, source = route(get_expert("vuln"), "verifie les ciphers et certificats de example.com:443", None)
    assert tool_name == "testssl"
    assert params["target"] == "example.com:443"
    assert source == "heuristic"


def test_router_prefers_bandit_for_python_sast():
    tool_name, params, _ = route(get_expert("vuln"), "analyse statique du code python dans ./src", None)
    assert tool_name == "bandit"
    assert params["targets"] == ["./src"]


def test_router_prefers_slowhttptest_for_slowloris():
    tool_name, _, _ = route(get_expert("vuln"), "teste la resistance slowloris de http://example.com", None)
    assert tool_name == "slowhttptest"


def test_router_prefers_cisco_torch_for_cisco():
    tool_name, _, _ = route(get_expert("vuln"), "audite l'equipement cisco 192.168.1.1", None)
    assert tool_name == "cisco-torch"


def test_testssl_build_argv_full():
    argv = get("testssl").build_argv({"target": "example.com:443", "full": True})
    assert argv == ["testssl.sh", "-U", "-p", "-s", "-S", "example.com:443"]


def test_bandit_build_argv_recursive():
    argv = get("bandit").build_argv({"targets": ["./src"], "recursive": True})
    assert argv == ["bandit", "-r", "./src"]


def test_slowhttptest_build_argv_mode():
    argv = get("slowhttptest").build_argv({"url": "http://example.com", "mode": "slowloris"})
    assert argv == ["slowhttptest", "-H", "-u", "http://example.com"]


def test_vuln_high_risk_tool_requires_confirmation():
    tool = get("t50")
    plan = CommandPlan(tool="t50", params={"target": "example.com"}, argv=tool.build_argv({"target": "example.com"}))
    verdict = evaluate(plan, tool, ControlPolicy(max_auto_risk=Risk.LOW))
    assert verdict.decision is Decision.CONFIRM


def test_vuln_expert_tools_all_available():
    expert = get_expert("vuln")
    assert set(expert.available_tools()) == set(expert.tool_names)
