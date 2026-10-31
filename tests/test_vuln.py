"""Tests de la classe Vulnerability Analysis (expert `vuln`)."""

from __future__ import annotations

from aisec.core import registry
from aisec.experts import get as get_expert
from aisec.experts.base import route


def test_vuln_expert_registered():
    expert = get_expert("vuln")
    assert {"testssl", "slowhttptest"} <= set(expert.tool_names)


def test_route_testssl():
    tool, params, _ = route(get_expert("vuln"), "audit tls complet de example.com", None)
    assert tool == "testssl"
    assert params["target"] == "example.com:443"
    assert params["full"] is True


def test_route_slowhttptest():
    tool, params, _ = route(get_expert("vuln"), "teste la resistance slowloris de https://example.com", None)
    assert tool == "slowhttptest"
    assert params["mode"] == "H"
    assert params["url"] == "https://example.com"


def test_testssl_build_argv():
    argv = registry.get("testssl").build_argv({"target": "example.com:443", "full": True})
    assert argv == ["testssl", "--full", "example.com:443"]


def test_testssl_alias_resolves():
    assert registry.get("testssl.sh").name == "testssl"


def test_slowhttptest_build_argv():
    argv = registry.get("slowhttptest").build_argv(
        {"url": "https://example.com", "mode": "H", "connections": 1000}
    )
    assert argv == ["slowhttptest", "-H", "-u", "https://example.com", "-c", "1000"]


def test_testssl_analyze_flags_vulnerable():
    output = " CRITICAL  Heartbleed: VULNERABLE\n HIGH      TLS 1.0 offered\n"
    analysis = registry.get("testssl").analyze(output, {})
    assert any(f.severity == "critical" for f in analysis.findings)
    assert any(f.severity == "high" for f in analysis.findings)


def test_slowhttptest_analyze_flags_vulnerable():
    output = "service is vulnerable to slowloris\n"
    analysis = registry.get("slowhttptest").analyze(output, {"url": "https://example.com"})
    assert any(f.severity == "high" for f in analysis.findings)
