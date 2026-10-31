"""Tests de la classe Web Application Analysis (expert `web`)."""

from __future__ import annotations

from aisec.core import registry
from aisec.experts import get as get_expert
from aisec.experts.base import route


def test_web_expert_registered():
    expert = get_expert("web")
    assert {"whatweb", "nikto", "gobuster", "ffuf"} <= set(expert.tool_names)


def test_route_whatweb():
    tool, params, _ = route(get_expert("web"), "identifie les technologies de https://example.com", None)
    assert tool == "whatweb"
    assert params["url"] == "https://example.com"


def test_route_nikto():
    tool, params, _ = route(get_expert("web"), "scanne https://example.com avec nikto sur le port 8080", None)
    assert tool == "nikto"
    assert params["host"] == "example.com"
    assert params["port"] == 8080
    assert params["ssl"] is True


def test_route_gobuster_dir():
    tool, params, _ = route(get_expert("web"), "brute force les repertoires de https://example.com avec gobuster", None)
    assert tool == "gobuster"
    assert params["mode"] == "dir"
    assert params["url"] == "https://example.com"


def test_route_gobuster_dns():
    tool, params, _ = route(get_expert("web"), "enumere les sous-domaines de example.com par brute force", None)
    assert tool == "gobuster"
    assert params["mode"] == "dns"
    assert params["domain"] == "example.com"


def test_route_ffuf():
    tool, params, _ = route(get_expert("web"), "fuzz les repertoires de https://example.com avec ffuf", None)
    assert tool == "ffuf"
    assert params["url"] == "https://example.com/FUZZ"


def test_nikto_build_argv():
    argv = registry.get("nikto").build_argv({"host": "example.com", "port": 8080, "ssl": True})
    assert argv == ["nikto", "-h", "example.com", "-p", "8080", "-ssl"]


def test_gobuster_build_argv_dir():
    argv = registry.get("gobuster").build_argv(
        {"mode": "dir", "url": "https://example.com", "wordlist": "words.txt", "threads": 20}
    )
    assert argv == ["gobuster", "dir", "-u", "https://example.com", "-w", "words.txt", "-t", "20"]


def test_gobuster_build_argv_dns():
    argv = registry.get("gobuster").build_argv({"mode": "dns", "domain": "example.com", "wordlist": "subs.txt"})
    assert argv == ["gobuster", "dns", "-d", "example.com", "-w", "subs.txt", "-t", "10"]


def test_ffuf_build_argv():
    argv = registry.get("ffuf").build_argv({"url": "https://example.com/FUZZ", "wordlist": "w.txt"})
    assert argv[:4] == ["ffuf", "-u", "https://example.com/FUZZ", "-w"]
    assert argv[4] == "w.txt"


def test_gobuster_analyze_parses_results():
    output = "/admin (Status: 301) [Size: 0]\n/index.php (Status: 200) [Size: 1234]\n"
    analysis = registry.get("gobuster").analyze(output, {})
    assert "2 ressource(s)" in analysis.summary
    assert any("301" in f.title for f in analysis.findings)


def test_ffuf_analyze_parses_results():
    output = "admin   [Status: 200, Size: 1234, Words: 12]\nlogin   [Status: 302, Size: 0, Words: 0]\n"
    analysis = registry.get("ffuf").analyze(output, {})
    assert len(analysis.findings) == 2
