"""Tests de l'expert Web Application Analysis (classe `03-webapp-analysis`).

Verifie l'enregistrement des outils, le routage heuristique (sans LLM) et la
construction d'argv des principaux outils web.
"""

from __future__ import annotations

from aisec.core.registry import get
from aisec.experts import get as get_expert, select
from aisec.experts.base import route


def test_webapp_expert_registered():
    expert = get_expert("webapp")
    assert "nikto" in expert.tool_names
    assert "gobuster" in expert.tool_names
    assert "whatweb" in expert.tool_names


def test_webapp_tools_are_registered():
    for name in ("nikto", "whatweb", "wpscan", "joomscan", "gobuster", "ffuf", "dirb"):
        assert get(name).binary


def test_router_selects_webapp_for_web_request():
    expert = select("analyse l'application web http://example.com")
    assert expert.name == "webapp"


def test_router_prefers_wpscan_for_wordpress():
    tool_name, params, source = route(get_expert("webapp"), "scanne le wordpress de http://example.com", None)
    assert tool_name == "wpscan"
    assert params["target"] == "http://example.com"
    assert source == "heuristic"


def test_router_prefers_whatweb_for_technologies():
    tool_name, _, _ = route(get_expert("webapp"), "identifie les technologies de http://example.com", None)
    assert tool_name == "whatweb"


def test_router_prefers_gobuster_for_directory_bruteforce():
    tool_name, params, _ = route(
        get_expert("webapp"), "bruteforce les repertoires de http://example.com", None
    )
    assert tool_name == "gobuster"
    assert params["mode"] == "dir"


def test_router_prefers_nikto_for_server_scan():
    tool_name, _, _ = route(get_expert("webapp"), "scanne le serveur web http://example.com", None)
    assert tool_name == "nikto"


def test_nikto_build_argv():
    argv = get("nikto").build_argv({"target": "http://example.com", "port": 8443, "ssl": True})
    assert argv == ["nikto", "-h", "http://example.com", "-p", "8443", "-ssl"]


def test_gobuster_build_argv_extensions():
    argv = get("gobuster").build_argv(
        {"mode": "dir", "target": "http://example.com", "wordlist": "/tmp/wl.txt", "extensions": ["php", "html"]}
    )
    assert argv == ["gobuster", "dir", "-u", "http://example.com", "-w", "/tmp/wl.txt", "-x", "php,html"]


def test_ffuf_build_argv_adds_fuzz_keyword():
    tool = get("ffuf")
    params = tool.parse_intent("fuzz http://example.com/ avec ffuf")
    argv = tool.build_argv(params)
    assert argv[0] == "ffuf"
    assert "-u" in argv
    assert "FUZZ" in argv[argv.index("-u") + 1]


def test_wpscan_build_argv_enumerate():
    argv = get("wpscan").build_argv(
        {"target": "http://example.com", "enumerate": "vp,u"}
    )
    assert argv == ["wpscan", "--url", "http://example.com", "--enumerate", "vp,u"]


def test_webapp_expert_is_available_tools():
    expert = get_expert("webapp")
    assert set(expert.available_tools()) == set(expert.tool_names)
