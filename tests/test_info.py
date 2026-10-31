"""Tests de la classe Information Gathering (expert `info`)."""

from __future__ import annotations

from aisec.core import registry
from aisec.experts import get as get_expert
from aisec.experts.base import route


def test_info_expert_registered():
    expert = get_expert("info")
    assert {"nmap", "masscan", "arp-scan", "sslscan", "wafw00f", "dnsrecon"} <= set(expert.tool_names)


def test_route_wafw00f():
    tool, params, source = route(get_expert("info"), "detecte le waf devant https://example.com", None)
    assert tool == "wafw00f"
    assert params["url"] == "https://example.com"
    assert source == "heuristic"


def test_route_sslscan():
    tool, params, _ = route(get_expert("info"), "analyse le ssl de example.com:443", None)
    assert tool == "sslscan"
    assert params["target"] == "example.com"
    assert params["port"] == 443


def test_route_dnsrecon_axfr():
    tool, params, _ = route(get_expert("info"), "enumere le dns de example.com avec un transfert de zone", None)
    assert tool == "dnsrecon"
    assert params["scan_type"] == "axfr"


def test_route_arp_scan_cidr():
    tool, params, _ = route(get_expert("info"), "decouvre les hotes sur 192.168.1.0/24", None)
    assert tool == "arp-scan"
    assert params["targets"] == ["192.168.1.0/24"]


def test_route_masscan_ports():
    tool, params, _ = route(get_expert("info"), "scan masscan des ports 80,443 sur 10.0.0.0/24 tres rapidement", None)
    assert tool == "masscan"
    assert params["ports"] == "80,443"
    assert params["targets"] == ["10.0.0.0/24"]


def test_masscan_build_argv():
    argv = registry.get("masscan").build_argv({"targets": ["10.0.0.0/24"], "ports": "80,443", "rate": 1000})
    assert argv == ["masscan", "-p", "80,443", "--rate", "1000", "10.0.0.0/24"]


def test_sslscan_build_argv():
    argv = registry.get("sslscan").build_argv({"target": "example.com", "port": 443})
    assert argv == ["sslscan", "example.com:443"]


def test_wafw00f_build_argv_adds_scheme():
    argv = registry.get("wafw00f").build_argv({"url": "example.com"})
    assert argv == ["wafw00f", "https://example.com"]


def test_dnsrecon_build_argv():
    argv = registry.get("dnsrecon").build_argv({"target": "example.com", "scan_type": "axfr"})
    assert argv == ["dnsrecon", "-d", "example.com", "-t", "axfr"]


def test_arp_scan_build_argv():
    argv = registry.get("arp-scan").build_argv({"targets": ["192.168.1.0/24"]})
    assert argv == ["arp-scan", "192.168.1.0/24"]


def test_dnsrecon_analyze_flags_axfr():
    output = "[*] Zone Transfer Successful for example.com\n"
    analysis = registry.get("dnsrecon").analyze(output, {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_wafw00f_analyze_detects_waf():
    output = "The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
    analysis = registry.get("wafw00f").analyze(output, {"url": "example.com"})
    assert any("Cloudflare" in f.title for f in analysis.findings)
