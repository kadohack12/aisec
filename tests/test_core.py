"""Tests unitaires: parsing d'intention, construction d'argv, securite."""

from __future__ import annotations

from aisec.core.safety import validate_argv, validate_target
from aisec.core import registry


def test_registry_has_nmap_and_tshark():
    names = registry.all_names()
    assert "nmap" in names
    assert "tshark" in names
    assert registry.get("nmapAI").name == "nmap"


def test_nmap_intent_ports_and_target():
    tool = registry.get("nmap")
    params = tool.parse_intent("analyse les ports 22, 80, 8080 sur target.com")
    assert params["ports"] == "22,80,8080"
    assert "target.com" in params["targets"]


def test_nmap_build_argv():
    tool = registry.get("nmap")
    params = tool.coerce({"targets": ["target.com"], "ports": "22,80,8080", "service_detection": True})
    argv = tool.build_argv(params)
    assert argv[0] == "nmap"
    assert "-sV" in argv
    assert argv[argv.index("-p") + 1] == "22,80,8080"
    assert argv[-1] == "target.com"


def test_nmap_top_ports():
    tool = registry.get("nmap")
    argv = tool.build_argv(tool.coerce({"targets": ["10.0.0.1"], "ports": "top100"}))
    assert "--top-ports" in argv
    assert "100" in argv


def test_nmap_analyze_detects_open_ports():
    tool = registry.get("nmap")
    output = (
        "Nmap scan report for target.com (1.2.3.4)\n"
        "Host is up (0.010s latency).\n"
        "22/tcp   open  ssh     OpenSSH 8.9\n"
        "80/tcp   open  http    nginx 1.24\n"
        "443/tcp  closed https\n"
        "Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds\n"
    )
    analysis = tool.analyze(output, {})
    assert "2 port(s) ouvert(s)" in analysis.summary
    assert any("ssh" in f.detail for f in analysis.findings)


def test_nmap_analyze_flags_risky_port():
    tool = registry.get("nmap")
    output = (
        "Nmap scan report for db.local (10.0.0.9)\n"
        "3389/tcp open  ms-wbt-server\n"
    )
    analysis = tool.analyze(output, {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_tshark_intent_pcap_and_dns():
    tool = registry.get("tshark")
    params = tool.parse_intent("lis capture.pcap et affiche les requetes dns")
    assert params["read_file"] == "capture.pcap"
    assert params["display_filter"] == "dns"


def test_tshark_build_argv():
    tool = registry.get("tshark")
    argv = tool.build_argv(
        tool.coerce({"interface": "eth0", "count": 100, "display_filter": "http"})
    )
    assert argv[0] == "tshark"
    assert "-i" in argv and "eth0" in argv
    assert "-c" in argv and "100" in argv
    assert "-Y" in argv and "http" in argv


def test_safety_rejects_shell_metachars():
    report = validate_argv(["nmap", "target; rm -rf /"], "nmap")
    assert not report.ok


def test_safety_rejects_wrong_binary():
    report = validate_argv(["rm", "-rf", "/"], "nmap")
    assert not report.ok


def test_safety_rejects_huge_cidr():
    report = validate_target("0.0.0.0/0")
    assert not report.ok


def test_safety_accepts_private_target_with_warning():
    report = validate_target("192.168.1.10")
    assert report.ok
    assert report.warnings
