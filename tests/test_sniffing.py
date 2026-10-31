"""Tests de la classe Sniffing & Spoofing (expert `sniffing`)."""

from __future__ import annotations

from aisec.core import registry
from aisec.experts import get as get_expert
from aisec.experts.base import route


def test_sniffing_expert_registered():
    expert = get_expert("sniffing")
    assert {"tshark", "bettercap"} <= set(expert.tool_names)


def test_route_tshark_capture():
    tool, params, _ = route(get_expert("sniffing"), "capture le trafic http sur eth0 pendant 100 paquets", None)
    assert tool == "tshark"
    assert params["interface"] == "eth0"
    assert params["count"] == 100


def test_route_bettercap_spoof():
    tool, params, _ = route(get_expert("sniffing"), "arp spoof de 192.168.1.50 avec bettercap sur eth0", None)
    assert tool == "bettercap"
    assert params["interface"] == "eth0"
    assert "arp.spoof" in params["eval"]


def test_route_bettercap_probe():
    tool, params, _ = route(get_expert("sniffing"), "decouvre les hotes du reseau avec bettercap", None)
    assert tool == "bettercap"
    assert params["eval"] == "net.probe on"


def test_bettercap_build_argv():
    argv = registry.get("bettercap").build_argv({"interface": "eth0", "eval": "net.probe on"})
    assert argv == ["bettercap", "-iface", "eth0", "-eval", "net.probe on"]


def test_bettercap_analyze_flags_credentials():
    output = "endpoint 192.168.1.10 : aa:bb:cc:dd:ee:ff\n[credential] user=admin password=secret\n"
    analysis = registry.get("bettercap").analyze(output, {})
    assert any(f.severity == "critical" for f in analysis.findings)
