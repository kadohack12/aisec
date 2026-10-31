"""Tests de la classe Wireless Testing (expert `wireless`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

WIRELESS_TOOLS = {
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "reaver",
    "wifite",
    "mdk4",
    "pixiewps",
    "bully",
    "cowpatty",
    "asleap",
    "bluesnarfer",
    "blueranger",
    "hcitool",
    "mfoc",
    "mfcuk",
    "nfc-list",
}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("wireless")
    assert WIRELESS_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in WIRELESS_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("active le mode moniteur sur wlan0", "airmon-ng", ["airmon-ng", "start", "wlan0"]),
        ("capture les reseaux wifi sur wlan0mon", "airodump-ng", ["airodump-ng", "wlan0mon"]),
        (
            "capture le handshake du bssid AA:BB:CC:DD:EE:FF sur wlan0mon",
            "airodump-ng",
            ["airodump-ng", "--bssid", "AA:BB:CC:DD:EE:FF", "wlan0mon"],
        ),
        (
            "desauthentifie le client du bssid AA:BB:CC:DD:EE:FF sur wlan0mon",
            "aireplay-ng",
            ["aireplay-ng", "-0", "1", "-a", "AA:BB:CC:DD:EE:FF", "wlan0mon"],
        ),
        (
            "casse le wpa de capture.cap avec rockyou.txt",
            "aircrack-ng",
            ["aircrack-ng", "-w", "rockyou.txt", "capture.cap"],
        ),
        (
            "attaque le wps du bssid AA:BB:CC:DD:EE:FF sur wlan0mon",
            "reaver",
            ["reaver", "-i", "wlan0mon", "-b", "AA:BB:CC:DD:EE:FF"],
        ),
        ("lance wifite --wps", "wifite", ["wifite", "--wps"]),
        ("teste la robustesse du canal 6 sur wlan0mon", "mdk4", ["mdk4", "wlan0mon", "d", "-c", "6"]),
        ("scanne les peripheriques bluetooth", "hcitool", ["hcitool", "scan"]),
        (
            "extrait le repertoire du telephone AA:BB:CC:DD:EE:FF",
            "bluesnarfer",
            ["bluesnarfer", "-b", "AA:BB:CC:DD:EE:FF", "-C", "0"],
        ),
        ("liste les tags nfc a portee", "nfc-list", ["nfc-list"]),
        ("recupere les cles de la carte mifare dans dump.mfd", "mfoc", ["mfoc", "-O", "dump.mfd"]),
    ],
)
def test_route_and_argv(text, tool, expected):
    name, params, _source = route(get_expert("wireless"), text, provider=None)
    assert name == tool
    assert registry.get(name).build_argv(params) == expected


def test_aircrack_high_risk_requires_confirmation():
    verdict = evaluate(_plan(["aircrack-ng", "-w", "rockyou.txt", "capture.cap"]), registry.get("aircrack-ng"), ControlPolicy())
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_aireplay_deauth_requires_confirmation():
    verdict = evaluate(_plan(["aireplay-ng", "-0", "5", "wlan0mon"]), registry.get("aireplay-ng"), ControlPolicy())
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_airodump_capture_is_medium():
    verdict = evaluate(_plan(["airodump-ng", "wlan0mon"]), registry.get("airodump-ng"), ControlPolicy())
    assert verdict.risk is Risk.MEDIUM
    assert verdict.decision is Decision.CONFIRM


def test_hcitool_scan_is_low_and_allowed():
    verdict = evaluate(_plan(["hcitool", "scan"]), registry.get("hcitool"), ControlPolicy())
    assert verdict.risk is Risk.LOW
    assert verdict.decision is Decision.ALLOW


def test_router_selects_wireless_for_wifi():
    assert select("capture le handshake wifi sur wlan0mon").name == "wireless"


def test_engine_plans_airodump_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("airodump-ng", "capture les reseaux wifi sur wlan0mon", dry_run=True)
    assert plan.argv == ["airodump-ng", "wlan0mon"]
    assert result is None and analysis is None


def test_aircrack_flags_key_found():
    analysis = registry.get("aircrack-ng").analyze("KEY FOUND! [ s3cr3t ]\n", {})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_airodump_flags_handshake():
    output = "BSSID              STATION            PWR   ... WPA handshake: AA:BB:CC:DD:EE:FF\n"
    analysis = registry.get("airodump-ng").analyze(output, {})
    assert any("handshake" in f.title.lower() for f in analysis.findings)


def test_reaver_flags_pin_cracked():
    analysis = registry.get("reaver").analyze("WPS PIN: '12345678'\nWPA PSK: 'monreseau'\n", {})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_hcitool_lists_devices():
    output = "Scanning ...\nAA:BB:CC:DD:EE:FF  Mon telephone\n"
    analysis = registry.get("hcitool").analyze(output, {})
    assert any(f.severity == "info" for f in analysis.findings)
