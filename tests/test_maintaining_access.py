"""Tests de la classe Maintaining Access (expert `maintaining`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

MAINTAINING_TOOLS = {
    "bloodhound",
    "dnscat2-server",
    "dnscat2-client",
    "villain",
    "starkiller",
    "convoc2",
    "windows-binaries",
    "powershell-empire",
    "pwncat",
    "cryptcat",
    "sbd",
    "sliver",
    "weevely",
    "webacoo",
    "laudanum",
    "nishang",
    "webshells",
    "htshells",
    "iodine",
    "dns2tcp",
    "godoh",
    "miredo",
    "proxychains",
    "proxychains4",
    "proxytunnel",
    "ptunnel",
    "pwnat",
    "socat",
    "stunnel4",
    "udptunnel",
    "shellter",
    "veil-evasion",
    "hyperion",
    "exe2hexbat",
}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("maintaining")
    assert MAINTAINING_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in MAINTAINING_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("cartographie active directory de corp.local avec bloodhound", "bloodhound", ["bloodhound", "--domain", "corp.local"]),
        ("lance le serveur dnscat2 sur tunnel.example.com", "dnscat2-server", ["dnscat2-server", "tunnel.example.com"]),
        ("connecte le client dnscat2 au domaine tunnel.example.com", "dnscat2-client", ["dnscat2", "tunnel.example.com"]),
        ("lance le framework villain sur le port 4443", "villain", ["villain", "--port", "4443"]),
        ("lance starkiller sur le port 1337", "starkiller", ["starkiller", "--port", "1337"]),
        ("lance le serveur powershell-empire", "powershell-empire", ["powershell-empire", "server"]),
        ("ecoute sur le port 4444 avec pwncat", "pwncat", ["pwncat", "-l", "-p", "4444"]),
        ("ecoute chiffree sur le port 4444 avec cryptcat", "cryptcat", ["cryptcat", "-l", "-p", "4444"]),
        ("lance une backdoor sbd en ecoute sur le port 4444", "sbd", ["sbd", "-l", "-p", "4444"]),
        ("genere un implant avec sliver", "sliver", ["sliver", "generate"]),
        ("genere un webshell avec weevely et la cle secret", "weevely", ["weevely", "generate", "secret"]),
        ("connecte weevely a http://cible/shell.php", "weevely", ["weevely", "http://cible/shell.php"]),
        ("genere un webshell webacoo", "webacoo", ["webacoo", "-g"]),
        ("liste les webshells laudanum disponibles", "laudanum", ["laudanum", "--list"]),
        ("liste les scripts nishang", "nishang", ["nishang", "--list"]),
        ("liste les webshells de la collection", "webshells", ["webshells", "--list"]),
        ("liste les htaccess offensifs disponibles", "htshells", ["htshells", "--list"]),
        ("ouvre un tunnel iodine vers tunnel.example.com", "iodine", ["iodine", "-c", "tunnel.example.com"]),
        ("lance le serveur dns2tcp sur le domaine tunnel.example.com", "dns2tcp", ["dns2tcp", "-s", "-d", "tunnel.example.com"]),
        ("lance godoh en serveur c2 doh", "godoh", ["godoh", "server", "--domain", "doh.example.com"]),
        ("lance miredo pour un tunnel teredo", "miredo", ["miredo"]),
        ("lance nmap via proxychains sur 10.0.0.5", "proxychains", ["proxychains4", "nmap"]),
        ("lance hydra via proxychains4 sur 10.0.0.5", "proxychains4", ["proxychains4", "hydra"]),
        (
            "ouvre un tunnel ssh via le proxy http://proxy:8080 vers 10.0.0.5:22",
            "proxytunnel",
            ["proxytunnel", "-p", "http://proxy:8080", "-d", "10.0.0.5:22"],
        ),
        ("ouvre un tunnel ptunnel via 10.0.0.5 vers 10.0.0.9:22", "ptunnel", ["ptunnel", "-p", "10.0.0.5", "-l", "10.0.0.9:22"]),
        ("tunnel udp de 10.0.0.5:53 vers 10.0.0.9:53 avec udptunnel", "udptunnel", ["udptunnel", "-l", "53", "-r", "10.0.0.5:53"]),
        ("lance pwnat en serveur sur le port 8000", "pwnat", ["pwnat", "-s", "-p", "8000"]),
        ("relaye tcp-listen:4444 vers tcp:10.0.0.5:22 avec socat", "socat", ["socat", "tcp-listen:4444", "tcp:10.0.0.5:22"]),
        ("lance stunnel4 avec la configuration stunnel.conf", "stunnel4", ["stunnel4", "stunnel.conf"]),
        ("injecte un shellcode dans app.exe avec shellter", "shellter", ["shellter", "-a", "-f", "app.exe"]),
        ("chiffre app.exe avec hyperion", "hyperion", ["hyperion", "app.exe"]),
        ("convertit app.exe en bat avec exe2hexbat", "exe2hexbat", ["exe2hexbat", "-x", "app.exe"]),
    ],
)
def test_routing_and_argv(text, tool, expected):
    expert = get_expert("maintaining")
    routed, params, _ = route(expert, text, None)
    assert routed == tool
    argv = registry.get(routed).build_argv(params)
    assert argv == expected


def test_router_selects_maintaining_for_backdoor():
    assert select("installe une backdoor persistante sur la cible").name == "maintaining"


def test_router_selects_maintaining_for_tunnel():
    assert select("exfiltre des donnees via un tunnel dns").name == "maintaining"


def test_backdoor_is_high_risk():
    assert registry.get("sbd").risk == "high"


def test_backdoor_requires_confirmation():
    verdict = evaluate(_plan(["sbd", "-l", "-p", "4444"]), registry.get("sbd"), ControlPolicy())
    assert verdict.decision is Decision.CONFIRM


def test_bloodhound_is_medium_risk():
    assert registry.get("bloodhound").risk == "medium"


def test_bloodhound_requires_confirmation():
    verdict = evaluate(
        _plan(["bloodhound", "--domain", "corp.local"]),
        registry.get("bloodhound"),
        ControlPolicy(),
    )
    assert verdict.decision is Decision.CONFIRM


def test_proxychains_is_medium_risk():
    assert registry.get("proxychains").risk == "medium"


def test_engine_plans_socat_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run(
        "socat", "relaye tcp-listen:4444 vers tcp:10.0.0.5:22 avec socat", dry_run=True
    )
    assert plan.argv == ["socat", "tcp-listen:4444", "tcp:10.0.0.5:22"]
    assert result is None and analysis is None


def test_socat_plan_is_not_low_risk():
    # Un relais peut exposer un service interne: jamais classe "low".
    assert registry.get("socat").risk == "medium"
    verdict = evaluate(
        _plan(["socat", "tcp-listen:4444", "tcp:10.0.0.5:22"]),
        registry.get("socat"),
        ControlPolicy(),
    )
    assert verdict.decision is Decision.CONFIRM


def test_bloodhound_flags_privileged_path():
    output = "Found 1 path to Domain Admins (owned)\n"
    analysis = registry.get("bloodhound").analyze(output, {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_villain_flags_public_c2():
    analysis = registry.get("villain").analyze("", {"host": "0.0.0.0", "port": "4443"})
    assert any(f.severity == "high" for f in analysis.findings)


def test_powershell_empire_flags_agent():
    analysis = registry.get("powershell-empire").analyze("listener started, agent checked in\n", {})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_convoc2_always_flags_cloud_c2():
    analysis = registry.get("convoc2").analyze("", {})
    assert analysis.findings and analysis.findings[0].severity == "high"


def test_shellter_flags_injection():
    analysis = registry.get("shellter").analyze("", {"binary": "app.exe"})
    assert any(f.severity == "high" for f in analysis.findings)
