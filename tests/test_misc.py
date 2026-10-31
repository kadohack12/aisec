"""Tests de la classe 15 Autres (expert `misc`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.models import CommandPlan
from aisec.core.safety import validate_argv
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

MISC_TOOLS = {
    "apache2",
    "nginx",
    "mariadb-server",
    "postgresql",
    "openssh-server",
    "metasploit-framework",
    "gvm",
    "arduino",
    "powershell",
    "chirp",
    "nyx",
    "firefox",
    "firefox-esr",
    "coreutils",
    "gpa",
    "keepassxc",
    "mat2",
    "sirikali",
    "zulucrypt-gui",
    "zulumount-gui",
    "woeusb-ng",
}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("misc")
    assert MISC_TOOLS <= set(expert.tool_names)


def test_tool_count_is_21():
    assert len(get_expert("misc").tool_names) == 21
    assert len(MISC_TOOLS) == 21


def test_every_tool_is_registered():
    for name in MISC_TOOLS:
        assert registry.get(name).name == name


def test_no_name_collision_with_other_experts():
    names = registry.all_names()
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "text, expected",
    [
        ("demarre le service nginx", "misc"),
        ("arrete le service postgresql", "misc"),
        ("efface de facon securisee secrets.txt", "misc"),
        ("detruit le fichier keys.txt", "misc"),
        ("nettoie les metadonnees de rapport.pdf", "misc"),
        ("monte le volume chiffre /dev/sdb1", "misc"),
        ("cree une cle usb windows depuis win11.iso sur /dev/sdb", "misc"),
        ("verifie la presence de rootkits avec rkhunter", "forensics"),
        ("recupere les fichiers supprimes de disk.img", "forensics"),
        ("fuzz le binaire sample.elf", "vulnerability"),
        ("casse ce hash de mot de passe", "passwords"),
        ("capture le trafic reseau en pcap", "sniffing"),
        ("brute force les repertoires du site web", "webapp"),
        ("recherche un exploit apache", "exploitation"),
        ("desassemble crackme.elf avec radare2", "reverse"),
        ("enumeration des hotes du reseau", "info"),
        ("resous les MX de example.com", "dns"),
    ],
)
def test_router_selects_expected_expert(text, expected):
    assert select(text).name == expected


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("demarre le service nginx", "nginx", ["systemctl", "start", "nginx"]),
        ("arrete le service apache", "apache2", ["systemctl", "stop", "apache2"]),
        ("redemarre postgresql", "postgresql", ["systemctl", "restart", "postgresql"]),
        ("etat du service ssh", "openssh-server", ["systemctl", "status", "ssh"]),
        ("efface secrets.txt", "coreutils", ["shred", "-z", "-u", "-n", "3", "secrets.txt"]),
        ("nettoie les metadonnees de rapport.pdf", "mat2", ["mat2", "-i", "rapport.pdf"]),
        ("monte le volume chiffre /dev/sdb1", "sirikali", ["sirikali", "/dev/sdb1"]),
        (
            "cree une cle usb windows depuis win11.iso sur /dev/sdb",
            "woeusb-ng",
            ["woeusb", "--partition", "--device", "/dev/sdb", "win11.iso"],
        ),
    ],
)
def test_argv_construction(text, tool, expected):
    name, params, _ = route(get_expert("misc"), text, provider=None)
    assert name == tool
    assert registry.get(name).build_argv(params) == expected


def test_argv_never_contains_shell_metacharacters():
    expert = get_expert("misc")
    for text in (
        "demarre le service nginx",
        "efface secrets.txt",
        "monte le volume chiffre /dev/sdb1",
        "nettoie les metadonnees de rapport.pdf",
    ):
        name, params, _ = route(expert, text, provider=None)
        tool = registry.get(name)
        argv = tool.build_argv(params)
        report = validate_argv(argv, tool.binary)
        assert report.ok, (argv, report.errors)


def test_service_command_is_critical_and_needs_confirmation():
    verdict = evaluate(_plan(["systemctl", "restart", "nginx"]), registry.get("nginx"), ControlPolicy())
    assert verdict.risk is Risk.CRITICAL
    assert verdict.decision is Decision.CONFIRM


def test_keepassxc_is_high_and_needs_confirmation():
    verdict = evaluate(
        _plan(["keepassxc-cli", "show", "coffre.kdbx", "gmail"]),
        registry.get("keepassxc"),
        ControlPolicy(),
    )
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_woeusb_is_critical():
    assert registry.get("woeusb-ng").risk == "critical"


def test_mat2_is_low_and_allowed():
    verdict = evaluate(_plan(["mat2", "rapport.pdf"]), registry.get("mat2"), ControlPolicy())
    assert verdict.risk is Risk.LOW
    assert verdict.decision is Decision.ALLOW


def test_engine_plans_misc_dry_run():
    from aisec.experts.base import run_expert

    config = Config(provider="none", auto_approve_risk="high", dry_run=True)
    plan, result, analysis, tool_name = run_expert(
        get_expert("misc"), "nettoie les metadonnees de rapport.pdf", None, config
    )
    assert tool_name == "mat2"
    assert plan.argv == ["mat2", "-i", "rapport.pdf"]
    assert result is None and analysis is None


def test_service_command_requires_confirmation_via_expert():
    from aisec.core.executor import ConfirmationRequired
    from aisec.experts.base import run_expert

    config = Config(provider="none", auto_approve_risk="low")
    with pytest.raises(ConfirmationRequired):
        run_expert(get_expert("misc"), "demarre le service nginx", None, config)
