"""Tests de la classe Reverse Engineering (expert `reverse`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

REVERSE_TOOLS = {
    "rabin2",
    "radare2",
    "rahash2",
    "rasm2",
    "radiff2",
    "rizin",
    "rz-hash",
    "rz-find",
    "gdb",
    "bddisasm",
    "die",
    "apktool",
    "dex2jar",
    "jadx",
    "androguard",
    "baksmali",
    "smali",
}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("reverse")
    assert REVERSE_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in REVERSE_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("identifie sample.exe avec detect-it-easy", "die", ["diec", "sample.exe"]),
        ("liste les imports de malware.dll", "rabin2", ["rabin2", "-i", "malware.dll"]),
        ("extrait les infos de sample.exe avec rabin2", "rabin2", ["rabin2", "-I", "sample.exe"]),
        (
            "desassemble la fonction main de sample.exe avec radare2",
            "radare2",
            ["radare2", "-c", "aaa", "-c", "pdf @ main", "sample.exe"],
        ),
        ("calcule le hash de sample.exe avec rahash2", "rahash2", ["rahash2", "-a", "sha256", "sample.exe"]),
        ("compare sample_v1.exe et sample_v2.exe avec radiff2", "radiff2", ["radiff2", "-C", "sample_v1.exe", "sample_v2.exe"]),
        ("desassemble les octets 9090 avec rasm2", "rasm2", ["rasm2", "-d", "9090"]),
        ("desassemble la fonction main de sample.elf avec rizin", "rizin", ["rizin", "-c", "aaa", "-c", "pdf @ main", "sample.elf"]),
        ("cherche la chaine password dans sample.exe avec rz-find", "rz-find", ["rz-find", "-s", "password", "sample.exe"]),
        ("debogue sample.exe avec gdb", "gdb", ["gdb", "--batch", "-ex", "info functions", "sample.exe"]),
        ("decode les instructions 90 90 c3 en x86-64 avec bddisasm", "bddisasm", ["bddisasm", "--64", "90 90 c3"]),
        ("decode app.apk avec apktool", "apktool", ["apktool", "d", "app.apk"]),
        ("decompile app.apk avec jadx", "jadx", ["jadx", "app.apk"]),
        ("convertit classes.dex en jar avec dex2jar", "dex2jar", ["d2j-dex2jar", "classes.dex"]),
        ("analyse les permissions de app.apk avec androguard", "androguard", ["androguard", "apk", "app.apk"]),
        ("desassemble classes.dex avec baksmali", "baksmali", ["baksmali", "disassemble", "classes.dex"]),
        ("assemble le repertoire smali/ en app.dex avec smali", "smali", ["smali", "assemble", "smali/"]),
    ],
)
def test_routing_and_argv(text, tool, expected):
    expert = get_expert("reverse")
    routed, params, _ = route(expert, text, None)
    assert routed == tool
    argv = registry.get(routed).build_argv(params)
    if expected is not None:
        assert argv == expected


def test_router_selects_reverse():
    assert select("analyse et desassemble ce binaire suspect").name == "reverse"


def test_gdb_is_medium_risk():
    assert registry.get("gdb").risk == "medium"


def test_gdb_requires_confirmation():
    verdict = evaluate(
        _plan(["gdb", "--batch", "-ex", "info functions", "sample.exe"]),
        registry.get("gdb"),
        ControlPolicy(),
    )
    assert verdict.decision is Decision.CONFIRM


def test_rabin2_low_risk_auto_allowed():
    verdict = evaluate(_plan(["rabin2", "-I", "sample.exe"]), registry.get("rabin2"), ControlPolicy())
    assert verdict.risk is Risk.LOW
    assert verdict.decision is Decision.ALLOW


def test_engine_plans_rabin2_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("rabin2", "liste les imports de malware.dll", dry_run=True)
    assert plan.argv == ["rabin2", "-i", "malware.dll"]
    assert result is None and analysis is None


def test_die_flags_packer():
    output = "PE64\n  Protector: UPX(3.96)\n  Linker: Microsoft Linker\n"
    analysis = registry.get("die").analyze(output, {})
    assert any("UPX" in f.title for f in analysis.findings)


def test_rabin2_flags_suspicious_strings():
    output = (
        "nth paddr      vaddr      len size section type  string\n"
        "0   0x00001234 0x00401234 18  19   .data   ascii http://evil.example/x\n"
        "1   0x00002000 0x00402000 8   9    .data   ascii password\n"
    )
    analysis = registry.get("rabin2").analyze(output, {})
    assert any(f.severity == "medium" for f in analysis.findings)


def test_jadx_flags_dangerous_permission():
    analysis = registry.get("jadx").analyze("uses-permission SEND_SMS\n", {})
    assert any("SEND_SMS" in f.title for f in analysis.findings)


def test_radare2_flags_risky_calls():
    output = "0x00401a2b  call sym.imp.system\n0x00401a30  mov eax, strcpy\n"
    analysis = registry.get("radare2").analyze(output, {})
    assert any(f.severity == "medium" for f in analysis.findings)


def test_rahash2_reports_digest():
    analysis = registry.get("rahash2").analyze("sha256-abcdef0123456789\n", {})
    assert analysis.findings and analysis.findings[0].severity == "info"
