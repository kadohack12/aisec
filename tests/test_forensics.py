"""Tests de la classe Digital Forensics (expert `forensics`)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

FORENSICS_TOOLS = {
    "fls",
    "mmls",
    "icat",
    "foremost",
    "scalpel",
    "binwalk",
    "bulk_extractor",
    "pdfid",
    "pdf-parser",
    "yara",
    "volatility3",
    "regripper",
    "reglookup",
    "galleta",
    "vinetto",
    "hashdeep",
    "ssdeep",
    "rkhunter",
    "chkrootkit",
    "extundelete",
    "dc3dd",
    "ddrescue",
}


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_expert_registered_with_all_tools():
    expert = get_expert("forensics")
    assert FORENSICS_TOOLS <= set(expert.tool_names)


def test_every_tool_is_registered():
    for name in FORENSICS_TOOLS:
        assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        ("analyse le firmware firmware.bin avec binwalk", "binwalk", ["binwalk", "firmware.bin"]),
        ("recupere les fichiers de disk.img avec foremost", "foremost", ["foremost", "-i", "disk.img"]),
        ("analyse suspect.pdf avec pdfid", "pdfid", ["pdfid", "suspect.pdf"]),
        ("scanne sample.bin avec les regles malware.yar", "yara", ["yara", "malware.yar", "sample.bin"]),
        (
            "liste les processus de dump.mem avec volatility3",
            "volatility3",
            ["volatility3", "-f", "dump.mem", "windows.pslist"],
        ),
        ("affiche les partitions de disk.img avec mmls", "mmls", ["mmls", "disk.img"]),
        ("liste les fichiers de disk.img avec fls", "fls", ["fls", "disk.img"]),
        ("extrait les cookies de Cookies.txt avec galleta", "galleta", ["galleta", "Cookies.txt"]),
        ("extrait les vignettes de Thumbs.db avec vinetto", "vinetto", ["vinetto", "-d", "Thumbs.db"]),
        ("detecte les rootkits avec chkrootkit", "chkrootkit", ["chkrootkit"]),
        ("recupere les fichiers supprimes de /dev/sda1 avec extundelete", "extundelete", ["extundelete", "/dev/sda1"]),
        ("image forensique de /dev/sdb vers disk.img avec dc3dd", "dc3dd", ["dc3dd", "if=/dev/sdb", "of=disk.img"]),
        ("recupere les donnees de /dev/sdb vers disk.img avec ddrescue", "ddrescue", ["ddrescue", "/dev/sdb", "disk.img"]),
        ("parcourt la ruche SYSTEM avec reglookup", "reglookup", ["reglookup", "SYSTEM"]),
        ("calcule les empreintes de /evidence avec hashdeep", "hashdeep", None),
        ("cherche les injections dans memory.raw", "volatility3", None),
        ("cherche le javascript dans document.pdf", "pdfid", ["pdfid", "document.pdf"]),
        ("analyse la ruche NTUSER.DAT avec regripper plugin run", "regripper", ["regripper", "-r", "NTUSER.DAT", "-p", "run"]),
    ],
)
def test_routing_and_argv(text, tool, expected):
    expert = get_expert("forensics")
    routed, params, _ = route(expert, text, None)
    assert routed == tool
    argv = registry.get(routed).build_argv(params)
    if expected is not None:
        assert argv == expected


def test_bulk_extractor_default_output():
    argv = registry.get("bulk_extractor").build_argv(
        {"input": "disk.img", "scanners": "email,url"}
    )
    assert argv == ["bulk_extractor", "-o", "output", "-e", "email,url", "disk.img"]


def test_router_selects_forensics():
    assert select("analyse forensique de l'image disque disk.img").name == "forensics"


def test_dc3dd_is_high_risk():
    assert registry.get("dc3dd").risk == "high"


def test_ddrescue_needs_confirmation():
    verdict = evaluate(
        _plan(["ddrescue", "/dev/sdb", "disk.img"]),
        registry.get("ddrescue"),
        ControlPolicy(),
    )
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_binwalk_low_risk_auto_allowed():
    verdict = evaluate(
        _plan(["binwalk", "firmware.bin"]),
        registry.get("binwalk"),
        ControlPolicy(),
    )
    assert verdict.risk is Risk.LOW
    assert verdict.decision is Decision.ALLOW


def test_engine_plans_binwalk_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("binwalk", "analyse le firmware firmware.bin", dry_run=True)
    assert plan.argv == ["binwalk", "firmware.bin"]
    assert result is None and analysis is None


def test_binwalk_analyze_flags_firmware():
    output = (
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        "0             0x0             Squashfs filesystem, little endian\n"
        "1024          0x400           gzip compressed data\n"
    )
    analysis = registry.get("binwalk").analyze(output, {})
    assert len(analysis.findings) == 2
    assert all(f.severity == "medium" for f in analysis.findings)


def test_pdfid_analyze_flags_javascript():
    output = " PDFiD 0.2.7 suspect.pdf\n /JS                 2\n /JavaScript         2\n /OpenAction         1\n /Page               5\n"
    analysis = registry.get("pdfid").analyze(output, {})
    assert any(f.severity == "high" for f in analysis.findings)
    assert not any("Page" in f.title for f in analysis.findings)


def test_yara_analyze_reports_match():
    output = "malware_rule [trojan] /samples/sample.bin\n"
    analysis = registry.get("yara").analyze(output, {})
    assert len(analysis.findings) == 1
    assert analysis.findings[0].severity == "high"
    assert "malware_rule" in analysis.findings[0].title


def test_volatility_analyze_flags_hashdump():
    output = (
        "User           RID  LM Hash                          NT Hash\n"
        "Administrator  500  aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0\n"
    )
    analysis = registry.get("volatility3").analyze(output, {"plugin": "windows.hashdump"})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_fls_analyze_lists_entries():
    output = "r/r * 5: file.txt\nr/r 7: photo.jpg\nd/d 11: Windows\n"
    analysis = registry.get("fls").analyze(output, {})
    assert len(analysis.findings) >= 2


def test_chkrootkit_analyze_flags_infection():
    output = "Checking `lkm'... INFECTED\nSearching for suspicious files... WARNING\n"
    analysis = registry.get("chkrootkit").analyze(output, {})
    assert any(f.severity == "critical" for f in analysis.findings)
