"""Tests de l'expert Web Application Analysis (classe 03).

Couvre le routage, la construction d'argv, l'extraction d'URL, l'analyse
heuristique, et la politique de controle (niveau 2) pour les outils intrusifs.
"""

from __future__ import annotations

import pytest

from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.executor import ConfirmationRequired
from aisec.core.registry import get
from aisec.experts import all_experts, get as get_expert, select
from aisec.experts.base import route

EXPERT = get_expert("webapp")


# ---- Enregistrement et perimetre -----------------------------------------


def test_webapp_expert_is_registered():
    assert "webapp" in {e.name for e in all_experts()}
    assert len(EXPERT.tool_names) == 38
    assert EXPERT.available_tools() == EXPERT.tool_names


def test_every_tool_of_the_class_is_registered():
    from aisec.core import registry

    assert set(EXPERT.tool_names) <= set(registry.all_names())


@pytest.mark.parametrize(
    "query",
    [
        "scanne le wordpress http://target",
        "fuzz http://target/FUZZ",
        "teste les xss sur http://target",
        "identifie les technologies de example.com",
        "bruteforce les repertoires de http://target",
    ],
)
def test_router_selects_webapp(query):
    assert select(query).name == "webapp"


# ---- Routage interne ------------------------------------------------------


@pytest.mark.parametrize(
    "query,expected",
    [
        ("scanne le wordpress http://target", "wpscan"),
        ("scanne le joomla http://target", "joomscan"),
        ("identifie les technologies de http://target", "whatweb"),
        ("fuzz http://target/FUZZ avec la liste common.txt", "ffuf"),
        ("bruteforce les repertoires de http://target", "gobuster"),
        ("enumere les sous-domaines de example.com", "gobuster"),
        ("crawle http://target", "gospider"),
        ("decouvre les parametres caches de http://target", "arjun"),
        ("aspire le site http://target en miroir", "httrack"),
        ("scanne le serveur web example.com", "nikto"),
        ("scanne les vulnerabilites de http://target", "wapiti"),
        ("teste les failles xss sur http://target", "xsser"),
        ("teste l injection sql sur http://target", "jsql-injection"),
        ("teste le webdav de http://target", "davtest"),
        ("teste la faille heartbleed de example.com", "heartleech"),
        ("cherche les buckets s3 exposes", "s3scanner"),
        ("analyse le robots.txt de http://target", "parsero"),
    ],
)
def test_routing_rules(query, expected):
    tool_name, _, source = route(EXPERT, query, None)
    assert tool_name == expected
    assert source == "heuristic"


# ---- Construction d'argv --------------------------------------------------


def test_ffuf_builds_fuzz_command():
    argv = get("ffuf").build_argv(
        {"url": "http://target/FUZZ", "wordlist": "common.txt", "filter_codes": "404", "extensions": "php"}
    )
    assert argv[0] == "ffuf"
    assert argv[argv.index("-u") + 1] == "http://target/FUZZ"
    assert argv[argv.index("-fc") + 1] == "404"


def test_gobuster_puts_mode_first():
    argv = get("gobuster").build_argv(
        {"mode": "dir", "url": "http://target", "wordlist": "common.txt", "extensions": "php"}
    )
    assert argv[:2] == ["gobuster", "dir"]
    assert argv[argv.index("-u") + 1] == "http://target"


def test_gobuster_defaults_to_dir_mode():
    argv = get("gobuster").build_argv({"url": "http://target"})
    assert argv[:2] == ["gobuster", "dir"]


def test_wpscan_builds_url_and_enumeration():
    argv = get("wpscan").build_argv({"url": "http://target", "enumerate": "u"})
    assert argv == ["wpscan", "--url", "http://target", "-e", "u"]


def test_nikto_builds_ssl_scan():
    argv = get("nikto").build_argv({"host": "example.com", "port": "443", "ssl": True})
    assert argv == ["nikto", "-h", "example.com", "-p", "443", "-ssl"]


def test_cutycapt_joins_option_values():
    argv = get("cutycapt").build_argv({"url": "http://target", "output": "page.png"})
    assert argv == ["cutycapt", "--url=http://target", "--out=page.png"]


def test_xsser_includes_url_option():
    argv = get("xsser").build_argv({"url": "http://target"})
    assert argv == ["xsser", "-u", "http://target"]


# ---- Extraction d'intention ----------------------------------------------


def test_url_is_extracted_for_ffuf():
    params = get("ffuf").parse_intent("fuzz http://target/FUZZ avec la liste common.txt")
    assert params["url"] == "http://target/FUZZ"


def test_gobuster_dns_mode_maps_url_to_domain():
    params = get("gobuster").parse_intent("enumere les sous-domaines de example.com")
    assert params["mode"] == "dns"
    assert params["domain"] == "example.com"
    assert "url" not in params


def test_wpscan_intent_maps_enumerate_users():
    params = get("wpscan").parse_intent("scanne le wordpress http://target et enumere les utilisateurs")
    assert params["url"] == "http://target"
    assert params["enumerate"] == "u"


def test_whatweb_accepts_bare_host():
    params = get("whatweb").parse_intent("identifie les technologies de example.com")
    assert params["target"] == "example.com"


# ---- Analyse heuristique --------------------------------------------------


def test_nikto_reports_findings():
    output = "+ /admin/: Directory indexing found.\n+ Server leaks inodes via ETags\n"
    analysis = get("nikto").analyze(output, {})
    assert analysis.findings


def test_wpscan_flags_vulnerability_and_version():
    output = "[!] Title: WordPress 5.0 - XSS\nWordPress version 5.0 identified\n"
    analysis = get("wpscan").analyze(output, {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_s3scanner_flags_public_bucket():
    analysis = get("s3scanner").analyze("bucket exists\nPUBLIC: listable\n", {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_whatweb_detects_cms():
    analysis = get("whatweb").analyze("http://target [WordPress, PHP/7.4, Apache/2.4]\n", {})
    assert any("CMS" in f.title for f in analysis.findings)


def test_uniscan_flags_injection():
    analysis = get("uniscan").analyze("XSS found in /search\nSQL injection in /login\n", {})
    assert any(f.severity == "high" for f in analysis.findings)


def test_davtest_flags_executable_upload():
    analysis = get("davtest").analyze("SUCCEED: php executable uploaded\n", {})
    assert any(f.severity == "critical" for f in analysis.findings)


# ---- Politique de controle (niveau 2) ------------------------------------


def _plan(argv, targets=None):
    from aisec.core.models import CommandPlan

    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_fuzzing_tool_needs_confirmation():
    verdict = evaluate(_plan(["ffuf", "-u", "http://target/FUZZ"]), get("ffuf"), ControlPolicy())
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_exploitation_tool_is_critical():
    verdict = evaluate(
        _plan(["jboss-autopwn", "10.0.0.1"]), get("jboss-autopwn"), ControlPolicy()
    )
    assert verdict.risk is Risk.CRITICAL
    assert verdict.decision is Decision.CONFIRM


def test_fingerprint_tool_is_allowed():
    verdict = evaluate(
        _plan(["whatweb", "example.com"]), get("whatweb"), ControlPolicy()
    )
    assert verdict.decision is Decision.ALLOW


def test_engine_confirms_before_running_wpscan():
    engine = Engine(Config(provider="none", auto_approve_risk="low"))
    with pytest.raises(ConfirmationRequired):
        engine.run("wpscan", "scanne le wordpress http://target")


def test_engine_dry_run_skips_fuzzing():
    engine = Engine(Config(provider="none", auto_approve_risk="low"))
    plan, result, analysis = engine.run(
        "ffuf", "fuzz http://target/FUZZ avec la liste common.txt", dry_run=True
    )
    assert result is None
    assert analysis is None
    assert plan.risk == "high"
