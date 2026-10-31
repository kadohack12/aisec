"""Tests du catalogue Parrot et du routage par expert (classe DNS)."""

from __future__ import annotations

from aisec.catalog import get_catalog
from aisec.experts import all_experts, get as get_expert, select
from aisec.experts.base import route


def test_catalog_loads_parrot_tools():
    catalog = get_catalog()
    assert len(catalog.tools) > 400
    names = {t.name for t in catalog.tools}
    assert {"nmap", "wireshark", "gobuster", "hydra", "sqlmap"} <= names
    # La detection d'installation doit ecarter les libelles de menu.
    import shutil

    nmap = catalog.by_name("nmap")
    assert nmap.binaries == ["nmap"]
    assert nmap.installed == (shutil.which("nmap") is not None)


def test_catalog_search_and_category():
    catalog = get_catalog()
    dns_tools = catalog.by_category_id("01-01-dns-analysis")
    assert any(t.name == "dnsenum" for t in dns_tools)
    assert any(t.name == "fierce" for t in dns_tools)
    hits = catalog.search("directory bruteforce")
    assert any("gobuster" in t.name or "dirb" in t.name or "bruteforce" in t.category.lower() for t in hits)


def test_catalog_root_category_resolution():
    catalog = get_catalog()
    assert catalog.root_category_id("01-01-dns-analysis") == "01-info-gathering"


def test_dns_expert_is_registered():
    expert = get_expert("dns")
    assert "dig" in expert.tool_names
    assert "whois" in expert.tool_names


def test_router_selects_dns_for_domain_request():
    expert = select("je veux enumerer les sous-domaines de example.com")
    assert expert.name == "dns"


def test_router_prefers_whois_for_ownership():
    expert = get_expert("dns")
    tool_name, params, source = route(expert, "qui possede example.com", None)
    assert tool_name == "whois"
    assert params["target"] == "example.com"
    assert source == "heuristic"


def test_router_prefers_host_for_ip():
    expert = get_expert("dns")
    tool_name, _, _ = route(expert, "trouve l ip de github.com", None)
    assert tool_name == "host"


def test_router_prefers_dig_for_records():
    expert = get_expert("dns")
    tool_name, params, _ = route(expert, "resous les enregistrements MX de example.com", None)
    assert tool_name == "dig"
    assert params["record_type"] == "MX"


def test_router_dig_axfr_flag():
    expert = get_expert("dns")
    tool_name, params, _ = route(expert, "tente un transfert de zone sur example.com", None)
    assert tool_name == "dig"
    assert params["axfr"] is True


def test_dig_build_argv_axfr():
    from aisec.core.registry import get

    argv = get("dig").build_argv({"target": "example.com", "axfr": True})
    assert argv == ["dig", "AXFR", "example.com"]


def test_dig_build_argv_records():
    from aisec.core.registry import get

    argv = get("dig").build_argv({"target": "example.com", "record_type": "MX", "short": True})
    assert argv == ["dig", "MX", "example.com", "+short"]


def test_all_experts_exposes_dns():
    assert "dns" in {e.name for e in all_experts()}
