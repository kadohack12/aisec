"""Tests de l'expert Password Attacks (classe `05-password-attacks`).

Verifie l'enregistrement des outils, le routage heuristique, la construction
d'argv et l'application de la politique de controle (niveau 2): ces outils
sont en high/critical, donc jamais auto-approuves au niveau `low`.
"""

from __future__ import annotations

from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.models import CommandPlan
from aisec.core.registry import get
from aisec.experts import get as get_expert, select
from aisec.experts.base import route


def test_passwords_expert_registered():
    expert = get_expert("passwords")
    assert "hydra" in expert.tool_names
    assert "hashcat" in expert.tool_names
    assert "john" in expert.tool_names


def test_passwords_tools_are_registered():
    for name in ("hash-identifier", "hydra", "medusa", "ncrack", "patator", "hashcat", "john", "crunch", "cewl"):
        assert get(name).binary


def test_router_selects_passwords_for_hash_request():
    expert = select("craque ce hash md5 avec un dictionnaire")
    assert expert.name == "passwords"


def test_router_prefers_hash_identifier_for_type():
    tool_name, params, source = route(
        get_expert("passwords"), "identifie le hash 5f4dcc3b5aa765d61d8327deb882cf99", None
    )
    assert tool_name == "hash-identifier"
    assert params["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert source == "heuristic"


def test_router_prefers_hydra_for_ssh_bruteforce():
    tool_name, params, _ = route(
        get_expert("passwords"), "bruteforce ssh sur 10.0.0.5 avec l'utilisateur root", None
    )
    assert tool_name == "hydra"
    assert params["service"] == "ssh"
    assert params["target"] == "10.0.0.5"


def test_router_prefers_hashcat_for_hash_file():
    tool_name, params, _ = route(
        get_expert("passwords"), "craque le fichier hashes.txt en mode 0 avec rockyou.txt", None
    )
    assert tool_name == "hashcat"
    assert params["hashfile"] == "hashes.txt"
    assert params["wordlist"] == "rockyou.txt"


def test_router_prefers_crunch_for_wordlist_generation():
    tool_name, _, _ = route(get_expert("passwords"), "genere une liste de mots de passe", None)
    assert tool_name == "crunch"


def test_router_prefers_cewl_for_site_wordlist():
    tool_name, params, _ = route(get_expert("passwords"), "genere une wordlist depuis le site http://example.com", None)
    assert tool_name == "cewl"
    assert params["url"] == "http://example.com"


def test_hydra_build_argv():
    argv = get("hydra").build_argv(
        {"target": "10.0.0.5", "service": "ssh", "username": "root", "passlist": "/tmp/pw.txt"}
    )
    assert argv == ["hydra", "-l", "root", "-P", "/tmp/pw.txt", "10.0.0.5", "ssh"]


def test_hashcat_build_argv_mask_mode():
    argv = get("hashcat").build_argv({"hashfile": "hashes.txt", "mask": "?a?a?a?a", "hash_mode": 0})
    assert argv == ["hashcat", "-m", "0", "-a", "3", "hashes.txt", "?a?a?a?a"]


def test_crunch_build_argv_range():
    argv = get("crunch").build_argv({"min_length": 6, "max_length": 8, "output": "out.txt"})
    assert argv == ["crunch", "6", "8", "-o", "out.txt"]


def test_password_attack_never_auto_approved_at_low():
    tool = get("hydra")
    plan = CommandPlan(
        tool="hydra",
        params={"target": "10.0.0.5", "service": "ssh"},
        argv=tool.build_argv({"target": "10.0.0.5", "service": "ssh"}),
    )
    verdict = evaluate(plan, tool, ControlPolicy(max_auto_risk=Risk.LOW))
    assert verdict.decision is Decision.CONFIRM
    assert verdict.risk is Risk.CRITICAL


def test_passwords_expert_tools_all_available():
    expert = get_expert("passwords")
    assert set(expert.available_tools()) == set(expert.tool_names)
