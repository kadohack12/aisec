"""Tests de la classe Password Attacks (expert `password`)."""

from __future__ import annotations

from aisec.core import registry
from aisec.experts import get as get_expert
from aisec.experts.base import route


def test_password_expert_registered():
    expert = get_expert("password")
    assert {"hydra", "john", "hashid", "cewl"} <= set(expert.tool_names)


def test_route_hashid():
    tool, params, _ = route(get_expert("password"), "identifie le hash 5f4dcc3b5aa765d61d8327deb882cf99", None)
    assert tool == "hashid"
    assert params["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_route_hydra_ssh():
    tool, params, _ = route(get_expert("password"), "teste les mots de passe ssh sur 10.0.0.1", None)
    assert tool == "hydra"
    assert params["target"] == "10.0.0.1"
    assert params["protocol"] == "ssh"


def test_route_john_offline():
    tool, params, _ = route(get_expert("password"), "casse le fichier hashes.txt au format ntlm hors ligne", None)
    assert tool == "john"
    assert params["hashfile"] == "hashes.txt"
    assert params["format"] == "nt"


def test_route_cewl():
    tool, params, _ = route(get_expert("password"), "genere un dictionnaire a partir de https://example.com", None)
    assert tool == "cewl"
    assert params["url"] == "https://example.com"


def test_hydra_build_argv():
    argv = registry.get("hydra").build_argv(
        {"target": "10.0.0.1", "protocol": "ssh", "userlist": "users.txt", "passlist": "pass.txt", "threads": 4}
    )
    assert argv == ["hydra", "-L", "users.txt", "-P", "pass.txt", "-t", "4", "10.0.0.1", "ssh"]


def test_john_build_argv():
    argv = registry.get("john").build_argv(
        {"hashfile": "hashes.txt", "format": "nt", "wordlist": "rockyou.txt", "rules": True}
    )
    assert argv == ["john", "--format", "nt", "--wordlist", "rockyou.txt", "--rules", "hashes.txt"]


def test_hashid_build_argv():
    argv = registry.get("hashid").build_argv({"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "mode": "hashcat"})
    assert argv == ["hashid", "-m", "5f4dcc3b5aa765d61d8327deb882cf99"]


def test_cewl_build_argv():
    argv = registry.get("cewl").build_argv(
        {"url": "https://example.com", "depth": 2, "output": "mots.txt", "emails": True}
    )
    assert argv == ["cewl", "https://example.com", "-d", "2", "-m", "3", "-w", "mots.txt", "-e"]


def test_hydra_analyze_flags_credentials():
    output = "[22][ssh] host: 10.0.0.1   login: admin   password: admin123\n"
    analysis = registry.get("hydra").analyze(output, {})
    assert any(f.severity == "critical" for f in analysis.findings)


def test_hashid_analyze_lists_candidates():
    output = "[+] MD5\n[+] NTLM\n"
    analysis = registry.get("hashid").analyze(output, {})
    assert len(analysis.findings) == 2
