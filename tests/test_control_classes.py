"""Controle (niveau 2) et routage pour les 5 classes d'experts livrees."""

from __future__ import annotations

import pytest

from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.engine import Engine
from aisec.core.config import Config
from aisec.core.executor import ExecutionError
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


@pytest.mark.parametrize(
    "expert_name, text, expected",
    [
        ("web", "brute force les repertoires du site web", "web"),
        ("password", "casse ce hash de mot de passe", "password"),
        ("sniffing", "capture le trafic reseau en pcap", "sniffing"),
        ("vulnerability", "audit de vulnerabilite tls", "vulnerability"),
        ("info", "enumeration des hotes du reseau", "info"),
    ],
)
def test_router_selects_expected_expert(expert_name, text, expected):
    assert select(text).name == expected


def test_hydra_is_high_risk_and_needs_confirmation():
    from aisec.core.registry import get

    tool = get("hydra")
    assert tool.risk == "high"
    verdict = evaluate(
        _plan(["hydra", "-L", "u.txt", "-P", "p.txt", "10.0.0.1", "ssh"], ["10.0.0.1"]),
        tool,
        ControlPolicy(),
    )
    assert verdict.risk is Risk.HIGH
    assert verdict.decision is Decision.CONFIRM


def test_bettercap_eval_escalates_risk():
    from aisec.core.registry import get

    verdict = evaluate(
        _plan(["bettercap", "-eval", "arp.spoof on"], []),
        get("bettercap"),
        ControlPolicy(),
    )
    # risque intrinseque high + argument sensible -> critical
    assert verdict.risk is Risk.CRITICAL


def test_nikto_medium_needs_confirmation():
    from aisec.core.registry import get

    verdict = evaluate(_plan(["nikto", "-h", "example.com"]), get("nikto"), ControlPolicy())
    assert verdict.decision is Decision.CONFIRM


def test_engine_plans_nikto_dry_run():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, result, analysis = engine.run("nikto", "scanne https://example.com avec nikto", dry_run=True)
    assert plan.argv[0] == "nikto"
    assert result is None and analysis is None


def test_engine_blocks_masscan_huge_cidr():
    engine = Engine(Config(provider="none"))
    with pytest.raises(ExecutionError):
        engine.plan("masscan", "scanne les ports 80 sur 0.0.0.0/0")
