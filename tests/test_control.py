"""Tests de la couche de controle de l'IA (niveau 2)."""

from __future__ import annotations

import pytest

from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.executor import ConfirmationRequired, ExecutionError
from aisec.core.engine import Engine
from aisec.core.config import Config


class _FakeTool:
    def __init__(self, binary: str, risk: str = "low") -> None:
        self.binary = binary
        self.risk = risk


def _plan(argv: list[str], targets: list[str] | None = None):
    from aisec.core.models import CommandPlan

    return CommandPlan(
        tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic"
    )


def test_low_risk_is_allowed():
    verdict = evaluate(_plan(["dig", "MX", "example.com"]), _FakeTool("dig"), ControlPolicy())
    assert verdict.decision is Decision.ALLOW
    assert verdict.risk is Risk.LOW


def test_medium_risk_needs_confirmation():
    verdict = evaluate(
        _plan(["nmap", "-p", "22", "10.0.0.1"], ["10.0.0.1"]),
        _FakeTool("nmap", "medium"),
        ControlPolicy(),
    )
    assert verdict.decision is Decision.CONFIRM
    assert verdict.risk is Risk.MEDIUM


def test_escalator_raises_risk():
    verdict = evaluate(
        _plan(["dig", "AXFR", "example.com"], ["example.com"]),
        _FakeTool("dig"),
        ControlPolicy(),
    )
    # axfr fait monter le risque -> confirmation.
    assert verdict.risk is Risk.MEDIUM
    assert verdict.decision is Decision.CONFIRM


def test_denied_tool():
    policy = ControlPolicy(denied_tools={"rm"})
    verdict = evaluate(_plan(["rm", "-rf", "/"], []), _FakeTool("rm"), policy)
    assert verdict.decision is Decision.DENY


def test_allowed_tools_whitelist():
    policy = ControlPolicy(allowed_tools={"dig"})
    verdict = evaluate(_plan(["nmap", "10.0.0.1"], ["10.0.0.1"]), _FakeTool("nmap"), policy)
    assert verdict.decision is Decision.DENY


def test_too_many_targets():
    policy = ControlPolicy(max_targets=2)
    targets = ["a.com", "b.com", "c.com"]
    verdict = evaluate(_plan(["nmap", *targets], targets), _FakeTool("nmap"), policy)
    assert verdict.decision is Decision.DENY
    assert "trop de cibles" in verdict.reasons[0]


def test_deny_private_targets():
    policy = ControlPolicy(deny_private_targets=True)
    verdict = evaluate(
        _plan(["nmap", "192.168.1.1"], ["192.168.1.1"]), _FakeTool("nmap"), policy
    )
    assert verdict.decision is Decision.DENY


def test_engine_raises_confirmation_required():
    engine = Engine(Config(provider="none", auto_approve_risk="low"))
    with pytest.raises(ConfirmationRequired) as exc:
        engine.run("nmap", "scan des ports 22,80 sur 10.0.0.1")
    assert exc.value.plan is not None
    assert exc.value.plan.risk == "medium"


def test_engine_assume_yes_bypasses_confirmation(monkeypatch):
    engine = Engine(Config(provider="none", auto_approve_risk="low"))
    called = {}

    def fake_run(argv, allowed_binary=None, timeout=120.0, dry_run=False):
        from aisec.core.models import ExecResult

        called["argv"] = argv
        return ExecResult(argv=argv, returncode=0, stdout="", stderr="", duration_s=0.0)

    monkeypatch.setattr("aisec.core.engine.run_argv", fake_run)
    plan, result, _ = engine.run(
        "nmap", "scan des ports 22,80 sur 10.0.0.1", assume_yes=True
    )
    assert result is not None
    assert called["argv"][0] == "nmap"


def test_engine_dry_run_skips_confirmation():
    engine = Engine(Config(provider="none", auto_approve_risk="low"))
    plan, result, analysis = engine.run(
        "nmap", "scan des ports 22,80 sur 10.0.0.1", dry_run=True
    )
    assert plan.risk == "medium"
    assert result is None


def test_high_ceiling_auto_approves():
    engine = Engine(Config(provider="none", auto_approve_risk="high"))
    plan, _, _ = engine.run("nmap", "scan des ports 22,80 sur 10.0.0.1", dry_run=True)
    assert plan.risk == "medium"


def test_policy_rejects_shell_metacharacter_target():
    engine = Engine(Config(provider="none", auto_approve_risk="critical"))
    with pytest.raises(ExecutionError):
        engine.run("dig", "MX example.com; rm -rf /")
