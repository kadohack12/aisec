"""Politique de risque par classe (niveau 3).

Verrouille le durcissement par classe: une classe offensive exige toujours une
confirmation, meme pour un outil de risque faible, et la politique combinee ne
relache jamais une borne du niveau global.
"""

from __future__ import annotations

from aisec.core.config import Config
from aisec.core.control import ControlPolicy, Decision, Risk, evaluate
from aisec.core.models import CommandPlan
from aisec.core.policies import (
    DEFAULT_CLASS_POLICIES,
    ClassPolicy,
    apply_class_policy,
    parse_class_policies,
    policy_for,
)
from aisec.core.registry import get


def _plan(argv, targets=None):
    return CommandPlan(tool=argv[0], params={"targets": targets or []}, argv=argv, source="heuristic")


def test_exploitation_class_requires_confirmation_for_low_risk():
    # searchsploit est de risque faible, mais la classe offensive impose une confirmation.
    tool = get("searchsploit")
    config = Config(provider="none", auto_approve_risk="high")
    policy = policy_for(config, "exploitation")
    verdict = evaluate(_plan(["searchsploit", "apache"]), tool, policy)
    assert verdict.decision is Decision.CONFIRM
    assert policy.require_confirmation is True


def test_global_policy_would_allow_same_tool_without_class_policy():
    tool = get("searchsploit")
    verdict = evaluate(_plan(["searchsploit", "apache"]), tool, ControlPolicy(max_auto_risk=Risk.HIGH))
    assert verdict.decision is Decision.ALLOW


def test_non_offensive_class_inherits_global_policy():
    config = Config(provider="none", auto_approve_risk="high")
    policy = policy_for(config, "dns")
    assert policy.require_confirmation is False
    assert policy.max_auto_risk is Risk.HIGH


def test_class_policy_never_relaxes_global_cap():
    # Plafond global bas (low) : la classe "wireless" (medium) ne le releve pas.
    config = Config(provider="none", auto_approve_risk="low")
    policy = policy_for(config, "wireless")
    assert policy.max_auto_risk is Risk.LOW


def test_class_policy_lowers_global_cap():
    # Plafond global high : la classe "webapp" (medium) le baisse.
    config = Config(provider="none", auto_approve_risk="high")
    policy = policy_for(config, "webapp")
    assert policy.max_auto_risk is Risk.MEDIUM


def test_unknown_expert_uses_global_policy():
    config = Config(provider="none", auto_approve_risk="medium")
    policy = policy_for(config, "classe-inexistante")
    assert policy.max_auto_risk is Risk.MEDIUM
    assert policy.require_confirmation is False


def test_apply_class_policy_preserves_bounds():
    global_policy = ControlPolicy(max_auto_risk=Risk.HIGH, max_targets=8)
    merged = apply_class_policy(global_policy, ClassPolicy(max_auto_risk=Risk.LOW))
    assert merged.max_auto_risk is Risk.LOW
    assert merged.max_targets == 8


def test_parse_class_policies_overrides_defaults():
    policies = parse_class_policies(
        {"exploitation": {"max_auto_risk": "high", "require_confirmation": False}}
    )
    assert policies["exploitation"].max_auto_risk is Risk.HIGH
    assert policies["exploitation"].require_confirmation is False
    # Les autres classes gardent leur politique par defaut.
    assert policies["passwords"].require_confirmation is True


def test_parse_class_policies_adds_new_class():
    policies = parse_class_policies({"forensics": {"require_confirmation": True}})
    assert policies["forensics"].require_confirmation is True


def test_config_class_policies_uses_overrides():
    config = Config(
        provider="none",
        auto_approve_risk="critical",
        expert_policies={"exploitation": {"require_confirmation": False, "max_auto_risk": "critical"}},
    )
    policy = policy_for(config, "exploitation")
    assert policy.require_confirmation is False
    assert policy.max_auto_risk is Risk.CRITICAL


def test_default_policies_target_offensive_classes():
    for name in ("exploitation", "post-exploit", "wireless", "passwords"):
        assert DEFAULT_CLASS_POLICIES[name].require_confirmation is True
