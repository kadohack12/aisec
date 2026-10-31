"""Politique de risque par classe d'expert (niveau 3).

Le niveau 2 (`aisec/core/control.py`) classe une commande par risque a partir
de l'outil et de ses arguments. Le niveau 3 affine cette politique **par
classe** : certaines classes (exploitation, post-exploitation, wireless) sont
plus sensibles que d'autres et exigent davantage de prudence.

La politique par classe ne remplace pas le niveau 2, elle le **durcit** :

  - `max_auto_risk` : plafond de risque auto-approuve pour la classe. S'il est
    plus bas que le plafond global, il l'emporte (on ne fait jamais moins
    prudent que la politique globale).
  - `require_confirmation` : la classe exige toujours une confirmation, meme
    pour un risque faible (ex. une commande d'exploitation).
  - `deny_private_targets` : refuser les cibles privees/internes pour la classe.

`policy_for(config, expert_name)` combine la politique globale (niveau 2) et
la politique par classe (niveau 3) : le resultat est la politique **la plus
stricte** des deux.
"""

from __future__ import annotations

from dataclasses import dataclass

from .control import ControlPolicy, Risk


@dataclass(frozen=True)
class ClassPolicy:
    """Regles de controle specifiques a une classe d'experts."""

    # Plafond de risque auto-approuve pour la classe (None = politique globale).
    max_auto_risk: Risk | None = None
    # Toujours demander confirmation, meme pour un risque faible.
    require_confirmation: bool = False
    # Refuser les cibles privees/internes (None = politique globale).
    deny_private_targets: bool | None = None
    # Justification lisible (affichee dans les motifs de decision).
    reason: str = ""


# Politique par defaut, indexee par nom d'expert.
#
# On ne liste que les classes qui exigent une attention particuliere. Les
# classes absentes heritent de la politique globale (niveau 2) sans durcissement.
DEFAULT_CLASS_POLICIES: dict[str, ClassPolicy] = {
    # Offensif direct : ne part jamais sans confirmation explicite.
    "exploitation": ClassPolicy(
        max_auto_risk=Risk.LOW,
        require_confirmation=True,
        reason="classe offensive (exploitation)",
    ),
    "post-exploit": ClassPolicy(
        max_auto_risk=Risk.LOW,
        require_confirmation=True,
        reason="classe offensive (post-exploitation)",
    ),
    "wireless": ClassPolicy(
        max_auto_risk=Risk.MEDIUM,
        require_confirmation=True,
        reason="classe offensive (sans fil)",
    ),
    "passwords": ClassPolicy(
        max_auto_risk=Risk.LOW,
        require_confirmation=True,
        reason="classe sensible (attaques de mots de passe)",
    ),
    "vulnerability": ClassPolicy(
        max_auto_risk=Risk.MEDIUM,
        reason="classe active (analyse de vulnerabilites)",
    ),
    "webapp": ClassPolicy(
        max_auto_risk=Risk.MEDIUM,
        reason="classe active (analyse d'application web)",
    ),
    "ai": ClassPolicy(
        max_auto_risk=Risk.MEDIUM,
        reason="classe sensible (outils d'IA offensive)",
    ),
    # Reconnaissance / lecture (info, dns, forensics, reverse, reporting,
    # sniffing, automotive) : pas de durcissement, elles heritent de la
    # politique globale (niveau 2).
}


def policy_for(
    config,
    expert_name: str | None = None,
    *,
    class_policies: dict[str, ClassPolicy] | None = None,
) -> ControlPolicy:
    """Combine la politique globale (niveau 2) et la politique de classe (niveau 3).

    Renvoie la politique la **plus stricte** des deux : on ne relache jamais une
    borne fixee au niveau global.
    """
    global_policy = ControlPolicy(
        max_auto_risk=Risk.parse(config.auto_approve_risk),
        max_targets=config.max_targets,
        deny_private_targets=config.deny_private_targets,
    )

    policies = class_policies
    if policies is None:
        builder = getattr(config, "class_policies", None)
        policies = builder() if callable(builder) else DEFAULT_CLASS_POLICIES
    if not expert_name or expert_name not in policies:
        return global_policy

    return apply_class_policy(global_policy, policies[expert_name])


def apply_class_policy(global_policy: ControlPolicy, class_policy: ClassPolicy) -> ControlPolicy:
    """Durcit une politique globale avec une politique de classe."""
    max_auto = global_policy.max_auto_risk
    if class_policy.max_auto_risk is not None:
        max_auto = min(max_auto, class_policy.max_auto_risk)

    deny_private = global_policy.deny_private_targets
    if class_policy.deny_private_targets is not None:
        deny_private = deny_private or class_policy.deny_private_targets

    return ControlPolicy(
        max_auto_risk=max_auto,
        allowed_tools=set(global_policy.allowed_tools),
        denied_tools=set(global_policy.denied_tools),
        max_targets=global_policy.max_targets,
        deny_private_targets=deny_private,
        require_confirmation=(
            global_policy.require_confirmation or class_policy.require_confirmation
        ),
    )


@dataclass
class ClassPolicyOverride:
    """Surcharge partielle d'une politique de classe (config utilisateur)."""

    max_auto_risk: str | None = None
    require_confirmation: bool | None = None
    deny_private_targets: bool | None = None

    def merged(self, base: ClassPolicy) -> ClassPolicy:
        risk = (
            Risk.parse(self.max_auto_risk)
            if self.max_auto_risk is not None
            else base.max_auto_risk
        )
        return ClassPolicy(
            max_auto_risk=risk,
            require_confirmation=(
                base.require_confirmation
                if self.require_confirmation is None
                else self.require_confirmation
            ),
            deny_private_targets=(
                base.deny_private_targets
                if self.deny_private_targets is None
                else self.deny_private_targets
            ),
            reason=base.reason,
        )


def parse_class_policies(raw: dict | None) -> dict[str, ClassPolicy]:
    """Construit les politiques de classe a partir de la config (`[expert_policies]`).

    Les entrees absentes gardent la politique par defaut ; les entrees presentes
    la surchargent partiellement.
    """
    policies = dict(DEFAULT_CLASS_POLICIES)
    if not raw:
        return policies
    for name, values in raw.items():
        if not isinstance(values, dict):
            continue
        base = policies.get(name, ClassPolicy())
        override = ClassPolicyOverride(
            max_auto_risk=values.get("max_auto_risk"),
            require_confirmation=values.get("require_confirmation"),
            deny_private_targets=values.get("deny_private_targets"),
        )
        policies[name] = override.merged(base)
    return policies


__all__ = [
    "ClassPolicy",
    "DEFAULT_CLASS_POLICIES",
    "policy_for",
    "apply_class_policy",
    "parse_class_policies",
]
