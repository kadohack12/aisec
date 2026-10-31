"""Garde-fous avant execution d'une commande.

aisec genere des commandes a partir de langage naturel: on valide donc
systematiquement le resultat avant de lancer quoi que ce soit.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Caracteres qui n'ont aucune raison d'apparaitre dans un argument d'outil
# et qui trahissent une tentative d'injection shell.
_SUSPICIOUS = re.compile(r"[;&|`$><\n\r\\]")

# Un CIDR plus large que /16 est presque toujours une erreur ou un abus.
_MAX_PREFIX_LEN = 16

_HOSTLIKE = re.compile(r"^[A-Za-z0-9._:\-\[\]/]+$")


@dataclass
class SafetyReport:
    ok: bool
    errors: list[str]
    warnings: list[str]

    def __bool__(self) -> bool:  # permet `if report:`
        return self.ok


def validate_argv(argv: list[str], allowed_binary: str) -> SafetyReport:
    """Verifie qu'un argv est sur a executer sans shell."""
    errors: list[str] = []
    warnings: list[str] = []

    if not argv:
        errors.append("argv vide")
        return SafetyReport(False, errors, warnings)

    if argv[0] != allowed_binary:
        errors.append(
            f"binaire inattendu '{argv[0]}' (attendu '{allowed_binary}')"
        )

    for arg in argv[1:]:
        if _SUSPICIOUS.search(arg):
            errors.append(f"argument suspect (metacaractere shell): {arg!r}")

    return SafetyReport(not errors, errors, warnings)


def validate_target(target: str, allow_private: bool = True) -> SafetyReport:
    """Verifie qu'une cible (IP, CIDR, hostname) est acceptable."""
    errors: list[str] = []
    warnings: list[str] = []

    if not target or not _HOSTLIKE.match(target):
        errors.append(f"cible invalide: {target!r}")
        return SafetyReport(False, errors, warnings)

    # CIDR trop large ?
    if "/" in target:
        base, _, prefix = target.partition("/")
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            errors.append(f"CIDR invalide: {target!r}")
            return SafetyReport(False, errors, warnings)
        if net.prefixlen < _MAX_PREFIX_LEN:
            errors.append(
                f"plage trop large ({net.prefixlen} < {_MAX_PREFIX_LEN}): "
                f"{target!r} - scan potentiellement abusif"
            )
        base_ip = ipaddress.ip_address(base)
        if base_ip.is_private or base_ip.is_loopback or base_ip.is_link_local:
            warnings.append(f"cible privee/interne: {target!r}")
        return SafetyReport(not errors, errors, warnings)

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # hostname: rien de plus a verifier ici.
        return SafetyReport(True, errors, warnings)

    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        errors.append(f"adresse non routable/abusive: {target!r}")
    elif ip.is_private or ip.is_loopback or ip.is_link_local:
        warnings.append(f"cible privee/interne: {target!r}")

    return SafetyReport(not errors, errors, warnings)


def scan_guardrails(targets: list[str]) -> SafetyReport:
    """Agrege les verifications pour une liste de cibles."""
    errors: list[str] = []
    warnings: list[str] = []
    if not targets:
        errors.append("aucune cible fournie")
    for target in targets:
        report = validate_target(target)
        errors.extend(report.errors)
        warnings.extend(report.warnings)
    return SafetyReport(not errors, errors, warnings)
