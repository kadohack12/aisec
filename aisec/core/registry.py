"""Registre des outils (plugins).

Ajouter un nouvel outil = creer un module dans aisec/tools qui expose une
instance de `Tool` et l'enregistrer ici (ou via le decorateur `register`).
"""

from __future__ import annotations

from ..tools.base import Tool

_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    _REGISTRY[tool.name] = tool
    for alias in tool.aliases:
        _REGISTRY.setdefault(alias, tool)
    return tool


def get(name: str) -> Tool:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"outil inconnu '{name}'. Disponibles: {', '.join(sorted(all_names()))}"
        ) from None


def all_names() -> list[str]:
    return sorted(_REGISTRY)


def all_tools() -> list[Tool]:
    seen: dict[int, Tool] = {}
    for tool in _REGISTRY.values():
        seen[id(tool)] = tool
    return list(seen.values())


def _load_builtins() -> None:
    # Importe les modules pour declencher leur enregistrement.
    from ..tools import dns as _dns  # noqa: F401
    from ..tools import nmap as _nmap  # noqa: F401
    from ..tools import tshark as _tshark  # noqa: F401
    # Classe 1 - Information Gathering
    from ..tools import arp_scan as _arp_scan  # noqa: F401
    from ..tools import dnsrecon as _dnsrecon  # noqa: F401
    from ..tools import masscan as _masscan  # noqa: F401
    from ..tools import sslscan as _sslscan  # noqa: F401
    from ..tools import wafw00f as _wafw00f  # noqa: F401
    # Classe 2 - Vulnerability Analysis
    from ..tools import vuln_cisco as _vuln_cisco  # noqa: F401
    from ..tools import vuln_fuzz as _vuln_fuzz  # noqa: F401
    from ..tools import vuln_scan as _vuln_scan  # noqa: F401
    from ..tools import vuln_stress as _vuln_stress  # noqa: F401
    from ..tools import vuln_voip as _vuln_voip  # noqa: F401
    # Classe 3 - Web Application Analysis
    from ..tools import webapp as _webapp  # noqa: F401
    # Classe 5 - Password Attacks
    from ..tools import passwords as _passwords  # noqa: F401
    # Classe 9 - Sniffing & Spoofing
    from ..tools import bettercap as _bettercap  # noqa: F401


_load_builtins()
