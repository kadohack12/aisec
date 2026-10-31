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
    from ..tools import slowhttptest as _slowhttptest  # noqa: F401
    from ..tools import testssl as _testssl  # noqa: F401
    # Classe 3 - Web Application Analysis
    from ..tools import ffuf as _ffuf  # noqa: F401
    from ..tools import gobuster as _gobuster  # noqa: F401
    from ..tools import nikto as _nikto  # noqa: F401
    from ..tools import whatweb as _whatweb  # noqa: F401
    # Classe 5 - Password Attacks
    from ..tools import cewl as _cewl  # noqa: F401
    from ..tools import hashid as _hashid  # noqa: F401
    from ..tools import hydra as _hydra  # noqa: F401
    from ..tools import john as _john  # noqa: F401
    # Classe 9 - Sniffing & Spoofing
    from ..tools import bettercap as _bettercap  # noqa: F401


_load_builtins()
