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
    from ..tools import exploitation as _exploitation  # noqa: F401
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
    from ..tools import web_crawl as _web_crawl  # noqa: F401
    from ..tools import web_misc as _web_misc  # noqa: F401
    from ..tools import web_vuln as _web_vuln  # noqa: F401
    # Classe 5 - Password Attacks
    from ..tools import passwords as _passwords  # noqa: F401
    # Classe 9 - Sniffing & Spoofing
    from ..tools import bettercap as _bettercap  # noqa: F401
    # Classe 8 - Post Exploitation
    from ..tools import post_exploit as _post_exploit  # noqa: F401
    # Classe 12 - Reporting Tools
    from ..tools import reporting as _reporting  # noqa: F401
    # Classe 11 - Digital Forensics
    from ..tools import binwalk as _binwalk  # noqa: F401
    from ..tools import bulk_extractor as _bulk_extractor  # noqa: F401
    from ..tools import extundelete as _extundelete  # noqa: F401
    from ..tools import foremost as _foremost  # noqa: F401
    from ..tools import imaging as _imaging  # noqa: F401
    from ..tools import integrity as _integrity  # noqa: F401
    from ..tools import pdf_forensics as _pdf_forensics  # noqa: F401
    from ..tools import scalpel as _scalpel  # noqa: F401
    from ..tools import sleuthkit as _sleuthkit  # noqa: F401
    from ..tools import volatility as _volatility  # noqa: F401
    from ..tools import windows_artifacts as _windows_artifacts  # noqa: F401
    from ..tools import yara as _yara  # noqa: F401
    # Classe 07 - Reverse Engineering
    from ..tools import android as _android  # noqa: F401
    from ..tools import die as _die  # noqa: F401
    from ..tools import gdb as _gdb  # noqa: F401
    from ..tools import radare2 as _radare2  # noqa: F401
    from ..tools import rizin as _rizin  # noqa: F401
    # Classe 06 - Wireless Testing
    from ..tools import wireless as _wireless  # noqa: F401
    # Classe 13 - Automotive
    from ..tools import automotive as _automotive  # noqa: F401
    # Classe 14 - AI Tools
    from ..tools import ai_tools as _ai_tools  # noqa: F401
    # Classe 15 - Autres (System Services / Utility / ...)
    from ..tools import misc as _misc  # noqa: F401


_load_builtins()
