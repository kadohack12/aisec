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


_load_builtins()
