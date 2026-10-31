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
    # Classe 07 - Reverse Engineering
    from ..tools import android as _android  # noqa: F401
    from ..tools import die as _die  # noqa: F401
    from ..tools import gdb as _gdb  # noqa: F401
    from ..tools import radare2 as _radare2  # noqa: F401
    from ..tools import rizin as _rizin  # noqa: F401


_load_builtins()
