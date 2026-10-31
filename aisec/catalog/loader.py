"""Chargement du catalogue d'outils.

Source: https://tools.parrotsec.org/tools.json (445 outils, taxonomie Parrot).
Le catalogue sert de base de connaissance: recherche, filtre par classe, et
detection des outils reellement installes sur la machine.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "parrot_tools.json"

# Un lanceur est un nom de binaire s'il ressemble a un seul token de commande.
_BIN_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")


@dataclass
class CatalogTool:
    name: str
    package: str
    description: str
    category: str  # label lisible, ex: "DNS Analysis"
    primary_category: str  # id technique, ex: "01-01-dns-analysis"
    categories: list[str] = field(default_factory=list)
    launchers: list[str] = field(default_factory=list)
    dependencies: str = ""
    version: str = ""

    @property
    def binaries(self) -> list[str]:
        """Noms de binaires plausibles (les libelles de menu sont ecartes)."""
        real = [b for b in self.launchers if _BIN_RE.match(b)]
        if not real:
            return [self.name]
        return real

    @property
    def installed(self) -> bool:
        return any(shutil.which(b) for b in self.binaries)

    def binary_path(self) -> str | None:
        for b in self.binaries:
            path = shutil.which(b)
            if path:
                return path
        return None


@dataclass
class Catalog:
    tools: list[CatalogTool]
    categories: list[dict]
    source: str = "https://tools.parrotsec.org/tools.json"

    def by_name(self, name: str) -> CatalogTool | None:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None

    def by_category_id(self, category_id: str) -> list[CatalogTool]:
        return [
            t
            for t in self.tools
            if category_id in t.categories or t.primary_category == category_id
        ]

    def by_category_label(self, label: str) -> list[CatalogTool]:
        low = label.lower()
        return [t for t in self.tools if low in t.category.lower()]

    def search(self, query: str) -> list[CatalogTool]:
        q = query.lower().strip()
        if not q:
            return []
        hits = []
        for tool in self.tools:
            haystack = f"{tool.name} {tool.package} {tool.category} {tool.description}".lower()
            if q in haystack:
                hits.append(tool)
        return hits

    def installed(self) -> list[CatalogTool]:
        return [t for t in self.tools if t.installed]

    def root_categories(self) -> list[dict]:
        return [c for c in self.categories if "parentId" not in c]

    def category_label(self, category_id: str) -> str:
        for c in self.categories:
            if c["id"] == category_id:
                return c["label"]
        return category_id

    def root_category_id(self, category_id: str) -> str:
        index = {c["id"]: c for c in self.categories}
        seen = set()
        while category_id in index and index[category_id].get("parentId") and category_id not in seen:
            seen.add(category_id)
            category_id = index[category_id]["parentId"]
        return category_id


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    with _DATA.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    tools = [
        CatalogTool(
            name=t.get("name", ""),
            package=t.get("packageName", t.get("name", "")),
            description=(t.get("description") or "").strip(),
            category=t.get("category", "") or "Uncategorized",
            primary_category=t.get("primaryCategory", ""),
            categories=list(t.get("categories", []) or []),
            launchers=list(t.get("launchers", []) or []),
            dependencies=t.get("dependencies", ""),
            version=t.get("version", ""),
        )
        for t in raw.get("tools", [])
    ]
    return Catalog(tools=tools, categories=raw.get("categories", []), source=raw.get("source", ""))
