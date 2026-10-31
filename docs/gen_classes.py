#!/usr/bin/env python3
"""Genere docs/CLASSES.md et docs/classes.json depuis le catalogue Parrot.

Repartit les 445 outils en classes (taxonomie Parrot) pour confier une classe
a un agent. Relancer apres une mise a jour du catalogue:

    python docs/gen_classes.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from aisec.catalog import get_catalog

DOCS = Path(__file__).parent


def build() -> tuple[dict, str]:
    catalog = get_catalog()
    by_label: dict[str, list] = defaultdict(list)
    for tool in catalog.tools:
        by_label[tool.category].append(tool)

    roots = sorted(
        [
            c
            for c in catalog.categories
            if c.get("parentId") is None and c["id"][:2].isdigit()
        ],
        key=lambda c: c.get("order", 999),
    )

    classes: list[dict] = []
    md = [
        "# Classes d'outils Parrot (assignables par agent)",
        "",
        f"Source: {catalog.source} — {len(catalog.tools)} outils, {len(roots)} classes.",
        "",
        "Chaque classe peut etre confiee a un agent : il implemente un `Expert`",
        "(prompt dedie + outils + routage + analyse) pour cette classe.",
        "",
    ]
    covered: set[str] = set()

    for root in roots:
        subs = sorted(
            [c for c in catalog.categories if c.get("parentId") == root["id"]],
            key=lambda c: c.get("order", 999),
        )
        groups: list[dict] = []
        seen: set[str] = set()

        if by_label.get(root["label"]):
            names = sorted({t.name for t in by_label[root["label"]]})
            groups.append({"id": root["id"], "label": root["label"] + " (direct)", "tools": names})
            seen.update(names)
        for sub in subs:
            names = sorted({t.name for t in by_label.get(sub["label"], [])} - seen)
            if names:
                groups.append({"id": sub["id"], "label": sub["label"], "tools": names})
                seen.update(names)

        covered.update(seen)
        classes.append(
            {
                "class_id": root["id"],
                "class": root["label"],
                "tool_count": len(seen),
                "subcategories": groups,
            }
        )
        md += [f"## {root['label']}  — {len(seen)} outils  (`{root['id']}`)", ""]
        for group in groups:
            listed = ", ".join(f"`{n}`" for n in group["tools"])
            md.append(f"- **{group['label']}** ({len(group['tools'])}) : {listed}")
        md.append("")

    rest: dict[str, list[str]] = defaultdict(list)
    for tool in catalog.tools:
        if tool.name not in covered:
            rest[tool.category].append(tool.name)
    if rest:
        total = sum(len(v) for v in rest.values())
        classes.append(
            {
                "class_id": "misc",
                "class": "Autres (System Services / Utility / ...)",
                "tool_count": total,
                "subcategories": [
                    {"id": "misc", "label": k, "tools": sorted(v)} for k, v in sorted(rest.items())
                ],
            }
        )
        md += [f"## Autres (System Services / Utility / ...)  — {total} outils  (`misc`)", ""]
        for key in sorted(rest):
            listed = ", ".join(f"`{n}`" for n in sorted(rest[key]))
            md.append(f"- **{key}** ({len(rest[key])}) : {listed}")
        md.append("")

    payload = {
        "source": catalog.source,
        "total_tools": len(catalog.tools),
        "classes": classes,
    }
    return payload, "\n".join(md) + "\n"


def main() -> None:
    payload, markdown = build()
    (DOCS / "classes.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (DOCS / "CLASSES.md").write_text(markdown, encoding="utf-8")
    covered = sum(c["tool_count"] for c in payload["classes"])
    print(f"{len(payload['classes'])} classes, {covered}/{payload['total_tools']} outils couverts")


if __name__ == "__main__":
    main()
