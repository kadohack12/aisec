"""Expert AI Tools (classe 14-ai-tools).

Les outils d'IA offensive: orchestration de securite par MCP (hexstrike-ai,
mcpwn), agents de codage en terminal (opencode, pi-dev) et entrainement de
modeles (unsloth).
"""

from __future__ import annotations

from .base import Expert

AI_EXPERT = Expert(
    name="ai",
    description="Outils d'IA offensive: orchestration MCP, agents de codage, entrainement de modeles.",
    system_prompt=(
        "Tu es un expert des outils d'IA appliques a la securite. Tu choisis "
        "l'outil le plus adapte parmi hexstrike-ai, mcpwn, opencode, pi-dev et "
        "unsloth, puis tu extrais les parametres exacts. Ces binaires pilotent "
        "d'autres outils ou executent du code: un serveur MCP ne doit pas etre "
        "expose sur toutes les interfaces (0.0.0.0) et un agent de codage ne doit "
        "pas executer de commande destructrice sans validation."
    ),
    tool_names=["hexstrike-ai", "mcpwn", "opencode", "pi-dev", "unsloth"],
    routing_rules=(
        ("mcpwn", ("mcpwn",)),
        ("hexstrike-ai", ("hexstrike", "orchestration mcp", "plateforme mcp")),
        ("opencode", ("opencode",)),
        ("pi-dev", ("pi-dev", "agent pi", "harnais pi")),
        ("unsloth", ("unsloth", "entraine un modele", "fine-tune", "fine tune", "fine-tuning")),
    ),
    keywords=(
        "hexstrike",
        "mcpwn",
        "mcp",
        "opencode",
        "pi-dev",
        "unsloth",
        "agent de codage",
        "agent ia",
        "orchestration",
        "fine-tuning",
        "entrainement de modele",
        "llm",
        "modele de langage",
    ),
)
