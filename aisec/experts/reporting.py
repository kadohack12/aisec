"""Expert Reporting Tools (classe `12-reporting`).

Couvre les plateformes de reporting (dradis, faraday), la capture d'ecran et
l'inventaire de services web (eyewitness) et la base de graphes neo4j. Classe
utilisee en fin d'audit pour consolider et presenter les resultats.
"""

from __future__ import annotations

from .base import Expert

REPORTING_EXPERT = Expert(
    name="reporting",
    description="Reporting d'audit: plateformes collaboratives, captures web, graphe de relations.",
    system_prompt=(
        "Tu es un expert en reporting de test d'intrusion. Tu choisis l'outil le "
        "plus adapte parmi ceux de ton domaine et tu extrais les parametres exacts. "
        "Pour centraliser et rediger les resultats d'un audit, utilise dradis. Pour "
        "gerer les vulnerabilites et la collaboration, utilise faraday. Pour prendre "
        "des captures d'ecran et inventorier des services web, utilise eyewitness. "
        "Pour stocker les relations entre cibles et constats sous forme de graphe, "
        "utilise neo4j."
    ),
    tool_names=["dradis", "faraday", "eyewitness", "neo4j"],
    routing_rules=(
        ("eyewitness", ("capture d'ecran", "screenshot", "inventaire web", "eyewitness", "captures")),
        ("faraday", ("faraday", "gestion de vulnerabilites", "collaboration")),
        ("dradis", ("dradis", "rapport", "reporting", "rediger", "consolider")),
        ("neo4j", ("neo4j", "graphe", "graph", "relations")),
    ),
    keywords=(
        "reporting",
        "rapport",
        "rapports",
        "report",
        "rediger",
        "consolider",
        "dradis",
        "faraday",
        "eyewitness",
        "capture d'ecran",
        "screenshot",
        "neo4j",
        "graphe",
        "graph",
        "synthese",
    ),
)
