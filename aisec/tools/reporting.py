"""Outils de reporting (classe `12-reporting`).

Couvre les plateformes de gestion de rapports de pentest (dradis, faraday),
la prise de captures d'ecran web (eyewitness) et la base de graphes neo4j.
Chaque outil est un plugin `SpecTool`.
"""

from __future__ import annotations

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, Rule, SpecTool


class DradisTool(SpecTool):
    name = "dradis"
    binary = "dradis"
    risk = "low"
    description = "Plateforme collaborative de reporting de test d'intrusion (Dradis)."
    examples = ("lance le serveur dradis pour centraliser les resultats",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (-p)", "int"),
        ParameterSpec("host", "Adresse d'ecoute (-b)", "string"),
    )
    options = (Option("port", "-p"), Option("host", "-b"))
    patterns = (
        Pattern(r"listening|started|Puma", "Serveur Dradis demarre", "info"),
        Pattern(r"error|failed", "Echec de demarrage", "low"),
    )


class FaradayTool(SpecTool):
    name = "faraday"
    binary = "faraday"
    risk = "low"
    description = "Plateforme de gestion de vulnerabilites et de collaboration (Faraday)."
    examples = ("lance le serveur faraday sur le port 5985",)
    parameters = (
        ParameterSpec("mode", "Mode: start, stop, status", "string", default="start"),
        ParameterSpec("port", "Port d'ecoute (-p)", "int"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("mode"),)
    rules = (
        Rule("mode", ("demarre", "start", "lance"), "start"),
        Rule("mode", ("arrete", "stop"), "stop"),
        Rule("mode", ("statut", "status"), "status"),
    )
    patterns = (
        Pattern(r"running|started", "Serveur Faraday actif", "info"),
        Pattern(r"error|failed", "Echec de demarrage", "low"),
    )


class EyewitnessTool(SpecTool):
    name = "eyewitness"
    binary = "eyewitness"
    risk = "medium"
    description = "Capture d'ecran et inventaire de services web (EyeWitness)."
    examples = (
        "prends des captures des services web depuis un fichier de cibles avec eyewitness",
        "eyewitness sur le fichier urls.txt",
    )
    parameters = (
        ParameterSpec("targets", "Fichier de cibles (-f) ou URL unique", "string", required=True),
        ParameterSpec("output", "Dossier de sortie (-d)", "string"),
        ParameterSpec("timeout", "Timeout par cible (--timeout)", "int"),
        ParameterSpec("no_dns", "Ne pas resoudre le DNS (--no-dns)", "bool", default=False),
        ParameterSpec("web", "Analyser les services web (--web)", "bool", default=False),
    )
    options = (Option("targets", "-f"), Option("output", "-d"), Option("timeout", "--timeout"))
    flags = (Flag("no_dns", "--no-dns"), Flag("web", "--web"))
    patterns = (
        Pattern(r"Saved|screenshot", "Capture d'ecran enregistree", "info"),
        Pattern(r"error|failed", "Echec de capture", "low"),
    )


class Neo4jTool(SpecTool):
    name = "neo4j"
    binary = "neo4j"
    risk = "low"
    description = "Base de donnees graphe (stockage des relations d'un audit)."
    examples = ("demarre le serveur neo4j",)
    parameters = (
        ParameterSpec("action", "Action: start, stop, status, console", "string", default="start"),
        ParameterSpec("config", "Fichier de configuration", "string"),
    )
    positionals = (Positional("action"),)
    rules = (
        Rule("action", ("demarre", "start", "lance"), "start"),
        Rule("action", ("arrete", "stop"), "stop"),
        Rule("action", ("statut", "status"), "status"),
    )
    patterns = (
        Pattern(r"Started|running", "Serveur Neo4j actif", "info"),
        Pattern(r"error|failed", "Echec de demarrage", "low"),
    )


for _tool in (
    DradisTool(),
    FaradayTool(),
    EyewitnessTool(),
    Neo4jTool(),
):
    register(_tool)
