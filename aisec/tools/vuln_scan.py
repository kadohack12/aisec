"""Outils d'analyse de vulnerabilites (classe 02, sous-categorie directe).

Couvre: afl++ (fuzzing), defectdojo, honeypots, peass, bandit (SAST), sentrypeer,
testssl.sh, tnscmd10g, unix-privesc-check.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class AflTool(SpecTool):
    name = "afl++"
    aliases = ("afl",)
    binary = "afl-fuzz"
    risk = "high"
    description = "Fuzzer guide par couverture (AFL++): cherche des crashs dans un binaire."
    examples = (
        "fuzz le binaire ./parser avec les entrees du dossier seeds et ecris dans findings",
    )
    parameters = (
        ParameterSpec("target", "Binaire a fuzzer", "string", required=True),
        ParameterSpec("input_dir", "Dossier des entrees (corpus, -i)", "string"),
        ParameterSpec("output_dir", "Dossier de sortie (-o)", "string"),
        ParameterSpec("dictionary", "Dictionnaire de tokens (-x)", "string"),
        ParameterSpec("memory", "Limite memoire en Mo, ou 'none' (-m)", "string"),
        ParameterSpec("timeout_ms", "Timeout par execution en ms (-t)", "int"),
        ParameterSpec("target_args", "Arguments du binaire cible (utilise '@@' pour le fichier)", "list"),
    )
    options = (
        Option("input_dir", "-i"),
        Option("output_dir", "-o"),
        Option("dictionary", "-x"),
        Option("memory", "-m"),
        Option("timeout_ms", "-t"),
    )
    rules = (
        Rule("memory", ("aucune limite", "sans limite", "no limit", "none"), "none"),
    )
    numbers = (Number("memory", r"(\d+)\s*(?:mo|mb)"),)
    patterns = (
        Pattern(r"unique crashes\s*:\s*(\d+)", "Crashs uniques: {0}", "high", "Le fuzzer a trouve des entrees qui font planter la cible."),
        Pattern(r"total crashes\s*:\s*(\d+)", "Crashs totaux: {0}", "medium"),
        Pattern(r"PROGRAM ABORT|Segmentation fault", "Crash detecte pendant le fuzzing", "high"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["afl-fuzz"]
        argv += self._options_argv(params)
        argv += self._flags_argv(params)
        argv.append("--")
        argv.append(str(params.get("target", "")))
        argv += [str(a) for a in params.get("target_args", []) or []]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        binary = re.search(r"(\./[\w./\-]+|/[\w./\-]+)", text)
        if binary:
            params["target"] = binary.group(1)
        return params


class DefectDojoTool(SpecTool):
    name = "defectdojo"
    aliases = ()
    binary = "defectdojo-stop"
    risk = "low"
    description = "Plateforme de gestion de vulnerabilites (DefectDojo): controle du service."
    examples = ("arrete le service defectdojo",)
    parameters = (
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )
    flags = (Flag("quiet", "-q"),)
    patterns = (
        Pattern(r"stopped|arret", "Service DefectDojo arrete", "info"),
        Pattern(r"error|failed", "Erreur lors de l'arret du service", "medium"),
    )


class HoneypotTool(SpecTool):
    name = "hb-honeypot"
    aliases = ()
    binary = "hb-honeypot"
    risk = "medium"
    description = "Honeypot: expose un leurre et journalise les interactions."
    examples = ("lance le honeypot sur le port 8080",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute", "int"),
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("daemon", "Detacher en arriere-plan (-d)", "bool", default=False),
    )
    options = (Option("config", "-c"),)
    flags = (Flag("daemon", "-d"),)
    rules = (Rule("port", ("port",), 8080),)
    numbers = (Number("port", r"port\s+(\d+)"),)
    patterns = (
        Pattern(r"listening on|ecoute sur", "Honeypot actif", "info"),
        Pattern(r"connection from (\S+)", "Connexion depuis {0}", "low"),
    )


class PeassTool(SpecTool):
    name = "peass"
    aliases = ()
    binary = "peass"
    risk = "medium"
    description = "PEASS (linpeas/winpeas): recherche de vecteurs d'elevation de privileges."
    examples = ("cherche les vecteurs d'elevation de privileges en mode complet",)
    parameters = (
        ParameterSpec("all", "Recherche complete (-a)", "bool", default=False),
        ParameterSpec("fast", "Mode rapide (-f)", "bool", default=False),
        ParameterSpec("output", "Fichier de rapport", "string"),
    )
    flags = (Flag("all", "-a"), Flag("fast", "-f"))
    rules = (Rule("all", ("complet", "complete", "tout", "all", "approfondi"), True),)
    patterns = (
        Pattern(r"SUID|sudo -l", "Binaires SUID / droits sudo detectes", "high", "Vecteur d'elevation de privileges potentiel."),
        Pattern(r"writable", "Fichiers/chemins inscriptibles detectes", "medium"),
        Pattern(r"password|mot de passe", "Mot de passe en clair detecte", "critical"),
    )


class BanditTool(SpecTool):
    name = "python3-bandit"
    aliases = ("bandit",)
    binary = "bandit"
    risk = "low"
    description = "Analyse statique (SAST) de code Python: cherche des failles de securite."
    examples = ("analyse le dossier ./src en recursif au format json",)
    parameters = (
        ParameterSpec("target", "Chemin a analyser", "string", required=True),
        ParameterSpec("recursive", "Analyse recursive (-r)", "bool", default=False),
        ParameterSpec("format", "Format de sortie (-f): txt, json, csv, html", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("severity", "Niveau minimal (-ll, -lll)", "string"),
    )
    options = (Option("format", "-f"), Option("output", "-o"))
    flags = (Flag("recursive", "-r"),)
    positionals = (Positional("target"),)
    rules = (Rule("recursive", ("recursif", "recursive", "dossier", "repertoire"), True),)
    patterns = (
        Pattern(r"Severity:\s*High", "Vulnerabilite de severite haute detectee", "high"),
        Pattern(r"Severity:\s*Medium", "Vulnerabilite de severite moyenne detectee", "medium"),
        Pattern(r"Issue:\s*\[([^\]]+)\]", "Probleme detecte: {0}", "low"),
        Pattern(r"Total lines of code", "Analyse terminee", "info"),
    )


class SentrypeerTool(SpecTool):
    name = "sentrypeer"
    aliases = ()
    binary = "sentrypeer"
    risk = "medium"
    description = "Honeypot SIP: detecte les tentatives de fraude et d'enumeration VoIP."
    examples = ("lance sentrypeer sur l'interface eth0",)
    parameters = (
        ParameterSpec("interface", "Interface reseau (-i)", "string"),
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("interface", "-i"), Option("config", "-c"))
    flags = (Flag("verbose", "-v"),)
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"fraud|fraude", "Tentative de fraude detectee", "high"),
        Pattern(r"scanner|scan", "Enumeration VoIP detectee", "medium"),
    )


class TestsslTool(SpecTool):
    name = "testssl.sh"
    aliases = ("testssl",)
    binary = "testssl"
    risk = "medium"
    description = "Audit TLS/SSL complet d'un service (protocoles, chiffrements, vulnerabilites)."
    examples = ("audite le tls de example.com:443 et liste les vulnerabilites",)
    parameters = (
        ParameterSpec("target", "Hote (ou host:port)", "string", required=True),
        ParameterSpec("port", "Port (ajoute a la cible)", "string"),
        ParameterSpec("protocols", "Tester les protocoles (--protocols)", "bool", default=False),
        ParameterSpec("vulnerabilities", "Tester les vulnerabilites connues", "bool", default=False),
        ParameterSpec("headers", "Tester les en-tetes de securite", "bool", default=False),
        ParameterSpec("json_output", "Fichier de sortie JSON (--jsonfile)", "string"),
        ParameterSpec("quiet", "Mode silencieux (--quiet)", "bool", default=False),
    )
    options = (Option("json_output", "--jsonfile"),)
    target_params = ("target",)
    flags = (
        Flag("protocols", "--protocols"),
        Flag("vulnerabilities", "--vulnerabilities"),
        Flag("headers", "--headers"),
        Flag("quiet", "--quiet"),
    )
    rules = (
        Rule("protocols", ("protocole", "protocol", "tls", "ssl"), True),
        Rule("vulnerabilities", ("vulnerabilite", "vulnerability", "cve", "faiblesse"), True),
        Rule("headers", ("en-tete", "entete", "header", "hsts"), True),
    )
    patterns = (
        Pattern(r"(HEARTBLEED|CCS|ROBOT|TICKETBLEED)\s+.*?(VULNERABLE|not vulnerable)", "{0}: {1}", "high"),
        Pattern(r"SSLv2|SSLv3", "Protocole obsolete supporte", "high", "SSLv2/SSLv3 sont casses."),
        Pattern(r"TLS\s*1\.0|TLS\s*1\.1", "Protocole TLS obsolete supporte", "medium"),
        Pattern(r"certificate.*expired|expired", "Certificat expire", "high"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["testssl"]
        argv += self._flags_argv(params)
        argv += self._options_argv(params)
        target = str(params["target"])
        if params.get("port"):
            target = f"{target}:{params['port']}"
        argv.append(target)
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        port = re.search(r"(?:port\s+|:)(\d{2,5})", text.lower())
        if port:
            params["port"] = port.group(1)
        return params


class TnscmdTool(SpecTool):
    name = "tnscmd10g"
    aliases = ()
    binary = "tnscmd10g"
    risk = "medium"
    description = "Interroge un listener Oracle TNS (version, statut, services)."
    examples = ("recupere la version du listener oracle sur db.local port 1521",)
    parameters = (
        ParameterSpec("command", "Commande: status, ping, version, services", "string", default="status"),
        ParameterSpec("host", "Hote du listener (-h)", "string"),
        ParameterSpec("port", "Port du listener (-p)", "string"),
    )
    options = (Option("host", "-h"), Option("port", "-p"))
    positionals = (Positional("command"),)
    rules = (
        Rule("command", ("version", "versions"), "version"),
        Rule("command", ("statut", "status", "etat"), "status"),
        Rule("command", ("ping", "vivant", "alive"), "ping"),
        Rule("command", ("service", "services"), "services"),
    )
    patterns = (
        Pattern(r"TNSLSNR|Version\s+([\d.]+)", "Listener Oracle TNS detecte", "info"),
        Pattern(r"no listener|refused|timed out", "Listener injoignable", "low"),
        Pattern(r"DESCRIPTION|SERVICE_NAME", "Services Oracle exposes", "medium", "L'information peut faciliter des attaques sur la base."),
    )


class UnixPrivescCheckTool(SpecTool):
    name = "unix-privesc-check"
    aliases = ()
    binary = "unix-privesc-check"
    risk = "low"
    description = "Audit local Unix: chercher des erreurs de configuration permettant l'escalade."
    examples = ("lance un audit detaille des privileges locaux",)
    parameters = (
        ParameterSpec("mode", "Mode: standard ou detailed", "string", default="standard"),
        ParameterSpec("verbose", "Verbeux (--verbose)", "bool", default=False),
    )
    flags = (Flag("verbose", "--verbose"),)
    positionals = (Positional("mode"),)
    rules = (Rule("mode", ("detail", "detaille", "detailed", "complet"), "detailed"),)
    patterns = (
        Pattern(r"WARNING", "Avertissement de configuration", "medium"),
        Pattern(r"SUID|sgid", "Binaire SUID/SGID detecte", "high"),
        Pattern(r"world[- ]writable|inscriptible", "Fichier accessible en ecriture", "medium"),
    )


for _tool in (
    AflTool(),
    DefectDojoTool(),
    HoneypotTool(),
    PeassTool(),
    BanditTool(),
    SentrypeerTool(),
    TestsslTool(),
    TnscmdTool(),
    UnixPrivescCheckTool(),
):
    register(_tool)
