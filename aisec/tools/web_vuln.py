"""Scanners de vulnerabilites web (classe 03, sous-categorie Web Vulnerability Scanners).

Couvre: cadaver, davtest, heartleech, jboss-autopwn, jsql-injection, nikto,
owasp-mantra-ff, padbuster, wapiti, watobo, websploit, whatweb, xsser.
"""

from __future__ import annotations

from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, Rule, SpecTool


class CadaverTool(SpecTool):
    name = "cadaver"
    aliases = ()
    binary = "cadaver"
    risk = "medium"
    description = "Client WebDAV en ligne de commande (navigation, depot de fichiers)."
    examples = ("liste le contenu webdav de http://target/dav",)
    parameters = (
        ParameterSpec("url", "URL WebDAV", "string", required=True),
        ParameterSpec("quiet", "Mode non interactif (-t)", "bool", default=False),
    )
    flags = (Flag("quiet", "-t"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"dav://|http://", "Serveur WebDAV joignable", "info"),
        Pattern(r"Could not|failed|401|403", "Acces refuse ou erreur", "low"),
    )


class DavtestTool(SpecTool):
    name = "davtest"
    aliases = ()
    binary = "davtest"
    risk = "high"
    description = "Teste un serveur WebDAV: types de fichiers deposables et executables."
    examples = ("teste le webdav de http://target et tente le depot de fichiers",)
    parameters = (
        ParameterSpec("url", "URL WebDAV (-url)", "string", required=True),
        ParameterSpec("upload", "Dossier de televersement (-upload)", "string"),
        ParameterSpec("extensions", "Extensions a tester (-fileext)", "string"),
        ParameterSpec("random", "Noms aleatoires (-random)", "bool", default=False),
    )
    options = (Option("url", "-url"), Option("upload", "-upload"), Option("extensions", "-fileext"))
    flags = (Flag("random", "-random"),)
    url_param = "url"
    patterns = (
        Pattern(r"SUCCEED|Success", "Depot de fichier reussi", "high", "WebDAV accepte des fichiers: risque d'execution."),
        Pattern(r"FAIL", "Depot refuse", "info"),
        Pattern(r"executable", "Fichier executable deposable", "critical", "Un depot executable mene a une execution de code."),
    )


class HeartleechTool(SpecTool):
    name = "heartleech"
    aliases = ()
    binary = "heartleech"
    risk = "high"
    description = "Exploite la faille Heartbleed (CVE-2014-0160) pour extraire la memoire TLS."
    examples = ("teste la vulnerabilite heartbleed de example.com:443",)
    parameters = (
        ParameterSpec("target", "Hote cible (-host)", "string", required=True),
        ParameterSpec("port", "Port (-port)", "string", default="443"),
        ParameterSpec("output", "Fichier de sortie (-dump)", "string"),
        ParameterSpec("auto", "Mode automatique (-autopwn)", "bool", default=False),
    )
    options = (Option("target", "-host"), Option("port", "-port"), Option("output", "-dump"))
    flags = (Flag("auto", "-autopwn"),)
    patterns = (
        Pattern(r"heartbleed|vulnerable", "Cible vulnerable a Heartbleed", "critical", "Fuite de memoire serveur possible."),
        Pattern(r"not vulnerable|fixed", "Cible non vulnerable", "info"),
    )


class JbossAutopwnTool(SpecTool):
    name = "jboss-autopwn"
    aliases = ()
    binary = "jboss-autopwn"
    risk = "critical"
    description = "Exploitation automatisee de serveurs JBoss mal configures."
    examples = ("tente l exploitation de jboss sur 10.0.0.1:8080",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("port", "-p"),)
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)
    patterns = (
        Pattern(r"deployed|success|shell", "Exploitation reussie", "critical", "Execution de code a distance confirmee."),
        Pattern(r"failed|not vulnerable", "Exploitation echouee", "low"),
    )


class JsqlTool(SpecTool):
    name = "jsql-injection"
    aliases = ("jsql",)
    binary = "jsql"
    risk = "high"
    description = "Outil d'injection SQL (jSQL Injection) avec interface graphique."
    examples = ("lance jsql injection sur http://target",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("method", "Methode HTTP: GET, POST", "string"),
        ParameterSpec("data", "Donnees POST", "string"),
    )
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"injection|vulnerable", "Injection SQL possible", "critical"),
        Pattern(r"error", "Erreur de l'outil", "low"),
    )


class NiktoTool(SpecTool):
    name = "nikto"
    aliases = ()
    binary = "nikto"
    risk = "medium"
    description = "Scanner de serveur web: fichiers dangereux, versions obsoletes, mauvaises configurations."
    examples = ("scanne le serveur web example.com sur le port 443 en https",)
    parameters = (
        ParameterSpec("host", "Hote cible (-h)", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("ssl", "Forcer TLS (-ssl)", "bool", default=False),
        ParameterSpec("tuning", "Categories de tests (-Tuning)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("format", "Format de sortie (-Format): txt, html, csv, json", "string"),
        ParameterSpec("no_interactive", "Ne pas demander confirmation (-nointeractive)", "bool", default=False),
    )
    options = (Option("host", "-h"), Option("port", "-p"), Option("tuning", "-Tuning"), Option("output", "-o"), Option("format", "-Format"))
    flags = (Flag("ssl", "-ssl"), Flag("no_interactive", "-nointeractive"))
    patterns = (
        Pattern(r"^\+ (\S+):\s*(.+)", "Constat: {0}", "medium"),
        Pattern(r"OSVDB-(\d+)", "Reference OSVDB-{0}", "low"),
        Pattern(r"^\+\s*(.+)", "Constat: {0}", "low"),
        Pattern(r"Server leaks|vulnerable|outdated", "Probleme de configuration detecte", "medium"),
    )


class OwaspMantraTool(SpecTool):
    name = "owasp-mantra-ff"
    aliases = ()
    binary = "owasp-mantra-ff"
    risk = "medium"
    description = "Navigateur d'audit web (OWASP Mantra) pour tester des applications."
    examples = ("lance owasp mantra sur http://target",)
    parameters = (ParameterSpec("url", "URL a ouvrir", "string"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class PadbusterTool(SpecTool):
    name = "padbuster"
    aliases = ()
    binary = "padbuster"
    risk = "high"
    description = "Exploite le padding oracle (CBC) pour dechiffrer ou forger des cookies."
    examples = ("teste le padding oracle sur http://target avec le cookie chiffre",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("encrypted", "Valeur chiffree (base64/hex)", "string", required=True),
        ParameterSpec("blocksize", "Taille de bloc en octets", "int", default=8),
        ParameterSpec("encoding", "Encodage: 0=base64, 1=hex, 2=base64url (-encoding)", "string"),
        ParameterSpec("cookies", "Cookies (-cookies)", "string"),
        ParameterSpec("error", "Chaine d'erreur revelatrice (-error)", "string"),
    )
    options = (Option("encoding", "-encoding"), Option("cookies", "-cookies"), Option("error", "-error"))
    positionals = (Positional("url"), Positional("encrypted"), Positional("blocksize"))
    url_param = "url"
    patterns = (
        Pattern(r"Decrypted|dechiffre", "Valeur dechiffree", "critical", "Un padding oracle permet de forger des jetons."),
        Pattern(r"ERROR|failed", "Pas de padding oracle", "low"),
    )


class WapitiTool(SpecTool):
    name = "wapiti"
    aliases = ()
    binary = "wapiti"
    risk = "high"
    description = "Scanner de vulnerabilites web: injections, XSS, LFI, SSRF, fichiers."
    examples = ("scanne http://target pour les injections et les xss",)
    parameters = (
        ParameterSpec("url", "URL de base (-u)", "string", required=True),
        ParameterSpec("modules", "Modules a activer (-m), ex: sql,xss,file", "string"),
        ParameterSpec("scope", "Portee: page, folder, domain, url (-s)", "string"),
        ParameterSpec("output", "Fichier de rapport (-o)", "string"),
        ParameterSpec("format", "Format du rapport (-f): html, json, txt", "string"),
        ParameterSpec("depth", "Profondeur de crawl (-d)", "int"),
        ParameterSpec("flush", "Vider la session (--flush-session)", "bool", default=False),
    )
    options = (Option("url", "-u"), Option("modules", "-m"), Option("scope", "-s"), Option("output", "-o"), Option("format", "-f"), Option("depth", "-d"))
    flags = (Flag("flush", "--flush-session"),)
    url_param = "url"
    rules = (
        Rule("modules", ("injection sql", "sql"), "sql"),
        Rule("modules", ("xss", "cross site"), "xss"),
        Rule("modules", ("lfi", "inclusion de fichier"), "file"),
        Rule("modules", ("ssrf",), "ssrf"),
    )
    patterns = (
        Pattern(r"(SQL Injection|Cross Site Scripting|File Disclosure|SSRF)", "Vulnerabilite: {0}", "high", "Faille exploitable confirmee par Wapiti."),
        Pattern(r"Vulnerability found", "Vulnerabilite detectee", "high"),
        Pattern(r"^(\w+)\s+in\s+(\S+)", "{0} dans {1}", "medium"),
    )


class WatoboTool(SpecTool):
    name = "watobo"
    aliases = ()
    binary = "watobo"
    risk = "medium"
    description = "Proxy d'audit web (Watobo) avec analyse des requetes."
    examples = ("lance watobo sur http://target",)
    parameters = (
        ParameterSpec("url", "URL a auditer", "string"),
        ParameterSpec("port", "Port d'ecoute du proxy (-p)", "string"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class WebsploitTool(SpecTool):
    name = "websploit"
    aliases = ()
    binary = "websploit"
    risk = "critical"
    description = "Framework d'exploitation web modulaire (scanners et modules d'attaque)."
    examples = ("lance websploit et charge le module de scan web",)
    parameters = (
        ParameterSpec("module", "Module a charger (-m)", "string"),
        ParameterSpec("target", "Cible (-t)", "string"),
    )
    options = (Option("module", "-m"), Option("target", "-t"))
    patterns = (
        Pattern(r"vulnerable|exploit", "Cible vulnerable ou exploitable", "critical"),
        Pattern(r"error|failed", "Echec du module", "low"),
    )


class WhatwebTool(SpecTool):
    name = "whatweb"
    aliases = ()
    binary = "whatweb"
    risk = "low"
    description = "Empreinte d'un site: CMS, serveur, frameworks, versions, technologies."
    examples = ("identifie les technologies de http://target en mode agressif",)
    parameters = (
        ParameterSpec("target", "URL ou hote cible", "string", required=True),
        ParameterSpec("aggression", "Niveau d'agressivite (-a): 1 a 4", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("format", "Format de sortie (--log-json, --log-xml)", "string"),
    )
    options = (Option("aggression", "-a"), Option("output", "-o"))
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)
    url_param = "target"
    target_params = ("target",)
    patterns = (
        Pattern(r"WordPress|Joomla|Drupal|Magento", "CMS detecte: {0}", "medium", "Un CMS identifie doit etre tenu a jour."),
        Pattern(r"PHP/([\d.]+)", "PHP {0}", "info"),
        Pattern(r"Apache/([\d.]+)|nginx/([\d.]+)", "Serveur web detecte", "info"),
        Pattern(r"outdated|vulnerable", "Version potentiellement obsoleted", "medium"),
    )


class XsserTool(SpecTool):
    name = "xsser"
    aliases = ()
    binary = "xsser"
    risk = "high"
    description = "Detecte et exploite les failles XSS (Cross-Site Scripting)."
    examples = ("teste les failles xss sur http://target/page.php?q=FUZZ",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("crawl", "Crawler les liens (--crawl)", "bool", default=False),
        ParameterSpec("auto", "Mode automatique (--auto)", "bool", default=False),
        ParameterSpec("cookie", "Cookie de session (--cookie)", "string"),
        ParameterSpec("threads", "Threads (--threads)", "int"),
        ParameterSpec("output", "Fichier de rapport (--save)", "string"),
    )
    options = (Option("url", "-u"), Option("cookie", "--cookie"), Option("threads", "--threads"), Option("output", "--save"))
    flags = (Flag("crawl", "--crawl"), Flag("auto", "--auto"))
    url_param = "url"
    patterns = (
        Pattern(r"XSS\s*(found|vulnerable)|vulnerable", "Faille XSS detectee", "high", "Injection de script cote client."),
        Pattern(r"injectable|payload", "Parametre injectable", "high"),
        Pattern(r"not injectable|failed", "Pas d'injection", "info"),
    )


for _tool in (
    CadaverTool(),
    DavtestTool(),
    HeartleechTool(),
    JbossAutopwnTool(),
    JsqlTool(),
    NiktoTool(),
    OwaspMantraTool(),
    PadbusterTool(),
    WapitiTool(),
    WatoboTool(),
    WebsploitTool(),
    WhatwebTool(),
    XsserTool(),
):
    register(_tool)
