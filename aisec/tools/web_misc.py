"""Analyse web directe, CMS et proxies (classe 03).

Couvre la sous-categorie directe (httrack, parsero, s3scanner, skipfish, wig,
wpscan, zaproxy, paros, webscarab), CMS (joomscan) et les proxies web
(burpsuite, caido, goshs).
"""

from __future__ import annotations


from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, Rule, SpecTool


class HttrackTool(SpecTool):
    name = "httrack"
    aliases = ()
    binary = "httrack"
    risk = "low"
    description = "Copie miroir d'un site web (aspiration hors ligne)."
    examples = ("aspire le site http://target dans le dossier ./miroir",)
    parameters = (
        ParameterSpec("url", "URL du site", "string", required=True),
        ParameterSpec("output", "Dossier de destination (-O)", "string"),
        ParameterSpec("depth", "Profondeur maximale (-r)", "int"),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )
    options = (Option("output", "-O"), Option("depth", "-r"))
    flags = (Flag("quiet", "-q"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"mirror|site copied|complete", "Miroir du site termine", "info"),
        Pattern(r"error|failed", "Echec de l'aspiration", "low"),
    )


class ParosTool(SpecTool):
    name = "paros"
    aliases = ()
    binary = "paros"
    risk = "medium"
    description = "Proxy d'audit web (Paros): interception et analyse des requetes."
    examples = ("lance le proxy paros sur le port 8080",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (-port)", "string", default="8080"),
        ParameterSpec("url", "URL a auditer", "string"),
    )
    options = (Option("port", "-port"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class ParseroTool(SpecTool):
    name = "parsero"
    aliases = ()
    binary = "parsero"
    risk = "medium"
    description = "Cherche des fichiers et repertoires caches dans robots.txt."
    examples = ("cherche les entrees cachees de robots.txt de example.com",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("url", "-u"), Option("wordlist", "-w"))
    flags = (Flag("verbose", "-v"),)
    url_param = "url"
    patterns = (
        Pattern(r"Disallow:\s*(\S+)", "Entree robots.txt: {0}", "low", "Un chemin non liste peut reveler une surface d'attaque."),
        Pattern(r"^(\S+)\s+\[(\d+)\]", "{0} -> {1}", "medium"),
    )


class S3scannerTool(SpecTool):
    name = "s3scanner"
    aliases = ()
    binary = "s3scanner"
    risk = "medium"
    description = "Cherche des buckets S3 exposes (listage ou ecriture publique)."
    examples = ("cherche le bucket s3 nomme mon-bucket et teste ses permissions",)
    parameters = (
        ParameterSpec("bucket", "Nom du bucket (-bucket)", "string"),
        ParameterSpec("buckets_file", "Fichier de buckets (-bucket-file)", "string"),
        ParameterSpec("provider", "Fournisseur: aws, gcp, digitalocean (-provider)", "string"),
        ParameterSpec("enumerate", "Enumere le contenu (-enumerate)", "bool", default=False),
    )
    options = (Option("bucket", "-bucket"), Option("buckets_file", "-bucket-file"), Option("provider", "-provider"))
    flags = (Flag("enumerate", "-enumerate"),)
    positionals = (Positional("bucket"),)
    patterns = (
        Pattern(r"bucket exists|exists", "Bucket S3 existe", "medium"),
        Pattern(r"public|PUBLIC|listable|writable", "Bucket accessible publiquement", "high", "Fuite ou modification de donnees possible."),
        Pattern(r"not found|does not exist", "Bucket introuvable", "info"),
    )


class SkipfishTool(SpecTool):
    name = "skipfish"
    aliases = ()
    binary = "skipfish"
    risk = "high"
    description = "Scanner web actif: carte le site et cherche des failles d'injection."
    examples = ("scanne http://target avec skipfish vers le dossier resultats",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("output", "Dossier de sortie (-o)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-W)", "string"),
        ParameterSpec("threads", "Threads (-l)", "int"),
        ParameterSpec("auth", "Authentification (-A user:pass)", "string"),
    )
    options = (Option("output", "-o"), Option("wordlist", "-W"), Option("threads", "-l"), Option("auth", "-A"))
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"(\d+)\s+(?:issues|problems|findings)", "{0} probleme(s) detecte(s)", "medium"),
        Pattern(r"high risk|HIGH", "Risque eleve detecte", "high"),
        Pattern(r"medium risk", "Risque moyen detecte", "medium"),
    )


class WebscarabTool(SpecTool):
    name = "webscarab"
    aliases = ()
    binary = "webscarab"
    risk = "medium"
    description = "Proxy d'analyse web (WebScarab): inspection et rejeu des requetes."
    examples = ("lance le proxy webscarab sur le port 8008",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute", "string"),
        ParameterSpec("url", "URL a auditer", "string"),
    )
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class WigTool(SpecTool):
    name = "wig"
    aliases = ()
    binary = "wig"
    risk = "medium"
    description = "Empreinte de CMS: detecte WordPress, Joomla, Drupal et leurs failles connues."
    examples = ("identifie le cms de http://target",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("verbose", "Verbeux", "bool", default=False),
    )
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"WordPress|Joomla|Drupal|Magento|TYPO3", "CMS detecte: {0}", "medium"),
        Pattern(r"vulnerable|exploit", "Version vulnerable", "high"),
    )


class WpscanTool(SpecTool):
    name = "wpscan"
    aliases = ()
    binary = "wpscan"
    risk = "high"
    description = "Scanner WordPress: versions, plugins, themes, utilisateurs, vulnerabilites."
    examples = ("scanne le wordpress http://target et enumere les utilisateurs vulnerables",)
    parameters = (
        ParameterSpec("url", "URL du site WordPress (--url)", "string", required=True),
        ParameterSpec("enumerate", "Enumeration (-e): vp, vt, u, ap", "string"),
        ParameterSpec("api_token", "Jeton d'API WPScan (--api-token)", "string"),
        ParameterSpec("plugins_detection", "Detection des plugins (--plugins-detection)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("format", "Format (-f): cli, json", "string"),
        ParameterSpec("stealthy", "Mode discret (--stealthy)", "bool", default=False),
    )
    options = (Option("url", "--url"), Option("enumerate", "-e"), Option("api_token", "--api-token"), Option("plugins_detection", "--plugins-detection"), Option("output", "-o"), Option("format", "-f"))
    flags = (Flag("stealthy", "--stealthy"),)
    url_param = "url"
    rules = (
        Rule("enumerate", ("utilisateur", "user", "comptes"), "u"),
        Rule("enumerate", ("plugin",), "vp"),
        Rule("enumerate", ("theme",), "vt"),
    )
    patterns = (
        Pattern(r"\[!\]\s*(.+)", "Vulnerabilite: {0}", "high"),
        Pattern(r"XML-RPC seems to be enabled", "XML-RPC active (bruteforce possible)", "medium"),
        Pattern(r"WordPress version ([\d.]+)", "Version WordPress {0}", "info"),
        Pattern(r"User\(s\) Identified", "Utilisateurs WordPress identifies", "medium"),
    )


class ZaproxyTool(SpecTool):
    name = "zaproxy"
    aliases = ("owasp-zap",)
    binary = "owasp-zap"
    risk = "high"
    description = "Scanner d'application web OWASP ZAP: spider, scan actif, alertes."
    examples = ("scanne http://target avec zap et genere un rapport html",)
    parameters = (
        ParameterSpec("url", "URL cible (-quickurl)", "string"),
        ParameterSpec("scan", "Lancer un scan actif (-quickprogress)", "bool", default=False),
        ParameterSpec("report", "Fichier de rapport (-quickout)", "string"),
        ParameterSpec("config", "Fichier de configuration (-config)", "string"),
        ParameterSpec("daemon", "Mode daemon (-daemon)", "bool", default=False),
        ParameterSpec("port", "Port du proxy (-port)", "string"),
    )
    options = (Option("url", "-quickurl"), Option("report", "-quickout"), Option("config", "-config"), Option("port", "-port"))
    flags = (Flag("scan", "-quickprogress"), Flag("daemon", "-daemon"))
    url_param = "url"
    patterns = (
        Pattern(r"(High|Medium|Low)\s*:\s*(\d+)", "Alertes {0}: {1}", "medium"),
        Pattern(r"SQL Injection|Cross Site Scripting|XSS", "Vulnerabilite: {0}", "high"),
        Pattern(r"Number of alerts", "Alertes generees", "info"),
    )


class JoomscanTool(SpecTool):
    name = "joomscan"
    aliases = ()
    binary = "joomscan"
    risk = "high"
    description = "Scanner Joomla: version, composants, vulnerabilites connues."
    examples = ("scanne le joomla http://target et enumere les composants",)
    parameters = (
        ParameterSpec("url", "URL du site Joomla (-u)", "string", required=True),
        ParameterSpec("enumerate", "Enumeration des composants (-ec)", "bool", default=False),
        ParameterSpec("output", "Dossier de sortie (-o)", "string"),
        ParameterSpec("random_agent", "User-agent aleatoire (--random-agent)", "bool", default=False),
    )
    options = (Option("url", "-u"), Option("output", "-o"))
    flags = (Flag("enumerate", "-ec"), Flag("random_agent", "--random-agent"))
    url_param = "url"
    patterns = (
        Pattern(r"Joomla Version|Joomla! ([\d.]+)", "Version Joomla detectee", "info"),
        Pattern(r"Vulnerabilit|vulnerable|CVE-\d+", "Vulnerabilite Joomla detectee", "high"),
        Pattern(r"Component(s)? found|com_", "Composant Joomla detecte", "medium"),
    )


class BurpsuiteTool(SpecTool):
    name = "burpsuite"
    aliases = ()
    binary = "burpsuite"
    risk = "medium"
    description = "Proxy d'interception (Burp Suite CE) pour tester les applications web."
    examples = ("lance burp suite sur le port 8080",)
    parameters = (
        ParameterSpec("port", "Port du proxy", "string", default="8080"),
        ParameterSpec("config", "Fichier de configuration", "string"),
    )
    positionals = (Positional("config"),)
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class CaidoTool(SpecTool):
    name = "caido"
    aliases = ()
    binary = "Caido"
    risk = "medium"
    description = "Proxy d'audit web moderne (Caido): interception et rejeu."
    examples = ("lance caido sur le port 8080",)
    parameters = (
        ParameterSpec("port", "Port du proxy (--listen)", "string"),
        ParameterSpec("no_open", "Ne pas ouvrir le navigateur (--no-open)", "bool", default=False),
    )
    options = (Option("port", "--listen"),)
    flags = (Flag("no_open", "--no-open"),)
    patterns = (Pattern(r"error|failed", "Erreur de lancement", "low"),)


class GoshsTool(SpecTool):
    name = "goshs"
    aliases = ()
    binary = "goshs"
    risk = "high"
    description = "Serveur HTTP simple (Go): partage de fichiers et depot (upload)."
    examples = ("lance goshs sur le port 8000 avec televersement",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (-p)", "string", default="8000"),
        ParameterSpec("upload", "Autoriser le televersement (-u)", "bool", default=False),
        ParameterSpec("directory", "Dossier partage (-d)", "string"),
        ParameterSpec("tls", "Activer TLS (-s)", "bool", default=False),
    )
    options = (Option("port", "-p"), Option("directory", "-d"))
    flags = (Flag("upload", "-u"), Flag("tls", "-s"))
    patterns = (
        Pattern(r"listening on|ecoute sur", "Serveur actif", "info"),
        Pattern(r"upload", "Televersement active", "medium", "Un depot ouvert expose a l'exfiltration de fichiers."),
    )


for _tool in (
    HttrackTool(),
    ParosTool(),
    ParseroTool(),
    S3scannerTool(),
    SkipfishTool(),
    WebscarabTool(),
    WigTool(),
    WpscanTool(),
    ZaproxyTool(),
    JoomscanTool(),
    BurpsuiteTool(),
    CaidoTool(),
    GoshsTool(),
):
    register(_tool)
