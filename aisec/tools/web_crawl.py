"""Crawlers et bruteforce de repertoires (classe 03, sous-categorie Crawlers).

Couvre: apache-users, arjun, cutycapt, dirb, dirbuster, dirsearch, feroxbuster,
ffuf, gobuster, gospider, uniscan, wfuzz.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .base import extract_hosts
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class ApacheUsersTool(SpecTool):
    name = "apache-users"
    aliases = ()
    binary = "apache-users"
    risk = "medium"
    description = "Enumere les comptes Unix via le module Apache UserDir."
    examples = ("enumere les utilisateurs apache de example.com avec la liste users.txt",)
    parameters = (
        ParameterSpec("host", "Hote cible (-h)", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string", default="80"),
        ParameterSpec("wordlist", "Liste de noms (-l)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("ssl", "Utiliser HTTPS (-s)", "bool", default=False),
    )
    options = (Option("host", "-h"), Option("port", "-p"), Option("wordlist", "-l"), Option("threads", "-t"))
    flags = (Flag("ssl", "-s"),)
    target_params = ("host",)
    patterns = (
        Pattern(r"^(\w+)\s+200", "Compte trouve: {0}", "high", "Le module UserDir expose les comptes du systeme."),
        Pattern(r"not found|404", "Aucun compte supplementaire", "info"),
    )


class ArjunTool(SpecTool):
    name = "arjun"
    aliases = ()
    binary = "arjun"
    risk = "medium"
    description = "Decouverte de parametres HTTP caches (GET/POST/JSON)."
    examples = ("decouvre les parametres caches de http://target/search",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("method", "Methode HTTP (-m): GET, POST, JSON", "string"),
        ParameterSpec("wordlist", "Liste de parametres (-w)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("url", "-u"), Option("method", "-m"), Option("wordlist", "-w"), Option("threads", "-t"), Option("output", "-o"))
    url_param = "url"
    patterns = (
        Pattern(r"Parameters found|parametres trouves", "Parametres caches decouverts", "medium", "Des parametres non documentes augmentent la surface d'attaque."),
        Pattern(r"^(\w+)\s*$", "Parametre: {0}", "low"),
    )


class CutycaptTool(SpecTool):
    name = "cutycapt"
    aliases = ()
    binary = "cutycapt"
    risk = "low"
    description = "Capture une page web en image (rendu WebKit)."
    examples = ("capture http://target dans page.png",)
    parameters = (
        ParameterSpec("url", "URL a capturer (--url)", "string", required=True),
        ParameterSpec("output", "Fichier image de sortie (--out)", "string", required=True),
        ParameterSpec("delay", "Delai avant capture en ms (--delay)", "int"),
        ParameterSpec("width", "Largeur (--min-width)", "int"),
    )
    options = (
        Option("url", "--url=", joined=True),
        Option("output", "--out=", joined=True),
        Option("delay", "--delay=", joined=True),
        Option("width", "--min-width=", joined=True),
    )
    url_param = "url"
    patterns = (
        Pattern(r"error|failed", "Echec de la capture", "low"),
        Pattern(r"wrote|saved", "Capture enregistree", "info"),
    )


class DirbTool(SpecTool):
    name = "dirb"
    aliases = ()
    binary = "dirb"
    risk = "medium"
    description = "Bruteforce de repertoires et fichiers web par dictionnaire."
    examples = ("bruteforce les repertoires de http://target avec la liste commune",)
    parameters = (
        ParameterSpec("url", "URL de base", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire", "string"),
        ParameterSpec("extensions", "Extensions a tester (-X), ex: php,html", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("recursive", "Descente recursive (-r)", "bool", default=False),
        ParameterSpec("silent", "Mode silencieux (-S)", "bool", default=False),
        ParameterSpec("not_found", "Ignorer les codes (-N)", "string"),
    )
    options = (Option("extensions", "-X"), Option("output", "-o"), Option("not_found", "-N"))
    flags = (Flag("recursive", "-r"), Flag("silent", "-S"))
    positionals = (Positional("url"), Positional("wordlist"))
    url_param = "url"
    patterns = (
        Pattern(r"^\+ (https?://\S+)", "Chemin decouvert: {0}", "medium", "Repertoire ou fichier accessible."),
        Pattern(r"==> DIRECTORY", "Repertoire liste", "low"),
        Pattern(r"Found:\s*(\d+)", "{0} entree(s) trouvee(s)", "info"),
    )


class DirbusterTool(SpecTool):
    name = "dirbuster"
    aliases = ()
    binary = "dirbuster"
    risk = "medium"
    description = "Bruteforce de repertoires et fichiers web (interface graphique)."
    examples = ("lance dirbuster sur http://target",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire", "string"),
        ParameterSpec("extensions", "Extensions a tester", "string"),
        ParameterSpec("threads", "Threads", "int"),
    )
    positionals = (Positional("url"),)
    url_param = "url"
    patterns = (
        Pattern(r"error|failed", "Erreur de DirBuster", "low"),
    )


class DirsearchTool(SpecTool):
    name = "dirsearch"
    aliases = ()
    binary = "DirSearch"
    risk = "medium"
    description = "Scanner de chemins web: repertoires et fichiers caches."
    examples = ("cherche les chemins caches de http://target avec les extensions php et bak",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("extensions", "Extensions (-e), ex: php,html,bak", "string"),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("recursive", "Recursif (-r)", "bool", default=False),
        ParameterSpec("exclude_codes", "Codes a exclure (--exclude-status)", "string"),
    )
    options = (Option("url", "-u"), Option("extensions", "-e"), Option("wordlist", "-w"), Option("threads", "-t"), Option("output", "-o"), Option("exclude_codes", "--exclude-status"))
    flags = (Flag("recursive", "-r"),)
    url_param = "url"
    patterns = (
        Pattern(r"^(\d{3})\s+\S+\s+(\S+)", "[{0}] {1}", "medium", "Chemin accessible trouve."),
        Pattern(r"200\s+OK", "Acces autorise", "medium"),
        Pattern(r"403\s+Forbidden", "Acces interdit (chemin existant)", "low"),
    )


class FeroxbusterTool(SpecTool):
    name = "feroxbuster"
    aliases = ()
    binary = "feroxbuster"
    risk = "medium"
    description = "Bruteforce recursif rapide de contenu web (Rust)."
    examples = ("bruteforce recursivement http://target avec les extensions php et js",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("extensions", "Extensions (-x)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("depth", "Profondeur de recursion (-d)", "int"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("insecure", "Ignorer les erreurs TLS (-k)", "bool", default=False),
    )
    options = (Option("url", "-u"), Option("wordlist", "-w"), Option("extensions", "-x"), Option("threads", "-t"), Option("depth", "-d"), Option("output", "-o"))
    flags = (Flag("insecure", "-k"),)
    url_param = "url"
    patterns = (
        Pattern(r"^(\d{3})\s+\S+\s+\d+l\s+\d+w\s+\d+c\s+(\S+)", "[{0}] {1}", "medium"),
        Pattern(r"Scanning|Crawling", "Scan en cours", "info"),
    )


class FfufTool(SpecTool):
    name = "ffuf"
    aliases = ()
    binary = "ffuf"
    risk = "high"
    description = "Fuzzer web rapide: chemins, parametres, valeurs (mot-cle FUZZ)."
    examples = ("fuzz http://target/FUZZ avec la liste commune en filtrant les 404",)
    parameters = (
        ParameterSpec("url", "URL avec le mot-cle FUZZ (-u)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string", required=True),
        ParameterSpec("method", "Methode HTTP (-X)", "string"),
        ParameterSpec("match_codes", "Codes a garder (-mc)", "string"),
        ParameterSpec("filter_codes", "Codes a filtrer (-fc)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("extensions", "Extensions (-e)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("insecure", "Ignorer les erreurs TLS (-k)", "bool", default=False),
        ParameterSpec("silent", "Sortie silencieuse (-s)", "bool", default=False),
    )
    options = (Option("url", "-u"), Option("wordlist", "-w"), Option("method", "-X"), Option("match_codes", "-mc"), Option("filter_codes", "-fc"), Option("threads", "-t"), Option("extensions", "-e"), Option("output", "-o"))
    flags = (Flag("insecure", "-k"), Flag("silent", "-s"))
    url_param = "url"
    patterns = (
        Pattern(r"^(\S+)\s+\[Status:\s*(\d+)", "{0} -> {1}", "medium", "Ressource decouverte par fuzzing."),
        Pattern(r":: Progress", "Fuzzing en cours", "info"),
    )


class GobusterTool(SpecTool):
    name = "gobuster"
    aliases = ()
    binary = "gobuster"
    risk = "medium"
    description = "Bruteforce de repertoires, DNS, vhosts et parametres web."
    examples = ("bruteforce les repertoires de http://target avec les extensions php et txt",)
    parameters = (
        ParameterSpec("mode", "Mode: dir, dns, vhost, fuzz", "string", default="dir"),
        ParameterSpec("url", "URL cible (-u)", "string"),
        ParameterSpec("domain", "Domaine cible (-d, mode dns)", "string"),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("extensions", "Extensions (-x)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("insecure", "Ignorer les erreurs TLS (-k)", "bool", default=False),
        ParameterSpec("status_codes", "Codes a afficher (-s)", "string"),
    )
    options = (Option("url", "-u"), Option("domain", "-d"), Option("wordlist", "-w"), Option("extensions", "-x"), Option("threads", "-t"), Option("output", "-o"), Option("status_codes", "-s"))
    flags = (Flag("insecure", "-k"),)
    positionals = (Positional("mode"),)
    # gobuster attend le mode en premier: `gobuster dir -u URL -w LISTE`.
    order = ("positionals", "options", "flags")
    url_param = "url"
    rules = (
        Rule("mode", ("dns", "sous-domaine", "subdomain"), "dns"),
        Rule("mode", ("vhost", "hote virtuel", "virtual host"), "vhost"),
        Rule("mode", ("fuzz",), "fuzz"),
        Rule("mode", ("repertoire", "directory", "dossier", "dir"), "dir"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = {"mode": "dir", **params}
        return super().build_argv(params)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        # En mode dns, gobuster attend -d <domaine> et non -u <url>.
        if params.get("mode") == "dns":
            hosts = extract_hosts(params.pop("url", "") or text)
            if hosts:
                params["domain"] = hosts[0]
        return params

    patterns = (
        Pattern(r"^(\S+)\s+\(Status:\s*(\d+)", "{0} -> {1}", "medium"),
        Pattern(r"Found:\s*(\S+)", "Trouve: {0}", "medium"),
        Pattern(r"^Found: (\S+)", "Sous-domaine: {0}", "medium"),
    )


class GospiderTool(SpecTool):
    name = "gospider"
    aliases = ()
    binary = "gospider"
    risk = "low"
    description = "Crawler web rapide: liens, scripts, formulaires, endpoints."
    examples = ("crawle http://target sur 3 niveaux de profondeur",)
    parameters = (
        ParameterSpec("site", "Site de depart (-s)", "string", required=True),
        ParameterSpec("depth", "Profondeur (-d)", "int"),
        ParameterSpec("concurrency", "Requetes concurrentes (-c)", "int"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("output", "Dossier de sortie (-o)", "string"),
        ParameterSpec("robots", "Lire robots.txt (--robots)", "bool", default=False),
        ParameterSpec("sitemap", "Lire sitemap.xml (--sitemap)", "bool", default=False),
    )
    options = (Option("site", "-s"), Option("depth", "-d"), Option("concurrency", "-c"), Option("threads", "-t"), Option("output", "-o"))
    flags = (Flag("robots", "--robots"), Flag("sitemap", "--sitemap"))
    url_param = "site"
    patterns = (
        Pattern(r"\[url\]\s*-\s*(\S+)", "URL crawlee: {0}", "info"),
        Pattern(r"\[javascript\]\s*-\s*(\S+)", "Script: {0}", "low"),
        Pattern(r"\[form\]", "Formulaire detecte", "low"),
    )


class UniscanTool(SpecTool):
    name = "uniscan"
    aliases = ()
    binary = "uniscan"
    risk = "medium"
    description = "Scanner web: whois, sitemap, fichiers sensibles, injection SQL/XSS."
    examples = ("scan complet de http://target avec whois et sitemap",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("whois", "Interroger whois (-w)", "bool", default=False),
        ParameterSpec("sitemap", "Generer le sitemap (-s)", "bool", default=False),
        ParameterSpec("files", "Chercher les fichiers sensibles (-d)", "bool", default=False),
        ParameterSpec("inject", "Tester les injections (-e)", "bool", default=False),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )
    options = (Option("url", "-u"),)
    flags = (Flag("whois", "-w"), Flag("sitemap", "-s"), Flag("files", "-d"), Flag("inject", "-e"), Flag("quiet", "-q"))
    url_param = "url"
    rules = (
        Rule("whois", ("whois",), True),
        Rule("sitemap", ("sitemap", "plan du site"), True),
        Rule("files", ("fichier", "repertoire", "directory"), True),
        Rule("inject", ("injection", "sql", "xss", "vulnerabilite"), True),
    )
    patterns = (
        Pattern(r"(SQL injection|XSS|LFI|RFI)", "Vulnerabilite: {0}", "high", "Faille exploitable detectee."),
        Pattern(r"robots\.txt|sitemap", "Fichier de decouverte trouve", "low"),
        Pattern(r"\[!\]", "Avertissement du scanner", "medium"),
    )


class WfuzzTool(SpecTool):
    name = "wfuzz"
    aliases = ()
    binary = "wfuzz"
    risk = "high"
    description = "Fuzzer web generique: injecte des charges utiles dans requetes HTTP."
    examples = ("fuzz http://target/FUZZ avec la liste commune",)
    parameters = (
        ParameterSpec("url", "URL avec le mot-cle FUZZ (-u)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string", required=True),
        ParameterSpec("hide_codes", "Codes a masquer (--hc)", "string"),
        ParameterSpec("show_codes", "Codes a afficher (--sc)", "string"),
        ParameterSpec("postdata", "Donnees POST (-d)", "string"),
        ParameterSpec("header", "En-tete HTTP (-H)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("output", "Fichier de sortie (-f)", "string"),
    )
    options = (Option("url", "-u"), Option("wordlist", "-w"), Option("hide_codes", "--hc"), Option("show_codes", "--sc"), Option("postdata", "-d"), Option("header", "-H"), Option("threads", "-t"), Option("output", "-f"))
    url_param = "url"
    patterns = (
        Pattern(r"^(\d+)\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+(\S+)", "[{0}] {1}", "medium"),
        Pattern(r"Total requests:\s*(\d+)", "{0} requete(s) envoyee(s)", "info"),
    )


for _tool in (
    ApacheUsersTool(),
    ArjunTool(),
    CutycaptTool(),
    DirbTool(),
    DirbusterTool(),
    DirsearchTool(),
    FeroxbusterTool(),
    FfufTool(),
    GobusterTool(),
    GospiderTool(),
    UniscanTool(),
    WfuzzTool(),
):
    register(_tool)
