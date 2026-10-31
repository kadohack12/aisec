"""Classe 01 - Information Gathering : DNS, OSINT, SMB, SMTP/SNMP.

Sous-categories couvertes:
  - 01-01-dns-analysis    : amass, certgraph, dnsenum, dnsmap, dnstracer,
                            dnswalk, fierce, urlcrazy
  - 01-07-osint-analysis  : assetfinder, bing-ip2hosts, cloud-enum,
                            emailharvester, goofile, inspy, instaloader,
                            metagoofil, osrframework, python3-censys,
                            python3-shodan, sherlock, spiderfoot, theharvester
  - 01-10-smb-analysis    : enum4linux, enum4linux-ng, nbtscan, polenum, smbmap
  - 01-11-smtp-analysis   : ismtp, smtp-user-enum, swaks
  - 01-12-snmp-analysis   : braa, onesixtyone, snmpcheck

Reconnaissance passive ou a faible impact: risque `medium` (l'enumeration
SMB/SNMP touche des services internes).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class AmassTool(SpecTool):
    name = "amass"
    binary = "amass"
    risk = "medium"
    description = "Cartographie les domaines et sous-domaines (OSINT + brute force DNS)."
    examples = ("enumere les sous-domaines de example.com avec amass",)
    parameters = (
        ParameterSpec("domain", "Domaine cible", "string", required=True),
        ParameterSpec("passive", "Mode passif uniquement (-passive)", "bool", default=False),
        ParameterSpec("brute", "Force brute DNS (-brute)", "bool", default=False),
    )
    flags = (Flag("passive", "-passive"), Flag("brute", "-brute"))
    positionals = (Positional("domain"),)
    order = ("flags", "positionals")
    target_params = ("domain",)
    patterns = (
        Pattern(r"([\w.-]+\.\w{2,})", "Sous-domaine decouvert: {0}", "info"),
        Pattern(r"error|failed", "Echec de resolution", "low"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["amass", "enum"]
        if params.get("passive"):
            argv.append("-passive")
        if params.get("brute"):
            argv.append("-brute")
        if params.get("domain"):
            argv += ["-d", str(params["domain"])]
        return argv


class CertgraphTool(SpecTool):
    name = "certgraph"
    binary = "certgraph"
    risk = "medium"
    description = "Graphe des certificats TLS successifs d'un domaine (transparence)."
    examples = ("trace le graphe de certificats de example.com avec certgraph",)
    parameters = (ParameterSpec("domain", "Domaine cible", "string", required=True),)
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (Pattern(r"[\w.-]+\.\w{2,}", "Certificat: {0}", "info"),)


class DnsenumTool(SpecTool):
    name = "dnsenum"
    binary = "dnsenum"
    risk = "medium"
    description = "Enumere DNS: transfert de zone, sous-domaines, enregistrements."
    examples = ("enumere example.com avec dnsenum",)
    parameters = (
        ParameterSpec("domain", "Domaine cible", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-f)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
    )
    options = (Option("wordlist", "-f"), Option("threads", "-t"))
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (
        Pattern(r"AXFR|zone transfer", "Transfert de zone possible", "high", "Fuite d'annuaire DNS."),
        Pattern(r"([\w.-]+\.\w{2,})", "Sous-domaine: {0}", "info"),
    )


class DnsmapTool(SpecTool):
    name = "dnsmap"
    binary = "dnsmap"
    risk = "medium"
    description = "Brute force de sous-domaines par dictionnaire."
    examples = ("brute force les sous-domaines de example.com avec dnsmap",)
    parameters = (
        ParameterSpec("domain", "Domaine cible", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
    )
    options = (Option("wordlist", "-w"),)
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (
        Pattern(r"([\w.-]+\.\w{2,})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})", "Sous-domaine: {0} -> {1}", "info"),
    )


class DnstracerTool(SpecTool):
    name = "dnstracer"
    binary = "dnstracer"
    risk = "low"
    description = "Suit la chaine de delegation DNS jusqu'au serveur faisant autorite."
    examples = ("trace la delegation dns de example.com avec dnstracer",)
    parameters = (ParameterSpec("domain", "Domaine cible", "string", required=True),)
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (
        Pattern(r"via\s+([\w.-]+)", "Delegation via {0}", "info"),
        Pattern(r"servfail|nxdomain", "Reponse DNS en erreur", "low"),
    )


class DnswalkTool(SpecTool):
    name = "dnswalk"
    binary = "dnswalk"
    risk = "medium"
    description = "Verifie la coherence d'une zone DNS (transfert + enregistrements)."
    examples = ("verifie la zone example.com avec dnswalk",)
    parameters = (
        ParameterSpec("zone", "Zone DNS (fqdn.)", "string", required=True),
        ParameterSpec("debug", "Mode verbeux (-d)", "bool", default=False),
    )
    flags = (Flag("debug", "-d"),)
    positionals = (Positional("zone"),)
    order = ("flags", "positionals")
    target_params = ("zone",)
    patterns = (
        Pattern(r"FAIL|WARN|ERROR", "Anomalie de zone: {0}", "medium"),
        Pattern(r"Transfer failed|refused", "Transfert de zone refuse", "info"),
    )


class FierceTool(SpecTool):
    name = "fierce"
    binary = "fierce"
    risk = "medium"
    description = "Reconnaissance DNS: sous-domaines, zone transfer, reverse."
    examples = ("enumere example.com avec fierce",)
    parameters = (
        ParameterSpec("domain", "Domaine cible", "string", required=True),
        ParameterSpec("nameserver", "Serveur DNS (--dns-servers)", "string"),
    )
    options = (Option("nameserver", "--dns-servers"),)
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (
        Pattern(r"Found:\s*([\w.-]+)", "Hote trouve: {0}", "info"),
        Pattern(r"zone transfer|AXFR", "Transfert de zone reussi", "high"),
    )


class UrlcrazyTool(SpecTool):
    name = "urlcrazy"
    binary = "urlcrazy"
    risk = "low"
    description = "Genere des variantes typosquat d'un domaine (phishing, fraude)."
    examples = ("genere les variantes de example.com avec urlcrazy",)
    parameters = (ParameterSpec("domain", "Domaine cible", "string", required=True),)
    positionals = (Positional("domain"),)
    target_params = ("domain",)
    patterns = (Pattern(r"([\w-]+\.\w{2,})\s", "Variante enregistree: {0}", "low"),)


class AssetfinderTool(SpecTool):
    name = "assetfinder"
    binary = "assetfinder"
    risk = "medium"
    description = "Trouve les domaines et sous-domaines lies a une organisation."
    examples = ("trouve les sous-domaines de example.com avec assetfinder",)
    parameters = (
        ParameterSpec("domain", "Domaine cible", "string", required=True),
        ParameterSpec("subs_only", "Sous-domaines uniquement (--subs-only)", "bool", default=False),
    )
    flags = (Flag("subs_only", "--subs-only"),)
    positionals = (Positional("domain"),)
    order = ("flags", "positionals")
    target_params = ("domain",)
    patterns = (Pattern(r"([\w.-]+\.\w{2,})", "Domaine: {0}", "info"),)


class BingIp2HostsTool(SpecTool):
    name = "bing-ip2hosts"
    binary = "bing-ip2hosts"
    risk = "low"
    description = "Reverse DNS via Bing: hotes partageant une meme adresse IP."
    examples = ("trouve les hotes de 10.0.0.5 avec bing-ip2hosts",)
    parameters = (ParameterSpec("ip", "Adresse IP", "string", required=True),)
    positionals = (Positional("ip"),)
    target_params = ("ip",)
    patterns = (Pattern(r"([\w.-]+\.\w{2,})", "Hote: {0}", "info"),)


class CloudEnumTool(SpecTool):
    name = "cloud-enum"
    binary = "cloud_enum"
    risk = "medium"
    target_params = ("keyword",)
    description = "Enumere les ressources cloud publiques (S3, Azure, GCP) d'un nom."
    examples = ("enumere les buckets cloud de example avec cloud-enum",)
    parameters = (
        ParameterSpec("keyword", "Mot-cle d'entreprise (-k)", "string", required=True),
        ParameterSpec("brute", "Force brute (-b)", "bool", default=False),
    )
    flags = (Flag("brute", "-b"),)
    options = (Option("keyword", "-k"),)
    order = ("options", "flags")

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\b(?:de|pour|du)\s+([\w-]{2,})", text, re.IGNORECASE)
        if m and "keyword" not in params:
            params["keyword"] = m.group(1)
        return params

    patterns = (
        Pattern(r"(https?://[\w./-]+)", "Ressource cloud exposee: {0}", "high", "Stockage potentiellement public."),
    )


class EmailharvesterTool(SpecTool):
    name = "emailharvester"
    binary = "EmailHarvester"
    risk = "medium"
    target_params = ("domain",)
    description = "Collecte les adresses e-mail liees a un domaine (moteurs + PGP)."
    examples = ("collecte les emails de example.com avec emailharvester",)
    parameters = (
        ParameterSpec("domain", "Domaine cible (-d)", "string", required=True),
        ParameterSpec("limit", "Limite de resultats (-l)", "int"),
    )
    options = (Option("domain", "-d"), Option("limit", "-l"))
    patterns = (Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "Adresse collectee: {0}", "info"),)


class GoofileTool(SpecTool):
    name = "goofile"
    binary = "goofile"
    risk = "low"
    target_params = ("domain",)
    description = "Recherche des fichiers exposes d'un type donne sur un domaine."
    examples = ("cherche les pdf de example.com avec goofile",)
    parameters = (
        ParameterSpec("domain", "Domaine cible (-d)", "string", required=True),
        ParameterSpec("ext", "Extension recherchee (-f)", "string"),
    )
    options = (Option("domain", "-d"), Option("ext", "-f"))
    patterns = (Pattern(r"(https?://\S+\.\w{2,4})", "Fichier expose: {0}", "medium"),)


class InspyTool(SpecTool):
    name = "inspy"
    binary = "inspy"
    risk = "low"
    description = "Analyse un profil LinkedIn public (informations d'entreprise)."
    examples = ("analyse le profil linkedin de example avec inspy",)
    parameters = (ParameterSpec("target", "Identifiant du profil", "string", required=True),)
    positionals = (Positional("target"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"profil\s+\S+\s+de\s+([\w.-]{2,})", text, re.IGNORECASE) or re.search(r"\bde\s+([\w.-]{2,})", text, re.IGNORECASE)
        if m and "target" not in params:
            params["target"] = m.group(1)
        return params

    patterns = (Pattern(r"\S+", "Element de profil: {0}", "info"),)


class InstaloaderTool(SpecTool):
    name = "instaloader"
    binary = "instaloader"
    risk = "medium"
    description = "Collecte des metadonnees de profils Instagram publics."
    examples = ("collecte le profil instagram de example avec instaloader",)
    parameters = (
        ParameterSpec("profile", "Profil cible", "string", required=True),
        ParameterSpec("metadata", "Metadonnees uniquement (--no-pictures)", "bool", default=False),
    )
    flags = (Flag("metadata", "--no-pictures"),)
    positionals = (Positional("profile"),)
    order = ("flags", "positionals")

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"profil\s+\S+\s+de\s+([\w.-]{2,})", text, re.IGNORECASE) or re.search(r"\bde\s+([\w.-]{2,})", text, re.IGNORECASE)
        if m and "profile" not in params:
            params["profile"] = m.group(1)
        return params

    patterns = (Pattern(r"Downloaded|profile", "Profil collecte", "info"),)


class MetagoofilTool(SpecTool):
    name = "metagoofil"
    binary = "metagoofil"
    risk = "medium"
    target_params = ("domain",)
    description = "Collecte et analyse les metadonnees de documents publics d'un domaine."
    examples = ("extrait les metadonnees des documents de example.com avec metagoofil",)
    parameters = (
        ParameterSpec("domain", "Domaine cible (-d)", "string", required=True),
        ParameterSpec("filetypes", "Types de fichiers (-t)", "string"),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("domain", "-d"), Option("filetypes", "-t"), Option("output", "-o"))
    patterns = (
        Pattern(r"\[(?:User|Software|Author)\]\s*:?\s*(.+)", "Metadonnee: {0}", "medium"),
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "Compte dans un document: {0}", "info"),
    )


class OsrframeworkTool(SpecTool):
    name = "osrframework"
    binary = "usufy"
    risk = "medium"
    description = "Recherche un pseudonyme sur de nombreux sites (OSRFramework/usufy)."
    examples = ("recherche le pseudo example avec osrframework",)
    parameters = (ParameterSpec("nickname", "Pseudonyme", "string", required=True),)
    positionals = (Positional("nickname"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\b(?:pseudo|pseudonyme|nick)\s+([\w.-]{2,})", text, re.IGNORECASE)
        if m and "nickname" not in params:
            params["nickname"] = m.group(1)
        return params

    patterns = (Pattern(r"(https?://\S+)", "Compte trouve: {0}", "info"),)


class CensysTool(SpecTool):
    name = "python3-censys"
    aliases = ("censys",)
    binary = "censys"
    risk = "medium"
    target_params = ("query",)
    description = "Interroge Censys (services et certificats exposes sur Internet)."
    examples = ("cherche example.com sur censys avec python3-censys",)
    parameters = (
        ParameterSpec("query", "Requete de recherche", "string", required=True),
        ParameterSpec("index", "Index (hosts|certificates)", "string"),
    )
    options = (Option("index", "--index"),)
    positionals = (Positional("query"),)
    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Adresse exposee: {0}", "info"),
        Pattern(r"port\s*:?\s*(\d{1,5})", "Port expose: {0}", "info"),
    )


class ShodanTool(SpecTool):
    name = "python3-shodan"
    aliases = ("shodan",)
    binary = "shodan"
    risk = "medium"
    target_params = ("query",)
    description = "Interroge Shodan (services exposes, bannieres, vulnerabilites)."
    examples = ("cherche example.com sur shodan avec python3-shodan",)
    parameters = (ParameterSpec("query", "Requete de recherche", "string", required=True),)
    positionals = (Positional("query"),)
    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Adresse exposee: {0}", "info"),
        Pattern(r"port\s*:?\s*(\d{1,5})", "Port expose: {0}", "info"),
    )


class SherlockTool(SpecTool):
    name = "sherlock"
    binary = "sherlock"
    risk = "medium"
    description = "Traque un pseudonyme sur des centaines de reseaux sociaux."
    examples = ("traque le pseudo example avec sherlock",)
    parameters = (ParameterSpec("username", "Pseudonyme", "string", required=True),)
    positionals = (Positional("username"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\b(?:pseudo|pseudonyme|nick|username)\s+([\w.-]{2,})", text, re.IGNORECASE)
        if m and "username" not in params:
            params["username"] = m.group(1)
        return params

    patterns = (Pattern(r"(https?://\S+)", "Compte trouve: {0}", "info"),)


class SpiderfootTool(SpecTool):
    name = "spiderfoot"
    binary = "spiderfoot"
    risk = "medium"
    target_params = ("target",)
    description = "Automatise l'OSINT: collecte multi-sources sur une cible."
    examples = ("lance une reconnaissance osint sur example.com avec spiderfoot",)
    parameters = (
        ParameterSpec("target", "Cible (-s)", "string", required=True),
        ParameterSpec("scan", "Type de scan (-t)", "string"),
    )
    options = (Option("target", "-s"), Option("scan", "-t"))
    patterns = (
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "E-mail: {0}", "info"),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Adresse: {0}", "info"),
    )


class TheharvesterTool(SpecTool):
    name = "theharvester"
    binary = "theHarvester"
    risk = "medium"
    target_params = ("domain",)
    description = "Collecte emails, hotes et sous-domaines via des sources publiques."
    examples = ("collecte les emails de example.com avec theharvester",)
    parameters = (
        ParameterSpec("domain", "Domaine cible (-d)", "string", required=True),
        ParameterSpec("source", "Source (-b), ex: bing", "string"),
        ParameterSpec("limit", "Limite de resultats (-l)", "int"),
    )
    options = (Option("domain", "-d"), Option("source", "-b"), Option("limit", "-l"))
    patterns = (
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "E-mail: {0}", "info"),
        Pattern(r"([\w.-]+\.\w{2,})", "Hote: {0}", "info"),
    )


class Enum4linuxTool(SpecTool):
    name = "enum4linux"
    binary = "enum4linux"
    risk = "medium"
    description = "Enumere les partages, utilisateurs et groupes d'un hote SMB Windows."
    examples = ("enumere les partages smb de 10.0.0.5 avec enum4linux",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("all", "Enumeration complete (-a)", "bool", default=False),
    )
    flags = (Flag("all", "-a"),)
    positionals = (Positional("host"),)
    order = ("flags", "positionals")
    target_params = ("host",)
    patterns = (
        Pattern(r"Sharename\s+(\S+)", "Partage SMB: {0}", "medium"),
        Pattern(r"user:\[([^\]]+)\]", "Utilisateur: {0}", "info"),
        Pattern(r"Password:\s*(\S+)", "Mot de passe trouve: {0}", "high", "Secret expose."),
    )


class Enum4linuxNgTool(SpecTool):
    name = "enum4linux-ng"
    binary = "enum4linux-ng"
    risk = "medium"
    description = "Version moderne d'enum4linux (sortie JSON, enumere SMB/LDAP)."
    examples = ("enumere les partages smb de 10.0.0.5 avec enum4linux-ng",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("all", "Enumeration complete (-A)", "bool", default=False),
    )
    flags = (Flag("all", "-A"),)
    positionals = (Positional("host"),)
    order = ("flags", "positionals")
    target_params = ("host",)
    patterns = (
        Pattern(r"Sharename\s+(\S+)", "Partage SMB: {0}", "medium"),
        Pattern(r"\[\+\]\s*(.+)", "Decouverte: {0}", "info"),
    )


class NbtscanTool(SpecTool):
    name = "nbtscan"
    binary = "nbtscan"
    risk = "medium"
    description = "Enumere les noms NetBIOS des hotes d'un reseau."
    examples = ("enumere les noms netbios de 10.0.0.0/24 avec nbtscan",)
    parameters = (ParameterSpec("target", "Plage ou hote", "string", required=True),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)", "NetBIOS: {0} -> {1}", "info"),
    )


class PolenumTool(SpecTool):
    name = "polenum"
    binary = "polenum"
    risk = "medium"
    description = "Recupere la politique de mots de passe d'un domaine Windows."
    examples = ("recupere la politique de mot de passe de 10.0.0.5 avec polenum",)
    parameters = (ParameterSpec("host", "Hote cible", "string", required=True),)
    positionals = (Positional("host"),)
    target_params = ("host",)
    patterns = (
        Pattern(r"Minimum password length:\s*(\d+)", "Longueur minimale: {0}", "info"),
        Pattern(r"Lockout Threshold:\s*(\S+)", "Seuil de verrouillage: {0}", "info"),
    )


class SmbmapTool(SpecTool):
    name = "smbmap"
    binary = "smbmap"
    risk = "medium"
    description = "Liste les partages SMB accessibles et les permissions."
    examples = ("liste les partages smb de 10.0.0.5 avec smbmap",)
    parameters = (
        ParameterSpec("host", "Hote cible (-H)", "string", required=True),
        ParameterSpec("user", "Utilisateur (-u)", "string"),
        ParameterSpec("password", "Mot de passe (-p)", "string"),
    )
    options = (Option("host", "-H"), Option("user", "-u"), Option("password", "-p"))
    target_params = ("host",)
    patterns = (
        Pattern(r"(\S+)\s+READ,\s*WRITE", "Partage accessible en ecriture: {0}", "high", "Ecriture sur partage."),
        Pattern(r"(\S+)\s+READ ONLY", "Partage lisible: {0}", "medium"),
    )


class IsmtpTool(SpecTool):
    name = "ismtp"
    binary = "ismtp"
    risk = "medium"
    target_params = ("host",)
    description = "Teste les relais SMTP ouverts et l'enumeration d'utilisateurs."
    examples = ("teste le relais smtp de 10.0.0.5 avec ismtp",)
    parameters = (
        ParameterSpec("host", "Serveur SMTP (-h)", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("wordlist", "Liste de mots (-f)", "string"),
    )
    options = (Option("host", "-h"), Option("port", "-p"), Option("wordlist", "-f"))
    patterns = (
        Pattern(r"250|OK", "Utilisateur valide: {0}", "info"),
        Pattern(r"relay|open relay", "Relais ouvert detecte", "high", "Le serveur peut relayer du spam."),
    )


class SmtpUserEnumTool(SpecTool):
    name = "smtp-user-enum"
    binary = "smtp-user-enum"
    risk = "medium"
    description = "Enumere les comptes valides d'un serveur SMTP (VRFY/EXPN/RCPT)."
    examples = ("enumere les utilisateurs smtp de 10.0.0.5 avec smtp-user-enum",)
    parameters = (
        ParameterSpec("host", "Serveur SMTP (-t)", "string", required=True),
        ParameterSpec("mode", "Methode (-M), ex: VRFY", "string"),
        ParameterSpec("users", "Fichier d'utilisateurs (-U)", "string"),
    )
    options = (Option("host", "-t"), Option("mode", "-M"), Option("users", "-U"))
    target_params = ("host",)
    patterns = (
        Pattern(r"(\S+)@\S+\s+exists", "Utilisateur valide: {0}", "medium"),
        Pattern(r"\d+\s+users found", "Utilisateurs enumeres: {0}", "medium"),
    )


class SwaksTool(SpecTool):
    name = "swaks"
    binary = "swaks"
    risk = "medium"
    description = "Teste un serveur SMTP: envoi, authentification, TLS."
    examples = ("teste l'envoi smtp vers 10.0.0.5 avec swaks",)
    parameters = (
        ParameterSpec("host", "Serveur SMTP (--server)", "string", required=True),
        ParameterSpec("to", "Destinataire (--to)", "string"),
        ParameterSpec("port", "Port (--port)", "string"),
    )
    options = (Option("host", "--server"), Option("to", "--to"), Option("port", "--port"))
    target_params = ("host",)
    patterns = (
        Pattern(r"AUTH|LOGIN|PLAIN", "Authentification SMTP proposee: {0}", "medium"),
        Pattern(r"STARTTLS", "STARTTLS disponible", "info"),
    )


class BraaTool(SpecTool):
    name = "braa"
    binary = "braa"
    risk = "medium"
    target_params = ("target",)
    description = "Interroge massivement des equipements SNMP (OID en parallele)."
    examples = ("interroge le snmp de 10.0.0.5 avec braa",)
    parameters = (
        ParameterSpec("target", "Cible et OID (community@host)", "string", required=True),
        ParameterSpec("timeout", "Timeout (-t)", "int"),
    )
    positionals = (Positional("target"),)
    options = (Option("timeout", "-t"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"=\s*(.+)", "Valeur OID: {0}", "info"),
        Pattern(r"timeout|no response", "Equipement injoignable", "low"),
    )


class OnesixtyoneTool(SpecTool):
    name = "onesixtyone"
    binary = "onesixtyone"
    risk = "medium"
    description = "Decouvre les communautes SNMP par defaut d'un parc d'equipements."
    examples = ("decouvre les communautes snmp de 10.0.0.5 avec onesixtyone",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("community", "Fichier de communautes (-c)", "string"),
    )
    options = (Option("community", "-c"),)
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (
        Pattern(r"\[([^\]]+)\]", "Communaute SNMP valide: {0}", "high", "Communaute par defaut acceptee."),
    )


class SnmpcheckTool(SpecTool):
    name = "snmpcheck"
    binary = "snmpcheck"
    risk = "medium"
    description = "Recupere les informations systeme exposees en SNMP."
    examples = ("enumere le snmp de 10.0.0.5 avec snmpcheck",)
    parameters = (ParameterSpec("host", "Hote cible (-t)", "string", required=True),)
    options = (Option("host", "-t"),)
    target_params = ("host",)
    patterns = (
        Pattern(r"System information|sysDescr", "Information systeme exposee", "medium"),
        Pattern(r"Processes|Interfaces", "Details exposes: {0}", "info"),
    )


for _tool in (
    AmassTool(), CertgraphTool(), DnsenumTool(), DnsmapTool(), DnstracerTool(),
    DnswalkTool(), FierceTool(), UrlcrazyTool(),
    AssetfinderTool(), BingIp2HostsTool(), CloudEnumTool(), EmailharvesterTool(),
    GoofileTool(), InspyTool(), InstaloaderTool(), MetagoofilTool(),
    OsrframeworkTool(), CensysTool(), ShodanTool(), SherlockTool(),
    SpiderfootTool(), TheharvesterTool(),
    Enum4linuxTool(), Enum4linuxNgTool(), NbtscanTool(), PolenumTool(), SmbmapTool(),
    IsmtpTool(), SmtpUserEnumTool(), SwaksTool(),
    BraaTool(), OnesixtyoneTool(), SnmpcheckTool(),
):
    register(_tool)
