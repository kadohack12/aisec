"""Classe 05 - Password Attacks : outils complementaires.

Sous-categories couvertes:
  - 05-01-online-attacks : brutespray, changeme, crowbar, device-pharmer,
                           gpp-decrypt, hydra-gtk, maskprocessor,
                           statsprocessor, thc-pptp-bruter
  - 05-02-offline-attacks: bruteforce-salted-openssl, crackle, fcrackzip,
                           multiforcer, pdfcrack, rainbowcrack, rarcrack,
                           rcracki-mt, sipcrack, sucrack, truecrack
  - 05-03-local-attacks  : bruteforce-luks, cmospwd, creddump7,
                           passing-the-hash
  - 05-05-profile        : pipal, seclists, twofi, username-anarchy,
                           wordlists

Le cassage de mots de passe est intrusif: la majorite de ces outils est classee
`high` (confirmation obligatoire) et l'extraction de secrets locaux `critical`.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, SpecTool


# --------------------------------------------------------------------------
# Online attacks
# --------------------------------------------------------------------------
class BrutesprayTool(SpecTool):
    name = "brutespray"
    binary = "brutespray"
    risk = "high"
    description = "Rejoue des identifiants sur les services trouves par nmap (GNMAP)."
    examples = ("brute force les services du scan.gnmap avec brutespray",)
    parameters = (
        ParameterSpec("file", "Fichier GNMAP (-f)", "string", required=True),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("userlist", "Liste d'utilisateurs (-U)", "string"),
    )
    options = (Option("file", "-f"), Option("threads", "-t"), Option("userlist", "-U"))
    patterns = (
        Pattern(r"\[SUCCESS\]\s*(\S+)", "Identifiants valides: {0}", "high", "Acces obtenu."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.gnmap\b", text, re.IGNORECASE)
        if m:
            params["file"] = m.group(0)
        return params


class ChangemeTool(SpecTool):
    name = "changeme"
    binary = "changeme"
    risk = "high"
    description = "Detecte les identifiants par defaut sur de nombreux services."
    examples = ("detecte les identifiants par defaut de 10.0.0.5 avec changeme",)
    parameters = (
        ParameterSpec("target", "Cible", "string", required=True),
        ParameterSpec("protocol", "Protocole (-p)", "string"),
    )
    positionals = (Positional("target"),)
    options = (Option("protocol", "-p"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"Valid|success|default", "Identifiants par defaut: {0}", "high", "Compte par defaut actif."),
    )


class CrowbarTool(SpecTool):
    name = "crowbar"
    binary = "crowbar"
    risk = "high"
    description = "Brute force de services (SSH, RDP, SMB, VNC) sans dependances."
    examples = ("brute force le ssh de 10.0.0.5 avec crowbar",)
    parameters = (
        ParameterSpec("service", "Service (-b), ex: ssh", "string"),
        ParameterSpec("server", "Serveur (-s)", "string", required=True),
        ParameterSpec("user", "Utilisateur (-u)", "string"),
        ParameterSpec("wordlist", "Liste de mots (-C)", "string"),
    )
    options = (Option("service", "-b"), Option("server", "-s"), Option("user", "-u"), Option("wordlist", "-C"))
    target_params = ("server",)
    patterns = (
        Pattern(r"SUCCESS|found", "Mot de passe trouve: {0}", "high", "Acces obtenu."),
    )


class DevicePharmerTool(SpecTool):
    name = "device-pharmer"
    binary = "device-pharmer"
    risk = "high"
    description = "Teste les identifiants de cameras IP sur une plage (Shodan)."
    examples = ("teste les cameras ip de 10.0.0.0/24 avec device-pharmer",)
    parameters = (
        ParameterSpec("range", "Plage d'adresses", "string", required=True),
        ParameterSpec("threads", "Threads (-t)", "int"),
    )
    positionals = (Positional("range"),)
    options = (Option("threads", "-t"),)
    order = ("options", "positionals")
    target_params = ("range",)
    patterns = (
        Pattern(r"login|password|default", "Identifiants par defaut: {0}", "high"),
    )


class GppDecryptTool(SpecTool):
    name = "gpp-decrypt"
    binary = "gpp-decrypt"
    risk = "medium"
    description = "Dechiffre les mots de passe de preferences de groupe (cpassword)."
    examples = ("dechiffre le cpassword GPP avec gpp-decrypt",)
    parameters = (ParameterSpec("cpassword", "Chaîne cpassword", "string", required=True),)
    positionals = (Positional("cpassword"),)
    patterns = (
        Pattern(r"[\w!@#$%^&*()\-+=]{4,}", "Mot de passe dechiffre: {0}", "high", "Secret GPP revele."),
    )


class HydraGtkTool(SpecTool):
    name = "hydra-gtk"
    binary = "xhydra"
    risk = "high"
    description = "Interface graphique de hydra (brute force multi-protocole)."
    examples = ("lance l'interface graphique hydra avec hydra-gtk",)
    parameters = (
        ParameterSpec("target", "Cible", "string"),
        ParameterSpec("service", "Service", "string"),
    )
    positionals = (Positional("target"),)
    patterns = (Pattern(r"success|found", "Identifiants trouves", "high"),)


class MaskprocessorTool(SpecTool):
    name = "maskprocessor"
    binary = "mp64"
    risk = "medium"
    description = "Genere des mots de passe selon un masque (complement de hashcat)."
    examples = ("genere les mots de passe ?d?d?d?d avec maskprocessor",)
    parameters = (
        ParameterSpec("mask", "Masque (ex: ?d?d?d?d)", "string", required=True),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    positionals = (Positional("mask"),)
    options = (Option("output", "-o"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"\S+", "Mot genere: {0}", "info"),)


class StatsprocessorTool(SpecTool):
    name = "statsprocessor"
    binary = "sp64"
    risk = "medium"
    description = "Genere des candidats a partir de statistiques (Markov)."
    examples = ("genere des candidats depuis un hcstat avec statsprocessor",)
    parameters = (
        ParameterSpec("hcstat", "Fichier de statistiques", "string", required=True),
        ParameterSpec("mask", "Masque", "string"),
        ParameterSpec("limit", "Limite (-n)", "int"),
    )
    positionals = (Positional("hcstat"), Positional("mask"))
    options = (Option("limit", "-n"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"\S+", "Candidat: {0}", "info"),)


class ThcPptpBruterTool(SpecTool):
    name = "thc-pptp-bruter"
    binary = "thc-pptp-bruter"
    risk = "high"
    description = "Brute force des identifiants VPN PPTP."
    examples = ("brute force le vpn pptp de 10.0.0.5 avec thc-pptp-bruter",)
    parameters = (
        ParameterSpec("target", "Serveur PPTP", "string", required=True),
        ParameterSpec("user", "Utilisateur (-u)", "string"),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
    )
    options = (Option("user", "-u"), Option("wordlist", "-w"))
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"login|password", "Identifiant VPN trouve: {0}", "high", "Acces VPN obtenu."),
    )


for _tool in (
    BrutesprayTool(), ChangemeTool(), CrowbarTool(), DevicePharmerTool(),
    GppDecryptTool(), HydraGtkTool(), MaskprocessorTool(), StatsprocessorTool(),
    ThcPptpBruterTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Offline attacks
# --------------------------------------------------------------------------
class BruteforceSaltedOpensslTool(SpecTool):
    name = "bruteforce-salted-openssl"
    binary = "bruteforce-salted-openssl"
    risk = "high"
    description = "Brute force un fichier chiffre par OpenSSL (sel + mot de passe)."
    examples = ("brute force le fichier secret.enc avec bruteforce-salted-openssl",)
    parameters = (
        ParameterSpec("file", "Fichier chiffre", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("cipher", "Chiffrement (-c)", "string"),
    )
    options = (Option("wordlist", "-w"), Option("cipher", "-c"))
    positionals = (Positional("file"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Password found:\s*(\S+)", "Mot de passe trouve: {0}", "high", "Fichier dechiffre."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:enc|aes|des)\b", text, re.IGNORECASE)
        if m:
            params["file"] = m.group(0)
        return params


class CrackleTool(SpecTool):
    name = "crackle"
    binary = "crackle"
    risk = "high"
    description = "Casse le chiffrement Bluetooth LE (TK/BLE) d'une capture."
    examples = ("casse la capture bluetooth capture.pcap avec crackle",)
    parameters = (
        ParameterSpec("pcap", "Capture BLE (pcap)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
    )
    options = (Option("wordlist", "-w"),)
    positionals = (Positional("pcap"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"TK found|key", "Cle BLE trouvee: {0}", "high", "Chiffrement BLE casse."),
    )


class FcrackzipTool(SpecTool):
    name = "fcrackzip"
    binary = "fcrackzip"
    risk = "high"
    description = "Casse le mot de passe d'une archive ZIP."
    examples = ("casse l'archive archive.zip avec fcrackzip",)
    parameters = (
        ParameterSpec("archive", "Archive ZIP", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-D -p)", "string"),
        ParameterSpec("brute", "Force brute (-b)", "bool", default=False),
    )
    flags = (Flag("brute", "-b"),)
    positionals = (Positional("archive"),)
    order = ("flags", "positionals")
    patterns = (
        Pattern(r"PASSWORD FOUND!!\s*(\S+)", "Mot de passe trouve: {0}", "high", "Archive ouverte."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.zip\b", text, re.IGNORECASE)
        if m:
            params["archive"] = m.group(0)
        return params


class MultiforcerTool(SpecTool):
    name = "multiforcer"
    binary = "multiforcer"
    risk = "high"
    description = "Force brute multi-algorithmes sur GPU (CPU/GPU)."
    examples = ("force brute le hash avec multiforcer",)
    parameters = (
        ParameterSpec("algorithm", "Algorithme (-a)", "string"),
        ParameterSpec("target", "Hash ou fichier (-t)", "string", required=True),
        ParameterSpec("charset", "Jeu de caracteres (-c)", "string"),
    )
    options = (Option("algorithm", "-a"), Option("target", "-t"), Option("charset", "-c"))
    patterns = (
        Pattern(r"found|Found", "Mot de passe trouve: {0}", "high", "Hash casse."),
    )


class PdfcrackTool(SpecTool):
    name = "pdfcrack"
    binary = "pdfcrack"
    risk = "high"
    description = "Recupere le mot de passe d'un PDF chiffre."
    examples = ("casse le pdf rapport.pdf avec pdfcrack",)
    parameters = (
        ParameterSpec("pdf", "Fichier PDF", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
    )
    options = (Option("wordlist", "-w"),)
    positionals = (Positional("pdf"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"found user-password:\s*'([^']*)'", "Mot de passe trouve: {0}", "high", "PDF ouvert."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pdf\b", text, re.IGNORECASE)
        if m:
            params["pdf"] = m.group(0)
        return params


class RainbowcrackTool(SpecTool):
    name = "rainbowcrack"
    binary = "rcrack"
    risk = "high"
    description = "Casse des hashes avec des tables arc-en-ciel."
    examples = ("casse le hash avec les tables arc-en-ciel avec rainbowcrack",)
    parameters = (
        ParameterSpec("tables", "Repertoire de tables", "string", required=True),
        ParameterSpec("hash", "Hash a casser (-h)", "string"),
    )
    positionals = (Positional("tables"),)
    options = (Option("hash", "-h"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"plaintext of\s*\S+\s*is\s*(\S+)", "Mot de passe trouve: {0}", "high", "Hash casse."),
    )


class RarcrackTool(SpecTool):
    name = "rarcrack"
    binary = "rarcrack"
    risk = "high"
    description = "Casse le mot de passe d'archives RAR/ZIP/7z."
    examples = ("casse l'archive archive.rar avec rarcrack",)
    parameters = (ParameterSpec("archive", "Archive chiffree", "string", required=True),)
    positionals = (Positional("archive"),)
    patterns = (
        Pattern(r"PASSWORD FOUND.*?:\s*(\S+)", "Mot de passe trouve: {0}", "high", "Archive ouverte."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:rar|7z|zip)\b", text, re.IGNORECASE)
        if m:
            params["archive"] = m.group(0)
        return params


class RcrackiMtTool(SpecTool):
    name = "rcracki-mt"
    binary = "rcracki_mt"
    risk = "high"
    description = "Version multithread de rcrack (tables arc-en-ciel)."
    examples = ("casse le hash avec rcracki-mt",)
    parameters = (
        ParameterSpec("tables", "Repertoire de tables", "string", required=True),
        ParameterSpec("hash", "Fichier de hashes (-h)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
    )
    positionals = (Positional("tables"),)
    options = (Option("hash", "-h"), Option("threads", "-t"))
    order = ("options", "positionals")
    patterns = (
        Pattern(r"plaintext of\s*\S+\s*is\s*(\S+)", "Mot de passe trouve: {0}", "high"),
    )


class SipcrackTool(SpecTool):
    name = "sipcrack"
    binary = "sipcrack"
    risk = "high"
    description = "Casse les identifiants d'authentification SIP captures."
    examples = ("casse la capture sip capture.pcap avec sipcrack",)
    parameters = (
        ParameterSpec("pcap", "Capture SIP", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
    )
    options = (Option("wordlist", "-w"),)
    positionals = (Positional("pcap"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"password:\s*(\S+)", "Mot de passe SIP trouve: {0}", "high", "Compte SIP compromis."),
    )


class SucrackTool(SpecTool):
    name = "sucrack"
    binary = "sucrack"
    risk = "high"
    description = "Brute force local via `su` (multithread)."
    examples = ("brute force le compte su root avec sucrack",)
    parameters = (
        ParameterSpec("wordlist", "Dictionnaire", "string", required=True),
        ParameterSpec("threads", "Threads (-w)", "int"),
        ParameterSpec("user", "Utilisateur (-u)", "string"),
    )
    positionals = (Positional("wordlist"),)
    options = (Option("threads", "-w"), Option("user", "-u"))
    order = ("options", "positionals")
    patterns = (
        Pattern(r"password is\s*(\S+)", "Mot de passe trouve: {0}", "critical", "Compte local compromis."),
    )


class TruecrackTool(SpecTool):
    name = "truecrack"
    binary = "truecrack"
    risk = "high"
    description = "Force brute les volumes TrueCrypt/VeraCrypt."
    examples = ("brute force le volume volume.tc avec truecrack",)
    parameters = (
        ParameterSpec("volume", "Volume chiffre", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("hash", "Type de hash (-H)", "string"),
    )
    options = (Option("wordlist", "-w"), Option("hash", "-H"))
    positionals = (Positional("volume"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Found password:\s*(\S+)", "Mot de passe trouve: {0}", "high", "Volume monte."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:tc|hc)\b", text, re.IGNORECASE)
        if m:
            params["volume"] = m.group(0)
        return params


for _tool in (
    BruteforceSaltedOpensslTool(), CrackleTool(), FcrackzipTool(), MultiforcerTool(),
    PdfcrackTool(), RainbowcrackTool(), RarcrackTool(), RcrackiMtTool(),
    SipcrackTool(), SucrackTool(), TruecrackTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Local attacks
# --------------------------------------------------------------------------
class BruteforceLuksTool(SpecTool):
    name = "bruteforce-luks"
    binary = "bruteforce-luks"
    risk = "high"
    description = "Force brute la phrase secrete d'un volume LUKS."
    examples = ("brute force le volume volume.luks avec bruteforce-luks",)
    parameters = (
        ParameterSpec("volume", "Volume LUKS", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
    )
    options = (Option("wordlist", "-w"), Option("threads", "-t"))
    positionals = (Positional("volume"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Password found:\s*(\S+)", "Phrase secrete trouvee: {0}", "high", "Volume dechiffre."),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:luks|img)\b", text, re.IGNORECASE)
        if m:
            params["volume"] = m.group(0)
        return params


class CmospwdTool(SpecTool):
    name = "cmospwd"
    binary = "cmospwd"
    risk = "high"
    description = "Recupere le mot de passe du BIOS depuis une sauvegarde CMOS."
    examples = ("recupere le mot de passe bios de cmos.bin avec cmospwd",)
    parameters = (
        ParameterSpec("dump", "Sauvegarde CMOS", "string", required=True),
        ParameterSpec("decrypt", "Dechiffrer (-d)", "bool", default=False),
    )
    flags = (Flag("decrypt", "-d"),)
    positionals = (Positional("dump"),)
    order = ("flags", "positionals")
    patterns = (
        Pattern(r"Password\s*:\s*(\S+)", "Mot de passe BIOS: {0}", "high", "Acces BIOS revele."),
    )


class Creddump7Tool(SpecTool):
    name = "creddump7"
    binary = "cachedump"
    risk = "critical"
    description = "Extrait les hashes de mots de passe Windows (SAM, LSA, cache)."
    examples = ("extrait les hashes du system et sam avec creddump7",)
    parameters = (
        ParameterSpec("system", "Ruche SYSTEM", "string", required=True),
        ParameterSpec("sam", "Ruche SAM", "string", required=True),
    )
    positionals = (Positional("system"), Positional("sam"))
    patterns = (
        Pattern(r"([0-9a-fA-F]{32}:[0-9a-fA-F]{32})", "Hash NTLM extrait: {0}", "critical", "Empreintes Windows revelees."),
    )


class PassingTheHashTool(SpecTool):
    name = "passing-the-hash"
    binary = "pth-winexe"
    risk = "critical"
    description = "Executes des commandes Windows a distance via un hash NTLM (PtH)."
    examples = ("executes une commande via passing-the-hash sur 10.0.0.5",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("hash", "Hash NTLM (--hash)", "string"),
        ParameterSpec("share", "Partage (-s)", "string"),
    )
    options = (Option("hash", "--hash"), Option("share", "-s"))
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"connected|access", "Acces distant etabli", "critical", "Authentification detournee."),
    )


for _tool in (
    BruteforceLuksTool(), CmospwdTool(), Creddump7Tool(), PassingTheHashTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Profile / wordlists
# --------------------------------------------------------------------------
class PipalTool(SpecTool):
    name = "pipal"
    binary = "pipal"
    risk = "medium"
    description = "Analyse statistique d'une liste de mots de passe (tendances)."
    examples = ("analyse la liste passwords.txt avec pipal",)
    parameters = (ParameterSpec("wordlist", "Liste de mots de passe", "string", required=True),)
    positionals = (Positional("wordlist"),)
    patterns = (
        Pattern(r"Total entries\s*=?\s*(\d+)", "Entrees analysees: {0}", "info"),
        Pattern(r"Top \d+ passwords", "Motifs recurrents detectes", "medium"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:txt|lst)\b", text, re.IGNORECASE)
        if m:
            params["wordlist"] = m.group(0)
        return params


class SeclistsTool(SpecTool):
    name = "seclists"
    binary = "seclists"
    risk = "low"
    description = "Collection de listes de mots (chemins, utilisateurs, fuzzing)."
    examples = ("liste les categories de listes seclists",)
    parameters = (ParameterSpec("category", "Categorie de listes", "string"),)
    positionals = (Positional("category"),)
    patterns = (Pattern(r"\S+\.txt", "Liste disponible: {0}", "info"),)


class TwofiTool(SpecTool):
    name = "twofi"
    binary = "twofi"
    risk = "medium"
    description = "Genere une liste de mots depuis les tendances Twitter."
    examples = ("genere une liste de mots depuis twitter avec twofi",)
    parameters = (
        ParameterSpec("term", "Terme de recherche (-t)", "string", required=True),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("term", "-t"), Option("output", "-o"))
    patterns = (Pattern(r"\S+", "Mot collecte: {0}", "info"),)


class UsernameAnarchyTool(SpecTool):
    name = "username-anarchy"
    binary = "username-anarchy"
    risk = "medium"
    description = "Genere des variantes de noms d'utilisateur a partir d'un nom."
    examples = ("genere des noms d'utilisateur pour Jean Dupont avec username-anarchy",)
    parameters = (
        ParameterSpec("name", "Nom complet", "string", required=True),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("name"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"\S+", "Nom d'utilisateur genere: {0}", "info"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"(?:pour|de)\s+([A-Za-zÀ-ÿ][\w'-]+(?:\s+[A-Za-zÀ-ÿ][\w'-]+)?)", text)
        if m:
            params["name"] = m.group(1)
        return params


class WordlistsTool(SpecTool):
    name = "wordlists"
    binary = "wordlists"
    risk = "low"
    description = "Fournit les listes de mots fournies par Kali/Parrot (inventaire)."
    examples = ("liste les listes de mots disponibles avec wordlists",)
    parameters = (ParameterSpec("pattern", "Motif de recherche", "string"),)
    positionals = (Positional("pattern"),)
    patterns = (Pattern(r"\S+", "Liste: {0}", "info"),)


for _tool in (
    PipalTool(), SeclistsTool(), TwofiTool(), UsernameAnarchyTool(), WordlistsTool(),
):
    register(_tool)
