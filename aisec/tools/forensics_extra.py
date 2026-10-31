"""Classe 11 - Digital Forensics : imagerie, carving et journaux.

Sous-categories couvertes:
  - 11-forensics (direct)        : autopsy, inetsim, mc, missidentify, procdump,
                                   pst-utils, undbx, unhide, xplico
  - 11-08-forensic-suites        : grokevt
  - 11-05-forensic-carving-tools : ext3grep, ext4magic, magicrescue, myrescue,
                                   pasco, pev, recoverdm, recoverjpeg, rifiuti,
                                   rifiuti2, safecopy, scrounge-ntfs
  - 11-07-forensic-imaging-tools : afflib-tools, dcfldd, ewf-tools, guymager

L'acquisition et l'analyse de preuves sont non destructives: la plupart des
outils sont en `medium`. La restauration de fichiers supprimes ecrit sur disque
et reste `medium` (a destination explicite).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, SpecTool


# --------------------------------------------------------------------------
# Suites / analyse generale
# --------------------------------------------------------------------------
class AutopsyTool(SpecTool):
    name = "autopsy"
    binary = "autopsy"
    risk = "medium"
    description = "Plateforme d'investigation numerique (interface web sur Sleuth Kit)."
    examples = ("lance autopsy sur le port 9999",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (-p)", "string"),
        ParameterSpec("image", "Image a analyser (-d)", "string"),
    )
    options = (Option("port", "-p"), Option("image", "-d"))
    patterns = (Pattern(r"listening|started", "Autopsy demarre sur le port {0}", "info"),)


class InetsimTool(SpecTool):
    name = "inetsim"
    binary = "inetsim"
    risk = "medium"
    description = "Simule des services reseau pour analyser un malware en sandbox."
    examples = ("lance inetsim pour analyser un malware",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("output", "Repertoire de sortie (-l)", "string"),
    )
    options = (Option("config", "-c"), Option("output", "-l"))
    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Connexion simulee: {0}", "info"),
    )


class McCarverTool(SpecTool):
    name = "mc"
    binary = "mc"
    risk = "low"
    description = "Gestionnaire de fichiers en mode texte (inspection d'images)."
    examples = ("ouvre mc sur le repertoire /mnt/image",)
    parameters = (ParameterSpec("path", "Repertoire a inspecter", "string"),)
    positionals = (Positional("path"),)
    patterns = (Pattern(r"\S+", "Entree: {0}", "info"),)


class MissidentifyTool(SpecTool):
    name = "missidentify"
    binary = "missidentify"
    risk = "low"
    description = "Identifie des executables par leur signature, meme renommes."
    examples = ("identifie les executables de /mnt/image avec missidentify",)
    parameters = (ParameterSpec("path", "Repertoire ou image", "string", required=True),)
    positionals = (Positional("path"),)
    patterns = (
        Pattern(r"(\S+\.exe)", "Executable identifie: {0}", "info"),
    )


class ProcdumpTool(SpecTool):
    name = "procdump"
    binary = "procdump"
    risk = "high"
    description = "Extrait les executables d'un dump memoire Windows (Volatility)."
    examples = ("extrait les executables du dump memory.dmp avec procdump",)
    parameters = (
        ParameterSpec("dump", "Dump memoire", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("dump"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Process:\s*(\S+)", "Processus extrait: {0}", "medium"),
    )


class PstUtilsTool(SpecTool):
    name = "pst-utils"
    binary = "readpst"
    risk = "medium"
    description = "Lit et convertit les fichiers Outlook PST (courriels, contacts)."
    examples = ("convertit le fichier archive.pst avec pst-utils",)
    parameters = (
        ParameterSpec("pst", "Fichier PST", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("pst"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Storing|Exporting", "Message exporte", "info"),
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "Expediteur/destinataire: {0}", "info"),
    )


class UndbxTool(SpecTool):
    name = "undbx"
    binary = "undbx"
    risk = "medium"
    description = "Extrait les messages d'une boite Outlook Express (DBX)."
    examples = ("extrait les messages de boite.dbx avec undbx",)
    parameters = (
        ParameterSpec("dbx", "Fichier DBX", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("dbx"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"(\d+)\s+messages", "Messages extraits: {0}", "info"),)


class UnhideTool(SpecTool):
    name = "unhide"
    binary = "unhide"
    risk = "medium"
    description = "Detecte les processus et ports caches (rootkits)."
    examples = ("detecte les processus caches avec unhide",)
    parameters = (
        ParameterSpec("mode", "Mode (-m), ex: brute", "string"),
        ParameterSpec("quick", "Mode rapide (-q)", "bool", default=False),
    )
    options = (Option("mode", "-m"),)
    flags = (Flag("quick", "-q"),)
    patterns = (
        Pattern(r"Found hidden|hidden pid", "Element cache detecte: {0}", "high", "Indice de rootkit."),
    )


class XplicoTool(SpecTool):
    name = "xplico"
    binary = "xplico"
    risk = "medium"
    description = "Reconstruit le contenu applicatif (HTTP, mail) d'une capture pcap."
    examples = ("reconstruit le contenu de capture.pcap avec xplico",)
    parameters = (
        ParameterSpec("pcap", "Capture pcap", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("pcap"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"GET|POST", "Requete reconstituee: {0}", "info"),
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "Adresse reconstituee: {0}", "medium"),
    )


class GrokevtTool(SpecTool):
    name = "grokevt"
    binary = "grokevt-ripdll"
    risk = "medium"
    description = "Parse les journaux d'evenements Windows (EVT) d'un disque."
    examples = ("parse les journaux evt de /mnt/image avec grokevt",)
    parameters = (ParameterSpec("path", "Repertoire des journaux EVT", "string", required=True),)
    positionals = (Positional("path"),)
    patterns = (
        Pattern(r"Event ID\s*:?\s*(\d+)", "Evenement: {0}", "info"),
    )


for _tool in (
    AutopsyTool(), InetsimTool(), McCarverTool(), MissidentifyTool(), ProcdumpTool(),
    PstUtilsTool(), UndbxTool(), UnhideTool(), XplicoTool(), GrokevtTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Carving / recuperation
# --------------------------------------------------------------------------
class Ext3grepTool(SpecTool):
    name = "ext3grep"
    binary = "ext3grep"
    risk = "medium"
    description = "Recupere des fichiers supprimes sur un volume ext3."
    examples = ("recupere les fichiers supprimes de /dev/sdb1 avec ext3grep",)
    parameters = (
        ParameterSpec("device", "Volume ext3", "string", required=True),
        ParameterSpec("inode", "Inode a restaurer (--restore-inode)", "string"),
        ParameterSpec("output", "Repertoire de restauration (--restore-file)", "string"),
    )
    positionals = (Positional("device"),)
    options = (Option("inode", "--restore-inode"), Option("output", "--restore-file"))
    order = ("options", "positionals")
    patterns = (
        Pattern(r"Restoring|found", "Fichier recupere: {0}", "info"),
    )


class Ext4magicTool(SpecTool):
    name = "ext4magic"
    binary = "ext4magic"
    risk = "medium"
    description = "Recupere des fichiers supprimes sur un volume ext4."
    examples = ("recupere les fichiers supprimes de /dev/sdb1 avec ext4magic",)
    parameters = (
        ParameterSpec("device", "Volume ext4", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-d)", "string"),
        ParameterSpec("recover", "Recuperation (-r)", "bool", default=False),
    )
    flags = (Flag("recover", "-r"),)
    positionals = (Positional("device"),)
    options = (Option("output", "-d"),)
    order = ("options", "flags", "positionals")
    patterns = (
        Pattern(r"Recovering|restored", "Fichier recupere: {0}", "info"),
    )


class MagicrescueTool(SpecTool):
    name = "magicrescue"
    binary = "magicrescue"
    risk = "medium"
    description = "Carving par signatures: recupere des fichiers d'un volume."
    examples = ("carve l'image image.dd avec magicrescue",)
    parameters = (
        ParameterSpec("device", "Image ou volume (-d)", "string", required=True),
        ParameterSpec("recipes", "Recettes (-r)", "string"),
        ParameterSpec("output", "Repertoire de sortie (-M)", "string"),
    )
    options = (Option("device", "-d"), Option("recipes", "-r"), Option("output", "-M"))
    patterns = (
        Pattern(r"Found\s+\S+\s+at\s+(\d+)", "Fichier trouve a l'offset {0}", "info"),
    )


class MyrescueTool(SpecTool):
    name = "myrescue"
    binary = "myrescue"
    risk = "medium"
    description = "Image un disque en sautant les zones illisibles (disque mourant)."
    examples = ("image le disque /dev/sdb vers rescue.img avec myrescue",)
    parameters = (
        ParameterSpec("device", "Disque source", "string", required=True),
        ParameterSpec("image", "Image de sortie", "string", required=True),
    )
    positionals = (Positional("device"), Positional("image"))
    patterns = (
        Pattern(r"(\d+)\s+bytes", "Octets lus: {0}", "info"),
        Pattern(r"bad|error", "Secteur illisible rencontre", "medium"),
    )


class PascoTool(SpecTool):
    name = "pasco"
    binary = "pasco"
    risk = "low"
    description = "Analyse l'historique Internet d'IE (fichier index.dat)."
    examples = ("analyse index.dat avec pasco",)
    parameters = (
        ParameterSpec("index", "Fichier index.dat", "string", required=True),
        ParameterSpec("output", "Fichier CSV de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("index"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"(https?://\S+)", "URL visitee: {0}", "info"),
    )


class PevTool(SpecTool):
    name = "pev"
    binary = "pev"
    risk = "low"
    description = "Analyse les executables Windows PE (en-tetes, sections, signatures)."
    examples = ("analyse le binaire sample.exe avec pev",)
    parameters = (ParameterSpec("binary", "Executable PE", "string", required=True),)
    positionals = (Positional("binary"),)
    patterns = (
        Pattern(r"TimeDateStamp\s*:?\s*(.+)", "Date de compilation: {0}", "info"),
        Pattern(r"Suspicious|packed|UPX", "Binaire suspect: {0}", "medium"),
    )


class RecoverdmTool(SpecTool):
    name = "recoverdm"
    binary = "recoverdm"
    risk = "medium"
    description = "Recupere des fichiers d'un CD/DVD ou d'un disque abime."
    examples = ("recupere les fichiers de /dev/sr0 avec recoverdm",)
    parameters = (
        ParameterSpec("device", "Peripherique source (-d)", "string", required=True),
        ParameterSpec("output", "Image de sortie (-o)", "string"),
    )
    options = (Option("device", "-d"), Option("output", "-o"))
    patterns = (Pattern(r"(\d+)\s+sectors", "Secteurs lus: {0}", "info"),)


class RecoverjpegTool(SpecTool):
    name = "recoverjpeg"
    binary = "recoverjpeg"
    risk = "medium"
    description = "Recupere les images JPEG d'un disque ou d'une image."
    examples = ("recupere les images de image.dd avec recoverjpeg",)
    parameters = (
        ParameterSpec("device", "Image ou peripherique", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("device"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"(\d+)\s+images", "Images recuperees: {0}", "info"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.(?:dd|img|raw)\b", text, re.IGNORECASE)
        if m:
            params["device"] = m.group(0)
        return params


class RifiutiTool(SpecTool):
    name = "rifiuti"
    binary = "rifiuti"
    risk = "low"
    description = "Parse la corbeille Windows (INFO2) d'un disque."
    examples = ("parse la corbeille INFO2 de /mnt/image avec rifiuti",)
    parameters = (ParameterSpec("info2", "Fichier INFO2", "string", required=True),)
    positionals = (Positional("info2"),)
    patterns = (Pattern(r"(\S+\.\w{2,4})", "Fichier en corbeille: {0}", "info"),)


class Rifiuti2Tool(SpecTool):
    name = "rifiuti2"
    binary = "rifiuti2"
    risk = "low"
    description = "Version moderne de rifiuti (corbeille Windows $Recycle.Bin)."
    examples = ("parse la corbeille $Recycle.Bin de /mnt/image avec rifiuti2",)
    parameters = (ParameterSpec("path", "Fichier $I ou repertoire", "string", required=True),)
    positionals = (Positional("path"),)
    patterns = (Pattern(r"(\S+\.\w{2,4})", "Fichier en corbeille: {0}", "info"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"(/\S+)", text)
        if m:
            params["path"] = m.group(1)
        return params


class SafecopyTool(SpecTool):
    name = "safecopy"
    binary = "safecopy"
    risk = "medium"
    description = "Copie une source abimee en tolerant les erreurs de lecture."
    examples = ("copie /dev/sdb vers rescue.img avec safecopy",)
    parameters = (
        ParameterSpec("source", "Source", "string", required=True),
        ParameterSpec("output", "Destination (-o)", "string", required=True),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("source"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"(\d+)\s+bytes", "Octets copies: {0}", "info"),
        Pattern(r"error|bad sector", "Erreur de lecture toleree", "medium"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        src = re.search(r"(/dev/\S+)", text)
        if src:
            params["source"] = src.group(1)
        out = re.search(r"\S+\.img\b", text, re.IGNORECASE)
        if out:
            params["output"] = out.group(0)
        return params


class ScroungeNtfsTool(SpecTool):
    name = "scrounge-ntfs"
    binary = "scrounge-ntfs"
    risk = "medium"
    description = "Recupere des donnees d'un volume NTFS endommage."
    examples = ("recupere les fichiers de /dev/sdb1 avec scrounge-ntfs",)
    parameters = (
        ParameterSpec("device", "Volume NTFS", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("start", "Secteur de debut (-s)", "string"),
    )
    options = (Option("output", "-o"), Option("start", "-s"))
    positionals = (Positional("device"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"(\S+)\s+recovered", "Fichier recupere: {0}", "info"),
    )


for _tool in (
    Ext3grepTool(), Ext4magicTool(), MagicrescueTool(), MyrescueTool(), PascoTool(),
    PevTool(), RecoverdmTool(), RecoverjpegTool(), RifiutiTool(), Rifiuti2Tool(),
    SafecopyTool(), ScroungeNtfsTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Imagerie
# --------------------------------------------------------------------------
class AfflibToolsTool(SpecTool):
    name = "afflib-tools"
    binary = "affconvert"
    risk = "medium"
    description = "Convertit et verifie les images disque au format AFF."
    examples = ("convertit image.dd en aff avec afflib-tools",)
    parameters = (
        ParameterSpec("source", "Image source", "string", required=True),
        ParameterSpec("output", "Image AFF de sortie (-O)", "string"),
    )
    options = (Option("output", "-O"),)
    positionals = (Positional("source"),)
    order = ("options", "positionals")
    patterns = (Pattern(r"converted|wrote", "Image convertie: {0}", "info"),)


class DcflddTool(SpecTool):
    name = "dcfldd"
    binary = "dcfldd"
    risk = "medium"
    description = "Image disque avec hachage et progression (successeur de dd)."
    examples = ("image le disque /dev/sdb vers disk.img avec dcfldd",)
    source_hint = "/dev/sdb"
    parameters = (
        ParameterSpec("source", "Source (if=)", "string", required=True),
        ParameterSpec("output", "Destination (of=)", "string", required=True),
        ParameterSpec("hash", "Hachage (hash=), ex: sha256", "string"),
    )
    options = (Option("hash", "hash="),)
    positionals = (Positional("source"), Positional("output"))
    order = ("options", "positionals")
    patterns = (
        Pattern(r"(\d+)\s+bytes", "Octets copies: {0}", "info"),
        Pattern(r"Total.*?\s([0-9a-f]{32,})", "Empreinte de l'image: {0}", "info"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dcfldd"]
        if params.get("hash"):
            argv.append(f"hash={params['hash']}")
        if params.get("source"):
            argv.append(f"if={params['source']}")
        if params.get("output"):
            argv.append(f"of={params['output']}")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        out = re.search(r"\S+\.img\b", text, re.IGNORECASE)
        if out:
            params["output"] = out.group(0)
        src = re.search(r"(/dev/\S+)", text)
        if src:
            params["source"] = src.group(1)
        return params


class EwfToolsTool(SpecTool):
    name = "ewf-tools"
    binary = "ewfacquire"
    risk = "medium"
    description = "Acquiert et verifie les images disque au format Expert Witness (E01)."
    examples = ("cree une image e01 de /dev/sdb avec ewf-tools",)
    parameters = (
        ParameterSpec("source", "Source", "string", required=True),
        ParameterSpec("target", "Fichier cible (-t)", "string"),
        ParameterSpec("compression", "Niveau de compression (-c)", "string"),
    )
    options = (Option("target", "-t"), Option("compression", "-c"))
    positionals = (Positional("source"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"acquired|Written", "Image E01 creee: {0}", "info"),
        Pattern(r"MD5|SHA1", "Empreinte de l'image: {0}", "info"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"(/dev/\S+)", text)
        if m:
            params["source"] = m.group(1)
        return params


class GuymagerTool(SpecTool):
    name = "guymager"
    binary = "guymager"
    risk = "medium"
    description = "Interface graphique d'acquisition d'images disque (E01, dd)."
    examples = ("lance guymager pour acquerir une image",)
    parameters = (
        ParameterSpec("source", "Peripherique source", "string"),
        ParameterSpec("target", "Fichier cible", "string"),
    )
    positionals = (Positional("source"),)
    patterns = (Pattern(r"acquired|completed", "Acquisition terminee", "info"),)


for _tool in (
    AfflibToolsTool(), DcflddTool(), EwfToolsTool(), GuymagerTool(),
):
    register(_tool)
