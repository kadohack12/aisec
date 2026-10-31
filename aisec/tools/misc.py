"""Classe 15 - Autres (System Services / Utility / ...).

Couvre les services systeme (HTTP, base de donnees, SSH, Metasploit, OpenVAS),
l'outillage de developpement (arduino, powershell), la radio amateur (chirp),
la navigation (firefox, firefox-esr, nyx) et l'utilitaire (coreutils, gpa,
keepassxc, mat2, sirikali, woeusb-ng, zulucrypt-gui, zulumount-gui).

Les commandes de service (start/stop/restart) sont en `critical`: la politique
de controle de niveau 2 impose une confirmation avant toute execution.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_any_path
from .spec import Flag, Option, Pattern, Positional, Rule, SpecTool

_ACTION_FLAGS = ("start", "stop", "restart", "reload", "status", "enable", "disable")
_ACTION_WORDS = {
    "demarre": "start",
    "demarrer": "start",
    "lance": "start",
    "lancer": "start",
    "start": "start",
    "arrete": "stop",
    "arreter": "stop",
    "stoppe": "stop",
    "stop": "stop",
    "redemarre": "restart",
    "redemarrer": "restart",
    "restart": "restart",
    "recharge": "reload",
    "recharger": "reload",
    "reload": "reload",
    "etat": "status",
    "status": "status",
    "statut": "status",
    "active": "enable",
    "active le service": "enable",
    "desactive": "disable",
    "desactiver": "disable",
    "disable": "disable",
}


def _extract_action(text: str) -> str:
    low = text.lower()
    for word, action in _ACTION_WORDS.items():
        if re.search(rf"\b{re.escape(word)}\b", low):
            return action
    return "status"


class ServiceActionTool(Tool):
    """Commande de service systemd (start/stop/restart/status)."""

    name = ""
    binary = ""
    risk = "critical"
    service = ""
    description = ""
    aliases: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.parameters = (
            ParameterSpec(
                "action",
                "Action systemctl: start, stop, restart, reload, status, enable, disable",
                "string",
                required=True,
                default="status",
            ),
        )
        super().__init__()

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        action = str(params.get("action") or "status").lower()
        if action not in _ACTION_FLAGS:
            action = "status"
        return ["systemctl", action, self.service]

    def parse_intent(self, text: str) -> dict[str, Any]:
        return {"action": _extract_action(text)}

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        low = stdout.lower()
        if "active: active" in low or "active: running" in low:
            findings.append(Finding(title="Service actif", severity="info", evidence=self.service))
        elif "active: inactive" in low or "active: failed" in low:
            findings.append(
                Finding(title="Service inactif ou en echec", severity="medium", evidence=self.service)
            )
        return AnalysisResult(
            summary=f"systemctl {params.get('action', 'status')} {self.service}",
            findings=findings,
            source="heuristic",
        )


class WoeusbTool(Tool):
    name = "woeusb-ng"
    binary = "woeusb"
    risk = "critical"
    description = "Cree une cle USB d'installation Windows a partir d'une image ISO."
    aliases = ("woeusb",)
    examples = (
        "cree une cle usb windows depuis win11.iso sur /dev/sdb avec woeusb-ng",
        "ecris l'image windows.iso sur /dev/sdc avec woeusb",
    )

    def __init__(self) -> None:
        self.parameters = (
            ParameterSpec("source", "Image ISO source", "string", required=True),
            ParameterSpec("device", "Peripherique cible (ex: /dev/sdb)", "string", required=True),
            ParameterSpec("partition", "Creer et formater une partition (--partition)", "bool", default=True),
            ParameterSpec("force", "Forcer l'ecriture (--force)", "bool", default=False),
        )
        super().__init__()

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["woeusb"]
        if params.get("partition"):
            argv.append("--partition")
        if params.get("force"):
            argv.append("--force")
        argv += ["--device", str(params["device"]), str(params["source"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"partition": True}
        source = extract_any_path(text)
        if source:
            params["source"] = source
        device = re.search(r"(/dev/[a-z]+\d*)\b", text)
        if device:
            params["device"] = device.group(1)
        if "force" in low or "forcer" in low:
            params["force"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"error|failed|echec", stdout, re.IGNORECASE):
            findings.append(Finding(title="Echec de creation de la cle USB", severity="high"))
        if re.search(r"success|termine|done", stdout, re.IGNORECASE):
            findings.append(Finding(title="Cle USB creee", severity="info"))
        return AnalysisResult(
            summary="Creation d'une cle USB Windows (woeusb-ng).",
            findings=findings,
            source="heuristic",
        )


class PowershellTool(SpecTool):
    name = "powershell"
    binary = "pwsh"
    risk = "high"
    description = "Execute un script ou une commande PowerShell (interactif: -Command)."
    aliases = ("pwsh",)
    examples = (
        "execute Get-Process en powershell",
        "lance une commande powershell d'audit",
    )
    parameters = (
        ParameterSpec("command", "Commande PowerShell a executer (-Command)", "string"),
        ParameterSpec("file", "Script PowerShell (-File)", "string"),
        ParameterSpec("no_profile", "Ne pas charger le profil (-NoProfile)", "bool", default=True),
        ParameterSpec("no_logo", "Masquer la banniere (-NoLogo)", "bool", default=True),
        ParameterSpec("output_format", "Format de sortie (-OutputFormat)", "string"),
    )
    flags = (
        Flag("no_profile", "-NoProfile"),
        Flag("no_logo", "-NoLogo"),
    )
    options = (
        Option("command", "-Command"),
        Option("file", "-File"),
        Option("output_format", "-OutputFormat"),
    )
    order = ("flags", "options")

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"no_profile": True, "no_logo": True}
        file_path = extract_any_path(text)
        if file_path and file_path.endswith((".ps1", ".psm1")):
            params["file"] = file_path
        match = re.search(r"(?:commande|execute|lance|run)\s+(.+)$", text, re.IGNORECASE)
        if match:
            params["command"] = match.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"^(.*(?:error|exception|access denied).*)$", stdout, re.IGNORECASE | re.MULTILINE):
            findings.append(Finding(title=match.group(1).strip()[:140], severity="medium"))
        return AnalysisResult(
            summary=f"{len(stdout.splitlines())} ligne(s) de sortie PowerShell.",
            findings=findings[:40],
            source="heuristic",
        )


class ArduinoTool(SpecTool):
    name = "arduino"
    binary = "arduino"
    risk = "medium"
    description = "IDE Arduino en ligne de commande: verifie et televerse un croquis."
    examples = (
        "verifie le croquis sketch.ino avec arduino",
        "televerse le croquis sur la carte arduino",
    )
    parameters = (
        ParameterSpec("sketch", "Croquis (.ino) ou repertoire", "string"),
        ParameterSpec("verify", "Verifier la compilation (--verify)", "bool", default=True),
        ParameterSpec("upload", "Televerser sur la carte (--upload)", "bool", default=False),
        ParameterSpec("board", "Carte cible (--board)", "string"),
        ParameterSpec("port", "Port serie (--port)", "string"),
    )
    flags = (
        Flag("verify", "--verify"),
        Flag("upload", "--upload"),
    )
    options = (
        Option("board", "--board"),
        Option("port", "--port"),
    )
    order = ("flags", "options", "positionals")
    positionals = (Positional("sketch"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        sketch = re.search(r"([\w./-]+\.ino)", text)
        if sketch:
            params["sketch"] = sketch.group(1)
        if "televerse" in low or "televerser" in low or "upload" in low:
            params["upload"] = True
        if "verifie" in low or "verifier" in low or "compile" in low:
            params["verify"] = True
        board = re.search(r"(?:carte|board)\s+([\w:.-]+)", low)
        if board:
            params["board"] = board.group(1)
        port = re.search(r"(/dev/tty\w+)", text)
        if port:
            params["port"] = port.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"error:.*", stdout, re.IGNORECASE):
            findings.append(Finding(title=match.group(0).strip()[:140], severity="medium"))
        return AnalysisResult(
            summary="Compilation/televersement Arduino.",
            findings=findings[:40],
            source="heuristic",
        )


class ChirpTool(SpecTool):
    name = "chirp"
    binary = "chirp"
    risk = "low"
    description = "Configure les radios amateur: lecture/ecriture de canaux depuis un fichier."
    examples = (
        "charge la configuration radio depuis channels.img avec chirp",
        "ouvre le fichier radio.img avec chirp",
    )
    parameters = (
        ParameterSpec("file", "Fichier de canaux (.img)", "string"),
        ParameterSpec("module", "Module radio (--module)", "string"),
        ParameterSpec("action", "Action: download, upload, export", "string", default="download"),
    )
    options = (Option("module", "--module"),)
    order = ("options", "positionals")
    positionals = (Positional("file"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        file_path = extract_any_path(text)
        if file_path:
            params["file"] = file_path
        if "televerse" in low or "upload" in low:
            params["action"] = "upload"
        elif "export" in low:
            params["action"] = "export"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        count = len(re.findall(r"^\s*\d+\s+", stdout, re.MULTILINE))
        return AnalysisResult(
            summary=f"Configuration radio CHIRP ({count} canal(aux)).",
            findings=[],
            data={"channels": count},
            source="heuristic",
        )


class NyxTool(Tool):
    name = "nyx"
    binary = "nyx"
    risk = "low"
    description = "Moniteur d'etat pour Tor: bande passante, circuits et journaux."
    examples = ("surveille tor avec nyx", "affiche l'etat de tor")
    parameters = (
        ParameterSpec("config", "Fichier torrc a utiliser", "string"),
        ParameterSpec("interval", "Intervalle de rafraichissement en secondes", "int", default=5),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nyx"]
        if params.get("config"):
            argv += ["-c", str(params["config"])]
        if params.get("interval"):
            argv += ["-i", str(params["interval"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        config = extract_any_path(text)
        if config:
            params["config"] = config
        interval = re.search(r"(\d+)\s*(?:s|sec|secondes?)", text, re.IGNORECASE)
        if interval:
            params["interval"] = int(interval.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"(?:error|warning).*", stdout, re.IGNORECASE):
            findings.append(Finding(title=match.group(0).strip()[:140], severity="low"))
        return AnalysisResult(
            summary="Moniteur Tor (nyx).",
            findings=findings[:40],
            source="heuristic",
        )


class CoreutilsTool(Tool):
    name = "coreutils"
    binary = "shred"
    risk = "critical"
    description = "Effacement securise de fichiers (shred, secure-delete) via les coreutils."
    aliases = ("shred",)
    examples = (
        "efface de facon securisee secrets.txt avec coreutils",
        "detruit le fichier keys.txt de maniere irreversible",
    )
    parameters = (
        ParameterSpec("file", "Fichier a effacer", "string", required=True),
        ParameterSpec("passes", "Nombre de passes (-n)", "int", default=3),
        ParameterSpec("zero", "Terminer par des zeros (-z)", "bool", default=True),
        ParameterSpec("remove", "Supprimer le fichier apres (-u)", "bool", default=True),
        ParameterSpec("force", "Forcer les permissions (-f)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["shred"]
        if params.get("force"):
            argv.append("-f")
        if params.get("zero"):
            argv.append("-z")
        if params.get("remove"):
            argv.append("-u")
        argv += ["-n", str(params.get("passes") or 3)]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"zero": True, "remove": True}
        path = extract_any_path(text)
        if path:
            params["file"] = path
        passes = re.search(r"(\d+)\s*(?:passes?|fois)", low)
        if passes:
            params["passes"] = int(passes.group(1))
        if "garde" in low or "conserve" in low:
            params["remove"] = False
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"error|cannot|denied", stdout, re.IGNORECASE):
            findings.append(Finding(title="Effacement impossible", severity="medium"))
        return AnalysisResult(
            summary=f"Effacement securise de {params.get('file', '?')}.",
            findings=findings,
            source="heuristic",
        )


class GpaTool(SpecTool):
    name = "gpa"
    binary = "gpa"
    risk = "low"
    description = "GNU Privacy Assistant: gestion des cles et signatures GnuPG."
    examples = ("gere mes cles gpg avec gpa", "ouvre gpa pour signer une cle")
    parameters = (
        ParameterSpec("file", "Fichier de cles GnuPG", "string"),
        ParameterSpec("detach", "Detacher de la console", "bool", default=False),
    )
    flags = (Flag("detach", "--detach"),)
    order = ("flags", "positionals")
    positionals = (Positional("file"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_any_path(text)
        if path:
            params["file"] = path
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        keys = len(re.findall(r"pub\s+", stdout))
        return AnalysisResult(
            summary=f"Gestion de cles GnuPG ({keys} cle(s) publique(s)).",
            findings=[],
            data={"keys": keys},
            source="heuristic",
        )


class KeepassxcTool(Tool):
    name = "keepassxc"
    binary = "keepassxc-cli"
    risk = "high"
    description = "Gestionnaire de mots de passe KeePassXC en ligne de commande."
    aliases = ("keepassxc-cli",)
    examples = (
        "liste les entrees de coffre.kdbx avec keepassxc",
        "affiche le mot de passe de l'entree 'gmail' du coffre.kdbx",
    )
    parameters = (
        ParameterSpec("action", "Action: show, ls, create, export, clip", "string", required=True, default="ls"),
        ParameterSpec("database", "Coffre KeePass (.kdbx)", "string", required=True),
        ParameterSpec("entry", "Entree a consulter", "string"),
        ParameterSpec("key_file", "Fichier de cle (-k)", "string"),
        ParameterSpec("no_password", "Pas de mot de passe maitre (--no-password)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["keepassxc-cli", str(params["action"])]
        if params.get("key_file"):
            argv += ["-k", str(params["key_file"])]
        if params.get("no_password"):
            argv.append("--no-password")
        argv.append(str(params["database"]))
        if params.get("entry"):
            argv.append(str(params["entry"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"action": "ls"}
        db = re.search(r"([\w./-]+\.kdbx)", text, re.IGNORECASE)
        if db:
            params["database"] = db.group(1)
        if "affiche" in low or "montre" in low or "show" in low:
            params["action"] = "show"
        entry = re.search(r"(?:entree|entry)\s+['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
        if entry:
            params["entry"] = entry.group(1)
        key = re.search(r"([\w./-]+\.key)", text)
        if key:
            params["key_file"] = key.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        entries = [line.strip() for line in stdout.splitlines() if line.strip() and "/" in line]
        return AnalysisResult(
            summary=f"{len(entries)} entree(s) dans le coffre.",
            findings=[
                Finding(title=f"Entree: {e[:120]}", severity="info") for e in entries[:20]
            ],
            data={"entries": len(entries)},
            source="heuristic",
        )


class Mat2Tool(Tool):
    name = "mat2"
    binary = "mat2"
    risk = "low"
    description = "Supprime les metadonnees d'un fichier (anonymisation avant partage)."
    examples = (
        "nettoie les metadonnees de rapport.pdf avec mat2",
        "anonymise photo.jpg avant publication",
    )
    parameters = (
        ParameterSpec("file", "Fichier a nettoyer", "string", required=True),
        ParameterSpec("inplace", "Modifier en place (-i)", "bool", default=True),
        ParameterSpec("show", "Afficher les metadonnees (--show)", "bool", default=False),
        ParameterSpec("lightweight", "Mode leger (-L)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mat2"]
        if params.get("show"):
            argv.append("--show")
        if params.get("lightweight"):
            argv.append("-L")
        if params.get("inplace") and not params.get("show"):
            argv.append("-i")
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"inplace": True}
        path = extract_any_path(text)
        if path:
            params["file"] = path
        if "affiche" in low or "montre" in low or "voir" in low:
            params["show"] = True
        if "copie" in low or "sans modifier" in low:
            params["inplace"] = False
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        meta = re.findall(r"^\s*([\w-]+):\s*(.+)$", stdout, re.MULTILINE)
        for key, value in meta[:20]:
            findings.append(Finding(title=f"{key}: {value.strip()[:100]}", severity="low"))
        return AnalysisResult(
            summary=f"{len(meta)} metadonnee(s) traitee(s).",
            findings=findings,
            source="heuristic",
        )


class SirikaliTool(Tool):
    name = "sirikali"
    binary = "sirikali"
    risk = "high"
    description = "Monte et gere des volumes chiffres (VeraCrypt, LUKS, EncFS...)."
    examples = (
        "monte le volume chiffre /dev/sdb1 avec sirikali",
        "ouvre le conteneur crypte secret.tc",
    )
    parameters = (
        ParameterSpec("volume", "Volume ou conteneur a monter", "string", required=True),
        ParameterSpec("mountpoint", "Point de montage", "string"),
        ParameterSpec("type", "Type de volume (veracrypt, luks, encfs)", "string"),
        ParameterSpec("readonly", "Monter en lecture seule", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["sirikali"]
        if params.get("readonly"):
            argv.append("--readonly")
        if params.get("type"):
            argv += ["--type", str(params["type"])]
        argv.append(str(params["volume"]))
        if params.get("mountpoint"):
            argv.append(str(params["mountpoint"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_any_path(text)
        if path:
            params["volume"] = path
        device = re.search(r"(/dev/[a-z]+\d*)\b", text)
        if device:
            params["volume"] = device.group(1)
        for kind in ("veracrypt", "luks", "encfs", "cryfs"):
            if kind in low:
                params["type"] = kind
        if "lecture seule" in low or "readonly" in low:
            params["readonly"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"error|failed|denied", stdout, re.IGNORECASE):
            findings.append(Finding(title="Montage du volume echoue", severity="medium"))
        return AnalysisResult(
            summary=f"Volume chiffre {params.get('volume', '?')}.",
            findings=findings,
            source="heuristic",
        )


class ZulucryptTool(Tool):
    name = "zulucrypt-gui"
    binary = "zuluCrypt-gui"
    risk = "high"
    description = "Interface graphique zuluCrypt: creation et montage de volumes chiffres."
    aliases = ("zulucrypt",)
    examples = ("ouvre zulucrypt pour monter un volume chiffre",)
    parameters = (
        ParameterSpec("volume", "Volume a ouvrir", "string"),
        ParameterSpec("mountpoint", "Point de montage", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["zuluCrypt-gui"]
        if params.get("volume"):
            argv.append(str(params["volume"]))
        if params.get("mountpoint"):
            argv.append(str(params["mountpoint"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        device = re.search(r"(/dev/[a-z]+\d*)\b", text)
        if device:
            params["volume"] = device.group(1)
        else:
            path = extract_any_path(text)
            if path:
                params["volume"] = path
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        return AnalysisResult(summary="Interface zuluCrypt.", findings=[], source="heuristic")


class ZulumountTool(Tool):
    name = "zulumount-gui"
    binary = "zuluMount-gui"
    risk = "high"
    description = "Interface graphique zuluMount: montage de volumes chiffres."
    aliases = ("zulumount",)
    examples = ("monte le volume chiffre avec zulumount",)
    parameters = (ParameterSpec("volume", "Volume a monter", "string"),)

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["zuluMount-gui"]
        if params.get("volume"):
            argv.append(str(params["volume"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        device = re.search(r"(/dev/[a-z]+\d*)\b", text)
        if device:
            params["volume"] = device.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        return AnalysisResult(summary="Interface zuluMount.", findings=[], source="heuristic")


class FirefoxTool(SpecTool):
    name = "firefox"
    binary = "firefox"
    risk = "low"
    description = "Navigateur Firefox en ligne de commande (profil, URL, mode sans tete)."
    aliases = ("firefox-esr",)
    examples = (
        "ouvre https://example.com dans firefox",
        "lance firefox avec le gestionnaire de profils",
    )
    parameters = (
        ParameterSpec("url", "URL a ouvrir", "string"),
        ParameterSpec("profile", "Profil a utiliser (-P)", "string"),
        ParameterSpec("headless", "Mode sans tete (--headless)", "bool", default=False),
        ParameterSpec("new_window", "Nouvelle fenetre (-new-window)", "bool", default=False),
        ParameterSpec("private", "Navigation privee (-private-window)", "bool", default=False),
    )
    flags = (
        Flag("headless", "--headless"),
        Flag("new_window", "-new-window"),
        Flag("private", "-private-window"),
    )
    options = (Option("profile", "-P"),)
    order = ("flags", "options", "positionals")
    positionals = (Positional("url"),)
    url_param = "url"

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"(?:error|failed).*", stdout, re.IGNORECASE):
            findings.append(Finding(title=match.group(0).strip()[:140], severity="low"))
        return AnalysisResult(summary="Session Firefox.", findings=findings[:20], source="heuristic")


class MetasploitServiceTool(ServiceActionTool):
    name = "metasploit-framework"
    binary = "systemctl"
    service = "metasploit"
    description = "Service Metasploit Framework (msfrpcd/console) pilote par systemctl."


class MariadbServiceTool(ServiceActionTool):
    name = "mariadb-server"
    binary = "systemctl"
    service = "mariadb"
    description = "Service MariaDB/MySQL pilote par systemctl."


class PostgresqlServiceTool(ServiceActionTool):
    name = "postgresql"
    binary = "systemctl"
    service = "postgresql"
    description = "Service PostgreSQL pilote par systemctl."


class Apache2ServiceTool(ServiceActionTool):
    name = "apache2"
    binary = "systemctl"
    service = "apache2"
    description = "Service HTTP Apache 2 pilote par systemctl."


class NginxServiceTool(ServiceActionTool):
    name = "nginx"
    binary = "systemctl"
    service = "nginx"
    description = "Service HTTP nginx pilote par systemctl."


class OpensshServiceTool(ServiceActionTool):
    name = "openssh-server"
    binary = "systemctl"
    service = "ssh"
    description = "Service SSH (sshd) pilote par systemctl."


class GvmServiceTool(ServiceActionTool):
    name = "gvm"
    binary = "systemctl"
    service = "gvm"
    description = "OpenVAS/Greenbone Vulnerability Manager: demarrage, mise a jour, arret."


class FirefoxEsrTool(FirefoxTool):
    name = "firefox-esr"
    binary = "firefox-esr"
    aliases = ()
    description = "Navigateur Firefox ESR (Extended Support Release) en ligne de commande."


register(MetasploitServiceTool())
register(MariadbServiceTool())
register(PostgresqlServiceTool())
register(Apache2ServiceTool())
register(NginxServiceTool())
register(OpensshServiceTool())
register(GvmServiceTool())
register(WoeusbTool())
register(PowershellTool())
register(ArduinoTool())
register(ChirpTool())
register(NyxTool())
register(CoreutilsTool())
register(GpaTool())
register(KeepassxcTool())
register(Mat2Tool())
register(SirikaliTool())
register(ZulucryptTool())
register(ZulumountTool())
register(FirefoxTool())
register(FirefoxEsrTool())
