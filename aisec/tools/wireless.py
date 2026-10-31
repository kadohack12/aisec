"""Outils de test sans fil (classe `06-wireless-attacks`).

Couvre le Wi-Fi 802.11 (suite aircrack-ng, reaver, wifite, bully, mdk4, pixiewps,
cowpatty, asleap), le Bluetooth (bluesnarfer, blueranger, hcitool) et le RFID/NFC
(mfoc, mfcuk, nfc-list). Chaque binaire est un plugin `Tool` (argv sans shell).

Politique de controle: la capture et le scan sont en `medium` (l'interface passe
en mode moniteur et ecoute le spectre), la desauthentification, l'injection et le
cassage de cle sont en `high` (perturbation ou attaque active du reseau).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool

_IFACE_RE = re.compile(r"\b(wlan\d+\w*|mon\d+|wlan\d+mon|ath\d+|phy\d+)\b", re.IGNORECASE)
_BSSID_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
_CHANNEL_RE = re.compile(r"\b(?:canal|channel|ch)\s*(\d{1,3})\b", re.IGNORECASE)
_ESSID_RE = re.compile(r"(?<![a-z])(?:essid|ssid|reseau|network)\s+[\"']?([\w.\- ]{1,32})", re.IGNORECASE)
_CAP_RE = re.compile(r"([\w./-]*[\w-]+\.(?:cap|pcap|pcapng|ivs|hccapx|22000))\b", re.IGNORECASE)


def _iface(text: str, default: str = "wlan0") -> str:
    match = _IFACE_RE.search(text)
    return match.group(1) if match else default


def _bssid(text: str) -> str:
    match = _BSSID_RE.search(text)
    return match.group(1).upper() if match else ""


def _channel(text: str) -> str:
    match = _CHANNEL_RE.search(text)
    return match.group(1) if match else ""


class AirmonTool(Tool):
    name = "airmon-ng"
    aliases = ("airmon",)
    binary = "airmon-ng"
    risk = "medium"
    description = "Active/desactive le mode moniteur sur une interface Wi-Fi."
    examples = ("active le mode moniteur sur wlan0", "arrete le mode moniteur de wlan0mon")
    parameters = (
        ParameterSpec("action", "Action: start, stop, check", "string", default="start"),
        ParameterSpec("interface", "Interface Wi-Fi, ex: wlan0", "string", required=True),
        ParameterSpec("channel", "Canal a verrouiller (start + canal)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        action = str(params.get("action") or "start")
        argv = ["airmon-ng", action, str(params["interface"])]
        if params.get("channel"):
            argv.append(str(params["channel"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": _iface(text)}
        if "stop" in low or "arrete" in low or "desactive" in low or "coupe" in low:
            params["action"] = "stop"
        elif "check" in low or "verifie" in low or "liste" in low:
            params["action"] = "check"
        else:
            params["action"] = "start"
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        renamed = re.search(r"monitor mode (?:enabled|vif enabled) on (\S+)", stdout, re.IGNORECASE)
        if renamed:
            findings.append(
                Finding(
                    title="Mode moniteur active",
                    severity="info",
                    detail=f"Utiliser l'interface {renamed.group(1)} pour la capture.",
                )
            )
        return AnalysisResult(
            summary="Gestion du mode moniteur Wi-Fi.",
            findings=findings,
            source="heuristic",
        )


class AirodumpTool(Tool):
    name = "airodump-ng"
    aliases = ("airodump",)
    binary = "airodump-ng"
    risk = "medium"
    description = "Capture les reseaux Wi-Fi et les handshakes WPA."
    examples = ("capture les reseaux wifi sur wlan0mon", "capture le handshake du bssid AA:BB:CC:DD:EE:FF")
    parameters = (
        ParameterSpec("interface", "Interface en mode moniteur", "string", required=True),
        ParameterSpec("bssid", "Filtrer sur un BSSID", "string"),
        ParameterSpec("channel", "Canal (--channel)", "string"),
        ParameterSpec("write", "Prefixe des fichiers de capture (-w)", "string"),
        ParameterSpec("band", "Bande: a, b, g (--band)", "string"),
        ParameterSpec("essid", "Filtrer sur un SSID (--essid)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["airodump-ng"]
        if params.get("bssid"):
            argv += ["--bssid", str(params["bssid"])]
        if params.get("channel"):
            argv += ["--channel", str(params["channel"])]
        if params.get("band"):
            argv += ["--band", str(params["band"])]
        if params.get("essid"):
            argv += ["--essid", str(params["essid"])]
        if params.get("write"):
            argv += ["-w", str(params["write"])]
        argv.append(str(params["interface"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": _iface(text, "wlan0mon")}
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        essid = _ESSID_RE.search(text)
        if essid:
            params["essid"] = essid.group(1).strip()
        prefix = re.search(r"(?:prefixe|fichier|sortie|-w)\s+([\w./-]+)", low)
        if prefix:
            params["write"] = prefix.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"WPA handshake", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Handshake WPA capture",
                    severity="medium",
                    detail="Un handshake permet une attaque hors ligne par dictionnaire.",
                )
            )
        open_nets = len(re.findall(r"\bOPN\b", stdout))
        if open_nets:
            findings.append(
                Finding(
                    title="Reseau(x) ouvert(s) detecte(s)",
                    severity="low",
                    detail=f"{open_nets} reseau(x) sans chiffrement.",
                )
            )
        return AnalysisResult(
            summary="Capture Wi-Fi (reseau et handshakes).",
            findings=findings,
            source="heuristic",
        )


class AireplayTool(Tool):
    name = "aireplay-ng"
    aliases = ("aireplay",)
    binary = "aireplay-ng"
    risk = "high"
    description = "Injecte des trames Wi-Fi (desauthentification, rejeu, faux AP)."
    examples = ("desauthentifie le client du bssid AA:BB:CC:DD:EE:FF sur wlan0mon",)
    parameters = (
        ParameterSpec("attack", "Mode: deauth, fakeauth, arpreplay, chopchop, test", "string", default="deauth"),
        ParameterSpec("count", "Nombre de paquets (-0 N)", "int"),
        ParameterSpec("bssid", "BSSID de l'AP (-a)", "string"),
        ParameterSpec("client", "MAC du client (-c)", "string"),
        ParameterSpec("interface", "Interface en mode moniteur", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        attack = str(params.get("attack") or "deauth")
        argv = ["aireplay-ng"]
        if attack == "deauth":
            argv += ["-0", str(params.get("count") or 1)]
        elif attack == "fakeauth":
            argv.append("-1")
        elif attack == "arpreplay":
            argv.append("-3")
        elif attack == "chopchop":
            argv.append("-4")
        elif attack == "test":
            argv.append("-9")
        if params.get("bssid"):
            argv += ["-a", str(params["bssid"])]
        if params.get("client"):
            argv += ["-c", str(params["client"])]
        argv.append(str(params["interface"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": _iface(text, "wlan0mon")}
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        client = re.findall(_BSSID_RE, text)
        if len(client) > 1:
            params["client"] = client[1].upper()
        if "fakeauth" in low or "fausse authent" in low:
            params["attack"] = "fakeauth"
        elif "arpreplay" in low or "rejeu" in low:
            params["attack"] = "arpreplay"
        elif "chopchop" in low:
            params["attack"] = "chopchop"
        elif "test" in low:
            params["attack"] = "test"
        else:
            params["attack"] = "deauth"
        count = re.search(r"(\d+)\s*(?:paquets?|trames?|packets?)", low)
        if count:
            params["count"] = int(count.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("attack") == "deauth":
            findings.append(
                Finding(
                    title="Desauthentification envoyee",
                    severity="high",
                    detail="Action active: coupe la connexion des clients (deni de service cible).",
                )
            )
        if re.search(r"DeAuth|deauth", stdout) and re.search(r"\bSending\b", stdout):
            findings.append(
                Finding(
                    title="Trames de desauthentification emises",
                    severity="high",
                    detail="Des clients ont pu etre deconnectes du reseau.",
                )
            )
        return AnalysisResult(
            summary="Injection de trames Wi-Fi.",
            findings=findings,
            source="heuristic",
        )


class AircrackTool(Tool):
    name = "aircrack-ng"
    aliases = ("aircrack",)
    binary = "aircrack-ng"
    risk = "high"
    description = "Casse une cle WEP/WPA a partir d'une capture (dictionnaire ou statistiques)."
    examples = ("casse le wpa de capture.cap avec rockyou.txt",)
    parameters = (
        ParameterSpec("capture", "Fichier de capture (.cap/.pcap)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
        ParameterSpec("bssid", "BSSID cible (-b)", "string"),
        ParameterSpec("essid", "ESSID cible (-e)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["aircrack-ng"]
        if params.get("bssid"):
            argv += ["-b", str(params["bssid"])]
        if params.get("essid"):
            argv += ["-e", str(params["essid"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        argv.append(str(params["capture"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        capture = _CAP_RE.search(text)
        if capture:
            params["capture"] = capture.group(1)
        wordlist = re.search(r"([\w./-]*(?:rockyou|wordlist|dictionnaire|mots)[\w./-]*\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        essid = _ESSID_RE.search(text)
        if essid:
            params["essid"] = essid.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        key = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", stdout, re.IGNORECASE)
        if key:
            findings.append(
                Finding(
                    title="Cle Wi-Fi trouvee",
                    severity="critical",
                    detail=f"La cle du reseau est '{key.group(1)}' (reseau compromis).",
                )
            )
        elif re.search(r"KEY NOT FOUND|Passphrase not in", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Cle non trouvee dans le dictionnaire",
                    severity="info",
                    detail="Essayer un dictionnaire plus large ou une attaque par masque.",
                )
            )
        return AnalysisResult(
            summary="Cassage de cle Wi-Fi a partir d'une capture.",
            findings=findings,
            source="heuristic",
        )


class ReaverTool(Tool):
    name = "reaver"
    binary = "reaver"
    risk = "high"
    description = "Attaque WPS (PIN) contre un point d'acces."
    examples = ("attaque le wps du bssid AA:BB:CC:DD:EE:FF sur wlan0mon",)
    parameters = (
        ParameterSpec("interface", "Interface en mode moniteur", "string", required=True),
        ParameterSpec("bssid", "BSSID de l'AP (-b)", "string", required=True),
        ParameterSpec("channel", "Canal (-c)", "string"),
        ParameterSpec("verbose", "Verbeux (-vv)", "bool", default=False),
        ParameterSpec("pixie", "Attaque Pixie Dust (-K)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["reaver", "-i", str(params["interface"]), "-b", str(params["bssid"])]
        if params.get("channel"):
            argv += ["-c", str(params["channel"])]
        if params.get("pixie"):
            argv.append("-K")
        if params.get("verbose"):
            argv.append("-vv")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": _iface(text, "wlan0mon")}
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        if "pixie" in low or "pixiewps" in low:
            params["pixie"] = True
        if "verbeux" in low or "verbose" in low or "-vv" in low:
            params["verbose"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        pin = re.search(r"WPS PIN:\s*'?(\d{4,8})'?", stdout, re.IGNORECASE)
        if pin:
            findings.append(
                Finding(
                    title="PIN WPS casse",
                    severity="critical",
                    detail=f"PIN {pin.group(1)}: l'AP est compromis (WPS vulnerable).",
                )
            )
        psk = re.search(r"WPA PSK:\s*'?([^'\n]+)'?", stdout, re.IGNORECASE)
        if psk:
            findings.append(
                Finding(
                    title="Cle WPA recuperee via WPS",
                    severity="critical",
                    detail=f"PSK '{psk.group(1).strip()}'.",
                )
            )
        if re.search(r"WPS lock|locked", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="WPS verrouille",
                    severity="low",
                    detail="L'AP bloque les tentatives WPS: patienter avant de reprendre.",
                )
            )
        return AnalysisResult(
            summary="Attaque WPS contre un point d'acces.",
            findings=findings,
            source="heuristic",
        )


class WifiteTool(Tool):
    name = "wifite"
    binary = "wifite"
    risk = "high"
    description = "Automatise les attaques Wi-Fi (WPS, WPA, WEP) sur les reseaux detectes."
    examples = ("lance wifite en mode automatique", "wifite --wpa sur le canal 6")
    parameters = (
        ParameterSpec("interface", "Interface Wi-Fi (--interface)", "string"),
        ParameterSpec("wps", "Cibler le WPS (--wps)", "bool", default=False),
        ParameterSpec("wpa", "Cibler le WPA (--wpa)", "bool", default=False),
        ParameterSpec("wep", "Cibler le WEP (--wep)", "bool", default=False),
        ParameterSpec("channel", "Canal a cibler (--channel)", "string"),
        ParameterSpec("kill", "Tuer les processus genants (--kill)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["wifite"]
        if params.get("interface"):
            argv += ["--interface", str(params["interface"])]
        if params.get("channel"):
            argv += ["--channel", str(params["channel"])]
        for opt in ("wps", "wpa", "wep"):
            if params.get(opt):
                argv.append(f"--{opt}")
        if params.get("kill"):
            argv.append("--kill")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        iface = _iface(text, "")
        if iface:
            params["interface"] = iface
        if "wps" in low:
            params["wps"] = True
        if "wpa" in low:
            params["wpa"] = True
        if "wep" in low:
            params["wep"] = True
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        if "kill" in low:
            params["kill"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"(WPA|WPS|WEP).*(cracked|key found|pin found)", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Reseau casse par wifite",
                    severity="critical",
                    detail="Une cle a ete recuperee: le reseau Wi-Fi est compromis.",
                )
            )
        return AnalysisResult(
            summary="Attaque Wi-Fi automatisee (wifite).",
            findings=findings,
            source="heuristic",
        )


class MdkTool(Tool):
    name = "mdk4"
    aliases = ("mdk3",)
    binary = "mdk4"
    risk = "high"
    description = "Genere des trames Wi-Fi (tests de robustesse, desauthentification en masse)."
    examples = ("teste la robustesse du canal 6 sur wlan0mon",)
    parameters = (
        ParameterSpec("interface", "Interface en mode moniteur", "string", required=True),
        ParameterSpec("mode", "Mode: b (beacon), a (auth), d (deauth), p (probe)", "string", default="d"),
        ParameterSpec("channel", "Canal (-c)", "string"),
        ParameterSpec("bssid", "BSSID cible (-b)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mdk4", str(params["interface"]), str(params.get("mode") or "d")]
        if params.get("channel"):
            argv += ["-c", str(params["channel"])]
        if params.get("bssid"):
            argv += ["-b", str(params["bssid"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"interface": _iface(text, "wlan0mon")}
        if "beacon" in low:
            params["mode"] = "b"
        elif "auth" in low or "authentification" in low:
            params["mode"] = "a"
        elif "probe" in low:
            params["mode"] = "p"
        else:
            params["mode"] = "d"
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Generation de trames Wi-Fi (test de robustesse)",
                severity="high",
                detail="Une emission massive perturbe le reseau (deni de service).",
            )
        ]
        return AnalysisResult(
            summary="Generation de trames Wi-Fi (mdk4).",
            findings=findings,
            source="heuristic",
        )


class PixiewpsTool(Tool):
    name = "pixiewps"
    binary = "pixiewps"
    risk = "medium"
    description = "Calcule le PIN WPS hors ligne a partir des valeurs capturees (Pixie Dust)."
    examples = ("calcule le pin wps hors ligne avec pixiewps",)
    parameters = (
        ParameterSpec("pke", "Cle publique de l'AP (-e)", "string"),
        ParameterSpec("pkr", "Cle publique du client (-r)", "string"),
        ParameterSpec("e_hash1", "E-Hash1 (-s)", "string"),
        ParameterSpec("e_hash2", "E-Hash2 (-z)", "string"),
        ParameterSpec("authkey", "AuthKey (-a)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["pixiewps"]
        for key, flag in (("pke", "-e"), ("pkr", "-r"), ("e_hash1", "-s"), ("e_hash2", "-z"), ("authkey", "-a")):
            if params.get(key):
                argv += [flag, str(params[key])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        for key, label in (("pke", "e"), ("pkr", "r"), ("e_hash1", "s"), ("e_hash2", "z"), ("authkey", "a")):
            match = re.search(rf"-{label}\s+([0-9A-Fa-f]+)", text)
            if match:
                params[key] = match.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        pin = re.search(r"WPS pin:\s*'?(\d{4,8})'?", stdout, re.IGNORECASE)
        if pin:
            findings.append(
                Finding(
                    title="PIN WPS calcule hors ligne",
                    severity="critical",
                    detail=f"PIN {pin.group(1)}: l'AP est vulnerable a Pixie Dust.",
                )
            )
        return AnalysisResult(
            summary="Calcul hors ligne du PIN WPS (Pixie Dust).",
            findings=findings,
            source="heuristic",
        )


class BullyTool(Tool):
    name = "bully"
    binary = "bully"
    risk = "high"
    description = "Attaque WPS (PIN) alternative, ecrite en C (rapide et robuste)."
    examples = ("attaque le wps du bssid AA:BB:CC:DD:EE:FF avec bully",)
    parameters = (
        ParameterSpec("interface", "Interface en mode moniteur", "string", required=True),
        ParameterSpec("bssid", "BSSID de l'AP (-b)", "string", required=True),
        ParameterSpec("channel", "Canal (-c)", "string"),
        ParameterSpec("essid", "SSID (-d)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bully", str(params["interface"]), "-b", str(params["bssid"])]
        if params.get("channel"):
            argv += ["-c", str(params["channel"])]
        if params.get("essid"):
            argv += ["-d", str(params["essid"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"interface": _iface(text, "wlan0mon")}
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        channel = _channel(text)
        if channel:
            params["channel"] = channel
        essid = _ESSID_RE.search(text)
        if essid:
            params["essid"] = essid.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"Pin is '?(\d{4,8})", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="PIN WPS casse (bully)",
                    severity="critical",
                    detail="L'AP est compromis via WPS.",
                )
            )
        return AnalysisResult(
            summary="Attaque WPS (bully).",
            findings=findings,
            source="heuristic",
        )


class CowpattyTool(Tool):
    name = "cowpatty"
    binary = "cowpatty"
    risk = "high"
    description = "Casse une cle WPA-PSK a partir d'un handshake (attaque par dictionnaire)."
    examples = ("casse le wpa de capture.cap avec rockyou.txt",)
    parameters = (
        ParameterSpec("capture", "Capture contenant le handshake (-r)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-f)", "string", required=True),
        ParameterSpec("essid", "SSID du reseau (-s)", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return [
            "cowpatty",
            "-r",
            str(params["capture"]),
            "-f",
            str(params["wordlist"]),
            "-s",
            str(params["essid"]),
        ]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        capture = _CAP_RE.search(text)
        if capture:
            params["capture"] = capture.group(1)
        wordlist = re.search(r"([\w./-]*(?:rockyou|wordlist|dictionnaire|mots)[\w./-]*\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        essid = _ESSID_RE.search(text)
        if essid:
            params["essid"] = essid.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"The PSK is|Passphrase:\s*'?([^'\n]+)", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Cle WPA-PSK trouvee",
                    severity="critical",
                    detail="Le mot de passe du reseau a ete casse hors ligne.",
                )
            )
        return AnalysisResult(
            summary="Cassage WPA-PSK hors ligne (cowpatty).",
            findings=findings,
            source="heuristic",
        )


class AsleapTool(Tool):
    name = "asleap"
    binary = "asleap"
    risk = "high"
    description = "Casse les identifiants Cisco LEAP a partir d'une capture."
    examples = ("casse les identifiants leap de capture.cap avec rockyou.txt",)
    parameters = (
        ParameterSpec("capture", "Capture contenant le challenge LEAP (-r)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-W)", "string"),
        ParameterSpec("server", "Serveur RADIUS (-s)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["asleap", "-r", str(params["capture"])]
        if params.get("wordlist"):
            argv += ["-W", str(params["wordlist"])]
        if params.get("server"):
            argv += ["-s", str(params["server"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        capture = _CAP_RE.search(text)
        if capture:
            params["capture"] = capture.group(1)
        wordlist = re.search(r"([\w./-]*(?:rockyou|wordlist|dictionnaire|mots)[\w./-]*\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"password:\s*\"?([^\"\n]+)", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Identifiants LEAP casses",
                    severity="critical",
                    detail="Le couple utilisateur/mot de passe a ete recupere (Cisco LEAP vulnerable).",
                )
            )
        return AnalysisResult(
            summary="Cassage d'identifiants Cisco LEAP (asleap).",
            findings=findings,
            source="heuristic",
        )


class BluesnarferTool(Tool):
    name = "bluesnarfer"
    binary = "bluesnarfer"
    risk = "high"
    description = "Extrait des donnees d'un telephone via Bluetooth (AT, repertoire, SMS)."
    examples = ("extrait le repertoire du telephone AA:BB:CC:DD:EE:FF",)
    parameters = (
        ParameterSpec("bssid", "Adresse Bluetooth de la cible (-b)", "string", required=True),
        ParameterSpec("mode", "Action (-C N): repertoire, sms, ...", "string"),
        ParameterSpec("channel", "Canal RFCOMM (-c)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bluesnarfer", "-b", str(params["bssid"])]
        if params.get("channel"):
            argv += ["-c", str(params["channel"])]
        if params.get("mode"):
            argv += ["-C", str(params["mode"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        low = text.lower()
        if "repertoire" in low or "contacts" in low:
            params["mode"] = "0"
        elif "sms" in low:
            params["mode"] = "1"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if stdout.strip() and not re.search(r"error|fail", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Donnees extraites via Bluetooth",
                    severity="high",
                    detail="Le telephone cible est accessible sans authentification suffisante.",
                )
            )
        return AnalysisResult(
            summary="Extraction de donnees Bluetooth (bluesnarfer).",
            findings=findings,
            source="heuristic",
        )


class BluerangerTool(Tool):
    name = "blueranger"
    binary = "blueranger"
    risk = "medium"
    description = "Localise un peripherique Bluetooth par mesure de puissance du signal."
    examples = ("localise le peripherique AA:BB:CC:DD:EE:FF sur hci0",)
    parameters = (
        ParameterSpec("interface", "Interface Bluetooth, ex: hci0", "string", required=True),
        ParameterSpec("bssid", "Adresse Bluetooth cible", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["blueranger", str(params["interface"]), str(params["bssid"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"interface": "hci0"}
        iface = re.search(r"\b(hci\d+)\b", text, re.IGNORECASE)
        if iface:
            params["interface"] = iface.group(1)
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        return AnalysisResult(
            summary="Localisation d'un peripherique Bluetooth (blueranger).",
            source="heuristic",
        )


class HcitoolTool(Tool):
    name = "hcitool"
    binary = "hcitool"
    risk = "low"
    description = "Enumere et interroge les peripheriques Bluetooth a portee."
    examples = ("scanne les peripheriques bluetooth",)
    parameters = (
        ParameterSpec("action", "Action: scan, inq, info, name, con", "string", default="scan"),
        ParameterSpec("bssid", "Adresse Bluetooth cible", "string"),
        ParameterSpec("interface", "Interface Bluetooth (-i)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hcitool"]
        if params.get("interface"):
            argv += ["-i", str(params["interface"])]
        argv.append(str(params.get("action") or "scan"))
        if params.get("bssid"):
            argv.append(str(params["bssid"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"action": "scan"}
        for action, kws in (
            ("info", ("info", "informations")),
            ("name", ("nom", "name")),
            ("con", ("connexion", "connecte")),
            ("inq", ("inquiry", "recherche")),
        ):
            if any(kw in low for kw in kws):
                params["action"] = action
                break
        bssid = _bssid(text)
        if bssid:
            params["bssid"] = bssid
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        devices = re.findall(_BSSID_RE, stdout)
        if devices:
            findings.append(
                Finding(
                    title="Peripheriques Bluetooth detectes",
                    severity="info",
                    detail=f"{len(devices)} peripherique(s): {', '.join(devices[:10])}",
                )
            )
        return AnalysisResult(
            summary=f"Enumeration Bluetooth ({len(devices)} peripherique(s)).",
            findings=findings,
            source="heuristic",
        )


class RtlSdrTool(Tool):
    name = "rtl_sdr"
    aliases = ("rtl-sdr",)
    binary = "rtl_sdr"
    risk = "low"
    description = "Capture des echantillons IQ bruts avec un recepteur RTL-SDR."
    examples = ("capture 433.92 MHz sur rtl_sdr dans capture.bin",)
    parameters = (
        ParameterSpec("frequency", "Frequence en Hz (-f)", "string", required=True),
        ParameterSpec("sample_rate", "Frequence d'echantillonnage (-s)", "string"),
        ParameterSpec("gain", "Gain (-g)", "string"),
        ParameterSpec("output", "Fichier de sortie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rtl_sdr", "-f", str(params["frequency"])]
        if params.get("sample_rate"):
            argv += ["-s", str(params["sample_rate"])]
        if params.get("gain"):
            argv += ["-g", str(params["gain"])]
        if params.get("output"):
            argv.append(str(params["output"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        freq = re.search(r"(\d+(?:[.,]\d+)?)\s*(GHz|MHz|kHz|Hz)", text, re.IGNORECASE)
        if freq:
            value = float(freq.group(1).replace(",", "."))
            factor = {"ghz": 1e9, "mhz": 1e6, "khz": 1e3, "hz": 1}.get(freq.group(2).lower(), 1)
            params["frequency"] = str(int(value * factor))
        else:
            raw = re.search(r"-f\s+(\d{5,})", text)
            if raw:
                params["frequency"] = raw.group(1)
        sample = re.search(r"(\d+(?:[.,]\d+)?)\s*(MS/s|MSps|kS/s|ksps)", text, re.IGNORECASE)
        if sample:
            value = float(sample.group(1).replace(",", "."))
            factor = 1e6 if sample.group(2).lower().startswith("m") else 1e3
            params["sample_rate"] = str(int(value * factor))
        output = re.search(r"([\w./-]+\.(?:bin|iq|raw|wav|cu8))", text, re.IGNORECASE)
        if output:
            params["output"] = output.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"Lost at least|dropped", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Echantillons perdus",
                    severity="low",
                    detail="Reduire la frequence d'echantillonnage ou le gain.",
                )
            )
        return AnalysisResult(
            summary="Capture IQ RTL-SDR.",
            findings=findings,
            source="heuristic",
        )


class RfcatTool(Tool):
    name = "rfcat"
    binary = "rfcat"
    risk = "medium"
    description = "Emet et recoit des trames radio avec un peripherique RFCat (sub-GHz)."
    examples = ("ouvre une session rfcat sur 433.92 MHz",)
    parameters = (
        ParameterSpec("frequency", "Frequence en Hz (-f)", "string"),
        ParameterSpec("mode", "Mode: interactive, dump, replay", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rfcat"]
        if params.get("frequency"):
            argv += ["-f", str(params["frequency"])]
        if params.get("mode"):
            argv += ["--", str(params["mode"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        freq = re.search(r"(\d+(?:[.,]\d+)?)\s*(GHz|MHz)", text, re.IGNORECASE)
        if freq:
            value = float(freq.group(1).replace(",", "."))
            factor = 1e9 if freq.group(2).lower() == "ghz" else 1e6
            params["frequency"] = str(int(value * factor))
        low = text.lower()
        if "dump" in low:
            params["mode"] = "dump"
        elif "replay" in low or "rejoue" in low:
            params["mode"] = "replay"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Emission radio sub-GHz",
                severity="medium",
                detail="Peut perturber des dispositifs sans fil non proteges (alarmes, telecommandes).",
            )
        ]
        return AnalysisResult(
            summary="Session RFCat (emission/reception sub-GHz).",
            findings=findings,
            source="heuristic",
        )


class MfocTool(Tool):
    name = "mfoc"
    binary = "mfoc"
    risk = "high"
    description = "Recupere les cles d'une carte Mifare Classic par attaque par defaut."
    examples = ("recupere les cles de la carte mifare dans dump.mfd",)
    parameters = (
        ParameterSpec("output", "Fichier de sortie (-O)", "string"),
        ParameterSpec("keys", "Fichier de cles (-f)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mfoc"]
        if params.get("output"):
            argv += ["-O", str(params["output"])]
        if params.get("keys"):
            argv += ["-f", str(params["keys"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        output = re.search(r"([\w./-]+\.(?:mfd|dump|bin))", text, re.IGNORECASE)
        if output:
            params["output"] = output.group(1)
        keys = re.search(r"([\w./-]+\.(?:keys|dic|txt))", text, re.IGNORECASE)
        if keys:
            params["keys"] = keys.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"Found Key|key found", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Cles Mifare recuperees",
                    severity="high",
                    detail="La carte peut etre clonee (acces physique compromis).",
                )
            )
        return AnalysisResult(
            summary="Recuperation de cles Mifare Classic (mfoc).",
            findings=findings,
            source="heuristic",
        )


class MfcukTool(Tool):
    name = "mfcuk"
    binary = "mfcuk"
    risk = "high"
    description = "Recupere une cle Mifare Classic par attaque Darkside (sans cle connue)."
    examples = ("recupere la cle mifare par attaque darkside",)
    parameters = (
        ParameterSpec("library", "Bibliotheque: 0 (libnfc) ou 1 (libusb)", "string", default="0"),
        ParameterSpec("reader", "Lecteur (-R)", "string", default="0:A"),
        ParameterSpec("blocks", "Bloc source (-s)", "string", default="250"),
        ParameterSpec("target", "Bloc cible (-S)", "string", default="250"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mfcuk", "-C"]
        argv += ["-R", str(params.get("library") or "0") + ":" + str(params.get("reader") or "A")]
        argv += ["-s", str(params.get("blocks") or "250")]
        argv += ["-S", str(params.get("target") or "250")]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if "libusb" in text.lower():
            params["library"] = "1"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        key = re.search(r"KEY:\s*([0-9A-Fa-f]{12})", stdout)
        if key:
            findings.append(
                Finding(
                    title="Cle Mifare recuperee (Darkside)",
                    severity="high",
                    detail=f"Cle {key.group(1)}: la carte est clonee possiblement.",
                )
            )
        return AnalysisResult(
            summary="Attaque Darkside Mifare Classic (mfcuk).",
            findings=findings,
            source="heuristic",
        )


class NfcListTool(Tool):
    name = "nfc-list"
    binary = "nfc-list"
    risk = "low"
    description = "Liste les tags NFC a portee du lecteur."
    examples = ("liste les tags nfc a portee",)
    parameters = (
        ParameterSpec("verbose", "Mode verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nfc-list"]
        if params.get("verbose"):
            argv.append("-v")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if "verbeux" in text.lower() or "verbose" in text.lower():
            params["verbose"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        tags = re.findall(r"UID.*?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+|0x[0-9A-Fa-f]+)", stdout)
        if tags:
            findings.append(
                Finding(
                    title="Tag NFC detecte",
                    severity="info",
                    detail=f"{len(tags)} tag(s): {', '.join(tags[:5])}",
                )
            )
        return AnalysisResult(
            summary=f"Enumeration NFC ({len(tags)} tag(s)).",
            findings=findings,
            source="heuristic",
        )


register(AirmonTool())
register(AirodumpTool())
register(AireplayTool())
register(AircrackTool())
register(ReaverTool())
register(WifiteTool())
register(MdkTool())
register(PixiewpsTool())
register(BullyTool())
register(CowpattyTool())
register(AsleapTool())
register(BluesnarferTool())
register(BluerangerTool())
register(HcitoolTool())
register(RtlSdrTool())
register(RfcatTool())
register(MfocTool())
register(MfcukTool())
register(NfcListTool())
