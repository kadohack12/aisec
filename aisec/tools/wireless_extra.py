"""Classe 06 - Wireless Testing : Wi-Fi, Bluetooth, SDR et RFID/NFC.

Sous-categories couvertes:
  - 06-wireless-attacks   : fern-wifi-cracker, kismet-core, wig-ng
  - 06-01-wireless-tools  : airgeddon, eapmd5pass, freeradius,
                            freeradius-wpe, sparrow-wifi, wifi-honey
  - 06-02-bluetooth-tools : bluelog, bluez-hcidump, btscanner, redfang,
                            spooftooph
  - 06-05-radio-tools     : gqrx-sdr, gr-air-modes, inspectrum,
                            rtlsdr-scanner
  - 06-03-rfid-nfc-tools  : libfreefare-bin, libnfc-bin, mfterm
  - 06-04-other-wireless  : gnuradio, hackrf, ubertooth

L'ecoute passive (scan, capture) reste en `medium`; les outils qui emettent
(faux point d'acces, spoofing, brute force WPS) sont en `high` et exigent une
confirmation.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, SpecTool


# --------------------------------------------------------------------------
# Wi-Fi
# --------------------------------------------------------------------------
class FernWifiCrackerTool(SpecTool):
    name = "fern-wifi-cracker"
    binary = "fern-wifi-cracker"
    risk = "high"
    description = "Interface graphique de cassage Wi-Fi (WEP/WPA/WPS)."
    examples = ("lance fern-wifi-cracker sur wlan0",)
    parameters = (ParameterSpec("interface", "Interface sans fil", "string"),)
    positionals = (Positional("interface"),)
    patterns = (Pattern(r"cracked|key found", "Cle Wi-Fi trouvee: {0}", "high", "Reseau compromis."),)


class KismetCoreTool(SpecTool):
    name = "kismet-core"
    aliases = ("kismet",)
    binary = "kismet"
    risk = "medium"
    description = "Detecteur de reseaux sans fil (passif, multi-cartes)."
    examples = ("detecte les reseaux sans fil de wlan0 avec kismet-core",)
    parameters = (
        ParameterSpec("interface", "Interface (-c)", "string"),
        ParameterSpec("logdir", "Repertoire de journaux", "string"),
    )
    options = (Option("interface", "-c"),)
    patterns = (
        Pattern(r"BSSID|SSID", "Reseau detecte: {0}", "info"),
        Pattern(r"WPA|WEP|Open", "Chiffrement: {0}", "info"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\b(wlan\d+|mon\d+)\b", text, re.IGNORECASE)
        if m:
            params["interface"] = m.group(1)
        return params


class WigNgTool(SpecTool):
    name = "wig-ng"
    binary = "wig-ng"
    risk = "high"
    description = "Cartographie les applications web exposees sur les reseaux sans fil."
    examples = ("cartographie les applications web de wlan0 avec wig-ng",)
    parameters = (ParameterSpec("interface", "Interface sans fil", "string"),)
    positionals = (Positional("interface"),)
    patterns = (Pattern(r"(https?://\S+)", "Application trouvee: {0}", "medium"),)


class AirgeddonTool(SpecTool):
    name = "airgeddon"
    binary = "airgeddon"
    risk = "high"
    description = "Suite d'audit Wi-Fi (WPA/WPS, evil twin, desauth)."
    examples = ("lance airgeddon sur wlan0",)
    parameters = (ParameterSpec("interface", "Interface sans fil", "string"),)
    positionals = (Positional("interface"),)
    patterns = (
        Pattern(r"handshake", "Handshake capture: {0}", "high", "Poignee de main WPA capturee."),
        Pattern(r"key|cracked", "Cle trouvee: {0}", "critical", "Reseau compromis."),
    )


class Eapmd5passTool(SpecTool):
    name = "eapmd5pass"
    binary = "eapmd5pass"
    risk = "high"
    description = "Casse les identifiants EAP-MD5 captures sur un reseau Wi-Fi."
    examples = ("casse la capture eap capture.pcap avec eapmd5pass",)
    parameters = (
        ParameterSpec("pcap", "Capture EAP (-r)", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-w)", "string"),
    )
    options = (Option("pcap", "-r"), Option("wordlist", "-w"))
    patterns = (
        Pattern(r"Password|found", "Mot de passe EAP trouve: {0}", "high", "Authentification cassee."),
    )


class FreeradiusTool(SpecTool):
    name = "freeradius"
    binary = "freeradius"
    risk = "medium"
    description = "Serveur RADIUS (authentification 802.1X)."
    examples = ("lance le serveur freeradius",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-X)", "string"),
        ParameterSpec("debug", "Mode debug (-X)", "bool", default=False),
    )
    flags = (Flag("debug", "-X"),)
    patterns = (Pattern(r"Ready to process requests", "Serveur RADIUS pret", "info"),)


class FreeradiusWpeTool(SpecTool):
    name = "freeradius-wpe"
    binary = "freeradius-wpe"
    risk = "high"
    description = "Faux serveur RADIUS pour capturer les identifiants EAP/MSCHAP."
    examples = ("lance freeradius-wpe pour capturer des identifiants",)
    parameters = (ParameterSpec("debug", "Mode debug (-X)", "bool", default=False),)
    flags = (Flag("debug", "-X"),)
    patterns = (
        Pattern(r"MSCHAP|Challenge", "Identifiants MSCHAP captures", "critical", "Empreintes EAP revelees."),
    )


class SparrowWifiTool(SpecTool):
    name = "sparrow-wifi"
    binary = "sparrow-wifi"
    risk = "medium"
    description = "Analyseur Wi-Fi graphique avec GPS et mode avance."
    examples = ("lance sparrow-wifi sur wlan0",)
    parameters = (ParameterSpec("interface", "Interface sans fil", "string"),)
    positionals = (Positional("interface"),)
    patterns = (Pattern(r"BSSID|SSID", "Reseau detecte: {0}", "info"),)


class WifiHoneyTool(SpecTool):
    name = "wifi-honey"
    binary = "wifi-honey"
    risk = "high"
    description = "Cree un faux point d'acces (honeypot) pour pieger les clients."
    examples = ("cree un faux point d'acces avec wifi-honey",)
    parameters = (
        ParameterSpec("essid", "Nom du faux reseau", "string"),
        ParameterSpec("interface", "Interface sans fil", "string"),
    )
    positionals = (Positional("essid"),)
    patterns = (
        Pattern(r"client|associated", "Client piege: {0}", "high", "Client connecte au honeypot."),
    )


# --------------------------------------------------------------------------
# Bluetooth
# --------------------------------------------------------------------------
class BluelogTool(SpecTool):
    name = "bluelog"
    binary = "bluelog"
    risk = "medium"
    description = "Journalise les appareils Bluetooth a portee."
    examples = ("journalise les appareils bluetooth de hci0 avec bluelog",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("interface", "-i"), Option("output", "-o"))
    patterns = (Pattern(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", "Appareil: {0}", "info"),)


class BluezHcidumpTool(SpecTool):
    name = "bluez-hcidump"
    aliases = ("hcidump",)
    binary = "hcidump"
    risk = "medium"
    description = "Capture et analyse le trafic Bluetooth HCI."
    examples = ("capture le trafic bluetooth de hci0 avec bluez-hcidump",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("output", "Fichier de sortie (-w)", "string"),
    )
    options = (Option("interface", "-i"), Option("output", "-w"))
    patterns = (
        Pattern(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", "Appareil: {0}", "info"),
    )


class BtscannerTool(SpecTool):
    name = "btscanner"
    binary = "btscanner"
    risk = "medium"
    description = "Scanne les appareils Bluetooth et leurs services."
    examples = ("scanne les appareils bluetooth de hci0 avec btscanner",)
    parameters = (ParameterSpec("interface", "Interface (-i)", "string"),)
    options = (Option("interface", "-i"),)
    patterns = (
        Pattern(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", "Appareil Bluetooth: {0}", "info"),
    )


class RedfangTool(SpecTool):
    name = "redfang"
    binary = "fang"
    risk = "medium"
    description = "Decouvre les appareils Bluetooth non decouvrables (brute force MAC)."
    examples = ("decouvre les appareils caches avec redfang",)
    parameters = (
        ParameterSpec("range", "Plage d'adresses MAC (-r)", "string", required=True),
        ParameterSpec("delay", "Delai (-s)", "int"),
    )
    options = (Option("range", "-r"), Option("delay", "-s"))
    patterns = (
        Pattern(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", "Appareil cache trouve: {0}", "medium"),
    )


class SpooftoophTool(SpecTool):
    name = "spooftooph"
    binary = "spooftooph"
    risk = "high"
    description = "Usurpe l'adresse et le nom d'un appareil Bluetooth."
    examples = ("usurpe l'adresse bluetooth AA:BB:CC:DD:EE:FF avec spooftooph",)
    parameters = (
        ParameterSpec("mac", "Adresse MAC (-a)", "string", required=True),
        ParameterSpec("name", "Nom a usurper (-n)", "string"),
    )
    options = (Option("mac", "-a"), Option("name", "-n"))
    patterns = (Pattern(r"spoofed|changed", "Identite Bluetooth usurpee", "high", "Usurpation Bluetooth."),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", text)
        if m:
            params["mac"] = m.group(1)
        return params


for _tool in (
    FernWifiCrackerTool(), KismetCoreTool(), WigNgTool(), AirgeddonTool(),
    Eapmd5passTool(), FreeradiusTool(), FreeradiusWpeTool(), SparrowWifiTool(),
    WifiHoneyTool(), BluelogTool(), BluezHcidumpTool(), BtscannerTool(),
    RedfangTool(), SpooftoophTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Radio logicielle (SDR)
# --------------------------------------------------------------------------
class GqrxSdrTool(SpecTool):
    name = "gqrx-sdr"
    aliases = ("gqrx",)
    binary = "gqrx"
    risk = "medium"
    description = "Recepteur SDR graphique (analyse de spectre, demodulation)."
    examples = ("lance gqrx-sdr pour analyser le spectre",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("device", "Appareil SDR (-d)", "string"),
    )
    options = (Option("config", "-c"), Option("device", "-d"))
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Frequence detectee: {0}", "info"),)


class GrAirModesTool(SpecTool):
    name = "gr-air-modes"
    binary = "gr-air-modes"
    risk = "medium"
    description = "Decode les signaux ADS-B des avions (suivi aerien)."
    examples = ("decode les signaux ads-b avec gr-air-modes",)
    parameters = (
        ParameterSpec("gain", "Gain (-g)", "string"),
        ParameterSpec("frequency", "Frequence (-f)", "string"),
    )
    options = (Option("gain", "-g"), Option("frequency", "-f"))
    patterns = (
        Pattern(r"([0-9A-F]{6})", "Avion detecte (ICAO): {0}", "info"),
    )


class InspectrumTool(SpecTool):
    name = "inspectrum"
    binary = "inspectrum"
    risk = "medium"
    description = "Analyse visuelle d'un enregistrement de signal (SDR)."
    examples = ("analyse l'enregistrement signal.wav avec inspectrum",)
    parameters = (ParameterSpec("file", "Fichier d'enregistrement", "string", required=True),)
    positionals = (Positional("file"),)
    patterns = (Pattern(r"(\d+)\s*Hz", "Frequence: {0}", "info"),)


class RtlsdrScannerTool(SpecTool):
    name = "rtlsdr-scanner"
    binary = "rtlsdr-scanner"
    risk = "medium"
    description = "Scanner de spectre SDR (RTL-SDR) avec carte de couverture."
    examples = ("scanne le spectre avec rtlsdr-scanner",)
    parameters = (
        ParameterSpec("start", "Frequence de debut", "string"),
        ParameterSpec("stop", "Frequence de fin", "string"),
    )
    options = (Option("start", "-s"), Option("stop", "-e"))
    patterns = (Pattern(r"(\d+)\s*Hz", "Signal detecte a {0}", "info"),)


# --------------------------------------------------------------------------
# RFID / NFC
# --------------------------------------------------------------------------
class LibfreefareTool(SpecTool):
    name = "libfreefare-bin"
    aliases = ("freefare",)
    binary = "mifare-classic-format"
    risk = "high"
    description = "Lit et ecrit les cartes MIFARE (secteurs, blocs)."
    examples = ("formate une carte mifare avec libfreefare-bin",)
    parameters = (ParameterSpec("device", "Peripherique NFC", "string"),)
    positionals = (Positional("device"),)
    patterns = (Pattern(r"UID:\s*([0-9A-Fa-f ]+)", "UID de la carte: {0}", "info"),)


class LibnfcBinTool(SpecTool):
    name = "libnfc-bin"
    aliases = ("nfc-poll",)
    binary = "nfc-poll"
    risk = "medium"
    description = "Suite NFC: detecte, lit et emule des cartes (libnfc)."
    examples = ("detecte les cartes nfc a portee avec libnfc-bin",)
    parameters = (ParameterSpec("device", "Peripherique NFC", "string"),)
    positionals = (Positional("device"),)
    patterns = (
        Pattern(r"UID[^\n]*?([0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2})+)", "Carte detectee (UID): {0}", "info"),
    )


class MftermTool(SpecTool):
    name = "mfterm"
    binary = "mfterm"
    risk = "high"
    description = "Terminal interactif pour manipuler les cartes MIFARE."
    examples = ("ouvre mfterm pour manipuler une carte mifare",)
    parameters = (ParameterSpec("keyfile", "Fichier de cles", "string"),)
    positionals = (Positional("keyfile"),)
    patterns = (Pattern(r"Key [A-B]\s*:\s*([0-9A-Fa-f]{12})", "Cle MIFARE trouvee: {0}", "high", "Cle de carte revelee."),)


# --------------------------------------------------------------------------
# Autres (SDR generique)
# --------------------------------------------------------------------------
class GnuradioTool(SpecTool):
    name = "gnuradio"
    binary = "gnuradio-companion"
    risk = "medium"
    description = "Framework de traitement du signal (SDR) avec interface graphique."
    examples = ("lance gnuradio pour construire un flux de traitement",)
    parameters = (ParameterSpec("flowgraph", "Graphe de traitement (.grc)", "string"),)
    positionals = (Positional("flowgraph"),)
    patterns = (Pattern(r"Running|started", "Flux GNU Radio demarre", "info"),)


class HackrfTool(SpecTool):
    name = "hackrf"
    binary = "hackrf_transfer"
    risk = "high"
    description = "Emet et recoit des signaux radio avec un HackRF (TX/RX)."
    examples = ("capture un signal avec hackrf sur 433 mhz",)
    parameters = (
        ParameterSpec("frequency", "Frequence (-f)", "string"),
        ParameterSpec("sample_rate", "Frequence d'echantillonnage (-s)", "string"),
        ParameterSpec("output", "Fichier de sortie (-r)", "string"),
    )
    options = (Option("frequency", "-f"), Option("sample_rate", "-s"), Option("output", "-r"))
    patterns = (Pattern(r"(\d+)\s*Hz", "Signal a {0}", "info"),)


class UbertoothTool(SpecTool):
    name = "ubertooth"
    binary = "ubertooth-rx"
    risk = "high"
    description = "Capture et analyse le Bluetooth avec un Ubertooth."
    examples = ("capture le bluetooth avec ubertooth",)
    parameters = (
        ParameterSpec("channel", "Canal (-c)", "string"),
        ParameterSpec("output", "Fichier de sortie (-r)", "string"),
    )
    options = (Option("channel", "-c"), Option("output", "-r"))
    patterns = (
        Pattern(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", "Appareil Bluetooth: {0}", "info"),
    )


for _tool in (
    GqrxSdrTool(), GrAirModesTool(), InspectrumTool(), RtlsdrScannerTool(),
    LibfreefareTool(), LibnfcBinTool(), MftermTool(), GnuradioTool(), HackrfTool(),
    UbertoothTool(),
):
    register(_tool)
