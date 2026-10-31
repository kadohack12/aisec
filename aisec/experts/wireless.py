"""Expert Wireless Testing (classe 06-wireless-attacks).

Jalon 1: Wi-Fi 802.11 (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, reaver,
wifite, mdk4, pixiewps, bully, cowpatty, asleap), Bluetooth (bluesnarfer,
blueranger, hcitool) et RFID/NFC (mfoc, mfcuk, nfc-list).
"""

from __future__ import annotations

from .base import Expert

WIRELESS_EXPERT = Expert(
    name="wireless",
    description="Tests sans fil: Wi-Fi (capture, WPS, cassage), Bluetooth et RFID/NFC.",
    system_prompt=(
        "Tu es un expert en test de reseaux sans fil. Tu choisis l'outil le plus "
        "adapte parmi airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, reaver, "
        "wifite, mdk4, pixiewps, bully, cowpatty, asleap, bluesnarfer, blueranger, "
        "hcitool, mfoc, mfcuk et nfc-list, puis tu extrais les parametres exacts. "
        "La capture et le scan sont passifs; la desauthentification, l'injection et "
        "le cassage de cle perturbent ou attaquent le reseau et exigent une "
        "confirmation. N'agis que sur un reseau que tu es autorise a tester."
    ),
    tool_names=[
        "airmon-ng",
        "airodump-ng",
        "aireplay-ng",
        "aircrack-ng",
        "reaver",
        "wifite",
        "mdk4",
        "pixiewps",
        "bully",
        "cowpatty",
        "asleap",
        "bluesnarfer",
        "blueranger",
        "hcitool",
        "mfoc",
        "mfcuk",
        "nfc-list",
    ],
    routing_rules=(
        ("airmon-ng", ("airmon", "mode moniteur", "monitor mode")),
        ("airodump-ng", ("airodump", "capture les reseaux", "capture le handshake", "capture les wifi", "scan wifi")),
        ("aireplay-ng", ("aireplay", "desauthentifie", "desauthentification", "deauth", "fakeauth", "rejeu", "chopchop")),
        ("aircrack-ng", ("aircrack", "casse le wpa", "casse le wep", "casser le wifi", "cracker le wifi")),
        ("reaver", ("reaver", "wps", "pin wps")),
        ("wifite", ("wifite", "attaque automatique wifi", "wifite --")),
        ("mdk4", ("mdk4", "mdk3", "robustesse", "test de charge wifi", "beacon flood", "desauthentification en masse")),
        ("pixiewps", ("pixiewps", "pixie dust", "pixie")),
        ("bully", ("bully",)),
        ("cowpatty", ("cowpatty",)),
        ("asleap", ("asleap", "leap", "cisco leap")),
        ("hcitool", ("hcitool", "peripheriques bluetooth", "scan bluetooth", "enumere les bluetooth", "scanne les bluetooth")),
        ("bluesnarfer", ("bluesnarfer", "extrait le repertoire", "extrait les contacts", "sms du telephone")),
        ("blueranger", ("blueranger", "localise le bluetooth", "localiser un bluetooth")),
        ("mfoc", ("mfoc", "mifare", "clone la carte")),
        ("mfcuk", ("mfcuk", "darkside")),
        ("nfc-list", ("nfc-list", "tags nfc", "tag nfc", "liste les nfc")),
    ),
    keywords=(
        "wifi",
        "wi-fi",
        "802.11",
        "wireless",
        "sans fil",
        "moniteur",
        "monitor",
        "handshake",
        "wpa",
        "wpa2",
        "wpa3",
        "wep",
        "wps",
        "aircrack",
        "airodump",
        "aireplay",
        "airmon",
        "deauth",
        "desauthentification",
        "beacon",
        "probe",
        "reaver",
        "wifite",
        "mdk3",
        "mdk4",
        "pixiewps",
        "bully",
        "cowpatty",
        "asleap",
        "leap",
        "bluetooth",
        "ble",
        "hci",
        "hcitool",
        "bluesnarfer",
        "blueranger",
        "nfc",
        "rfid",
        "mifare",
        "mfoc",
        "mfcuk",
        "sdr",
        "rtl-sdr",
        "rfcat",
    ),
)
