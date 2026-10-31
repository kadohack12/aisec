"""Expert Sniffing & Spoofing (classe 09-sniffing-spoofing).

Premier jalon: reconnaissance reseau et MITM (bettercap), reutilisant
l'outil tshark deja livre pour l'analyse de trafic.
"""

from __future__ import annotations

from .base import Expert

SNIFFING_EXPERT = Expert(
    name="sniffing",
    description="Ecoute et usurpation reseau: capture de trafic (tshark) et MITM (bettercap).",
    system_prompt=(
        "Tu es un expert en ecoute et usurpation reseau. Tu choisis l'outil le plus "
        "adapte parmi tshark et bettercap, et tu extrais les parametres exacts. "
        "Utilise tshark pour capturer ou lire du trafic et appliquer des filtres "
        "d'affichage. Utilise bettercap pour la reconnaissance reseau et les attaques "
        "de type MITM (ARP spoofing, DNS spoofing, sniffing, sslstrip). Ces actions "
        "exigent une autorisation explicite."
    ),
    tool_names=["tshark", "bettercap"],
    routing_rules=(
        (
            "bettercap",
            ("bettercap", "mitm", "arp spoof", "arp spoofing", "dns spoof", "sslstrip", "usurpation", "spoof", "probe"),
        ),
        (
            "tshark",
            ("tshark", "capture", "pcap", "sniff", "filtre", "paquets", "trafic", "wireshark"),
        ),
    ),
    keywords=(
        "sniffing",
        "sniffer",
        "ecoute",
        "espionnage",
        "capture",
        "pcap",
        "mitm",
        "spoofing",
        "spoof",
        "usurpation",
        "arp",
        "bettercap",
        "ettercap",
        "responder",
        "wireshark",
        "tshark",
        "trafic",
        "paquets",
        "interception",
    ),
)
