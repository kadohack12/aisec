"""Expert Sniffing & Spoofing (classe 09-sniffing-spoofing).

Premier jalon: reconnaissance reseau et MITM (bettercap), reutilisant
l'outil tshark deja livre pour l'analyse de trafic.
"""

from __future__ import annotations

from .base import Expert

SNIFFING_EXPERT = Expert(
    name="sniffing",
    description="Ecoute et usurpation reseau: sniffers (tshark, tcpflow) et MITM (bettercap, ettercap).",
    system_prompt=(
        "Tu es un expert en ecoute et usurpation reseau. Tu choisis l'outil le plus "
        "adapte parmi les sniffers (tshark, tcpflow, netsniff-ng, darkstat, driftnet, "
        "etherape, sslsniff) et les outils de spoofing/MITM (bettercap, ettercap, "
        "responder, dnschef, sslsplit, mitmproxy, macchanger, dsniff, tcpreplay), et tu "
        "extrais les parametres exacts. Utilise tshark pour capturer ou lire du trafic et "
        "appliquer des filtres d'affichage; tcpflow pour reconstituer les flux TCP; "
        "bettercap ou ettercap pour le MITM (ARP/DNS spoofing, sniffing, sslstrip); "
        "responder pour LLMNR/NBT-NS; dnschef/sslsplit/mitmproxy pour l'interception; "
        "macchanger pour changer l'adresse MAC. Ces actions exigent une autorisation explicite."
    ),
    tool_names=[
        "tshark", "bettercap",
        "etherape", "etherwake", "ettercap-text-only", "ettercap-graphical",
        "ferret-sidejack", "hamster-sidejack", "macchanger", "mitmproxy",
        "python3-impacket", "python3-scapy", "responder", "chaosreader", "darkstat",
        "driftnet", "hexinject", "netsniff-ng", "sslsniff", "tcpflow", "dnschef",
        "dsniff", "evil-ssdp", "fiked", "isr-evilgrade", "rebind", "sniffjoke",
        "sslsplit", "tcpreplay",
    ],
    routing_rules=(
        ("responder", ("responder", "llmnr", "nbt-ns", "ntlm", "netbios name")),
        ("dnschef", ("dnschef", "faux serveur dns", "dns spoof", "usurper le dns")),
        ("sslsplit", ("sslsplit", "proxy transparent", "interception tls", "intercepter le tls")),
        ("mitmproxy", ("mitmproxy", "proxy d'interception", "proxy http")),
        ("sslsniff", ("sslsniff", "dechiffrer le tls")),
        ("driftnet", ("driftnet", "images qui transitent", "capturer les images")),
        ("macchanger", ("macchanger", "adresse mac", "changer de mac")),
        ("dsniff", ("dsniff", "mots de passe en clair")),
        ("tcpreplay", ("tcpreplay", "rejouer un pcap", "rejouer le trafic")),
        ("tcpflow", ("tcpflow", "reconstituer les flux", "reconstitution de flux")),
        ("netsniff-ng", ("netsniff-ng", "sniffer haute performance")),
        ("darkstat", ("darkstat", "statistiques de trafic")),
        ("chaosreader", ("chaosreader", "reconstruire les sessions")),
        ("ettercap", ("ettercap", "arp poisoning", "empoisonnement arp")),
        ("bettercap", ("bettercap", "mitm", "arp spoof", "arp spoofing", "dns spoof", "sslstrip", "usurpation", "spoof", "probe")),
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
        "pcap",
        "mitm",
        "spoofing",
        "spoof",
        "usurpation",
        "arp",
        "ettercap",
        "responder",
        "macchanger",
        "tcpflow",
        "sslsplit",
        "dnschef",
        "driftnet",
        "wireshark",
        "tshark",
        "trafic",
        "paquets",
        "interception",
    ),
)
