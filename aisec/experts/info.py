"""Expert Information Gathering (classe 01-info-gathering).

Couvre la reconnaissance: decouverte d'hotes (nmap, masscan, arp-scan),
analyse TLS (sslscan), detection de WAF (wafw00f) et enumeration DNS
avancee (dnsrecon). L'expert DNS dedie (`dns`) reste la reference pour
dig/host/whois.
"""

from __future__ import annotations

from .base import Expert

INFO_EXPERT = Expert(
    name="info",
    description="Reconnaissance: hotes, ports, TLS, WAF et enumeration DNS avancee.",
    system_prompt=(
        "Tu es un expert en reconnaissance (Information Gathering). Tu choisis l'outil "
        "le plus adapte parmi nmap, masscan, arp-scan, sslscan, wafw00f et dnsrecon, et "
        "tu extrais les parametres exacts. Utilise nmap pour un scan de ports detaille "
        "avec detection de services; masscan pour scanner une large plage tres vite; "
        "arp-scan pour decouvrir les hotes du reseau local par ARP; sslscan pour la "
        "configuration TLS d'un service; wafw00f pour identifier un WAF; dnsrecon pour "
        "l'enumeration DNS avancee (transfert de zone, force brute, reverse)."
    ),
    tool_names=["nmap", "masscan", "arp-scan", "sslscan", "wafw00f", "dnsrecon"],
    routing_rules=(
        ("wafw00f", ("wafw00f", "waf", "pare-feu applicatif", "pare feu applicatif")),
        ("sslscan", ("sslscan", "certificat", "chiffrement tls", "configuration ssl", "configuration tls")),
        ("dnsrecon", ("dnsrecon", "transfert de zone", "axfr", "enumeration dns", "brute force dns", "reverse lookup")),
        ("arp-scan", ("arp-scan", "arp scan", "reseau local", "localnet", "adresse mac", "decouverte arp")),
        ("masscan", ("masscan", "tres rapide", "tres vite", "grande plage", "rapidement")),
        (
            "nmap",
            (
                "nmap",
                "scan de ports",
                "scanner les ports",
                "hotes vivants",
                "live hosts",
                "decouverte",
                "version",
                "systeme d'exploitation",
                "os",
            ),
        ),
    ),
    keywords=(
        "reconnaissance",
        "recon",
        "enumeration",
        "enumerer",
        "decouverte",
        "hotes vivants",
        "live hosts",
        "scan reseau",
        "scanner reseau",
        "port",
        "ports",
        "scan de ports",
        "scanner les ports",
        "nmap",
        "masscan",
        "arp-scan",
        "arp scan",
        "sslscan",
        "wafw00f",
        "waf",
        "dnsrecon",
        "osint",
        "shodan",
        "censys",
        "smb",
        "smtp",
        "snmp",
        "certificat",
    ),
)
