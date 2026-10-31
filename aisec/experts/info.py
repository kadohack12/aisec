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
    description="Reconnaissance: hotes, ports, TLS, WAF, OSINT, SMB/SNMP et enumeration DNS avancee.",
    system_prompt=(
        "Tu es un expert en reconnaissance (Information Gathering). Tu choisis l'outil "
        "le plus adapte parmi nmap, masscan, arp-scan, naabu, unicornscan, sslscan, "
        "sslyze, ssldump, tlssled, wafw00f, dnsrecon, amass, dnsenum, fierce, "
        "theHarvester, recon-ng, spiderfoot, sherlock, enum4linux, smbmap, nbtscan, "
        "smtp-user-enum, swaks, onesixtyone, snmpcheck, dmitry, netdiscover, fping, "
        "hping3, ike-scan et trufflehog, et tu extrais les parametres exacts. Utilise "
        "nmap pour un scan de ports detaille avec detection de services; masscan/naabu "
        "pour scanner une large plage tres vite; arp-scan/netdiscover pour le reseau "
        "local; sslscan/sslyze pour la configuration TLS; wafw00f pour un WAF; "
        "dnsrecon/amass/dnsenum/fierce pour l'enumeration DNS; theHarvester/recon-ng/"
        "spiderfoot pour l'OSINT; enum4linux/smbmap/nbtscan pour SMB; smtp-user-enum/"
        "swaks pour SMTP; onesixtyone/snmpcheck pour SNMP. L'expert DNS dedie (`dns`) "
        "reste la reference pour dig/host/whois."
    ),
    tool_names=[
        "nmap", "masscan", "arp-scan", "sslscan", "wafw00f", "dnsrecon",
        "amass", "certgraph", "dnsenum", "dnsmap", "dnstracer", "dnswalk",
        "fierce", "urlcrazy", "assetfinder", "bing-ip2hosts", "cloud-enum",
        "emailharvester", "goofile", "inspy", "instaloader", "metagoofil",
        "osrframework", "python3-censys", "python3-shodan", "sherlock",
        "spiderfoot", "theharvester", "enum4linux", "enum4linux-ng", "nbtscan",
        "polenum", "smbmap", "ismtp", "smtp-user-enum", "swaks", "braa",
        "onesixtyone", "snmpcheck", "amap", "autorecon", "clamav", "dmitry",
        "geoip-bin", "ike-scan", "kerberoast", "legion", "mac-robber", "maltego",
        "naabu", "ndiff", "netdiscover", "nmapsi4", "p0f", "patchleaks",
        "recon-ng", "savi", "syft", "trufflehog", "witnessme", "arping", "fping",
        "hping3", "iputils-arping", "maryam", "ncat", "firewalk", "fragrouter",
        "ftester", "lbd", "2ping", "dbd", "netcat-openbsd", "unicornscan",
        "0trace", "intrace", "irpas", "netmask", "ssldump", "sslh", "sslyze",
        "tlssled",
    ],
    routing_rules=(
        ("amass", ("amass", "cartographie les domaines", "cartographie les sous-domaines")),
        ("trufflehog", ("trufflehog", "secrets dans", "fuite de secrets", "cle exposee")),
        ("syft", ("syft", "sbom", "inventaire des composants")),
        ("witnessme", ("witnessme", "capture des pages web", "capturer les applications")),
        ("kerberoast", ("kerberoast", "kerberoasting", "ticket kerberos")),
        ("ike-scan", ("ike-scan", "ipsec", "vpn ike")),
        ("enum4linux-ng", ("enum4linux-ng", "enum4linux moderne")),
        ("enum4linux", ("enum4linux", "enumeration smb", "partages smb")),
        ("smbmap", ("smbmap", "permissions smb", "lecture ecriture smb")),
        ("smtp-user-enum", ("smtp-user-enum", "utilisateurs smtp", "vrfy")),
        ("swaks", ("swaks", "test smtp", "relais smtp")),
        ("onesixtyone", ("onesixtyone", "communautes snmp", "communaute snmp")),
        ("snmpcheck", ("snmpcheck", "informations snmp", "enumeration snmp")),
        ("theharvester", ("theharvester", "collecte les emails", "collecte les adresses")),
        ("recon-ng", ("recon-ng", "framework osint", "reconnaissance modulaire")),
        ("spiderfoot", ("spiderfoot", "osint automatise", "collecte multi-sources")),
        ("sherlock", ("sherlock", "pseudonyme", "traque le pseudo")),
        ("sslyze", ("sslyze", "audit tls", "audit de la configuration tls")),
        ("ssldump", ("ssldump", "session tls", "analyser le tls")),
        ("tlssled", ("tlssled", "evalue la configuration tls")),
        ("fierce", ("fierce",)),
        ("dnsenum", ("dnsenum",)),
        ("naabu", ("naabu", "scanner de ports rapide")),
        ("unicornscan", ("unicornscan", "scanner asynchrone")),
        ("arp-scan", ("arp-scan", "arp scan", "reseau local", "localnet", "adresse mac", "decouverte arp", "decouvre les hotes", "hotes du reseau", "hotes sur")),
        ("netdiscover", ("netdiscover",)),
        ("hping3", ("hping3", "forge les paquets", "paquets personnalises")),
        ("fping", ("fping", "ping en parallele", "plage de ping")),
        ("wafw00f", ("wafw00f", "waf", "pare-feu applicatif", "pare feu applicatif")),
        ("sslscan", ("sslscan", "certificat", "chiffrement tls", "configuration ssl", "configuration tls")),
        ("dnsrecon", ("dnsrecon", "transfert de zone", "axfr", "enumeration dns", "brute force dns", "reverse lookup")),
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
        "sslyze",
        "wafw00f",
        "waf",
        "dnsrecon",
        "amass",
        "dnsenum",
        "fierce",
        "osint",
        "shodan",
        "censys",
        "theharvester",
        "recon-ng",
        "spiderfoot",
        "sherlock",
        "smb",
        "enum4linux",
        "smbmap",
        "smtp",
        "swaks",
        "snmp",
        "onesixtyone",
        "certificat",
        "ike-scan",
        "ipsec",
        "netdiscover",
        "naabu",
        "hping3",
        "trufflehog",
    ),
)
