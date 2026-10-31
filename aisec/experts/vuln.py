"""Expert Vulnerability Analysis (classe `02-vulnerability-analysis`).

Couvre l'audit TLS/SSL, l'analyse statique de code, le fuzzing, le stress
testing, l'audit de configuration d'equipements reseau et les attaques de
niveau 2 de la classe Vulnerability Analysis.
"""

from __future__ import annotations

from .base import Expert

VULN_EXPERT = Expert(
    name="vuln",
    description="Analyse de vulnerabilites: audit TLS, SAST, fuzzing, stress, equipements reseau.",
    system_prompt=(
        "Tu es un expert en analyse de vulnerabilites. Tu choisis l'outil le plus "
        "adapte parmi ceux de ton domaine et tu extrais les parametres exacts. "
        "Pour auditer la configuration TLS/SSL (protocoles, ciphers, certificats, "
        "CVE), utilise testssl. Pour une analyse statique de code Python, utilise "
        "bandit. Pour un audit local de privilege escalation Unix, utilise "
        "unix-privesc-check. Pour fuzzer un service reseau, utilise sfuzz. Pour "
        "tester la resistance aux attaques slow HTTP, utilise slowhttptest. Pour un "
        "test de charge HTTP, utilise siege. Pour l'injection de trafic, utilise "
        "t50 ou dhcpig. Pour auditer un equipement Cisco ou une configuration "
        "reseau, utilise cisco-torch, nipper-ng ou yersinia."
    ),
    tool_names=[
        "testssl",
        "bandit",
        "unix-privesc-check",
        "sfuzz",
        "slowhttptest",
        "siege",
        "t50",
        "dhcpig",
        "cisco-torch",
        "nipper-ng",
        "yersinia",
    ],
    routing_rules=(
        ("testssl", ("tls", "ssl", "certificat", "certificate", "cipher", "chiffrement", "https")),
        ("bandit", ("code python", "python", "sast", "analyse statique", "code source")),
        ("unix-privesc-check", ("privilege escalation", "privesc", "elevation de privilege", "suid")),
        ("slowhttptest", ("slowloris", "slow http", "slow read", "deni de service lent")),
        ("siege", ("charge", "benchmark", "load test", "stress http")),
        ("sfuzz", ("fuzz", "fuzzing")),
        ("dhcpig", ("dhcp",)),
        ("cisco-torch", ("cisco",)),
        ("nipper-ng", ("configuration reseau", "config cisco", "routeur", "switch")),
        ("yersinia", ("vlan", "stp", "cdp", "dtp", "vtp", "niveau 2", "couche 2")),
        ("t50", ("injection", "injecte", "stress reseau")),
    ),
    keywords=(
        "vulnerabilite",
        "vulnerabilites",
        "audit",
        "tls",
        "ssl",
        "certificat",
        "cipher",
        "testssl",
        "bandit",
        "sast",
        "fuzz",
        "fuzzing",
        "stress",
        "charge",
        "slowloris",
        "privesc",
        "privilege escalation",
        "cisco",
        "nipper",
        "yersinia",
        "dhcp",
        "t50",
        "siege",
        "sfuzz",
        "slowhttptest",
    ),
)
