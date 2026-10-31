"""Expert DNS (classe Information Gathering / DNS Analysis).

Premier expert de la suite: il maitrise les outils DNS et leurs patterns.
Son modele peut etre remplace par une IA entrainee pour cette classe
(via le champ `model` ou la config `expert_models.dns`).
"""

from __future__ import annotations

from .base import Expert

DNS_EXPERT = Expert(
    name="dns",
    description="Resolution et investigation DNS (enregistrements, transferts de zone).",
    system_prompt=(
        "Tu es un expert DNS. Tu choisis l'outil le plus adapte parmi dig, host et "
        "whois, et tu extrais les parametres exacts. Pour des enregistrements precis "
        "(A, MX, NS, TXT, SOA, CNAME) ou un transfert de zone, utilise dig. Pour une "
        "simple resolution d'IP ou une resolution inverse, utilise host. Pour la "
        "propriete d'un domaine ou sa date d'expiration, utilise whois."
    ),
    tool_names=["dig", "host", "whois"],
    routing_rules=(
        (
            "whois",
            ("qui possede", "proprietaire", "propriete", "expiration", "expire", "registrar", "whois"),
        ),
        ("host", ("ip", "adresse ip", "resolution inverse", "inverse", "ptr", "adresse")),
        (
            "dig",
            (
                "enregistrement",
                "record",
                "mx",
                "ns",
                "txt",
                "soa",
                "cname",
                "aaaa",
                "axfr",
                "transfert de zone",
                "serveur de noms",
                "nameserver",
                "resous",
                "resoudre",
                "resolution",
            ),
        ),
    ),
    keywords=(
        "dns",
        "domaine",
        "domain",
        "sous-domaine",
        "subdomain",
        "enregistrement",
        "record",
        "mx",
        "nameserver",
        "serveur de noms",
        "resolution",
        "resous",
        "resoudre",
        "transfert de zone",
        "axfr",
        "whois",
        "ptr",
        "txt",
    ),
)
