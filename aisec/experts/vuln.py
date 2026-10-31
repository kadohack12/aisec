"""Expert Vulnerability Analysis (classe 02-vulnerability-analysis).

Premier jalon de la classe: audit TLS complet (testssl) et test de
resistance aux attaques lentes (slowhttptest). Les autres sous-categories
(Cisco, fuzzing, VoIP, stress) seront ajoutees au fil des outils.
"""

from __future__ import annotations

from .base import Expert

VULN_EXPERT = Expert(
    name="vuln",
    description="Analyse de vulnerabilites: audit TLS/SSL et tests de deni de service lent.",
    system_prompt=(
        "Tu es un expert en analyse de vulnerabilites. Tu choisis l'outil le plus "
        "adapte parmi testssl et slowhttptest, et tu extrais les parametres exacts. "
        "Utilise testssl pour un audit complet de la configuration TLS/SSL "
        "(protocoles, chiffrements, vulnerabilites comme Heartbleed ou ROBOT). "
        "Utilise slowhttptest pour tester la resistance d'un serveur web aux "
        "attaques lentes (Slowloris, slow POST, slow read)."
    ),
    tool_names=["testssl", "slowhttptest"],
    routing_rules=(
        (
            "slowhttptest",
            ("slowhttptest", "slowloris", "slow loris", "attaque lente", "slow read", "slow post", "deni de service", "dos"),
        ),
        (
            "testssl",
            ("testssl", "audit tls", "audit ssl", "vulnerabilite tls", "vulnerabilite ssl", "heartbleed", "robot", "cve"),
        ),
    ),
    keywords=(
        "vulnerabilite",
        "vulnerabilites",
        "vulnerability",
        "testssl",
        "slowhttptest",
        "slowloris",
        "slow loris",
        "audit tls",
        "audit ssl",
        "faiblesse",
        "cve",
        "heartbleed",
        "robot",
        "cisco",
        "fuzzing",
        "fuzz",
        "voip",
        "sip",
        "stress",
        "deni de service",
        "hardening",
    ),
)
