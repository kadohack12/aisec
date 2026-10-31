"""Expert Web Application Analysis (classe 03-webapp-analysis).

Premier jalon: empreinte web (whatweb), scanner de vulnerabilites web
(nikto) et force brute de repertoires/sous-domaines (gobuster, ffuf).
"""

from __future__ import annotations

from .base import Expert

WEB_EXPERT = Expert(
    name="web",
    description="Analyse d'applications web: empreinte, scan de vulnerabilites, fuzzing.",
    system_prompt=(
        "Tu es un expert en analyse d'applications web. Tu choisis l'outil le plus "
        "adapte parmi whatweb, nikto, gobuster et ffuf, et tu extrais les parametres "
        "exacts. Utilise whatweb pour l'empreinte (serveur, CMS, frameworks). "
        "Utilise nikto pour un scan de vulnerabilites de serveur web. Utilise "
        "gobuster pour le force brute de repertoires/fichiers ou de sous-domaines. "
        "Utilise ffuf pour le fuzzing web rapide (URL avec le mot-cle FUZZ)."
    ),
    tool_names=["whatweb", "nikto", "gobuster", "ffuf"],
    routing_rules=(
        ("whatweb", ("whatweb", "empreinte", "technologie", "fingerprint", "cms", "framework", "wordpress", "joomla")),
        ("nikto", ("nikto", "vulnerabilite web", "scanner le serveur web", "fichiers dangereux", "misconfiguration")),
        ("ffuf", ("ffuf", "fuzz", "fuzzing", "fuzz les parametres", "parametre")),
        (
            "gobuster",
            ("gobuster", "brute force", "force brute", "repertoires", "repertoire", "directory", "sous-domaines", "vhost"),
        ),
    ),
    keywords=(
        "web",
        "site",
        "application web",
        "http",
        "https",
        "url",
        "whatweb",
        "nikto",
        "gobuster",
        "ffuf",
        "repertoire",
        "repertoires",
        "directory",
        "fuzz",
        "fuzzing",
        "vulnerabilite web",
        "scanner web",
        "cms",
        "wordpress",
        "wpscan",
        "joomla",
        "crawler",
        "proxy",
        "burp",
        "zap",
    ),
)
