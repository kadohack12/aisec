"""Expert Web Application Analysis (classe `03-webapp-analysis`).

Couvre les scanners de vulnerabilites web, le fingerprinting de technologies,
les crawlers et le bruteforce de repertoires. Le prompt oriente le choix de
l'outil et le routage heuristique (sans LLM) suit les memes regles.
"""

from __future__ import annotations

from .base import Expert

WEBAPP_EXPERT = Expert(
    name="webapp",
    description="Analyse d'applications web: scanners, fingerprinting, crawlers, bruteforce.",
    system_prompt=(
        "Tu es un expert en analyse d'applications web. Tu choisis l'outil le plus "
        "adapte parmi ceux de ton domaine et tu extrais les parametres exacts. "
        "Pour un scan de vulnerabilites generaliste d'un serveur, utilise nikto ; "
        "pour une application, wapiti. Pour identifier les technologies (CMS, "
        "serveur, framework), utilise whatweb. Pour WordPress ou Joomla, utilise "
        "wpscan ou joomscan. Pour decouvrir des repertoires ou fichiers, utilise "
        "gobuster, ffuf, feroxbuster, dirb, dirsearch ou wfuzz. Pour decouvrir des "
        "parametres HTTP caches, utilise arjun. Pour explorer les liens d'un site, "
        "utilise gospider ou httrack. Pour tester les failles XSS, utilise xsser. "
        "Pour tester un serveur WebDAV, utilise davtest. Pour verifier un bucket "
        "S3, utilise s3scanner."
    ),
    tool_names=[
        "nikto",
        "whatweb",
        "wpscan",
        "joomscan",
        "gobuster",
        "ffuf",
        "dirb",
        "feroxbuster",
        "wfuzz",
        "arjun",
        "gospider",
        "dirsearch",
        "wapiti",
        "xsser",
        "skipfish",
        "s3scanner",
        "davtest",
        "httrack",
    ],
    routing_rules=(
        ("wpscan", ("wordpress", "wp-", "wp admin", "wp-admin")),
        ("joomscan", ("joomla",)),
        ("whatweb", ("technologie", "fingerprint", "empreinte", "cms", "quel serveur", "quelle techno")),
        ("nikto", ("nikto", "serveur web", "erreurs de configuration", "mauvaise configuration")),
        ("wapiti", ("vulnerabilite", "vulnerabilites", "injection", "ssrf", "scan complet")),
        ("xsser", ("xss", "cross site scripting")),
        ("davtest", ("webdav", "dav ")),
        ("s3scanner", ("bucket", "s3", "stockage objet")),
        ("arjun", ("parametre", "parametres", "query string", "hidden parameter")),
        ("gospider", ("crawle", "crawler", "spider", "explorer les liens")),
        ("httrack", ("miroir", "copie du site", "hors-ligne", "offline")),
        ("gobuster", ("gobuster", "vhost", "sous-domaine", "subdomain")),
        ("ffuf", ("ffuf", "fuzz", "fuzzing")),
        ("feroxbuster", ("feroxbuster", "recursif", "recursive")),
        ("dirsearch", ("dirsearch",)),
        ("wfuzz", ("wfuzz",)),
        ("dirb", ("dirb",)),
        ("skipfish", ("skipfish",)),
        (
            "gobuster",
            (
                "bruteforce",
                "brute force",
                "repertoire",
                "repertoires",
                "directory",
                "fichier",
                "fichiers",
                "chemins",
                "chemin",
            ),
        ),
    ),
    keywords=(
        "web",
        "site",
        "application web",
        "http",
        "https",
        "url",
        "nikto",
        "whatweb",
        "wpscan",
        "wordpress",
        "joomla",
        "gobuster",
        "ffuf",
        "feroxbuster",
        "dirb",
        "dirsearch",
        "wfuzz",
        "arjun",
        "gospider",
        "crawler",
        "crawle",
        "spider",
        "wapiti",
        "xsser",
        "xss",
        "skipfish",
        "s3scanner",
        "bucket s3",
        "webdav",
        "davtest",
        "httrack",
        "repertoire",
        "repertoires",
        "directory",
        "bruteforce",
        "brute force",
        "parametres",
        "vulnerabilite web",
    ),
)
