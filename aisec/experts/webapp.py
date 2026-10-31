"""Expert Web Application Analysis (classe 03).

Classe Parrot `03-webapp-analysis` (38 outils): analyse directe, CMS, crawlers
et bruteforce de repertoires, proxies, scanners de vulnerabilites web.
L'expert choisit l'outil de sa classe et en extrait les parametres; les outils
de fuzzing et d'exploitation restent soumis a la politique de controle (niveau 2).
"""

from __future__ import annotations

from .base import Expert

WEBAPP_EXPERT = Expert(
    name="webapp",
    description="Analyse d'application web: empreinte, bruteforce, scanners, CMS, proxies.",
    system_prompt=(
        "Tu es un expert en analyse d'applications web. Tu choisis l'outil le plus "
        "adapte parmi ceux de ta classe et tu extrais les parametres exacts.\n"
        "- Identifier les technologies/CMS d'un site -> whatweb, wig.\n"
        "- WordPress -> wpscan ; Joomla -> joomscan.\n"
        "- Bruteforce de repertoires et fichiers -> gobuster, ffuf, feroxbuster, "
        "dirb, dirsearch, wfuzz.\n"
        "- Decouvrir des parametres caches -> arjun ; crawler un site -> gospider, httrack.\n"
        "- Scanner les vulnerabilites d'un serveur web -> nikto, wapiti, skipfish, "
        "owasp-zap ; injections SQL -> jsql-injection, wapiti ; XSS -> xsser, wapiti.\n"
        "- WebDAV -> cadaver, davtest ; padding oracle -> padbuster ; Heartbleed -> heartleech.\n"
        "- Buckets S3 -> s3scanner ; robots.txt -> parsero.\n"
        "- Proxies d'interception (analyse manuelle) -> burpsuite, caido, paros, webscarab.\n"
        "Un scan actif ou un fuzzing est intrusif: ne le propose que si la demande "
        "est explicite et sur une cible autorisee."
    ),
    tool_names=[
        # Analyse directe
        "httrack",
        "paros",
        "parsero",
        "s3scanner",
        "skipfish",
        "webscarab",
        "wig",
        "wpscan",
        "zaproxy",
        # CMS
        "joomscan",
        # Crawlers & bruteforce
        "apache-users",
        "arjun",
        "cutycapt",
        "dirb",
        "dirbuster",
        "dirsearch",
        "feroxbuster",
        "ffuf",
        "gobuster",
        "gospider",
        "uniscan",
        "wfuzz",
        # Proxies
        "burpsuite",
        "caido",
        "goshs",
        # Scanners de vulnerabilites web
        "cadaver",
        "davtest",
        "heartleech",
        "jboss-autopwn",
        "jsql-injection",
        "nikto",
        "owasp-mantra-ff",
        "padbuster",
        "wapiti",
        "watobo",
        "websploit",
        "whatweb",
        "xsser",
    ],
    routing_rules=(
        ("wpscan", ("wordpress", "wp-", "wp ", "wpscan")),
        ("joomscan", ("joomla",)),
        ("whatweb", ("technologie", "empreinte", "fingerprint", "cms", "framework", "identifie le site")),
        ("wig", ("quel cms", "detecte le cms", "wig")),
        ("ffuf", ("fuzz", "fuuf", "mot-cle fuzz")),
        ("wfuzz", ("wfuzz",)),
        ("gobuster", ("repertoire", "directory", "dossier", "gobuster", "sous-domaine", "subdomain", "vhost")),
        ("feroxbuster", ("feroxbuster", "recursif rapide")),
        ("dirsearch", ("dirsearch", "chemins caches", "fichiers caches")),
        ("dirb", ("dirb", "bruteforce les dossiers")),
        ("dirbuster", ("dirbuster",)),
        ("arjun", ("parametre cache", "parametres caches", "arjun")),
        ("gospider", ("crawle", "crawler", "spider", "explore le site")),
        ("httrack", ("miroir", "aspire", "copie le site", "hors ligne", "httrack")),
        ("nikto", ("nikto", "scanne le serveur web", "serveur web")),
        ("wapiti", ("wapiti", "scanne les vulnerabilites", "scan complet web")),
        ("skipfish", ("skipfish",)),
        ("zaproxy", ("zap", "owasp zap", "zaproxy")),
        ("xsser", ("xss", "cross site scripting")),
        ("jsql-injection", ("injection sql", "sql injection", "jsql")),
        ("davtest", ("webdav", "davtest")),
        ("cadaver", ("cadaver", "client webdav")),
        ("padbuster", ("padding oracle", "padbuster", "cookie chiffre")),
        ("heartleech", ("heartbleed", "heartleech")),
        ("jboss-autopwn", ("jboss",)),
        ("s3scanner", ("bucket", "s3", "stockage objet")),
        ("parsero", ("robots.txt", "robots", "parsero")),
        ("apache-users", ("userdir", "utilisateurs apache", "apache-users")),
        ("uniscan", ("uniscan",)),
        ("cutycapt", ("capture", "screenshot", "image de la page")),
        ("burpsuite", ("burp", "burpsuite")),
        ("caido", ("caido",)),
        ("paros", ("paros",)),
        ("webscarab", ("webscarab",)),
        ("watobo", ("watobo",)),
        ("owasp-mantra-ff", ("mantra",)),
        ("goshs", ("goshs", "partage de fichiers", "serveur http")),
        ("websploit", ("websploit",)),
    ),
    keywords=(
        "web",
        "site",
        "url",
        "http",
        "https",
        "application web",
        "serveur web",
        "technologie",
        "empreinte",
        "fingerprint",
        "cms",
        "wordpress",
        "joomla",
        "drupal",
        "repertoire",
        "directory",
        "dossier",
        "bruteforce",
        "fuzz",
        "crawler",
        "spider",
        "proxy",
        "nikto",
        "wpscan",
        "xss",
        "injection sql",
        "sql",
        "webdav",
        "bucket",
        "robots.txt",
        "parametre",
        "endpoint",
        "formulaire",
    ),
)
