"""Expert Password Attacks (classe 05-password-attacks).

Premier jalon: attaque en ligne (hydra), cassage hors ligne (john),
identification de hash (hashid) et generation de dictionnaire (cewl).
"""

from __future__ import annotations

from .base import Expert

PASSWORD_EXPERT = Expert(
    name="password",
    description="Attaques de mots de passe: en ligne (hydra), hors ligne (john), hashid, cewl.",
    system_prompt=(
        "Tu es un expert en attaques de mots de passe. Tu choisis l'outil le plus "
        "adapte parmi hydra, john, hashid et cewl, et tu extrais les parametres "
        "exacts. Utilise hydra pour une attaque en ligne sur un service (ssh, ftp, "
        "rdp, http). Utilise john pour casser des hashes hors ligne. Utilise hashid "
        "pour identifier le type d'un hash. Utilise cewl pour generer un dictionnaire "
        "a partir du contenu d'un site. Rappelle que ces actions exigent une "
        "autorisation explicite."
    ),
    tool_names=["hydra", "john", "hashid", "cewl"],
    routing_rules=(
        ("hashid", ("hashid", "identifier le hash", "type de hash", "quel type de hash")),
        ("john", ("john", "hors ligne", "offline", "casser le hash", "crack", "ntlm", "md5crypt")),
        ("cewl", ("cewl", "dictionnaire", "wordlist", "mots du site", "generer une liste")),
        (
            "hydra",
            ("hydra", "brute force", "force brute", "attaque en ligne", "en ligne", "online", "ssh", "ftp", "rdp", "smb", "mysql"),
        ),
    ),
    keywords=(
        "mot de passe",
        "mots de passe",
        "password",
        "hash",
        "hashcat",
        "john",
        "hydra",
        "hashid",
        "cewl",
        "brute force",
        "force brute",
        "bruteforce",
        "crack",
        "wordlist",
        "dictionnaire",
        "rockyou",
        "identifiants",
        "credentials",
        "ntlm",
        "kerberos",
    ),
)
