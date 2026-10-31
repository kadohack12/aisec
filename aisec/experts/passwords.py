"""Expert Password Attacks (classe `05-password-attacks`).

Couvre l'identification de hash, les attaques en ligne (hydra, medusa, ncrack,
patator), les attaques hors ligne (hashcat, john, ophcrack) et la generation de
listes de mots (crunch, cewl, rsmangler). La politique de controle de niveau 2
classe ces outils en `high`/`critical`: rien ne s'execute sans confirmation.
"""

from __future__ import annotations

from .base import Expert

PASSWORDS_EXPERT = Expert(
    name="passwords",
    description="Attaques de mots de passe: en ligne, hors ligne, listes de mots, extraction locale.",
    system_prompt=(
        "Tu es un expert en attaques de mots de passe, dans un cadre de test "
        "d'intrusion autorise. Tu choisis l'outil le plus adapte parmi ceux de ton "
        "domaine et tu extrais les parametres exacts. Pour identifier un type de "
        "hash, utilise hash-identifier. Pour une attaque en ligne (SSH, FTP, RDP, "
        "SMB, formulaires HTTP), utilise hydra, medusa, ncrack ou patator. Pour une "
        "attaque hors ligne sur des hashes, utilise hashcat ou john. Pour les hashes "
        "Windows, utilise ophcrack. Pour extraire des hashes depuis une ruche SAM, "
        "utilise samdump2 ou chntpw. Pour generer une liste de mots de passe, utilise "
        "crunch ; pour la construire depuis un site, cewl ; pour la transformer, "
        "rsmangler."
    ),
    tool_names=[
        "hash-identifier",
        "hydra",
        "medusa",
        "ncrack",
        "patator",
        "hashcat",
        "john",
        "ophcrack",
        "samdump2",
        "chntpw",
        "crunch",
        "cewl",
        "rsmangler",
    ],
    routing_rules=(
        ("cewl", ("depuis le site", "depuis un site", "site web", "contenu du site", "http")),
        ("rsmangler", ("mangle", "transformer la liste", "permutation", "variantes")),
        ("crunch", ("generer une liste", "genere une liste", "liste de mots", "generateur", "generer des mots", "combinaison")),
        (
            "hash-identifier",
            ("identifie le hash", "identifier le hash", "type de hash", "quel hash"),
        ),
        ("ophcrack", ("windows", "tables arc-en-ciel", "rainbow", "lm", "ntlm windows")),
        ("samdump2", ("ruche sam", "hive sam", "extraire les hashes", "sam")),
        ("chntpw", ("reinitialiser", "reset", "modifier le mot de passe", "compte windows")),
        ("hashcat", ("hashcat", "gpu", "cracker un hash", "craque le fichier", "mask", "masque")),
        ("john", ("john", "john the ripper", "shadow", "fichier de hashes")),
        ("patator", ("patator", "module", "multi-protocole")),
        ("ncrack", ("ncrack", "rdp", "reseau")),
        ("medusa", ("medusa",)),
        ("hydra", ("hydra",)),
        (
            "hydra",
            (
                "bruteforce",
                "brute force",
                "dictionnaire",
                "force brute",
                "attaque en ligne",
                "ssh",
                "ftp",
                "smb",
                "formulaire",
                "login",
            ),
        ),
    ),
    keywords=(
        "mot de passe",
        "mots de passe",
        "password",
        "hash",
        "hashes",
        "craque",
        "crack",
        "bruteforce",
        "brute force",
        "force brute",
        "dictionnaire",
        "wordlist",
        "hydra",
        "medusa",
        "ncrack",
        "patator",
        "hashcat",
        "john",
        "ophcrack",
        "samdump2",
        "chntpw",
        "crunch",
        "cewl",
        "rsmangler",
        "identifiants",
        "credentials",
    ),
)
