"""Expert Digital Forensics (classe 11-forensics).

Premier jalon: analyse d'images disque (Sleuth Kit), carving (foremost,
scalpel, binwalk, bulk_extractor), forensique PDF (pdfid, pdf-parser),
detection par regles (yara), memoire vive (volatility3), artefacts Windows
(registre, navigateurs, vignettes), integrite/rootkits (hashdeep, ssdeep,
rkhunter, chkrootkit), recuperation (extundelete) et acquisition (dc3dd,
ddrescue).
"""

from __future__ import annotations

from .base import Expert

FORENSICS_EXPERT = Expert(
    name="forensics",
    description="Investigation numerique: images disque, carving, PDF, memoire, artefacts.",
    system_prompt=(
        "Tu es un expert en investigation numerique (digital forensics). Tu choisis "
        "l'outil le plus adapte parmi fls, mmls, icat, foremost, scalpel, binwalk, "
        "bulk_extractor, pdfid, pdf-parser, yara, volatility3, regripper, reglookup, "
        "galleta, vinetto, hashdeep, ssdeep, rkhunter, chkrootkit, extundelete, dc3dd "
        "et ddrescue, puis tu extrais les parametres exacts. Privilegie l'analyse en "
        "lecture seule: pour une acquisition, il faut une confirmation explicite. "
        "Utilise les outils d'imagerie (dc3dd, ddrescue) uniquement sur un support "
        "autorise, et jamais sur un disque monte en ecriture."
    ),
    tool_names=[
        "fls",
        "mmls",
        "icat",
        "foremost",
        "scalpel",
        "binwalk",
        "bulk_extractor",
        "pdfid",
        "pdf-parser",
        "yara",
        "volatility3",
        "regripper",
        "reglookup",
        "galleta",
        "vinetto",
        "hashdeep",
        "ssdeep",
        "rkhunter",
        "chkrootkit",
        "extundelete",
        "dc3dd",
        "ddrescue",
    ],
    routing_rules=(
        ("pdfid", ("pdfid", "javascript", "mots-cles du pdf", "pdf suspect")),
        ("pdf-parser", ("pdf-parser", "objet du pdf", "structure du pdf", "stream du pdf")),
        ("volatility3", ("volatility", "memoire vive", "memory dump", "dump memoire", "memoire", "injection", "injections", "malfind", "pslist", "processus")),
        ("yara", ("yara", "regle yara", "signature malware", "detection de motif")),
        ("bulk_extractor", ("bulk_extractor", "bulk-extractor", "extraction en masse", "numeros de carte", "ccn")),
        ("binwalk", ("binwalk", "firmware", "donnees embarquees", "systeme de fichiers embarque", "rootfs")),
        ("foremost", ("foremost", "recupere les fichiers", "carving", "signature de fichier")),
        ("scalpel", ("scalpel", "carving avec configuration", "scalpel.conf")),
        ("galleta", ("galleta", "cookies", "historique internet explorer", "index.dat")),
        ("vinetto", ("vinetto", "thumbs.db", "vignettes")),
        ("regripper", ("regripper", "ruche de registre", "ntuser.dat", "cles de demarrage")),
        ("reglookup", ("reglookup", "parcourir le registre", "cle usb dans le registre")),
        ("icat", ("icat", "extraire l'inode", "contenu de l'inode")),
        ("mmls", ("mmls", "table de partitions", "partitions de l'image", "offsets de secteurs")),
        ("fls", ("fls", "liste les fichiers", "inodes", "sleuth kit", "sleuthkit")),
        ("rkhunter", ("rkhunter", "porte derobee")),
        ("chkrootkit", ("chkrootkit", "detecter un rootkit")),
        ("ssdeep", ("ssdeep", "empreinte floue", "fuzzy", "fichiers similaires", "similarite")),
        ("hashdeep", ("hashdeep", "integrite", "hachage recursif", "empreintes de fichiers")),
        ("extundelete", ("extundelete", "fichiers supprimes", "recuperer un fichier", "ext4", "ext3")),
        ("dc3dd", ("dc3dd", "image forensique", "acquisition forensique", "copie forensique")),
        ("ddrescue", ("ddrescue", "disque defectueux", "disque abime", "recuperation de donnees")),
    ),
    keywords=(
        "forensique",
        "forensics",
        "investigation",
        "investigation numerique",
        "image disque",
        "image forensique",
        "carving",
        "artefact",
        "artefacts",
        "memoire vive",
        "dump memoire",
        "volatility",
        "binwalk",
        "foremost",
        "scalpel",
        "bulk_extractor",
        "pdfid",
        "pdf-parser",
        "yara",
        "rootkit",
        "rkhunter",
        "chkrootkit",
        "thumbs.db",
        "registre",
        "ruche",
        "cookie",
        "vignette",
        "supprime",
        "recuperation",
        "recuperer",
        "integrite",
        "empreinte",
        "hash",
        "sleuthkit",
        "fls",
        "mmls",
        "icat",
        "ddrescue",
        "dc3dd",
    ),
)
