"""Routage libre (`select`) : un enonce par classe et cas limites.

Verrouille les correctifs de relecture :
- match sur mot entier (et non sous-chaine) ;
- defaut = expert de reconnaissance (`info`), pas `dns` ;
- un nom d'outil explicite (ex. "mimikatz") pese plus qu'un terme generique
  (ex. "mots de passe").
"""

from __future__ import annotations

import pytest

from aisec.experts import select


@pytest.mark.parametrize(
    "text, expected",
    [
        # Classe 01 - Information Gathering (dont l'exemple nmapAI du README)
        ("nmap -p 22,80,8080 target", "info"),
        ("analyse les ports 22, 80, 8080 de la cible", "info"),
        ("scan des ports ouverts sur 10.0.0.1", "info"),
        ("enumeration des hotes du reseau", "info"),
        # Classe 01 - expert dns dedie
        ("enumere les sous-domaines de example.com", "dns"),
        # Classe 02 - Vulnerability Analysis
        ("fuzz le binaire ./parser avec afl", "vulnerability"),
        ("audite le routeur cisco 10.0.0.1", "vulnerability"),
        ("audit de vulnerabilite tls", "vulnerability"),
        # Classe 03 - Web Application Analysis
        ("brute force les repertoires de https://example.com", "webapp"),
        ("scanne le wordpress http://cible", "webapp"),
        # Classe 04 - Exploitation Tools
        ("teste une injection sql sur http://example.com", "exploitation"),
        # Classe 06 - Wireless Testing
        ("casse le wpa de capture.cap avec rockyou.txt", "wireless"),
        ("capture le handshake wifi sur wlan0mon", "wireless"),
        ("scanne les peripheriques bluetooth", "wireless"),
        # Classe 05 - Password Attacks
        ("crack le hash 5f4dcc3b5aa765d61d8327deb882cf99", "passwords"),
        ("craque ce hash md5 avec un dictionnaire", "passwords"),
        # Classe 07 - Reverse Engineering
        ("desassemble la fonction main de sample.exe avec radare2", "reverse"),
        ("decompile app.apk avec jadx", "reverse"),
        # Classe 08 - Post Exploitation
        ("extrait les mots de passe windows avec mimikatz", "post-exploit"),
        ("privilege escalation sur cette machine linux", "post-exploit"),
        # Classe 09 - Sniffing & Spoofing
        ("capture le trafic http sur eth0", "sniffing"),
        # Classe 11 - Digital Forensics
        ("analyse le firmware firmware.bin avec binwalk", "forensics"),
        ("recupere les fichiers de disk.img avec foremost", "forensics"),
        # Classe 12 - Reporting
        ("redige le rapport de l'audit", "reporting"),
        ("capture d'ecran des services web", "reporting"),
        # Classe 13 - Automotive
        ("capture les trames can sur can0", "automotive"),
        # Classe 14 - AI Tools
        ("lance hexstrike-ai sur la cible", "ai"),
        ("utilise unsloth pour entrainer un modele", "ai"),
    ],
)
def test_select_routes_to_expected_expert(text, expected):
    assert select(text).name == expected


def test_select_falls_back_to_info_not_dns():
    # Aucun mot-cle connu: le defaut est l'expert de reconnaissance.
    assert select("fais un truc sur la machine").name == "info"


def test_select_matches_whole_word_not_substring():
    # "port" ne doit pas matcher dans "important" (pas de faux positif info).
    assert select("c'est important de comprendre").name == "info"


def test_file_extension_is_not_a_dns_keyword():
    # "rockyou.txt" ne doit pas etre pris pour un enregistrement DNS TXT.
    assert select("casse le wpa de capture.cap avec rockyou.txt").name == "wireless"


def test_explicit_tool_name_outweighs_generic_keyword():
    # "mimikatz" (outil) doit primer sur "mots de passe" (terme generique).
    assert select("extrait les mots de passe windows avec mimikatz").name == "post-exploit"
