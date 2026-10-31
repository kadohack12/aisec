"""Expert Autres (classe `misc`).

Couvre les services systeme (HTTP, base de donnees, SSH, Metasploit, OpenVAS),
l'outillage de developpement (arduino, powershell), la radio amateur (chirp),
la navigation (firefox, nyx) et l'utilitaire (coreutils, gpa, keepassxc, mat2,
sirikali, woeusb-ng, zulucrypt-gui, zulumount-gui).

Les commandes de service (start/stop/restart) et l'effacement/ecriture disque
sont en `critical`: la politique de controle de niveau 2 impose une
confirmation avant toute execution.
"""

from __future__ import annotations

from .base import Expert

MISC_EXPERT = Expert(
    name="misc",
    description="Autres: services systeme, developpement, radio, navigation et utilitaires.",
    system_prompt=(
        "Tu es un expert systeme et utilitaire, dans un cadre de test "
        "d'intrusion autorise. Tu choisis l'outil le plus adapte parmi ceux de "
        "ton domaine et tu extrais les parametres exacts. Pour piloter un "
        "service (demarrer, arreter, redemarrer, etat), utilise le service "
        "concerne: apache2, nginx, mariadb-server, postgresql, openssh-server, "
        "metasploit-framework ou gvm (OpenVAS). Pour compiler ou televerser un "
        "croquis Arduino, utilise arduino. Pour executer une commande "
        "PowerShell, utilise powershell. Pour configurer une radio amateur, "
        "utilise chirp. Pour surveiller Tor, utilise nyx. Pour naviguer ou "
        "automatiser un navigateur, utilise firefox. Pour effacer un fichier de "
        "facon irreversible, utilise coreutils (shred). Pour gerer des cles "
        "GnuPG, utilise gpa. Pour un coffre de mots de passe KeePass, utilise "
        "keepassxc. Pour nettoyer les metadonnees d'un fichier, utilise mat2. "
        "Pour monter un volume chiffre, utilise sirikali, zulucrypt-gui ou "
        "zulumount-gui. Pour creer une cle USB d'installation Windows, utilise "
        "woeusb-ng."
    ),
    tool_names=[
        "apache2",
        "nginx",
        "mariadb-server",
        "postgresql",
        "openssh-server",
        "metasploit-framework",
        "gvm",
        "arduino",
        "powershell",
        "chirp",
        "nyx",
        "firefox",
        "firefox-esr",
        "coreutils",
        "gpa",
        "keepassxc",
        "mat2",
        "sirikali",
        "zulucrypt-gui",
        "zulumount-gui",
        "woeusb-ng",
    ],
    routing_rules=(
        ("coreutils", ("shred", "efface", "effacer", "detruit", "detruire", "destruction", "irreversible", "cle usb securisee")),
        ("woeusb-ng", ("woeusb", "cle usb", "clef usb", "usb windows", "installateur windows")),
        ("keepassxc", ("keepass", "keepassxc", "coffre", "kdbx")),
        ("mat2", ("mat2", "metadonnee", "metadonnees", "anonymise", "anonymisation")),
        ("sirikali", ("sirikali", "veracrypt", "monte le volume", "monter le volume", "volume chiffre")),
        ("zulucrypt-gui", ("zulucrypt",)),
        ("zulumount-gui", ("zulumount",)),
        ("gpa", ("gpa", "gnupg", "gpg", "cle pgp", "signe une cle")),
        ("nyx", ("nyx", "moniteur tor", "surveille tor", "etat de tor")),
        ("chirp", ("chirp", "radio amateur", "canaux radio", "frequence radio")),
        ("arduino", ("arduino", "croquis", "sketch", "televerse le croquis", "carte arduino")),
        ("powershell", ("powershell", "pwsh", "commande powershell", "script ps1")),
        ("firefox-esr", ("firefox esr", "firefox-esr")),
        ("firefox", ("firefox", "navigateur web", "ouvre l'url", "navigateur")),
        ("gvm", ("gvm", "openvas", "greenbone")),
        ("metasploit-framework", ("metasploit", "msfrpcd", "service metasploit")),
        ("openssh-server", ("openssh", "sshd", "service ssh", "serveur ssh")),
        ("mariadb-server", ("mariadb", "mysql", "service mysql")),
        ("postgresql", ("postgresql", "postgres", "service postgres")),
        ("apache2", ("apache", "httpd", "service apache")),
        ("nginx", ("nginx", "service nginx")),
    ),
    keywords=(
        "service",
        "systemctl",
        "daemon",
        "apache",
        "nginx",
        "httpd",
        "mariadb",
        "mysql",
        "postgresql",
        "postgres",
        "sshd",
        "openssh",
        "metasploit",
        "gvm",
        "openvas",
        "greenbone",
        "arduino",
        "croquis",
        "sketch",
        "powershell",
        "pwsh",
        "chirp",
        "radio amateur",
        "firefox",
        "navigateur",
        "nyx",
        "moniteur tor",
        "shred",
        "efface",
        "effacer",
        "effacement",
        "effacement securise",
        "irreversible",
        "detruit",
        "destruction securisee",
        "gnupg",
        "keepass",
        "keepassxc",
        "coffre",
        "mat2",
        "metadonnees",
        "sirikali",
        "veracrypt",
        "volume chiffre",
        "zulucrypt",
        "zulumount",
        "cle usb",
        "woeusb",
    ),
)
