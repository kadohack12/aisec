"""Tests des experts ajoutes au jalon 2 (classes 01, 04, 05, 06, 07, 11, 13)."""

from __future__ import annotations

import pytest

from aisec.core import registry
from aisec.core.control import ControlPolicy, Decision, evaluate
from aisec.core.models import CommandPlan
from aisec.experts import get as get_expert, select
from aisec.experts.base import route

PASSWORDS_TOOLS = {
    "brutespray", "changeme", "crowbar", "device-pharmer", "gpp-decrypt",
    "hydra-gtk", "maskprocessor", "statsprocessor", "thc-pptp-bruter",
    "bruteforce-salted-openssl", "crackle", "fcrackzip", "multiforcer",
    "pdfcrack", "rainbowcrack", "rarcrack", "rcracki-mt", "sipcrack",
    "sucrack", "truecrack", "bruteforce-luks", "cmospwd", "creddump7",
    "passing-the-hash", "pipal", "seclists", "twofi", "username-anarchy",
    "wordlists",
}

FORENSICS_TOOLS = {
    "autopsy", "inetsim", "mc", "missidentify", "procdump", "pst-utils",
    "undbx", "unhide", "xplico", "grokevt", "ext3grep", "ext4magic",
    "magicrescue", "myrescue", "pasco", "pev", "recoverdm", "recoverjpeg",
    "rifiuti", "rifiuti2", "safecopy", "scrounge-ntfs", "afflib-tools",
    "dcfldd", "ewf-tools", "guymager",
}

WIRELESS_TOOLS = {
    "fern-wifi-cracker", "kismet-core", "wig-ng", "airgeddon", "eapmd5pass",
    "freeradius", "freeradius-wpe", "sparrow-wifi", "wifi-honey", "bluelog",
    "bluez-hcidump", "btscanner", "redfang", "spooftooph", "gqrx-sdr",
    "gr-air-modes", "inspectrum", "rtlsdr-scanner", "libfreefare-bin",
    "libnfc-bin", "mfterm", "gnuradio", "hackrf", "ubertooth",
}

EXPLOITATION_TOOLS = {
    "hashrat", "armitage", "pompem", "unicorn-magic", "sqldict", "sqlsus",
}

REVERSE_TOOLS = {
    "ghidra", "android-sdk", "rizin-cutter", "edb-debugger", "javasnoop",
    "ollydbg", "bytecode-viewer", "jd-gui", "recstudio",
}

AUTOMOTIVE_TOOLS = {"can-utils"}

INFO_EXTRA_TOOLS = {
    "amap", "autorecon", "clamav", "dmitry", "geoip-bin", "ike-scan",
    "kerberoast", "legion", "mac-robber", "maltego", "naabu", "ndiff",
    "netdiscover", "nmapsi4", "p0f", "patchleaks", "recon-ng", "savi",
    "syft", "trufflehog", "witnessme", "arping", "fping", "hping3",
    "iputils-arping", "maryam", "ncat", "firewalk", "fragrouter", "ftester",
    "lbd", "2ping", "dbd", "netcat-openbsd", "unicornscan", "0trace",
    "intrace", "irpas", "netmask", "ssldump", "sslh", "sslyze", "tlssled",
}

ALL_NEW = (
    PASSWORDS_TOOLS | FORENSICS_TOOLS | WIRELESS_TOOLS | EXPLOITATION_TOOLS
    | REVERSE_TOOLS | AUTOMOTIVE_TOOLS | INFO_EXTRA_TOOLS
)


def _plan(argv: list[str]) -> CommandPlan:
    return CommandPlan(tool=argv[0], params={}, argv=argv)


@pytest.mark.parametrize("name", sorted(ALL_NEW))
def test_tool_registered(name):
    assert registry.get(name).name == name


@pytest.mark.parametrize(
    "text, tool, expected",
    [
        # Classe 05 - mots de passe
        ("brute force les services du scan.gnmap avec brutespray", "brutespray", ["brutespray", "-f", "scan.gnmap"]),
        ("brute force le ssh de 10.0.0.5 avec crowbar", "crowbar", ["crowbar", "-s", "10.0.0.5"]),
        ("casse l'archive archive.zip avec fcrackzip", "fcrackzip", ["fcrackzip", "archive.zip"]),
        ("casse le pdf rapport.pdf avec pdfcrack", "pdfcrack", ["pdfcrack", "rapport.pdf"]),
        ("brute force le volume volume.tc avec truecrack", "truecrack", ["truecrack", "volume.tc"]),
        ("analyse la liste passwords.txt avec pipal", "pipal", ["pipal", "passwords.txt"]),
        # Classe 11 - forensique
        ("image le disque /dev/sdb vers disk.img avec dcfldd", "dcfldd", ["dcfldd", "if=/dev/sdb", "of=disk.img"]),
        ("copie /dev/sdb vers rescue.img avec safecopy", "safecopy", ["safecopy", "-o", "rescue.img", "/dev/sdb"]),
        ("recupere les images de image.dd avec recoverjpeg", "recoverjpeg", ["recoverjpeg", "image.dd"]),
        # Classe 06 - sans fil
        ("detecte les reseaux sans fil de wlan0 avec kismet-core", "kismet-core", ["kismet", "-c", "wlan0"]),
        ("usurpe l'adresse bluetooth AA:BB:CC:DD:EE:FF avec spooftooph", "spooftooph", ["spooftooph", "-a", "AA:BB:CC:DD:EE:FF"]),
        # Classe 04 - exploitation
        ("lance sqlsus sur http://target/page.php?id=1", "sqlsus", ["sqlsus", "http://target/page.php?id=1"]),
        ("genere une charge pour 10.0.0.5 avec unicorn-magic", "unicorn-magic", ["unicorn-magic", "10.0.0.5"]),
        # Classe 07 - reverse
        ("analyse le binaire sample.exe avec ghidra", "ghidra", ["analyzeHeadless", "-import", "sample.exe"]),
        # Classe 01 - reconnaissance
        ("scanne les ports de 10.0.0.5 avec naabu", "naabu", ["naabu", "-host", "10.0.0.5"]),
        ("scan les ports de 10.0.0.5 avec hping3", "hping3", ["hping3", "10.0.0.5"]),
        ("audite la configuration tls de example.com:443 avec sslyze", "sslyze", ["sslyze", "example.com:443"]),
        ("extrait les tickets kerberos du domaine corp.local avec kerberoast", "kerberoast", ["kerberoast", "corp.local"]),
        ("empreinte le serveur ipsec de 10.0.0.5 avec ike-scan", "ike-scan", ["ike-scan", "10.0.0.5"]),
        ("decouvre les hotes sur 192.168.1.0/24", "arp-scan", ["arp-scan", "192.168.1.0/24"]),
    ],
)
def test_routing_and_argv(text, tool, expected):
    expert = get_expert(tool in PASSWORDS_TOOLS and "passwords"
                        or tool in FORENSICS_TOOLS and "forensics"
                        or tool in WIRELESS_TOOLS and "wireless"
                        or tool in EXPLOITATION_TOOLS and "exploitation"
                        or tool in REVERSE_TOOLS and "reverse"
                        or tool in AUTOMOTIVE_TOOLS and "automotive"
                        or "info")
    routed, params, _ = route(expert, text, None)
    assert routed == tool
    assert registry.get(routed).build_argv(params) == expected


def test_expert_tool_counts():
    assert len(get_expert("info").tool_names) >= 70
    assert len(get_expert("forensics").tool_names) >= 48
    assert len(get_expert("wireless").tool_names) >= 44
    assert len(get_expert("passwords").tool_names) >= 42
    assert len(get_expert("exploitation").tool_names) >= 24
    assert len(get_expert("reverse").tool_names) >= 26


def test_router_selects_wireless_for_bluetooth():
    assert select("scanne les appareils bluetooth a portee").name == "wireless"


def test_router_selects_forensics_for_carving():
    assert select("recupere les fichiers supprimes d'une image disque").name == "forensics"


def test_router_selects_passwords_for_hashcat():
    assert select("craque le fichier de hashes avec un dictionnaire").name == "passwords"


@pytest.mark.parametrize("name", ["sucrack", "passing-the-hash", "creddump7", "kerberoast"])
def test_high_risk_tools(name):
    assert registry.get(name).risk in {"high", "critical"}


def test_passing_the_hash_requires_confirmation():
    tool = registry.get("passing-the-hash")
    verdict = evaluate(_plan(["pth-winexe", "10.0.0.5"]), tool, ControlPolicy())
    assert verdict.decision is Decision.CONFIRM


def test_dcfldd_is_medium_risk():
    assert registry.get("dcfldd").risk == "medium"


def test_can_utils_registered():
    assert registry.get("can-utils").binary == "can-utils"
