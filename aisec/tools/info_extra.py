"""Classe 01 - Information Gathering : scanners, hotes vivants, IDS/IPS, TLS.

Sous-categories couvertes:
  - 01-info-gathering           : amap, autorecon, clamav, dmitry, geoip-bin,
                                  ike-scan, kerberoast, legion, mac-robber,
                                  maltego, naabu, ndiff, netdiscover, nmapsi4,
                                  p0f, patchleaks, recon-ng, savi, syft,
                                  trufflehog, witnessme
  - 01-02-identify-live-hosts   : arping, fping, hping3, iputils-arping,
                                  maryam, ncat
  - 01-03-ids-ips-identification: firewalk, fragrouter, ftester, lbd
  - 01-04-network-scanners      : 2ping, dbd, netcat-openbsd, unicornscan
  - 01-08-route-analysis        : 0trace, intrace, irpas, netmask
  - 01-13-ssl-analysis          : ssldump, sslh, sslyze, tlssled

Reconnaissance et cartographie: la plupart des outils sont en `medium`; les
outils qui fragmentent ou modifient le trafic (fragrouter, irpas) sont en
`high`.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class AmapTool(SpecTool):
    name = "amap"
    binary = "amap"
    risk = "medium"
    description = "Identifie les services par empreinte applicative (bannieres)."
    examples = ("identifie les services de 10.0.0.5 sur le port 8080 avec amap",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("banner", "Detection par banniere (-b)", "bool", default=False),
    )
    flags = (Flag("banner", "-b"),)
    options = (Option("port", "-p"),)
    positionals = (Positional("host"),)
    order = ("options", "flags", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"(\d+/\w+)\s+(\S+)", "Service identifie: {0} -> {1}", "info"),)


class AutoreconTool(SpecTool):
    name = "autorecon"
    binary = "autorecon"
    risk = "medium"
    description = "Reconnaissance automatisee multi-outils sur une cible."
    examples = ("lance une reconnaissance automatisee de 10.0.0.5 avec autorecon",)
    parameters = (
        ParameterSpec("target", "Cible", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"open\s+tcp\s+(\d+)", "Port ouvert: {0}", "info"),
        Pattern(r"Found|Discovered", "Decouverte: {0}", "info"),
    )


class ClamavTool(SpecTool):
    name = "clamav"
    aliases = ("clamscan",)
    binary = "clamscan"
    risk = "medium"
    description = "Antivirus: detecte les malwares dans des fichiers ou repertoires."
    examples = ("analyse le repertoire /data avec clamav",)
    parameters = (
        ParameterSpec("path", "Fichier ou repertoire", "string", required=True),
        ParameterSpec("recursive", "Recursif (-r)", "bool", default=False),
    )
    flags = (Flag("recursive", "-r"),)
    positionals = (Positional("path"),)
    order = ("flags", "positionals")
    patterns = (
        Pattern(r"FOUND", "Malware detecte: {0}", "critical", "Fichier infecte."),
        Pattern(r"Infected files:\s*(\d+)", "Fichiers infectes: {0}", "high"),
    )


class DmitryTool(SpecTool):
    name = "dmitry"
    binary = "dmitry"
    risk = "medium"
    description = "Collecte d'informations sur un hote (whois, ports, sous-domaines)."
    examples = ("collecte des informations sur example.com avec dmitry",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("whois", "Requete whois (-w)", "bool", default=False),
        ParameterSpec("ports", "Scan de ports (-p)", "bool", default=False),
        ParameterSpec("subdomains", "Sous-domaines (-s)", "bool", default=False),
    )
    flags = (Flag("whois", "-w"), Flag("ports", "-p"), Flag("subdomains", "-s"))
    positionals = (Positional("target"),)
    order = ("flags", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"(\d+)\s+open", "Port ouvert: {0}", "info"),
        Pattern(r"HostIP|NetName", "Information whois: {0}", "info"),
    )


class GeoipBinTool(SpecTool):
    name = "geoip-bin"
    aliases = ("geoiplookup",)
    binary = "geoiplookup"
    risk = "low"
    description = "Localise une adresse IP (pays, ville) via GeoIP."
    examples = ("localise l'adresse 8.8.8.8 avec geoip-bin",)
    parameters = (ParameterSpec("ip", "Adresse IP", "string", required=True),)
    positionals = (Positional("ip"),)
    target_params = ("ip",)
    patterns = (Pattern(r"GeoIP\s+\w+,\s*(.+)", "Localisation: {0}", "info"),)


class IkeScanTool(SpecTool):
    name = "ike-scan"
    binary = "ike-scan"
    risk = "medium"
    description = "Decouvre et empreinte les serveurs VPN IPSec (IKE)."
    examples = ("empreinte le serveur ipsec de 10.0.0.5 avec ike-scan",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("aggressive", "Mode agressif (-A)", "bool", default=False),
    )
    flags = (Flag("aggressive", "-A"),)
    positionals = (Positional("host"),)
    order = ("flags", "positionals")
    target_params = ("host",)
    patterns = (
        Pattern(r"SA=.*?\((.+?)\)", "Empreinte IKE: {0}", "info"),
        Pattern(r"Handshake returned", "Serveur IPSec detecte", "medium"),
    )


class KerberoastTool(SpecTool):
    name = "kerberoast"
    binary = "kerberoast"
    risk = "high"
    description = "Extrait les tickets Kerberos de comptes de service (Kerberoasting)."
    examples = ("extrait les tickets kerberos du domaine corp.local avec kerberoast",)
    parameters = (
        ParameterSpec("domain", "Domaine AD", "string", required=True),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("domain"),)
    order = ("options", "positionals")
    target_params = ("domain",)
    patterns = (
        Pattern(r"\$krb5tgs\$", "Ticket Kerberos extrait", "high", "Ticket de service revele."),
    )


class LegionTool(SpecTool):
    name = "legion"
    binary = "legion"
    risk = "medium"
    description = "Plateforme de reconnaissance et de cartographie (GUI)."
    examples = ("lance legion pour cartographier 10.0.0.0/24",)
    parameters = (ParameterSpec("target", "Cible", "string"),)
    positionals = (Positional("target"),)
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Hote decouvert: {0}", "info"),)


class MacroBberTool(SpecTool):
    name = "mac-robber"
    binary = "mac-robber"
    risk = "low"
    description = "Collecte les metadonnees (MAC times) d'un systeme de fichiers."
    examples = ("collecte les metadonnees de /mnt/image avec mac-robber",)
    parameters = (ParameterSpec("path", "Repertoire a analyser", "string", required=True),)
    positionals = (Positional("path"),)
    patterns = (Pattern(r"\|(\S+)\|", "Fichier avec metadonnees: {0}", "info"),)


class MaltegoTool(SpecTool):
    name = "maltego"
    binary = "maltego"
    risk = "medium"
    description = "Cartographie graphique de relations OSINT."
    examples = ("lance maltego pour cartographier example.com",)
    parameters = (ParameterSpec("target", "Cible initiale", "string"),)
    positionals = (Positional("target"),)
    patterns = (Pattern(r"(\S+\.\w{2,})", "Entite liee: {0}", "info"),)


class NaabuTool(SpecTool):
    name = "naabu"
    binary = "naabu"
    risk = "medium"
    description = "Scanner de ports rapide (ecrit en Go)."
    examples = ("scanne les ports de 10.0.0.5 avec naabu",)
    parameters = (
        ParameterSpec("host", "Hote cible (-host)", "string", required=True),
        ParameterSpec("top_ports", "Top ports (-top-ports)", "string"),
        ParameterSpec("rate", "Debit (-rate)", "int"),
    )
    options = (Option("host", "-host"), Option("top_ports", "-top-ports"), Option("rate", "-rate"))
    target_params = ("host",)
    patterns = (Pattern(r":(\d{1,5})", "Port ouvert: {0}", "info"),)


class NdiffTool(SpecTool):
    name = "ndiff"
    binary = "ndiff"
    risk = "low"
    description = "Compare deux sorties nmap pour suivre l'evolution d'un parc."
    examples = ("compare scan1.xml et scan2.xml avec ndiff",)
    parameters = (
        ParameterSpec("before", "Scan de reference", "string", required=True),
        ParameterSpec("after", "Scan a comparer", "string", required=True),
    )
    positionals = (Positional("before"), Positional("after"))
    patterns = (
        Pattern(r"\+.*?(\d+/\w+)", "Nouveau port: {0}", "medium"),
        Pattern(r"-.*?(\d+/\w+)", "Port disparu: {0}", "info"),
    )


class NetdiscoverTool(SpecTool):
    name = "netdiscover"
    binary = "netdiscover"
    risk = "medium"
    description = "Decouvre les hotes d'un reseau par ARP (actif ou passif)."
    examples = ("decouvre les hotes de 10.0.0.0/24 avec netdiscover",)
    parameters = (
        ParameterSpec("range", "Plage a scanner (-r)", "string", required=True),
        ParameterSpec("passive", "Mode passif (-p)", "bool", default=False),
    )
    flags = (Flag("passive", "-p"),)
    options = (Option("range", "-r"),)
    order = ("options", "flags")
    target_params = ("range",)
    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f:]{17})", "Hote: {0} MAC: {1}", "info"),
    )


class Nmapsi4Tool(SpecTool):
    name = "nmapsi4"
    binary = "nmapsi4"
    risk = "medium"
    description = "Interface graphique Qt pour nmap."
    examples = ("lance nmapsi4 pour scanner 10.0.0.5",)
    parameters = (ParameterSpec("target", "Cible", "string"),)
    positionals = (Positional("target"),)
    patterns = (Pattern(r"(\d+)/tcp\s+open", "Port ouvert: {0}", "info"),)


class P0fTool(SpecTool):
    name = "p0f"
    binary = "p0f"
    risk = "medium"
    description = "Empreinte passive du systeme d'exploitation par le trafic reseau."
    examples = ("empreinte passive sur eth0 avec p0f",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("pcap", "Fichier pcap (-r)", "string"),
    )
    options = (Option("interface", "-i"), Option("pcap", "-r"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"os\s*=\s*(\S+)", "Systeme identifie: {0}", "info"),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Client observe: {0}", "info"),
    )


class PatchleaksTool(SpecTool):
    name = "patchleaks"
    binary = "patchleaks"
    risk = "low"
    description = "Detecte des fuites de correctifs Microsoft (patch diffing)."
    examples = ("detecte les correctifs manquants sur 10.0.0.5 avec patchleaks",)
    parameters = (ParameterSpec("target", "Hote cible", "string", required=True),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (Pattern(r"(KB\d+)", "Correctif manquant: {0}", "medium"),)


class ReconNgTool(SpecTool):
    name = "recon-ng"
    binary = "recon-ng"
    risk = "medium"
    description = "Framework de reconnaissance OSINT modulaire."
    examples = ("lance recon-ng pour une reconnaissance osint",)
    parameters = (
        ParameterSpec("workspace", "Espace de travail (-w)", "string"),
        ParameterSpec("module", "Module a charger (-m)", "string"),
    )
    options = (Option("workspace", "-w"), Option("module", "-m"))
    patterns = (
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "E-mail collecte: {0}", "info"),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Adresse collectee: {0}", "info"),
    )


class SaviTool(SpecTool):
    name = "savi"
    binary = "savi"
    risk = "medium"
    description = "Analyse les vulnerabilites des protocoles de signalisation (VoIP)."
    examples = ("analyse la signalisation de 10.0.0.5 avec savi",)
    parameters = (ParameterSpec("target", "Hote cible", "string", required=True),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (Pattern(r"vulnerable|CVE-\d{4}-\d+", "Vulnerabilite: {0}", "high"),)


class SyftTool(SpecTool):
    name = "syft"
    binary = "syft"
    risk = "low"
    description = "Inventorie les composants logiciels (SBOM) d'une image ou d'un disque."
    examples = ("genere un sbom de l'image alpine avec syft",)
    parameters = (
        ParameterSpec("target", "Image ou repertoire", "string", required=True),
        ParameterSpec("output", "Format de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (
        Pattern(r"(\S+)\s+(\d+\.\d+[\w.-]*)", "Composant: {0} {1}", "info"),
        Pattern(r"CVE-\d{4}-\d+", "Vulnerabilite connue: {0}", "high"),
    )


class TrufflehogTool(SpecTool):
    name = "trufflehog"
    binary = "trufflehog"
    risk = "medium"
    description = "Detecte les secrets (cles, jetons) dans des depots et fichiers."
    examples = ("cherche des secrets dans le depot avec trufflehog",)
    parameters = (
        ParameterSpec("target", "Depot ou chemin (filesystem)", "string", required=True),
        ParameterSpec("verified", "Secrets verifies uniquement (--only-verified)", "bool", default=False),
    )
    flags = (Flag("verified", "--only-verified"),)
    positionals = (Positional("target"),)
    order = ("flags", "positionals")
    patterns = (
        Pattern(r"(Found verified result|AWS|Private Key)", "Secret detecte: {0}", "critical", "Secret expose."),
    )


class WitnessmeTool(SpecTool):
    name = "witnessme"
    binary = "witnessme"
    risk = "medium"
    description = "Capture des pages web de toutes les applications d'un parc (preuves)."
    examples = ("capture les applications web de 10.0.0.0/24 avec witnessme",)
    parameters = (
        ParameterSpec("targets", "Cibles ou fichier (-t)", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("targets", "-t"), Option("output", "-o"))
    patterns = (
        Pattern(r"(https?://\S+)", "Application capturee: {0}", "info"),
    )


for _tool in (
    AmapTool(), AutoreconTool(), ClamavTool(), DmitryTool(), GeoipBinTool(),
    IkeScanTool(), KerberoastTool(), LegionTool(), MacroBberTool(), MaltegoTool(),
    NaabuTool(), NdiffTool(), NetdiscoverTool(), Nmapsi4Tool(), P0fTool(),
    PatchleaksTool(), ReconNgTool(), SaviTool(), SyftTool(), TrufflehogTool(),
    WitnessmeTool(),
):
    register(_tool)


# --------------------------------------------------------------------------
# Hotes vivants
# --------------------------------------------------------------------------
class ArpingTool(SpecTool):
    name = "arping"
    binary = "arping"
    risk = "medium"
    description = "Verifie la presence d'un hote par requetes ARP."
    examples = ("verifie la presence de 10.0.0.5 avec arping",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("interface", "Interface (-I)", "string"),
        ParameterSpec("count", "Nombre de requetes (-c)", "int"),
    )
    options = (Option("interface", "-I"), Option("count", "-c"))
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"reply from\s+(\S+)", "Reponse ARP de {0}", "info"),)


class FpingTool(SpecTool):
    name = "fping"
    binary = "fping"
    risk = "medium"
    description = "Ping en parallele d'une liste d'hotes."
    examples = ("ping en parallele 10.0.0.1 10.0.0.2 avec fping",)
    parameters = (
        ParameterSpec("targets", "Hotes cibles", "list", required=True),
        ParameterSpec("alive", "Afficher les vivants (-a)", "bool", default=False),
    )
    flags = (Flag("alive", "-a"),)
    positionals = (Positional("targets"),)
    order = ("flags", "positionals")
    target_params = ("targets",)
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})\s+is alive", "Hote vivant: {0}", "info"),)


class Hping3Tool(SpecTool):
    name = "hping3"
    binary = "hping3"
    risk = "high"
    description = "Forge et envoie des paquets TCP/UDP/ICMP (scan, DoS, spoof)."
    examples = ("scan les ports de 10.0.0.5 avec hping3",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("scan", "Scan de ports (-S)", "bool", default=False),
        ParameterSpec("port", "Port de destination (-p)", "string"),
        ParameterSpec("count", "Nombre de paquets (-c)", "int"),
    )
    flags = (Flag("scan", "-S"),)
    options = (Option("port", "-p"), Option("count", "-c"))
    positionals = (Positional("host"),)
    order = ("options", "flags", "positionals")
    target_params = ("host",)
    patterns = (
        Pattern(r"flags=SA", "Port ouvert (SYN/ACK)", "info"),
        Pattern(r"flags=RA", "Port ferme (RST/ACK)", "info"),
    )


class IputilsArpingTool(SpecTool):
    name = "iputils-arping"
    binary = "arping"
    risk = "medium"
    description = "Arping de la suite iputils (verification ARP)."
    examples = ("verifie la presence de 10.0.0.5 avec iputils-arping",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("count", "Nombre de requetes (-c)", "int"),
    )
    options = (Option("count", "-c"),)
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"reply from\s+(\S+)", "Reponse de {0}", "info"),)


class MaryamTool(SpecTool):
    name = "maryam"
    binary = "maryam"
    risk = "medium"
    description = "Framework OSINT modulaire (OWASP Maryam)."
    examples = ("lance une reconnaissance osint avec maryam",)
    parameters = (ParameterSpec("module", "Module (-m)", "string"),)
    options = (Option("module", "-m"),)
    patterns = (
        Pattern(r"(\S+\.\w{2,})", "Entite trouvee: {0}", "info"),
        Pattern(r"[\w.+-]+@[\w.-]+\.\w{2,}", "E-mail: {0}", "info"),
    )


class NcatTool(SpecTool):
    name = "ncat"
    aliases = ("netcat",)
    binary = "ncat"
    risk = "medium"
    description = "Netcat moderne (Nmap): connexions, transferts, ecoute."
    examples = ("ecoute sur le port 4444 avec ncat",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string"),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("listen", "Mode ecoute (-l)", "bool", default=False),
    )
    flags = (Flag("listen", "-l"),)
    options = (Option("port", "-p"),)
    positionals = (Positional("host"),)
    order = ("options", "flags", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"connect|listening", "Connexion/ecoute: {0}", "info"),)


# --------------------------------------------------------------------------
# IDS/IPS
# --------------------------------------------------------------------------
class FirewalkTool(SpecTool):
    name = "firewalk"
    binary = "firewalk"
    risk = "medium"
    description = "Cartographie les regles d'un pare-feu (TTL/ports)."
    examples = ("cartographie le pare-feu de 10.0.0.1 avec firewalk",)
    parameters = (
        ParameterSpec("gateway", "Passerelle", "string", required=True),
        ParameterSpec("target", "Hote cible", "string", required=True),
    )
    positionals = (Positional("gateway"), Positional("target"))
    target_params = ("target",)
    patterns = (Pattern(r"open|accept", "Regle autorisant: {0}", "info"),)


class FragrouterTool(SpecTool):
    name = "fragrouter"
    binary = "fragrouter"
    risk = "high"
    description = "Fragmente les paquets pour contourner les IDS/IPS."
    examples = ("fragmente le trafic pour contourner les ids avec fragrouter",)
    parameters = (ParameterSpec("mode", "Mode de fragmentation (-F1..)", "string"),)
    positionals = (Positional("mode"),)
    patterns = (Pattern(r"forwarding|frag", "Fragmentation active", "high", "Contournement d'IDS."),)


class FtesterTool(SpecTool):
    name = "ftester"
    binary = "ftester"
    risk = "medium"
    description = "Teste les regles d'un pare-feu (Firewall Tester)."
    examples = ("teste les regles du pare-feu de 10.0.0.5 avec ftester",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port", "string"),
    )
    options = (Option("port", "-d"),)
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (Pattern(r"accepted|filtered", "Resultat: {0}", "info"),)


class LbdTool(SpecTool):
    name = "lbd"
    binary = "lbd"
    risk = "medium"
    description = "Detecte l'equilibrage de charge (load balancing) d'un site."
    examples = ("detecte l'equilibrage de charge de example.com avec lbd",)
    parameters = (ParameterSpec("target", "Hote ou domaine", "string", required=True),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (Pattern(r"load balanc", "Equilibrage de charge detecte", "medium"),)


# --------------------------------------------------------------------------
# Scanners reseau
# --------------------------------------------------------------------------
class TwoPingTool(SpecTool):
    name = "2ping"
    binary = "2ping"
    risk = "medium"
    description = "Ping bidirectionnel fiable (mesure la perte aller-retour)."
    examples = ("ping bidirectionnel vers 10.0.0.5 avec 2ping",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("count", "Nombre de paquets (-c)", "int"),
    )
    options = (Option("count", "-c"),)
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"loss|min/avg", "Statistiques: {0}", "info"),)


class DbdTool(SpecTool):
    name = "dbd"
    binary = "dbd"
    risk = "high"
    description = "Backdoor Netcat chiffree avec shell distant (acces furtif)."
    examples = ("ouvre un acces furtif sur le port 4444 avec dbd",)
    parameters = (
        ParameterSpec("host", "Hote", "string"),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("exec", "Commande a executer (-e)", "string"),
    )
    options = (Option("port", "-p"), Option("exec", "-e"))
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"shell|connect", "Acces distant etabli", "critical", "Backdoor active."),)


class NetcatOpenbsdTool(SpecTool):
    name = "netcat-openbsd"
    binary = "nc"
    risk = "medium"
    description = "Netcat (OpenBSD): connexions, transferts, relais."
    examples = ("ecoute sur le port 4444 avec netcat-openbsd",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string"),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("listen", "Mode ecoute (-l)", "bool", default=False),
    )
    flags = (Flag("listen", "-l"),)
    options = (Option("port", "-p"),)
    positionals = (Positional("host"),)
    order = ("options", "flags", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"connect|listening", "Connexion/ecoute: {0}", "info"),)


class UnicornscanTool(SpecTool):
    name = "unicornscan"
    binary = "unicornscan"
    risk = "medium"
    description = "Scanner de ports asynchrone (tres rapide, modele OS)."
    examples = ("scanne les ports de 10.0.0.5 avec unicornscan",)
    parameters = (
        ParameterSpec("target", "Cible", "string", required=True),
        ParameterSpec("ports", "Ports (-p)", "string"),
        ParameterSpec("rate", "Debit (-r)", "int"),
    )
    options = (Option("ports", "-p"), Option("rate", "-r"))
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    target_params = ("target",)
    patterns = (Pattern(r"open\s+(\d+)", "Port ouvert: {0}", "info"),)


# --------------------------------------------------------------------------
# Analyse de route
# --------------------------------------------------------------------------
class ZeroTraceTool(SpecTool):
    name = "0trace"
    binary = "0trace"
    risk = "medium"
    description = "Trace la route jusqu'a une cible en traversant les pare-feux."
    examples = ("trace la route vers 10.0.0.5 avec 0trace",)
    parameters = (
        ParameterSpec("interface", "Interface", "string"),
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port", "string"),
    )
    positionals = (Positional("interface"), Positional("host"), Positional("port"))
    target_params = ("host",)
    patterns = (Pattern(r"hop\s+\d+\s+(\S+)", "Saut: {0}", "info"),)


class IntraceTool(SpecTool):
    name = "intrace"
    binary = "intrace"
    risk = "medium"
    description = "Trace la route au niveau TCP (traverse les pare-feux)."
    examples = ("trace la route tcp vers 10.0.0.5 avec intrace",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("host"),)
    order = ("options", "positionals")
    target_params = ("host",)
    patterns = (Pattern(r"(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3})", "Saut {0}: {1}", "info"),)


class IrpasTool(SpecTool):
    name = "irpas"
    binary = "irpas"
    risk = "high"
    description = "Suite IRPAS: routage, spoofing et analyse de protocoles (CDP/HSRP)."
    examples = ("analyse le protocole cdp avec irpas",)
    parameters = (
        ParameterSpec("mode", "Outil de la suite (cdp, hsrp, ass, ...)", "string"),
        ParameterSpec("interface", "Interface", "string"),
    )
    positionals = (Positional("mode"),)
    patterns = (Pattern(r"CDP|HSRP", "Protocole detecte: {0}", "high", "Information d'infrastructure revelee."),)


class NetmaskTool(SpecTool):
    name = "netmask"
    binary = "netmask"
    risk = "low"
    description = "Convertit et calcule les masques et plages reseau."
    examples = ("calcule la plage de 10.0.0.0/24 avec netmask",)
    parameters = (ParameterSpec("cidr", "Adresse ou plage CIDR", "string", required=True),)
    positionals = (Positional("cidr"),)
    patterns = (Pattern(r"range\s+([\d.]+ - [\d.]+)", "Plage: {0}", "info"),)


# --------------------------------------------------------------------------
# Analyse TLS
# --------------------------------------------------------------------------
class SsldumpTool(SpecTool):
    name = "ssldump"
    binary = "ssldump"
    risk = "medium"
    description = "Analyse une session SSL/TLS (echange, certificats)."
    examples = ("analyse la session tls de capture.pcap avec ssldump",)
    parameters = (
        ParameterSpec("pcap", "Capture pcap (-r)", "string"),
        ParameterSpec("interface", "Interface (-i)", "string"),
    )
    options = (Option("pcap", "-r"), Option("interface", "-i"))
    patterns = (
        Pattern(r"Subject CN=([^\n,]+)", "Certificat: {0}", "info"),
        Pattern(r"ServerHello", "Negociation TLS detectee", "info"),
    )


class SslhTool(SpecTool):
    name = "sslh"
    binary = "sslh"
    risk = "medium"
    description = "Multiplexe TLS et SSH sur un meme port (contournement)."
    examples = ("multiplexe tls et ssh sur le port 443 avec sslh",)
    parameters = (
        ParameterSpec("listen", "Ecoute (--listen)", "string"),
        ParameterSpec("ssh", "Cible SSH (--ssh)", "string"),
        ParameterSpec("tls", "Cible TLS (--tls)", "string"),
    )
    options = (Option("listen", "--listen"), Option("ssh", "--ssh"), Option("tls", "--tls"))
    patterns = (Pattern(r"listening|forwarding", "Multiplexage actif sur {0}", "medium"),)


class SslyzeTool(SpecTool):
    name = "sslyze"
    binary = "sslyze"
    risk = "medium"
    description = "Audit rapide de la configuration TLS d'un service."
    examples = ("audite la configuration tls de example.com:443 avec sslyze",)
    parameters = (
        ParameterSpec("target", "Cible hote:port", "string", required=True),
        ParameterSpec("json", "Sortie JSON (--json)", "string"),
    )
    options = (Option("json", "--json"),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (
        Pattern(r"VULNERABLE|vulnerable", "Vulnerabilite TLS: {0}", "high"),
        Pattern(r"Certificate Information", "Certificat analyse", "info"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\b([\w.-]+\.[a-z]{2,}:\d{1,5})\b", text, re.IGNORECASE)
        if m:
            params["target"] = m.group(1)
        return params


class TlssledTool(SpecTool):
    name = "tlssled"
    binary = "tlssled"
    risk = "medium"
    description = "Evalue la configuration TLS d'un site (scripts SSL)."
    examples = ("evalue la configuration tls de example.com avec tlssled",)
    parameters = (ParameterSpec("target", "Hote ou domaine", "string", required=True),)
    positionals = (Positional("target"),)
    target_params = ("target",)
    patterns = (
        Pattern(r"SSLv2|SSLv3", "Protocole obsolete: {0}", "high", "Chiffrement obsolete."),
        Pattern(r"weak|RC4|DES", "Suite faible: {0}", "medium"),
    )


for _tool in (
    ArpingTool(), FpingTool(), Hping3Tool(), IputilsArpingTool(), MaryamTool(),
    NcatTool(), FirewalkTool(), FragrouterTool(), FtesterTool(), LbdTool(),
    TwoPingTool(), DbdTool(), NetcatOpenbsdTool(), UnicornscanTool(), ZeroTraceTool(),
    IntraceTool(), IrpasTool(), NetmaskTool(), SsldumpTool(), SslhTool(),
    SslyzeTool(), TlssledTool(),
):
    register(_tool)
