"""Classe 09 - Sniffing & Spoofing : sniffers dedies et spoofing/MITM.

Sous-categories couvertes:
  - 09-sniffing-spoofing (direct): etherape, etherwake, ettercap-graphical,
    ettercap-text-only, ferret-sidejack, hamster-sidejack, macchanger,
    mitmproxy, python3-impacket, python3-scapy, responder
  - 09-01-network-sniffers: chaosreader, darkstat, driftnet, hexinject,
    netsniff-ng, sslsniff, tcpflow
  - 09-02-network-spoofing: dnschef, dsniff, evil-ssdp, fiked,
    isr-evilgrade, rebind, sniffjoke, sslsplit, tcpreplay

L'ecoute passive reste en `medium`; l'usurpation active (ARP/DNS/SSL) et le
detournement de session sont en `high` et exigent une confirmation.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class EtherapeTool(SpecTool):
    name = "etherape"
    binary = "etherape"
    risk = "medium"
    description = "Affiche graphiquement le trafic reseau (interfaces et protocoles)."
    examples = ("affiche le trafic de eth0 avec etherape",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("filter", "Filtre pcap (-f)", "string"),
    )
    options = (Option("interface", "-i"), Option("filter", "-f"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Flux: {0}", "info"),)


class EtherwakeTool(SpecTool):
    name = "etherwake"
    binary = "etherwake"
    risk = "low"
    description = "Envoie un paquet magique Wake-on-LAN a une adresse MAC."
    examples = ("reveille la machine AA:BB:CC:DD:EE:FF avec etherwake",)
    parameters = (
        ParameterSpec("mac", "Adresse MAC", "string", required=True),
        ParameterSpec("interface", "Interface (-i)", "string"),
    )
    options = (Option("interface", "-i"),)
    positionals = (Positional("mac"),)
    order = ("options", "positionals")

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        mac = re.search(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", text)
        if mac:
            params["mac"] = mac.group(1)
        return params


class EttercapTextTool(SpecTool):
    name = "ettercap-text-only"
    aliases = ("ettercap",)
    binary = "ettercap"
    risk = "high"
    description = "MITM en mode texte (ARP poisoning, filtres, sniffing)."
    examples = ("lance un arp poisoning de 10.0.0.5 avec ettercap-text-only",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("target", "Cible (-T)", "string"),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )
    options = (Option("interface", "-i"), Option("target", "-T"))
    flags = (Flag("quiet", "-q"),)
    patterns = (
        Pattern(r"ARP poisoning", "Empoisonnement ARP actif", "high", "Interception du trafic en cours."),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Hote observe: {0}", "info"),
    )


class EttercapGraphicalTool(SpecTool):
    name = "ettercap-graphical"
    binary = "ettercap"
    risk = "high"
    description = "MITM avec interface graphique (ARP poisoning, filtres)."
    examples = ("lance ettercap-graphical sur eth0",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("target", "Cible (-T)", "string"),
    )
    options = (Option("interface", "-i"), Option("target", "-T"))
    patterns = (
        Pattern(r"ARP poisoning", "Empoisonnement ARP actif", "high"),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Hote observe: {0}", "info"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ettercap", "-G"]
        if params.get("interface"):
            argv += ["-i", str(params["interface"])]
        if params.get("target"):
            argv += ["-T", str(params["target"])]
        return argv


class FerretTool(SpecTool):
    name = "ferret-sidejack"
    aliases = ("ferret",)
    binary = "ferret"
    risk = "medium"
    description = "Extrait les cookies et identifiants d'une capture reseau (sidejacking)."
    examples = ("extrait les cookies de capture.pcap avec ferret-sidejack",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("read", "Fichier pcap a lire (-r)", "string"),
    )
    options = (Option("interface", "-i"), Option("read", "-r"))

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pcap(?:ng)?\b", text, re.IGNORECASE)
        if m:
            params["read"] = m.group(0)
        return params

    patterns = (
        Pattern(r"cookie", "Cookie capture: {0}", "high", "Jeton de session expose."),
        Pattern(r"HTTP", "Flux HTTP detecte", "medium"),
    )


class HamsterTool(SpecTool):
    name = "hamster-sidejack"
    aliases = ("hamster",)
    binary = "hamster"
    risk = "high"
    description = "Rejoue les cookies captures pour detourner des sessions (sidejacking)."
    examples = ("rejoue les sessions avec hamster-sidejack",)
    parameters = (
        ParameterSpec("interface", "Interface d'ecoute", "string"),
        ParameterSpec("port", "Port d'ecoute", "string"),
    )
    patterns = (
        Pattern(r"session|hijack", "Session detournee", "high", "Detournement de session."),
    )


class MacchangerTool(SpecTool):
    name = "macchanger"
    binary = "macchanger"
    risk = "medium"
    description = "Change ou randomise l'adresse MAC d'une interface."
    examples = ("change l'adresse mac de eth0 avec macchanger",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("mac", "Nouvelle adresse MAC (-m)", "string"),
        ParameterSpec("random", "Adresse aleatoire (-r)", "bool", default=False),
    )
    options = (Option("interface", "-i"), Option("mac", "-m"))
    flags = (Flag("random", "-r"),)
    rules = (Rule("interface", ("eth0",), "eth0"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        mac = re.search(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", text)
        if mac:
            params["mac"] = mac.group(1)
        return params


class MitmproxyTool(SpecTool):
    name = "mitmproxy"
    binary = "mitmproxy"
    risk = "high"
    description = "Proxy d'interception HTTP/HTTPS interactif (analyse et modification)."
    examples = ("lance mitmproxy sur le port 8080",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (-p)", "string"),
        ParameterSpec("mode", "Mode (-m), ex: transparent", "string"),
    )
    options = (Option("port", "-p"), Option("mode", "-m"))
    numbers = (Number("port", r"port\s+(\d{2,5})", cast="str"),)
    patterns = (
        Pattern(r"GET|POST", "Requete interceptee: {0}", "info"),
        Pattern(r"Authorization|Cookie", "Secret d'authentification: {0}", "high", "Jeton capture."),
    )


class ImpacketTool(SpecTool):
    name = "python3-impacket"
    aliases = ("impacket",)
    binary = "impacket-smbserver"
    risk = "high"
    description = "Suite de protocoles Windows (SMB, MSRPC) pour l'ecoute et le relais."
    examples = ("lance un serveur smb impacket sur le port 445",)
    parameters = (
        ParameterSpec("share", "Nom du partage", "string"),
        ParameterSpec("path", "Repertoire partage", "string"),
        ParameterSpec("port", "Port d'ecoute (-port)", "string"),
    )
    positionals = (Positional("share"), Positional("path"))
    options = (Option("port", "-port"),)
    order = ("options", "positionals")

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"partage\s+(\S+)", text, re.IGNORECASE)
        if m:
            params["share"] = m.group(1)
        m = re.search(r"(/\S+)", text)
        if m:
            params["path"] = m.group(1)
        return params

    patterns = (
        Pattern(r"hash|NTLM", "Secret NTLM capture: {0}", "high", "Empreinte d'authentification."),
        Pattern(r"connect", "Connexion entrante", "info"),
    )


class ScapyTool(SpecTool):
    name = "python3-scapy"
    aliases = ("scapy",)
    binary = "scapy"
    risk = "medium"
    description = "Manipulation de paquets (forge, envoi, capture) en Python."
    examples = ("forge et envoie un paquet arp avec python3-scapy",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("filter", "Filtre de capture", "string"),
    )
    options = (Option("interface", "-i"), Option("filter", "-f"))
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Paquet: {0}", "info"),)


class ResponderTool(SpecTool):
    name = "responder"
    binary = "Responder"
    risk = "high"
    description = "Empoisonne LLMNR/NBT-NS/mDNS pour capturer des empreintes NTLM."
    examples = ("lance responder sur eth0 pour capturer des hashes ntlm",)
    parameters = (
        ParameterSpec("interface", "Interface (-I)", "string"),
        ParameterSpec("analyze", "Mode analyse seul (-A)", "bool", default=False),
    )
    options = (Option("interface", "-I"),)
    flags = (Flag("analyze", "-A"),)
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"NTLMv2-SSP Hash", "Empreinte NTLMv2 capturee", "critical", "Authentification detournee."),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Hote repondant: {0}", "medium"),
    )


class ChaosreaderTool(SpecTool):
    name = "chaosreader"
    binary = "chaosreader"
    risk = "low"
    description = "Reconstruit sessions, flux et fichiers depuis une capture pcap."
    examples = ("reconstruit les sessions de capture.pcap avec chaosreader",)
    parameters = (ParameterSpec("pcap", "Fichier pcap", "string", required=True),)
    positionals = (Positional("pcap"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pcap(?:ng)?\b", text, re.IGNORECASE)
        if m:
            params["pcap"] = m.group(0)
        return params

    patterns = (
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3}:\d+)\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}:\d+)", "Session: {0} -> {1}", "info"),
    )


class DarkstatTool(SpecTool):
    name = "darkstat"
    binary = "darkstat"
    risk = "medium"
    description = "Collecte des statistiques de trafic et les expose en HTTP."
    examples = ("collecte les statistiques de eth0 avec darkstat",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("port", "Port HTTP (-p)", "string"),
    )
    options = (Option("interface", "-i"), Option("port", "-p"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Hote observe: {0}", "info"),)


class DriftnetTool(SpecTool):
    name = "driftnet"
    binary = "driftnet"
    risk = "high"
    description = "Capture les images qui transitent sur le reseau."
    examples = ("capture les images de eth0 avec driftnet",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("directory", "Repertoire de sortie (-d)", "string"),
    )
    options = (Option("interface", "-i"), Option("directory", "-d"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"saved|image", "Image capturee: {0}", "medium"),)


class HexinjectTool(SpecTool):
    name = "hexinject"
    binary = "hexinject"
    risk = "high"
    description = "Injecte des paquets bruts en hexadecimal sur une interface."
    examples = ("injecte des paquets sur eth0 avec hexinject",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("data", "Donnees hexadecimales", "string"),
    )
    options = (Option("interface", "-i"),)
    positionals = (Positional("data"),)
    order = ("options", "positionals")
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"inject|sent", "Paquet injecte", "medium"),)


class NetsniffNgTool(SpecTool):
    name = "netsniff-ng"
    binary = "netsniff-ng"
    risk = "medium"
    description = "Sniffer haute performance (capture, filtres BPF, rejeu)."
    examples = ("capture le trafic de eth0 avec netsniff-ng",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("filter", "Filtre BPF (-f)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("interface", "-i"), Option("filter", "-f"), Option("output", "-o"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Flux capture: {0}", "info"),)


class SslsniffTool(SpecTool):
    name = "sslsniff"
    binary = "sslsniff"
    risk = "high"
    description = "Intercepte et dechiffre le trafic TLS (proxy de MITM)."
    examples = ("intercepte le trafic tls sur eth0 avec sslsniff",)
    parameters = (
        ParameterSpec("interface", "Interface", "string", required=True),
        ParameterSpec("port", "Port d'ecoute (-p)", "string"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("interface"),)
    order = ("options", "positionals")
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"certificate|CA", "Certificat de MITM genere", "high", "Interception TLS."),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Client intercepte: {0}", "medium"),
    )


class TcpflowTool(SpecTool):
    name = "tcpflow"
    binary = "tcpflow"
    risk = "medium"
    description = "Reconstitue les flux TCP d'une capture ou d'une interface."
    examples = ("reconstitue les flux de capture.pcap avec tcpflow",)
    parameters = (
        ParameterSpec("read", "Fichier pcap (-r)", "string"),
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
    )
    options = (Option("read", "-r"), Option("interface", "-i"), Option("output", "-o"))

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pcap(?:ng)?\b", text, re.IGNORECASE)
        if m:
            params["read"] = m.group(0)
        return params

    patterns = (
        Pattern(r"GET|POST", "Requete HTTP reconstituee: {0}", "info"),
        Pattern(r"Authorization|Cookie", "Secret d'authentification: {0}", "high"),
    )


class DnschefTool(SpecTool):
    name = "dnschef"
    binary = "dnschef"
    risk = "high"
    description = "Faux serveur DNS pour rediriger les resolutions (MITM)."
    examples = ("lance un faux serveur dns avec dnschef",)
    parameters = (
        ParameterSpec("interface", "Interface d'ecoute (--interface)", "string"),
        ParameterSpec("fakeip", "IP de reponse (--fakeip)", "string"),
        ParameterSpec("fakedomains", "Domaines a usurper (--fakedomains)", "string"),
    )
    options = (Option("interface", "--interface"), Option("fakeip", "--fakeip"), Option("fakedomains", "--fakedomains"))
    patterns = (
        Pattern(r"spoofing|redirect", "Reponse DNS usurpee", "high", "Redirection DNS."),
        Pattern(r"(\d{1,3}(?:\.\d{1,3}){3})", "Reponse: {0}", "medium"),
    )


class DsniffTool(SpecTool):
    name = "dsniff"
    binary = "dsniff"
    risk = "high"
    description = "Detecte et capture les mots de passe en clair sur le reseau."
    examples = ("capture les mots de passe en clair avec dsniff",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("pcap", "Fichier pcap (-p)", "string"),
    )
    options = (Option("interface", "-i"), Option("pcap", "-p"))
    rules = (Rule("interface", ("eth0",), "eth0"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pcap(?:ng)?\b", text, re.IGNORECASE)
        if m:
            params["pcap"] = m.group(0)
        return params

    patterns = (
        Pattern(r"password|login", "Identifiant en clair: {0}", "critical", "Mot de passe expose."),
    )


class EvilSsdpTool(SpecTool):
    name = "evil-ssdp"
    binary = "evil-ssdp"
    risk = "high"
    description = "Faux serveur SSDP/UPnP pour rediriger les victimes (phishing)."
    examples = ("lance evil-ssdp sur eth0",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("template", "Modele (-t)", "string"),
    )
    options = (Option("interface", "-i"), Option("template", "-t"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"SSDP|UPnP", "Service SSDP usurpe", "high", "Redirection UPnP."),
    )


class FikedTool(SpecTool):
    name = "fiked"
    binary = "fiked"
    risk = "high"
    description = "Faux serveur IKE pour capturer les secrets VPN (PSK/XAuth)."
    examples = ("lance un faux serveur ike avec fiked",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string"),
        ParameterSpec("psk", "Faux PSK (-p)", "string"),
    )
    options = (Option("interface", "-i"), Option("psk", "-p"))
    patterns = (
        Pattern(r"PSK|XAuth", "Secret VPN capture: {0}", "critical", "Cle VPN exposee."),
    )


class IsrEvilgradeTool(SpecTool):
    name = "isr-evilgrade"
    binary = "isr-evilgrade"
    risk = "high"
    description = "Faux serveur de mise a jour pour pousser du code malveillant."
    examples = ("lance isr-evilgrade sur le port 80",)
    parameters = (
        ParameterSpec("module", "Module a charger (-m)", "string"),
        ParameterSpec("port", "Port d'ecoute (-p)", "string"),
    )
    options = (Option("module", "-m"), Option("port", "-p"))
    patterns = (
        Pattern(r"update|module", "Fausse mise a jour servie: {0}", "high", "Code malveillant pousse."),
    )


class RebindTool(SpecTool):
    name = "rebind"
    binary = "rebind"
    risk = "high"
    description = "Attaque par rebinding DNS pour contourner la politique d'origine."
    examples = ("lance rebind sur le port 53",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute", "string"),
        ParameterSpec("target", "Hote a rebinder", "string"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("target"),)
    order = ("options", "positionals")
    patterns = (
        Pattern(r"rebind|(\d{1,3}(?:\.\d{1,3}){3})", "Reponse rebindee: {0}", "high"),
    )


class SniffjokeTool(SpecTool):
    name = "sniffjoke"
    binary = "sniffjoke"
    risk = "high"
    description = "Brouille les sniffers adverses en perturbant les flux TCP."
    examples = ("brouille les sniffers sur eth0 avec sniffjoke",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("debug", "Mode debug (-D)", "bool", default=False),
    )
    options = (Option("interface", "-i"),)
    flags = (Flag("debug", "-D"),)
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (Pattern(r"inject|tamper", "Paquet perturbe", "medium"),)


class SslsplitTool(SpecTool):
    name = "sslsplit"
    binary = "sslsplit"
    risk = "high"
    description = "Proxy transparent TLS: intercepte et journalise les connexions."
    examples = ("intercepte le tls sur eth0 avec sslsplit",)
    parameters = (
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("logdir", "Repertoire de journaux (-l)", "string"),
    )
    options = (Option("interface", "-i"), Option("logdir", "-l"))
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"GET|POST|CONNECT", "Connexion interceptee: {0}", "high", "Trafic TLS dechiffre."),
    )


class TcpreplayTool(SpecTool):
    name = "tcpreplay"
    binary = "tcpreplay"
    risk = "high"
    description = "Rejoue un fichier pcap sur une interface (test, injection)."
    examples = ("rejoue capture.pcap sur eth0 avec tcpreplay",)
    parameters = (
        ParameterSpec("pcap", "Fichier pcap", "string", required=True),
        ParameterSpec("interface", "Interface (-i)", "string", required=True),
        ParameterSpec("loop", "Nombre de repetitions (-l)", "int"),
    )
    options = (Option("interface", "-i"), Option("loop", "-l"))
    positionals = (Positional("pcap"),)
    order = ("options", "positionals")
    rules = (Rule("interface", ("eth0",), "eth0"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        m = re.search(r"\S+\.pcap(?:ng)?\b", text, re.IGNORECASE)
        if m:
            params["pcap"] = m.group(0)
        return params

    patterns = (Pattern(r"Actual:\s*(\d+)", "Paquets rejoues: {0}", "info"),)


for _tool in (
    EtherapeTool(), EtherwakeTool(), EttercapTextTool(), EttercapGraphicalTool(),
    FerretTool(), HamsterTool(), MacchangerTool(), MitmproxyTool(), ImpacketTool(),
    ScapyTool(), ResponderTool(), ChaosreaderTool(), DarkstatTool(), DriftnetTool(),
    HexinjectTool(), NetsniffNgTool(), SslsniffTool(), TcpflowTool(), DnschefTool(),
    DsniffTool(), EvilSsdpTool(), FikedTool(), IsrEvilgradeTool(), RebindTool(),
    SniffjokeTool(), SslsplitTool(), TcpreplayTool(),
):
    register(_tool)
