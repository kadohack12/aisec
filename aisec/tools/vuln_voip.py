"""Outils d'analyse et de test VoIP (classe 02, sous-categorie VoIP Tools).

Couvre: enumiax, iaxflood, inviteflood, ohrwurm, protos-sip, rtpbreak, rtpflood,
rtpinsertsound, rtpmixsound, sctpscan, sipp, sipsak, sipvicious (svmap/svwar/
svcrack/svcrash/svreport), twinkle, twinkle-console, voiphopper.

Les outils de flood/enumeration sont classes a risque eleve: ils exigent une
confirmation par la politique de controle (niveau 2).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class EnumiaxTool(SpecTool):
    name = "enumiax"
    aliases = ()
    binary = "enumiax"
    risk = "medium"
    description = "Enumere les comptes IAX2 d'un service Asterisk (avec dictionnaire)."
    examples = ("enumere les utilisateurs iax2 de 10.0.0.1 avec un dictionnaire",)
    parameters = (
        ParameterSpec("target", "Hote Asterisk", "string", required=True),
        ParameterSpec("dictionary", "Dictionnaire de noms (-d)", "string"),
        ParameterSpec("max", "Nombre maximal de comptes (-m)", "int"),
        ParameterSpec("rate", "Requetes par seconde (-r)", "int"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("dictionary", "-d"), Option("max", "-m"), Option("rate", "-r"))
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)
    patterns = (
        Pattern(r"Found|trouve", "Compte IAX2 valide detecte", "high"),
        Pattern(r"timeout|unreachable", "Service injoignable", "low"),
    )


class IaxfloodTool(SpecTool):
    name = "iaxflood"
    aliases = ()
    binary = "iaxflood"
    risk = "critical"
    description = "Flood IAX2: teste la resistance d'un service Asterisk."
    examples = ("flood iax2 de 10.0.0.1 avec 5000 paquets",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("username", "Nom d'utilisateur IAX2", "string"),
        ParameterSpec("packets", "Nombre de paquets", "int"),
    )
    positionals = (Positional("target"), Positional("username"), Positional("packets"))
    numbers = (Number("packets", r"(\d+)\s*paquets"),)
    patterns = (
        Pattern(r"flood|sent", "Flood IAX2 en cours", "critical"),
        Pattern(r"error", "Echec du flood", "low"),
    )


class InvitefloodTool(SpecTool):
    name = "inviteflood"
    aliases = ()
    binary = "inviteflood"
    risk = "critical"
    description = "Flood d'INVITE SIP: teste la resistance d'un service SIP."
    examples = ("flood invite sip sur 10.0.0.1 vers 1000 comme user 100",)
    parameters = (
        ParameterSpec("interface", "Interface reseau", "string", required=True),
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("user", "Utilisateur SIP", "string"),
        ParameterSpec("domain", "Domaine SIP", "string"),
        ParameterSpec("number", "Numero appele", "string"),
        ParameterSpec("packets", "Nombre de paquets (-n)", "int"),
    )
    options = (Option("packets", "-n"),)
    positionals = (
        Positional("interface"),
        Positional("target"),
        Positional("user"),
        Positional("domain"),
        Positional("number"),
    )
    numbers = (Number("packets", r"(\d+)\s*paquets"),)
    patterns = (
        Pattern(r"INVITE|sent", "INVITE SIP envoyes", "critical"),
        Pattern(r"error|failed", "Echec de l'envoi", "low"),
    )


class OhrwurmTool(SpecTool):
    name = "ohrwurm"
    aliases = ()
    binary = "ohrwurm"
    risk = "high"
    description = "Decode et rejoue des flux RTP captures (ecoute de conversations VoIP)."
    examples = ("decode le flux rtp du fichier capture.pcap",)
    parameters = (
        ParameterSpec("interface", "Interface reseau", "string"),
        ParameterSpec("pcap", "Fichier pcap a analyser", "string"),
        ParameterSpec("output", "Dossier de sortie (-o)", "string"),
    )
    options = (Option("output", "-o"),)
    positionals = (Positional("interface"), Positional("pcap"))
    patterns = (
        Pattern(r"\.wav|\.raw", "Flux audio extrait", "high", "Une conversation VoIP a pu etre reconstituee."),
        Pattern(r"rtp stream|codec", "Flux RTP detecte", "medium"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        pcap = re.search(r"([\w./\-]+\.pcap(?:ng)?|[\w./\-]+\.cap)", text, re.IGNORECASE)
        if pcap:
            params["pcap"] = pcap.group(1)
        return params


class ProtosSipTool(SpecTool):
    name = "protos-sip"
    aliases = ()
    binary = "protos-sip"
    risk = "high"
    description = "Fuzzer de services SIP (protos): teste des messages malformes."
    examples = ("fuzz le service sip de 10.0.0.1",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port SIP", "string", default="5060"),
        ParameterSpec("input", "Dossier de scenarios", "string"),
    )
    positionals = (Positional("target"), Positional("port"))
    patterns = (
        Pattern(r"crash|segfault", "Service SIP plante", "high"),
        Pattern(r"error|refused", "Erreur de connexion", "low"),
    )


class RtpbreakTool(SpecTool):
    name = "rtpbreak"
    aliases = ()
    binary = "rtpbreak"
    risk = "high"
    description = "Detecte et extrait les flux RTP d'un trafic (interface ou pcap)."
    examples = ("extrait les flux rtp de capture.pcap vers le dossier out",)
    parameters = (
        ParameterSpec("interface", "Interface reseau (-i)", "string"),
        ParameterSpec("pcap", "Fichier pcap (-r)", "string"),
        ParameterSpec("output", "Dossier de sortie (-d)", "string"),
    )
    options = (Option("interface", "-i"), Option("pcap", "-r"), Option("output", "-d"))
    patterns = (
        Pattern(r"RTP|stream", "Flux RTP detecte", "medium"),
        Pattern(r"wrote|ecrit", "Flux RTP extrait", "high"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        pcap = re.search(r"([\w./\-]+\.pcap(?:ng)?|[\w./\-]+\.cap)", text, re.IGNORECASE)
        if pcap:
            params["pcap"] = pcap.group(1)
        return params


class RtpfloodTool(SpecTool):
    name = "rtpflood"
    aliases = ()
    binary = "rtpflood"
    risk = "critical"
    description = "Flood RTP: teste la resistance d'un recepteur audio VoIP."
    examples = ("flood rtp vers 10.0.0.1 port 10000",)
    parameters = (
        ParameterSpec("target", "Adresse de destination", "string", required=True),
        ParameterSpec("port", "Port de destination", "string"),
        ParameterSpec("payload", "Fichier de charge utile", "string"),
    )
    positionals = (Positional("target"), Positional("port"), Positional("payload"))
    patterns = (
        Pattern(r"flood|sent", "Flood RTP en cours", "critical"),
        Pattern(r"error", "Echec du flood", "low"),
    )


class RtpinsertsoundTool(SpecTool):
    name = "rtpinsertsound"
    aliases = ()
    binary = "rtpinsertsound"
    risk = "high"
    description = "Insere un son dans un flux RTP existant (test de manipulation audio)."
    examples = ("insere message.wav dans le flux rtp de capture.pcap",)
    parameters = (
        ParameterSpec("sound", "Fichier audio a inserer (-f)", "string", required=True),
        ParameterSpec("pcap", "Fichier pcap du flux (-r)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
        ParameterSpec("delay", "Delai en ms (-d)", "int"),
    )
    options = (Option("sound", "-f"), Option("pcap", "-r"), Option("output", "-o"), Option("delay", "-d"))
    patterns = (
        Pattern(r"inserted|insere", "Son insere dans le flux", "high"),
        Pattern(r"error|failed", "Echec de l'insertion", "low"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        sound = re.search(r"([\w./\-]+\.(?:wav|raw|au))", text, re.IGNORECASE)
        if sound:
            params["sound"] = sound.group(1)
        pcap = re.search(r"([\w./\-]+\.pcap(?:ng)?|[\w./\-]+\.cap)", text, re.IGNORECASE)
        if pcap:
            params["pcap"] = pcap.group(1)
        return params


class RtpmixsoundTool(SpecTool):
    name = "rtpmixsound"
    aliases = ()
    binary = "rtpmixsound"
    risk = "high"
    description = "Mixte un son dans un flux RTP (superposition audio)."
    examples = ("mixte message.wav dans le flux rtp de capture.pcap",)
    parameters = (
        ParameterSpec("sound", "Fichier audio a mixer (-f)", "string", required=True),
        ParameterSpec("pcap", "Fichier pcap du flux (-r)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )
    options = (Option("sound", "-f"), Option("pcap", "-r"), Option("output", "-o"))
    patterns = (
        Pattern(r"mixed|mixte", "Son mixe dans le flux", "high"),
        Pattern(r"error|failed", "Echec du mixage", "low"),
    )

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        sound = re.search(r"([\w./\-]+\.(?:wav|raw|au))", text, re.IGNORECASE)
        if sound:
            params["sound"] = sound.group(1)
        pcap = re.search(r"([\w./\-]+\.pcap(?:ng)?|[\w./\-]+\.cap)", text, re.IGNORECASE)
        if pcap:
            params["pcap"] = pcap.group(1)
        return params


class SctpscanTool(SpecTool):
    name = "sctpscan"
    aliases = ()
    binary = "sctpscan"
    risk = "medium"
    description = "Scanner SCTP: decouverte d'associations et d'endpoints SCTP."
    examples = ("scanne les endpoints sctp sur eth0",)
    parameters = (
        ParameterSpec("interface", "Interface reseau (-i)", "string"),
        ParameterSpec("source", "Adresse source (-s)", "string"),
        ParameterSpec("destination", "Adresse de destination (-d)", "string"),
        ParameterSpec("ports", "Ports a tester (-p)", "string"),
    )
    options = (Option("interface", "-i"), Option("source", "-s"), Option("destination", "-d"), Option("ports", "-p"))
    patterns = (
        Pattern(r"SCTP|endpoint", "Endpoint SCTP detecte", "info"),
        Pattern(r"open", "Port SCTP ouvert", "medium"),
    )


class SippTool(SpecTool):
    name = "sipp"
    aliases = ()
    binary = "sipp"
    risk = "high"
    description = "Generateur de trafic SIP (sipp): tests de charge et scenarios."
    examples = ("lance un scenario de charge sip vers 10.0.0.1 avec 100 appels",)
    parameters = (
        ParameterSpec("target", "Hote cible (host:port)", "string", required=True),
        ParameterSpec("scenario", "Fichier de scenario XML (-sf)", "string"),
        ParameterSpec("calls", "Nombre d'appels (-m)", "int"),
        ParameterSpec("rate", "Appels par seconde (-r)", "int"),
        ParameterSpec("local_port", "Port local (-l)", "int"),
        ParameterSpec("trace", "Tracer les messages (-trace_msg)", "bool", default=False),
    )
    options = (Option("scenario", "-sf"), Option("calls", "-m"), Option("rate", "-r"), Option("local_port", "-l"))
    flags = (Flag("trace", "-trace_msg"),)
    positionals = (Positional("target"),)
    numbers = (
        Number("calls", r"(\d+)\s*(?:appels|calls)"),
        Number("rate", r"(\d+)\s*(?:par seconde|/s)"),
    )
    patterns = (
        Pattern(r"Successful call", "Appel SIP reussi", "info"),
        Pattern(r"Failed call|timeout", "Appel SIP echoue", "low"),
        Pattern(r"Call rate|Throughput", "Debit atteint", "info"),
    )


class SipsakTool(SpecTool):
    name = "sipsak"
    aliases = ()
    binary = "sipsak"
    risk = "medium"
    description = "Testeur de service SIP: options, enregistrement, messages."
    examples = ("teste les options sip de 10.0.0.1",)
    parameters = (
        ParameterSpec("uri", "URI SIP (-s), ex: sip:user@host", "string"),
        ParameterSpec("host", "Hote cible", "string"),
        ParameterSpec("options", "Envoyer une requete OPTIONS (-U)", "bool", default=False),
        ParameterSpec("register", "Tester l'enregistrement (-U -C)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("uri", "-s"),)
    flags = (Flag("options", "-U"), Flag("register", "-C"), Flag("verbose", "-v"))
    positionals = (Positional("host"),)
    rules = (
        Rule("options", ("options", "option"), True),
        Rule("register", ("enregistrement", "register"), True),
    )
    patterns = (
        Pattern(r"SIP/2\.0\s+(\d{3})", "Reponse SIP {0}", "info"),
        Pattern(r"timeout|unreachable", "Service SIP injoignable", "low"),
    )


class _SipviciousBase(SpecTool):
    risk = "high"
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port SIP", "string"),
        ParameterSpec("extension", "Extension ou plage d'extensions (-e)", "string"),
        ParameterSpec("method", "Methode SIP (-m)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("port", "-p"), Option("extension", "-e"), Option("method", "-m"))
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)


class SvmapTool(_SipviciousBase):
    name = "sipvicious"
    aliases = ("svmap",)
    binary = "svmap"
    description = "SIPVicious (svmap): decouverte de services et equipements SIP."
    examples = ("decouvre les services sip sur 10.0.0.0/24",)
    patterns = (
        Pattern(r"SIP\s*\d*\.?\d*|User-Agent", "Service SIP detecte", "info"),
        Pattern(r"no response|timeout", "Aucune reponse SIP", "low"),
    )


class SvwarTool(_SipviciousBase):
    name = "svwar"
    aliases = ()
    binary = "svwar"
    description = "SIPVicious (svwar): enumeration d'extensions SIP valides."
    examples = ("enumere les extensions sip de 10.0.0.1 de 100 a 999",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("extension", "Plage d'extensions (-e)", "string"),
        ParameterSpec("method", "Methode SIP (-m)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("extension", "-e"), Option("method", "-m"))
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)
    rules = (Rule("method", ("options", "invite", "register"), "REGISTER"),)
    patterns = (
        Pattern(r"extension|Authentication", "Extension SIP valide detectee", "high"),
        Pattern(r"no response", "Aucune reponse", "low"),
    )


class SvcrackTool(_SipviciousBase):
    name = "svcrack"
    aliases = ()
    binary = "svcrack"
    description = "SIPVicious (svcrack): cassage de mots de passe SIP par force brute."
    examples = ("casse le mot de passe sip de l'extension 100 sur 10.0.0.1",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("extension", "Extension a casser (-u)", "string"),
        ParameterSpec("dictionary", "Dictionnaire de mots de passe (-d)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("extension", "-u"), Option("dictionary", "-d"))
    flags = (Flag("verbose", "-v"),)
    positionals = (Positional("target"),)
    patterns = (
        Pattern(r"password|mot de passe", "Mot de passe SIP trouve", "critical"),
        Pattern(r"no response|failed", "Echec du cassage", "low"),
    )


class SvcrashTool(_SipviciousBase):
    name = "svcrash"
    aliases = ()
    binary = "svcrash"
    description = "SIPVicious (svcrash): neutralise un outil d'enumeration SIP adverse."
    examples = ("neutralise l'outil d'enumeration sip sur 10.0.0.1",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port SIP", "string"),
    )
    options = (Option("port", "-p"),)
    positionals = (Positional("target"),)
    patterns = (
        Pattern(r"sent|envoye", "Reponses envoyees", "medium"),
        Pattern(r"error", "Echec", "low"),
    )


class SvreportTool(SpecTool):
    name = "svreport"
    aliases = ()
    binary = "svreport"
    risk = "low"
    description = "SIPVicious (svreport): consolide les sessions et genere un rapport."
    examples = ("genere un rapport des sessions sip enregistrees",)
    parameters = (
        ParameterSpec("mode", "Mode: sessions, extensions, passwords", "string", default="sessions"),
        ParameterSpec("format", "Format de sortie (-o)", "string"),
        ParameterSpec("output", "Fichier de sortie (-r)", "string"),
    )
    options = (Option("output", "-r"),)
    positionals = (Positional("mode"),)
    rules = (
        Rule("mode", ("extension",), "extensions"),
        Rule("mode", ("mot de passe", "password"), "passwords"),
    )
    patterns = (
        Pattern(r"extension|session", "Session SIP listee", "info"),
        Pattern(r"password", "Mot de passe repertorie", "high"),
    )


class TwinkleTool(SpecTool):
    name = "twinkle"
    aliases = ()
    binary = "twinkle"
    risk = "low"
    description = "Client SIP graphique (twinkle): passer des appels de test."
    examples = ("lance le client sip twinkle",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("call", "URI a appeler", "string"),
    )
    options = (Option("config", "-c"),)
    positionals = (Positional("call"),)
    patterns = (Pattern(r"error|failed", "Erreur du client SIP", "low"),)


class TwinkleConsoleTool(SpecTool):
    name = "twinkle-console"
    aliases = ()
    binary = "twinkle-console"
    risk = "low"
    description = "Client SIP en console (twinkle-console): appels de test scriptables."
    examples = ("appelle sip:100@10.0.0.1 depuis la console twinkle",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-c)", "string"),
        ParameterSpec("call", "URI a appeler", "string"),
    )
    options = (Option("config", "-c"),)
    positionals = (Positional("call"),)
    patterns = (Pattern(r"error|failed", "Erreur du client SIP", "low"),)


class VoiphopperTool(SpecTool):
    name = "voiphopper"
    aliases = ()
    binary = "voiphopper"
    risk = "high"
    description = "Decouverte de VLAN VoIP et saut de VLAN (CDP, DHCP, LLDP)."
    examples = ("decouvre le vlan voip sur eth0 via cdp",)
    parameters = (
        ParameterSpec("interface", "Interface reseau (-i)", "string"),
        ParameterSpec("mode", "Mode de decouverte (-c): 0=CDP, 1=DHCP, 2=LLDP, 3=802.1Q", "string"),
        ParameterSpec("vlan", "VLAN a tester (-e)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("interface", "-i"), Option("mode", "-c"), Option("vlan", "-e"))
    flags = (Flag("verbose", "-v"),)
    rules = (
        Rule("mode", ("cdp",), "0"),
        Rule("mode", ("dhcp",), "1"),
        Rule("mode", ("lldp",), "2"),
        Rule("mode", ("802.1q", "8021q", "vlan"), "3"),
    )
    patterns = (
        Pattern(r"VLAN\s*(\d+)", "VLAN VoIP decouvert: {0}", "high", "Un VLAN VoIP mal cloisonne permet d'ecouter le trafic voix."),
        Pattern(r"error|no cdp", "Aucun VLAN detecte", "low"),
    )


for _tool in (
    EnumiaxTool(),
    IaxfloodTool(),
    InvitefloodTool(),
    OhrwurmTool(),
    ProtosSipTool(),
    RtpbreakTool(),
    RtpfloodTool(),
    RtpinsertsoundTool(),
    RtpmixsoundTool(),
    SctpscanTool(),
    SippTool(),
    SipsakTool(),
    SvmapTool(),
    SvwarTool(),
    SvcrackTool(),
    SvcrashTool(),
    SvreportTool(),
    TwinkleTool(),
    TwinkleConsoleTool(),
    VoiphopperTool(),
):
    register(_tool)
