"""Outils de test de charge / resistance (classe 02, sous-categorie Stress Testing).

Couvre: dhcpig, siege, slowhttptest, t50, thc-ipv6, thc-ssl-dos.

Ces outils generent un trafic agressif: ils sont classes a risque eleve et
exigent donc une confirmation par la politique de controle (niveau 2).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Number, Option, Pattern, Positional, Rule, SpecTool


class DhcpigTool(SpecTool):
    name = "dhcpig"
    aliases = ()
    binary = "dhcpig"
    risk = "high"
    description = "Test de resistance DHCP: epuise le pool d'adresses d'un serveur DHCP."
    examples = ("teste la resistance du dhcp sur eth0",)
    parameters = (
        ParameterSpec("interface", "Interface reseau", "string", required=True),
        ParameterSpec("count", "Nombre de baux a demander (-c)", "int"),
    )
    options = (Option("count", "-c"),)
    positionals = (Positional("interface"),)
    rules = (Rule("interface", ("eth0",), "eth0"),)
    patterns = (
        Pattern(r"lease|bail", "Bail DHCP obtenu", "medium"),
        Pattern(r"exhaust|epuise", "Pool DHCP epuise", "high", "Deni de service DHCP confirme."),
    )


class SiegeTool(SpecTool):
    name = "siege"
    aliases = ()
    binary = "siege"
    risk = "high"
    description = "Test de charge HTTP: mesure la tenue d'un serveur web sous concurrence."
    examples = ("teste la charge de http://target avec 10 utilisateurs pendant 30 secondes",)
    parameters = (
        ParameterSpec("url", "URL cible", "string", required=True),
        ParameterSpec("concurrent", "Utilisateurs concurrents (-c)", "int"),
        ParameterSpec("time", "Duree du test (-t), ex: 30s", "string"),
        ParameterSpec("delay", "Delai entre requetes (-d)", "int"),
        ParameterSpec("benchmark", "Mode benchmark (-b)", "bool", default=False),
        ParameterSpec("internet", "Simuler des utilisateurs internet (-i)", "bool", default=False),
    )
    options = (Option("concurrent", "-c"), Option("time", "-t"), Option("delay", "-d"))
    flags = (Flag("benchmark", "-b"), Flag("internet", "-i"))
    positionals = (Positional("url"),)
    numbers = (Number("concurrent", r"(\d+)\s*(?:utilisateurs|users|concurrent)"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        url = re.search(r"(https?://\S+)", text)
        if url:
            params["url"] = url.group(1)
        return params

    patterns = (
        Pattern(r"Transactions:\s*(\d+)", "Transactions traitees: {0}", "info"),
        Pattern(r"Availability:\s*([\d.]+)", "Disponibilite: {0}%", "info"),
        Pattern(r"Failed transactions:\s*(\d+)", "Transactions echouees: {0}", "medium"),
    )


class SlowhttptestTool(SpecTool):
    name = "slowhttptest"
    aliases = ()
    binary = "slowhttptest"
    risk = "high"
    description = "Teste la resistance HTTP aux attaques lentes (slowloris, slow body)."
    examples = ("teste la resistance slowloris de http://target avec 1000 connexions",)
    parameters = (
        ParameterSpec("url", "URL cible (-u)", "string", required=True),
        ParameterSpec("connections", "Connexions concurrentes (-c)", "int"),
        ParameterSpec("slowloris", "Mode slow headers (-H)", "bool", default=False),
        ParameterSpec("slow_body", "Mode slow body (-B)", "bool", default=False),
        ParameterSpec("range", "Mode range (-R)", "bool", default=False),
        ParameterSpec("timeout", "Timeout de connexion (-t)", "int"),
        ParameterSpec("length", "Taille du contenu (-l)", "int"),
    )
    options = (Option("connections", "-c"), Option("timeout", "-t"), Option("length", "-l"))
    flags = (Flag("slowloris", "-H"), Flag("slow_body", "-B"), Flag("range", "-R"))
    rules = (
        Rule("slowloris", ("slowloris", "en-tete", "header", "lente"), True),
        Rule("slow_body", ("corps", "body"), True),
        Rule("range", ("range",), True),
    )
    numbers = (Number("connections", r"(\d+)\s*(?:connexions|connections)"),)

    def parse_intent(self, text: str) -> dict[str, Any]:
        params = super().parse_intent(text)
        url = re.search(r"(https?://\S+)", text)
        if url:
            params["url"] = url.group(1)
        return params

    patterns = (
        Pattern(r"service available|available", "Service toujours disponible", "info"),
        Pattern(r"not available|unavailable", "Service indisponible sous charge", "high", "Deni de service confirme."),
    )


class T50Tool(SpecTool):
    name = "t50"
    aliases = ()
    binary = "t50"
    risk = "critical"
    description = "Injecteur de paquets reseau: test de resistance multi-protocoles."
    examples = ("teste la resistance de 10.0.0.1 en tcp",)
    parameters = (
        ParameterSpec("target", "Cible", "string", required=True),
        ParameterSpec("protocol", "Protocole: tcp, udp, icmp, mix", "string"),
        ParameterSpec("flood", "Mode flood", "bool", default=False),
    )
    target_params = ("target",)
    flags = (Flag("flood", "--flood"),)
    positionals = (Positional("target"),)
    rules = (
        Rule("protocol", ("tcp",), "tcp"),
        Rule("protocol", ("udp",), "udp"),
        Rule("protocol", ("icmp",), "icmp"),
        Rule("protocol", ("mix", "mixte"), "mix"),
    )
    patterns = (
        Pattern(r"flood|injection", "Injection de paquets en cours", "critical"),
        Pattern(r"error|failed", "Echec de l'injection", "low"),
    )


class ThcIpv6Tool(SpecTool):
    name = "thc-ipv6"
    aliases = ()
    binary = "thcping6"
    risk = "critical"
    description = "Suite d'attaques IPv6 (thc-ipv6): decouverte, spoofing, DoS."
    examples = ("decouvre les hotes ipv6 sur eth0",)
    parameters = (
        ParameterSpec("interface", "Interface reseau", "string", required=True),
        ParameterSpec("target", "Cible IPv6", "string"),
    )
    positionals = (Positional("interface"), Positional("target"))
    patterns = (
        Pattern(r"alive|vivant", "Hote IPv6 vivant detecte", "info"),
        Pattern(r"attack|flood|spoof", "Attaque IPv6 lancee", "critical"),
    )


class ThcSslDosTool(SpecTool):
    name = "thc-ssl-dos"
    aliases = ()
    binary = "thc-ssl-dos"
    risk = "critical"
    description = "Teste la resistance d'un serveur TLS (renegociation couteuse)."
    examples = ("teste la resistance tls de target.com sur le port 443",)
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port TLS", "string", default="443"),
        ParameterSpec("connections", "Connexions concurrentes (-l)", "int"),
        ParameterSpec("accept", "Ne pas demander de confirmation (--accept)", "bool", default=False),
    )
    options = (Option("connections", "-l"),)
    flags = (Flag("accept", "--accept"),)
    positionals = (Positional("target"), Positional("port"))
    numbers = (Number("connections", r"(\d+)\s*(?:connexions|connections)"),)
    patterns = (
        Pattern(r"handshake", "Poignee de main TLS en cours", "medium"),
        Pattern(r"error|refused", "Serveur injoignable ou protege", "low"),
    )


for _tool in (DhcpigTool(), SiegeTool(), SlowhttptestTool(), T50Tool(), ThcIpv6Tool(), ThcSslDosTool()):
    register(_tool)
