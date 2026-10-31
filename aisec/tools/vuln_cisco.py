"""Outils d'audit Cisco (classe 02, sous-categorie Cisco Tools).

Couvre: cisco-auditing-tool, cisco-ocs, cisco-torch, copy-router-config,
nipper-ng, yersinia.
"""

from __future__ import annotations


from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Flag, Option, Pattern, Positional, Rule, SpecTool


class CiscoAuditingTool(SpecTool):
    name = "cisco-auditing-tool"
    aliases = ("CAT",)
    binary = "CAT"
    risk = "medium"
    description = "Audit d'un routeur Cisco: mots de passe par defaut, SNMP, services."
    examples = ("audite le routeur cisco 10.0.0.1 sur le port 23",)
    parameters = (
        ParameterSpec("host", "Adresse du routeur (-h)", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("password", "Mot de passe (-w)", "string"),
        ParameterSpec("snmp", "Auditer SNMP (-i)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    options = (Option("host", "-h"), Option("port", "-p"), Option("password", "-w"))
    flags = (Flag("snmp", "-i"), Flag("verbose", "-v"))
    patterns = (
        Pattern(r"password|default", "Mot de passe par defaut detecte", "high"),
        Pattern(r"snmp", "Service SNMP expose", "medium"),
        Pattern(r"failed|refused", "Connexion refusee", "low"),
    )


class CiscoOcsTool(SpecTool):
    name = "cisco-ocs"
    aliases = ()
    binary = "cisco-ocs"
    risk = "medium"
    description = "Cisco OCS: decouverte et audit des equipements Cisco du reseau."
    examples = ("decouvre les equipements cisco du reseau 192.168.1.0/24",)
    parameters = (
        ParameterSpec("target", "Reseau ou hote a scanner", "string", required=True),
        ParameterSpec("community", "Communaute SNMP", "string"),
        ParameterSpec("timeout", "Timeout en secondes", "int"),
    )
    target_params = ("target",)
    options = (Option("community", "-c"), Option("timeout", "-t"))
    patterns = (
        Pattern(r"Cisco IOS", "Equipement Cisco IOS detecte", "info"),
        Pattern(r"community", "Communaute SNMP detectee", "medium"),
    )


class CiscoTorchTool(SpecTool):
    name = "cisco-torch"
    aliases = ()
    binary = "cisco-torch"
    risk = "medium"
    description = "Scanner Cisco multi-protocoles: decouverte, empreintes, mots de passe."
    examples = ("scan cisco complet sur 10.0.0.1 avec empreintes",)
    parameters = (
        ParameterSpec("target", "Hote ou reseau", "string", required=True),
        ParameterSpec("fingerprint", "Empreinte des services (-f)", "bool", default=False),
        ParameterSpec("defaults", "Mots de passe par defaut (-b)", "bool", default=False),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )
    target_params = ("target",)
    flags = (Flag("fingerprint", "-f"), Flag("defaults", "-b"), Flag("verbose", "-v"))
    rules = (
        Rule("fingerprint", ("empreinte", "fingerprint", "banniere"), True),
        Rule("defaults", ("defaut", "default", "mots de passe"), True),
    )
    patterns = (
        Pattern(r"Cisco|IOS", "Equipement Cisco detecte", "info"),
        Pattern(r"password|login", "Service d'authentification expose", "medium"),
    )


class CopyRouterConfigTool(SpecTool):
    name = "copy-router-config"
    aliases = ()
    binary = "merge-router-config"
    risk = "high"
    description = "Recupere la configuration d'un routeur Cisco via SNMP/TFTP."
    examples = ("recupere la configuration du routeur 10.0.0.1 via snmp",)
    parameters = (
        ParameterSpec("target", "Adresse du routeur", "string", required=True),
        ParameterSpec("community", "Communaute SNMP (RO)", "string"),
        ParameterSpec("tftp_server", "Serveur TFTP de destination", "string"),
        ParameterSpec("config", "Fichier de sortie de la configuration", "string"),
    )
    target_params = ("target",)
    options = (
        Option("community", "-c"),
        Option("tftp_server", "-t"),
        Option("config", "-o"),
    )
    patterns = (
        Pattern(r"running-config|startup-config", "Configuration recuperee", "high", "Exposition de la configuration complete du routeur."),
        Pattern(r"timeout|failed", "Echec de la recuperation", "low"),
    )


class NipperTool(SpecTool):
    name = "nipper-ng"
    aliases = ("nipper",)
    binary = "nipper"
    risk = "low"
    description = "Audit hors-ligne de configurations d'equipements (Cisco, Juniper...)."
    examples = ("audite la configuration router.cfg et genere un rapport",)
    parameters = (
        ParameterSpec("input", "Fichier de configuration a analyser", "string", required=True),
        ParameterSpec("output", "Fichier de rapport (-o)", "string"),
        ParameterSpec("format", "Format du rapport: html, text, xml", "string"),
        ParameterSpec("device", "Type d'equipement: cisco, juniper, fortigate", "string"),
    )
    options = (Option("input", "-i"), Option("output", "-o"), Option("format", "-f"))
    patterns = (
        Pattern(r"high|High", "Vulnerabilite de severite haute", "high"),
        Pattern(r"security level|niveau de securite", "Niveau de securite evalue", "info"),
    )


class YersiniaTool(SpecTool):
    name = "yersinia"
    aliases = ()
    binary = "yersinia"
    risk = "high"
    description = "Attaques sur protocoles de niveau 2 (STP, CDP, DTP, DHCP, VTP)."
    examples = ("attaque dhcp avec yersinia sur eth0 en mode texte",)
    parameters = (
        ParameterSpec("protocol", "Protocole: stp, cdp, dtp, dhcp, vtp, dot1q", "string"),
        ParameterSpec("interface", "Interface reseau (-I)", "string"),
        ParameterSpec("attack", "Attaque a lancer (-attack)", "string"),
        ParameterSpec("text_mode", "Mode texte (-I -attack ...)", "bool", default=False),
    )
    options = (Option("interface", "-i"),)
    flags = (Flag("text_mode", "-I"),)
    positionals = (Positional("protocol"), Positional("attack"))
    rules = (
        Rule("protocol", ("stp", "spanning"), "stp"),
        Rule("protocol", ("cdp",), "cdp"),
        Rule("protocol", ("dtp",), "dtp"),
        Rule("protocol", ("dhcp",), "dhcp"),
        Rule("protocol", ("vtp",), "vtp"),
    )
    patterns = (
        Pattern(r"attack|attaque", "Attaque de niveau 2 lancee", "high", "Peut perturber le reseau commute."),
        Pattern(r"error|failed", "Echec de l'attaque", "low"),
    )


for _tool in (
    CiscoAuditingTool(),
    CiscoOcsTool(),
    CiscoTorchTool(),
    CopyRouterConfigTool(),
    NipperTool(),
    YersiniaTool(),
):
    register(_tool)
