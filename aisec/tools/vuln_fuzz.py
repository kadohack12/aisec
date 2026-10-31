"""Outils de fuzzing (classe 02, sous-categorie Fuzzing Tools).

Couvre: bed, doona, sfuzz, siparmyknife, spike.
"""

from __future__ import annotations


from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Option, Pattern, Positional, Rule, SpecTool


class BedTool(SpecTool):
    name = "bed"
    aliases = ()
    binary = "bed"
    risk = "high"
    description = "Fuzzer de protocoles: teste des analyseurs reseau avec des entrees malformees."
    examples = ("fuzz le protocole http de 10.0.0.1 sur le port 80",)
    parameters = (
        ParameterSpec("protocol", "Protocole a fuzzer (-t)", "string"),
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port cible", "string"),
        ParameterSpec("fuzz", "Champ a fuzzer", "string"),
    )
    options = (Option("protocol", "-t"),)
    positionals = (Positional("host"), Positional("port"))
    rules = (
        Rule("protocol", ("http",), "http"),
        Rule("protocol", ("ftp",), "ftp"),
        Rule("protocol", ("smtp",), "smtp"),
        Rule("protocol", ("pop3",), "pop3"),
    )
    patterns = (
        Pattern(r"crash|segfault|abort", "La cible a plante", "high"),
        Pattern(r"error|refused", "Erreur de connexion", "low"),
    )


class DoonaTool(SpecTool):
    name = "doona"
    aliases = ()
    binary = "doona"
    risk = "high"
    description = "Fuzzer de services reseau: cherche des crashs sur des daemons (issu de bed)."
    examples = ("fuzz le service ftp de 10.0.0.1 sur le port 21",)
    parameters = (
        ParameterSpec("host", "Hote cible", "string", required=True),
        ParameterSpec("port", "Port cible", "string"),
        ParameterSpec("protocol", "Protocole (-t)", "string"),
    )
    options = (Option("protocol", "-t"),)
    positionals = (Positional("host"), Positional("port"))
    rules = (
        Rule("protocol", ("ftp",), "ftp"),
        Rule("protocol", ("http",), "http"),
        Rule("protocol", ("ssh",), "ssh"),
    )
    patterns = (
        Pattern(r"crash|segfault", "Service plante", "high"),
        Pattern(r"closed|refused", "Service ferme", "low"),
    )


class SfuzzTool(SpecTool):
    name = "sfuzz"
    aliases = ()
    binary = "sfuzz"
    risk = "high"
    description = "Fuzzer de protocoles simple et configurable (sfuzz)."
    examples = ("fuzz 10.0.0.1 port 80 avec le modele http",)
    parameters = (
        ParameterSpec("host", "Hote cible (-i)", "string", required=True),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("mode", "Mode/protocole (-S)", "string"),
        ParameterSpec("input", "Fichier d'entree (-f)", "string"),
        ParameterSpec("output", "Fichier journal (-o)", "string"),
    )
    options = (Option("host", "-i"), Option("port", "-p"), Option("mode", "-S"), Option("input", "-f"), Option("output", "-o"))
    patterns = (
        Pattern(r"crash|segfault", "Crash detecte", "high"),
        Pattern(r"connection|connected", "Connexion etablie", "info"),
    )


class SiparmyknifeTool(SpecTool):
    name = "siparmyknife"
    aliases = ()
    binary = "siparmyknife"
    risk = "high"
    description = "Generateur de requetes SIP malformees pour fuzzer des services VoIP."
    examples = ("fuzz le service sip de 10.0.0.1",)
    parameters = (
        ParameterSpec("target", "Hote:port SIP", "string", required=True),
        ParameterSpec("count", "Nombre de requetes", "int"),
    )
    target_params = ("target",)
    patterns = (
        Pattern(r"sent|envoye", "Requetes SIP envoyees", "medium"),
        Pattern(r"response|200 OK", "Reponse SIP recue", "info"),
    )


class SpikeTool(SpecTool):
    name = "spike"
    aliases = ()
    binary = "spike"
    risk = "high"
    description = "Framework de fuzzing (Spike): ecriture de scripts et generation de tests."
    examples = ("liste les scripts spike disponibles",)
    parameters = (
        ParameterSpec("script", "Script Spike a executer", "string"),
        ParameterSpec("target", "Hote cible", "string"),
    )
    positionals = (Positional("script"),)
    patterns = (
        Pattern(r"crash|segfault", "Crash detecte", "high"),
        Pattern(r"usage|Usage", "Aide de Spike", "info"),
    )


for _tool in (BedTool(), DoonaTool(), SfuzzTool(), SiparmyknifeTool(), SpikeTool()):
    register(_tool)
