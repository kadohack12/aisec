"""Expert Automotive (classe 13-automotive).

Jalon 1: can-utils (SocketCAN). Lecture et ecriture de trames CAN, configuration
d'interface, conversion de journaux et decodage ISO-TP.
"""

from __future__ import annotations

from .base import Expert

AUTOMOTIVE_EXPERT = Expert(
    name="automotive",
    description="Bus CAN: capture, emission de trames, configuration d'interface et diagnostic ISO-TP.",
    system_prompt=(
        "Tu es un expert des bus CAN (automobile et industriel). Tu choisis l'outil "
        "le plus adapte parmi candump, cansend, cangen, canconfig, canconvert et "
        "isotpdump, puis tu extrais les parametres exacts. La lecture (candump, "
        "isotpdump) est passive; l'emission de trames (cansend, cangen) et la "
        "reconfiguration d'interface (canconfig) sont des actions d'ecriture sur le "
        "bus et exigent une confirmation. N'agis que sur un vehicule ou un banc "
        "d'essai que tu es autorise a manipuler."
    ),
    tool_names=["candump", "cansend", "cangen", "canconfig", "canconvert", "isotpdump"],
    routing_rules=(
        ("candump", ("candump", "capture les trames", "lit les trames", "ecoute le bus")),
        ("cansend", ("cansend", "envoie la trame", "emets une trame", "emettre une trame")),
        ("cangen", ("cangen", "genere du trafic", "generer des trames", "charge du bus")),
        ("canconfig", ("canconfig", "configure l'interface", "bitrate", "debit du bus")),
        ("canconvert", ("canconvert", "convertit le journal", "conversion de journal", "candump2asc")),
        ("isotpdump", ("isotpdump", "isotp", "diagnostic", "uds")),
    ),
    keywords=(
        "can",
        "canbus",
        "can bus",
        "bus can",
        "trame can",
        "trames can",
        "can0",
        "socketcan",
        "automotive",
        "automobile",
        "vehicule",
        "obd",
        "isotp",
        "uds",
        "candump",
        "cansend",
        "cangen",
        "canconfig",
        "trame can",
    ),
)
