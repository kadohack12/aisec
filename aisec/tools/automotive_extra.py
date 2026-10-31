"""Classe 13 - Automotive : entree de la suite can-utils.

La sous-categorie 13-01-can-utils liste la suite `can-utils` comme un seul
paquet; ses binaires (candump, cansend, cangen, canconfig, canconvert,
isotpdump...) sont deja implementes individuellement dans `automotive.py`.
Cette entree fournit un point d'entree d'inventaire pour la suite.
"""

from __future__ import annotations

from ..core.models import ParameterSpec
from ..core.registry import register
from .spec import Pattern, Positional, SpecTool


class CanUtilsTool(SpecTool):
    name = "can-utils"
    binary = "can-utils"
    risk = "medium"
    description = "Suite can-utils: capture, emission et conversion de trames CAN."
    examples = ("liste les utilitaires can-utils disponibles",)
    parameters = (ParameterSpec("binary", "Binaire de la suite a invoquer", "string"),)
    positionals = (Positional("binary"),)
    patterns = (
        Pattern(r"candump|cansend|cangen|canconfig", "Utilitaire disponible: {0}", "info"),
    )


register(CanUtilsTool())
