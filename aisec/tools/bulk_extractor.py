"""Outil bulk_extractor: extraction en masse d'indicateurs (emails, URLs, cartes...)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# Indicateurs sensibles souvent extraits par bulk_extractor.
_SENSITIVE = {
    "ccn": ("Numeros de carte bancaire (CCN)", "critical"),
    "ssn": ("Numeros de securite sociale (SSN)", "critical"),
    "email": ("Adresses email", "medium"),
    "url": ("URLs", "low"),
    "domain": ("Domaines", "low"),
    "telephone": ("Numeros de telephone", "medium"),
    "gps": ("Coordonnees GPS", "medium"),
    "bitcoin": ("Adresses Bitcoin", "medium"),
    "json": ("Structures JSON", "info"),
    "exif": ("Metadonnees EXIF", "low"),
}
_FEATURE_RE = re.compile(r"^\s*(\w[\w-]*)\s+(\d+)\s*$")


class BulkExtractorTool(Tool):
    name = "bulk_extractor"
    aliases = ("bulk-extractor",)
    binary = "bulk_extractor"
    risk = "medium"
    description = "Extrait en masse des indicateurs (emails, URLs, CCN, GPS, EXIF) d'une image."
    examples = (
        "extrait les emails et urls de disk.img avec bulk_extractor",
        "recherche les numeros de carte dans image.dd",
    )
    parameters = (
        ParameterSpec("input", "Image ou fichier source", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string", default="output"),
        ParameterSpec("scanners", "Scanners a activer (-e), ex: 'email,url'", "string"),
        ParameterSpec("disable", "Scanners a desactiver (-x)", "string"),
        ParameterSpec("threads", "Nombre de threads (-j)", "int"),
        ParameterSpec("all", "Tous les scanners (-e all)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bulk_extractor", "-o", str(params.get("output") or "output")]
        if params.get("all"):
            argv += ["-e", "all"]
        elif params.get("scanners"):
            argv += ["-e", str(params["scanners"])]
        if params.get("disable"):
            argv += ["-x", str(params["disable"])]
        if params.get("threads"):
            argv += ["-j", str(params["threads"])]
        argv.append(str(params["input"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["input"] = path
        wanted = [key for key in ("email", "url", "ccn", "ssn", "gps", "exif", "domain") if key in low]
        if wanted:
            params["scanners"] = ",".join(wanted)
        if "carte" in low or "bancaire" in low or "ccn" in low:
            params["scanners"] = "ccn"
        if "tous les scanners" in low or "all" in low:
            params["all"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for feature, count in _FEATURE_RE.findall(stdout):
            key = feature.lower()
            if key in _SENSITIVE:
                label, severity = _SENSITIVE[key]
                findings.append(
                    Finding(title=f"{label}: {count} occurrence(s)", severity=severity)
                )
        summary = f"{len(findings)} categorie(s) d'indicateurs extraite(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(BulkExtractorTool())
