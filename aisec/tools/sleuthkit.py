"""Outils Sleuth Kit: analyse d'images disque (partition, fichiers, inodes)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

# fls: "r/r * 1234-128-1: nom" ou "d/d 11: dossier"
_FLS_RE = re.compile(r"^([rdv])/([rdv])\s+(?:\*\s+)?(\d+)(?:-\d+-\d+)?:\s+(.*)$", re.MULTILINE)
# mmls: "000:  Meta  0000000000   0000000000   0000000001   Description"
_MMLS_RE = re.compile(r"^(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)$", re.MULTILINE)


class SleuthkitFlsTool(Tool):
    name = "fls"
    aliases = ("sleuthkit",)
    binary = "fls"
    risk = "low"
    description = "Liste les fichiers et repertoires d'une image disque (par inode)."
    examples = (
        "liste les fichiers de disk.img avec fls",
        "fls recursif sur image.dd",
    )
    parameters = (
        ParameterSpec("image", "Image disque", "string", required=True),
        ParameterSpec("offset", "Offset de la partition (-o)", "string"),
        ParameterSpec("recursive", "Listage recursif (-r)", "bool", default=False),
        ParameterSpec("deleted", "Inclure les fichiers supprimes (-d)", "bool", default=False),
        ParameterSpec("body_file", "Liste des fichiers a traiter (-m)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["fls"]
        if params.get("recursive"):
            argv.append("-r")
        if params.get("deleted"):
            argv.append("-d")
        if params.get("offset"):
            argv += ["-o", str(params["offset"])]
        argv.append(str(params["image"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["image"] = path
        if "recursif" in low or "recursive" in low:
            params["recursive"] = True
        if "supprime" in low or "deleted" in low:
            params["deleted"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        deleted = 0
        for ftype, _mtype, inode, name in _FLS_RE.findall(stdout):
            name = name.strip()
            if name in {".", ".."}:
                continue
            if "*" in name or ftype == "r":
                pass
            if name.startswith("*"):
                deleted += 1
            findings.append(
                Finding(title=f"inode {inode}: {name}", severity="info", evidence=name)
            )
        if deleted:
            findings.append(
                Finding(
                    title=f"{deleted} entree(s) supprimee(s) detectee(s)",
                    severity="low",
                    detail="Fichiers supprimes potentiellement recuperables.",
                )
            )
        summary = f"{len(findings)} entree(s) listee(s) par fls."
        return AnalysisResult(summary=summary, findings=findings[:60], source="heuristic")


class SleuthkitMmlsTool(Tool):
    name = "mmls"
    binary = "mmls"
    risk = "low"
    description = "Affiche la table de partitions d'une image disque (offsets de secteurs)."
    examples = (
        "affiche les partitions de disk.img avec mmls",
        "table de partitions de image.dd",
    )
    parameters = (
        ParameterSpec("image", "Image disque", "string", required=True),
        ParameterSpec("type", "Type de table (-t): dos, bsd, mac, gpt", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mmls"]
        if params.get("type"):
            argv += ["-t", str(params["type"])]
        argv.append(str(params["image"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["image"] = path
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for slot, meta, _start, _end, length, description in _MMLS_RE.findall(stdout):
            description = description.strip()
            findings.append(
                Finding(
                    title=f"Slot {slot} ({meta})",
                    severity="info",
                    detail=description,
                    evidence=f"secteurs: {length}",
                )
            )
        return AnalysisResult(
            summary=f"{len(findings)} partition(s) identifiee(s).",
            findings=findings,
            source="heuristic",
        )


class SleuthkitIcatTool(Tool):
    name = "icat"
    binary = "icat"
    risk = "medium"
    description = "Extrait le contenu d'un fichier d'une image disque par son inode."
    examples = (
        "extrait l'inode 1234 de disk.img avec icat",
        "icat sur image.dd pour recuperer le fichier inode 55",
    )
    parameters = (
        ParameterSpec("image", "Image disque", "string", required=True),
        ParameterSpec("inode", "Numero d'inode a extraire", "string", required=True),
        ParameterSpec("offset", "Offset de la partition (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["icat"]
        if params.get("offset"):
            argv += ["-o", str(params["offset"])]
        argv += [str(params["image"]), str(params["inode"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["image"] = path
        inode = re.search(r"inode\s+(\d+)", text, re.IGNORECASE)
        if inode:
            params["inode"] = inode.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        size = len(stdout)
        findings = [
            Finding(
                title=f"Contenu extrait de l'inode {params.get('inode', '?')}",
                severity="info",
                detail=f"{size} octets extraits",
            )
        ] if stdout else []
        return AnalysisResult(
            summary=f"{size} octet(s) extrait(s) de l'inode.",
            findings=findings,
            source="heuristic",
        )


register(SleuthkitFlsTool())
register(SleuthkitMmlsTool())
register(SleuthkitIcatTool())
