"""Outils d'imagerie forensique: dc3dd, dcfldd, ddrescue (acquisition de disque)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_path

_PROGRESS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:MB|GB|bytes)\s", re.IGNORECASE)
_RESCUED_RE = re.compile(r"rescued:\s*(\d+)\s*B", re.IGNORECASE)
_BAD_RE = re.compile(r"bad areas:\s*(\d+)", re.IGNORECASE)


class Dc3ddTool(Tool):
    name = "dc3dd"
    binary = "dc3dd"
    risk = "high"
    description = "Acquisition forensique d'un disque/partition avec hachage et journalisation."
    examples = (
        "image forensique de /dev/sdb vers disk.img avec dc3dd",
        "copie forensique du disque /dev/sda avec verification md5",
    )
    parameters = (
        ParameterSpec("input", "Source (if=)", "string", required=True),
        ParameterSpec("output", "Destination (of=)", "string", required=True),
        ParameterSpec("hash", "Algorithme(s) de hachage (hash=), ex: md5,sha256", "string"),
        ParameterSpec("log", "Journal (log=)", "string"),
        ParameterSpec("bs", "Taille de bloc (bs=)", "string"),
        ParameterSpec("progress", "Afficher la progression (progress=on)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dc3dd"]
        if params.get("progress"):
            argv.append("progress=on")
        if params.get("hash"):
            argv += [f"hash={params['hash']}"]
        if params.get("log"):
            argv.append(f"log={params['log']}")
        if params.get("bs"):
            argv.append(f"bs={params['bs']}")
        argv += [f"if={params['input']}", f"of={params['output']}"]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        src = re.search(r"(/dev/\w+|[\w./\-]+\.(?:dd|raw|img))", text)
        if src:
            params["input"] = src.group(1)
        dst = re.search(r"(?:vers|dans|to|of=)\s+([\w./\-]+\.(?:dd|raw|img|e01))", text)
        if dst:
            params["output"] = dst.group(1)
        if "md5" in low:
            params["hash"] = "md5"
        if "sha256" in low:
            params["hash"] = "sha256"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"md5", stdout, re.IGNORECASE):
            for algo, digest in re.findall(r"(md5|sha1|sha256)\s+([0-9a-f]{32,64})", stdout, re.IGNORECASE):
                findings.append(
                    Finding(title=f"Empreinte {algo.upper()}", severity="info", evidence=digest)
                )
        if re.search(r"error|failed|input\/output", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Erreurs de lecture pendant l'acquisition",
                    severity="high",
                    detail="Des secteurs n'ont pas pu etre lus: image potentiellement incomplete.",
                )
            )
        summary = f"Acquisition dc3dd: {len(findings)} constat(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


class DdrescueTool(Tool):
    name = "ddrescue"
    binary = "ddrescue"
    risk = "high"
    description = "Recuperation de donnees d'un disque defectueux vers une image (reprise possible)."
    examples = (
        "recupere les donnees de /dev/sdb vers disk.img avec ddrescue",
        "ddrescue avec mapfile sur un disque abime",
    )
    parameters = (
        ParameterSpec("input", "Source (disque/partition)", "string", required=True),
        ParameterSpec("output", "Image de sortie", "string", required=True),
        ParameterSpec("mapfile", "Fichier de suivi (mapfile)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
        ParameterSpec("retries", "Nombre de passes (-r)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ddrescue"]
        if params.get("verbose"):
            argv.append("-v")
        if params.get("retries"):
            argv += ["-r", str(params["retries"])]
        argv += [str(params["input"]), str(params["output"])]
        if params.get("mapfile"):
            argv.append(str(params["mapfile"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        src = re.search(r"(/dev/\w+)", text)
        if src:
            params["input"] = src.group(1)
        dst = re.search(r"vers\s+([\w./\-]+\.(?:dd|raw|img))", text, re.IGNORECASE)
        if dst:
            params["output"] = dst.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        rescued = _RESCUED_RE.search(stdout)
        bad = _BAD_RE.search(stdout)
        if rescued:
            findings.append(
                Finding(title=f"Donnees recuperees: {rescued.group(1)} octets", severity="info")
            )
        if bad and bad.group(1) != "0":
            findings.append(
                Finding(
                    title=f"{bad.group(1)} zone(s) illisible(s)",
                    severity="high",
                    detail="Secteurs defectueux: donnees partiellement perdues.",
                )
            )
        summary = f"Recuperation ddrescue: {len(findings)} constat(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


register(Dc3ddTool())
register(DdrescueTool())
