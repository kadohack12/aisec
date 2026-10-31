"""Outils d'artefacts Windows: registre (regripper, reglookup) et navigateurs (galleta, vinetto)."""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hive, extract_path

# Cles de registre interessantes en investigation.
_INTERESTING = (
    "run", "runonce", "services", "usb", "timezone", "lastwrite", "install",
    "autorun", "shellbag", "userassist", "network", "shutdown",
)
# regripper: "key = value"
_KV_RE = re.compile(r"^\s*([^=\n]+?)\s*=\s*(.*)$", re.MULTILINE)


class RegripperTool(Tool):
    name = "regripper"
    binary = "regripper"
    risk = "low"
    description = "Analyse une ruche de registre Windows (NTUSER.DAT, SYSTEM) par plugin."
    examples = (
        "analyse la ruche NTUSER.DAT avec regripper plugin run",
        "liste les cles de demarrage du registre SYSTEM",
    )
    parameters = (
        ParameterSpec("hive", "Fichier de ruche de registre", "string", required=True),
        ParameterSpec("plugin", "Plugin a executer (-p)", "string"),
        ParameterSpec("list_plugins", "Lister les plugins (-l)", "bool", default=False),
        ParameterSpec("output", "Fichier de sortie (-f)", "string"),
        ParameterSpec("all", "Executer tous les plugins (-a)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["regripper"]
        if params.get("list_plugins"):
            argv.append("-l")
        if params.get("all"):
            argv.append("-a")
        argv += ["-r", str(params["hive"])]
        if params.get("plugin"):
            argv += ["-p", str(params["plugin"])]
        if params.get("output"):
            argv += ["-f", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hive = extract_hive(text)
        if hive:
            params["hive"] = hive
        plugin = re.search(r"plugin\s+(\w+)", low)
        if plugin:
            params["plugin"] = plugin.group(1)
        for key in _INTERESTING:
            if key in low and "plugin" not in params:
                params["plugin"] = key
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for key, value in _KV_RE.findall(stdout):
            key = key.strip()
            value = value.strip()
            if not value:
                continue
            low = key.lower()
            if any(k in low for k in _INTERESTING):
                findings.append(
                    Finding(title=f"{key}: {value[:120]}", severity="medium", evidence=value[:200])
                )
        return AnalysisResult(
            summary=f"{len(findings)} cle(s) de registre interessante(s).",
            findings=findings[:40],
            source="heuristic",
        )


class ReglookupTool(Tool):
    name = "reglookup"
    binary = "reglookup"
    risk = "low"
    description = "Parcourt une ruche de registre Windows et filtre les cles (sortie CSV)."
    examples = (
        "parcourt la ruche SYSTEM avec reglookup",
        "cherche la cle usb dans le registre",
    )
    parameters = (
        ParameterSpec("hive", "Fichier de ruche de registre", "string", required=True),
        ParameterSpec("path_filter", "Filtre de chemin (regex POSIX)", "string"),
        ParameterSpec("type_filter", "Filtre de type de valeur (-t)", "string"),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["reglookup"]
        if params.get("verbose"):
            argv.append("-v")
        if params.get("type_filter"):
            argv += ["-t", str(params["type_filter"])]
        argv.append(str(params["hive"]))
        if params.get("path_filter"):
            argv.append(str(params["path_filter"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hive = extract_hive(text)
        if hive:
            params["hive"] = hive
        for key in _INTERESTING:
            if key in low:
                params["path_filter"] = key
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        count = 0
        for line in stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 4:
                continue
            count += 1
            path, key, value = parts[0], parts[1], parts[2]
            if any(k in path.lower() for k in _INTERESTING) and value:
                findings.append(
                    Finding(title=f"{path}\\{key}", severity="medium", detail=value[:120])
                )
        return AnalysisResult(
            summary=f"{count} entree(s) de registre lue(s).",
            findings=findings[:40],
            source="heuristic",
        )


class GalletaTool(Tool):
    name = "galleta"
    binary = "galleta"
    risk = "low"
    description = "Extrait les cookies et l'historique Internet Explorer d'un fichier."
    examples = (
        "extrait les cookies de Cookies.txt avec galleta",
        "analyse l'historique Internet Explorer index.dat",
    )
    parameters = (
        ParameterSpec("file", "Fichier a analyser (cookies, index.dat)", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-d)", "string"),
        ParameterSpec("format", "Format de sortie (-t): text, csv", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["galleta"]
        if params.get("format"):
            argv += ["-t", str(params["format"])]
        if params.get("output"):
            argv += ["-d", str(params["output"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["file"] = path
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if ":" not in line:
                continue
            low = line.lower()
            if "cookie" in low or "url" in low or "http" in low:
                findings.append(Finding(title=line.strip()[:140], severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} entree(s) de navigation extraite(s).",
            findings=findings[:40],
            source="heuristic",
        )


class VinettoTool(Tool):
    name = "vinetto"
    binary = "vinetto"
    risk = "low"
    description = "Extrait les vignettes d'un fichier Thumbs.db (artefacts Windows)."
    examples = (
        "extrait les vignettes de Thumbs.db avec vinetto",
        "liste les vignettes du fichier Thumbs.db",
    )
    parameters = (
        ParameterSpec("file", "Fichier Thumbs.db", "string", required=True),
        ParameterSpec("output", "Repertoire de sortie (-o)", "string"),
        ParameterSpec("info", "Afficher les metadonnees (-i)", "bool", default=False),
        ParameterSpec("dump", "Extraire les vignettes (-d)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["vinetto"]
        if params.get("info"):
            argv.append("-i")
        if params.get("dump"):
            argv.append("-d")
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        argv.append(str(params["file"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        path = extract_path(text)
        if path:
            params["file"] = path
        if "extrait" in low or "dump" in low:
            params["dump"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        count = len(re.findall(r"\.(?:jpe?g|png|bmp|gif)", stdout, re.IGNORECASE))
        if count:
            findings.append(Finding(title=f"{count} vignette(s) trouvee(s)", severity="info"))
        for line in stdout.splitlines():
            if re.search(r"(path|name|date)", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:140], severity="info"))
        return AnalysisResult(
            summary=f"{count} vignette(s) extraite(s) de Thumbs.db.",
            findings=findings[:40],
            source="heuristic",
        )


register(RegripperTool())
register(ReglookupTool())
register(GalletaTool())
register(VinettoTool())
