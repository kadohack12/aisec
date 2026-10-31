"""Outils d'IA offensive (classe `14-ai-tools`).

Cette classe regroupe les plateformes qui pilotent des outils de securite via un
modele de langage ou un serveur MCP: `hexstrike-ai` (plateforme MCP d'orchestration),
`mcpwn` (serveur MCP exposant des outils offensifs), `opencode` et `pi-dev`
(agents de codage en terminal) et `unsloth` (entrainement/execution de modeles).

Chaque outil est un plugin `Tool` (argv sans shell). Ces binaires executent du
code ou pilotent d'autres outils: le risque est `medium` a `high` selon qu'ils
lancent une session locale, un serveur d'ecoute ou une execution de commandes.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_any_path

_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_PORT_RE = re.compile(r"\b(?:port\s+)?(\d{2,5})\b")


def _host_port(text: str, default_host: str = "127.0.0.1", default_port: str = "") -> tuple[str, str]:
    url = _URL_RE.search(text)
    if url:
        raw = url.group(0).rstrip(".,;)")
        host = raw.split("://", 1)[-1].split("/", 1)[0]
        if ":" in host:
            host, port = host.split(":", 1)
            return host, port
        return host, default_port
    bare = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", text)
    if bare:
        return bare.group(1), (bare.group(2) or default_port)
    port = _PORT_RE.search(text)
    return default_host, (port.group(1) if port else default_port)


class HexstrikeTool(Tool):
    name = "hexstrike-ai"
    aliases = ("hexstrike",)
    binary = "hexstrike-ai"
    risk = "medium"
    description = "Plateforme d'orchestration de securite pilotee par IA (serveur MCP)."
    examples = (
        "lance le serveur hexstrike-ai sur le port 8888",
        "demarre hexstrike-ai avec le mode debug",
    )
    parameters = (
        ParameterSpec("server", "Demarrer le serveur MCP (--server)", "bool", default=False),
        ParameterSpec("host", "Adresse d'ecoute (--host)", "string"),
        ParameterSpec("port", "Port d'ecoute (--port)", "string"),
        ParameterSpec("debug", "Mode debug (--debug)", "bool", default=False),
        ParameterSpec("config", "Fichier de configuration (--config)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hexstrike-ai"]
        if params.get("server"):
            argv.append("--server")
        if params.get("host"):
            argv += ["--host", str(params["host"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        if params.get("config"):
            argv += ["--config", str(params["config"])]
        if params.get("debug"):
            argv.append("--debug")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "serveur" in low or "server" in low or "mcp" in low:
            params["server"] = True
        host, port = _host_port(text)
        if port:
            params["port"] = port
        if re.search(r"\b(0\.0\.0\.0|localhost|127\.0\.0\.1)\b", low):
            params["host"] = host
        if "debug" in low:
            params["debug"] = True
        path = extract_any_path(text)
        if path:
            params["config"] = path
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("host") == "0.0.0.0":
            findings.append(
                Finding(
                    title="Serveur MCP expose sur toutes les interfaces",
                    severity="high",
                    detail="Un serveur d'orchestration offensif ne doit pas etre joignable publiquement.",
                )
            )
        if re.search(r"\b(listening|running on|started)\b", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Serveur hexstrike-ai actif",
                    severity="medium",
                    detail="La plateforme peut executer des outils de securite via le modele.",
                )
            )
        return AnalysisResult(
            summary="Plateforme hexstrike-ai (orchestration IA de securite).",
            findings=findings,
            source="heuristic",
        )


class McpwnTool(Tool):
    name = "mcpwn"
    binary = "mcpwn"
    risk = "high"
    description = "Serveur MCP qui expose des outils offensifs a un modele de langage."
    examples = ("lance le serveur mcpwn sur le port 1337",)
    parameters = (
        ParameterSpec("server", "Mode serveur MCP (--server)", "bool", default=False),
        ParameterSpec("transport", "Transport MCP: stdio, sse, http", "string"),
        ParameterSpec("host", "Adresse d'ecoute", "string"),
        ParameterSpec("port", "Port d'ecoute", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["mcpwn"]
        if params.get("server"):
            argv.append("--server")
        if params.get("transport"):
            argv += ["--transport", str(params["transport"])]
        if params.get("host"):
            argv += ["--host", str(params["host"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "serveur" in low or "server" in low or "mcp" in low:
            params["server"] = True
        for transport in ("stdio", "sse", "http"):
            if transport in low:
                params["transport"] = transport
                break
        host, port = _host_port(text)
        if port:
            params["port"] = port
        if re.search(r"\b(0\.0\.0\.0|localhost|127\.0\.0\.1)\b", low):
            params["host"] = host
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("host") == "0.0.0.0":
            findings.append(
                Finding(
                    title="Serveur MCP offensif expose sur toutes les interfaces",
                    severity="critical",
                    detail="Toute machine du reseau pourrait executer des outils via le modele.",
                )
            )
        if str(params.get("transport", "")).lower() in {"sse", "http"}:
            findings.append(
                Finding(
                    title="Transport MCP reseau (SSE/HTTP)",
                    severity="medium",
                    detail="Le transport stdio est plus sur: il n'ouvre pas de port.",
                )
            )
        return AnalysisResult(
            summary="Serveur MCP mcpwn (outils offensifs exposes au modele).",
            findings=findings,
            source="heuristic",
        )


class OpencodeTool(Tool):
    name = "opencode"
    binary = "opencode"
    risk = "medium"
    description = "Agent de codage IA en terminal (modifie le projet et execute des commandes)."
    examples = (
        "lance opencode dans le projet courant",
        "demande a opencode de corriger le bug dans src/app.py",
    )
    parameters = (
        ParameterSpec("prompt", "Tache confiee a l'agent (positionnel)", "string"),
        ParameterSpec("model", "Modele a utiliser (-m)", "string"),
        ParameterSpec("agent", "Agent a utiliser (-a)", "string"),
        ParameterSpec("cwd", "Repertoire de travail (-c)", "string"),
        ParameterSpec("print", "Mode non interactif (-p)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["opencode"]
        if params.get("print"):
            argv.append("-p")
        if params.get("model"):
            argv += ["-m", str(params["model"])]
        if params.get("agent"):
            argv += ["-a", str(params["agent"])]
        if params.get("cwd"):
            argv += ["-c", str(params["cwd"])]
        if params.get("prompt"):
            argv.append(str(params["prompt"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "non interactif" in low or "sans interaction" in low or " -p" in low:
            params["print"] = True
        model = re.search(r"(?:modele|model)\s+([\w./:-]+)", low)
        if model:
            params["model"] = model.group(1)
        prompt = re.search(r"(?:demande|tache|corrige|explique|implemente)\s+(.+)", text, re.IGNORECASE)
        if prompt:
            params["prompt"] = prompt.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"\b(rm -rf|sudo|chmod 777|curl \||wget \|)\b", stdout):
            findings.append(
                Finding(
                    title="Commande systeme sensible proposee par l'agent",
                    severity="high",
                    detail="Un agent de codage ne doit pas executer de commande destructrice sans validation.",
                )
            )
        return AnalysisResult(
            summary="Agent de codage IA opencode (execution de taches sur le projet).",
            findings=findings,
            source="heuristic",
        )


class PiDevTool(Tool):
    name = "pi-dev"
    aliases = ("pi",)
    binary = "pi-dev"
    risk = "medium"
    description = "Agent IA de developpement en terminal (harnais + CLI interactive)."
    examples = ("lance l'agent pi-dev sur le projet",)
    parameters = (
        ParameterSpec("prompt", "Tache confiee a l'agent", "string"),
        ParameterSpec("model", "Modele a utiliser (-m)", "string"),
        ParameterSpec("cwd", "Repertoire de travail (-C)", "string"),
        ParameterSpec("yes", "Auto-approuver les actions (-y)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["pi-dev"]
        if params.get("model"):
            argv += ["-m", str(params["model"])]
        if params.get("cwd"):
            argv += ["-C", str(params["cwd"])]
        if params.get("yes"):
            argv.append("-y")
        if params.get("prompt"):
            argv.append(str(params["prompt"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "auto" in low or "sans confirmation" in low or "-y" in low:
            params["yes"] = True
        prompt = re.search(r"(?:demande|tache|fais|ajoute|corrige)\s+(.+)", text, re.IGNORECASE)
        if prompt:
            params["prompt"] = prompt.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("yes"):
            findings.append(
                Finding(
                    title="Auto-approbation activee",
                    severity="medium",
                    detail="L'agent peut modifier le projet et executer des commandes sans confirmation.",
                )
            )
        return AnalysisResult(
            summary="Agent de developpement IA pi-dev.",
            findings=findings,
            source="heuristic",
        )


class UnslothTool(Tool):
    name = "unsloth"
    binary = "unsloth"
    risk = "medium"
    description = "Entraine et execute des modeles de langage (Unsloth Studio)."
    examples = (
        "entraine un modele avec unsloth sur le jeu de donnees dataset.jsonl",
        "lance le studio unsloth",
    )
    parameters = (
        ParameterSpec("action", "Action: studio, train, run", "string"),
        ParameterSpec("model", "Modele de base (--model)", "string"),
        ParameterSpec("dataset", "Jeu de donnees d'entrainement (--dataset)", "string"),
        ParameterSpec("output", "Repertoire de sortie (--output)", "string"),
        ParameterSpec("epochs", "Nombre d'epoques (--epochs)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        action = str(params.get("action") or "studio")
        argv = ["unsloth", action]
        if params.get("model"):
            argv += ["--model", str(params["model"])]
        if params.get("dataset"):
            argv += ["--dataset", str(params["dataset"])]
        if params.get("output"):
            argv += ["--output", str(params["output"])]
        if params.get("epochs"):
            argv += ["--epochs", str(params["epochs"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "entrain" in low or "fine-tun" in low or "fine tun" in low or "train" in low:
            params["action"] = "train"
        elif "lance" in low and ("modele" in low or "run" in low):
            params["action"] = "run"
        else:
            params["action"] = "studio"
        dataset = re.search(r"([\w./-]+\.(?:jsonl?|csv|parquet|txt))", text, re.IGNORECASE)
        if dataset:
            params["dataset"] = dataset.group(1)
        model = re.search(r"(?:modele|model)\s+([\w./:-]+)", low)
        if model and model.group(1) != "unsloth":
            params["model"] = model.group(1)
        epochs = re.search(r"(\d+)\s*(?:epoques?|epochs?)", low)
        if epochs:
            params["epochs"] = int(epochs.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("action") == "train":
            findings.append(
                Finding(
                    title="Entrainement d'un modele local",
                    severity="info",
                    detail="Verifier que le jeu de donnees ne contient pas de secrets.",
                )
            )
        if re.search(r"\bCUDA out of memory|OOM\b", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Memoire GPU insuffisante",
                    severity="low",
                    detail="Reduire la taille de lot ou la longueur de sequence.",
                )
            )
        return AnalysisResult(
            summary="Unsloth (entrainement/execution de modeles).",
            findings=findings,
            source="heuristic",
        )


register(HexstrikeTool())
register(McpwnTool())
register(OpencodeTool())
register(PiDevTool())
register(UnslothTool())
