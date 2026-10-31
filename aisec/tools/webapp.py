"""Outils d'analyse d'applications web (classe Web Application Analysis).

Couvre les scanners de vulnerabilites web, le fingerprinting de technologies
et les crawlers / bruteforce de repertoires de la classe `03-webapp-analysis`.
Chaque outil est un plugin `Tool` (argv sans shell, risque declare pour la
politique de controle de niveau 2).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts

_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_PATH_RE = re.compile(r"(/[\w./\-]*wordlists?[\w./\-]*|/usr/share/[\w./\-]+)", re.IGNORECASE)


def _extract_target(text: str) -> str:
    """Recupere une URL complete, sinon un hostname/IP du texte."""
    url = _URL_RE.search(text)
    if url:
        return url.group(0).rstrip(".,;)")
    hosts = extract_hosts(text)
    return hosts[0] if hosts else ""


def _extract_wordlist(text: str) -> str:
    match = _PATH_RE.search(text)
    return match.group(1) if match else ""


def _extract_extensions(text: str) -> list[str]:
    match = re.search(r"(?:extensions?|ext)\s*[:=]?\s*([\w,./\- ]+)", text, re.IGNORECASE)
    if not match:
        return []
    return [part.strip().lstrip(".") for part in re.split(r"[,\s]+", match.group(1)) if part.strip()]


class NiktoTool(Tool):
    name = "nikto"
    binary = "nikto"
    risk = "medium"
    description = "Scanner de serveur web: erreurs de config, fichiers sensibles, CVE."
    examples = (
        "scanne le serveur web http://example.com avec nikto",
        "nikto sur example.com port 8443 en https",
    )
    parameters = (
        ParameterSpec("target", "URL ou hote a scanner", "string", required=True),
        ParameterSpec("port", "Port du service web", "int"),
        ParameterSpec("ssl", "Forcer HTTPS (-ssl)", "bool", default=False),
        ParameterSpec("tuning", "Categories de tests (-Tuning), ex: 123b", "string"),
        ParameterSpec("output_format", "Format de sortie: json, csv, html", "string"),
        ParameterSpec("output_file", "Fichier de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nikto", "-h", str(params["target"])]
        if params.get("port"):
            argv += ["-p", str(params["port"])]
        if params.get("ssl"):
            argv.append("-ssl")
        if params.get("tuning"):
            argv += ["-Tuning", str(params["tuning"])]
        if params.get("output_format"):
            argv += ["-Format", str(params["output_format"])]
        if params.get("output_file"):
            argv += ["-o", str(params["output_file"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        port = re.search(r"\bport\s+(\d+)", low)
        if port:
            params["port"] = int(port.group(1))
        if any(k in low for k in ("https", "ssl", "tls")):
            params["ssl"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.match(r"^\+\s", line) and "OSVDB" in line.upper():
                findings.append(Finding(title=line.strip()[:160], severity="medium"))
            elif re.search(r"\b(CVE-\d{4}-\d+)\b", line):
                cve = re.search(r"\b(CVE-\d{4}-\d+)\b", line).group(1)
                findings.append(Finding(title=f"Vulnerabilite {cve}", severity="high", evidence=line.strip()[:160]))
        if "Server:" in stdout:
            findings.append(Finding(title="Banniere serveur exposee", severity="low"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) nikto.",
            findings=findings,
            source="heuristic",
        )


class WhatwebTool(Tool):
    name = "whatweb"
    binary = "whatweb"
    risk = "low"
    description = "Fingerprinting de technologies web (CMS, serveur, frameworks, JS)."
    examples = (
        "identifie les technologies de http://example.com",
        "fingerprint agressif de example.com",
    )
    parameters = (
        ParameterSpec("target", "URL ou hote", "string", required=True),
        ParameterSpec("aggression", "Niveau d'agressivite (1-4)", "int"),
        ParameterSpec("verbose", "Sortie detaillee (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["whatweb"]
        if params.get("aggression"):
            argv.append(f"-a{params['aggression']}")
        if params.get("verbose"):
            argv.append("-v")
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        level = re.search(r"\b(?:agressif|aggression|niveau)\s*([1-4])\b", low)
        if level:
            params["aggression"] = int(level.group(1))
        elif "agressif" in low:
            params["aggression"] = 3
        if "verbose" in low or "detaille" in low:
            params["verbose"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if line.strip().startswith("http"):
                findings.append(
                    Finding(
                        title="Technologies detectees",
                        severity="info",
                        evidence=line.strip()[:200],
                    )
                )
        return AnalysisResult(
            summary=f"{len(findings)} hote(s) profile(s).",
            findings=findings,
            source="heuristic",
        )


class WpscanTool(Tool):
    name = "wpscan"
    binary = "wpscan"
    risk = "high"
    description = "Scanner WordPress: version, plugins et themes vulnerables, utilisateurs."
    examples = (
        "scanne le wordpress de http://example.com",
        "enumere les utilisateurs du wordpress example.com",
    )
    parameters = (
        ParameterSpec("target", "URL du site WordPress", "string", required=True),
        ParameterSpec("enumerate", "Que enumerer: vp,vt,u,cb,dbe", "string"),
        ParameterSpec("api_token", "Jeton API WPScan (--api-token)", "string"),
        ParameterSpec("plugins_detection", "Detection des plugins (--plugins-detection)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["wpscan", "--url", str(params["target"])]
        if params.get("enumerate"):
            argv += ["--enumerate", str(params["enumerate"])]
        if params.get("api_token"):
            argv += ["--api-token", str(params["api_token"])]
        if params.get("plugins_detection"):
            argv += ["--plugins-detection", str(params["plugins_detection"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        flags = []
        if any(k in low for k in ("plugin", "extension")):
            flags.append("vp")
        if "theme" in low:
            flags.append("vt")
        if any(k in low for k in ("utilisateur", "user", "auteur")):
            flags.append("u")
        if flags:
            params["enumerate"] = ",".join(flags)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"\[\+\].*(?:vulnerab|CVE)", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:160], severity="high"))
            elif re.search(r"\[i\].*WordPress version", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:160], severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} constat(s) WordPress.",
            findings=findings,
            source="heuristic",
        )


class JoomscanTool(Tool):
    name = "joomscan"
    binary = "joomscan"
    risk = "medium"
    description = "Scanner Joomla: version, composants et extensions vulnerables."
    examples = ("scanne le joomla de http://example.com",)
    parameters = (
        ParameterSpec("target", "URL du site Joomla", "string", required=True),
        ParameterSpec("enumerate_components", "Enumeration des composants (-ec)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["joomscan", "-u", str(params["target"])]
        if params.get("enumerate_components"):
            argv.append("-ec")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        if "composant" in text.lower() or "component" in text.lower():
            params["enumerate_components"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="medium")
            for line in stdout.splitlines()
            if re.search(r"vulnerab|CVE", line, re.IGNORECASE)
        ]
        return AnalysisResult(summary=f"{len(findings)} constat(s) Joomla.", findings=findings, source="heuristic")


class GobusterTool(Tool):
    name = "gobuster"
    binary = "gobuster"
    risk = "high"
    description = "Bruteforce de repertoires, DNS, vhosts et fichiers web."
    examples = (
        "bruteforce les repertoires de http://example.com avec gobuster",
        "enumere les vhosts de example.com",
    )
    parameters = (
        ParameterSpec("mode", "Mode: dir, dns, vhost, fuzz", "string", default="dir"),
        ParameterSpec("target", "URL (dir) ou domaine (dns/vhost)", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("extensions", "Extensions a tester (-x)", "list"),
        ParameterSpec("threads", "Nombre de threads (-t)", "int"),
        ParameterSpec("status_codes", "Codes a afficher (-s)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = str(params.get("mode") or "dir")
        argv = ["gobuster", mode, "-u", str(params["target"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        if params.get("extensions"):
            argv += ["-x", ",".join(params["extensions"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        if params.get("status_codes"):
            argv += ["-s", str(params["status_codes"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        if "vhost" in low or "hote virtuel" in low:
            params["mode"] = "vhost"
        elif any(k in low for k in ("sous-domaine", "subdomain", "dns")):
            params["mode"] = "dns"
        else:
            params["mode"] = "dir"
        wordlist = _extract_wordlist(text)
        if wordlist:
            params["wordlist"] = wordlist
        exts = _extract_extensions(text)
        if exts:
            params["extensions"] = exts
        threads = re.search(r"(\d+)\s*(?:threads|thread)", low)
        if threads:
            params["threads"] = int(threads.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            match = re.search(r"(?:Found|Status:\s*\d+).*", line)
            if match and re.search(r"\b(?:200|204|301|302|307|401|403)\b", line):
                findings.append(Finding(title=line.strip()[:160], severity="info"))
        return AnalysisResult(
            summary=f"{len(findings)} ressource(s) trouvee(s).",
            findings=findings,
            source="heuristic",
        )


class FfufTool(Tool):
    name = "ffuf"
    binary = "ffuf"
    risk = "high"
    description = "Fuzzing web rapide: repertoires, parametres, vhosts (mot-cle FUZZ)."
    examples = (
        "fuzz les repertoires de http://example.com/FUZZ",
        "ffuf sur http://example.com avec une liste de mots",
    )
    parameters = (
        ParameterSpec("url", "URL avec le mot-cle FUZZ", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("match_codes", "Codes a garder (-mc)", "string"),
        ParameterSpec("filter_size", "Taille a filtrer (-fs)", "int"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("method", "Methode HTTP (-X)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ffuf", "-u", str(params["url"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        if params.get("match_codes"):
            argv += ["-mc", str(params["match_codes"])]
        if params.get("filter_size"):
            argv += ["-fs", str(params["filter_size"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        if params.get("method"):
            argv += ["-X", str(params["method"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        url = _URL_RE.search(text)
        if url:
            base = url.group(0).rstrip(".,;)")
            params["url"] = base if "FUZZ" in base else base.rstrip("/") + "/FUZZ"
        wordlist = _extract_wordlist(text)
        if wordlist:
            params["wordlist"] = wordlist
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"\b(?:Status|status)\b.*\b\d{3}\b", line):
                findings.append(Finding(title=line.strip()[:160], severity="info"))
        return AnalysisResult(summary=f"{len(findings)} resultat(s) ffuf.", findings=findings, source="heuristic")


class DirbTool(Tool):
    name = "dirb"
    binary = "dirb"
    risk = "high"
    description = "Bruteforce de repertoires et fichiers web (wordlist + extensions)."
    examples = ("bruteforce les repertoires de http://example.com avec dirb",)
    parameters = (
        ParameterSpec("target", "URL cible", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots", "string"),
        ParameterSpec("extensions", "Extensions (-X)", "list"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dirb", str(params["target"])]
        if params.get("wordlist"):
            argv.append(str(params["wordlist"]))
        if params.get("extensions"):
            argv += ["-X", ",".join(params["extensions"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        wordlist = _extract_wordlist(text)
        if wordlist:
            params["wordlist"] = wordlist
        exts = _extract_extensions(text)
        if exts:
            params["extensions"] = exts
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="info")
            for line in stdout.splitlines()
            if re.search(r"\b(?:FOUND|CODE:)\b", line)
        ]
        return AnalysisResult(summary=f"{len(findings)} ressource(s) trouvee(s).", findings=findings, source="heuristic")


class FeroxbusterTool(Tool):
    name = "feroxbuster"
    binary = "feroxbuster"
    risk = "high"
    description = "Bruteforce recursif de repertoires web (Rust, rapide)."
    examples = ("feroxbuster sur http://example.com avec recursivite",)
    parameters = (
        ParameterSpec("target", "URL cible (-u)", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("depth", "Profondeur de recursion (-d)", "int"),
        ParameterSpec("extensions", "Extensions (-x)", "list"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["feroxbuster", "-u", str(params["target"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        if params.get("depth"):
            argv += ["-d", str(params["depth"])]
        if params.get("extensions"):
            argv += ["-x", ",".join(params["extensions"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        wordlist = _extract_wordlist(text)
        if wordlist:
            params["wordlist"] = wordlist
        depth = re.search(r"profondeur\s*(\d+)", low)
        if depth:
            params["depth"] = int(depth.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="info")
            for line in stdout.splitlines()
            if re.search(r"\b\d{3}\s+(?:GET|POST)\b", line)
        ]
        return AnalysisResult(summary=f"{len(findings)} ressource(s) trouvee(s).", findings=findings, source="heuristic")


class WfuzzTool(Tool):
    name = "wfuzz"
    binary = "wfuzz"
    risk = "high"
    description = "Fuzzing web generique (payloads FUZZ, filtrage par code/taille)."
    examples = ("fuzz http://example.com/FUZZ avec wfuzz",)
    parameters = (
        ParameterSpec("url", "URL avec le mot-cle FUZZ", "string", required=True),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("hide_codes", "Codes a masquer (--hc)", "string"),
        ParameterSpec("threads", "Threads (-t)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["wfuzz"]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        if params.get("hide_codes"):
            argv += ["--hc", str(params["hide_codes"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        argv.append(str(params["url"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        url = _URL_RE.search(text)
        if url:
            base = url.group(0).rstrip(".,;)")
            params["url"] = base if "FUZZ" in base else base.rstrip("/") + "/FUZZ"
        wordlist = _extract_wordlist(text)
        if wordlist:
            params["wordlist"] = wordlist
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="info")
            for line in stdout.splitlines()
            if re.search(r"\b\d{3}\b.*\bL\b.*\bW\b", line)
        ]
        return AnalysisResult(summary=f"{len(findings)} reponse(s) wfuzz.", findings=findings, source="heuristic")


class ArjunTool(Tool):
    name = "arjun"
    binary = "arjun"
    risk = "medium"
    description = "Decouverte de parametres HTTP caches (GET/POST/JSON)."
    examples = ("trouve les parametres caches de http://example.com/page",)
    parameters = (
        ParameterSpec("target", "URL cible (-u)", "string", required=True),
        ParameterSpec("method", "Methode HTTP (-m): GET, POST, JSON", "string"),
        ParameterSpec("wordlist", "Liste de parametres (-w)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["arjun", "-u", str(params["target"])]
        if params.get("method"):
            argv += ["-m", str(params["method"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        if "post" in low:
            params["method"] = "POST"
        elif "json" in low:
            params["method"] = "JSON"
        elif "get" in low:
            params["method"] = "GET"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        match = re.search(r"parameters found:?\s*(.+)", stdout, re.IGNORECASE)
        if match:
            findings.append(Finding(title=f"Parametres: {match.group(1).strip()[:160]}", severity="info"))
        return AnalysisResult(summary=f"{len(findings)} jeu(x) de parametres.", findings=findings, source="heuristic")


class GospiderTool(Tool):
    name = "gospider"
    binary = "gospider"
    risk = "medium"
    description = "Crawler web rapide: liens, scripts, formulaires, endpoints."
    examples = ("crawle http://example.com avec gospider",)
    parameters = (
        ParameterSpec("site", "URL de depart (-s)", "string", required=True),
        ParameterSpec("depth", "Profondeur (-d)", "int"),
        ParameterSpec("threads", "Threads (-t)", "int"),
        ParameterSpec("concurrent", "Requetes concurrentes (-c)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["gospider", "-s", str(params["site"])]
        if params.get("depth"):
            argv += ["-d", str(params["depth"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        if params.get("concurrent"):
            argv += ["-c", str(params["concurrent"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["site"] = target
        depth = re.search(r"profondeur\s*(\d+)", low)
        if depth:
            params["depth"] = int(depth.group(1))
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        urls = re.findall(r"https?://\S+", stdout)
        findings = [Finding(title="URL decouverte", severity="info", evidence=u[:160]) for u in urls[:20]]
        return AnalysisResult(summary=f"{len(urls)} URL decouverte(s).", findings=findings, source="heuristic")


class DirsearchTool(Tool):
    name = "dirsearch"
    binary = "dirsearch"
    risk = "high"
    description = "Bruteforce de repertoires web (Python, extensions configurables)."
    examples = ("dirsearch sur http://example.com",)
    parameters = (
        ParameterSpec("target", "URL cible (-u)", "string", required=True),
        ParameterSpec("extensions", "Extensions (-e)", "list"),
        ParameterSpec("wordlist", "Liste de mots (-w)", "string"),
        ParameterSpec("recursive", "Recursif (-r)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dirsearch", "-u", str(params["target"])]
        if params.get("extensions"):
            argv += ["-e", ",".join(params["extensions"])]
        if params.get("wordlist"):
            argv += ["-w", str(params["wordlist"])]
        if params.get("recursive"):
            argv.append("-r")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        exts = _extract_extensions(text)
        if exts:
            params["extensions"] = exts
        if "recursif" in low or "recursive" in low:
            params["recursive"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings = [
            Finding(title=line.strip()[:160], severity="info")
            for line in stdout.splitlines()
            if re.search(r"\b(?:200|301|302|401|403)\b", line) and "http" in line.lower()
        ]
        return AnalysisResult(summary=f"{len(findings)} chemin(s) trouve(s).", findings=findings, source="heuristic")


class WapitiTool(Tool):
    name = "wapiti"
    binary = "wapiti"
    risk = "high"
    description = "Scanner de vulnerabilites web (injection, XSS, fichiers, SSRF...)."
    examples = ("scanne les vulnerabilites de http://example.com avec wapiti",)
    parameters = (
        ParameterSpec("target", "URL de base (-u)", "string", required=True),
        ParameterSpec("modules", "Modules a charger (-m)", "list"),
        ParameterSpec("scope", "Perimetre (domain, folder, page, url)", "string"),
        ParameterSpec("format", "Format de rapport (-f)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["wapiti", "-u", str(params["target"])]
        if params.get("modules"):
            argv += ["-m", ",".join(params["modules"])]
        if params.get("scope"):
            argv += ["--scope", str(params["scope"])]
        if params.get("format"):
            argv += ["-f", str(params["format"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        modules = []
        if "xss" in low:
            modules.append("xss")
        if "sql" in low or "injection" in low:
            modules.append("sql")
        if "fichier" in low or "lfi" in low:
            modules.append("file")
        if modules:
            params["modules"] = modules
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"\b(?:Critical|High|Medium)\b", line):
                severity = "high" if "critical" in line.lower() or "high" in line.lower() else "medium"
                findings.append(Finding(title=line.strip()[:160], severity=severity))
        return AnalysisResult(summary=f"{len(findings)} vulnerabilite(s) wapiti.", findings=findings, source="heuristic")


class XsserTool(Tool):
    name = "xsser"
    binary = "xsser"
    risk = "high"
    description = "Detection et exploitation de failles XSS."
    examples = ("teste les failles xss sur http://example.com/page",)
    parameters = (
        ParameterSpec("url", "URL cible (--url)", "string", required=True),
        ParameterSpec("auto", "Mode automatique (--auto)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["xsser", "--url", str(params["url"])]
        if params.get("auto"):
            argv.append("--auto")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["url"] = target
        if "auto" in text.lower():
            params["auto"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"XSS\s+(?:found|vulnerab)", stdout, re.IGNORECASE):
            findings.append(Finding(title="Faille XSS detectee", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) XSS.", findings=findings, source="heuristic")


class SkipfishTool(Tool):
    name = "skipfish"
    binary = "skipfish"
    risk = "high"
    description = "Scanner de securite web recursif avec rapport HTML."
    examples = ("scanne http://example.com avec skipfish",)
    parameters = (
        ParameterSpec("output_dir", "Repertoire de rapport (-o)", "string", required=True),
        ParameterSpec("target", "URL cible", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["skipfish", "-o", str(params["output_dir"]), str(params["target"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        out = re.search(r"(?:sortie|rapport|output)\s+(/[\w./\-]+)", text, re.IGNORECASE)
        params["output_dir"] = out.group(1) if out else "./skipfish-report"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        match = re.search(r"(\d+)\s+warnings?", stdout, re.IGNORECASE)
        if match:
            findings.append(Finding(title=f"{match.group(1)} avertissement(s) skipfish", severity="medium"))
        return AnalysisResult(summary=f"{len(findings)} constat(s).", findings=findings, source="heuristic")


class S3scannerTool(Tool):
    name = "s3scanner"
    binary = "s3scanner"
    risk = "medium"
    description = "Detection de buckets S3 mal configures (acces public, ecriture)."
    examples = ("verifie le bucket s3 mon-bucket",)
    parameters = (
        ParameterSpec("bucket", "Nom du bucket (-bucket)", "string", required=True),
        ParameterSpec("provider", "Fournisseur (aws, gcp, digitalocean...)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["s3scanner", "-bucket", str(params["bucket"])]
        if params.get("provider"):
            argv += ["-provider", str(params["provider"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        match = re.search(r"\bbucket\s+([\w.\-]+)", text, re.IGNORECASE)
        if match:
            params["bucket"] = match.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"public|open|readable", stdout, re.IGNORECASE):
            findings.append(Finding(title="Bucket S3 accessible publiquement", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) S3.", findings=findings, source="heuristic")


class DavtestTool(Tool):
    name = "davtest"
    binary = "davtest"
    risk = "high"
    description = "Teste les serveurs WebDAV (upload et execution de fichiers)."
    examples = ("teste le webdav de http://example.com",)
    parameters = (
        ParameterSpec("url", "URL du service WebDAV (-url)", "string", required=True),
        ParameterSpec("directory", "Repertoire d'upload (-directory)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["davtest", "-url", str(params["url"])]
        if params.get("directory"):
            argv += ["-directory", str(params["directory"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["url"] = target
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"SUCCEED|Success", stdout, re.IGNORECASE):
            findings.append(Finding(title="Upload WebDAV reussi", severity="high", detail="Verifier l'execution de code."))
        return AnalysisResult(summary=f"{len(findings)} constat(s) WebDAV.", findings=findings, source="heuristic")


class HttrackTool(Tool):
    name = "httrack"
    binary = "httrack"
    risk = "medium"
    description = "Copie hors-ligne d'un site web (miroir de contenu)."
    examples = ("copie le site http://example.com en local avec httrack",)
    parameters = (
        ParameterSpec("target", "URL du site a copier", "string", required=True),
        ParameterSpec("output_dir", "Repertoire de destination (-O)", "string"),
        ParameterSpec("depth", "Profondeur de copie (-r)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["httrack", str(params["target"])]
        if params.get("output_dir"):
            argv += ["-O", str(params["output_dir"])]
        if params.get("depth"):
            argv += ["-r", str(params["depth"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        target = _extract_target(text)
        if target:
            params["target"] = target
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        match = re.search(r"(\d+)\s+files?\s+(?:retrieved|written)", stdout, re.IGNORECASE)
        if match:
            findings.append(Finding(title=f"{match.group(1)} fichier(s) copies", severity="info"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) httrack.", findings=findings, source="heuristic")


register(NiktoTool())
register(WhatwebTool())
register(WpscanTool())
register(JoomscanTool())
register(GobusterTool())
register(FfufTool())
register(DirbTool())
register(FeroxbusterTool())
register(WfuzzTool())
register(ArjunTool())
register(GospiderTool())
register(DirsearchTool())
register(WapitiTool())
register(XsserTool())
register(SkipfishTool())
register(S3scannerTool())
register(DavtestTool())
register(HttrackTool())
