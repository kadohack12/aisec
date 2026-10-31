"""Outils de maintien d'acces (classe `10-maintaining-access`).

Couvre les frameworks C2 et la reconnaissance AD (bloodhound, dnscat2, villain,
starkiller, convoc2, sliver), les backdoors systeme (powershell-empire, pwncat,
cryptcat, sbd), les backdoors web (weevely, webacoo, laudanum, nishang, webshells,
htshells) et la tunnellisation / evasion (iodine, dns2tcp, socat, proxychains,
stunnel, ptunnel, shellter, veil...).

Chaque binaire est un plugin `Tool` (argv sans shell). Politique de controle:
la reconnaissance et la configuration de proxy sont en `medium`; un serveur
d'ecoute, une backdoor, un implant, un tunnel ou une charge obfusquee sont en
`high` (acces persistant ou exfiltration). Ces outils ne doivent etre employes
que sur un perimetre autorise.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_any_path, extract_hosts

_PORT_RE = re.compile(r"\b(?:port|:)\s*(\d{2,5})\b", re.IGNORECASE)
_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+)\b", re.IGNORECASE)
_IFACE_RE = re.compile(r"\b(eth\d+|ens\d+|wlan\d+|tun\d+|tap\d+)\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_CONF_RE = re.compile(r"([\w./-]+\.conf)\b", re.IGNORECASE)


def _port(text: str, default: str = "") -> str:
    match = _PORT_RE.search(text)
    return match.group(1) if match else default


def _lhost(text: str) -> str:
    """Adresse d'ecoute: exige une IP ou un prefixe explicite (evite 'app.exe')."""
    explicit = re.search(r"(?:lhost|hote d'ecoute)\s+([\w.\-]+)", text, re.IGNORECASE)
    if explicit:
        return explicit.group(1)
    ip = _IP_RE.search(text)
    return ip.group(1) if ip else ""


def _host(text: str, default: str = "127.0.0.1") -> str:
    url = _URL_RE.search(text)
    if url:
        value = url.group(0).rstrip(".,;)").split("://", 1)[-1]
        return value.split("/", 1)[0].split(":", 1)[0]
    hosts = extract_hosts(text)
    return hosts[0] if hosts else default


def _domain(text: str, default: str = "example.com") -> str:
    hosts = extract_hosts(text)
    if hosts:
        return hosts[0]
    match = _DOMAIN_RE.search(text)
    return match.group(1) if match else default


# ---------------------------------------------------------------------------
# Frameworks C2 et reconnaissance Active Directory
# ---------------------------------------------------------------------------


class BloodhoundTool(Tool):
    name = "bloodhound"
    binary = "bloodhound"
    risk = "medium"
    description = "Cartographie les chemins d'attaque Active Directory (BloodHound CE)."
    examples = ("collecte les donnees active directory de corp.local",)
    parameters = (
        ParameterSpec("domain", "Domaine AD (--domain)", "string", required=True),
        ParameterSpec("username", "Utilisateur (--username)", "string"),
        ParameterSpec("password", "Mot de passe (--password)", "string"),
        ParameterSpec("collection", "Methode de collecte (-c)", "string"),
        ParameterSpec("output", "Dossier de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["bloodhound", "--domain", str(params["domain"])]
        if params.get("username"):
            argv += ["--username", str(params["username"])]
        if params.get("password"):
            argv += ["--password", str(params["password"])]
        if params.get("collection"):
            argv += ["-c", str(params["collection"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"domain": _domain(text)}
        user = re.search(r"utilisateur\s+([\w.\\-]+)", text, re.IGNORECASE)
        if user:
            params["username"] = user.group(1)
        if "session" in text.lower() or "sessions" in text.lower():
            params["collection"] = "Session"
        output = extract_any_path(text)
        if output:
            params["output"] = output
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"owned|admincount=1|domain admins", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Chemin vers un compte a privileges",
                    severity="high",
                    detail="BloodHound a trouve un chemin d'escalade vers un administrateur de domaine.",
                )
            )
        return AnalysisResult(
            summary="Collecte BloodHound (chemins d'attaque AD).",
            findings=findings,
            source="heuristic",
        )


class Dnscat2ServerTool(Tool):
    name = "dnscat2-server"
    binary = "dnscat2-server"
    risk = "high"
    description = "Serveur de tunnel C2 via DNS (dnscat2)."
    examples = ("lance le serveur dnscat2 sur le domaine tunnel.example.com",)
    parameters = (
        ParameterSpec("domain", "Domaine du tunnel", "string", required=True),
        ParameterSpec("secret", "Secret partage (--secret)", "string"),
        ParameterSpec("port", "Port d'ecoute (--dns port)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dnscat2-server"]
        if params.get("secret"):
            argv += ["--secret", str(params["secret"])]
        if params.get("port"):
            argv += ["--dns", f"port={params['port']}"]
        argv.append(str(params["domain"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"domain": _domain(text, "tunnel.example.com")}
        secret = re.search(r"secret\s+([\w-]+)", text, re.IGNORECASE)
        if secret:
            params["secret"] = secret.group(1)
        port = _port(text)
        if port:
            params["port"] = port
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"new session|session established|command session", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Session C2 etablie via DNS",
                    severity="critical",
                    detail="Un client a ouvert un canal de commande a travers le DNS.",
                )
            )
        return AnalysisResult(
            summary="Serveur C2 DNS dnscat2.",
            findings=findings,
            source="heuristic",
        )


class Dnscat2ClientTool(Tool):
    name = "dnscat2-client"
    binary = "dnscat2"
    risk = "high"
    description = "Client de tunnel C2 via DNS (dnscat2)."
    examples = ("connecte le client dnscat2 au domaine tunnel.example.com",)
    parameters = (
        ParameterSpec("domain", "Domaine du tunnel", "string", required=True),
        ParameterSpec("secret", "Secret partage (--secret)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["dnscat2"]
        if params.get("secret"):
            argv += ["--secret", str(params["secret"])]
        argv.append(str(params["domain"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"domain": _domain(text, "tunnel.example.com")}
        secret = re.search(r"secret\s+([\w-]+)", text, re.IGNORECASE)
        if secret:
            params["secret"] = secret.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"connected|session established", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Canal C2 DNS etabli",
                    severity="critical",
                    detail="La machine peut recevoir des commandes via DNS.",
                )
            )
        return AnalysisResult(
            summary="Client C2 DNS dnscat2.",
            findings=findings,
            source="heuristic",
        )


class VillainTool(Tool):
    name = "villain"
    binary = "villain"
    risk = "high"
    description = "Framework C2 haut niveau (sessions multiples, transferts)."
    examples = ("lance villain et ouvre une session c2",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (--port)", "string"),
        ParameterSpec("host", "Adresse d'ecoute", "string"),
        ParameterSpec("session", "Identifiant de session", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["villain"]
        if params.get("host"):
            argv += ["--host", str(params["host"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        port = _port(text, "4443")
        params["port"] = port
        if "0.0.0.0" in text:
            params["host"] = "0.0.0.0"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("host") == "0.0.0.0":
            findings.append(
                Finding(
                    title="Serveur C2 expose sur toutes les interfaces",
                    severity="high",
                    detail="Le framework C2 est joignable depuis tout le reseau.",
                )
            )
        if re.search(r"session|connected|implant", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Session C2 active",
                    severity="critical",
                    detail="Un implant est connecte au framework.",
                )
            )
        return AnalysisResult(
            summary="Framework C2 villain.",
            findings=findings,
            source="heuristic",
        )


class StarkillerTool(Tool):
    name = "starkiller"
    binary = "starkiller"
    risk = "medium"
    description = "Interface graphique/web pour PowerShell Empire (pilotage C2)."
    examples = ("lance starkiller sur le port 1337",)
    parameters = (
        ParameterSpec("port", "Port d'ecoute (--port)", "string"),
        ParameterSpec("host", "Adresse d'ecoute", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["starkiller"]
        if params.get("host"):
            argv += ["--host", str(params["host"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"port": _port(text, "1337")}
        if "0.0.0.0" in text:
            params["host"] = "0.0.0.0"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("host") == "0.0.0.0":
            findings.append(
                Finding(
                    title="Console C2 exposee publiquement",
                    severity="high",
                    detail="L'interface de pilotage ne doit pas etre joignable de l'exterieur.",
                )
            )
        return AnalysisResult(
            summary="Console Starkiller (pilotage PowerShell Empire).",
            findings=findings,
            source="heuristic",
        )


class Convoc2Tool(Tool):
    name = "convoc2"
    binary = "convoc2"
    risk = "high"
    description = "C2 utilisant Microsoft Teams comme canal de commande."
    examples = ("lance convoc2 avec un canal teams",)
    parameters = (
        ParameterSpec("tenant", "Identifiant du tenant Teams", "string"),
        ParameterSpec("channel", "Canal Teams", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["convoc2"]
        if params.get("tenant"):
            argv += ["--tenant", str(params["tenant"])]
        if params.get("channel"):
            argv += ["--channel", str(params["channel"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        tenant = re.search(r"tenant\s+([\w.-]+)", text, re.IGNORECASE)
        if tenant:
            params["tenant"] = tenant.group(1)
        channel = re.search(r"canal\s+([\w.-]+)", text, re.IGNORECASE)
        if channel:
            params["channel"] = channel.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="C2 via service cloud legitime",
                severity="high",
                detail="Le trafic se mele a Teams: tres difficile a detecter par filtrage reseau.",
            )
        ]
        return AnalysisResult(
            summary="C2 via Microsoft Teams (convoc2).",
            findings=findings,
            source="heuristic",
        )


class WindowsBinariesTool(Tool):
    name = "windows-binaries"
    binary = "windows-binaries"
    risk = "high"
    description = "Collection de binaires Windows utiles en post-exploitation (collection de fichiers)."
    examples = ("liste les binaires windows de post-exploitation",)
    parameters = (
        ParameterSpec("list", "Lister la collection", "bool", default=True),
        ParameterSpec("filter", "Filtre sur un nom", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["windows-binaries", "--list"]
        if params.get("filter"):
            argv += ["--filter", str(params["filter"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"list": True}
        match = re.search(r"(?:filtre|cherche)\s+([\w.-]+)", text, re.IGNORECASE)
        if match:
            params["filter"] = match.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        tools = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        if tools:
            findings.append(
                Finding(
                    title="Binaires de post-exploitation disponibles",
                    severity="medium",
                    detail=f"{len(tools)} binaire(s). Verifier la legitimite de leur usage.",
                )
            )
        return AnalysisResult(
            summary="Collection de binaires Windows (post-exploitation).",
            findings=findings,
            source="heuristic",
        )


# ---------------------------------------------------------------------------
# Backdoors systeme
# ---------------------------------------------------------------------------


class PowershellEmpireTool(Tool):
    name = "powershell-empire"
    aliases = ("empire",)
    binary = "powershell-empire"
    risk = "high"
    description = "Framework d'agents post-exploitation PowerShell et Python."
    examples = ("lance le serveur powershell-empire",)
    parameters = (
        ParameterSpec("server", "Demarrer le serveur (server)", "bool", default=True),
        ParameterSpec("port", "Port d'ecoute (--port)", "string"),
        ParameterSpec("host", "Adresse d'ecoute (--host)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["powershell-empire", "server"]
        if params.get("host"):
            argv += ["--host", str(params["host"])]
        if params.get("port"):
            argv += ["--port", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"server": True}
        port = _port(text)
        if port:
            params["port"] = port
        if "0.0.0.0" in text:
            params["host"] = "0.0.0.0"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("host") == "0.0.0.0":
            findings.append(
                Finding(
                    title="Serveur C2 Empire expose publiquement",
                    severity="high",
                    detail="Le serveur d'agents est joignable depuis tout le reseau.",
                )
            )
        if re.search(r"agent|stager|listener", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Listener ou agent Empire actif",
                    severity="critical",
                    detail="Un canal de post-exploitation est en place.",
                )
            )
        return AnalysisResult(
            summary="Serveur PowerShell Empire.",
            findings=findings,
            source="heuristic",
        )


class PwncatTool(Tool):
    name = "pwncat"
    binary = "pwncat"
    risk = "high"
    description = "Netcat ameliore: shell a distance, televersement et automatisation."
    examples = ("ecoute sur le port 4444 avec pwncat", "connecte pwncat a 10.0.0.5:4444")
    parameters = (
        ParameterSpec("listen", "Mode ecoute (-l)", "bool", default=False),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("host", "Hote a joindre", "string"),
        ParameterSpec("upload", "Fichier a televerser", "string"),
        ParameterSpec("exec", "Commande a executer (-e)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["pwncat"]
        if params.get("listen"):
            argv.append("-l")
            if params.get("port"):
                argv += ["-p", str(params["port"])]
            if params.get("exec"):
                argv += ["-e", str(params["exec"])]
            return argv
        if params.get("host"):
            argv.append(str(params["host"]))
            if params.get("port"):
                argv.append(str(params["port"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "ecoute" in low or "listen" in low or "-l" in low:
            params["listen"] = True
        port = _port(text, "4444")
        params["port"] = port
        if not params.get("listen"):
            params["host"] = _host(text)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("listen"):
            findings.append(
                Finding(
                    title="Ecoute d'un shell a distance",
                    severity="high",
                    detail="Une connexion entrante donnera un acces interactif a la machine.",
                )
            )
        return AnalysisResult(
            summary="Shell a distance via pwncat.",
            findings=findings,
            source="heuristic",
        )


class CryptcatTool(Tool):
    name = "cryptcat"
    binary = "cryptcat"
    risk = "high"
    description = "Netcat avec chiffrement Twofish (canal de commande discret)."
    examples = ("ecoute chiffree sur le port 4444 avec cryptcat",)
    parameters = (
        ParameterSpec("listen", "Mode ecoute (-l)", "bool", default=False),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("host", "Hote a joindre", "string"),
        ParameterSpec("exec", "Commande a executer (-e)", "string"),
        ParameterSpec("key", "Cle partagee (-k)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["cryptcat"]
        if params.get("key"):
            argv += ["-k", str(params["key"])]
        if params.get("listen"):
            argv += ["-l", "-p", str(params.get("port") or "4444")]
            if params.get("exec"):
                argv += ["-e", str(params["exec"])]
            return argv
        argv.append(str(params.get("host") or "127.0.0.1"))
        argv.append(str(params.get("port") or "4444"))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "ecoute" in low or "listen" in low or "-l" in low:
            params["listen"] = True
        params["port"] = _port(text, "4444")
        if not params.get("listen"):
            params["host"] = _host(text)
        key = re.search(r"cle\s+([\w-]+)", text, re.IGNORECASE)
        if key:
            params["key"] = key.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("listen"):
            findings.append(
                Finding(
                    title="Canal de commande chiffre en ecoute",
                    severity="high",
                    detail="Le trafic chiffre contrarie la detection par inspection.",
                )
            )
        return AnalysisResult(
            summary="Canal netcat chiffre (cryptcat).",
            findings=findings,
            source="heuristic",
        )


class SbdTool(Tool):
    name = "sbd"
    binary = "sbd"
    risk = "high"
    description = "Backdoor securisee (netcat) portable Linux et Windows."
    examples = ("lance une backdoor sbd en ecoute sur le port 4444",)
    parameters = (
        ParameterSpec("listen", "Mode ecoute (-l)", "bool", default=False),
        ParameterSpec("port", "Port (-p)", "string"),
        ParameterSpec("host", "Hote a joindre", "string"),
        ParameterSpec("exec", "Commande a executer (-e)", "string"),
        ParameterSpec("key", "Cle partagee (-k)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["sbd"]
        if params.get("key"):
            argv += ["-k", str(params["key"])]
        if params.get("listen"):
            argv += ["-l", "-p", str(params.get("port") or "4444")]
            if params.get("exec"):
                argv += ["-e", str(params["exec"])]
            return argv
        argv.append(str(params.get("host") or "127.0.0.1"))
        argv.append(str(params.get("port") or "4444"))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "ecoute" in low or "listen" in low or "-l" in low:
            params["listen"] = True
        params["port"] = _port(text, "4444")
        if not params.get("listen"):
            params["host"] = _host(text)
        key = re.search(r"cle\s+([\w-]+)", text, re.IGNORECASE)
        if key:
            params["key"] = key.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("listen"):
            findings.append(
                Finding(
                    title="Backdoor en ecoute",
                    severity="high",
                    detail="Un acces interactif sera ouvert a toute connexion.",
                )
            )
        return AnalysisResult(
            summary="Backdoor sbd.",
            findings=findings,
            source="heuristic",
        )


class SliverTool(Tool):
    name = "sliver"
    binary = "sliver"
    risk = "high"
    description = "Framework d'implants (Sliver) pour l'acces persistant."
    examples = ("lance le serveur sliver et genere un implant",)
    parameters = (
        ParameterSpec("action", "Action: server, client, generate", "string", default="server"),
        ParameterSpec("mtls", "Listener mTLS", "bool", default=False),
        ParameterSpec("host", "Adresse d'ecoute (-l)", "string"),
        ParameterSpec("port", "Port (-p)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        action = str(params.get("action") or "server")
        argv = ["sliver", action]
        if params.get("host"):
            argv += ["-l", str(params["host"])]
        if params.get("port"):
            argv += ["-p", str(params["port"])]
        if params.get("mtls"):
            argv += ["--mtls", str(params.get("port") or "8888")]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        if "implant" in low or "genere" in low:
            params["action"] = "generate"
        elif "client" in low:
            params["action"] = "client"
        else:
            params["action"] = "server"
        port = _port(text)
        if port:
            params["port"] = port
        if "mtls" in low:
            params["mtls"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"session|implant|beacon", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Implant Sliver actif",
                    severity="critical",
                    detail="Un implant est connecte: acces persistant a la cible.",
                )
            )
        return AnalysisResult(
            summary="Framework d'implants Sliver.",
            findings=findings,
            source="heuristic",
        )


# ---------------------------------------------------------------------------
# Backdoors web
# ---------------------------------------------------------------------------


class WeevelyTool(Tool):
    name = "weevely"
    binary = "weevely"
    risk = "high"
    description = "Genere et pilote un webshell PHP furtif."
    examples = ("genere un webshell avec weevely et la cle secret", "connecte weevely a http://cible/shell.php")
    parameters = (
        ParameterSpec("action", "Action: generate, session", "string", default="generate"),
        ParameterSpec("target", "URL du webshell (session)", "string"),
        ParameterSpec("password", "Mot de passe du shell", "string"),
        ParameterSpec("output", "Fichier de sortie (generate)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        action = str(params.get("action") or "generate")
        if action == "session":
            argv = ["weevely", str(params.get("target") or "")]
            if params.get("password"):
                argv.append(str(params["password"]))
            return argv
        argv = ["weevely", "generate"]
        if params.get("password"):
            argv.append(str(params["password"]))
        if params.get("output"):
            argv.append(str(params["output"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        url = _URL_RE.search(text)
        if url:
            params["action"] = "session"
            params["target"] = url.group(0).rstrip(".,;)")
        else:
            params["action"] = "generate"
        pwd = re.search(r"(?:cle|mot de passe|password)\s+([\w.-]+)", text, re.IGNORECASE)
        if pwd:
            params["password"] = pwd.group(1)
        output = extract_any_path(text)
        if output:
            params["output"] = output
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("action") == "session":
            findings.append(
                Finding(
                    title="Session webshell ouverte",
                    severity="critical",
                    detail="Un acces interactif au serveur web est en place.",
                )
            )
        elif re.search(r"generated|saved", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Webshell genere",
                    severity="high",
                    detail="Le fichier doit etre supprime apres le test.",
                )
            )
        return AnalysisResult(
            summary="Webshell PHP (weevely).",
            findings=findings,
            source="heuristic",
        )


class WebacooTool(Tool):
    name = "webacoo"
    binary = "webacoo"
    risk = "high"
    description = "Kit de webshell furtif communiquant par cookie."
    examples = ("genere un webshell webacoo", "connecte webacoo a http://cible/shell.php")
    parameters = (
        ParameterSpec("generate", "Generer un shell (-g)", "bool", default=False),
        ParameterSpec("target", "URL du webshell (-t)", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["webacoo"]
        if params.get("generate"):
            argv.append("-g")
            if params.get("output"):
                argv += ["-o", str(params["output"])]
            return argv
        if params.get("target"):
            argv += ["-t", str(params["target"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        url = _URL_RE.search(text)
        if url:
            params["target"] = url.group(0).rstrip(".,;)")
        if "genere" in low or "generer" in low or " -g" in low:
            params["generate"] = True
            output = extract_any_path(text)
            if output:
                params["output"] = output
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if params.get("target"):
            findings.append(
                Finding(
                    title="Session webshell (cookie) ouverte",
                    severity="critical",
                    detail="Un acces interactif au serveur web est en place.",
                )
            )
        return AnalysisResult(
            summary="Webshell furtif webacoo.",
            findings=findings,
            source="heuristic",
        )


class LaudanumTool(Tool):
    name = "laudanum"
    binary = "laudanum"
    risk = "high"
    description = "Collection de fichiers web injectables (webshells multi-langages)."
    examples = ("liste les webshells laudanum disponibles",)
    parameters = (
        ParameterSpec("list", "Lister la collection (--list)", "bool", default=True),
        ParameterSpec("language", "Filtrer par langage", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["laudanum", "--list"]
        if params.get("language"):
            argv += ["--language", str(params["language"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"list": True}
        for lang in ("php", "asp", "aspx", "jsp", "cfm"):
            if lang in low:
                params["language"] = lang
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        shells = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        if shells:
            findings.append(
                Finding(
                    title="Webshells disponibles",
                    severity="high",
                    detail=f"{len(shells)} fichier(s). Ne les deployer que sur un perimetre autorise.",
                )
            )
        return AnalysisResult(
            summary="Collection de webshells Laudanum.",
            findings=findings,
            source="heuristic",
        )


class NishangTool(Tool):
    name = "nishang"
    binary = "nishang"
    risk = "high"
    description = "Collection de scripts PowerShell (post-exploitation, exfiltration)."
    examples = ("liste les scripts nishang",)
    parameters = (
        ParameterSpec("list", "Lister les scripts (--list)", "bool", default=True),
        ParameterSpec("category", "Filtrer par categorie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["nishang", "--list"]
        if params.get("category"):
            argv += ["--category", str(params["category"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"list": True}
        for cat in ("recon", "exfiltration", "backdoor", "pivot", "privesc"):
            if cat in low:
                params["category"] = cat
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        scripts = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        if scripts:
            findings.append(
                Finding(
                    title="Scripts PowerShell de post-exploitation disponibles",
                    severity="high",
                    detail=f"{len(scripts)} script(s) (exfiltration, backdoor, pivot).",
                )
            )
        return AnalysisResult(
            summary="Collection de scripts Nishang.",
            findings=findings,
            source="heuristic",
        )


class WebshellsTool(Tool):
    name = "webshells"
    binary = "webshells"
    risk = "high"
    description = "Collection de webshells (PHP, ASP, JSP, Perl...)."
    examples = ("liste les webshells de la collection",)
    parameters = (
        ParameterSpec("list", "Lister la collection (--list)", "bool", default=True),
        ParameterSpec("language", "Filtrer par langage", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["webshells", "--list"]
        if params.get("language"):
            argv += ["--language", str(params["language"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"list": True}
        for lang in ("php", "asp", "aspx", "jsp", "perl", "python"):
            if lang in low:
                params["language"] = lang
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        shells = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        if shells:
            findings.append(
                Finding(
                    title="Webshells disponibles",
                    severity="high",
                    detail=f"{len(shells)} fichier(s) dans la collection.",
                )
            )
        return AnalysisResult(
            summary="Collection de webshells.",
            findings=findings,
            source="heuristic",
        )


class HtshellsTool(Tool):
    name = "htshells"
    binary = "htshells"
    risk = "high"
    description = "Fichiers .htaccess offensifs (execution, contournement)."
    examples = ("liste les htaccess offensifs disponibles",)
    parameters = (
        ParameterSpec("list", "Lister les fichiers (--list)", "bool", default=True),
        ParameterSpec("type", "Type: upload, exec, bypass", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["htshells", "--list"]
        if params.get("type"):
            argv += ["--type", str(params["type"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"list": True}
        for kind in ("upload", "exec", "bypass"):
            if kind in low:
                params["type"] = kind
                break
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if stdout.strip():
            findings.append(
                Finding(
                    title="Fichiers .htaccess offensifs disponibles",
                    severity="high",
                    detail="Permettent l'execution de code ou le contournement de restrictions.",
                )
            )
        return AnalysisResult(
            summary="Collection de .htaccess offensifs (htshells).",
            findings=findings,
            source="heuristic",
        )


# ---------------------------------------------------------------------------
# Tunnellisation et exfiltration
# ---------------------------------------------------------------------------


class IodineTool(Tool):
    name = "iodine"
    binary = "iodine"
    risk = "high"
    description = "Tunnel IPv4 a travers un serveur DNS (iodine)."
    examples = ("ouvre un tunnel iodine vers tunnel.example.com",)
    parameters = (
        ParameterSpec("mode", "Mode: client (-c) ou serveur (-s)", "string", default="client"),
        ParameterSpec("domain", "Domaine du tunnel", "string", required=True),
        ParameterSpec("password", "Mot de passe (-P)", "string"),
        ParameterSpec("interface", "Interface du tunnel (-d)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = "-s" if params.get("mode") == "server" else "-c"
        argv = ["iodine"]
        if params.get("password"):
            argv += ["-P", str(params["password"])]
        if params.get("interface"):
            argv += ["-d", str(params["interface"])]
        argv += [mode, str(params["domain"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {"domain": _domain(text, "tunnel.example.com")}
        params["mode"] = "server" if "serveur" in low or "server" in low else "client"
        pwd = re.search(r"mot de passe\s+([\w-]+)", text, re.IGNORECASE)
        if pwd:
            params["password"] = pwd.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"Connection setup complete|tunnel established|opened", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel DNS etabli",
                    severity="high",
                    detail="Le trafic IPv4 est encapsule dans le DNS: contourne les filtres classiques.",
                )
            )
        return AnalysisResult(
            summary="Tunnel IPv4 via DNS (iodine).",
            findings=findings,
            source="heuristic",
        )


class Dns2tcpTool(Tool):
    name = "dns2tcp"
    binary = "dns2tcp"
    risk = "high"
    description = "Tunnel TCP a travers DNS (client et serveur dns2tcp)."
    examples = ("lance le serveur dns2tcp sur le domaine tunnel.example.com",)
    parameters = (
        ParameterSpec("mode", "Mode: client (-c) ou serveur (-s)", "string", default="server"),
        ParameterSpec("config", "Fichier de configuration (-z)", "string"),
        ParameterSpec("domain", "Domaine du tunnel (-d)", "string"),
        ParameterSpec("resource", "Ressource a relayer (-r)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = "-s" if params.get("mode") == "server" else "-c"
        argv = ["dns2tcp", mode]
        if params.get("config"):
            argv += ["-z", str(params["config"])]
        if params.get("domain"):
            argv += ["-d", str(params["domain"])]
        if params.get("resource"):
            argv += ["-r", str(params["resource"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        params["mode"] = "client" if "client" in low else "server"
        path = extract_any_path(text)
        if path:
            params["config"] = path
        if "tunnel" in low or "domaine" in low:
            params["domain"] = _domain(text, "tunnel.example.com")
        resource = re.search(r"ressource\s+([\w.-]+)", text, re.IGNORECASE)
        if resource:
            params["resource"] = resource.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"connected|session|listening", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel DNS dns2tcp actif",
                    severity="high",
                    detail="Canal de relais TCP via DNS (exfiltration possible).",
                )
            )
        return AnalysisResult(
            summary="Tunnel TCP via DNS (dns2tcp).",
            findings=findings,
            source="heuristic",
        )


class GodohTool(Tool):
    name = "godoh"
    binary = "godoh"
    risk = "high"
    description = "C2 via DNS-over-HTTPS (DoH)."
    examples = ("lance godoh en serveur c2 doh",)
    parameters = (
        ParameterSpec("mode", "Mode: server, agent", "string", default="server"),
        ParameterSpec("domain", "Domaine DoH", "string"),
        ParameterSpec("key", "Cle de chiffrement", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["godoh", str(params.get("mode") or "server")]
        if params.get("domain"):
            argv += ["--domain", str(params["domain"])]
        if params.get("key"):
            argv += ["--key", str(params["key"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        params["mode"] = "agent" if "agent" in low else "server"
        if "doh" in low or "domaine" in low:
            params["domain"] = _domain(text, "doh.example.com")
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="C2 via DNS-over-HTTPS",
                severity="high",
                detail="Le trafic chiffre se mele au HTTPS legitime: detection difficile.",
            )
        ]
        return AnalysisResult(
            summary="C2 via DoH (godoh).",
            findings=findings,
            source="heuristic",
        )


class MiredoTool(Tool):
    name = "miredo"
    binary = "miredo"
    risk = "medium"
    description = "Tunnellisation IPv6 (Teredo) a travers NAT."
    examples = ("lance miredo pour un tunnel teredo",)
    parameters = (
        ParameterSpec("interface", "Interface Teredo (-i)", "string"),
        ParameterSpec("server", "Serveur Teredo (-s)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["miredo"]
        if params.get("interface"):
            argv += ["-i", str(params["interface"])]
        if params.get("server"):
            argv += ["-s", str(params["server"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        iface = _IFACE_RE.search(text)
        if iface:
            params["interface"] = iface.group(1)
        hosts = extract_hosts(text)
        if hosts:
            params["server"] = hosts[0]
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"teredo|tunnel", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel Teredo actif",
                    severity="medium",
                    detail="IPv6 encapsule dans UDP: peut contourner des regles IPv4.",
                )
            )
        return AnalysisResult(
            summary="Tunnel IPv6 Teredo (miredo).",
            findings=findings,
            source="heuristic",
        )


class ProxychainsTool(Tool):
    name = "proxychains"
    aliases = ()
    binary = "proxychains4"
    risk = "medium"
    description = "Redirige les connexions d'une commande via des proxys SOCKS/HTTP."
    examples = ("lance nmap via proxychains sur 10.0.0.5",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-f)", "string"),
        ParameterSpec("command", "Commande a executer via les proxys", "string", required=True),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["proxychains4"]
        if params.get("quiet"):
            argv.append("-q")
        if params.get("config"):
            argv += ["-f", str(params["config"])]
        argv += str(params["command"]).split()
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        config = extract_any_path(text)
        if config:
            params["config"] = config
        if "silencieux" in text.lower() or "quiet" in text.lower():
            params["quiet"] = True
        cmd = re.search(r"lance\s+(.+?)\s+via proxychains\b", text, re.IGNORECASE)
        if cmd:
            params["command"] = cmd.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"proxy|chain", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Trafic redirige via des proxys",
                    severity="info",
                    detail="L'origine reelle des connexions est masquee.",
                )
            )
        return AnalysisResult(
            summary="Redirection de connexions via proxychains.",
            findings=findings,
            source="heuristic",
        )


class Proxychains4Tool(Tool):
    name = "proxychains4"
    binary = "proxychains4"
    risk = "medium"
    description = "Redirection de connexions via proxys SOCKS/HTTP (proxychains-ng)."
    examples = ("lance hydra via proxychains4 sur 10.0.0.5",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration (-f)", "string"),
        ParameterSpec("command", "Commande a executer via les proxys", "string", required=True),
        ParameterSpec("quiet", "Mode silencieux (-q)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["proxychains4"]
        if params.get("quiet"):
            argv.append("-q")
        if params.get("config"):
            argv += ["-f", str(params["config"])]
        argv += str(params["command"]).split()
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        config = extract_any_path(text)
        if config:
            params["config"] = config
        if "silencieux" in text.lower() or "quiet" in text.lower():
            params["quiet"] = True
        cmd = re.search(r"lance\s+(.+?)\s+via proxychains4\b", text, re.IGNORECASE)
        if cmd:
            params["command"] = cmd.group(1).strip()
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"proxy|chain", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Trafic redirige via des proxys",
                    severity="info",
                    detail="L'origine reelle des connexions est masquee.",
                )
            )
        return AnalysisResult(
            summary="Redirection de connexions via proxychains4.",
            findings=findings,
            source="heuristic",
        )


class ProxytunnelTool(Tool):
    name = "proxytunnel"
    binary = "proxytunnel"
    risk = "medium"
    description = "Fait passer SSH (et autres protocoles) a travers un proxy HTTP(S)."
    examples = ("ouvre un tunnel ssh via le proxy http://proxy:8080 vers 10.0.0.5:22",)
    parameters = (
        ParameterSpec("proxy", "URL du proxy (-p)", "string", required=True),
        ParameterSpec("destination", "Hote:port cible (-d)", "string", required=True),
        ParameterSpec("user", "Utilisateur du proxy (-P)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["proxytunnel", "-p", str(params["proxy"])]
        if params.get("user"):
            argv += ["-P", str(params["user"])]
        argv += ["-d", str(params["destination"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        urls = _URL_RE.findall(text)
        if urls:
            params["proxy"] = urls[0].rstrip(".,;)")
        dest = re.search(r"vers\s+([\w.\-]+:\d+)", text, re.IGNORECASE)
        if dest:
            params["destination"] = dest.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"connected|tunnel", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel via proxy HTTP(S) etabli",
                    severity="medium",
                    detail="Le protocole interne (SSH) passe pour du trafic HTTP.",
                )
            )
        return AnalysisResult(
            summary="Tunnel via proxy HTTP(S) (proxytunnel).",
            findings=findings,
            source="heuristic",
        )


class PtunnelTool(Tool):
    name = "ptunnel"
    binary = "ptunnel"
    risk = "high"
    description = "Tunnel TCP encapsule dans des paquets ICMP (ping)."
    examples = ("ouvre un tunnel ptunnel via 10.0.0.5 vers 10.0.0.9:22",)
    parameters = (
        ParameterSpec("mode", "Mode: client (-p) ou proxy (-x)", "string", default="client"),
        ParameterSpec("host", "Hote du tunnel (-p)", "string"),
        ParameterSpec("destination", "Hote:port cible (-l)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = str(params.get("mode") or "client")
        argv = ["ptunnel"]
        if mode == "proxy":
            argv.append("-x")
            return argv
        if params.get("host"):
            argv += ["-p", str(params["host"])]
        if params.get("destination"):
            argv += ["-l", str(params["destination"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        params["mode"] = "proxy" if "proxy" in low else "client"
        hosts = extract_hosts(text)
        if hosts:
            params["host"] = hosts[0]
        dest = re.search(r"vers\s+([\w.\-]+:\d+)", text, re.IGNORECASE)
        if dest:
            params["destination"] = dest.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"tunnel|icmp", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel ICMP etabli",
                    severity="high",
                    detail="Le trafic TCP se cache dans des paquets ping: peu de filtres l'arretent.",
                )
            )
        return AnalysisResult(
            summary="Tunnel TCP via ICMP (ptunnel).",
            findings=findings,
            source="heuristic",
        )


class PwnatTool(Tool):
    name = "pwnat"
    binary = "pwnat"
    risk = "high"
    description = "Communication directe entre deux machines derriere NAT (sans serveur)."
    examples = ("lance pwnat en serveur sur le port 8000",)
    parameters = (
        ParameterSpec("mode", "Mode: server (-s) ou client (-c)", "string", default="server"),
        ParameterSpec("port", "Port local (-p)", "string"),
        ParameterSpec("host", "Hote distant (client)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        mode = str(params.get("mode") or "server")
        argv = ["pwnat"]
        if mode == "server":
            argv += ["-s", "-p", str(params.get("port") or "8000")]
            return argv
        if params.get("host"):
            argv += ["-c", str(params["host"])]
        if params.get("port"):
            argv += ["-p", str(params["port"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        params["mode"] = "client" if "client" in low else "server"
        params["port"] = _port(text, "8000")
        if params["mode"] == "client":
            hosts = extract_hosts(text)
            if hosts:
                params["host"] = hosts[0]
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"connected|tunnel|session", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel NAT-a-NAT etabli",
                    severity="high",
                    detail="Contourne le NAT sans serveur intermediaire.",
                )
            )
        return AnalysisResult(
            summary="Tunnel NAT-a-NAT (pwnat).",
            findings=findings,
            source="heuristic",
        )


class SocatTool(Tool):
    name = "socat"
    binary = "socat"
    risk = "medium"
    description = "Relais bidirectionnel generique (tunnels, shells, redirections)."
    examples = ("relaye tcp-listen:4444 vers tcp:10.0.0.5:22 avec socat",)
    parameters = (
        ParameterSpec("source", "Adresse source (ex: tcp-listen:4444)", "string", required=True),
        ParameterSpec("target", "Adresse cible (ex: tcp:10.0.0.5:22)", "string", required=True),
        ParameterSpec("verbose", "Verbeux (-v)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["socat"]
        if params.get("verbose"):
            argv.append("-v")
        argv += [str(params["source"]), str(params["target"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        src = re.search(r"(tcp-listen:\d+|udp-listen:\d+|tcp4-listen:\d+)", text, re.IGNORECASE)
        if src:
            params["source"] = src.group(1)
        dst = re.search(r"(tcp:[\w.\-]+:\d+|tcp4:[\w.\-]+:\d+|udp:[\w.\-]+:\d+)", text, re.IGNORECASE)
        if dst:
            params["target"] = dst.group(1)
        if "verbeux" in text.lower() or "verbose" in text.lower():
            params["verbose"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"listening|accepted|connected", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Relais socat actif",
                    severity="medium",
                    detail="Peut exposer un service interne ou pivoter vers un autre reseau.",
                )
            )
        return AnalysisResult(
            summary="Relais bidirectionnel socat.",
            findings=findings,
            source="heuristic",
        )


class StunnelTool(Tool):
    name = "stunnel4"
    aliases = ("stunnel",)
    binary = "stunnel4"
    risk = "medium"
    description = "Encapsule un service dans TLS (chiffrement de canal)."
    examples = ("lance stunnel4 avec la configuration stunnel.conf",)
    parameters = (
        ParameterSpec("config", "Fichier de configuration", "string", required=True),
        ParameterSpec("foreground", "Premier plan (-f)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["stunnel4"]
        if params.get("foreground"):
            argv.append("-f")
        argv.append(str(params["config"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        path = extract_any_path(text)
        if not path:
            conf = _CONF_RE.search(text)
            if conf:
                path = conf.group(1)
        if path:
            params["config"] = path
        if "premier plan" in text.lower() or "foreground" in text.lower() or "-f" in text:
            params["foreground"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"Configuration successful|listening", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel TLS actif",
                    severity="medium",
                    detail="Le trafic est chiffre: l'inspection passive ne le voit plus.",
                )
            )
        return AnalysisResult(
            summary="Encapsulation TLS (stunnel).",
            findings=findings,
            source="heuristic",
        )


class UdptunnelTool(Tool):
    name = "udptunnel"
    binary = "udptunnel"
    risk = "high"
    description = "Encapsule des paquets UDP dans une connexion TCP."
    examples = ("tunnel udp de 10.0.0.5:53 vers 10.0.0.9:53 avec udptunnel",)
    parameters = (
        ParameterSpec("listen", "Port TCP d'ecoute (-l)", "string"),
        ParameterSpec("destination", "Hote:port UDP cible (-r)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["udptunnel"]
        if params.get("listen"):
            argv += ["-l", str(params["listen"])]
        if params.get("destination"):
            argv += ["-r", str(params["destination"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        port = _port(text)
        if port:
            params["listen"] = port
        dest = re.search(r"([\w.\-]+:\d+)", text)
        if dest:
            params["destination"] = dest.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        if re.search(r"tunnel|listening|connected", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Tunnel UDP-sur-TCP actif",
                    severity="high",
                    detail="Le trafic UDP (ex: DNS) est encapsule dans TCP pour traverser les filtres.",
                )
            )
        return AnalysisResult(
            summary="Tunnel UDP dans TCP (udptunnel).",
            findings=findings,
            source="heuristic",
        )


# ---------------------------------------------------------------------------
# Evasion antivirus / obfuscation de charge
# ---------------------------------------------------------------------------


class ShellterTool(Tool):
    name = "shellter"
    binary = "shellter"
    risk = "high"
    description = "Injecte dynamiquement du shellcode dans un executable PE (evasion AV)."
    examples = ("injecte un shellcode dans app.exe avec shellter",)
    parameters = (
        ParameterSpec("mode", "Mode: auto (-a) ou manuel", "string", default="auto"),
        ParameterSpec("binary", "Executable PE cible (-f)", "string", required=True),
        ParameterSpec("payload", "Payload (-p)", "string"),
        ParameterSpec("lhost", "Hote d'ecoute (LHOST)", "string"),
        ParameterSpec("lport", "Port d'ecoute (LPORT)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["shellter"]
        if params.get("mode") == "auto":
            argv.append("-a")
        argv += ["-f", str(params["binary"])]
        if params.get("payload"):
            argv += ["-p", str(params["payload"])]
        if params.get("lhost"):
            argv += ["--lhost", str(params["lhost"])]
        if params.get("lport"):
            argv += ["--lport", str(params["lport"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"mode": "auto"}
        binary = re.search(r"([\w./-]+\.exe)", text, re.IGNORECASE)
        if binary:
            params["binary"] = binary.group(1)
        lhost = _lhost(text)
        if lhost:
            params["lhost"] = lhost
        port = _port(text)
        if port:
            params["lport"] = port
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Charge injectee dans un executable (evasion AV)",
                severity="high",
                detail="Un binaire infecte peut executer du code arbitraire sur la cible.",
            )
        ]
        return AnalysisResult(
            summary="Injection de shellcode PE (shellter).",
            findings=findings,
            source="heuristic",
        )


class VeilTool(Tool):
    name = "veil-evasion"
    aliases = ("veil",)
    binary = "veil-evasion"
    risk = "high"
    description = "Genere des charges evasives (veil-evasion)."
    examples = ("lance veil-evasion et genere une charge",)
    parameters = (
        ParameterSpec("payload", "Charge a generer", "string"),
        ParameterSpec("lhost", "Hote d'ecoute (LHOST)", "string"),
        ParameterSpec("lport", "Port d'ecoute (LPORT)", "string"),
        ParameterSpec("output", "Fichier de sortie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["veil-evasion"]
        if params.get("payload"):
            argv += ["--payload", str(params["payload"])]
        if params.get("lhost"):
            argv += ["--lhost", str(params["lhost"])]
        if params.get("lport"):
            argv += ["--lport", str(params["lport"])]
        if params.get("output"):
            argv += ["--output", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        lhost = _lhost(text)
        if lhost:
            params["lhost"] = lhost
        port = _port(text)
        if port:
            params["lport"] = port
        output = extract_any_path(text)
        if output:
            params["output"] = output
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Charge evasive generee",
                severity="high",
                detail="La charge vise a contourner les antivirus: usage strictement autorise.",
            )
        ]
        return AnalysisResult(
            summary="Generation de charge evasive (veil-evasion).",
            findings=findings,
            source="heuristic",
        )


class HyperionTool(Tool):
    name = "hyperion"
    binary = "hyperion"
    risk = "high"
    description = "Chiffreur d'executables 32 bits (evasion par chiffrement runtime)."
    examples = ("chiffre app.exe avec hyperion",)
    parameters = (
        ParameterSpec("binary", "Executable 32 bits a chiffrer", "string", required=True),
        ParameterSpec("output", "Fichier de sortie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hyperion", str(params["binary"])]
        if params.get("output"):
            argv.append(str(params["output"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        binary = re.search(r"([\w./-]+\.exe)", text, re.IGNORECASE)
        if binary:
            params["binary"] = binary.group(1)
        output = re.search(r"vers\s+([\w./-]+\.exe)", text, re.IGNORECASE)
        if output:
            params["output"] = output.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Executable chiffre (evasion)",
                severity="high",
                detail="Le code est dechiffre en memoire au runtime: complique l'analyse statique.",
            )
        ]
        return AnalysisResult(
            summary="Chiffrement d'executable (hyperion).",
            findings=findings,
            source="heuristic",
        )


class Exe2hexbatTool(Tool):
    name = "exe2hexbat"
    binary = "exe2hexbat"
    risk = "high"
    description = "Convertit un executable en script hex/batch (contournement de filtres)."
    examples = ("convertit app.exe en bat avec exe2hexbat",)
    parameters = (
        ParameterSpec("binary", "Executable a convertir", "string", required=True),
        ParameterSpec("output", "Fichier de sortie", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["exe2hexbat", "-x", str(params["binary"])]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        binary = re.search(r"([\w./-]+\.exe)", text, re.IGNORECASE)
        if binary:
            params["binary"] = binary.group(1)
        output = re.search(r"vers\s+([\w./-]+\.(?:bat|txt|hex))", text, re.IGNORECASE)
        if output:
            params["output"] = output.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = [
            Finding(
                title="Executable converti en script",
                severity="high",
                detail="Le format script peut contourner les filtres de pieces jointes.",
            )
        ]
        return AnalysisResult(
            summary="Conversion executable -> script (exe2hexbat).",
            findings=findings,
            source="heuristic",
        )


register(BloodhoundTool())
register(Dnscat2ServerTool())
register(Dnscat2ClientTool())
register(VillainTool())
register(StarkillerTool())
register(Convoc2Tool())
register(WindowsBinariesTool())
register(PowershellEmpireTool())
register(PwncatTool())
register(CryptcatTool())
register(SbdTool())
register(SliverTool())
register(WeevelyTool())
register(WebacooTool())
register(LaudanumTool())
register(NishangTool())
register(WebshellsTool())
register(HtshellsTool())
register(IodineTool())
register(Dns2tcpTool())
register(GodohTool())
register(MiredoTool())
register(ProxychainsTool())
register(Proxychains4Tool())
register(ProxytunnelTool())
register(PtunnelTool())
register(PwnatTool())
register(SocatTool())
register(StunnelTool())
register(UdptunnelTool())
register(ShellterTool())
register(VeilTool())
register(HyperionTool())
register(Exe2hexbatTool())
