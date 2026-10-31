"""Outils d'attaque de mots de passe (classe `05-password-attacks`).

Couvre l'identification de hash, les attaques en ligne (hydra, medusa, ncrack,
patator), les attaques hors ligne (hashcat, john, ophcrack), la generation de
listes de mots (crunch, cewl, rsmangler) et l'extraction locale (samdump2,
chntpw). Chaque outil est un plugin `Tool` (argv sans shell, risque declare).
"""

from __future__ import annotations

import re
from typing import Any

from ..core.models import AnalysisResult, Finding, ParameterSpec
from ..core.registry import register
from .base import Tool, extract_hosts


def _extract_host(text: str) -> str:
    hosts = extract_hosts(text)
    return hosts[0] if hosts else ""


def _extract_port(text: str) -> int | None:
    match = re.search(r"\bport\s+(\d+)", text.lower())
    return int(match.group(1)) if match else None


class HashIdentifierTool(Tool):
    name = "hash-identifier"
    binary = "hash-identifier"
    aliases = ("hashid",)
    risk = "low"
    description = "Identification du type de hash (MD5, SHA, bcrypt, NTLM...)."
    examples = ("identifie le type du hash 5f4dcc3b5aa765d61d8327deb882cf99",)
    parameters = (ParameterSpec("hash", "Hash a identifier", "string", required=True),)

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["hash-identifier", str(params["hash"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        match = re.search(r"\b([a-fA-F0-9]{16,128}|\$2[aby]\$[^\s]+)\b", text)
        return {"hash": match.group(1)} if match else {}

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"Possible Hashs?:?\s*(.+)", stdout, re.IGNORECASE):
            findings.append(Finding(title=f"Hash probable: {match.group(1).strip()[:120]}", severity="info"))
        return AnalysisResult(summary=f"{len(findings)} type(s) probable(s).", findings=findings, source="heuristic")


class HydraTool(Tool):
    name = "hydra"
    binary = "hydra"
    risk = "critical"
    description = "Attaque par force brute / dictionnaire en ligne (nombreux protocoles)."
    examples = (
        "attaque par dictionnaire ssh sur 10.0.0.5 avec l'utilisateur root",
        "bruteforce le formulaire http de example.com",
    )
    parameters = (
        ParameterSpec("target", "Hote cible", "string", required=True),
        ParameterSpec("service", "Service/protocole: ssh, ftp, http-get, rdp, smb...", "string", required=True),
        ParameterSpec("username", "Utilisateur unique (-l)", "string"),
        ParameterSpec("userlist", "Liste d'utilisateurs (-L)", "string"),
        ParameterSpec("password", "Mot de passe unique (-p)", "string"),
        ParameterSpec("passlist", "Liste de mots de passe (-P)", "string"),
        ParameterSpec("port", "Port du service (-s)", "int"),
        ParameterSpec("threads", "Taches paralleles (-t)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hydra"]
        if params.get("userlist"):
            argv += ["-L", str(params["userlist"])]
        elif params.get("username"):
            argv += ["-l", str(params["username"])]
        if params.get("passlist"):
            argv += ["-P", str(params["passlist"])]
        elif params.get("password"):
            argv += ["-p", str(params["password"])]
        if params.get("port"):
            argv += ["-s", str(params["port"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        argv += [str(params["target"]), str(params["service"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_host(text)
        if target:
            params["target"] = target
        for service in ("ssh", "ftp", "rdp", "smb", "telnet", "mysql", "postgres", "vnc", "http-get", "https-get"):
            if re.search(rf"\b{re.escape(service)}\b", low):
                params["service"] = service
                break
        user = re.search(r"\b(?:utilisateur|user|login)\s+([\w.\-@]+)", low)
        if user:
            params["username"] = user.group(1)
        userlist = re.search(r"(/[\w./\-]*users?[\w./\-]*\.txt)", text)
        if userlist:
            params["userlist"] = userlist.group(1)
        passlist = re.search(r"(/[\w./\-]*(?:pass|wordlist)[\w./\-]*\.txt)", text, re.IGNORECASE)
        if passlist:
            params["passlist"] = passlist.group(1)
        port = _extract_port(text)
        if port:
            params["port"] = port
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
            if match:
                findings.append(
                    Finding(
                        title=f"Identifiants trouves: {match.group(1)} / {match.group(2)}",
                        severity="critical",
                        evidence=line.strip()[:160],
                    )
                )
        return AnalysisResult(summary=f"{len(findings)} identifiant(s) trouve(s).", findings=findings, source="heuristic")


class MedusaTool(Tool):
    name = "medusa"
    binary = "medusa"
    risk = "critical"
    description = "Attaque en ligne parallele par force brute (SSH, FTP, HTTP...)."
    examples = ("medusa sur ssh 10.0.0.5 avec root et une liste de mots de passe",)
    parameters = (
        ParameterSpec("target", "Hote cible (-h)", "string", required=True),
        ParameterSpec("module", "Module/protocole (-M): ssh, ftp, http...", "string", required=True),
        ParameterSpec("username", "Utilisateur unique (-u)", "string"),
        ParameterSpec("userlist", "Liste d'utilisateurs (-U)", "string"),
        ParameterSpec("password", "Mot de passe unique (-p)", "string"),
        ParameterSpec("passlist", "Liste de mots de passe (-P)", "string"),
        ParameterSpec("port", "Port (-n)", "int"),
        ParameterSpec("threads", "Taches paralleles (-t)", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["medusa", "-h", str(params["target"]), "-M", str(params["module"])]
        if params.get("userlist"):
            argv += ["-U", str(params["userlist"])]
        elif params.get("username"):
            argv += ["-u", str(params["username"])]
        if params.get("passlist"):
            argv += ["-P", str(params["passlist"])]
        elif params.get("password"):
            argv += ["-p", str(params["password"])]
        if params.get("port"):
            argv += ["-n", str(params["port"])]
        if params.get("threads"):
            argv += ["-t", str(params["threads"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_host(text)
        if target:
            params["target"] = target
        for module in ("ssh", "ftp", "smbnt", "rdp", "mysql", "postgres", "vnc", "http"):
            if re.search(rf"\b{re.escape(module)}\b", low):
                params["module"] = module
                break
        user = re.search(r"\b(?:utilisateur|user|login)\s+([\w.\-@]+)", low)
        if user:
            params["username"] = user.group(1)
        passlist = re.search(r"(/[\w./\-]*(?:pass|wordlist)[\w./\-]*\.txt)", text, re.IGNORECASE)
        if passlist:
            params["passlist"] = passlist.group(1)
        port = _extract_port(text)
        if port:
            params["port"] = port
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"ACCOUNT FOUND", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:160], severity="critical"))
        return AnalysisResult(summary=f"{len(findings)} compte(s) compromis.", findings=findings, source="heuristic")


class NcrackTool(Tool):
    name = "ncrack"
    binary = "ncrack"
    risk = "critical"
    description = "Outil de craquage d'authentification reseau (RDP, SSH, FTP...)."
    examples = ("ncrack sur rdp://10.0.0.5 avec une liste de mots de passe",)
    parameters = (
        ParameterSpec("target", "Cible au format service://hote:port", "string", required=True),
        ParameterSpec("username", "Utilisateur (-U)", "string"),
        ParameterSpec("passlist", "Liste de mots de passe (-P)", "string"),
        ParameterSpec("port", "Port", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ncrack"]
        if params.get("username"):
            argv += ["-U", str(params["username"])]
        if params.get("passlist"):
            argv += ["-P", str(params["passlist"])]
        argv.append(str(params["target"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_host(text)
        service = None
        for svc in ("rdp", "ssh", "ftp", "telnet", "mysql", "vnc"):
            if re.search(rf"\b{svc}\b", low):
                service = svc
                break
        if target:
            port = _extract_port(text)
            prefix = f"{service}://" if service else ""
            suffix = f":{port}" if port else ""
            params["target"] = f"{prefix}{target}{suffix}"
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"Discovered credentials", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:160], severity="critical"))
        return AnalysisResult(summary=f"{len(findings)} identifiant(s) trouve(s).", findings=findings, source="heuristic")


class PatatorTool(Tool):
    name = "patator"
    binary = "patator"
    risk = "critical"
    description = "Bruteforce modulaire multi-protocoles (login, ftp, ssh, http...)."
    examples = ("patator ssh_login sur 10.0.0.5 avec root",)
    parameters = (
        ParameterSpec("module", "Module: ssh_login, ftp_login, http_fuzz...", "string", required=True),
        ParameterSpec("host", "Hote cible (host=)", "string", required=True),
        ParameterSpec("user", "Utilisateur (user=)", "string"),
        ParameterSpec("password", "Mot de passe ou fichier (password=FILE0)", "string"),
        ParameterSpec("port", "Port", "int"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["patator", str(params["module"])]
        argv.append(f"host={params['host']}")
        if params.get("port"):
            argv.append(f"port={params['port']}")
        if params.get("user"):
            argv.append(f"user={params['user']}")
        if params.get("password"):
            argv.append(f"password={params['password']}")
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        target = _extract_host(text)
        if target:
            params["host"] = target
        for module in ("ssh_login", "ftp_login", "smb_login", "rdp_login", "http_fuzz", "telnet_login"):
            if module.split("_")[0] in low:
                params["module"] = module
                break
        user = re.search(r"\b(?:utilisateur|user|login)\s+([\w.\-@]+)", low)
        if user:
            params["user"] = user.group(1)
        port = _extract_port(text)
        if port:
            params["port"] = port
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"\b(?:SUCCESS|FOUND)\b", line):
                findings.append(Finding(title=line.strip()[:160], severity="critical"))
        return AnalysisResult(summary=f"{len(findings)} identifiant(s) trouve(s).", findings=findings, source="heuristic")


class HashcatTool(Tool):
    name = "hashcat"
    binary = "hashcat"
    risk = "high"
    description = "Craquage de hash GPU/CPU (dictionnaire, regles, masques)."
    examples = (
        "craque le fichier hashes.txt en mode 0 avec rockyou.txt",
        "hashcat sur hashes.txt avec un masque de 8 caracteres",
    )
    parameters = (
        ParameterSpec("hashfile", "Fichier de hashes", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (-a 0)", "string"),
        ParameterSpec("hash_mode", "Mode de hash (-m), ex: 0=MD5, 1000=NTLM", "int"),
        ParameterSpec("attack_mode", "Mode d'attaque (-a): 0 dict, 3 mask", "int"),
        ParameterSpec("mask", "Masque (mode 3), ex: ?a?a?a?a", "string"),
        ParameterSpec("rules", "Fichier de regles (-r)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["hashcat"]
        if params.get("hash_mode") is not None:
            argv += ["-m", str(params["hash_mode"])]
        attack = params.get("attack_mode")
        if attack is None:
            attack = 3 if params.get("mask") else 0
        argv += ["-a", str(attack)]
        if params.get("rules"):
            argv += ["-r", str(params["rules"])]
        argv.append(str(params["hashfile"]))
        if params.get("mask"):
            argv.append(str(params["mask"]))
        elif params.get("wordlist"):
            argv.append(str(params["wordlist"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hashfile = re.search(r"([\w./\-]+\.(?:txt|hash|hashes))", text, re.IGNORECASE)
        if hashfile:
            params["hashfile"] = hashfile.group(1)
        wordlist = re.search(r"([\w./\-]*(?:rockyou|wordlist|pass)[\w./\-]*\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        mode = re.search(r"\bmode\s+(\d+)", low)
        if mode:
            params["hash_mode"] = int(mode.group(1))
        if "ntlm" in low:
            params["hash_mode"] = 1000
        elif "sha1" in low:
            params["hash_mode"] = 100
        elif "sha256" in low:
            params["hash_mode"] = 1400
        elif "md5" in low:
            params["hash_mode"] = 0
        mask = re.search(r"(?:\?[a-zA-Z]|\?d|\?l|\?u){2,}", text)
        if mask:
            params["mask"] = mask.group(0)
            params["attack_mode"] = 3
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"^([0-9a-fA-F]{16,}):(.+)$", stdout, re.MULTILINE):
            findings.append(
                Finding(
                    title=f"Hash craque: {match.group(2).strip()[:80]}",
                    severity="critical",
                    evidence=match.group(0)[:160],
                )
            )
        recovered = re.search(r"Recovered\.+:\s*(\d+)/", stdout)
        summary = f"{len(findings)} hash(es) craque(s)."
        if recovered:
            summary = f"{recovered.group(1)} hash(es) recupere(s)."
        return AnalysisResult(summary=summary, findings=findings, source="heuristic")


class JohnTool(Tool):
    name = "john"
    binary = "john"
    aliases = ("johnny",)
    risk = "high"
    description = "Craquage de mots de passe hors ligne (John the Ripper)."
    examples = ("john sur le fichier shadow.txt avec rockyou.txt",)
    parameters = (
        ParameterSpec("hashfile", "Fichier de hashes a craquer", "string", required=True),
        ParameterSpec("wordlist", "Dictionnaire (--wordlist)", "string"),
        ParameterSpec("format", "Format de hash (--format)", "string"),
        ParameterSpec("rules", "Activer les regles (--rules)", "bool", default=False),
        ParameterSpec("show", "Afficher les hashes craques (--show)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["john"]
        if params.get("format"):
            argv += ["--format", str(params["format"])]
        if params.get("wordlist"):
            argv += ["--wordlist", str(params["wordlist"])]
        if params.get("rules"):
            argv.append("--rules")
        if params.get("show"):
            argv.append("--show")
        argv.append(str(params["hashfile"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        hashfile = re.search(r"([\w./\-]+\.(?:txt|passwd|shadow|hash|hashes))", text, re.IGNORECASE)
        if hashfile:
            params["hashfile"] = hashfile.group(1)
        wordlist = re.search(r"([\w./\-]*(?:rockyou|wordlist|pass)[\w./\-]*\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        if "ntlm" in low:
            params["format"] = "NT"
        elif "sha512crypt" in low:
            params["format"] = "sha512crypt"
        elif "md5" in low:
            params["format"] = "raw-md5"
        if "regles" in low or "rules" in low:
            params["rules"] = True
        if "affiche" in low or "show" in low:
            params["show"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if ":" in line and re.search(r"\b(?:cracked|loaded|guesses)\b", line, re.IGNORECASE):
                findings.append(Finding(title=line.strip()[:160], severity="info"))
            elif re.match(r"^\S+:\S+$", line) and params.get("show"):
                findings.append(Finding(title=f"Hash craque: {line.strip()[:120]}", severity="critical"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) john.", findings=findings, source="heuristic")


class OphcrackTool(Tool):
    name = "ophcrack"
    binary = "ophcrack"
    aliases = ("ophcrack-cli",)
    risk = "high"
    description = "Craquage de mots de passe Windows par tables arc-en-ciel."
    examples = ("craque les hashes windows de hashes.txt avec ophcrack",)
    parameters = (
        ParameterSpec("hashfile", "Fichier de hashes ou ruche SAM", "string", required=True),
        ParameterSpec("tables", "Repertoire des tables (-d)", "string"),
        ParameterSpec("cli", "Mode ligne de commande (-c)", "bool", default=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["ophcrack", "-c"]
        if params.get("tables"):
            argv += ["-d", str(params["tables"])]
        argv += ["-f", str(params["hashfile"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        hashfile = re.search(r"([\w./\-]+\.(?:txt|hash|hashes))", text, re.IGNORECASE)
        if hashfile:
            params["hashfile"] = hashfile.group(1)
        tables = re.search(r"(/[\w./\-]*tables?[\w./\-]*)", text, re.IGNORECASE)
        if tables:
            params["tables"] = tables.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"(\S+)\s*:\s*([^\s:]+)\s+.*?([0-9a-fA-F]{32})", stdout):
            findings.append(Finding(title=f"Mot de passe: {match.group(2)}", severity="critical"))
        return AnalysisResult(summary=f"{len(findings)} mot(s) de passe craque(s).", findings=findings, source="heuristic")


class Samdump2Tool(Tool):
    name = "samdump2"
    binary = "samdump2"
    risk = "high"
    description = "Extraction des hashes depuis les ruches SAM et SYSTEM de Windows."
    examples = ("extrait les hashes depuis SAM et SYSTEM avec samdump2",)
    parameters = (
        ParameterSpec("system_hive", "Fichier SYSTEM", "string", required=True),
        ParameterSpec("sam_hive", "Fichier SAM", "string", required=True),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        return ["samdump2", str(params["system_hive"]), str(params["sam_hive"])]

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        sam = re.search(r"(/[\w./\-]*[Ss][Aa][Mm][\w./\-]*)", text)
        system = re.search(r"(/[\w./\-]*[Ss][Yy][Ss][Tt][Ee][Mm][\w./\-]*)", text)
        if system:
            params["system_hive"] = system.group(1)
        if sam:
            params["sam_hive"] = sam.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for match in re.finditer(r"^(\S+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", stdout, re.MULTILINE):
            findings.append(Finding(title=f"Hash NTLM extrait pour {match.group(1)}", severity="high"))
        return AnalysisResult(summary=f"{len(findings)} hash(es) extrait(s).", findings=findings, source="heuristic")


class ChntpwTool(Tool):
    name = "chntpw"
    binary = "chntpw"
    risk = "high"
    description = "Edition hors ligne de la base de comptes Windows (ruche SAM)."
    examples = ("reinitialise le mot de passe de l'admin depuis SAM avec chntpw",)
    parameters = (
        ParameterSpec("sam_hive", "Fichier SAM", "string", required=True),
        ParameterSpec("list", "Lister les utilisateurs (-l)", "bool", default=False),
        ParameterSpec("user", "Utilisateur a modifier (-u)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["chntpw"]
        if params.get("list"):
            argv.append("-l")
        if params.get("user"):
            argv += ["-u", str(params["user"])]
        argv.append(str(params["sam_hive"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        sam = re.search(r"(/[\w./\-]*[Ss][Aa][Mm][\w./\-]*)", text)
        if sam:
            params["sam_hive"] = sam.group(1)
        if "liste" in low or "lister" in low:
            params["list"] = True
        user = re.search(r"\b(?:utilisateur|user)\s+([\w.\-]+)", low)
        if user:
            params["user"] = user.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            if re.search(r"RID\s*:\s*\d+", line) or re.search(r"Username:\s*\S+", line):
                findings.append(Finding(title=line.strip()[:160], severity="info"))
        return AnalysisResult(summary=f"{len(findings)} entree(s) de compte.", findings=findings, source="heuristic")


class CrunchTool(Tool):
    name = "crunch"
    binary = "crunch"
    risk = "low"
    description = "Generateur de listes de mots de passe (longueur, jeu de caracteres, motif)."
    examples = ("genere une liste de mots de passe de 8 caracteres avec crunch",)
    parameters = (
        ParameterSpec("min_length", "Longueur minimale", "int", required=True),
        ParameterSpec("max_length", "Longueur maximale", "int"),
        ParameterSpec("charset", "Jeu de caracteres (-t/-f) ou motif", "string"),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        min_len = params.get("min_length", 1)
        max_len = params.get("max_length") or min_len
        argv = ["crunch", str(min_len), str(max_len)]
        if params.get("charset"):
            argv.append(str(params["charset"]))
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        lengths = re.findall(r"(\d+)\s*(?:caracteres|characters|chars)", low)
        if lengths:
            params["min_length"] = int(lengths[0])
            params["max_length"] = int(lengths[-1])
        out = re.search(r"([\w./\-]+\.txt)", text)
        if out:
            params["output"] = out.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        findings: list[Finding] = []
        match = re.search(r"(\d+)\s+lines?\s+written", stdout, re.IGNORECASE)
        if match:
            findings.append(Finding(title=f"{match.group(1)} mot(s) de passe genere(s)", severity="info"))
        return AnalysisResult(summary=f"{len(findings)} constat(s) crunch.", findings=findings, source="heuristic")


class CewlTool(Tool):
    name = "cewl"
    binary = "cewl"
    risk = "medium"
    description = "Generation de listes de mots a partir du contenu d'un site web."
    examples = ("genere une wordlist depuis http://example.com avec cewl",)
    parameters = (
        ParameterSpec("url", "URL a explorer", "string", required=True),
        ParameterSpec("depth", "Profondeur de crawl (-d)", "int"),
        ParameterSpec("min_length", "Longueur minimale des mots (-m)", "int"),
        ParameterSpec("output", "Fichier de sortie (-w)", "string"),
        ParameterSpec("lowercase", "Mettre en minuscules (--lowercase)", "bool", default=False),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["cewl"]
        if params.get("depth"):
            argv += ["-d", str(params["depth"])]
        if params.get("min_length"):
            argv += ["-m", str(params["min_length"])]
        if params.get("lowercase"):
            argv.append("--lowercase")
        if params.get("output"):
            argv += ["-w", str(params["output"])]
        argv.append(str(params["url"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        low = text.lower()
        params: dict[str, Any] = {}
        url = re.search(r"https?://[^\s'\"<>]+", text)
        if url:
            params["url"] = url.group(0).rstrip(".,;)")
        depth = re.search(r"profondeur\s*(\d+)", low)
        if depth:
            params["depth"] = int(depth.group(1))
        min_len = re.search(r"(?:longueur|minimum|min)\s*(\d+)", low)
        if min_len:
            params["min_length"] = int(min_len.group(1))
        out = re.search(r"([\w./\-]+\.txt)", text)
        if out:
            params["output"] = out.group(1)
        if "minuscule" in low or "lowercase" in low:
            params["lowercase"] = True
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        words = [w for w in stdout.split() if len(w) > 3]
        findings = [Finding(title="Mot collecte", severity="info", evidence=w[:80]) for w in words[:20]]
        return AnalysisResult(summary=f"{len(words)} mot(s) collecte(s).", findings=findings, source="heuristic")


class RsmanglerTool(Tool):
    name = "rsmangler"
    binary = "rsmangler"
    risk = "low"
    description = "Mangle une liste de mots (permutations, casse, suffixes, prefixes)."
    examples = ("mangle la wordlist base.txt avec rsmangler",)
    parameters = (
        ParameterSpec("wordlist", "Liste de mots source", "string", required=True),
        ParameterSpec("output", "Fichier de sortie (-o)", "string"),
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        params = self.coerce(params)
        argv = ["rsmangler"]
        if params.get("output"):
            argv += ["-o", str(params["output"])]
        argv.append(str(params["wordlist"]))
        return argv

    def parse_intent(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        wordlist = re.search(r"([\w./\-]+\.txt)", text, re.IGNORECASE)
        if wordlist:
            params["wordlist"] = wordlist.group(1)
        return params

    def analyze(self, stdout: str, params: dict[str, Any]) -> AnalysisResult:
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        findings = [Finding(title="Variante generee", severity="info", evidence=ln[:80]) for ln in lines[:10]]
        return AnalysisResult(summary=f"{len(lines)} variante(s) generee(s).", findings=findings, source="heuristic")


register(HashIdentifierTool())
register(HydraTool())
register(MedusaTool())
register(NcrackTool())
register(PatatorTool())
register(HashcatTool())
register(JohnTool())
register(OphcrackTool())
register(Samdump2Tool())
register(ChntpwTool())
register(CrunchTool())
register(CewlTool())
register(RsmanglerTool())
