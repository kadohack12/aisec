# Attribution des classes a des agents

Une ligne par agent. Remplis la colonne « agent » puis donne a chacun ce
fichier + `docs/CLASSES.md`. Chaque agent livre un `Expert` pour sa classe
(meme modele que l'expert DNS existant : `aisec/experts/dns.py`).

| # | Classe | `class_id` | Outils | Priorite | Agent | Statut |
|---|--------|-----------|--------|----------|-------|--------|
| 1 | Information Gathering | `01-info-gathering` | 82 | haute | agent-info | **en cours (jalon 1)** |
| 2 | Vulnerability Analysis | `02-vulnerability-analysis` | 42 | haute | agent-vuln | **en cours (jalon 1)** |
| 3 | Web Application Analysis | `03-webapp-analysis` | 38 | haute | agent-web | **en cours (jalon 1)** |
| 4 | Password Attacks | `05-password-attacks` | 45 | haute | agent-password | **en cours (jalon 1)** |
| 5 | Sniffing & Spoofing | `09-sniffing-spoofing` | 29 | moyenne | agent-sniffing | **en cours (jalon 1)** |
| 6 | Digital Forensics | `11-forensics` | 46 | moyenne | | a faire |
| 7 | Wireless Testing | `06-wireless-attacks` | 38 | moyenne | | a faire |
| 8 | Maintaining Access | `10-maintaining-access` | 34 | basse | | a faire |
| 9 | Exploitation Tools | `04-exploitation-tools` | 24 | basse | | a faire |
| 10 | Reverse Engineering | `07-reverseengineer` | 20 | basse | | a faire |
| 11 | Post Exploitation | `08-post-exploit` | 16 | basse | | a faire |
| 12 | Reporting Tools | `12-reporting` | 4 | basse | | a faire |
| 13 | Automotive | `13-automotive` | 1 | basse | | a faire |
| 14 | AI Tools | `14-ai-tools` | 5 | basse | | a faire |
| 15 | Autres (System/Utility/...) | `misc` | 21 | basse | | a faire |

Note : l'expert `dns` (`01-01-dns-analysis`, dans Information Gathering) est
deja livre — le decompte de la classe 1 pourra etre ajuste en consequence.

## Jalon 1 : 5 experts livres (premier lot d'outils)

Les classes 1, 2, 3, 5 et 9 sont amorcees avec un premier lot d'outils et un
expert fonctionnel (routage + construction d'argv + analyse heuristique).

| Expert | `class_id` | Outils du jalon 1 | Tests |
|--------|-----------|-------------------|-------|
| `info` | `01-info-gathering` | nmap, masscan, arp-scan, sslscan, wafw00f, dnsrecon | `tests/test_info.py` |
| `vuln` | `02-vulnerability-analysis` | testssl, slowhttptest | `tests/test_vuln.py` |
| `web` | `03-webapp-analysis` | whatweb, nikto, gobuster, ffuf | `tests/test_web.py` |
| `password` | `05-password-attacks` | hydra, john, hashid, cewl | `tests/test_password.py` |
| `sniffing` | `09-sniffing-spoofing` | tshark (reutilise), bettercap | `tests/test_sniffing.py` |

Note : l'expert `dns` (`01-01-dns-analysis`) reste la reference pour
dig/host/whois et n'a pas ete refait ; l'expert `info` couvre le reste de la
classe 1.

Les sous-categories restantes de chaque classe (OSINT, SMTP, SMB, SNMP, Cisco,
fuzzing, VoIP, stress, CMS, proxies, attaques hors ligne/locales, sniffers
dedies, spoofing MITM, ...) sont a traiter dans les jalons suivants.

## Contrat d'un agent (une classe)

1. **Outils** : creer `aisec/tools/<outil>.py` pour chaque binaire de la classe
   (classe `Tool` : `build_argv`, `parse_intent`, `analyze`, `parameters`,
   `risk`). Enregistrer dans `aisec/core/registry.py::_load_builtins`.
2. **Expert** : creer `aisec/experts/<classe>.py` (`Expert` : `system_prompt`,
   `tool_names`, `keywords`, `routing_rules`). Enregistrer dans
   `aisec/experts/__init__.py`.
3. **Tests** : ajouter `tests/test_<classe>.py` (routage + construction d'argv).
4. **Regle** : ne rien executer sans passer par la politique de controle
   (niveau 2) ; ne jamais utiliser de shell.

Voir `aisec/experts/dns.py` comme reference.
