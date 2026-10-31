# Attribution des classes a des agents

Une ligne par agent. Remplis la colonne « agent » puis donne a chacun ce
fichier + `docs/CLASSES.md`. Chaque agent livre un `Expert` pour sa classe
(meme modele que l'expert DNS existant : `aisec/experts/dns.py`).

| # | Classe | `class_id` | Outils | Priorite | Agent | Statut |
|---|--------|-----------|--------|----------|-------|--------|
| 1 | Information Gathering | `01-info-gathering` | 82 | haute | agent-info | **livre (jalon 1)** |
| 2 | Vulnerability Analysis | `02-vulnerability-analysis` | 42 | haute | agent-vuln | **livre (jalon 1)** |
| 3 | Web Application Analysis | `03-webapp-analysis` | 38 | haute | agent-web | **livre (jalon 1)** |
| 4 | Password Attacks | `05-password-attacks` | 45 | haute | agent-password | **livre (jalon 1)** |
| 5 | Sniffing & Spoofing | `09-sniffing-spoofing` | 29 | moyenne | agent-sniffing | **livre (jalon 1)** |
| 6 | Digital Forensics | `11-forensics` | 46 | moyenne | agent-forensics | **livre (jalon 1)** |
| 7 | Wireless Testing | `06-wireless-attacks` | 38 | moyenne | | a faire |
| 8 | Maintaining Access | `10-maintaining-access` | 34 | basse | | a faire |
| 9 | Exploitation Tools | `04-exploitation-tools` | 24 | basse | agent-exploitation | **livre (jalon 1)** |
| 10 | Reverse Engineering | `07-reverseengineer` | 20 | basse | agent-reverse | **livre (jalon 1)** |
| 11 | Post Exploitation | `08-post-exploit` | 16 | basse | openhands | **livre** (`aisec/experts/post_exploit.py`) |
| 12 | Reporting Tools | `12-reporting` | 4 | basse | openhands | **livre** (`aisec/experts/reporting.py`) |
| 13 | Automotive | `13-automotive` | 1 | basse | | a faire |
| 14 | AI Tools | `14-ai-tools` | 5 | basse | | a faire |
| 15 | Autres (System/Utility/...) | `misc` | 21 | basse | | a faire |

Note : l'expert `dns` (`01-01-dns-analysis`, dans Information Gathering) est
deja livre — le decompte de la classe 1 pourra etre ajuste en consequence.

## Jalon 1 : 8 experts livres (premier lot d'outils)

Les classes 1, 2, 3, 4, 5, 7, 9 et 11 sont amorcees avec un premier lot d'outils et un
expert fonctionnel (routage + construction d'argv + analyse heuristique).

| Expert | `class_id` | Outils du jalon 1 | Tests |
|--------|-----------|-------------------|-------|
| `info` | `01-info-gathering` | nmap, masscan, arp-scan, sslscan, wafw00f, dnsrecon | `tests/test_info.py` |
| `vulnerability` | `02-vulnerability-analysis` | 46 outils (spec.py + vuln_scan/cisco/stress/fuzz/voip) | `tests/test_vulnerability.py` |
| `webapp` | `03-webapp-analysis` | 38 outils (web_crawl/web_vuln/web_misc : nikto, whatweb, wpscan, gobuster, ffuf, wapiti, ...) | `tests/test_webapp.py` |
| `exploitation` | `04-exploitation-tools` | 18 outils (sqlmap, msfconsole, searchsploit, ...) | `tests/test_exploitation.py` |
| `passwords` | `05-password-attacks` | hydra, medusa, ncrack, john, hashcat, ... (13) | `tests/test_passwords.py` |
| `reverse` | `07-reverseengineer` | 17 outils (rabin2, radare2, rahash2, rasm2, radiff2, rizin, rz-hash, rz-find, gdb, bddisasm, die, apktool, dex2jar, jadx, androguard, baksmali, smali) | `tests/test_reverse.py` |
| `sniffing` | `09-sniffing-spoofing` | tshark (reutilise), bettercap | `tests/test_sniffing.py` |
| `forensics` | `11-forensics` | 22 outils (fls, mmls, icat, foremost, scalpel, binwalk, bulk_extractor, pdfid, pdf-parser, yara, volatility3, regripper, reglookup, galleta, vinetto, hashdeep, ssdeep, rkhunter, chkrootkit, extundelete, dc3dd, ddrescue) | `tests/test_forensics.py` |

Note : l'expert `dns` (`01-01-dns-analysis`) reste la reference pour
dig/host/whois et n'a pas ete refait ; l'expert `info` couvre le reste de la
classe 1.

### Detail classe 11 (forensique)

Les outils sont volontairement majoritairement en lecture seule ; seuls `dc3dd`
et `ddrescue` sont classes `high` (acquisition/ecriture), et
`icat`/`extundelete`/`rkhunter`/`chkrootkit` en `medium`.

| Sous-categorie | Outils du jalon 1 |
|----------------|-------------------|
| Sleuth Kit | `fls`, `mmls`, `icat` |
| Carving | `foremost`, `scalpel`, `binwalk`, `bulk_extractor` |
| PDF Forensics | `pdfid`, `pdf-parser` |
| Detection | `yara` |
| Memoire vive | `volatility3` |
| Artefacts Windows | `regripper`, `reglookup`, `galleta`, `vinetto` |
| Integrite / rootkits | `hashdeep`, `ssdeep`, `rkhunter`, `chkrootkit` |
| Recuperation | `extundelete` |
| Imagerie | `dc3dd`, `ddrescue` |

Reste a couvrir dans les jalons suivants : imagerie et conteneurs (`autopsy`,
`guymager`, `ewf-tools`, `afflib-tools`, `dcfldd`), carving complementaire
(`magicrescue`, `safecopy`, `rifiuti2`, `pev`, `pasco`, `ext3grep`,
`ext4magic`, `myrescue`, `recoverdm`, `recoverjpeg`, `scrounge-ntfs`,
`undbx`), systeme et journaux (`grokevt`, `unhide`, `procdump`, `pst-utils`,
`mc`, `missidentify`) et reseau (`xplico`, `inetsim`).

Les sous-categories restantes des autres classes (OSINT, SMTP, SMB, SNMP, Cisco,
fuzzing, VoIP, stress, CMS, proxies, attaques hors ligne/locales, sniffers
dedies, spoofing MITM, ...) sont a traiter dans les jalons suivants.

## Jalon 1 : Reverse Engineering (`07-reverseengineer`)

17 outils et un expert `reverse` fonctionnel. Le lot est domine par l'analyse
statique en lecture seule (`low`) ; `gdb` (execution/debogage) et `smali`
(assemblage) sont en `medium` et exigent une confirmation.

| Sous-categorie | Outils du jalon 1 |
|----------------|-------------------|
| Suite Radare2 | `rabin2`, `radare2`, `rahash2`, `rasm2`, `radiff2` |
| Suite Rizin | `rizin`, `rz-hash`, `rz-find` |
| Debogueurs | `gdb` |
| Desassembleurs | `bddisasm` |
| Identification | `die` (detect-it-easy) |
| Android / Java | `apktool`, `dex2jar`, `jadx`, `androguard`, `baksmali`, `smali` |

Tests : `tests/test_reverse.py` (routage, argv, analyse, politique de controle).

Reste a couvrir dans les jalons suivants : `ghidra`, `edb-debugger`,
`ollydbg`, `rizin-cutter`, `bytecode-viewer`, `jd-gui`, `recstudio`,
`javasnoop`, `gdb-gef`, `android-sdk`, `libsmali-java` (interface graphique
ou SDK; a exposer via leurs binaires CLI quand ils existent).

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
