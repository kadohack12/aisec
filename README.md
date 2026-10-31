# aisec — suite d'outils de sécurité pilotés par IA

`aisec` traduit une **intention en langage naturel** en commande d'outil de
sécurité (nmap, tshark, dig, ...), la vérifie, **la contrôle**, l'exécute et
**analyse le résultat**.

Avant :

```bash
nmap -p 22,80,8080 -sV target.com
```

Avec `aisec` :

```bash
nmapAI "analyse les ports 22, 80, 8080 sur target.com et détecte les versions"
```

L'outil construit la commande, la lance, puis te renvoie un résumé et des
constats (ports sensibles, services à risque, ...).

---

## Le principe : deux niveaux de contrôle

**Niveau 1 — l'IA pilote l'outil.** Tu décris l'intention en français ; l'IA
choisit l'outil, les drapeaux et les paramètres, puis lit la sortie.

**Niveau 2 — l'humain pilote l'IA.** Rien ne s'exécute sans passer par une
**politique de contrôle**. Chaque commande proposée est classée par risque et
reçoit une décision : `allow`, `confirm` ou `deny`. C'est ce qui empêche l'IA
de partir en roue libre.

```
        Intention ("enumere les serveurs de noms de example.com")
                        |
                        v
   +--------------  NIVEAU 1 : l'IA pilote  ---------------+
   |  ROUTEUR  -->  EXPERT (classe Parrot)  -->  OUTIL       |
   |                  IA dediee + dig/host/whois             |
   +---------------------------+----------------------------+
                               v
   +--------------  NIVEAU 2 : l'humain pilote ------------+
   |  POLITIQUE DE CONTROLE                                  |
   |    risque de l'outil + mots-cles sensibles              |
   |    plafond de risque, cibles max, liste blanche/noire   |
   |    cibles privees                                       |
   |         |                                               |
   |    allow   --> execute                                  |
   |    confirm --> demande a l'humain --> execute / annule  |
   |    deny    --> refuse, point.                           |
   +---------------------------+----------------------------+
                               v
         Execution (argv, jamais de shell) --> Analyse
```

On construit **un expert à la fois** (comme la taxonomie de Parrot :
Information Gathering, Web, Password Attacks, Sniffing, Forensics, ...), on le
teste, puis on ajoute le suivant. À terme, un **orchestrateur unique** route
vers tous les experts.

Chaque expert peut être branché sur **sa propre IA entraînée**
(`[expert_models]` dans la config), ou partager le LLM global.

---

## Niveau 2 : contrôle de l'IA

Le moteur de contrôle (`aisec/core/control.py`) attribue à chaque commande un
**niveau de risque** et une **décision** :

| Risque     | Outils typiques            | Décision par défaut        |
|------------|----------------------------|----------------------------|
| `low`      | dig, host, whois, tshark   | exécute directement        |
| `medium`   | nmap (scan réseau)         | **demande confirmation**   |
| `high`     | —                          | demande confirmation       |
| `critical` | —                          | demande confirmation       |

Le risque d'un outil est déclaré dans le plugin (`risk = "low"`), et **monte
d'un cran** si la commande contient un argument sensible (`AXFR`, `--script`,
`brute`, `exploit`, `spoof`, ...).

La politique borne aussi le comportement de l'IA :

- **plafond de risque auto-approuvé** — au-delà, confirmation obligatoire ;
- **nombre maximal de cibles** par commande (défaut : 16) ;
- **liste blanche / liste noire** d'outils ;
- **refus des cibles privées/internes** (optionnel).

### En pratique

```bash
# Risque low : part tout seul
aisec dns "MX example.com"

# Risque medium : aisec demande confirmation avant de lancer nmap
aisec nmap "scan des ports 22,80 sur 10.0.0.1"
#   $ nmap -p 22,80 10.0.0.1  [risk: medium]
#     - risque medium > plafond auto-approuve low
#   Executer cette commande ? [y/N]

# On peut auto-approuver explicitement
aisec nmap "scan des ports 22,80 sur 10.0.0.1" --yes

# Ou relever le plafond pour la session
aisec nmap "scan des ports 22,80 sur 10.0.0.1" --auto-approve-risk medium

# Refus net : sortie 3 si l'humain annule
```

En mode non interactif (pas de TTY, ex. dans un script), une commande qui exige
une confirmation est **annulée** (jamais exécutée silencieusement).

---

## Pourquoi

Retenir la syntaxe exacte de chaque outil est pénible. Ici tu décris ce que tu
veux, `aisec` s'occupe des drapeaux, de la validation, du contrôle et de la
lecture du résultat. Chaque nouvel outil est un **plugin**, chaque nouvelle
classe un **expert** : on étend la suite sans toucher au cœur.

---

## Installation

```bash
pip install -e ".[dev]"        # depuis le dépôt
# ou, pour l'affichage enrichi :
pip install -e ".[dev,ui]"
```

Les binaires des outils doivent être présents :

```bash
sudo apt-get install -y nmap bind9-dnsutils whois tshark
```

## IA locale d'abord

Par défaut `aisec` utilise **Ollama** (100 % local, aucune donnée ne sort) :

```bash
# install Ollama: https://ollama.com
ollama pull llama3.1
```

Si Ollama n'est pas disponible, `aisec` bascule automatiquement sur un mode
**heuristique** (sans LLM) : il sait quand même construire les commandes
courantes et analyser les sorties.

Tu peux choisir le backend à chaque appel :

```bash
aisec dns "..." --provider ollama          # local (défaut)
aisec dns "..." --provider none            # heuristique seule
aisec dns "..." --provider openai --model gpt-4o-mini   # API (données envoyées)
```

### Configuration

Copie `aisec.example.toml` vers `./aisec.toml` (par projet) ou
`~/.config/aisec/config.toml` (global). Variables d'environnement `AISEC_*`
possibles (`AISEC_PROVIDER`, `AISEC_MODEL`, `AISEC_API_KEY`, ...).

```toml
provider = "ollama"
model = "llama3.1"

# --- Niveau 2 : politique de contrôle ---
auto_approve_risk = "low"      # low | medium | high | critical
max_targets = 16
deny_private_targets = false
assume_yes = false

# --- IA dédiée par expert ---
[expert_models]
dns = "aisec-dns:latest"
web = "aisec-web:latest"
```

---

## Utilisation

```bash
# Demande libre : le routeur choisit l'expert
aisec ask "je veux les enregistrements MX de example.com"

# Expert DNS (IA dédiée à la classe DNS)
dnsAI "qui possede example.com"
aisec dns "résolution inverse de 8.8.8.8"
aisec dns "tente un transfert de zone sur example.com"

# Experts par classe (reconnaissance, vulnerabilites, web, mots de passe, sniffing)
infoAI "découverte des hôtes sur 192.168.1.0/24"
infoAI "détecte le waf devant https://example.com"
vulnerabilityAI "audite le tls de example.com:443"
aisec vulnerability "audite le routeur cisco 10.0.0.1"
aisec vulnerability "enumere les extensions sip de 10.0.0.1"
aisec vulnerability "fuzz le binaire ./parser avec afl"
webappAI "brute force les répertoires de https://example.com avec gobuster"
passwordsAI "identifie le hash 5f4dcc3b5aa765d61d8327deb882cf99"
sniffingAI "capture le trafic http sur eth0 pendant 100 paquets"

# Expert Web Application Analysis (classe 03 : empreinte, bruteforce, scanners, CMS, proxies)
webappAI "scanne le wordpress http://cible"
aisec webapp "identifie les technologies de example.com"
aisec webapp "bruteforce les répertoires de http://cible"
aisec webapp "teste les failles xss sur http://cible"

# Expert forensique (analyse en lecture seule)
forensicsAI "analyse le firmware firmware.bin avec binwalk"
forensicsAI "analyse suspect.pdf avec pdfid"
forensicsAI "liste les processus de dump.mem avec volatility3"
forensicsAI "recupere les fichiers de disk.img avec foremost"

# Expert reverse engineering (analyse statique en lecture seule)
reverseAI "liste les imports de malware.dll"
reverseAI "identifie sample.exe avec detect-it-easy"
reverseAI "desassemble la fonction main de sample.exe avec radare2"
reverseAI "decompile app.apk avec jadx"

# Expert wireless (tests Wi-Fi, Bluetooth, RFID/NFC)
wirelessAI "capture les reseaux wifi sur wlan0mon"
wirelessAI "casse le wpa de capture.cap avec rockyou.txt"
wirelessAI "attaque le wps du bssid AA:BB:CC:DD:EE:FF sur wlan0mon"
wirelessAI "scanne les peripheriques bluetooth"

# Expert automotive (bus CAN)
automotiveAI "capture les trames can sur can0"
automotiveAI "envoie la trame 123#DEADBEEF sur can0"

# Expert AI tools (orchestration MCP, agents de codage, entrainement)
aiAI "lance le serveur mcpwn sur le port 1337"
aiAI "entraine un modele unsloth sur dataset.jsonl"

# Expert maintien d'acces (C2, backdoors, tunnels, evasion)
maintainingAI "cartographie active directory de corp.local avec bloodhound"
maintainingAI "ecoute sur le port 4444 avec pwncat"
maintainingAI "ouvre un tunnel iodine vers tunnel.example.com"
maintainingAI "lance nmap via proxychains sur 10.0.0.5"
maintainingAI "injecte un shellcode dans app.exe avec shellter"

# nmap / tshark (outils directs)
nmapAI "découverte des hôtes vivants sur 192.168.1.0/24"
tsharkAI "lis capture.pcap et affiche les requêtes dns"

# Catalogue (445 outils Parrot) : recherche + installés
aisec tools --search dns
aisec tools --installed

# Lister les experts (classes)
aisec experts

# Ne rien exécuter, juste voir la commande (et son risque)
aisec --dry-run dns "MX example.com"

# Sortie JSON (pour scripter)
aisec --json dns "qui possede example.com"
```

### Options globales

| Option | Effet |
|--------|-------|
| `--provider {ollama,openai,groq,none}` | backend LLM |
| `--model NAME` | modèle à utiliser |
| `--dry-run` | affiche sans exécuter |
| `--json` | sortie machine |
| `--report FICHIER` | écrit un rapport d'audit (`.json`, `.md` ou `.html`) |
| `--routing {heuristic,llm}` | sélection d'expert : mots-clés (défaut) ou LLM |
| `--yes` | auto-approuve les confirmations |
| `--auto-approve-risk LEVEL` | plafond de risque pour la session |

---

## Orchestrateur et rapports (jalon 4)

`aisec` sait enchaîner plusieurs demandes et produire un **rapport d'audit**.

### Routage par LLM (optionnel)

Par défaut le routeur est **heuristique** (mots-clés, déterministe). Avec un
provider actif, on peut demander au LLM de choisir la classe :

```bash
aisec ask --routing llm "trouve les failles du portail web"
# le LLM choisit l'expert (webapp), puis l'outil ; repli heuristique si échec
```

### Rapport d'audit

La commande `report` exécute plusieurs demandes (séparées par `;`) et écrit un
rapport consolidé :

```bash
aisec report -o audit.html \
  "analyse les ports 22, 80, 8080 de la cible 10.0.0.1 ; \
   audite le tls de example.com ; \
   brute force les répertoires de https://example.com"
```

Formats : `.html` (autonome, CSS inline), `.md`, `.json`. Le rapport contient
les constats triés par sévérité, la commande, le risque et la sortie de chaque
exécution.

Une seule demande peut aussi produire un rapport avec `--report` :

```bash
aisec nmap --report scan.md "scan des ports 22,80 sur 10.0.0.1"
```

### Politique de risque par classe (niveau 3)

Au-dessus du niveau 2, chaque **classe** peut durcir sa politique : les classes
offensives (`exploitation`, `post-exploit`, `wireless`, `passwords`) exigent
**toujours** une confirmation, même pour un outil de risque faible. La politique
combinée est la plus stricte des deux (on ne relâche jamais une borne globale).
Surchargeable dans `[expert_policies]` :

```toml
[expert_policies]
exploitation = { max_auto_risk = "low", require_confirmation = true }
```

### IA dédiée par expert

`[expert_models]` branche un modèle par classe (une IA entraînée par domaine) ;
l'orchestrateur l'applique automatiquement à l'expert sélectionné.

```toml
[expert_models]
dns = "aisec-dns:latest"
```

---

## Sécurité

`aisec` génère des commandes : il les vérifie **avant** exécution, puis les
**contrôle**.

- Jamais de `shell=True` : les commandes sont lancées avec une liste d'arguments.
- Le binaire est verrouillé (une commande `nmap` ne peut pas devenir `rm`).
- Les métacaractères shell (`;`, `|`, `$`, backticks, ...) sont rejetés.
- Les CIDR trop larges (ex : `/0`) et les cibles non routables sont bloqués.
- Les cibles privées/internes génèrent un avertissement (ou un refus).
- Politique de risque : `allow` / `confirm` / `deny` avant chaque exécution.
- `--dry-run` (ou `dry_run = true`) n'exécute rien.

⚠️ N'utilise ces outils que sur des systèmes que tu es autorisé à tester.

---

## Architecture

```
aisec/
  catalog/      catalogue d'outils (445 outils Parrot) + recherche/installés
  core/         moteur: config, safety, control, policies (niveau 3),
                executor, intent, analyzer, engine, orchestrator, registry
  experts/      experts par classe: base.py (socle) + dns, info, vulnerability,
                webapp, passwords, sniffing, exploitation, forensics, reverse,
                post_exploit, reporting, wireless, ai, automotive, maintaining,
                misc
  providers/    backends LLM: ollama (local), openai-compatible (API)
  report.py     rapport d'audit: agregation + export JSON / Markdown / HTML
  tools/        plugins: nmap, tshark, dig, host, whois, masscan, arp-scan,
                sslscan, wafw00f, dnsrecon, bettercap, passwords (13 outils),
                exploitation (18 outils) + spec.py (base déclarative)
                + vuln_scan/cisco/stress/fuzz/voip (classe 02 : 46 outils)
                + web_crawl/web_vuln/web_misc + webapp (classe 03 : 38 outils)
                + outils forensiques (classe 11 : fls, mmls, icat, foremost,
                  scalpel, binwalk, bulk_extractor, pdfid, pdf-parser, yara,
                  volatility3, regripper, reglookup, galleta, vinetto, hashdeep,
                  ssdeep, rkhunter, chkrootkit, extundelete, dc3dd, ddrescue)
                + outils reverse (classe 07 : rabin2, radare2, rahash2, rasm2,
                  radiff2, rizin, rz-hash, rz-find, gdb, bddisasm, die, apktool,
                  dex2jar, jadx, androguard, baksmali, smali)
                + post_exploit (classe 08 : 15 outils) + reporting (classe 12 :
                  4 outils)
                + outils wireless (classe 06 : airmon-ng, airodump-ng,
                  aireplay-ng, aircrack-ng, reaver, wifite, mdk4, pixiewps, bully,
                  cowpatty, asleap, bluesnarfer, blueranger, hcitool, mfoc, mfcuk,
                  nfc-list)
                + outils automotive (classe 13 : candump, cansend, cangen,
                  canconfig, canconvert, isotpdump)
                + outils IA (classe 14 : hexstrike-ai, mcpwn, opencode, pi-dev,
                  unsloth)
                + outils maintien d'acces (classe 10 : bloodhound, dnscat2,
                  villain, starkiller, convoc2, windows-binaries, powershell-empire,
                  pwncat, cryptcat, sbd, sliver, weevely, webacoo, laudanum,
                  nishang, webshells, htshells, iodine, dns2tcp, godoh, miredo,
                  proxychains, proxychains4, proxytunnel, ptunnel, pwnat, socat,
                  stunnel4, udptunnel, shellter, veil-evasion, hyperion, exe2hexbat)
                + misc (classe 15 : services systeme apache2/nginx/mariadb/
                  postgresql/openssh/metasploit/gvm, arduino, powershell,
                  chirp, nyx, firefox, coreutils, gpa, keepassxc, mat2,
                  sirikali, zulucrypt-gui, zulumount-gui, woeusb-ng)
  cli.py        CLI unifiée + commande `report` + alias (nmapAI, tsharkAI, dnsAI,
                infoAI, vulnerabilityAI, webappAI, passwordsAI, sniffingAI,
                exploitationAI, forensicsAI, reverseAI, postExploitAI,
                reportingAI, wirelessAI, aiAI, automotiveAI, maintainingAI,
                miscAI)
```

Flux : `intention → routeur → expert → outil → params → argv → garde-fous →
politique (niveaux 2+3) → exécution → analyse → rapport`.

### Ajouter un outil (plugin)

1. Créer `aisec/tools/mon_outil.py` avec une classe héritant de `Tool`
   (`build_argv`, `parse_intent`, `analyze`), un tuple `parameters` et un
   `risk` (`low`/`medium`/`high`/`critical`).
2. L'enregistrer via `register(MonOutil())`.
3. L'importer dans `aisec/core/registry.py::_load_builtins`.
4. (Optionnel) Ajouter un alias dans `pyproject.toml [project.scripts]`.

### Ajouter un expert (classe)

1. Créer `aisec/experts/ma_classe.py` avec un `Expert(...)` : `system_prompt`,
   `tool_names`, `keywords` (routage), `routing_rules` (outil + mots-clés).
2. Le `register(...)` dans `aisec/experts/__init__.py`.

C'est tout : le routeur, la CLI (`aisec ma_classe "..."`) et le rendu suivent.

---

## Tests

```bash
pytest -q
```

Couverture : moteur, garde-fous, catalogue Parrot, routage d'expert,
construction d'argv DNS, **politique de contrôle (niveau 2)**.
