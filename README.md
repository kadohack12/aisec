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
| `--yes` | auto-approuve les confirmations |
| `--auto-approve-risk LEVEL` | plafond de risque pour la session |

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
  core/         moteur: config, safety, control, executor, intent,
                analyzer, engine, registry
  experts/      experts par classe: base.py (socle) + dns.py, vuln.py,
                webapp.py, passwords.py
  providers/    backends LLM: ollama (local), openai-compatible (API)
  tools/        plugins: nmap, tshark, dig, host, whois + outils web,
                vulnerabilites et mots de passe
  cli.py        CLI unifiée + alias (nmapAI, tsharkAI, dnsAI)
```

Flux : `intention → expert → outil → params → argv → garde-fous → politique →
exécution → analyse`.

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
