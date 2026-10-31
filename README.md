# aisec — suite d'outils de sécurité pilotés par IA

`aisec` traduit une **intention en langage naturel** en commande d'outil de
sécurité (nmap, tshark, dig, ...), la vérifie, l'exécute et **analyse le résultat**.

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

## Principe : des experts par spécialité

La suite est organisée comme la taxonomie de Parrot (Information Gathering,
Vulnerability Analysis, Web, Password Attacks, Sniffing, Forensics, ...).
Chaque **classe** = un **expert** : une IA dédiée + ses outils + son analyseur.

```
Demande libre : "énumère les serveurs de noms de example.com"
        │
        ▼
   ROUTEUR (mots-clés / IA)  ──►  expert "dns"
        │
        ▼
   EXPERT DNS  •  IA dédiée (prompt spécialisé)  •  outils: dig, host, whois
        │
        ▼
   outil choisi (dig) + paramètres (NS) → commande → analyse
```

On construit **un expert à la fois**, on le teste, puis on en ajoute un autre.
À terme, un **orchestrateur unique** peut router vers tous les experts.

Chaque expert peut être branché sur **sa propre IA entraînée** (voir
`expert_models` dans la config), ou partager le LLM global.

## Pourquoi

Retenir la syntaxe exacte de chaque outil est pénible. Ici tu décris ce que tu
veux, `aisec` s'occupe des drapeaux, de la validation et de la lecture du résultat.
Chaque nouvel outil est un **plugin**, chaque nouvelle classe un **expert** : on
étend la suite sans toucher au cœur.

## Installation

```bash
pip install -e ".[dev]"        # depuis le dépôt
# ou, pour l'affichage enrichi :
pip install -e ".[dev,ui]"
```

Les binaires des outils doivent être présents :

```bash
sudo apt-get install -y nmap tshark dnsutils whois
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

Pour brancher une **IA dédiée par expert** :

```toml
[expert_models]
dns = "aisec-dns:latest"
web = "aisec-web:latest"
```

## Utilisation

```bash
# Demande libre: le routeur choisit l'expert
aisec ask "je veux les enregistrements MX de example.com"

# Expert DNS (IA dédiée à la classe DNS)
dnsAI "qui possede example.com"
aisec dns "résolution inverse de 8.8.8.8"
aisec dns "tente un transfert de zone sur example.com"

# nmap / tshark (outils directs)
nmapAI "découverte des hôtes vivants sur 192.168.1.0/24"
tsharkAI "lis capture.pcap et affiche les requêtes dns"

# Catalogue (445 outils Parrot): recherche + installés
aisec tools --search dns
aisec tools --installed

# Lister les experts (classes)
aisec experts

# Ne rien exécuter, juste voir la commande
aisec dns "MX example.com" --dry-run

# Sortie JSON (pour scripter)
aisec dns "qui possede example.com" --json
```

## Sécurité

`aisec` génère des commandes : il les vérifie **avant** exécution.

- Jamais de `shell=True` : les commandes sont lancées avec une liste d'arguments.
- Le binaire est verrouillé (une commande `nmap` ne peut pas devenir `rm`).
- Les métacaractères shell (`;`, `|`, `$`, backticks, ...) sont rejetés.
- Les CIDR trop larges (ex : `/0`) et les cibles non routables sont bloqués.
- Les cibles privées/internes génèrent un avertissement.
- `--dry-run` (ou `dry_run = true`) n'exécute rien.

⚠️ N'utilise ces outils que sur des systèmes que tu es autorisé à tester.

## Architecture

```
aisec/
  catalog/      catalogue d'outils (445 outils Parrot) + recherche/installés
  core/         moteur: config, safety, executor, intent, analyzer, engine, registry
  experts/      experts par classe: base.py (socle) + dns.py (expert DNS)
  providers/    backends LLM: ollama (local), openai-compatible (API)
  tools/        plugins: nmap, tshark, dig, host, whois
  cli.py        CLI unifiée + alias (nmapAI, tsharkAI, dnsAI)
```

Flux : `intention → expert → outil → params → argv → validation → exécution → analyse`.

### Ajouter un outil (plugin)

1. Créer `aisec/tools/mon_outil.py` avec une classe héritant de `Tool`
   (`build_argv`, `parse_intent`, `analyze`) et un tuple `parameters`.
2. L'enregistrer via `register(MonOutil())`.
3. L'importer dans `aisec/core/registry.py::_load_builtins`.
4. (Optionnel) Ajouter un alias dans `pyproject.toml [project.scripts]`.

### Ajouter un expert (classe)

1. Créer `aisec/experts/ma_classe.py` avec un `Expert(...)` : `system_prompt`,
   `tool_names`, `keywords` (routage), `routing_rules` (outil + mots-clés).
2. Le `register(...)` dans `aisec/experts/__init__.py`.

C'est tout : le routeur, la CLI (`aisec ma_classe "..."`) et le rendu suivent.

## Tests

```bash
pytest -q
```

