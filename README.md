# aisec — suite d'outils de sécurité pilotés par IA

`aisec` traduit une **intention en langage naturel** en commande d'outil de
sécurité (nmap, tshark, ...), la vérifie, l'exécute et **analyse le résultat**.

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

## Pourquoi

Retenir la syntaxe exacte de chaque outil est pénible. Ici tu décris ce que tu
veux, `aisec` s'occupe des drapeaux, de la validation et de la lecture du résultat.
Chaque nouvel outil est un **plugin** : on étend la suite sans toucher au cœur.

## Installation

```bash
pip install -e ".[dev]"        # depuis le dépôt
# ou, pour l'affichage enrichi :
pip install -e ".[dev,ui]"
```

Les binaires des outils doivent être présents : `nmap`, `tshark`.

```bash
sudo apt-get install -y nmap tshark
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
aisec nmap "..." --provider ollama          # local (défaut)
aisec nmap "..." --provider none            # heuristique seule
aisec nmap "..." --provider openai --model gpt-4o-mini   # API (données envoyées)
```

### Configuration

Copie `aisec.example.toml` vers `./aisec.toml` (par projet) ou
`~/.config/aisec/config.toml` (global). Variables d'environnement `AISEC_*`
possibles (`AISEC_PROVIDER`, `AISEC_MODEL`, `AISEC_API_KEY`, ...).

## Utilisation

```bash
# Lister les outils
aisec tools

# nmap
nmapAI "découverte des hôtes vivants sur 192.168.1.0/24"
nmapAI "scan udp des 100 ports les plus courants sur 10.0.0.5"
aisec nmap "scanne les ports 22,80,8080 sur target.com" --json

# tshark
tsharkAI "capture le trafic http sur eth0 pendant 100 paquets"
tsharkAI "lis capture.pcap et affiche les requêtes dns"

# Ne rien exécuter, juste voir la commande
aisec nmap "ports 443 sur example.com" --dry-run
```

Sortie JSON (pratique pour scripter) :

```bash
aisec nmap "ports 22,80 sur 10.0.0.1" --json
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
  core/         moteur: config, safety, executor, intent, analyzer, engine, registry
  providers/    backends LLM: ollama (local), openai-compatible (API)
  tools/        plugins: nmap, tshark, ...
  cli.py        CLI unifiée + alias par outil (nmapAI, tsharkAI)
```

Flux : `intention → params → argv → validation → exécution → analyse`.

### Ajouter un outil

1. Créer `aisec/tools/mon_outil.py` avec une classe héritant de `Tool`
   (`build_argv`, `parse_intent`, `analyze`) et un tuple `parameters`.
2. L'enregistrer via `register(MonOutil())`.
3. L'importer dans `aisec/core/registry.py::_load_builtins`.
4. (Optionnel) Ajouter un alias dans `pyproject.toml [project.scripts]`.

C'est tout : la CLI, la traduction LLM et le rendu s'appliquent automatiquement.

## Tests

```bash
pytest -q
```
