# Mettre en place et entraîner les IA — aisec

Ce document explique comment **brancher une IA** sur `aisec` (local d'abord) et
comment **l'entraîner / l'adapter** par classe d'outils. Aucune donnée ne sort de
la machine si vous restez sur Ollama.

> Rappel d'architecture : un **expert = une classe Parrot = une IA dédiée + ses
> outils**. Le routeur choisit d'abord l'expert (classe), puis l'expert choisit
> l'outil et ses paramètres. Les deux étapes peuvent utiliser le LLM, avec
> **repli heuristique déterministe** si aucun modèle n'est disponible.

---

## 1. Les providers (local d'abord)

| Provider | Valeur `provider` | Où tourne le modèle | Données |
|----------|-------------------|---------------------|---------|
| Ollama | `ollama` (défaut) | 100 % local | ne sortent jamais |
| API compatible OpenAI | `openai`, `groq` | distant | envoyées à l'API |
| Heuristique seule | `none` | aucun LLM | locales, déterministe |

`aisec` **retombe toujours** sur l'heuristique si le provider est injoignable :
l'outil reste utilisable sans aucune IA.

### 1.1 Local avec Ollama (recommandé)

```bash
# installer Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# récupérer un modèle de base
ollama pull llama3.1          # ou qwen2.5, mistral, llama3.2:3b (léger)

# vérifier
ollama list
```

Configuration minimale (`./aisec.toml` ou `~/.config/aisec/config.toml`) :

```toml
provider = "ollama"
model = "llama3.1"
ollama_host = "http://localhost:11434"
temperature = 0.1
```

Test :

```bash
aisec dns --provider ollama "les enregistrements MX de example.com"
aisec ask --routing llm "trouve les failles du portail web"   # le LLM choisit la classe
```

### 1.2 API distante (OpenAI / Groq)

```toml
provider = "groq"
api_base = "https://api.groq.com/openai/v1"
model = "llama-3.1-70b-versatile"
# api_key via AISEC_API_KEY / OPENAI_API_KEY / GROQ_API_KEY
```

```bash
export GROQ_API_KEY="..."     # jamais dans le dépôt
aisec --provider groq webapp "scanne les répertoires de https://cible.tld"
```

### 1.3 Heuristique seule (sans LLM)

```bash
aisec --provider none info "scan les ports 22,80,8080 de 10.0.0.1"
```

Le routage par mots-clés et `parse_intent` construisent la commande sans modèle.

---

## 2. Une IA dédiée par classe (`[expert_models]`)

Chaque expert peut utiliser **son propre modèle**. C'est le cœur du principe
« une IA entraînée par domaine » : un petit modèle spécialisé « passwords » est
plus fiable qu'un gros modèle généraliste sur cette tâche étroite.

```toml
model = "llama3.1"              # modèle global (repli)

[expert_models]
dns          = "aisec-dns:latest"
info         = "aisec-info:latest"
webapp       = "aisec-webapp:latest"
passwords    = "aisec-passwords:latest"
exploitation = "aisec-exploitation:latest"
```

`Config.model_for(expert_name)` résout le modèle, et l'orchestrateur
(`aisec/core/orchestrator.py`) l'applique automatiquement pour chaque expert.

---

## 3. Générer les jeux d'entraînement

Le savoir est **déjà dans le code** : `system_prompt`, `description`,
`parameters` et surtout les **`examples`** de chaque outil. Le script
`scripts/build_dataset.py` en dérive deux tâches supervisées, avec *exactement*
les prompts de production (importés de `aisec.experts.base`) :

1. **Routage de classe** : demande libre → `{"expert": "<nom>"}`
2. **Routage d'outil** : demande libre → `{"tool": "<nom>", "params": {...}}`

```bash
# format OpenAI/Ollama (messages), split 90/10
python scripts/build_dataset.py --out datasets

# format ChatML pour HuggingFace SFT / Unsloth
python scripts/build_dataset.py --out datasets --format chatml --split 0.9

# format Alpaca
python scripts/build_dataset.py --out datasets --format alpaca
```

Fichiers produits :

```
datasets/expert_routing.train.jsonl   datasets/expert_routing.val.jsonl
datasets/tool_routing.train.jsonl     datasets/tool_routing.val.jsonl
datasets/all.train.jsonl              datasets/all.val.jsonl
```

> **Le levier n°1 pour améliorer l'IA : écrire des `examples`.** Chaque exemple
> d'outil produit une paire d'entraînement. Le script affiche la couverture :
> `couverture exemples: N/M outils ont des examples`. Compléter les outils sans
> exemple (et en ajouter plusieurs par outil) est le moyen le plus direct
> d'augmenter la qualité.

### 3.1 Évaluer un modèle

Le script sait rejouer un dataset contre le provider actif et mesurer
l'**exactitude JSON** :

```bash
python scripts/build_dataset.py --eval datasets/expert_routing.val.jsonl --provider ollama
# -> accuracy: 34/36 = 94.4%
```

---

## 4. Adapter le modèle par classe

### 4.1 Ollama : Modelfile (le plus simple, sans GPU)

`build_dataset.py --modelfiles` écrit un `Modelfile` par expert : il fixe le
prompt système et injecte les exemples comme tours `MESSAGE` (few-shot
persistant, aucune étape d'entraînement lourde).

```bash
python scripts/build_dataset.py --modelfiles --out datasets --base-model llama3.1

ollama create aisec-info       -f datasets/Modelfile.info
ollama create aisec-passwords  -f datasets/Modelfile.passwords
ollama create aisec-webapp     -f datasets/Modelfile.webapp
# ... un modèle par classe

ollama list    # aisec-info:latest, aisec-passwords:latest, ...
```

Puis brancher ces modèles :

```toml
[expert_models]
info      = "aisec-info:latest"
passwords = "aisec-passwords:latest"
webapp    = "aisec-webapp:latest"
```

C'est la méthode **recommandée** pour démarrer : un « entraînement » immédiat,
100 % local, sans dataset à nettoyer.

### 4.2 Fine-tuning réel (LoRA / QLoRA) — hors ligne

Pour un vrai fine-tuning, générez le dataset au format ChatML puis utilisez un
outil standard. Exemple avec **Unsloth** (le paquet `unsloth` est déjà dans la
classe 14 du catalogue aisec) :

```python
# train_lora.py — squelette
from unsloth import FastLanguageModel
from datasets import load_dataset

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/llama-3.1-8b-bnb-4bit", max_seq_length=2048, load_in_4bit=True
)
model = FastLanguageModel.get_peft_model(model, r=16, lora_alpha=16)

data = load_dataset("json", data_files="datasets/tool_routing.train.jsonl", split="train")
# ... tokenizer + Trainer (SFTTrainer) sur le champ "text" (format ChatML)

model.save_pretrained("out/lora-info")
```

Puis exporter vers Ollama (GGUF) et enregistrer :

```bash
ollama create aisec-info -f Modelfile   # FROM ./out/lora-info.gguf
```

**Stratégie par classe** : un petit modèle (3–8B) fine-tuné **par expert** donne
d'excellents résultats sur une tâche étroite (choisir un outil + extraire des
paramètres), pour un coût d'entraînement faible. C'est exactement ce que permet
`[expert_models]`.

### 4.3 Boucle de contrôle qualité

1. `python scripts/build_dataset.py` → datasets + couverture.
2. `python scripts/build_dataset.py --eval ... --provider ollama` → accuracy de référence.
3. Ajouter/corriger des `examples`, regénérer, ré-évaluer.
4. Quand un modèle bat l'heuristique sur la tâche, l'activer via `--routing llm`
   ou `[expert_models]`.
5. **Toujours** garder `--provider none` comme filet de sécurité : il doit rester
   fonctionnel (déterminisme, aucune dépendance réseau).

---

## 5. Ce que l'IA ne fait jamais

- Elle ne construit **jamais** une ligne de shell : les commandes sont des
  **listes d'arguments** (`argv`), exécutées sans `shell=True`.
- Elle ne contourne **jamais** la politique de contrôle (niveaux 2 et 3) : risque,
  confirmation, refus des cibles privées s'appliquent quelle que soit la sortie
  du modèle.
- Une réponse LLM invalide (JSON malformé, outil inconnu) est **ignorée** au
  profit de l'heuristique — le modèle ne peut pas casser le flux.

Voir aussi : `README.md` (usage CLI), `docs/ROADMAP.md` (jalons),
`aisec.example.toml` (toutes les clés de configuration).
