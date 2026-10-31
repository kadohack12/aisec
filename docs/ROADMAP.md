# Feuille de route — aisec

État vérifié le **2026-10-31** (branches, PR, tests réels). Dépôt :
https://github.com/kadohack12/aisec

---

## 1. État des branches et PR

`main` = `3d2b382` (catalogue 445 outils + expert DNS + contrôle niveau 2 + docs
classes). **Toutes les branches d'agents partent de ce commit.**

| Branche | PR | Contenu | Tests | Base |
|---------|----|---------|-------|------|
| `main` | — | socle + expert `dns` + contrôle L2 | 43 ✅ | — |
| `feat/experts-web-vuln-passwords` | **#1** (draft) | 3 experts : `vuln` (11), `webapp` (18), `passwords` (13) | 80 ✅ | `3d2b382` |
| `expert-02-vulnerability-analysis` | **#2** (draft) | classe 02 complète : 46 outils + base déclarative `tools/spec.py` | 79 ✅ | `3d2b382` |
| `feat/experts-5-classes` | *aucune* | 5 experts : `info`, `vuln`, `web`, `password`, `sniffing` | 103 ✅ | `3d2b382` |

Les 3 branches **compilent et passent leurs tests** isolément. Aucune n'est
fusionnée : les 2 PR sont en **draft**.

### Problème : recouvrement entre branches

Les agents ont travaillé en parallèle sans se coordonner et se **recouvrent** :

| Classe | PR #1 | PR #2 | branche 5-classes |
|--------|:-----:|:-----:|:-----------------:|
| 01 Information Gathering | — | — | ✅ `info` |
| 02 Vulnerability Analysis | ✅ `vuln` | ✅ `vulnerability` | ✅ `vuln` |
| 03 Web Application | ✅ `webapp` | — | ✅ `web` |
| 05 Password Attacks | ✅ `passwords` | — | ✅ `password` |
| 09 Sniffing & Spoofing | — | — | ✅ `sniffing` |

**Outils enregistrés en double** (nom identique dans ≥ 2 branches) :
`testssl`, `sfuzz`, `siege`, `slowhttptest`, `cisco-torch`, `nipper-ng`,
`dhcpig`, `t50`, `unix-privesc-check`, `yersinia` — plus les socles partagés
`nmap`, `tshark`, `dig`, `host`, `whois`.

**Fichiers de couture modifiés par les 3** (conflits garantis) :
`README.md`, `aisec/cli.py`, `aisec/core/registry.py`,
`aisec/experts/__init__.py`, `pyproject.toml`, `docs/ASSIGNMENT.md`.

### Stratégie de consolidation recommandée

Intégrer **séquentiellement** (jamais 2 PR en parallèle), dans cet ordre :

1. **`feat/experts-5-classes`** d'abord (le plus large : 5 classes, 103 tests,
   et il ajoute des helpers dans `aisec/tools/base.py` qui serviront de socle).
   Ouvrir sa PR, la fusionner.
2. **`expert-02-vulnerability-analysis`** (PR #2) ensuite : apporte
   `aisec/tools/spec.py`, une **base déclarative** (flags/options/règles) —
   à adopter comme standard pour tous les futurs plugins. Arbitrer les
   doublons de la classe 02 en gardant la version la plus complète
   (`spec.py` + 46 outils).
3. **`feat/experts-web-vuln-passwords`** (PR #1) en dernier : récupérer
   uniquement les outils **non déjà présents** (ex. `arjun`, `wpscan`,
   `joomscan`, `hashcat`, `medusa`, `ncrack`, `chntpw`, `ophcrack`,
   `wapiti`, `xsser`, `skipfish`, `httrack`, `dirb`, `dirsearch`,
   `feroxbuster`, `gospider`...).

Après chaque fusion : `pytest -q`, puis fermer/mettre à jour la PR suivante.
Les 2 PR sont en **draft** → à passer en « ready for review » une par une.

---

## 2. Jalons

### Jalon 0 — socle ✅ (fusionné sur `main`)
- [x] Catalogue Parrot (445 outils) + recherche + détection installés
- [x] Expert `dns` (`dig`/`host`/`whois`) — modèle de référence
- [x] Contrôle **niveau 2** : risque + `allow`/`confirm`/`deny`, `--yes`,
      `--auto-approve-risk`, confirmation interactive
- [x] Répartition en 15 classes (`docs/CLASSES.md`, `docs/classes.json`)
- [x] 43 tests

### Jalon 1 — 5 experts (en cours, à consolider)
- [ ] Consolider les 3 branches ci-dessus en **une** base propre
- [ ] Dédupliquer les outils partagés (une seule classe `Tool` par binaire)
- [ ] Expert `info` (classe 01, hors `dns`) + `vuln` + `web` + `password` + `sniffing`
- [ ] Adopter `tools/spec.py` (base déclarative) comme standard
- [ ] Objectif : ~110+ tests sur `main`

### Jalon 2 — profondeur des classes amorcées
- [ ] Classe 01 : sous-catégories OSINT, SMTP, SMB, SNMP, SSL, IDS/IPS, Route
- [ ] Classe 02 : Cisco, Fuzzing, VoIP, Stress (couverture complète)
- [ ] Classe 03 : CMS, Crawlers, Proxies, Scanners web (couverture complète)
- [ ] Classe 05 : online / offline / local / wordlists
- [ ] Classe 09 : sniffers dédiés + spoofing/MITM (hors `tshark`)

### Jalon 3 — nouvelles classes
- [ ] 04 Exploitation Tools
- [ ] 06 Wireless Testing
- [ ] 07 Reverse Engineering
- [ ] 08 Post Exploitation
- [ ] 10 Maintaining Access
- [ ] 11 Digital Forensics
- [ ] 12 Reporting · 13 Automotive · 14 AI Tools · `misc`

### Jalon 4 — orchestrateur & IA par expert
- [ ] Orchestrateur unique : le routeur choisit **la classe** puis l'expert
- [ ] IA dédiée par expert (`[expert_models]`, déjà câblé)
- [ ] Sortie rapport (classe 12 Reporting) + export JSON/HTML
- [ ] Table de politiques de risque par classe (affiner au-delà du `risk` par outil)

---

## 3. Rappels pour les agents

- Contrat détaillé : `docs/ASSIGNMENT.md` (outil → expert → tests).
- Modèle à copier : `aisec/experts/dns.py`.
- **Obligatoire** : passer par la politique de contrôle (niveau 2), jamais de
  shell, argv en liste.
- **Coordination** : une classe = une branche = une PR ; ne pas re-toucher un
  outil déjà livré (vérifier `aisec/core/registry.py` avant d'ajouter un nom).
- Regénérer la répartition après évolution du catalogue : `python docs/gen_classes.py`.
