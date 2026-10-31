# Feuille de route — aisec

État vérifié le **2026-10-31**. Dépôt : https://github.com/kadohack12/aisec

---

## 0. Consolidation des branches d'agents ✅

Trois agents avaient produit des branches parallèles se recouvrant. Elles ont
été **fusionnées intelligemment** sur `consolidate/experts` :

| Branche d'origine | PR | Apport retenu |
|-------------------|----|---------------|
| `feat/experts-5-classes` | — | experts `info` (classe 01) et `sniffing` (classe 09), socle `tools/base.py` |
| `expert-02-vulnerability-analysis` | #2 | classe 02 : expert `vulnerability` (46 outils) + base déclarative `tools/spec.py` |
| `feat/experts-web-vuln-passwords` | #1 | classe 03 : `webapp` (18 outils) ; classe 05 : `passwords` (13 outils) |
| `feat/experts-exploitation` | #3 | classe 04 : expert `exploitation` (18 outils) |
| `expert-03-webapp-analysis` | #4 | classe 03 complète : `webapp` (38 outils via web_crawl/web_vuln/web_misc) |
| `feat/experts-forensics` | #6 | classe 11 : expert `forensics` (22 outils) |
| `feat/experts-reverse` | #7 | classe 07 : expert `reverse` (17 outils) |
| `feat/experts-jalon3` | #8 | classes 08 : `post-exploit` (15 outils) et 12 : `reporting` (4 outils) |
| `feat/experts-jalon4` | #9 | classes 06 : `wireless` (19 outils), 13 : `automotive` (6) et 14 : `ai` (5) |

**Règle d'arbitrage** : quand deux branches livraient la même classe, on a gardé
l'implémentation la plus **complète**, puis supprimé les doublons.

- Classe 02 : `vulnerability` (46 outils, PR #2) > `vuln` (11 outils) → `vuln` retiré.
- Classe 03 : `webapp` 38 outils (expert-03) > `webapp` 18 outils (PR #1) → `tools/webapp.py` retiré.
- Classe 05 : `passwords` (13 outils, PR #1) > `password` (4 outils) → `password` retiré.
- Classes 01 et 09 : seuls `info` et `sniffing` (lot 5-classes) existaient.
- Classe 04 : `exploitation` (PR #3), aucun recouvrement.
- Classe 11 : `forensics` (PR #6), aucun recouvrement.
- Classe 07 : `reverse` (PR #7), aucun recouvrement.
- Classes 08 et 12 : `post-exploit` et `reporting` (PR #8), aucun recouvrement.
- Classes 06, 13 et 14 : `wireless`, `automotive` et `ai` (PR #9), aucun recouvrement.

Résultat sur `main` : **14 experts** (dont `dns`), **214 outils uniques**,
**aucune collision de nom**, **349 tests** verts.

---

## 1. État de `main`

`main` = branche courante (socle + expert `dns` + contrôle niveau 2 + catalogue
445 outils + répartition en 15 classes + 14 experts + orchestrateur + rapports).
La consolidation des branches d'agents est **terminée** : toutes les PR sont
fusionnées et fermées, il ne reste que `main`.

Le socle est complet ; la suite consiste à **approfondir** les classes existantes
(jalon 2) et à couvrir les classes restantes (classe 10, `misc`).

---

## 2. Jalons

### Jalon 0 — socle ✅ (fusionné sur `main`)
- [x] Catalogue Parrot (445 outils) + recherche + détection installés
- [x] Expert `dns` (`dig`/`host`/`whois`) — modèle de référence
- [x] Contrôle **niveau 2** : risque + `allow`/`confirm`/`deny`, `--yes`,
      `--auto-approve-risk`, confirmation interactive
- [x] Répartition en 15 classes (`docs/CLASSES.md`, `docs/classes.json`)
- [x] 43 tests

### Jalon 1 — 14 experts ✅ (fusionnés sur `main`)
- [x] Consolider les branches d'agents en **une** base propre
- [x] Dédupliquer les outils partagés (une seule classe `Tool` par binaire)
- [x] Experts `info`, `vulnerability`, `webapp`, `exploitation`, `passwords`, `wireless`, `reverse`, `post-exploit`, `sniffing`, `forensics`, `reporting`, `automotive`, `ai`
- [x] Adopter `tools/spec.py` (base déclarative) comme standard
- [x] 349 tests (14 experts, 214 outils)

### Jalon 2 — profondeur des classes amorcées
- [ ] Classe 01 : sous-catégories OSINT, SMTP, SMB, SNMP, SSL, IDS/IPS, Route
- [ ] Classe 11 : imagerie (autopsy, guymager, ewf-tools), carving complementaire, journaux
- [ ] Classe 07 : ghidra, edb-debugger, rizin-cutter, bytecode-viewer, jd-gui (CLI)
- [ ] Classe 02 : Cisco, Fuzzing, VoIP, Stress (couverture complète)
- [ ] Classe 03 : CMS, Crawlers, Proxies, Scanners web (couverture complète)
- [ ] Classe 05 : online / offline / local / wordlists
- [ ] Classe 09 : sniffers dédiés + spoofing/MITM (hors `tshark`)

### Jalon 3 — nouvelles classes
- [x] 04 Exploitation Tools (`exploitation`, 18 outils)
- [x] 06 Wireless Testing (`wireless`, 19 outils)
- [x] 07 Reverse Engineering (`reverse`, 17 outils)
- [x] 08 Post Exploitation (`post-exploit`, 15 outils)
- [ ] 10 Maintaining Access
- [x] 11 Digital Forensics (`forensics`, 22 outils)
- [x] 12 Reporting (`reporting`, 4 outils)
- [x] 13 Automotive (`automotive`, 6 outils) · [x] 14 AI Tools (`ai`, 5 outils) · [x] `misc` (`misc`, 21 outils)

### Jalon 4 — orchestrateur & IA par expert ✅
- [x] Orchestrateur unique (`core/orchestrator.py`) : routeur -> expert -> outil -> exécution
- [x] IA dédiée par expert (`[expert_models]`) appliquée par l'orchestrateur
- [x] Routage LLM optionnel (`--routing llm`), repli heuristique déterministe
- [x] Sortie rapport (classe 12) + export JSON / Markdown / HTML (`report.py`, `aisec report`)
- [x] Politique de risque par classe (`core/policies.py`, niveau 3, `[expert_policies]`)
- [x] 381 tests (14 experts, 214 outils)

### Jalon 5 — couverture complète du catalogue
- [ ] Classe 10 `maintaining-access` (34 outils : bloodhound, dnscat2, iodine,
      proxychains, socat, stunnel4, weevely, nishang, veil, shellter, pwncat...)
- [ ] Classe `misc` (21 outils : mariadb, postgresql, nginx, apache2, gvm...)
- [ ] Compléter les classes amorcées : la couverture actuelle est d'environ
      **40 % du catalogue** (180/445 outils exposés).

---

## 3. Rappels pour les agents

- Contrat détaillé : `docs/ASSIGNMENT.md` (outil → expert → tests).
- Modèle à copier : `aisec/experts/dns.py`.
- **Obligatoire** : passer par la politique de contrôle (niveau 2), jamais de
  shell, argv en liste.
- **Coordination** : une classe = une branche = une PR ; ne pas re-toucher un
  outil déjà livré (vérifier `aisec/core/registry.py` avant d'ajouter un nom).
- Regénérer la répartition après évolution du catalogue : `python docs/gen_classes.py`.
