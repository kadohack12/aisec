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

Résultat sur `main` : **11 experts** (dont `dns`), **184 outils uniques**,
**aucune collision de nom**, **292 tests** verts.

---

## 1. État de `main`

`main` = `8f2a743` (socle + expert `dns` + contrôle niveau 2 + catalogue 445
outils + répartition en 15 classes). La consolidation est prête à être
fusionnée par-dessus (branche `consolidate/experts`).

---

## 2. Jalons

### Jalon 0 — socle ✅ (fusionné sur `main`)
- [x] Catalogue Parrot (445 outils) + recherche + détection installés
- [x] Expert `dns` (`dig`/`host`/`whois`) — modèle de référence
- [x] Contrôle **niveau 2** : risque + `allow`/`confirm`/`deny`, `--yes`,
      `--auto-approve-risk`, confirmation interactive
- [x] Répartition en 15 classes (`docs/CLASSES.md`, `docs/classes.json`)
- [x] 43 tests

### Jalon 1 — 11 experts ✅ (fusionnés sur `main`)
- [x] Consolider les branches d'agents en **une** base propre
- [x] Dédupliquer les outils partagés (une seule classe `Tool` par binaire)
- [x] Experts `info`, `vulnerability`, `webapp`, `exploitation`, `passwords`, `reverse`, `post-exploit`, `sniffing`, `forensics`, `reporting`
- [x] Adopter `tools/spec.py` (base déclarative) comme standard
- [x] 292 tests (11 experts, 184 outils)

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
- [ ] 06 Wireless Testing
- [x] 07 Reverse Engineering (`reverse`, 17 outils)
- [x] 08 Post Exploitation (`post-exploit`, 15 outils)
- [ ] 10 Maintaining Access
- [x] 11 Digital Forensics (`forensics`, 22 outils)
- [x] 12 Reporting (`reporting`, 4 outils) · [ ] 13 Automotive · [ ] 14 AI Tools · [ ] `misc`

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
