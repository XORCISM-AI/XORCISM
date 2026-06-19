# XORCISM — Plateforme unifiée open source de gestion de la cybersécurité

> **Exposition au cyber-risque global.** Une plateforme auto-hébergée pour gérer
> les actifs, la configuration, les vulnérabilités, les menaces, la conformité et
> les incidents — et les transformer en un score de risque d'entreprise unique,
> recalculé en continu.

![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20_LTS-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-better--sqlite3-003B57?logo=sqlite&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20%C2%B7%20D3FEND%20%C2%B7%20CAPEC-C8102E)
![EBIOS RM](https://img.shields.io/badge/EBIOS-Risk%20Manager-0055A4)
![STIX/TAXII](https://img.shields.io/badge/STIX%2FTAXII-2.1-6f42c1)
![Self-hosted](https://img.shields.io/badge/Auto--h%C3%A9berg%C3%A9-✔-success)

**[🇬🇧 English](README.md) · 🇫🇷 Français**

**🌐 [xorcism.ai](https://xorcism.ai) · 📖 [Installation](SETUP.MD) · 🧩 [Prérequis](REQUIREMENTS.MD) · ▶ [Chaîne YouTube](https://www.youtube.com/channel/UCk6OWxMBg1H4gHTZdpZGAhA)**

---

## 🎯 Présentation

Les équipes sécurité jonglent avec une dizaine d'outils déconnectés — une CMDB
ici, un scanner de vulnérabilités là, un tableur GRC, un flux CTI, un outil de
ticketing, un registre des risques — et passent l'essentiel de leur temps à les
réconcilier plutôt qu'à réduire le risque. XORCISM unifie tout le **cycle de vie
de l'exposition** derrière une seule application pilotée par le schéma et un seul
modèle d'identité : chaque actif, CVE, mesure de sécurité, acteur de menace et
incident vit au même endroit et alimente le même score de risque.

Et cela ne s'arrête pas à l'inventaire : une **boucle offensive-défensive**
intégrée enchaîne les outils de reconnaissance et d'exploitation, priorise ce qui
est *réellement* exploitable, valide les chemins d'attaque vers vos joyaux,
quantifie l'impact financier et prouve vos mesures de sécurité — en continu, de
l'OSINT jusqu'au comité de direction.

La plateforme est **entièrement auto-hébergée** : un serveur Node.js/TypeScript
au-dessus d'une famille de bases SQLite, avec des importeurs et connecteurs
Python optionnels. Pas de SaaS, pas de télémétrie : vos données ne quittent
jamais votre infrastructure.

### À qui s'adresse XORCISM

| Profil | Usage de XORCISM |
|---|---|
| **CISO / RSSI** | Score de risque d'entreprise, tableau de bord exécutif, posture de conformité, études EBIOS RM |
| **VOC / Analyste vulnérabilités** | Inventaire d'actifs, triage CVE/KEV/EPSS, ingestion de scans via connecteurs |
| **GRC / Auditeur** | Politiques et mesures, audits, preuves, workflow des constats, questionnaires OCIL |
| **CTI / Analyste menaces** | Entités STIX, matrices ATT&CK/D3FEND/A3M, chasses, hypothèses, graphe de menaces |
| **Red / Purple team** | Playbooks d'attaque chaînés (OSINT→exploit, Metasploit), analyse des chemins d'attaque et points de passage, couverture de détection purple-team, émulation BAS, programmes de bug bounty |
| **SOC / Blue team** | Gestion des alertes et incidents, ticketing, de la détection à la réponse |

### Pourquoi XORCISM

- **Un seul modèle de risque.** Actifs, vulnérabilités et valeur se combinent en
  un `RiskScore` par actif et un `EnterpriseRiskScore` par locataire, recalculés
  toutes les 30 s.
- **Gestion de l'exposition en boucle fermée.** Un flux continu — **découvrir**
  (chaîne OSINT + auto-inventaire) → **prioriser** (fusion d'exploitabilité) →
  **valider** (chemins d'attaque et purple-team) → **quantifier** (impact $ d'un
  ransomware) → **défendre** (couverture de détection, D3FEND) → **se conformer**
  (mesures prouvées en direct par la télémétrie). Sans recoller les outils ni
  passer par des tableurs.
- **Explorateur piloté par le schéma.** Chaque table génère un formulaire et une
  grille ; ajoutez une table à la base et elle apparaît dans l'UI après un
  redémarrage — sans code.
- **Standards intégrés.** MITRE ATT&CK / ATLAS / D3FEND / CAPEC, STIX/TAXII 2.1,
  Sigma, OVAL, OCIL, EBIOS Risk Manager, CVE/KEV/EPSS et référentiels GRC (ISO
  27001, NIST CSF/800-53, CIS, NIS2, DORA, CRA, SOC 2).
- **Extensible par simple dépôt de fichiers.** Un catalogue **recherchable de
  300+ connecteurs de sécurité** et un modèle de worker distant ; on en ajoute un
  avec un manifeste `connector.json` — sans recompilation.
- **Multi-tenant et RBAC.** Cloisonnement par locataire au niveau ligne et
  contrôle d'accès par rôle, avec connexion par clé d'accès (WebAuthn) et OIDC
  optionnel.
- **10 langues d'interface.** EN, FR, DE, IT, ES, PT, 中文, 日本語, العربية (RTL), Русский.

---

## ✨ Fonctionnalités

### 🗂️ Gestion de l'exposition (VOC / CTEM)

- **Gestion des actifs** — inventaire, propriétaires, valeur métier/financière,
  étiquettes, exposition ; scoring de risque par actif avec historique.
- **Graphe de surface d'attaque** — une carte interactive centrée sur l'actif,
  reliant chaque actif à ses applications, CPE, vulnérabilités, propriétaires,
  menaces et incidents (`/attack-surface`, accessible depuis le formulaire ASSET ;
  focus sur un actif ou tout le locataire, filtre par type, lien direct vers chaque formulaire).
- **Gestion de la configuration** — nommage CPE, définitions et audits **OVAL**.
- **Gestion des vulnérabilités** — CVE avec **KEV**, **CVSS** et **EPSS** ;
  recherches CIRCL et OSV ; **recherche Exploit-DB** (index SearchSploit, recherche
  CVE→exploit public sur le formulaire VULNERABILITY avec « marquer exploitable » en
  un clic) ; lien direct SOCRadar IOC-Radar pour les références CVE ; suivi des
  programmes et soumissions de **bug bounty**.
- **Expositions prioritaires (score de fusion)** — un **score unique d'exploitabilité
  et de pertinence** par vulnérabilité (`/exposure`) fusionnant EPSS + CVSS + **CISA
  KEV** + **exploits publics (Exploit-DB)** + **CTI « dans la nature »** + **rayon
  d'impact** (actifs affectés × valeur métier), classé en liste « corriger en premier ».
- **Chemins d'attaque & points d'étranglement** — graphe d'accessibilité (`/attack-path`)
  reliant actifs exposés sur Internet → joyaux de la couronne (liens sous-réseau + BIA,
  coût pondéré par l'exploitabilité de fusion) ; Dijkstra cartographie le chemin le plus
  facile vers chaque joyau et désigne le **point d'étranglement** — le correctif unique
  qui coupe le plus de routes d'attaque.
- **Scénario rançongiciel → $** — rejouez les TTP d'un vrai groupe de rançongiciel
  ATT&CK (`/ransomware`) sur votre parc et quantifiez l'**impact financier** via un
  modèle FAIR transparent : **SLE** (perte primaire = valeur à risque + rançon +
  reprise), **ALE** (× un ARO majoré par l'exposition Internet et les KEV), et le
  **résiduel avec contrôles** (sauvegardes hors ligne + segmentation). Affiche les
  phases de la kill chain couvertes, le rayon d'impact (actifs valorisés en $) et les
  **contre-mesures D3FEND** qui brisent la chaîne — le pont sécurité↔métier pour le conseil.
- **Conformité prouvée en continu** — chaque objectif de contrôle est évalué **en
  direct depuis votre télémétrie de sécurité** (`/assurance`), au lieu de captures
  d'écran annuelles : couverture de détection (Sigma), exposition KEV/exploit,
  classification des actifs, exposition Internet, récence des pentests, clôture des
  constats et **défense informée par la menace (ATT&CK/D3FEND)** — mappés à **ISO
  27001 / NIST CSF** avec un statut prouvé/partiel/lacune et un honnête « attestation
  requise » là où la télémétrie ne peut décider. Une conformité qui se reprouve à chaque chargement.
- **Veille CTI qui agit** — `/cti-watch` recoupe le renseignement en direct (**CISA
  KEV** + rapports de menace ingérés) avec votre inventaire d'actifs et ne fait
  remonter **que ce qui vous concerne**, avec **ouverture de ticket en un clic** (XTICKET).
- **Dérive de surface d'attaque** — `/drift` capture votre surface externe et compare
  les captures successives : actifs **apparus, disparus, ou nouvellement exposés sur
  Internet**. Se marie à la chaîne de découverte OSINT pour une surveillance continue.
- **Hub de contenu** — `/content` partage/réutilise le contenu en fichiers portables :
  **playbooks d'attaque** (import de recettes communautaires), **bundle de règles
  Sigma**, et un document **OpenVEX**.
- **Tableau de bord exécutif** — score de risque d'entreprise, répartition des
  vulnérabilités, valeur financière, **exposition au risque = risque × valeur**,
  nuage d'étiquettes d'actifs, tendances d'incidents (Chart.js).

### 🛡️ Gouvernance, risques et conformité (GRC)

- **Conformité** — cycle de vie des politiques, standards et procédures ; audits,
  preuves, état de préparation ; **workflow des constats** ; risque quantitatif
  **CRQ / FAIR** sur le registre. Référentiels : ISO 27001, NIST CSF, NIST
  800-53, CIS Controls, NIS2, DORA, CRA, SOC 2.
- **Politiques & Documents** — une vue de gouvernance sur les informations
  documentées : **cycle de vie** des politiques (brouillon → en revue → approuvée
  → publiée → retirée) et **registre des documents contrôlés**, avec un score de
  gouvernance par politique et une worklist (revues échues, politiques non
  publiées ou sans propriétaire, versions manquantes, documents expirés).
  Comprend un socle de **politiques ISO/IEC 42001:2023 (Système de Management de
  l'IA) en anglais et en français**, prêt à charger.
- **EBIOS Risk Manager** — la méthode ANSSI complète à 5 ateliers (cadrage et
  socle de sécurité, sources de risque, scénarios stratégiques et opérationnels,
  traitement) avec un **mode Express**, des valeurs métier, des biens supports,
  des événements redoutés (DICT), des sources de risque et un **écosystème de
  parties prenantes avec niveaux et zones de menace calculés automatiquement**.
- **TPRM** — évaluations de risque tiers / fournisseurs et questionnaires.
- **Questionnaires OCIL** — création compatible OCIL 2.0, import/export XML et un
  bouton « suggérer une réponse » par IA (optionnel).
- **Analyse d'impact métier (BIA)** — audits et entrées avec listes d'actifs
  éditables, ainsi qu'un **graphe de dépendances** : une carte des entrées BIA
  (colorées par criticité) et de leurs dépendances, avec **propagation
  d'impact** — cliquez sur une entrée pour voir tout ce qui tombe si elle
  défaille, le RTO le plus serré et la pire criticité impactée.

### 🔭 Menaces et détection

- **Gestion des menaces (CTI)** — entités STIX (acteurs, malwares, outils,
  campagnes, indicateurs, observables) avec propriétés communes façon OpenCTI
  (Confidence, TLP, Labels, Score), **observations (sightings)** et **relations**.
- **Flux et rapports de menaces** — un **lecteur RSS CTI** curé (33 flux) et des
  rapports de menaces avec **extraction automatique d'IOC** (IP, domaines, URL,
  empreintes, CVE) dans la table `IOC` ; **enrichissement CVE** par rapport,
  **listes de surveillance avec alertes**, besoins prioritaires de renseignement
  (**PIR**) et un **générateur de note de synthèse** par IA locale.
- **Chasse aux menaces et détection** — chasses, hypothèses et une vue d'ensemble
  IOC/techniques avec un **assistant de chasse** par IA locale ; **3 750+ règles
  de détection Sigma** consultables et reliées aux techniques ATT&CK.
- **Matrices MITRE** — **ATT&CK** (Enterprise / Mobile / ICS / **ATLAS**),
  contre-mesures défensives **D3FEND** (mappées à ATT&CK et à `XORCISM.CONTROL`),
  et **A3M — Agentic AI Attack Matrix**.
- **LLM ATT&CK Navigator (Anthropic)** — une **surcouche** d'exposition à l'IA sur
  la matrice ATT&CK : les techniques réellement employées par les acteurs assistés
  par IA, teintées selon leur prévalence (% de comptes bannis), d'après l'analyse
  Anthropic 2026. Activable sur `/attack` à côté de la couche de couverture BAS.
- **Émulation d'adversaire (BAS)** — plans d'émulation, tests atomiques et
  exécuteurs, et une **heatmap de couverture ATT&CK** superposée à la matrice.
- **Enchaînement d'outils (playbooks d'attaque)** — indiquez une cible et XORCISM
  imite un engagement complet : un outil s'exécute (ex. **nmap**), son résultat est
  analysé en *faits* (ports/services ouverts, technologies, vulnérabilités), et des
  règles lancent automatiquement l'outil suivant — un scanner web sur 80/443
  (**WhatWeb, Nikto, Nuclei**), **WPScan** si WordPress est détecté, **sslyze** sur
  TLS — récursivement, jusqu'à épuisement des règles. L'exécution est dessinée en
  **arbre temps réel** et les constats remontent à l'engagement. **Bibliothèque
  prédéfinie** de playbooks — pentest externe complet, évaluation d'app web,
  reconnaissance réseau, web-recon par sous-domaines (subfinder → httpx par hôte),
  **Exploitation externe (Metasploit)**, **Balayage AD/SMB interne (Metasploit +
  CrackMapExec)**, durcissement TLS/SSL, et **Recon externe → surface d'attaque
  (OSINT)** — un parcours d'attaquant passif d'abord depuis un domaine (subfinder ·
  theHarvester · Shodan · HIBP → sonde → scan web) qui, en mode **Réel**, **alimente
  automatiquement l'inventaire d'actifs** avec les hôtes découverts (découverte
  continue de surface d'attaque) — avec **import/export** des playbooks en JSON
  portable. **Couverture de détection purple-team** : chaque exécution de chaîne
  devient un rapport de couverture ATT&CK **fondé sur des preuves** (`/purple-team`) —
  chaque outil est mappé à sa technique, puis vérifié contre votre **bibliothèque
  de règles Sigma** (3 750+) ; les techniques sans règle sont des lacunes, comblées
  en **générant la règle Sigma manquante** (IA locale, squelette déterministe en repli).
  Deux modes : **Simulation** (sûr, sans scan réel) et **Réel** (jobs
  de connecteurs, périmètre uniquement, ROE appliqué). Localisé dans les 10 langues.
  Voir `/pentest` → carte « Chaîne d'attaque ».
- **Graphe de relations STIX** — graphe interactif reliant chasses ↔ techniques ↔
  acteurs ; les nœuds renvoient directement à leurs formulaires.
- **Modélisation des menaces** — périmètre STRIDE, actifs, menaces et mesures.
- **Gestion des incidents et ticketing** — alertes, incidents, tâches,
  commentaires et pièces jointes.

### 🔌 Intégrations et automatisation

- **300+ connecteurs** — un **catalogue recherchable** : lanceurs d'outils curés
  (nmap, nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS) et
  imports par API (Nessus, Qualys, Rapid7, Caldera, Dependency-Track, OSV-Scanner,
  depx, Wiz, Lacework, Sysdig, Aikido, Burp Suite, Metasploit, Splunk, Elastic
  Security, Microsoft Sentinel, QRadar, SAINT), plus un large jeu de **lanceurs
  d'outils OSINT**. Voir [§ Connecteurs](#-connecteurs).
- **Workers distants** — exécutez les connecteurs sur une autre machine (ex. une
  VM Kali) via un jeton de worker ; les résultats normalisés sont importés
  centralement.
- **Serveur TAXII 2.1** — publier/consommer des flux STIX.
- **IA locale (Ollama)** — assistants entièrement hors ligne : **« Ask the threat
  model »** (RAG sur vos données XORCISM), un **générateur de note de synthèse**,
  un **agent de triage de vulnérabilités** (KEV/EPSS + rayon d'impact sur les
  actifs touchés), un **assistant de chasse**, des suggestions de réponses OCIL, et
  des **copilotes red/blue** — un **analyste IA de chaîne d'attaque** (lecture d'une
  exécution : chemin critique, constats, prochaines étapes offensives + défenses
  ATT&CK·D3FEND) et une **synthèse d'exposition IA** (niveau RSSI sur la liste de
  fusion + chemins d'attaque). Chaque copilote bascule sur une synthèse déterministe
  des données quand l'IA locale est hors ligne — rien ne bloque ; aucune donnée ne quitte la machine.
- **Importeurs Python** — chargent les données de référence : ATT&CK, D3FEND,
  CAPEC, CVE/NVD, KEV, ISO 27001, NIST 800-53, CCE, OVAL, MAEC, Atomic Red Team,
  A3M, **règles Sigma**, chasses, **rapports de menaces et IOC**, **outils OSINT**.

### 🔐 Sécurité et identité

- Authentification par session ; **clés d'accès (WebAuthn)** vérifiées côté
  serveur (ES256/RS256) ; SSO **OIDC** optionnel.
- **RBAC** (`userCan`) + **cloisonnement par locataire au niveau ligne**
  (multi-tenant par conception).
- **Coffre de chiffrement de champs** (clé de données scellée par une phrase
  secrète, clé de récupération à usage unique).
- Garde **anti-automatisation** sur l'application authentifiée ; tables réservées
  aux administrateurs masquées.

### 🌐 UX et accessibilité

- **10 langues d'interface** avec parité stricte des clés ; mise en page **RTL**
  pour l'arabe.
- Système de thèmes (variables CSS + `data-theme`), thèmes sombres.
- Formulaires pilotés par le schéma avec sélecteurs de clés étrangères, création
  « + » en ligne, sélecteurs de date, listes statiques, colonnes cases à cocher,
  import Excel, champs en texte enrichi.

---

## 📸 Captures d'écran

> Interface en français, avec des données de démonstration. Images en pleine
> résolution dans [`docs/screenshots/fr/`](docs/screenshots/fr).

| | | |
|---|---|---|
| ![Lanceur de domaines](docs/screenshots/fr/01_landing_cards.png)<br>**Lanceur de domaines** — choisir un domaine de sécurité | ![Gestion des actifs](docs/screenshots/fr/02_asset_management.png)<br>**Gestion des actifs** — inventaire, worklist de gouvernance et score de risque | ![Configuration / OVAL](docs/screenshots/fr/03_configuration_oval.png)<br>**Configuration** — définitions OVAL |
| ![Conformité / GRC](docs/screenshots/fr/04_compliance_audit.png)<br>**Conformité** — audits, constats et preuves | ![TPRM](docs/screenshots/fr/05_tprm_dashboard.png)<br>**TPRM** — risque tiers | ![EBIOS, vue d'ensemble](docs/screenshots/fr/06_ebios_dashboard.png)<br>**EBIOS RM** — vue d'ensemble de l'étude |
| ![Parties prenantes EBIOS](docs/screenshots/fr/07_ebios_stakeholders.png)<br>**EBIOS** — parties prenantes et zones de menace | ![Événements redoutés EBIOS](docs/screenshots/fr/08_ebios_feared_events.png)<br>**EBIOS** — événements redoutés (DICT) | ![Gestion des vulnérabilités](docs/screenshots/fr/09_vulnerability_mgmt.png)<br>**Vulnérabilités** — CVE/KEV/CVSS/EPSS · SSVC |
| ![Renseignement sur les menaces](docs/screenshots/fr/10_threat_mgmt.png)<br>**Renseignement (CTI)** — acteurs et TTP | ![Modélisation des menaces](docs/screenshots/fr/11_threat_modeling.png)<br>**Modélisation des menaces** — STRIDE | ![Gestion des incidents](docs/screenshots/fr/12_incident_mgmt.png)<br>**Gestion des incidents** |
| ![Ticketing](docs/screenshots/fr/13_ticketing.png)<br>**Ticketing** — tâches et commentaires | ![Connecteurs](docs/screenshots/fr/14_xposure_connectors.png)<br>**Connecteurs** — nmap, nuclei, Nessus, SBOM… | ![OSINT](docs/screenshots/fr/15_osint_tools.png)<br>**OSINT** — boîte à outils |
| ![ATT&CK](docs/screenshots/fr/16_matrix_attack.png)<br>**MITRE ATT&CK** — avec heatmap de couverture BAS | ![D3FEND](docs/screenshots/fr/17_matrix_d3fend.png)<br>**MITRE D3FEND** — matrice défensive | ![A3M](docs/screenshots/fr/18_matrix_a3m.png)<br>**A3M** — Agentic AI Attack Matrix |
| ![Tableau de bord](docs/screenshots/fr/19_dashboard.png)<br>**Tableau de bord exécutif** — risque, exposition, tendances | ![BIA](docs/screenshots/fr/20_bia_audit.png)<br>**Analyse d'impact métier (BIA)** | ![Graphe STIX](docs/screenshots/fr/21_stix_graph.png)<br>**Graphe STIX** — chasses ↔ techniques ATT&CK |
| ![Identités & IAM](docs/screenshots/fr/54_identities.png)<br>**Identités & IAM** — inventaire humains + non-humains (NHI), worklist de gouvernance et score de risque | ![SSVC](docs/screenshots/fr/55_ssvc_calculator.png)<br>**SSVC** — calculateur CISA (catégorisation des vulnérabilités : Track / Track\* / Attend / Act) | ![Gestion des incidents](docs/screenshots/fr/56_incidents.png)<br>**Gestion des incidents** — file, worklist de gouvernance, dépassement SLA/RTO et score de priorité |
| ![Conformité & GRC](docs/screenshots/fr/57_compliance.png)<br>**Conformité & GRC** — inventaire des audits, worklist de remédiation et score de posture | ![Politiques & Documents](docs/screenshots/fr/58_policy_management.png)<br>**Politiques & Documents** — cycle de vie des politiques et registre documentaire, worklist de gouvernance et score par politique (politiques ISO 42001 EN/FR pré-chargées) | |

---

## 🚀 Démarrage rapide

L'application **crée toutes les bases au premier démarrage** ; une installation
neuve se résume donc à :

```powershell
cd xorcism_ts
npm install
npm run build                                       # build:server (tsc) + build:client (esbuild)
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"   # gardez les bases HORS de OneDrive
npm start                                           # node dist/server/index.js
# → ouvrez http://localhost:9292/login
```

Au **tout premier** démarrage (aucun utilisateur), le serveur affiche dans la
console un compte administrateur à usage unique :

```
  COMPTE ADMIN INITIAL CRÉÉ
    Email        : admin@xorcism.local
    Mot de passe : <mot de passe temporaire aléatoire, affiché UNE SEULE FOIS>
    (À CHANGER à la première connexion)
```

Connectez-vous avec ce compte ; vous serez obligé de définir un nouveau mot de
passe.

### Démarrage rapide (Docker)

```bash
docker compose up -d --build
# → http://localhost:9292/login
```

Les bases SQLite sont persistées dans le volume `xorcism-data` (`DB_DIR=/data`).
Pour utiliser vos bases existantes, montez-les en bind mount — p. ex.
`- C:/Users/vous/XORCISM_databases:/data` dans [`docker-compose.yml`](docker-compose.yml).

> **⚠️ Windows / OneDrive.** L'arborescence du code peut vivre sous OneDrive,
> mais les **bases SQLite doivent rester HORS de OneDrive** — OneDrive remplace
> les fichiers ouverts et corrompt les journaux WAL. `DB_DIR` par défaut :
> `C:\Users\<vous>\XORCISM_databases`.

---

## 📦 Installation détaillée

Le guide complet, étape par étape, est dans **[SETUP.MD](SETUP.MD)** ; les
versions des dépendances dans **[REQUIREMENTS.MD](REQUIREMENTS.MD)**. Résumé des
composants :

| Composant | Dossier | Runtime | Obligatoire |
|---|---|---|---|
| **Application web** (principale) | `xorcism_ts/` | Node.js 20 + TypeScript | ✅ Oui |
| **Bases de données** | `databases/` → `DB_DIR` | SQLite (better-sqlite3) | ✅ auto-créées |
| **Outillage / importeurs Python** | `xorcism_python/` | Python 3.11+ + SQLAlchemy 2 | ⬜ Optionnel |
| **Connecteurs / workers** | `connectors/` | Python | ⬜ Optionnel |
| **Serveur TAXII 2.1** | `taxii/` | Python + Flask | ⬜ Optionnel |

### Prérequis

| Outil | Version min. | Notes |
|---|---|---|
| **Node.js** | 20.x LTS (`>=20 <23`) | ou le runtime portable fourni dans `tools/nodejs/node.exe` |
| **CLI sqlite3** | 3.x | fourni dans `tools/sqlite3.exe` (uniquement pour le script de génération des bases) |
| **Python** | 3.11+ | importeurs / connecteurs / TAXII (optionnel) |
| **PowerShell** | 5.1+ | les scripts d'installation sont en PowerShell |
| **Navigateur** | moderne | Chrome, Edge, Firefox |

> **better-sqlite3 est un module natif.** Il doit tourner sur **Node 20**
> (binaires précompilés) ; Node 23+/24 casse l'ABI. Sous Windows sans Node
> système, utilisez le runtime portable `tools/nodejs/node.exe`.

### Variables d'environnement (communes)

```powershell
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"  # emplacement SQLite (hors de OneDrive)
$env:PORT   = "9292"                                       # port HTTP (défaut)
# $env:XORCISM_ALLOW_REGISTER = "0"                        # désactive l'auto-inscription publique
# $env:XORCISM_DB_DIR  → même chemin que DB_DIR, pour l'outillage Python
```

Voir [SETUP.MD](SETUP.MD) §4–§9 pour les connecteurs, TAXII, le forum et le
coffre de chiffrement, et [REQUIREMENTS.MD](REQUIREMENTS.MD) pour le tableau
complet des variables d'environnement.

---

## 🔧 Développement local

```powershell
cd xorcism_ts
npm install
npm run dev    # tsc --watch (serveur) + esbuild --watch (client) + nodemon
```

### Scripts npm

| Script | Action |
|---|---|
| `npm run build` | `build:server` + `build:client` |
| `npm run build:server` | `tsc -p tsconfig.server.json` → `dist/server/` (CommonJS) |
| `npm run build:client` | `node esbuild.config.js` → `dist/client/js/` (un bundle par page) |
| `npm start` | `node dist/server/index.js` (port 9292) |
| `npm run dev` | recompile en continu serveur + client et redémarre à chaud via nodemon |

> Les builds fonctionnent avec n'importe quel Node ; **l'exécution requiert Node
> 20** (ABI de better-sqlite3).

---

## 🏗️ Architecture

```
XORCISM/
├── xorcism_ts/                 # Application web principale (Node + TypeScript)
│   ├── server/
│   │   ├── index.ts            # Point d'entrée Express (port 9292), routes de pages, init des tables au boot
│   │   ├── db.ts               # Pool SQLite + logique de requêtes/agrégation + hooks de valeurs dérivées
│   │   ├── auth.ts             # sessions, RBAC (userCan), cloisonnement par locataire, tables masquées
│   │   ├── cron.ts agents.ts   # ordonnanceur de fond, points d'entrée agents
│   │   └── routes/             # explorer, bia, ocil, notifications, auth, oidc, vault, admin,
│   │       │                   #   connectors, feedback, agent, circl, osv, pentest, ai, ebios…
│   │       └── …
│   ├── client/
│   │   ├── *.html              # explorer, dashboard, bia, attack, d3fend, stix-graph, tprm,
│   │   │                       #   ebios, hunting, ask, threat-feeds, admin, connectors, login…
│   │   └── ts/
│   │       ├── app.ts          # formulaires et grilles pilotés par le schéma (moteur de l'explorateur)
│   │       ├── dashboard.ts attack.ts d3fend.ts stix-graph.ts bia.ts ebios.ts tprm.ts
│   │       ├── i18n.ts theme.ts api.ts rte.ts
│   │       └── locales/        # de it es pt zh ja ar ru (fr + en sont en ligne dans i18n.ts)
│   ├── esbuild.config.js  tsconfig*.json  package.json  start.ps1
│
├── databases/                  # DDL SQLite canonique (XORCISM, XVULNERABILITY, XTHREAT, …)
├── xorcism_python/             # Modèles SQLAlchemy + importers/ (chargeurs de données de référence)
├── connectors/                 # 300+ connecteurs (connector.json + run.py) + runner.py
├── taxii/                      # Serveur TAXII 2.1 (Flask)
├── docs/                       # Documentation + screenshots/
├── tools/nodejs/               # Runtime Node 20 portable (ABI de better-sqlite3)
├── Dockerfile  docker-compose.yml
└── SETUP.MD  REQUIREMENTS.MD  README.md
```

### Pile technique

| Couche | Technologie |
|---|---|
| Serveur | Node.js 20 + Express 4 + TypeScript (compilé en CommonJS) |
| Base de données | better-sqlite3 (synchrone, sans ORM) — une famille de fichiers SQLite |
| Client | TypeScript bundlé avec esbuild (une entrée par page) |
| Graphiques | Chart.js (tableau de bord) |
| Export | SheetJS / XLSX |
| Authentification | cookies de session, clés d'accès (WebAuthn ES256/RS256), OIDC optionnel |
| i18n | système de dictionnaires maison, 10 langues, support RTL |
| Outillage | Python 3.11 + SQLAlchemy 2 (importeurs), Flask (TAXII) |
| IA locale | Ollama (optionnel, RAG hors ligne) |
| Déploiement | Docker + Compose, ou Node 20 portable |

### Fonctionnement de l'explorateur

L'UI est **pilotée par le schéma** : le serveur découvre automatiquement les
bases et les tables dans `DB_DIR`, et le client génère un formulaire et une
grille pour chaque table à partir de son schéma. Des cartes de configuration
indexées par `"TABLE.Colonne"` (sélecteurs de clés étrangères, listes, couleurs
de grille, colonnes cases à cocher, sélecteurs de date, champs calculés en
lecture seule) ajoutent du comportement par-dessus — ainsi, ajouter une table la
fait apparaître après un redémarrage, sans code.

### Valeurs dérivées et tâches de fond

Les colonnes calculées sont remplies par des hooks dans `db.ts` avant
persistance (p. ex. `RiskScore` d'actif, `ThreatLevel`/`Zone` des parties
prenantes EBIOS). Le serveur Node exécute ses propres minuteries — **sans cron
externe** :

- **Boucle RiskScore** (30 s) : `RiskScore` par actif + `EnterpriseRiskScore` par
  locataire (en tête du tableau de bord), avec historique.
- **Ordonnanceur de connecteurs** (30 s) : lance les jobs de connecteurs
  planifiés dans `XJOB`.
- **Purge des sessions** (toutes les heures) : supprime les sessions expirées.

---

## 🧭 Modules

| Module | Route | Couverture |
|---|---|---|
| **Lanceur de domaines** | `/` | Grille de cartes ; entrée vers chaque module |
| **Gestion des actifs** | explorer | Inventaire, propriétaires, valeur, étiquettes, exposition, scoring |
| **Gestion de la configuration** | explorer | Nommage CPE, définitions et audits OVAL |
| **Gestion des vulnérabilités** | explorer | CVE/KEV/CVSS/EPSS, CIRCL/OSV, bug bounty |
| **Recherche Exploit-DB** | `/exploitdb` | Recherche de l'index SearchSploit local par mot-clé/CVE ; recherche CVE→exploit public sur le formulaire VULNERABILITY |
| **Expositions prioritaires** | `/exposure` | Score de fusion exploitabilité & pertinence — liste de travail « corriger en premier » (EPSS+KEV+exploit+CTI+rayon d'impact) |
| **Chemins d'attaque** | `/attack-path` | Graphe d'accessibilité entrée→joyau (liens sous-réseau + BIA, pondérés par la fusion) + analyse des points d'étranglement |
| **Couverture de détection** | `/purple-team` | Purple-team : outils de chaîne → ATT&CK → couverture par la bibliothèque Sigma + génération de la règle manquante |
| **Impact $ rançongiciel** | `/ransomware` | Rejoue les TTP d'un groupe de rançongiciel → impact $ SLE/ALE, rayon d'impact, contrôles D3FEND |
| **Assurance des contrôles** | `/assurance` | Conformité prouvée en continu — contrôles évalués en direct depuis la télémétrie, mappés ISO 27001 / NIST CSF |
| **Veille CTI** | `/cti-watch` | « CTI qui agit » — KEV + rapports recoupés avec l'inventaire + ouverture de ticket en un clic |
| **Dérive de surface** | `/drift` | Capture & comparaison de la surface d'attaque — apparu/disparu/nouvellement exposé |
| **Hub de contenu** | `/content` | Export/import de contenu portable — playbooks d'attaque, bundle Sigma, OpenVEX |
| **Conformité (GRC)** | explorer | Politiques, mesures, audits, preuves, constats, CRQ/FAIR |
| **EBIOS Risk Manager** | `/ebios` | 5 ateliers ANSSI, valeurs métier, événements redoutés, écosystème |
| **TPRM** | `/tprm` | Évaluations de risque tiers / fournisseurs et questionnaires |
| **Gestion des menaces (CTI)** | explorer | Entités STIX, propriétés OpenCTI, sightings, listes de surveillance, PIR |
| **Chasse aux menaces** | `/hunting` | Chasses, hypothèses, vue IOC/techniques, règles Sigma, assistant de chasse IA |
| **Flux de menaces** | `/threat-feeds` | Lecteur RSS CTI curé ; rapports avec extraction d'IOC et enrichissement CVE |
| **Ask the threat model** | `/ask` | Assistant RAG par IA locale sur vos données XORCISM |
| **Modélisation des menaces** | explorer | Périmètre STRIDE, actifs, menaces, mesures |
| **Gestion des incidents** | explorer | Alertes → incidents → réponse |
| **Ticketing** | explorer | Tâches, commentaires, pièces jointes |
| **Xposure / Connecteurs** | `/connectors` | Lanceurs d'outils et imports API, jobs planifiés, workers |
| **OSINT** | explorer | Boîte à outils de renseignement open source |
| **Tableau de bord** | `/dashboard` | Risque d'entreprise, vulnérabilités, valeur, **risque×valeur**, étiquettes, incidents |
| **BIA** | `/bia` | Audits et entrées d'analyse d'impact métier |
| **ATT&CK** | `/attack` | Enterprise / Mobile / ICS / ATLAS + surcouches couverture BAS & **LLM-enabled (Anthropic)** |
| **D3FEND** | `/d3fend` | Contre-mesures défensives mappées à ATT&CK et aux mesures |
| **A3M** | `/a3m` | Agentic AI Attack Matrix |
| **Kill chain** | `/kill-chain` | Tactiques ATT&CK en phases ordonnées de la kill chain + surcouche TTP d'un adversaire |
| **Graphe STIX** | `/stix-graph` | Graphe de relations ; les nœuds renvoient aux formulaires |
| **Graphe de surface d'attaque** | `/attack-surface` | Graphe centré sur l'actif — applications, CPE, vulns, organisations, personnes, menaces, incidents, étiquettes |
| **Pentest** | `/pentest` | Engagements (AUDIT type=Pentest) cadrés sur des actifs ; connecteurs d'outils ; constats, vulnérabilités et **rapport PDF** |
| **Chaîne d'attaque** | `/pentest/chain` | Exécution d'un playbook d'enchaînement d'outils — arbre temps réel (nmap → scanners web → WPScan), piloté par les faits, constats remontés |

---

## 🔌 Connecteurs

Les connecteurs vivent dans `connectors/<id>/` avec un manifeste `connector.json`
(découvert automatiquement sous **Connecteurs** — sans recompilation) et un
`run.py`. Les résultats sont normalisés en constats (projet → `ASSET`,
vulnérabilité → `VULNERABILITY` / `ASSETVULNERABILITY`). Le catalogue compte
**300+** connecteurs et est **recherchable** dans l'UI.

| Type | Connecteurs |
|---|---|
| **Scanners réseau / web** (lanceurs d'outils) | nmap, nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS |
| **Vulnérabilités / posture (API)** | Nessus, Qualys, Rapid7, Wiz, Lacework, Sysdig, Aikido |
| **SCA / chaîne d'approvisionnement** | Dependency-Track, OSV-Scanner, **depx** (audit de paquets malveillants) |
| **Offensif / BAS** | Caldera, Metasploit, Metasploit-scan, Burp Suite, SAINT |
| **SIEM / détection** | Splunk, Elastic Security, Microsoft Sentinel, QRadar |
| **OSINT** (lanceurs d'outils) | 300+ outils de reconnaissance / OSINT du catalogue recherchable |

- Les **lanceurs d'outils** ont besoin du binaire nommé dans le `PATH` de la
  machine qui exécute le runner.
- Les **connecteurs API** sont configurés **uniquement** via des variables
  d'environnement (jamais dans l'UI) — p. ex. `CALDERA_URL` + `CALDERA_API_KEY`,
  `QUALYS_API_URL`/`_USER`/`_PASSWORD`, `DTRACK_URL` + `DTRACK_API_KEY`.
- **Workers distants** : `python connectors/runner.py --remote https://host:9292 --token <t> --name kali-01 --capabilities nmap,nuclei`.

Ajouter un connecteur = déposer un dossier avec `connector.json` + `run.py`. Voir
[docs/CONNECTORS.md](docs/CONNECTORS.md) et
[`connectors/manifest.schema.json`](connectors/manifest.schema.json).

---

## 🗄️ Bases de données

XORCISM utilise une **famille de bases SQLite**, auto-créées au premier démarrage
dans `DB_DIR`. Les bases de schéma proviennent des fichiers versionnés
`databases/*_sqlite.sql` ; les bases opérationnelles sont créées dans le code.

| Base | Rôle |
|---|---|
| `XORCISM` | Cœur : actifs, applications, mesures, personnes, étiquettes, scores de risque |
| `XVULNERABILITY` | CVE/KEV/CVSS/EPSS, domaines de vulnérabilité, bug bounty |
| `XCOMPLIANCE` | GRC : audits, preuves, OCIL, TPRM, EBIOS, notifications aux régulateurs |
| `XTHREAT` | ATT&CK / ATLAS / D3FEND / A3M, CTI/STIX, chasses, hypothèses, BAS, règles Sigma, flux, rapports et IOC |
| `XATTACK` | Modèles d'attaque CAPEC |
| `XINCIDENT` | Incidents et alertes |
| `XOVAL` | Définitions OVAL |
| `XMALWARE` | MAEC / malwares |
| `XWINDOWS` | Données de configuration Windows |
| `XID` | Utilisateurs, rôles, locataires, sessions, clés d'accès (opérationnel) |
| `XTICKET` · `XJOB` · `XAGENT` | Ticketing · file des connecteurs · agents (opérationnel) |

DDL canonique : [`databases/`](databases) (`*_sqlite.sql`). Les nouvelles tables
apparaissent dans l'explorateur après un redémarrage, sans changement de code.

---

## 📥 Importeurs de données de référence

Les chargeurs de données de référence vivent dans
[`xorcism_python/importers/`](xorcism_python/importers) (`sqlite3` de la stdlib /
SQLAlchemy + `requests` ; chemins des bases depuis `xorcism_python/config.py`) :

| Importeur | Source → cible |
|---|---|
| `import_attack.py` | MITRE ATT&CK STIX (Enterprise/Mobile/ICS/**ATLAS**) → `XTHREAT.ATTACK*` |
| `import_d3fend.py` | MITRE D3FEND + mappings → `XTHREAT.D3FEND*` **et** `XORCISM.CONTROL` |
| `import_capec.py` | XML MITRE CAPEC → `XATTACK` |
| `import_a3m.py` | Agentic AI Attack Matrix → `XTHREAT` |
| `import_atomics.py` | Atomic Red Team → tables BAS de `XTHREAT` |
| `import_hunts.py` · `import_hypotheses.py` | Chasses et hypothèses → `XTHREAT` |
| `import_sigma.py` | Règles de détection SigmaHQ → `XTHREAT.SIGMARULE` |
| `import_threat_reports.py` | Rapports CTI + IOC extraits → `XTHREAT.THREATREPORT` / `IOC` |
| `import_osint_tools.py` | Catalogue d'outils OSINT → `XORCISM.TOOL` |
| `import_nvd_cve.py` · `import_vulnerabilities.py` · `import_KEV.py` · `import_cisa_kev.py` | CVE / KEV → `XVULNERABILITY` |
| `import_iso27001.py` · `import_nist800-53.py` · `import_controls.py` · `import_cce.py` | Référentiels de mesures → `XORCISM.CONTROL` |
| `import_oval.py` · `import_maec.py` · `import_threatevent.py` · `import_vulnerabilitydomains.py` | OVAL / MAEC / événements de menace / domaines |

```powershell
py -3 xorcism_python\importers\import_attack.py --domain atlas
py -3 xorcism_python\importers\import_d3fend.py
py -3 xorcism_python\importers\import_sigma.py                 # règles de détection SigmaHQ
py -3 xorcism_python\importers\import_threat_reports.py        # rapports CTI + IOC
py -3 xorcism_python\importers\import_threat_reports.py --url https://.../rapport   # un seul rapport
.\import_nvd_cve.ps1
```

---

## 🌐 Internationalisation

10 langues d'interface avec **parité stricte des clés** (chaque dictionnaire
contient le même ensemble de clés) :

| Code | Langue | | Code | Langue |
|---|---|---|---|---|
| `en` | English | | `pt` | Português |
| `fr` | Français | | `zh` | 中文 |
| `de` | Deutsch | | `ja` | 日本語 |
| `it` | Italiano | | `ar` | العربية (RTL) |
| `es` | Español | | `ru` | Русский |

`en` + `fr` sont en ligne dans `client/ts/i18n.ts` ; les huit autres sont dans
`client/ts/locales/*.ts`. La langue est stockée dans
`localStorage["xorcism_lang"]`, avec un repli `t(clé)` selon `LANG → en → fr →
clé`. Pour ajouter une langue : copiez un fichier de locale, traduisez toutes les
clés, déclarez-le dans `i18n.ts`.

---

## 👥 Rôles et multi-tenant

XORCISM est multi-tenant : la plupart des tables portent un `TenantID` et sont
**cloisonnées au niveau ligne** automatiquement. L'accès est régi par le **RBAC**
(`userCan`) plus les droits de lecture/écriture par rôle au niveau base.

- **Admin** — appartient au locataire **System**, super-administrateur (voit tous
  les locataires), gestion des utilisateurs et des diffusions.
- **User** — affecté à un locataire ; lecture/écriture dans son périmètre ; les
  tables réservées aux administrateurs sont masquées.

La connexion accepte **mot de passe**, **clés d'accès (WebAuthn)** et SSO
**OIDC** optionnel.

---

## 🧩 API REST

Une API REST, en lecture/écriture et cloisonnée par locataire, expose les données
de la plateforme (actifs, incidents, expositions, posture SLA/RTO, score de risque)
pour les SIEM, tableaux de bord, pipelines CI et l'automatisation.

- **URL de base :** `/api/v1` · **Spéc. :** `GET /api/v1/openapi.json` (OpenAPI 3)
- **Doc interactive :** **`/api-docs`** · **Clés :** **`/api-keys`** · **Webhooks :** **`/webhooks`**
- **Auth :** clé API (`Authorization: Bearer xor_…` ou `X-API-Key: xor_…`) ; une clé
  agit comme son utilisateur (mêmes droits RBAC + locataire), seul le SHA-256 est stocké.
  Les clés portent des **portées** (`read`/`write` ou granulaires comme `incidents:write`)
  et une **expiration** optionnelle.

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Sonde de vivacité (sans auth) |
| `GET` | `/api/v1/me` | Identité derrière la clé |
| `GET` · `PATCH` | `/api/v1/assets` · `/assets/{id}` | Inventaire des actifs (paginé) ; SLA/valeurs |
| `GET` · `POST` · `PATCH` | `/api/v1/incidents` · `/incidents/{id}` | Lister / créer / mettre à jour des incidents |
| `GET` | `/api/v1/incident-sla` | Durées d'incident vs SLA des actifs & RTO des BIA |
| `GET` | `/api/v1/exposures` | Top expositions (score d'exploitabilité fusionné) |
| `GET` | `/api/v1/risk` | Score de risque d'entreprise |

- **Webhooks :** enregistrez des points de terminaison HTTPS sur **`/webhooks`** pour
  recevoir un `POST` JSON signé (`X-XORCISM-Signature`) sur `incident.created` /
  `incident.updated` / `asset.updated`.

```bash
export XORCISM_API_KEY=xor_…
curl -s https://votre-hote/api/v1/incident-sla -H "Authorization: Bearer $XORCISM_API_KEY" | jq '.summary'
```

Référence complète, exemples et signature des webhooks : **[API.md](API.md)**.

## 🛠️ Dépannage

| Symptôme | Cause / correctif |
|---|---|
| `better-sqlite3` `ERR_DLOPEN_FAILED` / mauvais `NODE_MODULE_VERSION` | Exécution sous Node 23+/24. Utilisez **Node 20** (`tools/nodejs/node.exe`). |
| `Unknown database: X` | `DB_DIR` est erroné ou le `*.db` est absent. |
| Lectures périmées / corruption WAL | Les bases sont sous OneDrive / un dossier synchronisé — sortez `DB_DIR` de là. |
| `Cannot POST /api/...` renvoie du HTML | Build serveur périmé — `npm run build` puis redémarrez. |
| Port 9292 occupé | Définissez `$env:PORT` avant `npm start`. |
| Erreur de build `better-sqlite3` à `npm install` | Utilisez Node 20 LTS (précompilé) ou installez MSVC Build Tools + Python pour node-gyp. |
| Mot de passe admin initial perdu | Installation neuve uniquement : supprimez `DB_DIR\XID.db` et redémarrez pour le régénérer. |

Plus de détails dans [SETUP.MD § 11](SETUP.MD).

---

## 🤝 Contribuer

Les tickets et pull requests sont les bienvenus.

1. Branchez depuis `main`.
2. Compilez les deux côtés — `npm run build` (serveur `tsc` + client `esbuild`)
   doit passer.
3. Si vous touchez aux chaînes d'UI, **ajoutez la clé dans les 10 dictionnaires**
   (`i18n.ts` en ligne `en`/`fr` + les 8 `locales/*.ts`) et conservez la parité.
4. Toute nouvelle table contenant des données de locataire doit être ajoutée à
   l'ensemble cloisonné pour être filtrée par locataire.
5. Gardez les commentaires de code en **anglais**.
6. Ouvrez une PR avec une description claire.

---

## 📄 Licence et avertissements

XORCISM est une plateforme de cybersécurité **open source** — voir
[xorcism.ai](https://xorcism.ai) pour les conditions de licence (ajoutez un
fichier `LICENSE` au dépôt pour rendre les conditions explicites).

> **Marques et référentiels.** XORCISM intègre et référence des standards et
> référentiels tiers — **MITRE ATT&CK®, D3FEND™, CAPEC™** (MITRE Corporation),
> **EBIOS Risk Manager** (ANSSI), **STIX/TAXII** (OASIS), **OVAL**, **OCIL**,
> **CVE/KEV/CVSS/EPSS**. XORCISM **n'est ni affilié, ni approuvé, ni sponsorisé**
> par MITRE, l'ANSSI, l'OASIS ou un quelconque propriétaire de référentiel.
> Toutes les marques appartiennent à leurs détenteurs respectifs.

> **Aucune garantie.** Fourni « en l'état », sans garantie d'aucune sorte. Vous
> êtes responsable de la manière dont vous le déployez et l'utilisez, et de
> l'obtention des autorisations nécessaires avant de lancer un connecteur
> offensif / de scan contre une cible.

---

**En savoir plus → [xorcism.ai](https://xorcism.ai) · [Chaîne YouTube](https://www.youtube.com/channel/UCk6OWxMBg1H4gHTZdpZGAhA)**
