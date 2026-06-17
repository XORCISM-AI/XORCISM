# XORCISM — Open Unified Cybersecurity Management Platform

> **Global Cyber Risk Exposure.** One self-hosted platform to manage assets,
> configuration, vulnerabilities, threats, compliance and incidents — and turn
> them into a single, continuously-recomputed enterprise risk score.

![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20_LTS-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-better--sqlite3-003B57?logo=sqlite&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20%C2%B7%20D3FEND%20%C2%B7%20CAPEC-C8102E)
![EBIOS RM](https://img.shields.io/badge/EBIOS-Risk%20Manager-0055A4)
![STIX/TAXII](https://img.shields.io/badge/STIX%2FTAXII-2.1-6f42c1)
![Self-hosted](https://img.shields.io/badge/Self--hosted-✔-success)

**🇬🇧 English · [🇫🇷 Français](README.fr.md)**

**🌐 [xorcism.ai](https://xorcism.ai) · 📖 [Installation](SETUP.MD) · 🧩 [Requirements](REQUIREMENTS.MD) · ▶ [YouTube channel](https://www.youtube.com/channel/UCk6OWxMBg1H4gHTZdpZGAhA)**

---

## 🎯 Overview

Security teams juggle a dozen disconnected tools — a CMDB here, a vulnerability
scanner there, a GRC spreadsheet, a CTI feed, a ticketing system, a risk
register — and spend most of their time reconciling them instead of reducing
risk. XORCISM unifies the whole **cyber-exposure lifecycle** behind one
schema-driven application and one identity model, so every asset, CVE, control,
threat actor and incident lives in the same place and feeds the same risk score.

It is **fully self-hosted**: a Node.js/TypeScript server over a family of SQLite
databases, with optional Python importers and connectors. No SaaS, no telemetry,
your data never leaves your infrastructure.

### Who it is for

| Profile | How they use XORCISM |
|---|---|
| **CISO / RSSI** | Enterprise risk score, executive dashboard, compliance posture, EBIOS RM studies |
| **VOC / Vulnerability analyst** | Asset inventory, CVE/KEV/EPSS triage, connector-driven scan ingestion |
| **GRC / Auditor** | Policies & controls, audits, evidence, findings workflow, OCIL questionnaires |
| **CTI / Threat analyst** | STIX entities, ATT&CK/D3FEND/A3M matrices, hunts, hypotheses, threat graph |
| **Red / Purple team** | Pentest engagements, BAS adversary-emulation coverage, bug-bounty programs |
| **SOC / Blue team** | Alert & incident management, ticketing, detection-to-response |

### Why XORCISM

- **One risk model.** Assets, vulnerabilities and value combine into a per-asset
  `RiskScore` and a per-tenant `EnterpriseRiskScore`, recomputed every 30 s.
- **Schema-driven explorer.** Every table gets a generated form & grid; add a
  table to the database and it appears in the UI after a restart — no code.
- **Standards built in.** MITRE ATT&CK / ATLAS / D3FEND / CAPEC, STIX/TAXII 2.1,
  Sigma, OVAL, OCIL, EBIOS Risk Manager, CVE/KEV/EPSS, and GRC frameworks (ISO
  27001, NIST CSF/800-53, CIS, NIS2, DORA, CRA, SOC 2).
- **Extensible by drop-in.** A searchable catalogue of **300+ security
  connectors** and a remote-worker model; add one with a `connector.json`
  manifest — no rebuild.
- **Multi-tenant & RBAC.** Row-level tenant scoping and role-based access, with
  passkey (WebAuthn) and optional OIDC sign-in.
- **10 UI languages.** EN, FR, DE, IT, ES, PT, 中文, 日本語, العربية (RTL), Русский.

---

## ✨ Features

### 🗂️ Exposure management (VOC / CTEM)

- **Asset Management** — inventory, owners, business/financial value, tags,
  exposure; per-asset risk scoring with history.
- **Attack-surface graph** — an asset-centric force-directed map linking each
  asset to its applications, CPEs, vulnerabilities, owners, threats and incidents
  (`/attack-surface`, reachable from the ASSET form; focus one asset or the whole
  tenant, filter by entity type, deep-link back to any form).
- **Configuration Management** — CPE naming, **OVAL** definitions and audits.
- **Vulnerability Management** — CVE with **KEV**, **CVSS** and **EPSS**; CIRCL &
  OSV lookups; SOCRadar IOC-Radar deep-link for CVE references; **bug-bounty**
  program & submission tracking.
- **Executive Dashboard** — enterprise risk score, vulnerability breakdown,
  financial value, **risk exposure = risk × value**, asset tag cloud, incident
  trends (Chart.js).

### 🛡️ Governance, Risk & Compliance (GRC)

- **Compliance** — policies, standards & procedures lifecycle; audits, evidence,
  readiness; **findings workflow**; **CRQ / FAIR** quantitative risk on the
  register. Frameworks: ISO 27001, NIST CSF, NIST 800-53, CIS Controls, NIS2,
  DORA, CRA, SOC 2.
- **EBIOS Risk Manager** — the full 5-workshop ANSSI method (framing & security
  baseline, risk sources, strategic & operational scenarios, treatment) with an
  **Express mode**, business values, supporting assets, feared events (DICT),
  risk sources and an **ecosystem of stakeholders with auto-computed threat
  levels & zones**.
- **TPRM** — third-party / supplier risk assessments and questionnaires.
- **OCIL questionnaires** — OCIL 2.0-compatible authoring, XML import/export and
  an optional AI "suggest answer".
- **Business Impact Analysis (BIA)** — audits & entries with editable asset
  datalists.

### 🔭 Threat & detection

- **Threat Management (CTI)** — STIX entities (actors, malware, tools, campaigns,
  indicators, observables) with OpenCTI-style common properties (Confidence,
  TLP, Labels, Score), **sightings** and **relationships**.
- **Threat feeds & reports** — a curated **CTI RSS reader** (33 feeds) and threat
  reports with **automatic IOC extraction** (IPs, domains, URLs, hashes, CVEs)
  into the `IOC` table; per-report **CVE enrichment**, **watchlists with
  alerting**, priority-intelligence requirements (**PIR**) and a local-AI **intel
  brief builder**.
- **Threat hunting & detection** — hunts, hypotheses and an IOC/technique
  overview with a local-AI **hunt assistant**; **3,750+ Sigma detection rules**
  browsable and linked to ATT&CK techniques.
- **MITRE matrices** — **ATT&CK** (Enterprise / Mobile / ICS / **ATLAS**),
  **D3FEND** defensive countermeasures (mapped to ATT&CK and `XORCISM.CONTROL`),
  and **A3M — Agentic AI Attack Matrix**.
- **LLM ATT&CK Navigator (Anthropic)** — an AI-enablement **overlay layer** on the
  ATT&CK matrix: the techniques AI-enabled threat actors actually use, shaded by
  prevalence (% of banned accounts), from Anthropic's 2026 analysis. Toggle it on
  `/attack` alongside the BAS coverage layer.
- **Adversary emulation (BAS)** — emulation plans, atomic tests & executors, and
  an **ATT&CK coverage heatmap** overlaid on the matrix.
- **Pentesting** — engagements modeled as **AUDITs (type Pentest)** scoped to
  assets: launch tool connectors (nmap, nuclei, nikto, whatweb, wpscan, sqlmap,
  OpenVAS, Metasploit) against the scope under an enforced **ROE**, then collect
  **AUDITFINDINGs** and the **VULNERABILITYs** found on the in-scope assets
  (promote a vuln to a finding in one click), then print a client-ready
  **PDF report** (executive summary, scope, findings, vulnerabilities). Scan
  launch is capability-gated.
- **STIX relationship graph** — interactive graph linking hunts ↔ techniques ↔
  actors; nodes deep-link back to their forms.
- **Threat Modeling** — STRIDE scope, assets, threats and controls.
- **Incident Management & Ticketing** — alerts, incidents, tasks, comments and
  attachments.

### 🔌 Integrations & automation

- **300+ connectors** — a **searchable catalogue**: curated tool-runners (nmap,
  nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS) and API imports
  (Nessus, Qualys, Rapid7, Caldera, Dependency-Track, OSV-Scanner, depx, Wiz,
  Lacework, Sysdig, Aikido, Burp Suite, Metasploit, Splunk, Elastic Security,
  Microsoft Sentinel, QRadar, SAINT), plus a large **OSINT tool-runner** set. See
  [§ Connectors](#-connectors).
- **Remote workers** — run connectors on a separate host (e.g. a Kali VM) over a
  worker token; normalized results import centrally.
- **TAXII 2.1 server** — publish/consume STIX feeds.
- **Local AI (Ollama)** — fully-offline assistants: **"Ask the threat model"**
  (RAG over your XORCISM data), an **intel brief builder**, a
  **vulnerability-triage agent** (KEV/EPSS + affected-asset blast radius), a
  **hunt assistant**, and OCIL answer suggestions.
- **Python importers** — load reference data: ATT&CK, D3FEND, CAPEC, CVE/NVD,
  KEV, ISO 27001, NIST 800-53, CCE, OVAL, MAEC, Atomic Red Team, A3M, **Sigma
  rules**, hunts, **threat reports & IOCs**, **OSINT tools**.

### 🔐 Security & identity

- Session-based auth; **passkeys (WebAuthn)** verified server-side (ES256/RS256);
  optional **OIDC** SSO.
- **RBAC** (`userCan`) + **per-tenant row scoping** (multi-tenant by design).
- **Field-encryption vault** (passphrase-wrapped data key, one-time recovery key).
- **Anti-automation** guard on the authenticated app; hidden admin-only tables.

### 🌐 UX & accessibility

- **10 UI languages** with strict key parity; **RTL** layout for Arabic.
- Theme system (CSS variables + `data-theme`), dark themes.
- Schema-driven forms with FK pickers, "+ create" inline records, date pickers,
  static datalists, checkbox columns, Excel import, rich-text fields.

---

## 📸 Screenshots

> English UI, with demo data. Full-resolution images in [`docs/screenshots/`](docs/screenshots).

| | | |
|---|---|---|
| ![Domain launcher](docs/screenshots/01_landing_cards.png)<br>**Domain launcher** — pick a security domain | ![Asset management](docs/screenshots/02_asset_management.png)<br>**Asset management** — inventory & exposure | ![Configuration / OVAL](docs/screenshots/03_configuration_oval.png)<br>**Configuration** — OVAL definitions |
| ![Compliance / GRC](docs/screenshots/04_compliance_audit.png)<br>**Compliance** — audits, findings & evidence | ![TPRM](docs/screenshots/05_tprm_dashboard.png)<br>**TPRM** — third-party risk | ![EBIOS overview](docs/screenshots/06_ebios_dashboard.png)<br>**EBIOS RM** — study overview |
| ![EBIOS stakeholders](docs/screenshots/07_ebios_stakeholders.png)<br>**EBIOS** — stakeholders & threat zones | ![EBIOS feared events](docs/screenshots/08_ebios_feared_events.png)<br>**EBIOS** — feared events (DICT) | ![Vulnerability management](docs/screenshots/09_vulnerability_mgmt.png)<br>**Vulnerabilities** — CVE/KEV/CVSS/EPSS |
| ![Threat intelligence](docs/screenshots/10_threat_mgmt.png)<br>**Threat intelligence (CTI)** — actors & TTPs | ![Threat modeling](docs/screenshots/11_threat_modeling.png)<br>**Threat modeling** — STRIDE | ![Incident management](docs/screenshots/12_incident_mgmt.png)<br>**Incident management** |
| ![Ticketing](docs/screenshots/13_ticketing.png)<br>**Ticketing** — tasks & comments | ![Connectors](docs/screenshots/14_xposure_connectors.png)<br>**Connectors** — nmap, nuclei, Nessus, SBOM… | ![OSINT](docs/screenshots/15_osint_tools.png)<br>**OSINT** toolbox |
| ![ATT&CK](docs/screenshots/16_matrix_attack.png)<br>**MITRE ATT&CK** — with BAS coverage heatmap | ![D3FEND](docs/screenshots/17_matrix_d3fend.png)<br>**MITRE D3FEND** — defensive matrix | ![A3M](docs/screenshots/18_matrix_a3m.png)<br>**A3M** — Agentic AI Attack Matrix |
| ![Dashboard](docs/screenshots/19_dashboard.png)<br>**Executive dashboard** — risk, exposure, trends | ![BIA](docs/screenshots/20_bia_audit.png)<br>**Business Impact Analysis (BIA)** | ![STIX graph](docs/screenshots/21_stix_graph.png)<br>**STIX graph** — hunts ↔ ATT&CK techniques |
| ![Threat hunting](docs/screenshots/22_threat_hunting.png)<br>**Threat hunting** — HUNT · IOC · ATT&CK, local-AI assistant | ![Ask the threat model](docs/screenshots/23_ask_ai.png)<br>**Ask the threat model** — local-AI RAG | ![Connectors](docs/screenshots/24_connector_search.png)<br>**Connectors** — searchable catalogue (300+) |
| ![Threat feeds](docs/screenshots/25_threat_feeds.png)<br>**Threat feeds** — curated CTI RSS reader | ![Attack-surface graph](docs/screenshots/26_attack_surface.png)<br>**Attack-surface graph** — asset-centric force map | ![Attack-surface focus](docs/screenshots/27_attack_surface_focus.png)<br>**Attack surface** — focused on one asset |
| ![Pentesting](docs/screenshots/28_pentest.png)<br>**Pentesting** — engagements, scope, tooling, findings & vulns | ![LLM ATT&CK](docs/screenshots/31_llm_attack.png)<br>**LLM ATT&CK** — AI-enabled technique overlay (Anthropic) | |

---

## 🚀 Quick start

The web app **creates all databases on first start**, so a fresh setup is just:

```powershell
cd xorcism_ts
npm install
npm run build                                       # build:server (tsc) + build:client (esbuild)
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"   # keep databases OUTSIDE OneDrive
npm start                                           # node dist/server/index.js
# → open http://localhost:9292/login
```

On the **very first** start (no users yet) the server prints a one-time admin
account to the console:

```
  COMPTE ADMIN INITIAL CRÉÉ
    Email        : admin@xorcism.local
    Password     : <random temp password, shown ONCE>
    (change it at first login)
```

Sign in with that account; you'll be forced to set a new password.

### Quick start (Docker)

```bash
docker compose up -d --build
# → http://localhost:9292/login
```

SQLite databases persist in the `xorcism-data` volume (`DB_DIR=/data`). To use
your existing databases, bind-mount them instead — e.g.
`- C:/Users/you/XORCISM_databases:/data` in [`docker-compose.yml`](docker-compose.yml).

> **⚠️ Windows / OneDrive.** The code tree can live under OneDrive, but the
> **SQLite databases must live OUTSIDE OneDrive** — OneDrive replaces files under
> open handles and corrupts WAL journals. Default `DB_DIR` is
> `C:\Users\<you>\XORCISM_databases`.

---

## 📦 Detailed installation

The full, step-by-step guide is in **[SETUP.MD](SETUP.MD)**; dependency versions
are in **[REQUIREMENTS.MD](REQUIREMENTS.MD)**. Summary of components:

| Component | Folder | Runtime | Mandatory |
|---|---|---|---|
| **Web application** (main) | `xorcism_ts/` | Node.js 20 + TypeScript | ✅ Yes |
| **Databases** | `databases/` → `DB_DIR` | SQLite (better-sqlite3) | ✅ auto-created |
| **Python tooling / importers** | `xorcism_python/` | Python 3.11+ + SQLAlchemy 2 | ⬜ Optional |
| **Connectors / workers** | `connectors/` | Python | ⬜ Optional |
| **TAXII 2.1 server** | `taxii/` | Python + Flask | ⬜ Optional |

### Prerequisites

| Tool | Min version | Notes |
|---|---|---|
| **Node.js** | 20.x LTS (`>=20 <23`) | or the bundled portable runtime at `tools/nodejs/node.exe` |
| **sqlite3 CLI** | 3.x | bundled at `tools/sqlite3.exe` (only for the DB-generation script) |
| **Python** | 3.11+ | importers / connectors / TAXII (optional) |
| **PowerShell** | 5.1+ | the setup scripts are PowerShell |
| **Browser** | modern | Chrome, Edge, Firefox |

> **better-sqlite3 is a native module.** It must run on **Node 20** (prebuilt
> binaries); Node 23+/24 break the ABI. On Windows without a system Node, use the
> portable runtime at `tools/nodejs/node.exe`.

### Environment variables (common)

```powershell
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"  # SQLite location (must be outside OneDrive)
$env:PORT   = "9292"                                       # HTTP port (default)
# $env:XORCISM_ALLOW_REGISTER = "0"                        # disable public self-registration
# $env:XORCISM_DB_DIR  → same path as DB_DIR, for the Python tooling
```

See [SETUP.MD](SETUP.MD) §4–§9 for connectors, TAXII, forum and the encryption
vault, and [REQUIREMENTS.MD](REQUIREMENTS.MD) for the full env-var table.

---

## 🔧 Local development

```powershell
cd xorcism_ts
npm install
npm run dev    # tsc --watch (server) + esbuild --watch (client) + nodemon
```

### npm scripts

| Script | Action |
|---|---|
| `npm run build` | `build:server` + `build:client` |
| `npm run build:server` | `tsc -p tsconfig.server.json` → `dist/server/` (CommonJS) |
| `npm run build:client` | `node esbuild.config.js` → `dist/client/js/` (one bundle per page) |
| `npm start` | `node dist/server/index.js` (port 9292) |
| `npm run dev` | watch-compile server + client and hot-restart with nodemon |

> Builds run with any Node; **the runtime needs Node 20** (better-sqlite3 ABI).

---

## 🏗️ Architecture

```
XORCISM/
├── xorcism_ts/                 # Main web application (Node + TypeScript)
│   ├── server/
│   │   ├── index.ts            # Express entry (port 9292), page routes, boot-time table setup
│   │   ├── db.ts               # SQLite pool + all query/aggregation logic + derived-value hooks
│   │   ├── auth.ts             # sessions, RBAC (userCan), tenant scoping, hidden-table rules
│   │   ├── cron.ts agents.ts   # background scheduler, agent endpoints
│   │   └── routes/             # explorer, bia, ocil, notifications, auth, oidc, vault, admin,
│   │       │                   #   connectors, feedback, agent, circl, osv, pentest, ai, ebios…
│   │       └── …
│   ├── client/
│   │   ├── *.html              # explorer, dashboard, bia, attack, d3fend, stix-graph, tprm,
│   │   │                       #   ebios, hunting, ask, threat-feeds, admin, connectors, login…
│   │   └── ts/
│   │       ├── app.ts          # schema-driven forms & grids (the explorer engine)
│   │       ├── dashboard.ts attack.ts d3fend.ts stix-graph.ts bia.ts ebios.ts tprm.ts
│   │       ├── i18n.ts theme.ts api.ts rte.ts
│   │       └── locales/        # de it es pt zh ja ar ru (fr + en are inline in i18n.ts)
│   ├── esbuild.config.js  tsconfig*.json  package.json  start.ps1
│
├── databases/                  # Canonical SQLite DDL (XORCISM, XVULNERABILITY, XTHREAT, …)
├── xorcism_python/             # SQLAlchemy models + importers/ (reference-data loaders)
├── connectors/                 # 300+ connectors (connector.json + run.py) + runner.py
├── taxii/                      # TAXII 2.1 server (Flask)
├── docs/                       # Documentation + screenshots/
├── tools/nodejs/               # Portable Node 20 runtime (better-sqlite3 ABI)
├── Dockerfile  docker-compose.yml
└── SETUP.MD  REQUIREMENTS.MD  README.md
```

### Tech stack

| Layer | Technology |
|---|---|
| Server | Node.js 20 + Express 4 + TypeScript (compiled to CommonJS) |
| Database | better-sqlite3 (synchronous, no ORM) — a family of SQLite files |
| Client | TypeScript bundled with esbuild (one entry per page) |
| Charts | Chart.js (dashboard) |
| Export | SheetJS / XLSX |
| Auth | session cookies, passkeys (WebAuthn ES256/RS256), optional OIDC |
| i18n | custom dictionary system, 10 languages, RTL support |
| Tooling | Python 3.11 + SQLAlchemy 2 (importers), Flask (TAXII) |
| Local AI | Ollama (optional, offline RAG) |
| Deployment | Docker + Compose, or portable Node 20 |

### How the explorer works

The UI is **schema-driven**: the server auto-discovers databases and tables in
`DB_DIR`, and the client generates a form and a grid for each table from its
schema. Configuration maps keyed `"TABLE.Column"` (FK pickers, datalists, grid
colours, checkbox columns, date pickers, read-only computed fields) layer
behaviour on top — so adding a table makes it appear after a restart with no code.

### Derived values & background jobs

Computed columns are filled by hooks in `db.ts` before persistence (e.g. asset
`RiskScore`, EBIOS stakeholder `ThreatLevel`/`Zone`). The Node server runs its own
timers — **no external cron**:

- **RiskScore loop** (30 s): per-asset `RiskScore` + per-tenant
  `EnterpriseRiskScore` (Dashboard headline), with history.
- **Connector scheduler** (30 s): fires due scheduled connector jobs into `XJOB`.
- **Session purge** (hourly): removes expired sessions.

---

## 🧭 Modules

| Module | Route | What it covers |
|---|---|---|
| **Domain launcher** | `/` | Card grid; entry into every module |
| **Asset Management** | explorer | Inventory, owners, value, tags, exposure, risk scoring |
| **Configuration Management** | explorer | CPE naming, OVAL definitions & audits |
| **Vulnerability Management** | explorer | CVE/KEV/CVSS/EPSS, CIRCL/OSV, bug bounty |
| **Compliance (GRC)** | explorer | Policies, controls, audits, evidence, findings, CRQ/FAIR |
| **EBIOS Risk Manager** | `/ebios` | 5 ANSSI workshops, business values, feared events, ecosystem |
| **TPRM** | `/tprm` | Third-party / supplier risk assessments & questionnaires |
| **Threat Management (CTI)** | explorer | STIX entities, OpenCTI properties, sightings, watchlists, PIR |
| **Threat hunting** | `/hunting` | Hunts, hypotheses, IOC/technique overview, Sigma rules, local-AI hunt assistant |
| **Threat feeds** | `/threat-feeds` | Curated CTI RSS reader; reports with IOC extraction & CVE enrichment |
| **Ask the threat model** | `/ask` | Local-AI RAG assistant over your XORCISM data |
| **Threat Modeling** | explorer | STRIDE scope, assets, threats, controls |
| **Incident Management** | explorer | Alerts → incidents → response |
| **Ticketing** | explorer | Tasks, comments, attachments |
| **Xposure / Connectors** | `/connectors` | Tool-runners & API imports, scheduled jobs, workers |
| **OSINT** | explorer | Open-source intelligence toolbox |
| **Dashboard** | `/dashboard` | Enterprise risk, vulnerabilities, value, **risk×value**, tags, incidents |
| **BIA** | `/bia` | Business Impact Analysis audits & entries |
| **ATT&CK** | `/attack` | Enterprise / Mobile / ICS / ATLAS + BAS coverage & **LLM-enabled (Anthropic)** overlays |
| **D3FEND** | `/d3fend` | Defensive countermeasures mapped to ATT&CK & controls |
| **A3M** | `/a3m` | Agentic AI Attack Matrix |
| **STIX graph** | `/stix-graph` | Relationship graph; nodes link back to forms |
| **Attack-surface graph** | `/attack-surface` | Asset-centric force graph — apps, CPEs, vulns, orgs, persons, threats, incidents, tags |
| **Pentesting** | `/pentest` | Engagements (AUDIT type=Pentest) scoped to assets; run tool connectors; findings & vulnerabilities |

---

## 🔌 Connectors

Connectors live in `connectors/<id>/` with a `connector.json` manifest
(auto-discovered under **Connectors** — no rebuild) and a `run.py`. Results are
normalized into findings (project → `ASSET`, vuln → `VULNERABILITY` /
`ASSETVULNERABILITY`). The catalogue holds **300+** connectors and is
**searchable** in the UI.

| Type | Connectors |
|---|---|
| **Network / web scanners** (tool-runners) | nmap, nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS |
| **Vulnerability / posture (API)** | Nessus, Qualys, Rapid7, Wiz, Lacework, Sysdig, Aikido |
| **SCA / supply chain** | Dependency-Track, OSV-Scanner, **depx** (malicious-package audit) |
| **Offensive / BAS** | Caldera, Metasploit, Metasploit-scan, Burp Suite, SAINT |
| **SIEM / detection** | Splunk, Elastic Security, Microsoft Sentinel, QRadar |
| **OSINT** (tool-runners) | 300+ reconnaissance / OSINT tools from the searchable catalogue |

- **Tool-runners** need the named binary on `PATH` on the runner host.
- **API connectors** are configured **only** via environment variables (never in
  the UI) — e.g. `CALDERA_URL` + `CALDERA_API_KEY`, `QUALYS_API_URL`/`_USER`/`_PASSWORD`,
  `DTRACK_URL` + `DTRACK_API_KEY`.
- **Remote workers**: `python connectors/runner.py --remote https://host:9292 --token <t> --name kali-01 --capabilities nmap,nuclei`.

Adding a connector = drop a folder with `connector.json` + `run.py`. See
[docs/CONNECTORS.md](docs/CONNECTORS.md) and
[`connectors/manifest.schema.json`](connectors/manifest.schema.json).

---

## 🗄️ Databases

XORCISM uses a **family of SQLite databases**, auto-created on first start in
`DB_DIR`. Schema DBs are built from the committed `databases/*_sqlite.sql`;
operational DBs are created in code.

| Database | Purpose |
|---|---|
| `XORCISM` | Core: assets, applications, controls, persons, tags, risk scores |
| `XVULNERABILITY` | CVE/KEV/CVSS/EPSS, vulnerability domains, bug bounty |
| `XCOMPLIANCE` | GRC: audits, evidence, OCIL, TPRM, EBIOS, regulator notifications |
| `XTHREAT` | ATT&CK / ATLAS / D3FEND / A3M, CTI/STIX, hunts, hypotheses, BAS, Sigma rules, feeds, reports & IOCs |
| `XATTACK` | CAPEC attack patterns |
| `XINCIDENT` | Incidents & alerts |
| `XOVAL` | OVAL definitions |
| `XMALWARE` | MAEC / malware |
| `XWINDOWS` | Windows configuration data |
| `XID` | Users, roles, tenants, sessions, passkeys (operational) |
| `XTICKET` · `XJOB` · `XAGENT` | Ticketing · connector queue · agents (operational) |

Canonical DDL: [`databases/`](databases) (`*_sqlite.sql`). New tables show up in
the explorer after a restart with no code change.

---

## 📥 Reference-data importers

Reference-data loaders live in
[`xorcism_python/importers/`](xorcism_python/importers) (stdlib `sqlite3` /
SQLAlchemy + `requests`; DB paths from `xorcism_python/config.py`):

| Importer | Source → target |
|---|---|
| `import_attack.py` | MITRE ATT&CK STIX (Enterprise/Mobile/ICS/**ATLAS**) → `XTHREAT.ATTACK*` |
| `import_d3fend.py` | MITRE D3FEND + mappings → `XTHREAT.D3FEND*` **and** `XORCISM.CONTROL` |
| `import_capec.py` | MITRE CAPEC XML → `XATTACK` |
| `import_a3m.py` | Agentic AI Attack Matrix → `XTHREAT` |
| `import_atomics.py` | Atomic Red Team → BAS tables in `XTHREAT` |
| `import_llm_attack.py` | Anthropic LLM ATT&CK Navigator → `XTHREAT.LLMATTACKTECHNIQUE` |
| `import_hunts.py` · `import_hypotheses.py` | Threat hunts & hypotheses → `XTHREAT` |
| `import_sigma.py` | SigmaHQ detection rules → `XTHREAT.SIGMARULE` |
| `import_threat_reports.py` | CTI reports + extracted IOCs → `XTHREAT.THREATREPORT` / `IOC` |
| `import_osint_tools.py` | OSINT tools catalogue → `XORCISM.TOOL` |
| `import_nvd_cve.py` · `import_vulnerabilities.py` · `import_KEV.py` · `import_cisa_kev.py` | CVE / KEV → `XVULNERABILITY` |
| `import_iso27001.py` · `import_nist800-53.py` · `import_controls.py` · `import_cce.py` | Control frameworks → `XORCISM.CONTROL` |
| `import_oval.py` · `import_maec.py` · `import_threatevent.py` · `import_vulnerabilitydomains.py` | OVAL / MAEC / threat events / domains |

```powershell
py -3 xorcism_python\importers\import_attack.py --domain atlas
py -3 xorcism_python\importers\import_d3fend.py
py -3 xorcism_python\importers\import_sigma.py                 # SigmaHQ detection rules
py -3 xorcism_python\importers\import_threat_reports.py        # CTI reports + IOCs
py -3 xorcism_python\importers\import_threat_reports.py --url https://.../report   # one report
.\import_nvd_cve.ps1
```

---

## 🌐 Internationalization

10 UI languages with **strict key parity** (every dictionary holds the same keys):

| Code | Language | | Code | Language |
|---|---|---|---|---|
| `en` | English | | `pt` | Português |
| `fr` | Français | | `zh` | 中文 |
| `de` | Deutsch | | `ja` | 日本語 |
| `it` | Italiano | | `ar` | العربية (RTL) |
| `es` | Español | | `ru` | Русский |

`en` + `fr` are inline in `client/ts/i18n.ts`; the other eight are in
`client/ts/locales/*.ts`. Language is stored in `localStorage["xorcism_lang"]`,
with `t(key)` falling back `LANG → en → fr → key`. To add a language: copy a
locale file, translate all keys, register it in `i18n.ts`.

---

## 👥 Roles & multi-tenancy

XORCISM is multi-tenant: most tables carry a `TenantID` and are **row-scoped**
automatically. Access is governed by **RBAC** (`userCan`) plus DB-level
read/write per role.

- **Admin** — belongs to the **System** tenant, super-admin (sees all tenants),
  user & broadcast management.
- **User** — assigned to a tenant; read/write within scope; admin-only tables are
  hidden.

Sign-in supports **password**, **passkeys (WebAuthn)** and optional **OIDC** SSO.

---

## 🛠️ Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `better-sqlite3` `ERR_DLOPEN_FAILED` / wrong `NODE_MODULE_VERSION` | Running on Node 23+/24. Use **Node 20** (`tools/nodejs/node.exe`). |
| `Unknown database: X` | `DB_DIR` is wrong or the `*.db` is missing. |
| Stale reads / WAL corruption | Databases are inside OneDrive/a synced folder — move `DB_DIR` out. |
| `Cannot POST /api/...` returns HTML | Server build is stale — `npm run build` and restart. |
| Port 9292 busy | Set `$env:PORT` before `npm start`. |
| `better-sqlite3` build error on `npm install` | Use Node 20 LTS (prebuilt) or install MSVC Build Tools + Python for node-gyp. |
| Lost the seeded admin password | Fresh install only: delete `DB_DIR\XID.db` and restart to re-seed. |

More in [SETUP.MD § 11](SETUP.MD).

---

## 🤝 Contributing

Issues and pull requests are welcome.

1. Branch off `main`.
2. Build both sides — `npm run build` (server `tsc` + client `esbuild`) must pass.
3. If you touch UI strings, **add the key to all 10 dictionaries** (`i18n.ts`
   inline `en`/`fr` + the 8 `locales/*.ts`) and keep parity.
4. New tables that hold tenant data must be added to the tenant-scoped set so
   they are row-scoped.
5. Keep code comments in **English**.
6. Open a PR with a clear description.

---

## 📄 License & disclaimers

XORCISM is an **open-source** cybersecurity platform — see
[xorcism.ai](https://xorcism.ai) for licensing terms (add a `LICENSE` file to the
repository to make the terms explicit).

> **Trademarks & frameworks.** XORCISM integrates and references third-party
> standards and frameworks — **MITRE ATT&CK®, D3FEND™, CAPEC™** (MITRE
> Corporation), **EBIOS Risk Manager** (ANSSI), **STIX/TAXII** (OASIS), **OVAL**,
> **OCIL**, **CVE/KEV/CVSS/EPSS**. XORCISM is **not affiliated with, endorsed by,
> or sponsored by** MITRE, ANSSI, OASIS or any framework owner. All trademarks
> belong to their respective holders.

> **No warranty.** Provided "as is", without warranty of any kind. You are
> responsible for how you deploy and use it, and for obtaining authorization
> before running any offensive/scanning connector against a target.

---

**Learn more → [xorcism.ai](https://xorcism.ai) · [YouTube channel](https://www.youtube.com/channel/UCk6OWxMBg1H4gHTZdpZGAhA)**
