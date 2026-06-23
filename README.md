# XORCISM — Open Unified Cybersecurity Management Platform

> **Global Cyber Risk Exposure.** One self-hosted platform to manage assets,
> configuration, vulnerabilities, threats, compliance and incidents — and turn
> them into a single, continuously-recomputed enterprise risk score.

![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20_LTS-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-better--sqlite3-003B57?logo=sqlite&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-portable-4169E1?logo=postgresql&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL%2FMariaDB-portable-4479A1?logo=mysql&logoColor=white)
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

And it doesn't stop at inventory: a built-in **offensive-to-defensive loop**
chains recon and exploitation tools, prioritizes what is *truly* exploitable,
validates the attack paths to your crown jewels, quantifies the dollar impact,
and proves your controls — continuously, from OSINT to the boardroom.

It is **fully self-hosted**: a Node.js/TypeScript server over a family of SQLite
databases (zero-config by default, **portable to PostgreSQL / MySQL / MariaDB** —
see [§ Database backends](docs/DATABASE_BACKENDS.md)), with optional Python importers
and connectors. No SaaS, no telemetry, your data never leaves your infrastructure.

### Who it is for

| Profile | How they use XORCISM |
|---|---|
| **CISO / RSSI** | Enterprise risk score, executive dashboard, compliance posture, EBIOS RM studies |
| **VOC / Vulnerability analyst** | Asset inventory, CVE/KEV/EPSS triage, connector-driven scan ingestion |
| **GRC / Auditor** | Policies & controls, audits, evidence, findings workflow, OCIL questionnaires |
| **CTI / Threat analyst** | STIX entities, ATT&CK/D3FEND/A3M matrices, hunts, hypotheses, threat graph |
| **Red / Purple team** | Tool-chaining attack playbooks (OSINT→exploit, Metasploit), attack-path & choke-point analysis, purple-team detection coverage, BAS emulation, bug-bounty programs |
| **SOC / Blue team** | Alert & incident management, ticketing, detection-to-response |

### Why XORCISM

- **One risk model.** Assets, vulnerabilities and value combine into a per-asset
  `RiskScore` and a per-tenant `EnterpriseRiskScore`, recomputed every 30 s.
- **Closed-loop exposure management.** One continuous flow — **discover** (OSINT
  chain + auto-inventory) → **prioritize** (exploitability fusion) → **validate**
  (attack paths & purple-team) → **quantify** ($ ransomware impact) → **defend**
  (detection coverage, D3FEND) → **comply** (controls proven live from telemetry).
  No tool-stitching, no spreadsheets in between.
- **Schema-driven explorer.** Every table gets a generated form & grid; add a
  table to the database and it appears in the UI after a restart — no code.
- **Standards built in.** MITRE ATT&CK / ATLAS / D3FEND / CAPEC, STIX/TAXII 2.1,
  Sigma, OVAL, OCIL, EBIOS Risk Manager, CVE/KEV/EPSS, and GRC frameworks (ISO
  27001, NIST CSF/800-53, CIS, NIS2, DORA, CRA, SOC 2).
- **Extensible by drop-in.** A searchable, filterable catalogue of **1,200+ security
  connectors** and a remote-worker model; add one with a `connector.json`
  manifest — no rebuild.
- **Runs on your database.** Zero-config **SQLite** out of the box, and the data
  layer is **portable to PostgreSQL / MySQL / MariaDB** (`XORCISM_DB_ENGINE` +
  `tools/migrate_db.py`) — see [§ Database backends](docs/DATABASE_BACKENDS.md).
- **Continuously fresh.** The NVD **CVE importer runs hourly** and every new CVE is
  **auto-matched to the assets it affects** (by CPE + technology tags), raising
  *"New CVEs for ASSET"* notifications — no manual triage to discover new exposure.
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
  OSV lookups; **Exploit-DB search** (SearchSploit index, CVE→public-exploit lookup
  on the VULNERABILITY form with one-click "mark exploitable"); SOCRadar IOC-Radar
  deep-link for CVE references; **bug-bounty** program & submission tracking.
- **Vulnerability Operations Center (VOC)** — `/voc` — run remediation as an
  **operations function**: a configurable remediation-**SLA policy**, operational KPIs
  (SLA compliance, MTTR, aging, velocity), a risk-ranked worklist, remediation campaigns
  with burndown, and a formal **risk-acceptance / exception** register.
- **VM Executive Report** — `/vm-report` — vulnerability **risk & SLA posture over time**
  (is risk actually going *down*?): trend charts (risk-weighted exposure, backlog, KEV, SLA
  compliance, MTTR, coverage), a board-ready executive summary, and a **"myths vs reality"**
  section that debunks common VM misconceptions with your *own* live numbers. Print / PDF.
- **CTEM — exposure taxonomy** — `/ctem` — support for the **ctem.org** (SecureCoders)
  standardized exposure-identifier standard (a *"CVE/CWE for exposures"*: 29 identifiers
  across 8 categories, the 3-stage **Discover → Prioritize → Remediate** program); classify
  observed exposures, track them by stage, and discover them from internet-exposed assets.
- **Attack paths & choke points** — a reachability graph (`/attack-path`) over the
  asset estate: edges from **same-subnet adjacency** + **BIA dependencies**, entry
  nodes = internet-exposed assets, crown jewels = high business value, traversal cost
  weighted by each node's **fusion exploitability**. Fusion-weighted Dijkstra maps the
  **easiest attack path** from the internet to every crown jewel, and ranks the
  **choke point** — the single node on the most paths, i.e. the one fix that severs
  the most attack routes (the XM Cyber / BloodHound move, open and asset-graph-native).
- **Top exposures (fusion score)** — one **exploitability & relevance score** per
  vulnerability (`/exposure`) fusing EPSS + CVSS + **CISA KEV** + **public exploits
  (Exploit-DB)** + **in-the-wild CTI** + **blast radius** (affected assets × business
  value), ranked into a prioritized "fix this first" worklist with a transparent
  per-signal breakdown.
- **Ransomware-to-$ scenario** — replay a real ATT&CK **ransomware group's TTPs**
  (`/ransomware`) across your asset estate and quantify the **dollar impact** with a
  transparent FAIR-style model: **SLE** (primary loss = value at risk + ransom +
  recovery), **ALE** (× an ARO bumped by internet exposure & KEV), and the **residual
  with controls** (offline backups + segmentation). Shows the kill-chain phases the
  group covers, the blast-radius assets with per-asset $, and the **D3FEND
  countermeasures** that break the chain — the security-to-business bridge for the board.
- **Continuously-proven compliance** — control objectives evaluated **live from your
  security telemetry** (`/assurance`), not annual screenshots: detection coverage
  (Sigma), KEV/exploit exposure, asset classification, internet exposure, pentest
  recency, finding closure and **threat-informed defense (ATT&CK/D3FEND)** — each
  mapped to **ISO 27001 / NIST CSF** with a proven/partial/gap status and an honest
  "attestation required" where telemetry genuinely can't decide. Compliance that
  re-proves itself on every page load.
- **CTI that acts** — `/cti-watch` cross-references live intel (**CISA KEV** +
  ingested threat reports) against your asset inventory and surfaces **only what
  affects you**, with one-click **auto-ticketing** (XTICKET). Threat intel that does
  something, not a feed.
- **Attack-surface drift** — `/drift` snapshots your external surface and diffs
  consecutive captures: assets that **appeared, vanished, or newly became
  internet-exposed**. Pairs with the OSINT discovery chain to make discovery continuous.
- **Content hub** — `/content` shares/reuses content as portable files: **attack
  playbooks** (import community recipes), the **Sigma rule bundle**, and an
  **OpenVEX** document (which CVEs affect your products vs false-positive/fixed).
- **Executive Dashboard** — a holistic **Enterprise RiskScore** (asset hygiene + open
  risk-register residual + live incidents + compliance debt − assurance credits) shown with a
  **contributor breakdown**, a **security-program maturity radar** (detection / mitigation /
  validation / compliance / crisis-readiness / risk-treated), a **risk heatmap** (residual
  probability × impact), vulnerability breakdown, financial value, **risk exposure = risk ×
  value**, asset tag cloud and incident trends (Chart.js) — plus a **security-posture KPI strip**
  spanning the governance modules (assets, identities, incidents, compliance, risk register,
  **Threat-Informed Defense** and **Crisis Management**).

### 🛡️ Governance, Risk & Compliance (GRC)

- **Compliance** — policies, standards & procedures lifecycle; audits, evidence,
  readiness; **findings workflow**; **CRQ / FAIR** quantitative risk on the
  register. Frameworks: ISO 27001, NIST CSF, NIST 800-53, CIS Controls, NIS2,
  DORA, CRA, SOC 2.
- **Policies & Documents** — one governance view over the documented-information
  estate: policy **lifecycle** (draft → in review → approved → published →
  retired) and a controlled-**document register**, with a per-policy governance
  score and a worklist of overdue reviews, unpublished/unowned policies, missing
  versions and expired documents. Ships a seedable baseline of **ISO/IEC
  42001:2023 (AI Management System) policies in English & French**.
- **Crisis Management & Tabletop Exercises** — run **tabletop exercises (TTX)** against a
  seeded library of **crisis scenarios** (ransomware, data breach, DDoS, insider,
  supply-chain, cloud account, BEC). A tabletop exercise is an audit of type *Tabletop
  Exercise*, so its observations become **improvement actions** and its **after-action
  report** a linked document; on top, scenario templates carry **timed injects** and
  exercises track **participants/roles**. One click launches an exercise from a scenario
  (copying its injects), and a **crisis-readiness score** blends exercise completion with
  scenario coverage. The worklist surfaces overdue actions, scenarios never exercised and
  exercises with no after-action report.
- **Risk Register** — one governance view over the risk register: every risk's
  **inherent → current → residual** level, its **treatment** (strategy, plan, owner, review) and
  its **CRQ/FAIR** quantification (*Annualized Loss Expectancy*), with a 0-100 priority score per
  risk and a worklist of the gaps that matter — **high/critical residual risks left untreated**,
  risks **accepted without justification**, **overdue reviews**, treatments **past their target
  date**, and **unowned** risks. Mirrors the asset/identity/compliance governance pages.
- **PQCMM — Quantum Readiness** — the PKI Consortium's **Post-Quantum Cryptography Maturity
  Model**: assess every product, service or asset that relies on cryptography against the **6
  PQCMM levels** (0 None → 5 Optimized), track **current vs target** maturity, and roll up your
  organisation's quantum-readiness posture — what's still **quantum-vulnerable** (Level 0),
  **production-ready** with PQC (≥ 2) or fully **managed** (CBOM + zero-legacy, ≥ 4) — with a
  maturity score and a below-target worklist. Get ahead of "harvest-now-decrypt-later."
- **SCA — Software Composition Analysis** — know what your software is made of. Import a
  **Software Bill of Materials** in the two most widely used standards — **CycloneDX** (OWASP) and
  **SPDX** (Linux Foundation) — and XORCISM persists every component with its **version, PURL, CPE,
  license, supplier and hash**, links CPE-bearing components back to the asset's exposure inventory
  (`CPEFORASSET`), and maps the **dependency graph**. The worklist surfaces **known-vulnerable
  components**, **license-compliance gaps** and **unpinned versions**; any SBOM can be **exported**
  back out in either standard (CycloneDX 1.5 / SPDX 2.3). Breakdowns by component type, license and
  supplier, plus an interactive composition graph.
- **FAIR-MAM Materiality** — the FAIR Institute's **Materiality Assessment Model**: decompose a
  cyber loss event's single-loss magnitude across the **10 standardized cost categories**
  (incident response, cyber extortion, business interruption, asset restoration, privacy/security
  liability, network-security liability, communications & media, regulatory, PCI, reputation),
  each estimated as a **PERT** range (min / most-likely / max). An interactive calculator computes
  the expected single-loss, the **primary vs secondary** (and first- vs third-party) split, and a
  **materiality verdict** against your threshold (e.g. an SEC materiality figure) — the detailed
  breakdown of the risk register's *Single Loss Expectancy*.
- **Configuration Management** — one governance view over the secure-configuration
  content library (OVAL/SCAP): the compliance-class **hardening baselines** are the
  configuration items, with a per-baseline **health score** and a worklist of
  **deprecated** content, baselines **never verified by a scan**, interim-status
  checks and missing **CCE** mappings — verification fed by the OVAL agent scans.
- **EBIOS Risk Manager** — the full 5-workshop ANSSI method (framing & security
  baseline, risk sources, strategic & operational scenarios, treatment) with an
  **Express mode**, business values, supporting assets, feared events (DICT),
  risk sources and an **ecosystem of stakeholders with auto-computed threat
  levels & zones**.
- **NIST SP 800-30** — the US federal **Guide for Conducting Risk Assessments**, the
  EBIOS-RM counterpart: threat sources (adversarial & non-adversarial), threat events,
  vulnerabilities & predisposing conditions, and risk determination as **likelihood ×
  impact** on the 800-30 scale (Very Low → Very High, Appendix I Table I-2), with a
  cockpit dashboard and a guided-create flow (`/nist-800-30`).
- **TPRM** — third-party / supplier risk assessments and questionnaires.
- **OCIL questionnaires** — OCIL 2.0-compatible authoring, XML import/export and
  an optional AI "suggest answer".
- **Business Impact Analysis (BIA)** — audits & entries with editable asset
  datalists, plus a **dependency graph**: a force-directed map of the BIA
  entries (coloured by criticality) and their dependencies, with **impact
  propagation** — click an entry to see everything that fails if it goes down,
  the tightest RTO, and the worst impacted criticality.

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
- **Kill chain graph** — the ATT&CK tactics as the ordered phases of the kill
  chain (Reconnaissance → Impact); overlay any adversary (ATT&CK group) to map
  the techniques it uses per phase and reveal its **coverage and progression**
  (e.g. APT29: 13/15 phases). `/kill-chain`.
- **Adversary emulation (BAS)** — emulation plans, atomic tests & executors, and
  an **ATT&CK coverage heatmap** overlaid on the matrix.
- **Pentesting** — engagements modeled as **AUDITs (type Pentest)** scoped to
  assets: launch tool connectors (nmap, nuclei, nikto, whatweb, wpscan, sqlmap,
  OpenVAS, Metasploit) against the scope under an enforced **ROE**, then collect
  **AUDITFINDINGs** and the **VULNERABILITYs** found on the in-scope assets
  (promote a vuln to a finding in one click), then print a client-ready
  **PDF report** (executive summary, scope, findings, vulnerabilities). Scan
  launch is capability-gated.
- **Attack chaining (playbooks)** — seed a target and let XORCISM mimic a full
  engagement: a tool runs (e.g. **nmap**), its result is parsed into *facts*
  (open ports / services / detected tech / vulns), and rules auto-launch the
  right follow-on tool — a web scanner on 80/443 (**WhatWeb, Nikto, Nuclei**),
  **WPScan** when WordPress is detected, **sslyze** on TLS — recursively, until
  no rule matches. The run is drawn as a **live tree** and its findings roll up
  to the engagement. Ships with a **predefined library** of playbooks — full
  external pentest, web-app assessment, network recon, subdomain web-recon
  (subfinder → httpx fan-out per host), **External exploitation (Metasploit)**,
  **Internal AD/SMB sweep (Metasploit + CrackMapExec)**, TLS/SSL hardening, and
  **External recon → attack surface (OSINT)** — a passive‑first attacker journey
  from a domain (subfinder · theHarvester · Shodan · HIBP → probe → web scan) that
  in **Live** mode **auto‑populates the asset inventory** with discovered hosts
  (continuous attack‑surface discovery). Playbooks **import/export** as portable
  JSON. Two backends: **Simulate**
  (safe, no real scanning — design & demo playbooks) and **Live** (real connector
  jobs, in-scope only, ROE-enforced). Localized across all 10 UI languages.
- **Purple-team detection coverage** — turn any attack-chain run into an
  **evidence-based** ATT&CK coverage report (`/purple-team`): each tool is mapped to
  the technique it exercises, then checked against your **Sigma rule library** (3,750+
  rules) — techniques with a rule are "detected", the rest are gaps, and a gap can be
  closed by **generating the missing Sigma rule** (local AI, with a deterministic
  skeleton fallback). Coverage you can defend, not "we own a tool".
- **Threat-Informed Defense cockpit** (`/threat-informed-defense`) — the capstone that
  operationalises MITRE's TID loop across the whole platform. For every ATT&CK
  technique it weighs **adversary use** (ecosystem prevalence from ATT&CK groups,
  boosted ×3 by your local CTI & hunts) against your three defensive pillars —
  **detect** (Sigma), **mitigate** (D3FEND + ATT&CK mitigations) and **test** (Atomic
  Red Team) — and produces a single **threat-weighted program score**, per-tactic
  kill-chain coverage, and a **prioritised gap worklist** (the highest-threat
  techniques with the weakest defence, each linking to where you close it). As you
  import your own CTI (the connectors feed `INTELEXCHANGE → ATT&CK`) the priorities
  sharpen to *your* threat model. One click **closes the validation gap**: *Build
  validation plan* turns the top untested high-threat techniques into a scheduled
  **BAS emulation scenario** (Atomic Red Team injects); *Run on agent* then has the
  **XOR agent execute** those injects and report real outcomes (Prevented / Executed /
  Skipped) into `EMULATIONRESULT` — so a technique moves from *test defined* to *test
  executed/validated*, and the cockpit shows a distinct **executed** rate, not just
  *defined*. Agent execution is opt-in and safety-gated (only read-only recon is auto-run).
  The agent then **attributes detection** — correlating each executed inject with the host's
  telemetry (Defender / Sysmon / PowerShell-ScriptBlock / Security-audit) to record
  *Detected* / *Logged* / *Executed (ran undetected)*. The cockpit surfaces the sharpest
  finding of all: a technique whose **Sigma rule exists but whose emulation ran undetected**
  — **false coverage**, where you *thought* you'd detect it but the test proved the rule
  never fired. And it closes the loop: every detection gap (no rule, exposed, or false
  coverage) gets a **✨ draft Sigma** button that **generates a detection rule with the
  local AI** (deterministic skeleton fallback) and saves it to the library as
  *experimental* — adding capability you then **re-validate** by re-running the plan, so a
  draft only graduates to "proven" once the emulation confirms it fires. The draft is
  **procedure-tuned**: the generator is fed the exact command/telemetry the emulation ran,
  so the rule detects *that* procedure (e.g. the precise `systeminfo` / `whoami`
  command-line the test executed) rather than a generic technique guess. And *Schedule
  weekly* puts the whole thing on a **cadence** — the cron scheduler re-queues the
  validation emulation on the agent automatically, so drafted detections get re-proven (and
  regressions caught) without anyone clicking a button. And when a detection that *used* to fire
  stops firing on a later re-validation, the cockpit flags **detection drift** (a distinct `D↓`
  state, separate from "never fired") and raises a **Defender-aligned alert** (`XINCIDENT.ALERT`,
  de-duplicated) the moment the regression is observed — so a silently-broken rule (an edit, a
  dead log source, a sensor change) pages you instead of rotting unnoticed. The whole program also **exports to a
  MITRE ATT&CK Navigator layer** (one click, *⬇ ATT&CK Navigator layer*) — score = adversary
  prevalence, colour = defence status (red = false-coverage/exposed, amber = partial, green =
  covered) — so it opens straight in the official ATT&CK Navigator.
- **STIX relationship graph** — interactive graph linking hunts ↔ techniques ↔
  actors; nodes deep-link back to their forms.
- **Threat Modeling** — STRIDE scope, assets, threats and controls.
- **Incident Management & Ticketing** — alerts, incidents, tasks, comments and
  attachments.

### 🔌 Integrations & automation

- **1,200+ connectors** — a **searchable, filterable catalogue** (search + category /
  type filters, like the tool catalogue): curated tool-runners (nmap,
  nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS) and API imports
  (Nessus, Qualys, Rapid7, Caldera, Dependency-Track, OSV-Scanner, depx, Wiz,
  Lacework, Sysdig, Aikido, Burp Suite, Metasploit, Splunk, Elastic Security,
  Microsoft Sentinel, QRadar, SAINT, **OpenCVE**, **Microsoft Entra ID**), plus a
  large **OSINT tool-runner** set and a **YARA** scanner. See [§ Connectors](#-connectors).
- **Continuous CVE → asset matching** — the NVD CVE importer **runs every hour**
  (`XSCHEDULE`, incremental); each newly-imported or OpenCVE-pulled CVE is **auto-linked
  to the assets it affects** — matched by the asset's **CPE inventory** and free-text
  **technology tags** (`ASSETTAG`) — and every affected asset gets a **"New CVEs for
  ASSET" notification**. Runs after each import, hourly, and on demand (the *Match CVEs*
  button on Asset Management).
- **Identity & device sync (Microsoft Entra ID)** — the `entra-id` connector pulls
  users (human identities), service principals & managed identities (non-human / NHI)
  and registered devices (assets) from the **Microsoft Graph API** into `IDENTITY` +
  `ASSET` (app-only OAuth2; feeds the IAM orphaned-NHI / stale / MFA-gap worklist).
- **CTI platform connectors** — pull threat intelligence and detection content from
  **MISP** (events → `INTELEXCHANGE`, galaxies → ATT&CK/actor/malware tags), **OpenCTI**
  (reports via GraphQL or a STIX 2.1 bundle → `INTELEXCHANGE`) and **SOC Prime**
  (Sigma detection rules → `SIGMARULE` *and* `INTELEXCHANGE`, boosting the Threat-Informed
  Defense *detect* pillar). Each works live (API + env credentials) or fully offline (saved
  export) — stdlib-only, idempotent.
- **Remote workers** — run connectors on a separate host (e.g. a Kali VM) over a
  worker token; normalized results import centrally.
- **Recurring agent scans** — schedule OVAL/SCAP scans on a cadence from Configuration
  Management (hourly/daily/weekly/monthly via `XSCHEDULE`); the scheduler queues an agent
  job each cycle and the XOR agent runs it at check-in. See the agent [SETUP](agent/SETUP.md).
- **Live forensics (DFIR triage)** — the XOR agent's `--scan forensics` collects a
  **read-only** live-response snapshot (processes, network connections, persistence/autoruns,
  logon sessions, recent files, ARP/DNS/routes, drivers, event-log summary) with conservative
  triage **flags** → `XAGENT.FORENSICTRIAGE`; collection never modifies the host.
- **Endpoint EDR & YARA (XOR agent)** — `--scan yara` runs the local **YARA** engine using
  rules from XORCISM's `YARARULE` store (served to the agent) and reports matches as events; and
  the **Rustinel EDR bridge** (`--scan rustinel`) tails [Rustinel](https://github.com/Karib0u/rustinel)'s
  kernel-level **ETW / eBPF / Endpoint-Security** alerts (Sigma + YARA + IOC) into XORCISM —
  kernel-grade detection without a custom agent core. Both are read-only and part of `--scan full`.
- **Memory acquisition (XOR agent)** — `--scan memdump` captures a full **RAM image** for forensics
  (winpmem/avml); the image stays on the endpoint for **chain of custody** and only the manifest
  (tool / path / size / **SHA-256**) is shipped → `XAGENT.MEMORYDUMP`.
- **AI log hunting (XOR agent)** — `--scan loghunt` collects Sysmon / PowerShell / Security logs and
  the **local AI** hunts them for threats, mapping to **MITRE ATT&CK** and spawning a hunt when
  suspicious; no host data leaves the box.
- **Honeypot (XOR agent)** — `--scan honeypot` runs a bounded **deception sensor** on decoy ports;
  every connection attempt is logged and the attacker IPs become IOCs.
- **AI-agent guardrails management** (`/ai-guardrails`) — the agent's `--scan aiguard` **discovers**
  the LLM apps / autonomous AI agents on each host (LangChain, CrewAI, Ollama, MCP servers, exposed
  keys), **scores** them against a **12-control AI Guardrail Baseline** (OWASP AI Exchange / Google
  SAIF / ISO 42001 / OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF), and **monitors** their traces
  with the local AI for prompt injection / jailbreak / exfiltration / excessive agency → spawned
  hunts. Inline enforcement is delegated to a guardrail gateway (NeMo / LLM Guard / Llama Guard /
  Lakera) whose block telemetry is imported.
- **TAXII 2.1 server** — publish/consume STIX feeds.
- **Local AI (Ollama)** — fully-offline assistants: **"Ask the threat model"**
  (RAG over your XORCISM data), an **intel brief builder**, a
  **vulnerability-triage agent** (KEV/EPSS + affected-asset blast radius), a
  **hunt assistant**, OCIL answer suggestions, and **red/blue copilots** — an
  **AI attack-chain analyst** (read-out of a tool-chaining run: critical path,
  findings, next offensive steps + defenses/ATT&CK·D3FEND) and an **AI exposure
  briefing** (CISO-level read-out of the fusion worklist + attack paths). Every
  copilot degrades gracefully to a deterministic data summary when the local AI
  is offline, so nothing ever blocks; no data leaves the machine.
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
| ![Domain launcher](docs/screenshots/01_landing_cards.png)<br>**Domain launcher** — pick a security domain | ![Asset management](docs/screenshots/02_asset_management.png)<br>**Asset management** — inventory, governance worklist & per-asset risk score | ![Configuration / OVAL](docs/screenshots/03_configuration_oval.png)<br>**Configuration** — OVAL definitions |
| ![Compliance / GRC](docs/screenshots/04_compliance_audit.png)<br>**Compliance** — audits, findings & evidence | ![TPRM](docs/screenshots/05_tprm_dashboard.png)<br>**TPRM** — third-party risk | ![EBIOS overview](docs/screenshots/06_ebios_dashboard.png)<br>**EBIOS RM** — study overview |
| ![EBIOS stakeholders](docs/screenshots/07_ebios_stakeholders.png)<br>**EBIOS** — stakeholders & threat zones | ![EBIOS feared events](docs/screenshots/08_ebios_feared_events.png)<br>**EBIOS** — feared events (DICT) | ![Vulnerability management](docs/screenshots/09_vulnerability_mgmt.png)<br>**Vulnerabilities** — CVE/KEV/CVSS/EPSS · SSVC |
| ![Threat intelligence](docs/screenshots/10_threat_mgmt.png)<br>**Threat intelligence (CTI)** — actors & TTPs | ![Threat modeling](docs/screenshots/11_threat_modeling.png)<br>**Threat modeling** — STRIDE | ![Incident management](docs/screenshots/12_incident_mgmt.png)<br>**Incident management** |
| ![Ticketing](docs/screenshots/13_ticketing.png)<br>**Ticketing** — tasks & comments | ![Connectors](docs/screenshots/14_xposure_connectors.png)<br>**Connectors** — nmap, nuclei, Nessus, SBOM… | ![OSINT](docs/screenshots/15_osint_tools.png)<br>**OSINT** toolbox |
| ![ATT&CK](docs/screenshots/16_matrix_attack.png)<br>**MITRE ATT&CK** — with BAS coverage heatmap | ![D3FEND](docs/screenshots/17_matrix_d3fend.png)<br>**MITRE D3FEND** — defensive matrix | ![A3M](docs/screenshots/18_matrix_a3m.png)<br>**A3M** — Agentic AI Attack Matrix |
| ![Dashboard](docs/screenshots/19_dashboard.png)<br>**Executive dashboard** — risk, exposure, trends | ![BIA](docs/screenshots/20_bia_audit.png)<br>**Business Impact Analysis (BIA)** | ![STIX graph](docs/screenshots/21_stix_graph.png)<br>**STIX graph** — hunts ↔ ATT&CK techniques |
| ![Threat hunting](docs/screenshots/22_threat_hunting.png)<br>**Threat hunting** — HUNT · IOC · ATT&CK, local-AI assistant | ![Ask the threat model](docs/screenshots/23_ask_ai.png)<br>**Ask the threat model** — local-AI RAG | ![Connectors](docs/screenshots/24_connector_search.png)<br>**Connectors** — searchable catalogue (1,200+) |
| ![Threat feeds](docs/screenshots/25_threat_feeds.png)<br>**Threat feeds** — curated CTI RSS reader (newest first) | ![Attack-surface graph](docs/screenshots/26_attack_surface.png)<br>**Attack-surface graph** — asset-centric force map | ![Attack-surface focus](docs/screenshots/27_attack_surface_focus.png)<br>**Attack surface** — focused on one asset |
| ![Pentesting](docs/screenshots/28_pentest.png)<br>**Pentesting** — engagements, scope, tooling, findings & vulns | ![LLM ATT&CK](docs/screenshots/31_llm_attack.png)<br>**LLM ATT&CK** — AI-enabled technique overlay (Anthropic) | ![BIA dependency graph](docs/screenshots/33_bia_graph.png)<br>**BIA dependency graph** — impact propagation |
| ![Kill chain graph](docs/screenshots/34_kill_chain.png)<br>**Kill chain graph** — ATT&CK phases + adversary TTPs | ![Attack chain](docs/screenshots/35_attack_chain.png)<br>**Attack chain** — tool-chaining playbook run (nmap → web scanners → WPScan) | ![Attack chain card](docs/screenshots/36_pentest_chain_card.png)<br>**Attack chain** — launch a playbook from an engagement |
| ![Web-recon chain](docs/screenshots/37_attack_chain_recon.png)<br>**Web-recon chain** — subfinder → httpx fan-out per subdomain → web scanners | ![Metasploit chain](docs/screenshots/39_attack_chain_metasploit.png)<br>**Metasploit chain** — nmap → MS17-010 → Meterpreter session (playbook library) | ![Exploit-DB search](docs/screenshots/40_exploitdb_search.png)<br>**Exploit-DB search** — keyword/CVE search of the SearchSploit index |
| ![OSINT attacker journey](docs/screenshots/42_attack_chain_osint.png)<br>**OSINT chain** — domain → subfinder/theHarvester → Shodan/HIBP → web scan (auto-inventory) | ![Top exposures](docs/screenshots/43_top_exposures.png)<br>**Top exposures** — exploitability fusion score, prioritized worklist | ![Attack paths](docs/screenshots/44_attack_paths.png)<br>**Attack paths** — easiest routes to crown jewels + choke-point analysis |
| ![AI exposure brief](docs/screenshots/45_ai_exposure_brief.png)<br>**AI copilots** — red/blue chain analyst + CISO exposure briefing (local Ollama) | ![Purple-team coverage](docs/screenshots/46_purple_coverage.png)<br>**Purple-team** — chain → ATT&CK detection coverage (Sigma) + rule generation | ![Ransomware $ impact](docs/screenshots/47_ransomware_impact.png)<br>**Ransomware $** — group TTPs → SLE/ALE dollar impact + D3FEND controls | ![Control assurance](docs/screenshots/48_control_assurance.png)<br>**Control assurance** — compliance proven live from telemetry (ISO/NIST) | ![CTI watch](docs/screenshots/49_cti_watch.png)<br>**CTI watch** — KEV/reports matched to your inventory + auto-ticket |
| ![Surface drift](docs/screenshots/50_surface_drift.png)<br>**Surface drift** — snapshot & diff the external attack surface | ![Content hub](docs/screenshots/51_content_hub.png)<br>**Content hub** — export/import playbooks, Sigma, OpenVEX | ![Identities & IAM](docs/screenshots/54_identities.png)<br>**Identities & IAM** — human + non-human (NHI) inventory, governance worklist & risk score |
| ![SSVC calculator](docs/screenshots/55_ssvc_calculator.png)<br>**SSVC** — CISA Stakeholder-Specific Vulnerability Categorization calculator (Track / Track\* / Attend / Act) | ![Incident management](docs/screenshots/56_incidents.png)<br>**Incident management** — queue, governance worklist, SLA/RTO breach & priority score | ![Compliance & GRC](docs/screenshots/57_compliance.png)<br>**Compliance & GRC** — audit inventory, remediation worklist & posture score |
| ![Policies & Documents](docs/screenshots/58_policy_management.png)<br>**Policies & Documents** — policy lifecycle & controlled-document register, governance worklist & per-policy score (ISO 42001 AIMS policies seeded EN/FR) | ![Configuration Management](docs/screenshots/60_configuration_management.png)<br>**Configuration Management** — secure-configuration content library (OVAL hardening baselines), scan-verification coverage & per-baseline health score | ![Threat-Informed Defense](docs/screenshots/61_threat_informed_defense.png)<br>**Threat-Informed Defense** — per ATT&CK technique, adversary use vs detect (Sigma) / mitigate (D3FEND) / test (Atomic) coverage, threat-weighted program score & prioritised gap worklist |

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
# --- Optional: run the Python data layer on a server DB (see docs/DATABASE_BACKENDS.md) ---
# $env:XORCISM_DB_ENGINE   = "postgresql"   # sqlite (default) | postgresql | mysql | mariadb
# $env:XORCISM_DB_HOST     = "db.internal"  # + XORCISM_DB_PORT / _USER / _PASSWORD / _PREFIX
# --- Optional: hourly NVD CVE import + CVE→asset matching ---
# $env:NVD_API_KEY   = "..."                # higher NVD rate limit (hourly importer)
# $env:XOR_PYTHON    = "python"             # python used by the in-process CVE importer
# $env:XOR_CVE_IMPORT = "0"                 # disable the hourly CVE import schedule
# $env:XOR_CVE_MATCH  = "0"                 # disable the hourly CVE→asset matcher
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
├── xorcism_python/             # SQLAlchemy models + importers/ (engine-agnostic: config.py)
├── tools/migrate_db.py         # SQLite → PostgreSQL / MySQL / MariaDB migration (see docs/DATABASE_BACKENDS.md)
├── connectors/                 # 1,200+ connectors (connector.json + run.py) + runner.py
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
| Database | Node: better-sqlite3 (synchronous, no ORM) — a family of SQLite files. Python/SQLAlchemy data layer is **portable to PostgreSQL / MySQL / MariaDB** (`XORCISM_DB_ENGINE`, `tools/migrate_db.py`); see [docs/DATABASE_BACKENDS.md](docs/DATABASE_BACKENDS.md) |
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
| **Exploit-DB search** | `/exploitdb` | Search the local SearchSploit index by keyword/CVE; CVE→public-exploit lookup on the VULNERABILITY form |
| **Top exposures** | `/exposure` | Exploitability & relevance fusion score — prioritized "fix first" worklist (EPSS+KEV+exploit+CTI+blast radius) |
| **VOC — Vuln Operations** | `/voc` | Remediation as an ops function: SLA policy, MTTR/aging/velocity, campaigns, risk-acceptance register |
| **VM Executive Report** | `/vm-report` | Vuln risk & SLA posture over time + board-ready myth-busting summary (Print/PDF) |
| **CTEM** | `/ctem` | ctem.org exposure-identifier taxonomy (29 ids / 8 categories), 3-stage program, discover-from-assets |
| **Attack paths** | `/attack-path` | Reachability graph entry→crown-jewel (subnet + BIA edges, fusion-weighted) + choke-point analysis |
| **Detection coverage** | `/purple-team` | Purple-team: chain tools → ATT&CK → Sigma-library coverage + generate the missing rule |
| **Ransomware $ impact** | `/ransomware` | Replay a ransomware group's TTPs → SLE/ALE dollar impact, blast radius, D3FEND controls |
| **Control assurance** | `/assurance` | Continuously-proven compliance — controls evaluated live from telemetry, mapped to ISO 27001 / NIST CSF |
| **CTI watch** | `/cti-watch` | "CTI that acts" — KEV + threat reports matched to your inventory + one-click auto-ticketing |
| **Surface drift** | `/drift` | Attack-surface snapshot & diff — what appeared/vanished/newly-exposed since last time |
| **Content hub** | `/content` | Export/import portable content — attack playbooks, Sigma rule bundle, OpenVEX |
| **Compliance (GRC)** | explorer | Policies, controls, audits, evidence, findings, CRQ/FAIR |
| **EBIOS Risk Manager** | `/ebios` | 5 ANSSI workshops, business values, feared events, ecosystem |
| **TPRM** | `/tprm` | Third-party / supplier risk assessments & questionnaires |
| **Threat Management (CTI)** | explorer | STIX entities, OpenCTI properties, sightings, watchlists, PIR; **lossless STIX retention + FTS search** + content-addressed object store for large files ([docs/CTI_STORAGE.md](docs/CTI_STORAGE.md)) |
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
| **BIA dependency graph** | `/bia-graph` | Force graph of BIA entries & dependencies, with impact propagation |
| **ATT&CK** | `/attack` | Enterprise / Mobile / ICS / ATLAS + BAS coverage & **LLM-enabled (Anthropic)** overlays |
| **D3FEND** | `/d3fend` | Defensive countermeasures mapped to ATT&CK & controls |
| **A3M** | `/a3m` | Agentic AI Attack Matrix |
| **Kill chain** | `/kill-chain` | ATT&CK tactics as ordered kill-chain phases + adversary TTP overlay |
| **STIX graph** | `/stix-graph` | Relationship graph; nodes link back to forms |
| **Attack-surface graph** | `/attack-surface` | Asset-centric force graph — apps, CPEs, vulns, orgs, persons, threats, incidents, tags |
| **Pentesting** | `/pentest` | Engagements (AUDIT type=Pentest) scoped to assets; run tool connectors; findings & vulnerabilities |
| **Attack chain** | `/pentest/chain` | Tool-chaining playbook run — live tree of tool steps (nmap → web scanners → WPScan), facts-driven, findings roll-up |
| **SOC Operations** | `/soc` | Analyst shifts/on-call, MTTD/MTTA/MTTR, escalation, NIST 800-61 IR playbooks |
| **SOC-CMM** | `/soc-cmm` | SOC capability-maturity assessment |
| **CERT / DFIR** | `/cert-ops` | Forensic cases, evidence & chain of custody (NIST 800-86 / ISO 27037) |
| **Team Operations** | `/team-ops` | Purple/Red/Blue VECTR-style ATT&CK exercises — prevention/detection/visibility/MTTD |
| **Governance** | `/governance` | NIST CSF 2.0 **Govern (GV)** register |
| **Workforce** | `/workforce` | NICE + ENISA ECSF roles around PERSON |
| **AI Threat Advisor** | `/ai-threat-advisor` | OWASP AI Exchange agentic-threat catalogue + advisor |
| **AI Guardrails** | `/ai-guardrails` | AI-agent guardrails management — discover LLM apps/agents, score vs a 12-control baseline (OWASP AI Exchange / SAIF / ISO 42001 / LLM Top 10 / ATLAS / NIST AI RMF), local-AI runtime violation monitoring, gateway block telemetry |
| **EASM** | `/easm` | External Attack Surface Management — internet-facing assets, exposed services/ports, TLS posture, external KEV, shadow exposure, surface drift |
| **Frameworks** | `/frameworks` | Compliance/security framework catalogue + map each framework to a VOCABULARY (controls catalogue) |
| **Network sessions** | `/network-sessions` | NetFlow/IPFIX around assets (Obserae) — services, sessions, top talkers |
| **Compliance journeys** | `/compliance-journeys` | Guided multi-framework wizards (ISO / SOC 2 / NIST / DORA / NIS2 / GDPR …) |

---

## 🔌 Connectors

Connectors live in `connectors/<id>/` with a `connector.json` manifest
(auto-discovered under **Connectors** — no rebuild) and a `run.py`. Results are
normalized into findings (project → `ASSET`, vuln → `VULNERABILITY` /
`ASSETVULNERABILITY`). The catalogue holds **1,200+** connectors and is
**searchable and filterable** (by category & type) in the UI.

| Type | Connectors |
|---|---|
| **Network / web scanners** (tool-runners) | nmap, nuclei, nikto, sqlmap, whatweb, wpscan, WPProbe, w3af, OpenVAS |
| **Vulnerability / posture (API)** | Nessus, Qualys, Rapid7, Wiz, Lacework, Sysdig, Aikido |
| **CVE intelligence** | **OpenCVE** (CVE monitoring → `VULNERABILITY`) |
| **SCA / supply chain** | Dependency-Track, OSV-Scanner, **depx** (malicious-package audit) |
| **Offensive / BAS** | Caldera, Metasploit, Metasploit-scan, Burp Suite, SAINT |
| **SIEM / detection / EDR** | Splunk, Elastic Security, Microsoft Sentinel, QRadar, **Rustinel** (ETW/eBPF), **YARA** |
| **Identity (API)** | **Microsoft Entra ID** (users / NHI / devices → `IDENTITY` + `ASSET`) |
| **OSINT** (tool-runners) | 1,000+ reconnaissance / OSINT tools from the searchable catalogue |

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

## 🧩 REST API

A read-only, tenant-scoped REST API exposes the platform's data (assets,
incidents, exposures, SLA/RTO posture, enterprise risk score) for SIEMs,
dashboards, CI pipelines and automation.

- **Base URL:** `/api/v1` · **Spec:** `GET /api/v1/openapi.json` (OpenAPI 3)
- **Interactive docs:** **`/api-docs`** · **Manage keys:** **`/api-keys`**
- **Auth:** API key (`Authorization: Bearer xor_…` or `X-API-Key: xor_…`); a key
  acts as its owning user with the same RBAC + tenant scope. SHA-256 stored only.
  Keys hold **scopes** (`read`/`write` or granular like `incidents:write`) and an
  optional **expiry**.
- **Webhooks:** register HTTPS endpoints at **`/webhooks`** to receive an HMAC-signed
  (`X-XORCISM-Signature`) JSON `POST` on `incident.created` / `incident.updated` / `asset.updated`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness probe (no auth) |
| `GET` | `/api/v1/me` | Identity behind the key |
| `GET` · `PATCH` | `/api/v1/assets` · `/assets/{id}` | Asset inventory (paginated); set SLA/value fields |
| `GET` · `POST` · `PATCH` | `/api/v1/incidents` · `/incidents/{id}` | List / create / update incidents |
| `GET` | `/api/v1/incident-sla` | Incident durations vs asset SLAs & BIA RTOs |
| `GET` | `/api/v1/exposures` | Top exposures (fusion exploitability score) |
| `GET` | `/api/v1/risk` | Enterprise risk score |

```bash
export XORCISM_API_KEY=xor_…
curl -s https://your-host/api/v1/incident-sla -H "Authorization: Bearer $XORCISM_API_KEY" | jq '.summary'
```

Full reference, examples and the roadmap: **[API.md](API.md)**.

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
