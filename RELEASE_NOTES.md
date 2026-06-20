# XORCISM — Release Notes

All notable changes to XORCISM are documented here. Versions follow
[Semantic Versioning](https://semver.org/); dates are ISO-8601 (YYYY-MM-DD).

Pre-release (`-beta.N`) builds are feature-complete for the listed scope but may still change
before the stable cut. Database migrations run **idempotently at server boot** (CREATE IF NOT
EXISTS + additive ALTER) — upgrading is in-place and never drops data.

---

## [1.1.0-beta.1] — 2026-06-20

A large release centred on **operationalising defence**: a complete Threat-Informed Defense
loop, first-class CTI-platform connectors, crisis-management tabletop exercises, live endpoint
forensics, and the metrics to watch it all from one dashboard.

### Highlights

- **Threat-Informed Defense (TID) cockpit** — a self-monitoring detect/mitigate/test program
  keyed on MITRE ATT&CK, all the way from "do we cover our adversaries?" to drift alerting.
- **CTI-platform connectors** — MISP, OpenCTI and SOC Prime, into the intel exchange and the
  Sigma detection library.
- **Crisis Management & Tabletop Exercises** — a scenario library and exercise readiness scoring.
- **Live endpoint forensics (DFIR triage)** in the XOR agent.
- **Executive-dashboard KPIs** for the two new programs.

### Added

**Threat-Informed Defense** (`/threat-informed-defense`, scope `tid:read`)
- Per ATT&CK technique, a threat-weighted score comparing adversary use (groups, ×3 for local
  CTI/hunts) against **detect** (Sigma), **mitigate** (D3FEND + ATT&CK) and **test** (Atomic Red
  Team) coverage, with a prioritised gap worklist.
- **Close-the-validation-gap loop**: *Build validation plan* turns the top untested high-threat
  techniques into a BAS emulation scenario; *Run on agent* has the XOR agent execute the injects
  and report real outcomes; **detection attribution** correlates each executed inject with host
  telemetry (Detected / Logged / Executed-undetected).
- **False-coverage** surfacing (a Sigma rule exists but the emulation proved it didn't fire) and
  **detection-drift alerting** — a previously-proven detection that regresses raises a
  Defender-aligned `XINCIDENT.ALERT` (de-duplicated) the moment it's observed.
- **✨ Draft Sigma** generates a **procedure-tuned** detection rule (local AI, deterministic
  skeleton fallback) for any detection gap; **🔁 Schedule weekly** re-validates on a cadence.
- **ATT&CK Navigator layer export** (v4.5 JSON; one-click download or `…/navigator-layer` API).

**CTI-platform connectors** (`connectors/`)
- **MISP** → `INTELEXCHANGE` (events, galaxies → ATT&CK/actor/malware tags, CVEs, IOC summary).
- **OpenCTI** → `INTELEXCHANGE` (GraphQL reports, or a STIX 2.1 bundle offline).
- **SOC Prime** → **both** `SIGMARULE` and `INTELEXCHANGE` (Sigma detection content), feeding the
  TID *detect* pillar.
- New runner path `import_sigma_rules` so any detection-content connector can populate the Sigma
  library. All connectors run live (API + env credentials) or fully offline (saved export);
  stdlib-only, idempotent.

**Crisis Management & Tabletop Exercises** (`/crisis-management`, scope `crisis:read`)
- A tabletop exercise (TTX) is an audit of type *Tabletop Exercise*, plus dedicated
  `CRISISSCENARIO` / `EXERCISEINJECT` / `EXERCISEPARTICIPANT` tables.
- A seeded library of **7 crisis scenarios** (ransomware, data breach, DDoS, insider,
  supply-chain, cloud-account, BEC) with timed injects; one click **launches** an exercise from a
  scenario (copying its injects).
- A **crisis-readiness score** (exercise completion × scenario coverage) and an improvement
  worklist (overdue actions, scenarios never exercised, exercises with no after-action report).

**Endpoint agent**
- **Advanced forensics (live DFIR triage)** — `--scan forensics` collects a **read-only**
  live-response snapshot (processes, network connections, persistence/autoruns, logon sessions,
  recent files, ARP/DNS/routes, drivers, event-log summary) with conservative triage **flags**
  → `XAGENT.FORENSICTRIAGE` + a `forensic_triage` event. Collection never modifies the host.
- **Recurring OVAL/SCAP scans** — schedule scans on a cadence (hourly/daily/weekly/monthly) from
  Configuration Management; the in-process scheduler (`XSCHEDULE`) queues an agent job each cycle.
- **Native Windows OVAL evaluator** for hosts without OpenSCAP (registry / files / WMI / env), with
  the full OVAL result algebra.

**Governance & content**
- **Risk Register** governance page (`/risk-register`, scope `risk:read`) — inherent → current →
  residual posture, treatment/owner/review and CRQ/FAIR ALE per risk, a treatment worklist
  (untreated high/critical residual, accepted-without-justification, overdue reviews, treatments
  past target, unowned) and a residual-posture score; mirrors the asset/identity/compliance family.
- **FAIR-MAM Materiality** (`/fair-mam`, scope `fairmam:read`) — the FAIR Institute's Materiality
  Assessment Model: an interactive calculator decomposes a cyber loss event's single-loss magnitude
  across the 10 standardized cost categories (PERT min/most-likely/max), splits primary vs secondary
  (and first- vs third-party) loss, and renders a materiality verdict against a threshold. Extends
  the CRQ/FAIR figures on the risk register.
- Governance pages for **Policy** (`policies:read`) and **Configuration Management**
  (`configuration:read`), mirroring the asset/identity/incident/compliance family.
- Seeded **ISO/IEC 42001:2023 (AI Management System)** policies in English & French, plus its
  **Annex A controls**.
- **Executive dashboard** KPI strip extended with Threat-Informed Defense (program score,
  detection coverage, false-coverage/drift, exposed techniques) and Crisis Management (readiness,
  scenario coverage, improvement actions) tiles.

### Changed

- Public REST API (`/api/v1`) gained the `policies:read`, `configuration:read`, `crisis:read` and
  `tid:read` scopes and a **Governance** OpenAPI tag; `/api/v1/threat-informed-defense`,
  `/threat-informed-defense/navigator-layer` and `/crisis-management` endpoints added.
- `version` reported by `GET /health` and the OpenAPI document is now `1.1.0-beta.1`.

### Security notes

- **BAS emulation execution is opt-in and safety-gated** (`XOR_ALLOW_EMULATION=1`): only read-only
  reconnaissance commands auto-run; writes / persistence / downloads / credential-dumping /
  exec-chains are reported `Skipped` for manual execution.
- **Forensics collection is strictly read-only** — it inspects host state via standard tools and
  never modifies the host.
- Auto-drafted Sigma rules are marked **experimental** — capability (a rule exists) stays separated
  from **proven** efficacy (a re-run emulation fired it).

### Known limitations (beta)

- The MISP / OpenCTI / SOC Prime connectors were verified through their **offline import** paths;
  the live-API paths follow each platform's documented endpoints (SOC Prime's API is auth-gated, so
  offline import is the primary path).
- Detection attribution and drift detection reflect the host's available telemetry — on an
  unconfigured host, a benign inject correctly records *Executed (ran undetected)* rather than a
  false detection.

### Upgrade notes

- Schema changes apply automatically at server boot (new tables: `CRISISSCENARIO`,
  `EXERCISEINJECT`, `EXERCISEPARTICIPANT`, `FORENSICTRIAGE`; additive columns elsewhere).
- Seed the new content libraries: `python xorcism_python/importers/seed_crisis_scenarios.py` and
  `seed_iso42001_policies.py` / `import_iso42001_controls.py`.
- **Rebuild / redeploy the XOR agent** to pick up forensics and the recurring-scan kinds (a fresh
  `agent/dist/xor_agent.exe` is included). See [`agent/SETUP.md`](agent/SETUP.md).
- New optional connector env vars: `MISP_URL`/`MISP_KEY`, `OPENCTI_URL`/`OPENCTI_TOKEN`,
  `SOCPRIME_API_KEY`.

---

## [1.0.0] — baseline

The established XORCISM platform: a single, self-hosted application unifying **cyber exposure,
threat and compliance** over a set of SQLite databases — no SaaS, no telemetry.

- **Asset, vulnerability & exposure** management (CPE/CVE, KEV, CVSS, EPSS, exploit & CTI fusion,
  attack-path and choke-point analysis, CTEM loop).
- **Cyber Threat Intelligence** — STIX 2.1 / TAXII 2.1 server & client, threat graph, MITRE
  ATT&CK / ATLAS / D3FEND / CAPEC matrices, OpenCTI-style enrichment, threat hunting, threat feeds.
- **Governance, Risk & Compliance** — audits, findings, evidence, policies, OCIL questionnaires,
  CRQ/FAIR quantitative risk, EBIOS Risk Manager, TPRM.
- **Offensive & purple** — pentest engagements, tool-chaining playbooks, adversary emulation
  (BAS), purple-team detection coverage, bug-bounty programs.
- **Automation** — 300+ connectors with a remote-worker model, a local-AI assistant suite
  (Ollama), the cross-OS XOR endpoint agent (inventory / vuln / OVAL / AV / hunt), and a
  public REST API with OpenAPI docs.
