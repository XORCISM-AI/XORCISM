# XORCISM — Release Notes

All notable changes to XORCISM are documented here. Versions follow
[Semantic Versioning](https://semver.org/); dates are ISO-8601 (YYYY-MM-DD).

Pre-release (`-beta.N`) builds are feature-complete for the listed scope but may still change
before the stable cut. Database migrations run **idempotently at server boot** (CREATE IF NOT
EXISTS + additive ALTER) — upgrading is in-place and never drops data.

---

## [1.5.0-beta.1] — 2026-06-23

An **AI-security & endpoint-agent** release, headlined by **AI-agent guardrails management** — a
cockpit that discovers the LLM apps / autonomous AI agents running on your hosts, scores them
against a 12-control **AI Guardrail Baseline** (mapped to OWASP AI Exchange, Google SAIF,
ISO/IEC 42001, OWASP LLM Top 10, MITRE ATLAS and NIST AI RMF), and monitors their traces with the
**local AI** for guardrail violations. The XOR endpoint agent also gains **RAM acquisition**,
**AI log-hunting**, a **honeypot** sensor, and **fleet-wide compliance deployment**; plus an
**EASM** cockpit, **Frameworks management**, the **TaHiTI** hunting methodology, and seven new
connectors/tools.

### Highlights

- **AI-agent guardrails management** (`/ai-guardrails`) — the operational layer for guarding LLM
  apps & autonomous agents. The agent's new `aiguard` scan **discovers** AI agents (LangChain,
  CrewAI, AutoGen, LlamaIndex, Ollama/local models, MCP servers, exposed keys) and **assesses**
  each against the **AI Guardrail Baseline** (12 controls, cross-mapped to OWASP AI Exchange / SAIF
  / ISO 42001 / OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF); the **local AI** then **monitors**
  agent traces for prompt injection, jailbreaks, data exfiltration and excessive agency → spawns a
  **TaHiTI** hunt. Inline **enforcement** is delegated to a guardrail gateway (NeMo Guardrails /
  LLM Guard / Llama Guard / Lakera) whose block telemetry is imported (`llm-guard` connector).
- **XOR agent — new DFIR & AI capabilities** — `--scan memdump` (**RAM acquisition** for forensics
  via winpmem/avml; the image stays on the host for chain of custody, the manifest + SHA-256 is
  shipped), `--scan loghunt` (**AI log hunting**: collects Sysmon/PowerShell/Security logs → the
  local AI maps them to ATT&CK and spawns hunts), `--scan honeypot` (a bounded **deception sensor**
  on decoy ports; attacker IPs become IOCs), and `--scan aiguard` (above).
- **Fleet-wide compliance deployment** (`/configuration-management`) — push a CIS/OVAL compliance
  baseline to all online agents in one shot, with an optional recurrence for continuous assurance.
- **External Attack Surface Management** (`/easm`) — the attacker's outside-in view: internet-facing
  assets, exposed services & ports, TLS/cert posture, external KEV vulns, **shadow exposure** and
  surface drift, each scored.
- **Frameworks management** (`/frameworks`) — manage the compliance/security framework catalogue and
  **map each framework to a VOCABULARY** (its controls catalogue), with live control counts.
- **TaHiTI hunting methodology** (`/hunting`) — the 3-phase *Targeted Hunting integrating Threat
  Intelligence* funnel (Initiate → Hunt → Finalize) over the HUNT backlog.
- **Agents cockpit KPIs** (`/agents`) — fleet health, job success rate, scans/24h, alerts, honeypot
  hits, RAM dumps and AI-log-hunt KPIs; per-agent RAM-dump and AI-log-hunt panels.
- **New connectors & tools** — **DrogonSec** (SAST/SCA/secrets/IaC, SARIF), **graphql-cop**
  (GraphQL API DAST, wired into the attack chains), **Zabbix** (infrastructure monitoring → Asset
  Monitoring), **GLPI** (IT asset management / CMDB → assets), **EMAIL-CRAWL** (OSINT email
  harvesting), **llm-guard** (AI guardrail-gateway telemetry), plus a **GCVE CPE** dictionary search
  in the CPE editor (cpe.gcve.eu) and a topbar **"Go to…"** quick-jump menu.

### Added

**AI security**
- **AI-agent guardrails** (`aiguard.ts`, `/ai-guardrails`) — `AIAGENT` / `AIGUARDRAILRESULT` /
  `AIGUARDRAILVIOLATION` (XAGENT); the 12-control AI Guardrail Baseline; discovery scoring;
  heuristic + local-AI runtime violation monitoring → spawned TaHiTI hunts; gateway-telemetry
  ingest. Agent kind `aiguard` (`discover_ai_agents()`); `llm-guard` connector; 6 guardrail tools in
  the new **AI Guardrails** TOOL category.

**XOR endpoint agent**
- **Memory acquisition** — `--scan memdump` → `MEMORYDUMP` manifest (tool/path/size/SHA-256) + event.
- **AI log hunting** — `--scan loghunt` (`loghunt.ts`) → `LOGHUNT` + a spawned hunt when suspicious.
- **Honeypot** — `--scan honeypot` (`honeypot_listen`) → `HONEYPOTHIT` + attacker IPs as IOCs.
- **Fleet compliance deploy** — `POST /api/configuration/deploy-compliance` (OVAL fan-out + optional
  recurring enforcement).

**Modules**
- **EASM** (`easm.ts`, `/easm`), **Frameworks management** (`frameworks.ts`, `/frameworks`), the
  **TaHiTI** funnel on `/hunting`, the exploit-view on `/vulnerability-management`, and patch-package
  CVE counts on `/patch-management`.

**Connectors & tools**
- `drogonsec`, `graphql-cop` (+ attack-chain rule & a "GraphQL API assessment" playbook), `zabbix`,
  `glpi`, `email-crawl`, `llm-guard`; the **GCVE CPE** form search; the topbar quick-jump menu.

---

## [1.4.0-beta.1] — 2026-06-22

A **threat-informed operations** release: dedicated cockpits that run security as operational
functions (SOC, CERT/DFIR, Purple/Red/Blue Team, Vulnerability Operations), a board-ready
**VM Executive Report**, support for the **ctem.org** exposure-identifier standard, and a new
**CTI data architecture** — lossless STIX retention with full-text search and content-addressed
object storage (local **or S3/MinIO**) with lifecycle GC.

### Highlights

- **Security-operations cockpits** — **SOC** (`/soc`: analyst shifts/on-call, MTTD/MTTA/MTTR,
  escalation procedures, NIST 800-61 IR playbooks), **SOC-CMM** maturity (`/soc-cmm`), **CERT/DFIR**
  with chain-of-custody (`/cert-ops`), **Purple/Red/Blue Team Operations** (`/team-ops`, VECTR-style
  ATT&CK exercises with prevention/detection/visibility metrics), and the **Vulnerability Operations
  Center** (`/voc`: configurable remediation-SLA policy, MTTR/aging/velocity KPIs, campaigns,
  risk-acceptance register).
- **VM Executive Report** (`/vm-report`) — vulnerability risk & SLA posture **over time** (daily
  history) with a board-ready summary and a **data-driven "myths vs reality"** section that debunks
  common VM misconceptions using the program's *own* live numbers.
- **CTEM — ctem.org exposure taxonomy** (`/ctem`) — support for the **SecureCoders** standardized
  exposure-identifier standard (a "CVE/CWE for exposures": 29 identifiers across 8 categories, the
  3-stage Discover → Prioritize → Remediate program), with a discover-from-assets bridge.
- **CTI data architecture** — **lossless STIX/IOC retention** with **FTS5 full-text search**
  (the original object is kept, not just the normalized columns) and a **content-addressed object
  store** for large files (STIX bundles, PCAPs, samples) with a swappable **filesystem or S3/MinIO**
  backend and mark-and-sweep **garbage collection**.
- **Governance, Workforce & AI threats** — **Governance** (`/governance`, NIST CSF 2.0 **Govern**),
  **Workforce** (`/workforce`, **NICE** + ENISA **ECSF** roles around PERSON), and an **AI Threat
  Advisor** (`/ai-threat-advisor`, the **OWASP AI Exchange** agentic-threat catalogue + advisor).
- **Network observability** (`/network-sessions`) — NetFlow/IPFIX around assets via the **Obserae**
  collector: discovered assets, ASSET↔service relationships, reconstructed sessions.
- **Guided compliance journeys** (`/compliance-journeys`) and per-user **notification rules** in
  Settings (event → notification, severity-gated).

### Added

**Security operations**
- **SOC** (`soc.ts`, `/soc`) — `SOCSHIFT` on-call, MTTD/MTTA/MTTR (the dashboard gains an MTTD tile),
  `ESCALATIONPOLICY`/`TIER` + `INCIDENTESCALATION`, NIST 800-61 `PLAYBOOK`/`PLAYBOOKSTEP` attachable
  to incidents; queue with ack / escalate / run-playbook actions.
- **SOC-CMM** (`soccmm.ts`, `/soc-cmm`) — domain/aspect maturity scoring.
- **CERT / DFIR** (`certops.ts`, `/cert-ops`) — `FORENSICCASE` / `EVIDENCE` / `CUSTODYEVENT`
  (chain of custody) / `CERTACTIVITY`, NIST 800-86 / ISO 27037 aligned.
- **Purple/Red/Blue Team Operations** (`teamops.ts`, `/team-ops`) — VECTR-style `TEAMEXERCISE` /
  `EXERCISETESTCASE` mapped to ATT&CK, prevention/detection/visibility/MTTD, capability management,
  n8n automation playbooks.
- **Vulnerability Operations Center** (`voc.ts`, `/voc`) — configurable remediation-SLA policy
  (`VOCSLATIER`), KPIs over `ASSETVULNERABILITY ⋈ VULNERABILITY` (KEV/CVSS/EPSS), risk-ranked
  worklist, campaigns with burndown (`VOCCAMPAIGN`), risk-acceptance register (`VOCEXCEPTION`).

**Exposure & vulnerability**
- **VM Executive Report** (`vmtrends.ts`, `/vm-report`) — daily `VMSNAPSHOT` history (risk-weighted
  exposure, open backlog, KEV, SLA compliance, MTTR, coverage), accrued at boot + hourly; exec
  summary; six myth-busting cards computed from live data; pure-SVG trend charts + Print/PDF.
- **CTEM** (`ctem.ts`, `/ctem`) — `CTEMIDENTIFIER` reference catalogue (embedded seed +
  `import_ctem.py` from `ctem.org/source.json`) + `CTEMEXPOSURE` tracked instances run through the
  3 stages; catalogue browser, category coverage, risk worklist, discover-from-assets (internet-exposed
  → `CTEM-EXP-3/4`).

**CTI storage (the "store the original, index what you query" architecture)** — see [docs/CTI_STORAGE.md](docs/CTI_STORAGE.md)
- **Lossless STIX/IOC retention + search** (`stixstore.ts`) — a central `STIXOBJECT` store keyed by
  StixID plus `RawJson` columns on `OBSERVABLE` / `IOC` / `INTELEXCHANGE`, and an FTS5 index
  (`STIXOBJECT_FTS`). `GET /api/stix/object/:stixId` (the original object), `GET /api/stix/search`
  (IOC-aware), `POST /api/stix/ingest`, `POST /api/stix/backfill`. Live capture from the malware
  scanner + a boot/10-min reconciler that picks up connector/form writes; the Python runner now
  retains the original normalized item as `RawJson` on `INTELEXCHANGE`.
- **Content-addressed object store** (`blobstore.ts`) — SHA-256-sharded files under
  `DB_DIR/blobstore` with a `FILEBLOB` registry (dedup + refcount). Swappable backend:
  **filesystem (default) or S3/MinIO** (`XORCISM_BLOB_BACKEND=s3`, via curl's built-in SigV4 — no
  SDK dependency). `POST /api/blob` (upload), `GET /api/blob/:sha256`, `GET /api/blob/stats`.
  STIX-bundle ingest offloads the raw bundle by hash pointer. A **BlobSha256** hash-pointer column +
  `POST /api/blob/migrate` move existing in-row BLOBs (`OVALDEFINITION`, `DOCUMENT`) into the store
  (`/oval-xml` and the malware-scan reads are CAS-aware). Mark-and-sweep GC (`POST /api/blob/gc`,
  dry-run by default; pinned + referenced blobs survive). Form fields of type `BlobSha256` get an
  upload widget.

**Governance / workforce / AI**
- **Governance** (`governance.ts`, `/governance`) — NIST CSF 2.0 **Govern (GV)** register
  (`GOVERNANCEITEM`/`STATUS`), with live policy signals.
- **Workforce** (`workforce.ts`, `/workforce`) — **NICE** + ENISA **ECSF** roles (`WORKROLE` /
  `PERSONWORKROLE`) around PERSON.
- **AI Threat Advisor** (`aiexchange.ts`, `/ai-threat-advisor`) — the full **OWASP AI Exchange**
  agentic-threat catalogue (`AIEXCHANGETHREAT`) + `advise()`, plus an `owasp-ai-threat-advisor` connector.

**Operations data & UX**
- **Network sessions** (`netflow.ts`, `/network-sessions`) — `ASSETSERVICE` + `NETWORKSESSION` fed by
  the **Obserae** NetFlow/IPFIX connector (YAML/JSON import → `runner.import_netflow`).
- **Compliance journeys** (`journeys.ts`, `/compliance-journeys`) — 11 framework wizards
  (ISO 27001/42001, SOC 2, NIST CSF/800-53, FedRAMP, NIS2, DORA, CRA, MiCA, GDPR) as phased
  deep-linked checklists.
- **Notification rules** — per-user event→notification rules in Settings (`NOTIFICATIONRULE`,
  `dispatchEvent()` engine gated by enable + severity).
- **Connectors** — Obserae (NetFlow), ThePhishAnalyzer, burpwn, PySpector, n8n (SOAR),
  OWASP AI threat advisor; `docs/IMPORT_JSON_CSV.md` (table-view import guide).

### Notes

- New schema is created **idempotently at boot** (CREATE IF NOT EXISTS + additive ALTER); the CTI
  store and object store are populated in-place (no backfill flood). The S3/MinIO blob backend is
  opt-in via env and requires `curl`.

---

## [1.3.0-beta.1] — 2026-06-21

A **governance & compliance** release: end-to-end management of **NIST SP 800-53** with framework
crosswalks, a **Trust Center**, GRC-platform connectors, OT/ICS security, asset monitoring, patch
management, and CIS Benchmarks.

### Highlights

- **NIST SP 800-53 control management** (`/control-management`) — manage all **1,196** Rev 5 controls:
  per-control implementation status, responsibility, owner and narrative; **Low / Moderate / High /
  Privacy baselines**; full control text (statement, guidance, parameters, related controls); **SP
  800-53A assessments**; **POA&M**; coverage-by-family posture and a prioritised gap worklist.
- **Control crosswalks** — each 800-53 control mapped to **MITRE ATT&CK** (5,264 mappings, direct),
  **D3FEND** (direct), **NIST CSF 2.0** (direct, NIST OLIR), **DISA CCI** (authoritative), **CIS v8**
  (via CCI), and CSF-bridged **ISO 27001 / NICE** — surfaced in a per-control detail panel.
- **Trust Center** (`/trust-center`) — publish a Drata-style **public security-posture page** driven by
  live data (control coverage, frameworks, uptime, policies), shareable read-only at `/trust/<slug>`.
- **GRC connectors** — **Vanta, Drata, ServiceNow GRC, OneTrust, AuditBoard** sync evidence + policy
  documents into the controlled-document register (offline export or live API via worker env).
- **OT / ICS Security** (`/ot-security`) — IEC 62443 / NIST SP 800-82: zones & conduits with Security
  Levels, OT asset inventory, seeded requirement catalogues.
- **Asset Monitoring** (`/asset-monitoring`) — uptime/health/SSL monitors with an in-process prober;
  **"Activate monitoring"** auto-creates HTTP/SSL/Ping/DNS monitors from an asset's IP & URL, on an
  interval **or cron** schedule. New **Grafana** and **CheckCle** connectors.
- **Patch Management** (`/patch-management`) — per-asset×CVE patch lifecycle, risk-based SLAs, coverage
  & MTTR; now folded into the **dashboard** (patch-posture tiles) and the **risk score** (overdue
  patches contribute to per-asset and Enterprise Risk Score).
- **CIS Benchmarks** (under Configuration Management) — catalogue of major benchmarks + **CIS-CAT**
  result import (XCCDF / JSON).
- **CONTROL tagging** — free-text tags on controls (CONTROLTAG) with a tag-picker in the form.

### Notes

- All schema changes run **idempotently at boot** (CREATE IF NOT EXISTS + additive ALTER). New
  reference content is loaded by importers under `xorcism_python/importers/`. Marketplace connector
  listings refresh via the hourly `sync_connectors.php` cron.

---

## [1.2.0-beta.1] — 2026-06-21

Centred on **continuous exposure freshness** and **deployment portability**: the CVE database now
refreshes hourly and new CVEs are auto-matched to the assets they affect, the data layer becomes
portable to server databases, and the connector catalogue crosses **1,200+** (now searchable and
filterable) with new EDR / CVE-intel / identity integrations.

### Highlights

- **Continuous CVE → asset matching** — every new CVE is auto-linked to the assets it affects (by
  CPE + technology tags) with *"New CVEs for ASSET"* notifications.
- **Hourly NVD CVE import** — incremental, scheduled in-process.
- **Database portability (stage 1)** — the Python/SQLAlchemy data layer runs on
  **PostgreSQL / MySQL / MariaDB**, with a SQLite→server migration tool.
- **NIST SP 800-30** risk-assessment module (the EBIOS-RM counterpart).
- **New connectors** — OpenCVE, Microsoft Entra ID, Rustinel (EDR), and a real YARA connector.

### Added

**CVE → asset matching** (`cvematch.ts`, `/api/cve-match/run`)
- New CVEs are matched to assets by the asset's **CPE inventory** (vendor/product tokens) **and**
  free-text **technology tags** (`ASSETTAG`), with optional precise `VULNERABILITYFORCPE` links;
  matches create `ASSETVULNERABILITY` links and raise **"New CVEs for ASSET" notifications** to
  asset-readers. Watermark (`CVEMATCHCURSOR`, initialised to the current MAX — no backfill flood).
- Triggers: **after each CVE import**, an **hourly** background matcher, and **on demand** (the
  *↻ Match CVEs* button on Asset Management / `POST /api/cve-match/run`). `XOR_CVE_MATCH=0` disables.

**Hourly NVD CVE import**
- `import-nvd-cve` schedule (`XSCHEDULE`, cron `0 * * * *`) runs `import_nvd_cve.py --recent-only`
  in-process (single-flight; `XOR_PYTHON` / `NVD_API_KEY`; `XOR_CVE_IMPORT=0` to disable).

**Database backends — PostgreSQL / MySQL / MariaDB (stage 1)** — see [docs/DATABASE_BACKENDS.md](docs/DATABASE_BACKENDS.md)
- `xorcism_python/config.py` is engine-agnostic (`XORCISM_DB_ENGINE` + `XORCISM_DB_HOST/PORT/USER/PASSWORD/PREFIX`).
- `tools/migrate_db.py` copies the SQLite databases to a server backend (reflect → recreate → bulk copy).
- The Node server remains on SQLite (the async port is a documented stage 2).

**Risk assessment — NIST SP 800-30** (`/nist-800-30`)
- Reuses `RISKASSESSMENT` (Methodology = "NIST SP 800-30") + `NIST80030THREATSOURCE` / `THREATEVENT`
  / `VULNERABILITY` / `RISK`; dashboard, guided-create, and the Appendix I Table I-2 risk matrix.

**Connectors & catalogue**
- **OpenCVE** — CVE monitoring/alerting → `VULNERABILITY` (Bearer/Basic auth, vendor/product/CVSS filters).
- **Microsoft Entra ID** — users / service principals & managed identities (NHI) / devices → `IDENTITY` + `ASSET`
  via Microsoft Graph (app-only OAuth2); new runner path `import_identities`.
- **Rustinel** — kernel-level EDR (ETW/eBPF/ESF + Sigma/YARA/IOC) alerts → findings; plus an XOR-agent
  bridge (`--scan rustinel`).
- **YARA** — the scaffold is now a real connector (matches → findings; rules → the new `YARARULE` store);
  XOR-agent `--scan yara` (part of `--scan full`).
- **Connectors page** — now **searchable and filterable** (category / type / intrusive), like the tool catalogue.

**Asset / UX**
- **Guided-create modals** for Assets, Audits and NIST 800-30 assessments (replacing the raw explorer insert).
- **`ASSET.AssetID` is now a real `INTEGER PRIMARY KEY`** (idempotent boot migration `ensureAssetPrimaryKey`,
  rebuild preserving all data) — fixes the legacy non-PK auto-assign quirk.

### Changed
- Connector catalogue **300+ → 1,200+**; agent `--scan full` now also runs **Rustinel** + **YARA**.

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
- **PQCMM — Quantum Readiness** (`/pqcmm`, scope `pqcmm:read`) — the PKI Consortium's Post-Quantum
  Cryptography Maturity Model: assess products/assets against the 6 levels (0 None → 5 Optimized),
  track current vs target maturity, and roll up the quantum-readiness posture (vulnerable /
  production-ready / managed) with a maturity score and a below-target worklist.
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
