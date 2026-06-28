# XORCISM — Release Notes

All notable changes to XORCISM are documented here. Versions follow
[Semantic Versioning](https://semver.org/); dates are ISO-8601 (YYYY-MM-DD).

Pre-release (`-beta.N`) builds are feature-complete for the listed scope but may still change
before the stable cut. Database migrations run **idempotently at server boot** (CREATE IF NOT
EXISTS + additive ALTER) — upgrading is in-place and never drops data.

---

## [Unreleased]

- **Performance — much faster page loads & navigation.** Three deep changes:
  - **Shared i18n bundle (the big one).** The 11-language i18n dictionary (~700 KB) was being inlined into
    *every* page bundle **and** into `session-ui.js` (loaded on every page) — so each page shipped ~1.9 MB
    of mostly-duplicated strings. It's now built **once** as `/js/i18n.js` (a `window.XORI18N` global) and
    externalized from all 107 page bundles via an esbuild plugin; pages load it first and the browser caches
    it across the whole app. Result: **`dashboard.js` 983 KB → 31 KB, `session-ui.js` 976 KB → 24 KB**, etc.
    A page that used to ship ~1.9 MB now ships **~222 KB brotli on first visit** and **~7–30 KB per
    subsequent navigation** (the shared chunk is already cached) — navigation is near-instant.
  - **Brotli/gzip pre-compression.** Bundles are brotli-11 + gzip-9 compressed at build; a new `/js`
    middleware serves the precompressed bytes directly (smaller than on-the-fly gzip — `i18n.js` 953 KB →
    **210 KB brotli** — and removes per-request compression CPU from the synchronous hot path), falling back
    to live compression otherwise.
  - **SQLite tuning.** Added `synchronous=NORMAL`, `cache_size=16 MB`, `temp_store=MEMORY` and
    `mmap_size=256 MB` (on top of the existing WAL) to speed reads/writes on the query hot path.
- **Agentless & offline host scan (Cyberwatch-style credentialed scan)** — added the one acquisition
  method XORCISM was missing: a **credentialed agentless host scan**. Instead of an agent, an admin
  **SSH** (Linux/Unix) or **WinRM/PowerShell** (Windows) session — or an **air-gapped collector** for
  segregated networks (*mode déconnecté*) — reads the host's OS, installed software and a few
  security-baseline checks into a JSON snapshot. New **`agentless-scan` connector** + bundled
  **`collect.sh`** / **`collect.ps1`** collectors (run remotely or locally, read-only, no agent). On
  import: the host → **ASSET**; the OS and **every installed package → a CPE linked to that asset**, so
  XORCISM's own CVE matcher (`cvematch`, runs post-import) **detects every affected CVE with no active
  probing** — agentless vulnerability detection that then flows into Vulnerability Management, Patch
  Management, exposure prioritization (EPSS/KEV/SSVC/Exploit-DB) and the attack-path graph. Failed
  baseline checks → **hardening VULNs + a per-host "hardening level: N%"** (Cyberwatch-style Compliance
  Manager); CVEs already in the snapshot import directly. CPEs resolve to correct NVD `vendor:product`
  via a built-in package map (openssh→openbsd, httpd→apache, mysql→oracle…). 100% offline / self-hosted —
  no host data leaves your infrastructure. Plus the **"Agentless host scan → vulnerabilities & hardening"
  attack-chain playbook** (`/chain`) that seeds `agentless-scan` and escalates findings to CyberSentinel
  AI. (Inspired by [Cyberwatch](https://cyberwatch.fr/)'s Vulnerability Manager + Compliance Manager.)
- **pentest-ai-agents (AI pentest agents) — TOOL + connector + attack chain** — added
  [pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents), a suite of **50 Claude Code subagents
  for penetration testing** (recon / scanning / exploitation / post-exploitation / reporting) that
  orchestrate 80+ tools (nmap, nuclei, sqlmap, BloodHound, Impacket, Ghidra…) and persist to a **SQLite
  findings database** (`engagements / hosts / services / vulns / credentials / chains`) plus markdown/JSON
  reports. New **`pentest-ai-agents` connector** ingests that engagement — the **SQLite findings DB itself**
  (opened read-only) *or* a **JSON export** of its tables, auto-detected — and maps `hosts` → **ASSETs**
  (tagged by OS/role), `services` → **service facts**, and each `vuln`, recovered `credential` and
  identified attack-`chain` → a severity-ranked **VULN** carrying the agent's own `mitre_id`, CVE, CVSS,
  `tool_used` and found-by agent. Worker-safe (no live targeting, never writes the source DB). Plus the
  **TOOL catalogue entry** and the **"AI-driven pentest (pentest-ai-agents)" attack-chain playbook**
  (`/chain`) which seeds `pentest-ai-agents` and escalates any finding to CyberSentinel AI for deep ATT&CK
  analysis — feeding exposure / attack-path / vulnerability views.
- **RedCloud-OS (cloud adversary simulation) — TOOL + connector + attack chain** — added
  [RedCloud-OS](https://github.com/RedCloudOS), the *"Cloud Adversary Simulation Operating System for
  Red Teams"* that bundles the leading cloud attack tools across **AWS / Azure / GCP / Kubernetes**
  (Pacu, ScoutSuite, Prowler, cloud_enum, cloudfox, PMapper, heimdall, AzureHound, ROADtools,
  gcp_scanner, GCPBucketBrute, peirates, KubiScan, BloodHound, gitleaks…) organised by kill-chain phase.
  New **`redcloud-os` connector** ingests a RedCloud-OS engagement bundle — or a **raw ScoutSuite
  (`scoutsuite_results` JS/JSON), Prowler (OCSF / v3 JSON) or BloodHound/AzureHound/PMapper graph**
  export, all **auto-detected** — and maps cloud resources & identities to **ASSETs** (tagged by CSP +
  kind) and every misconfiguration / public exposure / privilege-escalation edge to an **ATT&CK-tagged
  cloud-attack VULN** (T1078/T1098/T1190/T1530/T1552/T1556/T1562/T1580), severity raised toward
  privileged targets. Worker-safe (no live cloud or DB access in `run.py`). Plus the **TOOL catalogue
  entry** and the **"Cloud adversary simulation (RedCloud-OS)" attack-chain playbook** (`/chain`) which
  seeds `redcloud-os` and escalates any finding to CyberSentinel AI for deep ATT&CK analysis — feeding
  exposure / attack-path / cloud-security views.
- **SOC 2 journey — full Trust Services Criteria coverage** — the SOC 2 (Type II) compliance journey
  (`/compliance-journeys`) was expanded from a 4-phase outline to a complete walkthrough of the AICPA
  Trust Services Criteria: **8 phases · 31 deep-linked steps**. Scope & system description (report type,
  category selection, system boundary, subservice organizations) → the **Common Criteria broken out
  criterion-by-criterion** (CC1–CC2 control environment & communication · CC3–CC4 risk assessment &
  monitoring · CC5–CC6 control activities & logical/physical access · CC7–CC9 operations, change &
  risk mitigation) → the **optional categories** (Availability A1 · Confidentiality C1 · Processing
  Integrity PI1 · Privacy P1–P8) → operating the controls & building the evidence trail → readiness,
  the **Type I report**, the observation window and the **Type II examination by a licensed CPA**. Each
  step deep-links into the module that does the work (scope, identities, risk register, monitoring,
  controls, config, vulnerabilities, incidents, crisis/BCP, TPRM, privacy, policies, awareness,
  evidence). Fully bilingual (EN/FR) — criteria numbers/titles only, original summaries (no TSC text
  reproduced).
- **ISO/IEC 42001:2023 journey — full standard coverage** — the AI Management System (AIMS) compliance
  journey (`/compliance-journeys`) was expanded from a thin 5-phase outline to a complete walkthrough of the
  standard: **8 phases · 37 deep-linked steps** covering every clause (4 Context · 5 Leadership · 6 Planning
  · 7 Support · 8 Operation · 9 Performance evaluation · 10 Improvement, down to each sub-clause 4.1→10.2)
  plus the Annex A control objectives (A.2 Policies … A.10 Third-party & customer relationships). Each step
  deep-links into the module that does the work (scope, risk register, AI risk & impact assessment, controls,
  policies, AI guardrails, TPRM, evidence, audit). Fully bilingual (EN/FR). Built from a structural read of
  the standard — clause numbers/titles only, original summaries (no normative text reproduced).
- **Vulnerability Assessment (Vulners-style) + Vulners connector** — integrated the missing Vulners.com
  capabilities. New **`/vuln-assessment`** page turns a **software inventory** into a decision-ready
  vulnerability report (their *Assessment / SBOM Analyzer / Library Audit*): paste OS packages
  (`dpkg -l` / `rpm -qa`), language packages (pip / npm / **PURL**), **CPE** URIs, or `product version`
  lines and each component is matched against XORCISM's own enriched store
  (`XVULNERABILITY.VULNERABILITYFORCPE`) and scored with CVSS, EPSS, CISA KEV, SSVC and **Exploit-DB**
  availability into **Act / Prioritise / Track** — 100% offline. New `server/vulnaudit.ts` (`parseInventory`
  + `assessInventory`), `POST /api/vuln-assessment`, landing card, EN/FR. Plus a **`vulners` connector** +
  TOOL entry that queries the Vulners API (**search / id / audit** modes — Lucene search, CVE lookup, and the
  agentless OS-package audit → VULNERABILITY; needs `VULNERS_API_KEY`, or normalises a saved response offline)
  for broader coverage and precise version-range matching.
- **CyberArkHound (CyberArk PAM attack paths) — TOOL + connector + attack chain** — added
  [CyberArkHound](https://github.com/jazofra/CyberArkHound) ("BloodHound for CyberArk": exports CyberArk
  PVWA / Privilege Cloud data — safes, accounts, users, groups, CCP AppIDs, PSM servers + the safe
  membership/permission matrix — into a BloodHound OpenGraph JSON of privilege-escalation / credential-access
  paths) to the TOOL catalogue, plus a **`cyberarkhound` connector** that ingests the OpenGraph JSON →
  CyberArk entities as ASSETs and each attack-path edge (HasAccessTo, CanGrantAccessTo, CanRetrieveViaCCP,
  CanHijackViaReconcile, CanApprove, LinkedTo) + misconfiguration (unrestricted CCP AppID, safe without CPM,
  wildcard AllowedSafes, PSM without session monitoring) as an identity-attack VULN (ATT&CK-tagged
  T1078/T1098/T1187/T1528/T1555; severity raised toward privileged targets / unrestricted CCP), plus a
  **"CyberArk PAM attack paths (CyberArkHound)"** attack-chain playbook (`chain.ts`) that escalates findings
  to CyberSentinel AI for ATT&CK mapping — feeding exposure / attack-path / ITDR.
- **ASD/ACSC "AI & ML — Supply chain risks and mitigations" (2025) — document + control framework** —
  ingested the Australian Signals Directorate guidance (co-sealed by CCCS, CSA-SG, NIS-KR, NCO-JP, NCSC-NZ,
  NCSC-UK, NSA; CC BY 4.0) into the **DOCUMENT** register (PDF stored in the content-addressed blob store,
  TLP:CLEAR / Public, framework-tagged) and imported its mitigations as the selectable control framework
  **"ASD AI/ML Supply Chain (2025)"** — `import_asd_ai_supplychain.py` → `XORCISM.CONTROL` (VocabID 48, **32
  controls** across 6 components: cross-cutting supply-chain risk management, AI data, ML models, AI software,
  AI infrastructure/hardware, third-party services), each carrying the risk it mitigates and the NIST
  Adversarial ML / MITRE ATLAS (AI Supply Chain Compromise) mappings. Added to the framework picker
  (control register, compliance journeys, document tagging). Complements the AI-security suite (AISVS, MLASVS,
  DASF, SAIF, AICM).
- **Mitigant Cloud Attacks Matrix — `/cloud-attacks`** — imported the **Mitigant Threat Catalog**
  (threats.mitigant.io, derived from the AWS Threat Technique Catalog): **139 AWS cloud attack techniques
  across 12 tactics**, each with a severity, AWS service (41 distinct), MITRE ATT&CK technique id,
  executable **AWS CLI commands** (256) and the **CloudTrail events** they generate (354, for detection).
  New importer `import_mitigant.py` (committed snapshot → `XTHREAT.MITIGANTTACTIC` / `MITIGANTTECHNIQUE`,
  idempotent full-replace) + a matrix view at `/cloud-attacks` (tactics as columns, severity-coloured cells,
  filter by keyword / AWS service / severity, click a technique for its description, commands and CloudTrail
  events) via `GET /api/mitigant/matrix`. Cross-linked from the ATT&CK / D3FEND / A3M matrices + a landing
  card. EN/FR. Mirrors the A3M / D3FEND matrix integrations.
- **GraphSpy (Entra ID / M365 attack tool) — TOOL + connector + attack chain** — added
  [GraphSpy](https://github.com/RedByte1337/GraphSpy) (initial-access & post-exploitation for Entra ID /
  Microsoft 365: device-code phishing, access/refresh/PRT token abuse, OneDrive/SharePoint/Outlook/Teams
  exfiltration, MFA-method persistence) to the TOOL catalogue, plus a **`graphspy` connector** that ingests
  a GraphSpy engagement export (JSON) → tenant/users/devices as ASSETs and captured tokens, successful
  device-code phishes, over-privileged weak-MFA users and PRT exports as identity-attack VULNs
  (ATT&CK-tagged T1528/T1550/T1078/T1114), plus a **"Microsoft 365 / Entra ID attack (GraphSpy)"**
  attack-chain playbook (`chain.ts`) that seeds GraphSpy and escalates any finding to CyberSentinel AI for
  ATT&CK mapping — feeding the exposure / attack-path / ITDR pipelines.
- **Cloud Management: AWS compliance checker + CloudTrail & AWS Config** — `/cloud-security` gains a built-in
  **CIS AWS Foundations** checker. Upload an AWS posture snapshot (or produce it with the new `aws-config` /
  `aws-cloudtrail` data or the `aws-compliance` connector) and it scores: IAM **password policy** (length/reuse/
  complexity), **MFA for IAM console users**, **no root account access keys** & **root MFA**, **inactive users
  (90 days)**, **access-key rotation (90 days)**, **CloudTrail** enablement (multi-region / log-file validation /
  CloudWatch Logs / KMS) and **AWS Config** all-regions recorder. Results are stored in `XORCISM.CLOUDFINDING`
  and shown with a compliance score and pass/fail-by-severity. New `evaluateAwsCompliance` in `cloudsec.ts`,
  `POST /api/cloud-security/aws-check` + `GET /api/cloud-security/compliance`, an `aws-compliance` connector
  (failing checks → VULNs) and TOOL-catalogue entries (AWS CIS Checker, CloudTrail, AWS Config).
- **CRQ Decision Support — `/crq` (Gartner-aligned)** — following Gartner's *Innovation Insight for Cyber Risk
  Quantification* (operationalize CRQ, don't just produce a number), a new cockpit turns the quantified risk
  register (FAIR/CRQ annualized loss) into the four decisions Gartner says a mature program answers
  continuously: **what to remediate first** (ranked by ALE), **which investments cut the most risk** (expected
  ALE reduction / ROSI), **which risks breach appetite** (board-level), and **scenario comparison** (current vs
  treated ALE) — in financial terms with an uncertainty band. Read-only over the live register, so it is
  continuous rather than periodic. New `crq.ts` + `GET /api/crq`, landing card, EN/FR.
- **ANSSI open-source tools (catalogue + connector)** — added the ANSSI-FR tools to the TOOL catalogue:
  **DFIR-ORC**, **ORADAD**, **ORADAZ**, **AD Control Paths**, **ADTimeline**, **bmc-tools**, **DECODE**,
  **OSAKA**, **fuzzysully**, **packetweaver**, **polichombr**, **lidi** — plus an **`anssi-ad-control-paths`
  connector** that maps AD Control Paths' relationship CSV into AD objects (ASSET) and identity attack-path
  findings (VULN), with severity raised for paths to high-value targets (Domain/Enterprise Admins, the domain root).
- **Threat-Intel Copilot (Exvora-inspired) — `/threat-copilot`** — a "noise → signal, decision-ready"
  cockpit grounded entirely in XORCISM's own data (no external SaaS). **Decision-ready triage** scores every
  relevant CVE to **Act / Prioritise / Track** from KEV (active exploitation), EPSS (exploit probability),
  CVSS and the stored SSVC decision, each with a confidence and a plain-English "why" — scoped to the
  tenant's asset estate (ASSETVULNERABILITY) when links exist, else the global KEV/high-EPSS frontier. A
  **multi-mode analyst** (the "Vera"-style assistant) answers in four modes — **Ask** (answer from your
  data), **Investigate** (a CVE / threat actor / asset), **Draft** (a board-ready threat-landscape brief)
  and **Challenge** (Analysis of Competing Hypotheses + a cognitive-bias checklist over your HYPOTHESIS
  records) — and **always shows the queries it ran and the sources it cited**. Uses the local LLM for
  synthesis with a deterministic offline fallback, so it works with no model configured. New
  `server/threatcopilot.ts` + `/api/threat-copilot/{feed,ask}`, landing card, EN/FR.
- **OVAL editor → latest version + test-content inspector** — the `/oval-editor` now targets the
  **OVAL-Community** schema line: a schema-version selector (**5.12.3 / 5.12.1 / 5.11.2**, default latest;
  5.11.2 kept for OpenSCAP interop) drives the generated `<oval:schema_version>`. You can now **see what a
  criterion's test (`tst`) actually checks**: a "👁 view test" inspector on every criterion shows the test
  type, check / check_existence, and the referenced object + state entities (name / operation / datatype /
  value) plus the raw bundle XML. Because XOVAL only ever imported the definition→criteria→test skeleton
  (test objects/states were never imported), an **⬆ Import test content** action ingests a full OVAL
  document (CIS benchmark or distro feed) and stores a self-contained per-test bundle into `OVALTEST.BLOB`
  (matched by test id, upsert); a Python CLI `import_oval_tests.py` does the same for bulk/offline feeds.
  With content imported, the editor can also emit **self-contained OVAL** (inlining the referenced
  `<tests>/<objects>/<states>`), turning an authored definition into an evaluatable document. New
  `parseOvalTests` / `importOvalTestContent` / `getOvalTest` in `ovaleditor.ts`.
- **ARF (Asset Reporting Format) import/export for Asset Management** — the `/asset-management` page gains
  **Export ARF** and **Import ARF** buttons that speak the NIST **Asset Reporting Format 1.1** (NISTIR 7694)
  over the **Asset Identification 1.1** (NISTIR 7693) data model — the SCAP container OpenSCAP and validated
  scanners emit. *Export* serialises the asset estate to an `<arf:asset-report-collection>`: each asset is an
  `<arf:asset>` wrapping an `<ai:computing-device>` (CPE, FQDN, hostname, motherboard-GUID, IPv4/IPv6
  network-interfaces), plus a XORCISM inventory-extension report carrying the GRC fields the AI model can't
  express (criticality, environment, business/financial value, PII, MFA, description/notes) and a
  `<core:relationships>` block linking the report `isAbout` every asset (ARF relationship vocabulary). *Import*
  ingests any ARF/Asset-Identification XML — a foreign scanner's result file (read as AI computing-devices) or a
  XORCISM export (AI identity **+** the extension merged back) — creating assets, or **upserting by name** when
  the option is ticked. The parser is namespace-tolerant (matches by element local-name, so `arf:`/`ai:`/`core:`
  or no prefix all work). CPEs are exported but not re-linked on import (CPE links are derived data, re-creatable
  via the CVE matcher). New `server/arf.ts`; verified by full export→parse→create→upsert round-trip on a DB copy
  and `.xml` well-formedness validation. EN/FR.
- **Excel/CSV import for the Risk Register and Risk Assessments** — the `/risk-register` page gains two
  import buttons (**Import register**, **Import assessments**) that open a column-mapping dialog. Upload an
  Excel (`.xlsx`/`.xls`) or CSV file; the dialog lazy-loads the SheetJS reader, detects the header row,
  and lets you map each spreadsheet column to the target field (with fuzzy auto-matching of common
  EN/FR header names, and a one-click downloadable template). Risk-register fields: title (required),
  reference/ID, category, description, status, treatment, probability (1–5), impact (1–5), review date,
  target date — the **inherent risk level is computed as probability × impact**. Risk-assessment fields:
  name (required), description, status, version, date. An optional **"update existing"** checkbox upserts
  by title (register) / name (assessment) instead of always creating. Rows with a blank required field are
  skipped and per-row errors are surfaced. Server importers (`importRiskRegisterEntries` /
  `importRiskAssessments` in `riskregister.ts`, column-aware + transactional, capped at 5000 rows/request,
  RBAC + audited) write to `XCOMPLIANCE.RISKREGISTERENTRY` / `RISKASSESSMENT`. The dialog is a reusable
  client helper (`xlsx-import.ts`) shared with Asset Management's import. EN/FR.
- **ISO/SAE 21434:2021 support (automotive cybersecurity engineering)** — `import_iso21434.py` loads the
  standard's clause structure (clauses 5–15, the normative "requirements & recommendations" sub-clauses:
  organizational & project cybersecurity management, distributed & continual activities, concept,
  product development, validation, production, operations & maintenance, end-of-support &
  decommissioning, and the TARA method) into `XORCISM.CONTROL` as the Vocabulary **"ISO/SAE 21434:2021"**
  (42 sub-clauses, CIS = clause id e.g. `15.6`). Only the factual clause numbering + short headings are
  used (the copyrighted normative text is not reproduced — each `Statement` is an original one-line
  summary). Added to the framework picker, a guided **ISO/SAE 21434 lifecycle journey** (org/project
  management → TARA & concept → development & validation → production/operations/assurance), and a
  website compliance card (Automotive · R155, EN/FR + structured data). It's the engineering backbone
  for UNECE WP.29 R155 (CSMS) type approval. Committed snapshot; idempotent; launched on prod.
- **CVE→asset matching: far fewer false positives (precision-tuned)** — the continuous CVE→ASSET
  matcher (`cvematch.ts`) used to link an asset to any CVE whose **full description** contained one of
  the asset's tokens, with only a tiny stop-list — so an asset tagged `email` matched the ~4,900 CVEs
  that merely mention "email", and bare vendor/OS tokens (`apple`, `windows`, `microsoft`) matched
  almost everything. Matching is now **confidence-tiered** and only auto-links at/above a threshold
  (default **Medium**):
  - **High** — a precise CPE link (`VULNERABILITYFORCPE` ↔ the asset's CPE, which *is* populated:
    62k rows) or a CPE **vendor+product pair** both word-matched in the CVE text.
  - **Medium** — a *specific product* token (from the asset's CPE products, or a product-shaped tag).
  - **Low** — a short/ambiguous tag (recorded, not auto-linked by default).
  - **Dropped** — a large blocklist of generic categories / protocols / OS / vendor names
    (email, web, dns, vpn, firewall, cloud, windows, apple, microsoft, …) and bare CPE vendor tokens
    never match on their own. Every auto-link now records **MatchConfidence / MatchSource /
    MatchedToken** on `ASSETVULNERABILITY` for audit and triage.
  The on-demand rematch (`POST /api/cve-match/run`) accepts `minConfidence` (`high|medium|low`) and an
  opt-in `rescore` that **re-scores the existing keyword-matched backlog and flags the now-weak links
  as FalsePositive** (reversible; scanner-found and manually-added links are left untouched). Verified
  on copies: an `email`-tagged asset went from ~thousands of bogus links to **0**; the backlog rescore
  flagged ~1,800 weak legacy links while keeping the legitimate ones.
- **Advanced OVAL Definition editor (/oval-editor)** — author and edit OVAL definitions in XORCISM with
  a visual editor that **reuses the OVAL content already imported in XOVAL** (140k+ tests, 35k+
  definitions). A metadata form (class/affected-family comboboxes, title, description, version,
  deprecated, CVE/CCE references) plus a **recursive criteria-tree builder**: AND/OR/ONE/XOR groups
  nest freely; `criterion` leaves pick an existing OVAL **test** via an autocomplete combobox
  (`/api/oval/test-search`), `extend_definition` leaves pick an existing **definition**
  (`/api/oval/def-search`); every node has negate / comment (and criteria have applicability_check).
  It generates an **OVAL 5.11-compliant** `<oval_definitions>` document (live preview + download) and
  **persists the definition relationally** into the XOVAL tables (OVALDEFINITION + the
  OVALCRITERIA / OVALCRITERIACRITERION / OVALCRITERIAEXTENDDEFINITION / OVALCRITERIAFOROVALCRITERIA
  tree) **and** stores the generated XML in OVALDEFINITION.BLOB. Authored definitions use the
  `oval:ai.xorcism:def:N` namespace + a repository marker so they stay separate from the imported
  CIS/MITRE reference set; any imported definition can be loaded as a clone, edited and saved as a new
  authored definition. Reached from the OVAL-scan page and the explorer OVALDEFINITION form. New
  endpoints under `/api/oval/*` (meta / test-search / def-search / definition GET+POST / preview),
  RBAC-guarded on XOVAL.OVALDEFINITION and audited. (Objects/States aren't reconstructable — those
  XOVAL tables were not imported — so leaves reference tests by id, the standard OVAL repository
  authoring model.) Verified end-to-end on a copy of XOVAL.db (create / load round-trip / update).
- **CMMC 2.0 support (DoD Cybersecurity Maturity Model Certification)** — `import_cmmc.py` loads the
  CMMC 2.0 model (32 CFR Part 170) into `XORCISM.CONTROL` under the Vocabulary **"CMMC 2.0"**: the
  assessable practice set — **Level 1 (17 FAR 52.204-21 practices, FCI)** + **Level 2 (110 practices =
  NIST SP 800-171 Rev 2, CUI)** across the 14 domains, with the 17 Level-1 practices flagged (CIS ids
  like `AC.L1-3.1.1` / `AC.L2-3.1.3`) — plus a 1:1 **`CONTROLMAPPING` crosswalk** of every practice to
  its NIST SP 800-171 Rev 2 id so CMMC is interoperable. (Level 3 = Level 2 + selected NIST SP 800-172
  enhanced requirements, government-assessed — noted in the catalogue.) The catalogue is embedded from
  public-domain NIST/DoD text (no fragile fetch) and a committed `importers/data/cmmc.json` snapshot is
  written; idempotent (delete-then-insert by VocabularyID). Added to the framework picker, a guided
  **CMMC 2.0 compliance journey** (scope/level → implement practices → SSP & SPRS self-assessment →
  POA&M & C3PAO certification), and a website compliance card (EN/FR + structured data). Launched on prod.
- **TTPForge support (Meta adversary-emulation engine)** — `import_ttpforge.py` makes XORCISM
  understand the **TTPForge** TTP format (github.com/facebookincubator/TTPForge, Meta's Purple-Team
  attack-simulation engine: TTPs as declarative YAML — MITRE ATT&CK mapping, args, and multi-step
  actions with cleanup). It parses any TTPForge TTP repository and loads each TTP into XORCISM's
  adversary-emulation library — `XTHREAT.ATOMICTEST` (Source="TTPForge", ATT&CK technique resolved
  from the `mitre:` block, steps rendered into Command/Cleanup) grouped into a runnable
  `EMULATIONSCENARIO` — exactly like the Atomic Red Team importer, feeding the BAS / ATT&CK
  validation-coverage heatmap. A committed snapshot ships the engine's example TTPs; `--repo <path>`
  (PyYAML) re-parses a fresh clone or **your own red-team TTP library**, and `--label` names the
  scenario. Idempotent (upsert by the TTP `uuid`); `requirements.platforms` drives platform inference;
  Go-templated structural files and `tests/` self-test fixtures are skipped. A TTPForge entry was added
  to the tool catalogue (Adversary Emulation). Verified on a copy of XTHREAT.db.
- **OWASP AISVS 1.0 imported + "Free GRC tool" landing page** — `import_aisvs.py` parses the OWASP
  **Artificial Intelligence Security Verification Standard** (github.com/OWASP/AISVS, v1.0, June 2026)
  into a committed JSON snapshot and loads its **191 verification requirements across 12 chapters**
  (training-data integrity, input validation, model lifecycle, infrastructure, access control & identity,
  supply chain, model behavior & safety, memory/embeddings/vector DB, orchestration & agentic security,
  MCP security, adversarial robustness, monitoring & logging — each graded Level 1/2/3) into
  `XORCISM.CONTROL` under the Vocabulary **"OWASP AISVS 1.0"**, as a selectable AI control framework
  next to ISO/IEC 42001, NIST AI RMF, the EU AI Act, CSA AICM, MLASVS and Databricks DASF. Re-parse a
  fresh clone via `--repo`. Added to the framework picker + an OWASP AISVS TOOL entry. Idempotent;
  launched on prod. A new SEO-optimized website page **/free-grc-tool.html** details the GRC features
  (policy lifecycle, quantified risk register, compliance & audit, controls library, Trust Center,
  TPRM, privacy, AI governance), benefits, and the 40+ supported frameworks (EN + FR, JSON-LD
  SoftwareApplication + FAQPage, sitemap + internal links).
- **Bulk remediation, false-positive triage & remediation/FP-aware risk scoring** — the ASSET form's
  "Vulnerabilities for Asset" panel gains two actions and the risk model is revised to reflect them:
  - **"+ Plan for all"** creates a remediation plan for *every* open (non-false-positive) vulnerability
    of the asset in one shot (`POST /api/patch-management/remediation-bulk`); all plans share a name so
    they form a single patch package. Resolved instances are skipped, and by default instances that
    already have a plan are skipped (idempotent) — a scope toggle allows forcing a plan on every open
    instance. No ticket storm (bulk creates plans only).
  - **False-positive toggle** on each vulnerability row (`POST /api/patch-management/false-positive`)
    sets `ASSETVULNERABILITY.FalsePositive`; flagged rows render greyed/struck and drop out of the
    worklists and risk scores.
  - **Revised risk scores (asset + enterprise).** The canonical `ASSET.RiskScore` and the aggregated
    `EnterpriseRiskScore` now (a) **exclude analyst-confirmed false positives** from the vulnerability
    and overdue-patch terms (previously false positives still inflated the score), and (b) **discount
    each open vulnerability by its remediation status** — residual risk = exposure × (1 − mitigation):
    Done/Resolved ×0.1, In progress ×0.5, Planned ×0.85, Deferred/none ×1.0 (most-mitigating plan
    wins). Overdue plans still incur the existing SLA penalty, so genuine progress lowers risk while
    slippage is punished. Enterprise inherits the asset improvements through its asset-sum component.
- **Asset MFA tracking + Excel/CSV asset import** — `ASSET` gains an `MFAEnabled` flag (0/1) to
  record whether multi-factor authentication is implemented on an asset; the column is added
  idempotently at boot (`ensureAssetColumns`) and is editable/visible in the explorer (Yes/No) and
  the guided "New asset" modal. Asset Management (`/asset-management`) adds an **⬆ Import Excel**
  workflow: upload an Excel (`.xlsx`/`.xls`) or CSV file, **map its columns to asset fields** (with
  fuzzy header auto-matching), optionally **upsert** existing assets by name (only mapped columns are
  updated — blanks never overwrite existing data), and bulk-create the rest. A one-click `.xlsx`
  template download documents the expected layout. Booleans accept yes/true/1/x/✓/oui. Parsing happens
  client-side (lazy-loaded SheetJS); the server endpoint (`POST /api/asset-management/import`, RBAC
  `create XORCISM.ASSET`, audited) creates via the same path as the guided form. Fully bilingual
  (EN/FR). Mapped fields: name (required) / description / criticality / environment / OS / hostname /
  IPv4 / Internet-facing / hosts-PII / **MFA enabled** / business value / financial value / currency /
  notes.
- **OWASP SPVS imported** — `import_spvs.py` parses the OWASP **Secure Pipeline Verification Standard**
  (owasp.org/www-project-spvs) into a committed JSON snapshot and loads both releases as selectable
  control frameworks: **SPVS 1.0 (110 requirements)** and **SPVS 1.5-AI (132 requirements)** → two
  `XORCISM.CONTROL` vocabularies, across the five pipeline stages (Plan / Develop / Integrate / Release
  / Operate) with L1/L2/L3 maturity and NIST 800-53 / OWASP CI/CD Top-10 (CICD-SEC) / CWE mappings.
  Re-parse a fresh clone via `--repo`. Added to the framework picker + an OWASP SPVS TOOL entry
  (DevSecOps). Idempotent; launched on prod.
- **MLASTG / MLASVS imported** — `import_mlasvs.py` parses the MLASTG repo (bb1nfosec/MLASTG, the
  "MLSec Application Security Testing Guide" — the ML/AI analogue of OWASP MASVS/MASTG) into a
  committed JSON snapshot and loads its **MLASVS verification standard (114 L1/L2 controls** across
  Data, Model, LLM, Supply Chain, Pipeline, Infrastructure and Governance, each with its MITRE ATLAS
  mapping + MLASTG test reference) into `XORCISM.CONTROL` under Vocabulary **"MLASVS (MLASTG)"**.
  Re-parse a fresh checkout via `--repo`. Added to the framework picker + a MLASTG TOOL catalogue entry.
  Idempotent; launched on prod.
- **Databricks AI Security Framework (DASF) imported** — `import_dasf.py` parses the published DASF
  workbook (Google Sheets export) into a committed JSON snapshot (`importers/data/dasf.json`) and loads
  it into XORCISM across three homes: **73 mitigation controls → `XORCISM.CONTROL`** (Vocabulary
  "Databricks DASF", with control type / AI-lifecycle step / mitigated-risk ids), **97 AI-lifecycle
  risks → `XTHREAT.DASFRISK` + `DASFCOMPONENT`** (per-risk component, mitigating controls, and
  deployment-model applicability — Predictive ML / RAG / Fine-tuned / Pre-trained / Foundational LLMs;
  mirrors the SAIF importer), and **46 third-party AI-security tools → `XORCISM.TOOL`** (Category "AI
  Security", with URLs). Re-runnable on a fresh export via `--xlsx`. "Databricks DASF" added to the
  framework picker. Idempotent; launched on prod.
- **ACSC Information Security Manual (ISM) imported + Essential Eight cockpit** — analyzed the ASD/ACSC
  Information Security Manual (June 2026, 261 pp) and built `import_ism.py`, which parses it into a
  committed JSON snapshot (`importers/data/ism_controls.json`) and loads **49 cyber security principles
  (GOV/IDE/PRO/DET/RES/REC) + 1101 security controls** into `XORCISM.CONTROL` under the Vocabulary
  **"ACSC ISM"** (with security-classification applicability NC/OS/P/S/TS and Essential Eight maturity
  mapping in each description). Re-runnable on newer editions via `--pdf`. "ACSC ISM" added to the
  framework picker. **New feature derived from it:** an **ASD Essential Eight Maturity** cockpit
  (`/essential-eight`, `ess8.ts`) — the 8 mitigation strategies × maturity levels ML0–ML3, with a
  per-strategy self-assessment, the official overall scoring (lowest level achieved across all eight),
  a gap worklist, and each strategy linked live to its backing ISM Essential-8 controls (122 mapped).
  Fully localized (FR + EN, `ess8.*`), landing card (`landing.ess8`), RBAC + boot demo seed (tenant 3).
- **ODESSA AI-IR Loop support** — integrated [ODESSA](https://github.com/Nate-Carroll-Cyber/ODESSA-AI-IR-Loop)
  ("Operate In Darkness, Illuminate Threats"), an open-source **AI Incident Response** framework, as a
  runnable **SOAR playbook**. Added a new `ai.adversarial` SOAR trigger ("Adversarial AI signal (model
  interaction)") and an idempotent **"ODESSA AI-IR Loop"** builtin playbook whose six ordered steps are
  the mandatory ODESSA cycle — Observation → Detection → Escalation → Source validation → Safeguard →
  Assessment — mapped to SOAR actions, plus a TOOL catalogue entry. Seeded at boot for tenant 3.
- **SOAR, Ask the Fleet & DevSecOps cockpits fully localized (FR)** — `/soar` (`soar.*`),
  `/endpoint-query` (`eq.*`) and `/devsecops` (`dso.*`) were English-only; all now use the i18n layer
  (FR + EN).
- **Seven framework / regulation importers** — created and launched importers populating
  **XORCISM.CONTROL** (idempotent, delete-then-insert by VocabularyID): **ISO/IEC 27002:2022** (93
  controls, titles only), **CIS Critical Security Controls v8** (18 controls / 153 safeguards, new
  `CIS Controls v8` vocab), **DORA** (Reg. (EU) 2022/2554, 64 articles), **NIS2** (Dir. (EU)
  2022/2555, 46 articles), **EU AI Act** (Reg. (EU) 2024/1689, 60 compliance-relevant articles),
  **GDPR** (Reg. (EU) 2016/679, 52 articles — new `GDPR` vocab), and **SOC 2 2017 TSC** (61 Trust
  Services Criteria — new `SOC2` vocab). 394 controls total; the empty ISO 27002 / DORA / NIS2 / EU
  AI Act vocabulary stubs are now populated. Copyrighted standards carry identifiers + titles only.
- **ANSSI Dalton — control-framework connector** — new `dalton` connector + TOOL entry parses the
  ANSSI Dalton matrix CSV (github.com/ANSSI-FR/dalton — thématique / verticale / pallier measures)
  into **XORCISM.CONTROL** under the Vocabulary "ANSSI Dalton", via a new reusable **`controls`
  import path** in the connector runner (`import_controls`, find-or-create vocab + upsert by id).
- **Six AI/GRC cockpits + their landing cards fully localized (FR)** — `/reg-calendar` (`rc.*`),
  `/ai-systems` (`ais.*`), `/ai-redteam` (`art.*`), `/llm-pentest` (`llmp.*`), `/ai-skills`
  (`aiops.*`) and `/agents` (`agt.*`) were English-only; all now use the i18n layer (FR + EN). The
  landing **Regulatory Calendar / AI System Inventory / LLM Red-Team / LLM Pentest Methodology / AI
  Operations / Ask the Fleet** cards are translated too (`landing.regcal`/`aisystems`/`airedteam`/
  `llmpentest`/`aiops`/`endpointquery`).
- **Wider ASSETVULNERABILITYREMEDIATION form** — the explorer form now opens as a wide modal (added
  to `WIDE_MODAL_TABLES`).
- **NADAR-CTI connector — Digital Risk Protection ingestion** — new `nadar-cti` connector +
  [TOOL](https://github.com/AdnanTL/NADAR-CTI) entry. NADAR-CTI scans 8 public OSINT sources
  (crt.sh, Ransomware.live, GitHub, URLScan, paste sites, LeakIX, Have I Been Pwned, Shodan) for an
  org's external exposure; the connector parses its JSON export and fans the multi-category findings
  into XORCISM in **one pass**: discovered subdomains/exposed hosts → **ASSET**, Shodan CVEs / LeakIX
  misconfig / exposed admin panels → **VULNERABILITY + ASSETVULNERABILITY**, and ransomware mentions /
  credential leaks / breaches → **CTI (XTHREAT.INTELEXCHANGE**, ATT&CK-tagged T1486 / T1078).
  Breached emails and credential leaks also feed the attack-chain engine. Wired into **/cti-expert**
  (two Digital-Risk-Protection techniques) and a new **"Digital Risk Protection sweep (NADAR-CTI)"**
  attack-chain playbook (DRP sweep → nmap the discovered hosts → CyberSentinel AI triage). All imports
  idempotent.
- **Wider ASSETVULNERABILITYREMEDIATION & TICKET forms** — both explorer forms now open as wide modals
  (added to `WIDE_MODAL_TABLES`), matching the other long forms.
- **Content hub & Wi-Fi Pentest fully localized** — `/content` (export/import cards for attack
  playbooks, Sigma bundle, OpenVEX) and `/wifi-pentest` (posture grades, per-network worklist,
  ATT&CK coverage, recommended toolkit, scan/import/demo actions and the import modal) were
  English-only; both now use the i18n layer (`chub.*` / `wifi.*`, FR + EN).
- **Wider TICKET form** — the `XTICKET / TICKET` explorer form now opens as a wide modal (added to
  `WIDE_MODAL_TABLES`), matching the other long forms.
- **Tool Catalogue fully localized** — `/tools` (the GitHub-style star catalogue) was English-only;
  its chrome, stat cards, search/sort toolbar, category pills, star tooltips, empty states and
  "load more" pager now use the i18n layer (`tcat.*`, FR + EN). *(Prefix is `tcat.` — `tc.` is the
  Trust Center.)*
- **Malware Scan, AI Threat Advisor & ChatOps fully localized** — `/malware-scan` (engine status,
  verdict badges, summary cards, worklist/document/history tables, scan controls), `/ai-threat-advisor`
  (system-shape checkboxes, advisor cards, OWASP catalogue) and `/chatops` (console chrome, welcome
  message, replies) were English-only; all three now use the i18n layer (`ms.*` / `ata.*` / `chat.*`
  keys, FR + EN). The landing **Agentic CROC Orchestrator** and **Two-way ChatOps** cards are now
  translated too (`landing.orch` / `landing.chatops`).
- **Six more cockpits fully localized** — `/siem`, `/mssp`, `/team-ops`, `/croc-orchestrator`,
  `/knowledge-graph` and `/osint-graph` were English-only; all now use the i18n layer
  (`siem.*` / `mssp.*` / `tops.*` / `cro.*` / `kg.*` / `og.*`, FR + EN). The landing
  **Security Knowledge Graph** card is now translated too (`landing.kgraph`). *(`/hunting` was
  already localized.)*
- **SIGMARULE tagging** — Sigma detection rules can now be tagged (`ransomware`, `tier-1`,
  `needs-tuning`…) from the explorer form, like assets/controls. New `XTHREAT.SIGMARULETAG` table +
  `GET/PUT /api/sigmarule-tags`.
- **Threat-content forms** — `HUNT`, `SIGMARULE` and `INTELEXCHANGE` explorer forms are now wide
  modals; their name columns (`HuntName` / `SigmaRuleName` / `IntelName`) are click-to-edit; and
  `HUNT.ValidFrom`, `HUNT.HuntDate` and `SIGMARULE.ValidFrom` got date pickers.
- **Purple-team, attack-chain viewer & Cyber Insurance Readiness fully localized** — `/purple-team`,
  the `/pentest/chain` run viewer and `/insurance-readiness` (including the policy modal) were
  English-only; all three now use the i18n layer (`pt.*` / `ch.*` / `ir.*` keys, FR + EN).
- **Bug-bounty program: edit by clicking the Name** — in the `XVULNERABILITY / BUGBOUNTYPROGRAM`
  explorer view the Name is now a click-to-edit link, and the `BUGBOUNTYPROGRAM` form is a wide modal.
- **run-server.bat pulls the local-AI model** — the launcher now runs `ollama pull llama3.1:8b`
  (idempotent) when Ollama is found, so the AI copilots' default model is present on first start.
- **Attack-surface graph & Adversary Opportunity Index fully localized** — `/attack-surface` (node-type
  labels, scope/legend, details) and `/adversary-opportunity` (gauge, the seven debt sources, "price the
  fix" tables, attack paths) were English-only; both now use the i18n layer (`as.*` / `ao.*` keys, FR + EN).
- **Vulnerability Management: see impacted assets** — in the triage worklist the affected-assets cell is now
  clickable and expands the in-scope assets impacted by that CVE (reusing `GET /api/fusion/vuln/:id/assets`),
  each linking to the asset's edit form. (Clicking the CVE to edit the vulnerability was already supported.)
- **Risk register: edit by clicking the Title** — in the `XCOMPLIANCE / RISKREGISTERENTRY` explorer view the
  Title is now a click-to-edit link (opens that entry's form), and the `RISKREGISTERENTRY` form is now a wide modal.
- **ASSET form → ASSETVULNERABILITY** — the ASSET edit form now has a link that opens the `ASSETVULNERABILITY`
  explorer view filtered to that asset's `AssetID`.
- **Board Report fully localized** — the `/board-report` cockpit (cards, the six board questions,
  trend/drivers panels, risk & financial tables, executive narrative) was English-only; now uses the
  i18n layer (`br.*` keys, FR + EN, others fall back to EN).
- **Exposure: see impacted assets** — on `/exposure`, the "N assets" chip is now clickable and
  expands an inline list of the in-scope assets impacted by that vulnerability (name · criticality ·
  internet-facing · address), each linking to the asset's edit form. New `GET /api/fusion/vuln/:id/assets`.
- **Patch Management: click a CVE to edit it** — in the patch worklist the CVE is now a link that opens
  the vulnerability's edit form (`VULNERABILITY` in the explorer), alongside the existing asset link.
- **CyberSentinel AI — primary-engine playbook** — [CyberSentinel AI](https://github.com/3sk1nt4n/cybersentinel-ai)
  was already integrated (TOOL + `cybersentinel-ai` connector + AI-triage step in 5 attack chains); added a
  new **"AI-driven full assessment (CyberSentinel AI)"** chain playbook that seeds it as the *primary* tool
  (live host/URL scan or offline results JSON → ASSET + VULNERABILITY, ATT&CK-tagged).
- **SCA & Security Awareness fully localized** — the `/sca` (Software Composition Analysis) and
  `/security-awareness` cockpits were English-only; both now use the i18n layer (`sca.*` / `saw.*`
  keys, FR + EN, other languages fall back to EN).
- **Demo SBOM in the demo account** — the demo tenant now ships with a representative CycloneDX SBOM
  (7 components, incl. a known-vulnerable `log4j-core` and license/version gaps) so `/sca` has content
  out of the box. Seeded idempotently at boot (`seedScaDemo`). *(Appears after a server restart.)*
- **AUDITFINDING form** — the explorer's create/edit form for `AUDITFINDING` is now a wide modal with
  a date picker on the **Due date** (alongside the existing Finding date).
- **Faster page loads (gzip + minified bundles)** — the client bundles inline the 11-language i18n
  dictionary, so every page was shipping **800 KB–1.4 MB of uncompressed JS**. Two fixes: the
  esbuild build now **minifies** (set `XOR_NO_MINIFY=1` to opt out for debugging), and the server
  now **gzip-compresses** responses (`compression` middleware). Net effect: `app.js` drops from
  **1.4 MB → ~325 KB on the wire (−70%)**, and `session-ui.js` (loaded on every page) from
  ~0.9 MB → ~260 KB. *(Requires a server restart to pick up compression.)*
- **Asset Management is now fully localized** — the `/asset-management` cockpit (KPI cards, table
  headers, governance worklist, legend, the "new asset" modal, toasts) was English-only; it now
  uses the i18n layer (`asm.*` keys, FR + EN, other languages fall back to EN).
- **IDENTITY form** — the explorer's create/edit form for `IDENTITY` is now a wide modal with
  date pickers on **Expiry**, **Last rotated**, **Last used** and **Modified** dates.
- **Incident evidence attachments** — each incident on **/incident-management** now carries a 📎 evidence
  button: attach screenshots, logs or exports (≤ 15 MB) straight from the queue. Files are stored in the
  content-addressed blob store (`XORCISM.FILEBLOB`, deduped by SHA-256 and pinned so they're never
  GC'd) and registered per-incident in the new `XINCIDENT.INCIDENTEVIDENCE` table; download reuses
  `/api/blob/:sha256`. Attaching/detaching is gated on incident **update** (read-only roles only see
  the list) and audited (`incident_evidence_attach` / `_detach`). This is the lightweight path — for
  chain-of-custody handling use **CERT Operations** (forensic cases).
- **Strix connector + attack-chain playbook** — imports findings from [Strix](https://github.com/usestrix/strix),
  the autonomous AI hacking agent (validates IDOR/injection/SSRF/XSS/auth/business-logic with a PoC): the
  target becomes an `ASSET`, each validated finding a `VULNERABILITY` (severity + CWE + PoC). New
  **"Autonomous AI pentest (Strix)"** playbook in `chain.ts` (seed Strix → CyberSentinel AI triage on any
  finding). + `Strix` in the tool catalogue (Penetration Testing).
- **Rulezet "detections for my exposed CVEs"** — `tools/rulezet_detections_for_cves.py` reads the CVEs
  present on your assets (`ASSETVULNERABILITY` ⋈ `VULNERABILITY`), prioritizes them by KEV/EPSS/CVSS, and
  pulls the matching Rulezet detection rules into `SIGMARULE`/`YARARULE` — closing the loop from exposure
  to ready-to-deploy detection.

- **Rulezet detection-rule connector** — searches [Rulezet](https://rulezet.org) (the open-source
  repository of ~197k community detection rules — YARA/Sigma/Suricata/Zeek/CRS/Nova/Wazuh/Elastic — over
  858+ ATT&CK techniques) and imports the matches into XORCISM. Search by **CVE** (CIRCL
  Vulnerability-Lookup proxy), by **ATT&CK technique** (attack-chain step) or free-text; Sigma & other
  formats → `SIGMARULE`, YARA → `YARARULE`, with the rules' ATT&CK techniques kept as tags so they light
  up **Threat-Informed Defense** and **Purple-Team** detection coverage. + `Rulezet` in the catalogue.
- **Hunt.io wired into CTI-Expert** — Hunt.io C2 / malicious-infrastructure enrichment is now an Enrich
  technique in `/cti-expert`, so an IP/domain investigation auto-includes it.
- **Website compliance page** gains a **Design & Documentation assessments** explainer card (EN + FR).

- **Hunt.io CTI connector** — enriches threat intelligence from the [Hunt.io](https://hunt.io) API
  (api.hunt.io): pass an `ip` to enrich a single address (`/v1/enrich/ip/{ip}`) or pull the active-C2
  feed (`/v1/c2s`). Each result becomes a `XTHREAT.INTELEXCHANGE` record (idempotent) carrying the
  malware family, AS/country, certificate subject, JARM/JA4 fingerprints and the C2 ATT&CK technique
  (T1071). API key via env. + `Hunt.io` in the tool catalogue.
- **HDS & TISAX journeys are now fully French** (`journeys_fr.ts`), like the other compliance journeys.

- **EDR connectors** — the most popular endpoint platforms, on a shared normalizer (`connectors/_edr.py`):
  **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **SentinelOne**, **Palo Alto Cortex XDR**
  and **VMware Carbon Black Cloud**. Each imports the vendor's detections/alerts into `XINCIDENT.ALERT`
  (via `runner.import_incidents`), links the impacted endpoint as an `ASSET`, keeps the ATT&CK
  tactic/technique as the classification, and normalizes severity across every vendor scale (0-100, 1-10,
  words, malicious/suspicious). 5 new tools in the catalogue (Endpoint Security).
- **Audit: Design & Documentation assessments** — `AUDIT` (and `AUDITFINDING`) now carry an
  `AssessmentType` (ISAE 3000 / SOC 2 dimension): **Design Assessment**, **Documentation Assessment**,
  **Operating Effectiveness**, Combined, or Readiness. Selectable in the guided *New audit* form and the
  explorer; `/compliance-management` reports the type per audit and design/documentation counts. Existing
  audits default to Operating Effectiveness.
- **HDS & TISAX compliance journeys** — guided, phased journeys for the two frameworks added last
  release, in `/compliance-journeys` (HDS: scope → ISO 27001/20000-1 foundation → health-data
  requirements → certification; TISAX: scope/level → VDA-ISA InfoSec → prototype & data protection →
  assessment & label).

- **Governed documents: Standards & Procedures on top of Policies** — the policy register (`POLICY`) now
  carries a `DocumentType` (Policy / Standard / Procedure / Guideline) and a `ParentPolicyID` (the ISO
  documentation pyramid: Procedure → Standard → Policy), so Standards and Procedures get the *same*
  lifecycle as policies — publish, version history, and per-user acknowledgement. `/policy-management`
  shows the type per document and a Policy/Standard/Procedure/Guideline breakdown; the explorer form has
  the type picker + parent link. Existing rows default to `Policy` (no change to the policy register).
- **HDS & TISAX framework support** (OverSecur-by-FeelAgile standards parity) — `import_hds.py` (HDS /
  Hébergeur de Données de Santé: the 6 certified hosting activities + health-data requirements on an
  ISO 27001 + 20000-1 foundation, with GDPR/ISO crosswalks) and `import_tisax.py` (TISAX / VDA-ISA:
  Information Security + Prototype Protection + Data Protection control areas + AL1/2/3 assessment levels,
  with an ISO 27001 Annex A crosswalk) → `XORCISM.CONTROL`. Both in the framework picker and on the
  website compliance page (16 → 18 cards, EN + FR). XORCISM already covered OverSecur's other standards
  (ISO 27001, NIS2, DORA, SOC 2) and its 360°-posture / automated-control / e-learning capabilities.

- **AI Operations cockpit** (`/ai-skills`) — "govern your *own* agentic AI" (inspired by Filigran XTM
  One's agentic layer; the counterpart to the AI inventory and AI-BAS). Four things in one cockpit:
  a governed **Skills & Prompt Library** (`AISKILL` — reusable markdown skills/prompts with tags,
  visibility, enable/disable, versioning and usage counts, that the copilots draw from); an **AI activity
  / decision-provenance log** (`AIACTIVITY` — every copilot/orchestrator decision recorded with actor,
  action, model, entity and outcome → **EU AI Act Art. 12 record-keeping, ISO 42001, NIST AI RMF
  MANAGE-4** evidence; the orchestrator now logs every propose/execute); the **agentic-flow / agent
  handover routing** (`AIHANDOVER` + the orchestrator's default routes, as an editable
  delegate/consult/transfer/escalate graph); and the configured **AI provider** (`aiProviderInfo()` —
  local Ollama by default, optional OpenAI-compatible / Anthropic / Azure via env).
- **Admiralty / NATO source grading** (STANAG 2511) — source-reliability **A–F** × info-credibility
  **1–6** on intel exchanges, reports and threat actors (`admiraltyGrade()` → combined grade + 0–100
  confidence), selectable in the explorer.

- **NIST AI RMF 1.0 support** — `import_nist_ai_rmf.py` loads the full NIST AI Risk Management Framework
  Core (GOVERN / MAP / MEASURE / MANAGE, **72 subcategories**) into `XORCISM.CONTROL` under the
  `"NIST AI RMF 1.0"` vocabulary (already in the framework picker and the AI-inventory governing-framework
  list), plus a guided **NIST AI RMF compliance journey** (`/compliance-journeys`) that walks the four
  functions. The AI-governance counterpart to ISO/IEC 42001 and the CSA AICM.
- **Website — small-business page** is now **fully localizable** (FR + the other 9 site languages) via
  `data-i18n` keys and a new `FR` block, with a language switcher in the nav, plus a new **Use cases**
  section (SaaS startup, clinic, law/accounting firm, manufacturer, e-commerce, public body).
- **Website — compliance page** now surfaces the frameworks XORCISM already supports but didn't show:
  **ISO/IEC 42001** (AIMS), **NIST AI RMF**, **CSA AICM**, **ISO/IEC 27031** (ICT readiness for BC),
  **ISO/IEC 27701** (PIMS) and **PCI DSS v4.0** — 6 new framework cards (EN + FR, grid 10 → 16), with
  title/OG/JSON-LD updated. The NIST AI RMF journey is also fully French (`journeys_fr.ts`).
- **Praxen connector** — imports a [Praxen](https://open-agent-ai-security.github.io/praxen/) AI-agent
  behaviour-verification report (by Exabeam): it checks an agent's code/config/logs against its declared
  Worker Remit (policy divergence, credential exposure, missing controls, capability drift, hidden
  prompts, compound attack paths) and maps findings to the OWASP LLM Top 10 (2025) / Agentic AI (2026).
  The connector turns the JSON report into agent **assets + findings** *and* an OWASP-LLM result list
  (→ `/ai-redteam` → auto-fills `/llm-pentest`), and seeds a new **"AI agent assessment"** attack-chain
  playbook (`chain.ts`). + `Praxen` in the TOOL catalogue.
- **OASIS connector** — imports a report from [OASIS](https://github.com/psyray/oasis), the *Ollama
  Automated Security Intelligence Scanner* — an **AI-powered SAST** tool (local Ollama LLMs + embeddings)
  that finds 24+ vulnerability classes and emits **SARIF 2.1.0**. The connector parses the SARIF (shared
  `_sarif.py`) into project assets + findings and records a **DevSecOps SAST scan** (`oasis` added to the
  runner's `_DEVSECOPS_TOOLS`). + `OASIS` in the TOOL catalogue.

- **LLM Application Penetration Test methodology** (`/llm-pentest`) — the **OWASP Top 10 for LLM
  Applications** testing methodology (after the Fortbridge field guide) as a structured **engagement**
  per AI system: all 10 OWASP-LLM-2025 categories × the guide's concrete test cases (instruction
  override, encoding tricks, indirect injection, RAG access across roles, model provenance/checksum,
  poisoning, RBAC/BOLA, system-prompt extraction, hallucination, token-flood…), each tracked
  *not-tested → pass / fail / partial / n-a* with severity, finding and evidence. It **composes** the
  engines XORCISM already runs rather than re-probing: automatable categories **auto-fill from the
  latest AI-BAS run**, LLM03 Supply chain from **AI-BOM model provenance**, LLM04 Poisoning from the
  **AI-runtime drift** signal; manual categories (RAG/vector, supply-chain audit, excessive agency) are
  seeded for the tester. Blended **readiness score** (coverage × pass-rate) + grade, a findings
  worklist, the 5-step engagement workflow, and high/critical findings that feed the **CROC loop**
  (`llm.pentest_finding`). `LLMPENTEST` + `LLMPENTESTCASE`.
- **Promptfoo connector** — imports `promptfoo redteam eval` output (the automation engine of the
  Fortbridge methodology), maps each red-team plugin to the OWASP LLM Top 10, and feeds the LLM
  red-team / AI-BAS module (`POST /api/ai-redteam/import`) → which auto-fills a `/llm-pentest`
  engagement. Joins the existing `garak` / `PyRIT` importers.

---

## [1.6.0-beta.1] — 2026-06-26

A **risk-quantification, privacy & supply-chain** release, headlined by two new top-line lenses that
join the defender's Enterprise Risk Score:

- **Adversary Opportunity Index (AOI)** (`/adversary-opportunity`) — the *attacker's-eye* "threat debt"
  top-line. A single 0–1000 number for the true adversary opportunity: every gap on a viable
  **attack path** to a crown jewel (the Attack Path Test), weighted by exploitability, by the
  adversaries that use those techniques (threat-informed defense) and by business impact, **net of the
  controls you can prove**. STOCK/FLOW history, an exact item-level **paid-down/accrued ledger**, a
  choke-point / per-source / per-finding **"price the fix"** worklist, a **CROC agentic paydown loop**
  (accrual → orchestrator proposes → approve → executes), and a **bidirectional CTEM bridge** (approved
  paydowns become tracked CTEM exposures; CTEM-remediated exposures credit the ledger). Surfaced on the
  dashboard, board report, public REST (`/api/v1/adversary-opportunity`), the MCP server and ChatOps.
- **Cyber Insurance Readiness** (`/insurance-readiness`) — the *insurer's-eye* lens. Maps the standard
  ransomware-supplemental underwriter checklist (MFA, backups, EDR/SIEM, PAM, patching, tested IR,
  segmentation…) to your **live signals**, scores renewal readiness with a gap worklist ordered by
  underwriting weight, and tracks the **policy** (carrier / limit / renewal) with **coverage adequacy**
  (limit vs. the FAIR-modeled ransomware loss) and a renewal countdown. On the dashboard, board report
  and ChatOps.

Also: **privacy frameworks** — ISO/IEC 27701 (PIMS, 49 controls + GDPR crosswalk), a first-class **EU
GDPR** article catalogue, and the **UK Data (Use and Access) Act 2025 (DUAA)** with a DUAA→GDPR
crosswalk; **backup testing** management (`BACKUPTEST` log: restore / integrity / failover, RTO/RPO
achieved, next-test-due); and two new connectors — **Xygeni** (software supply-chain security / ASPM —
SAST/SCA/secrets/IaC/malware/SLSA) and **Metatron** (offensive-security / pentest → assets + exploited
findings + attack chains).

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
