# XORCISM — Developer Guide

Complete file-by-file reference of the XORCISM codebase and the maintenance
playbook. Read [SETUP.MD](SETUP.MD) first to get a running install;
[REQUIREMENTS.MD](REQUIREMENTS.MD) lists dependencies.

---

## 1. Repository map

```
XORCISM/
├── xorcism_ts/          ⭐ Main web application (Node/TypeScript) — THE component you maintain most
├── xorcism_python/      SQLAlchemy models + reference-data importers (Python)
├── connectors/          Security-tool connectors (manifests + Python runners)
├── agent/               XOR endpoint agent (Python)
├── taxii/               TAXII 2.1 server / client (Python, Flask)
├── stix/                Sample STIX 2.1 bundles (test data for the STIX graph)
├── xorcism_php/         Standalone PHP portal (Infomaniak shared-hosting variant)
├── databases/           Generated SQLite schema dumps (*.sql) + build output (*.db)
├── docs/                Design docs (connectors, deployment, hardening)
├── tools/               Bundled binaries: nodejs/node.exe (portable Node 20), sqlite3.exe
├── nvd_cache/           Local cache of NVD CVE JSON feeds (data, not code)
├── XORCISM_repo/        LEGACY: original C#/.NET sources + T-SQL MODELS (read-only reference)
├── XOR/, Infomaniak/, website_backup/, resources/   Misc data / backups (not code)
├── create_databases.ps1 (Re)generates databases/*_sqlite.sql + *.db from XORCISM_repo/MODELS T-SQL — optional; the app auto-creates DBs on first start
├── generate_models.ps1  Regenerates xorcism_python/models/*.py from the SQLite schemas
├── import_nvd_cve.ps1   Driver script for the NVD CVE importer
├── xorcism_web.ps1      LEGACY: old PowerShell web UI (superseded by xorcism_ts) — do not extend
├── HIDE_TABLES.txt      Log of "hide table for non-admin" requests already applied
├── RiskScore.txt        Spec notes for the RiskScore calculations
├── SECRET.txt           Local secrets notes — NEVER commit or share
├── SETUP.MD / REQUIREMENTS.MD / DEV.MD   Documentation (this file)
```

**Runtime databases live OUTSIDE the repo** in `DB_DIR`
(default `C:\Users\<you>\XORCISM_databases`): 13 SQLite files + `XVAULT.json`.
Never move them into OneDrive (WAL corruption).

---

## 2. `xorcism_ts/` — the web application ⭐

Express + `better-sqlite3` (synchronous SQLite), TypeScript on both sides.
Server compiles with `tsc`, client bundles with `esbuild`. Default port **9292**.

### 2.1 Root files

| File | Purpose |
|---|---|
| `package.json` | Scripts: `build:server` (tsc), `build:client` (esbuild), `build`, `start`, `dev` (watchers). Deps: express, better-sqlite3. |
| `tsconfig.server.json` | Compiles `server/**` → `dist/server/` (CommonJS, Node). |
| `tsconfig.json` | Typecheck config for `client/ts/**` (`tsc --noEmit`). The client is **bundled** by esbuild, not tsc. |
| `esbuild.config.js` | Bundles each `client/ts/*.ts` entry point → `dist/client/js/*.js` (+ sourcemaps). Supports `--watch`. |
| `start.ps1` | Convenience launcher (sets env, starts `dist/server/index.js`). |
| `README.md` | Short app readme. |

### 2.2 `server/` — core modules

| File | Purpose |
|---|---|
| `index.ts` | **Entry point.** Express app assembly: static files, routers, auth gates, error handler. Startup sequence: `ensureSchemaDbs()` (builds the 8 schema DBs from `databases/*_sqlite.sql` if missing) → `seedAdmin()` → `ensureComplianceDb()` → `ensureTicketDb()` → `getAgentDb()` → `ensureThreatModelTables()` → `ensureTenantColumns()` → `getJobDb()` → `startScheduler()` → `startRiskScoreLoop()` → session purge timer → `listen(PORT)`. **All 13 DBs are auto‑created on first start.** |
| `db.ts` | **Largest module.** SQLite connection pool (`getDb(name)`, one connection per DB, WAL + busy_timeout). Explorer queries (`queryRows` with per-column filters, sort, tenant scope), schema introspection, insert/update/delete, lookups, dashboard aggregates, link-table helpers (`getIncidentAssets`/`setIncidentAssets`, `getIncidentThreatActor`/`setIncidentThreatActor`, `getAuditAssets`/`setAuditAssets`, asset↔CPE, asset↔vulnerability, threat-model helpers), `ensureComplianceDb`/`ensureTicketDb`/`ensureThreatModelTables`/`ensureTenantColumns` (idempotent DDL), `TENANT_SCOPED_TABLES`. |
| `auth.ts` | Session auth (`loadUser` middleware → `req.user: SessionUser` with `tenantId`, `isAdmin`, `isSuperAdmin`), gates (`requireAuthGate`, `requireAdmin`, `requirePageApi`), permission engine (`userCan(user, action, db, table?)` — **table rule has priority over database rule**, enabling targeted denies), `deniedFields`, password hashing/policy, `seedAdmin()` (one-time random admin password printed to console), `clientIp`. |
| `xid.ts` | XID.db data layer: schema (XUSER, XROLE, XUSERROLE, XPERMISSION, XSESSION, XAUDITLOG, XTENANT, password resets), user/role/tenant CRUD, `setPermission` (UPSERT on `(RoleID,ResourceType,ResourceKey)`), `getEffectivePermissions`, audit log (`addAudit`), `createPersonForUser` (auto-creates a PERSON row in XORCISM for each new user). |
| `riskscore.ts` | **RiskScore engine.** `AssetRiskScoreCalculator` (`compute`, `computeAndRecord`, `recomputeAll`) implementing the per-ASSET barème (PublicFacing +50; unpatched vulns +5/+10 KEV/+10 Exploited/+5 EasilyExploitable; active threats Criticity×5; unresolved findings Criticity×5; open incidents Criticity×3 +20 Compromised; completed trainings −5) and the per-tenant `computeEnterpriseRiskScore` / `recordEnterpriseRiskScore` (audits terminés −5, trainings −0.5, + somme des derniers scores ASSET). `startRiskScoreLoop()` reruns both every **30 s**; history rows written to ASSETRISKSCORE / RISKSCORE only **on change**. |
| `vault.ts` | Field-encryption vault (envelope encryption): scrypt-derived KEK wraps a random AES-256-GCM DEK stored in `DB_DIR/XVAULT.json`; DEK lives only in memory; encrypt/decrypt of `xenc1:`-prefixed values. |
| `scheduler.ts` | 30 s loop firing due `XSCHEDULE` cron entries into the XJOB queue (re-validates engagement scope before queuing). |
| `cron.ts` | Minimal 5-field cron parser/matcher (`*`, lists, ranges, steps). |
| `jobs.ts` | XJOB.db layer: job queue shared with the Python runner (create/claim/update), schedules, engagements, workers (token auth, capabilities allowlist). |
| `scope.ts` | Engagement scope check (ROE): IPv4/CIDR/ranges/hostnames — first-line validation (the Python runner re-validates authoritatively). |
| `agents.ts` | XAGENT.db layer for the XOR endpoint agent (enrolled agents, events, IOCs, asset link). |
| `antibot.ts` | Per-IP sliding-window rate limiting + honeypot helpers for public endpoints. |
| `i18n.ts` | Server-side localized messages (Accept-Language + `xorcism_lang` cookie). |
| `types/index.ts` | Shared TS types (DbRow etc.). |

### 2.3 `server/routes/` — Express routers

| File | Mounted | Purpose |
|---|---|---|
| `explorer.ts` | `/api` (auth) | **Main API.** `/databases`, `/tables` (filtered by `userCan`), `/schema`, `/rows` (pagination/sort/filters/tenant scope), `/insert`, `/update`, `/delete`, `/export`, `/lookup`, `/lookup-one`, dashboard endpoints (`/dashboard/risk-score`, `/dashboard/vuln-by-year`, `/dashboard/incidents-by-status`, `/dashboard/incidents-by-asset`), link APIs (`/incident-assets`, `/incident-threatactor`, `/audit-assets`, `/asset-cpes`, `/asset-vulnerabilities`, `/vuln-search`, threat-model APIs, `/threatagent-category`), with `tenantScope`/`parentTenantOr403` guards and audit logging. |
| `auth.ts` | `/api/auth` (public) | `/login`, `/register` (honeypot + rate limit + policy + auto-PERSON), `/logout`, `/forgot`, `/reset`, `/change-password`. |
| `oidc.ts` | `/api/oidc` | Generic OAuth2/OIDC login (discovery + PKCE) as an alternative to password login. |
| `admin.ts` | `/api/admin` (admin) | Tenants (super-admin), users, roles, permission matrix editing, audit log reading. |
| `connectors.ts` | `/api` (auth) | Connector registry (reads `connectors/*/connector.json`), parameter validation (types/enum/target/url), run → job creation, engagements CRUD, workers CRUD (token shown once), schedules CRUD. |
| `worker_api.ts` | `/worker` (token) | Remote-worker API (no session): claim jobs, post results/logs — used by `connectors/runner.py --remote`. |
| `agent.ts` | `/api/agent` (token + auth mix) | XOR endpoint-agent API: enroll, heartbeat, events, IOC distribution, plus UI-facing listing. |
| `bia.ts` | `/api/bia` (auth) | Business Impact Analysis: BIAAUDIT/BIAENTRY CRUD, asset/person search. |
| `vault.ts` | `/api/vault` (admin) | Vault configure/unlock/lock/recover. |
| `upload.ts` | `/api` (auth) | `/upload` — JSON base64 file upload to `uploads/` (size/type limits), served at `/uploads`. |
| `feedback.ts` | `/api/feedback` (auth) | Feature rating + improvement requests; triage for admins. |

### 2.4 `client/` — pages (HTML) and code (TypeScript)

Each HTML page loads one bundled JS entry point from `dist/client/js/`.
Shared styling in `css/style.css`.

| Page (HTML) | Script (client/ts) | Purpose |
|---|---|---|
| `index.html` | `app.ts` | **Database Explorer** — the main UI (see below). |
| `dashboard.html` | `dashboard.ts` | Dashboard: **Enterprise RiskScore card (first, auto-refresh 30 s)**, vulns by year, incidents by status/asset (Chart.js via CDN). |
| `admin.html` | `admin.ts` | Admin UI: tenants, users, roles, granular permissions (pages/DBs/tables/fields), audit log. |
| `connectors.html` | `connectors.ts` | Connectors UI: registry list, parameter form, engagements, workers, schedules, job log live view. |
| `bia.html` | `bia.ts` | BIA audits + entry grid (Excel/CSV export). |
| `stix-graph.html` | `stix-graph.ts` | STIX 2.1 bundle viewer — d3-force node/link graph styled like OpenCTI. |
| `vault.html` | *(inline + api)* | Vault management page. |
| `feedback.html` | *(bundled)* | Feedback / feature-rating page. |
| `login.html` | `login.ts` | Login + forced password change. |
| `register.html` | `register.ts` | Self-service registration. |
| `forgot.html` / `reset.html` | `forgot.ts` / `reset.ts` | Password reset flow. |
| — | `api.ts` | **Typed API client** used by every page: `request()` wrapper + one method per endpoint (`getRows`, `insertRow`, `getAuditAssets`, `setAuditAssets`, `getEnterpriseRiskScore`, …). Add new endpoints here first. |
| — | `i18n.ts` | Client i18n: FR + EN dictionaries, `t(key)`, `initI18n()` applies `data-i18n` attributes, language selector cookie. |
| — | `rte.ts` | Shared WYSIWYG rich-text editor (`mkRichText`). |
| — | `session-ui.ts` | Topbar widget: current user, Admin link, logout — included on all authenticated pages. |

#### `app.ts` — the Database Explorer (≈4 000 lines, the file you will edit most)

Renders any table generically (schema-driven), then **specializes per
table/column via registries**. To change form/grid behavior you almost always
just add an entry to one of these maps (all keyed `"TABLE.Column"` unless noted):

| Registry | Effect |
|---|---|
| `FK_COLUMNS` / `FK_BY_COLUMN` | `<select>` populated from a lookup table (label shown, id stored). |
| `VALUE_ENUM_COLUMNS` / `VALUE_ENUM_BY_COLUMN` | Fixed label→value dropdown (e.g. Very Low…Very High → 0–4), optional default. |
| `ENUM_*` (via `getEnumOptions`) | Simple value list dropdown. |
| `CHECKBOX_COLUMNS` | Render 0/1 column as a checkbox. |
| `RICHTEXT_COLUMNS` (+ name heuristic `isRichTextCol`) | WYSIWYG editor (HTML stored). |
| `DATE_PICKER_COLUMNS` | 📅 button → custom floating popup calendar (`openDatePopup`, viewport-clamped, OK/Annuler). |
| `AUTO_DATE_COLUMNS` | Auto-filled with today on create AND reset to today on edit (e.g. DateModified). |
| `DEFAULT_TODAY_DATE_COLUMNS` | Default to today **only when empty**. |
| `DATALIST_COLUMNS` | Free text + autocomplete from another table; optional `idCol`/`idTargetCol` to auto-fill a sibling ID field (e.g. `AUDITREPORT.ReportAuthor` → fills `PersonID`). |
| `NAME_SEARCH_COLUMNS` | Inserts a search-by-name field BEFORE an ID field that resolves name → fills the ID (optional `searchLabel`). |
| `NAME_HINT_COLUMNS` | Read-only label displayed AFTER an ID field (reverse of the above). |
| `VOCAB_VALUE_SELECT_COLUMNS` | Dropdown filtered by vocabulary. |
| `GRID_DISPLAY_COLUMNS` | **Array of `GridDisplaySpec`** per table — computed/joined display columns in the grid (cross-DB lookups allowed; italic, non-sortable). |
| `FIELD_REORDER` | Per-table form field reordering `[col, afterCol]`. |
| `HIDDEN_FORM_COLUMNS` | Columns never shown in forms (server-managed, e.g. `TenantID`). |
| `READONLY_FORM_COLUMNS` | Server-computed columns shown read-only and excluded from submits (e.g. `ASSET.RiskScore`). |
| `WIDE_MODAL_TABLES` | Tables whose modal is widened for relational sub-panels. |
| File upload (`hasFileUpload`) | File picker + upload via `/api/upload` (e.g. `EVIDENCE.EvidenceFile`). |

Beyond registries, `app.ts` contains per-table relational sub-panels (wired in
`openEditModal` / insert-modal and the two submit functions): INCIDENT↔ASSET +
ThreatActor, **AUDIT↔ASSET (searchable multi-select → ASSETAUDIT)**,
ASSET↔CPE/Vulnerabilities (edit mode only — create shows a “save first” hint),
THREATMODEL scope/threats/mitigations, THREATAGENT category, agent scan launch.

### 2.5 Generated output (do not edit)

`dist/server/**` (tsc output) and `dist/client/js/**` (esbuild bundles) are
build artifacts. `uploads/` holds user-uploaded evidence files.

---

## 3. `xorcism_python/` — models & importers

| File | Purpose |
|---|---|
| `config.py` | DB locations (reads `XORCISM_DB_DIR`), SQLAlchemy URLs, SMTP, logging. |
| `utils.py` | Shared helpers (GUIDs, dates, batching). |
| `requirements.txt` | sqlalchemy ≥2.0, requests, lxml, python-dateutil, cryptography. |
| `models/base.py` | Declarative `Base`, per-DB engines, `session_scope(db)` (binds via `__bind_key__`). |
| `models/xorcism.py` | XORCISM models (~770 KB, hundreds of tables: ASSET, PERSON, CPE, ACTION, ASSETAUDIT, ASSETRISKSCORE, RISKSCORE, …). |
| `models/xvulnerability.py` | VULNERABILITY & co. ⚠ Quirks: some tables have **no SQLite PK**; the only index is on `VULReferentialID` — query by that for performance; CVE import conventions documented in the importers. |
| `models/xattack.py`, `xincident.py`, `xthreat.py`, `xmalware.py`, `xoval.py`, `xwindows.py` | Per-DB models (one module per database). |
| `models/xcompliance.py` | AUDIT, AUDITFINDING, AUDITREPORT, EVIDENCE, AUDITEVIDENCE — **own MetaData** (`ComplianceBase`) to avoid name clashes with XORCISM’s AUDIT. |
| `models/xid.py`, `models/xticket.py` | XID (users/RBAC) and XTICKET models. |
| `importers/import_nvd_cve.py` | NVD CVE → XVULNERABILITY (uses `nvd_cache/`). Driven by root `import_nvd_cve.ps1`. |
| `importers/import_capec.py`, `import_cce.py`, `import_oval.py`, `import_maec.py` | CAPEC / CCE / OVAL / MAEC reference imports (lxml). `capec_latest.xml` is the cached source; `importers/OVALRepo/` is the **vendored upstream OVAL repository** (huge, data only — never hand-edit). |
| `importers/import_cisa_kev.py`, `import_KEV.py` | CISA Known Exploited Vulnerabilities flags. |
| `importers/import_controls.py`, `import_iso27001.py`, `import_iso42001_controls.py`, `import_nist800-53.py` | Compliance frameworks → CONTROL tables. |
| `importers/import_threatevent.py`, `import_vulnerabilities.py`, `import_vulnerabilitydomains.py` | Misc threat/vuln seeds. |
| `parsers/cwe_parser.py` | CWE XML parser. |
| `providers/provider_nessus.py` | Nessus `.nessus` report parser (legacy provider path). |
| `tests/test_models.py`, `tests/test_utils.py` | Smoke tests (models import, `SELECT 1` per DB, utils). Run with `pytest`. |

**Keep models in sync with the live DBs** (see §9.2). `generate_models.ps1`
can regenerate a model module wholesale from the SQLite schema, but it discards
hand-written comments/refinements — prefer targeted manual edits.

---

## 4. `connectors/` — tool connectors & runner

| File | Purpose |
|---|---|
| `manifest.schema.json` | JSON Schema for `connector.json` manifests (id, type: tool-runner/import/enrichment/export, parameters with types `target`/`url`/`enum`…, argv `command`, `parser`/`run`). |
| `runner.py` | **The worker.** Local mode: claims queued XJOB jobs, executes (argv, never shell), parses, imports into the DBs (unified `import_findings` mapping: assets/services/cpes/components/vulns), updates status/log. Remote mode (`--remote URL --token T --name N [--capabilities ...]`): same but over the worker HTTP API. |
| `import_iocs.py` | IOC import helper. |
| `<id>/connector.json` + `run.py` or `parse_*.py` (+ `sample.*`) | One folder per connector, **auto-discovered** by the server. Current set: `nmap`, `nuclei`, `whatweb`, `sqlmap`, `w3af` (tool-runners with parsers); `nessus`, `openvas`, `saint`, `metasploit`, `burpsuite`, `qualys`, `rapid7`, `dependency-track`, `caldera` (imports — file- or API-based; API config via env vars only). `sample.*` files are parser test fixtures. |

---

## 5. Other Python components

| Folder / file | Purpose |
|---|---|
| `agent/xor_agent.py` | XOR endpoint agent (enroll/heartbeat/events against `/api/agent`). `xor_agent.conf.example` config template; `install/` has the systemd unit + macOS plist. |
| `taxii/taxii_server.py` | Full TAXII 2.1 server (Flask) — discovery, collections, objects, manifest, versions, pagination, Basic auth via `TAXII_AUTH=1`. |
| `taxii/taxii_client.py` | TAXII client. `manager.py` + `manager_config.json`: collection admin. `create_taxii_db.sql`: SQLite store schema (`taxii.db` in DB_DIR). `README.md`/`GUIDE.md`: usage. |
| `stix/*.json` | Sample STIX bundles used to demo/test the STIX graph page. |

---

## 6. Root scripts & docs

| File | Purpose |
|---|---|
| `create_databases.ps1` | T-SQL → SQLite conversion (regex-based) for the 8 schema DBs; writes `databases/*.db` + `*_sqlite.sql`. **Optional now** — the server's `ensureSchemaDbs()` builds the schema DBs in `DB_DIR` from the committed `databases/*_sqlite.sql` on first start. Re-run this script only to regenerate that SQL from the T-SQL sources. |
| `generate_models.ps1` | Regenerates `xorcism_python/models/*.py` from live SQLite schemas (PRAGMA-driven). Overwrites manual edits — use sparingly. |
| `import_nvd_cve.ps1` | Downloads/refreshes `nvd_cache/` and runs the CVE importer. |
| `xorcism_web.ps1` | **Legacy** all-in-one PowerShell web UI (port 9191, no auth). Kept for reference; superseded by `xorcism_ts`. Never add features here. |
| `docs/CONNECTORS.md` | Connector architecture & roadmap (manifest/runner/parser/importer, remote workers, tool catalog). |
| `docs/DEPLOY-INFOMANIAK.md` | Shared-hosting deployment of the PHP portal. |
| `docs/OWASP-HARDENING.md` | Security hardening checklist applied to the app. |
| `HIDE_TABLES.txt` | Append-only log of table-hide requests already translated into XPERMISSION deny rules. Check it before re-applying one. |
| `SECRET.txt` | Local-only secrets notes. **Never commit, never echo into chat/logs.** |

---

## 7. Build, run, and verify

```powershell
cd xorcism_ts
# Server compile (errors = build break):
node node_modules/typescript/bin/tsc -p tsconfig.server.json
# Client typecheck (IGNORE the known errors about the XLSX CDN global):
node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json
# Client bundle:
node esbuild.config.js
# Start (or npm start):
$env:DB_DIR="C:\Users\<you>\XORCISM_databases"; node dist/server/index.js
```

Use the bundled `..\tools\nodejs\node.exe` if no system Node. `npm run dev`
starts tsc/esbuild watchers + nodemon.

**The running server only serves `dist/`** — after any server edit you must
rebuild **and restart**; after any client edit you must re-run esbuild (a stale
server is the classic cause of “`Cannot POST /api/...` returns HTML”).

**Manual verification pattern** (used throughout this project’s history):
1. Start a throwaway instance on another port: `$env:PORT=9393; node dist/server/index.js`.
2. Register a disposable user via `POST /api/auth/register`; exercise the new
   endpoints with `curl` (cookie jar) or the browser.
3. **Clean up**: delete the test rows you created, the test user
   (`XUSER`/`XSESSION`/`XUSERROLE` in XID.db) **and its auto-created PERSON**
   (matched by email in XORCISM.PERSON), then stop the instance.
4. Python side: `pytest xorcism_python/tests`.

---

## 8. Architecture rules you must respect

### 8.1 Security & RBAC
- **Permissions** = XPERMISSION rows `(RoleID, ResourceType 'page'|'database'|'table'|'field', ResourceKey, CanCreate/Read/Update/Delete)`.
  `userCan` gives the **table rule priority over the database rule** — so you
  hide a table from non-admins by UPSERTing a deny row: RoleID=2 (`User`),
  ResourceType=`table`, ResourceKey=`DB.TABLE`, all CRUD=0. Log the request in
  `HIDE_TABLES.txt`. ~160+ such rules exist; check before adding duplicates.
- **Multi-tenant**: `tenantScope(req)` returns `null` for super-admin (Admin in
  the System tenant, TenantID=1) else the user’s tenant. Tables listed in
  `TENANT_SCOPED_TABLES` are filtered on TenantID; link routes must call
  `parentTenantOr403` on the parent row (null tenant = mismatch for tenant
  users). New tenant-owned tables: add a TenantID column + register them there.
- **Secrets**: only env vars (server, connectors) or non-committed
  `config.local.php` (forum). Never in code, UI fields, or committed files.
  The assistant/tooling must never create DB accounts or type passwords.
- All `/api/*` routes (except `/api/auth/*` and worker/agent token routes) sit
  behind the auth gate; admin routes behind `requireAdmin`. Always add `deny()`
  + `xid.addAudit` on sensitive mutations (copy an existing route as template).

### 8.2 Database conventions
- SQLite, synchronous access via `better-sqlite3`; one shared connection per DB.
- **Integer PKs are MAX+1** (no AUTOINCREMENT except in XID) — compute inside a
  transaction when inserting (see `setAuditAssets` for the pattern).
- Dates are TEXT: `YYYY-MM-DD` (dates) or `YYYY-MM-DD HH:MM:SS` (timestamps).
  Validity windows treat NULL/empty bounds as unbounded.
- No cross-database foreign keys — joins across DBs are done in code
  (e.g. ASSETVULNERABILITY in XORCISM ↔ VULNERABILITY in XVULNERABILITY).
- Several legacy tables have a column literally named `BLOB` — always quote it.
- SQLite can’t ALTER constraints: to relax NOT NULL you rebuild the table
  (CREATE new + INSERT…SELECT + DROP + RENAME, in one transaction).

### 8.3 Background loops (in-process, no cron)
`scheduler.ts` (connector schedules) and `riskscore.ts` (asset + enterprise
scores) tick every 30 s; both are started from `index.ts` and `unref()`ed.
Keep new periodic work in this pattern; make ticks idempotent and cheap, and
write history rows **only on change** (see riskscore for the template).

### 8.4 i18n
Any user-visible string in the web app needs a key in **both** FR and EN
dictionaries of `client/ts/i18n.ts` (use `t("key")` / `data-i18n`).

---

## 9. Maintenance playbook (how-to recipes)

### 9.1 Add an API endpoint
1. Data function in `server/db.ts` (or the relevant module).
2. Route in the right `server/routes/*.ts` with `userCan` + tenant guard + audit.
3. Client method in `client/ts/api.ts`.
4. UI consumption in the page’s ts file.
5. Rebuild server + client, restart, verify with a throwaway user, clean up.

### 9.2 Add a column to an existing table
1. `ALTER TABLE ... ADD COLUMN` on the live DB in `DB_DIR` (script it with
   better-sqlite3; check `PRAGMA table_info` first for idempotence).
2. Mirror it in the matching `xorcism_python/models/<db>.py` model.
3. If the table is created by an `ensure*Db()` in `db.ts`, update that DDL too.
4. The Explorer picks it up automatically (schema-driven); add registry entries
   (§2.4) if it needs a widget; add to `READONLY_FORM_COLUMNS` if server-owned.
5. **Import/Export need NO changes.** Both are schema-driven and require zero
   per-table maintenance — see §9.9.

### 9.3 Customize a form field or grid
Add one entry to the relevant `app.ts` registry (§2.4) — dropdowns, date
pickers, rich text, name-search, computed grid columns, reordering, hiding.
Only build a bespoke widget when no registry fits (then follow the
`appendAuditAssetSelector` pattern: helper + wire into open/insert/edit/submit).

### 9.4 Hide tables from non-admin users
UPSERT XPERMISSION deny rows as in §8.1, verify with a throwaway **User**
session that `/api/tables?db=...` no longer lists them, then log the request in
`HIDE_TABLES.txt`. No rebuild needed (data-only change).

### 9.5 Add a connector
1. Create `connectors/<id>/connector.json` (validate against
   `manifest.schema.json`): tool-runner = `command` (argv template) + `parser`;
   import = `run` (module exposing `run(params, workdir)` → normalized result
   `{assets, services, cpes, components, vulns, project}`).
2. Secrets via env vars only; mark `intrusive: true` for active tools (forces
   engagement/ROE in the UI); include a `sample.*` fixture.
3. No server change needed — the registry auto-discovers the folder. Mention it
   in `docs/CONNECTORS.md` and the marketing catalog if public-facing.

### 9.6 Add a page
HTML in `client/` + entry ts in `client/ts/` (esbuild auto-globs entries; check
`esbuild.config.js`), include `session-ui.js`, register the static route/auth
gate in `index.ts`, add page permission handling if non-admin access differs.

### 9.7 Modify the RiskScore formulas
Asset barème in `AssetRiskScoreCalculator.compute()`, tenant aggregate in
`computeEnterpriseRiskScore()` (both in `server/riskscore.ts`). Keep
`compute()` pure (no writes) so it stays unit-testable; record functions handle
persistence/dedup. Verify with synthetic rows covering every branch (including
should-be-ignored cases), then clean up.

### 9.8 Regenerate databases or models (rare, destructive)
`create_databases.ps1` rebuilds empty schema DBs (then re-copy to DB_DIR —
this wipes data); `generate_models.ps1` rewrites model files (loses manual
edits). Prefer incremental ALTERs (§9.2) on a live system.

### 9.9 Import / Export (JSON & CSV) — auto-synced, do not hardcode
The Explorer's **Import JSON/CSV** and **Export CSV/Excel** are **schema-driven
and require no maintenance** when you add or change tables/columns:

- **Client** (`app.ts` `importFile` / `exportCSV` / `exportExcel`): fully generic
  — operates on the *currently selected* table with whatever columns the file or
  table has. No table/column lists.
- **Server import** (`POST /api/import`): `validCols = getSchema(db, table)` reads
  the **live** `PRAGMA table_info`, filters each row to valid columns (drops
  unknown ones, honours `deniedFields`), then routes through the **same
  `insertRow()`** as everything else. So imports automatically inherit: tenant
  stamping (`TenantID`), PK auto-increment, default dates, vault encryption, and
  **server-computed values** (`ASSET.RiskScore`, `RISKREGISTERENTRY.*RiskLevel`,
  …). `replace=true` clears tenant-scoped rows first (needs DELETE).
- **Server export** (`GET /api/export`): `SELECT *` — every column, always current.

**Invariant (enforced by a comment in the route): never hardcode a table or
column list in the import/export path.** As long as new structure goes through
`getSchema` + `insertRow`, Import/Export reflect every past and future change for
free. Verified end-to-end by importing into a freshly-added table
(`RISKREGISTERENTRY`): new columns accepted, unknown columns dropped, `TenantID`
stamped, and risk levels computed — with no import-specific code.

---

## 10. Known pitfalls

- **Stale server**: new routes 404 with an HTML error page until rebuild+restart.
- **OneDrive**: anything under OneDrive with an open SQLite handle will corrupt
  WAL or serve stale reads. DB_DIR must stay outside.
- **xlsx typecheck noise**: client `tsc --noEmit` reports missing `XLSX` global
  (CDN-loaded) — known and ignorable; esbuild builds fine.
- **XVULNERABILITY scale**: 350k+ rows, minimal indexing (only
  `VULReferentialID`) and some tables without PKs — avoid full scans; look up
  by VulnerabilityID/VULReferentialID; never add unbounded lookups to the UI
  (use `lookup-one`, not `lookup`).
- **`/api/lookup` on huge tables** freezes the datalist UI (e.g. PRODUCT ~3k is
  already slow) — for big tables use the lazy `NAME_HINT` / `lookup-one` path.
- **Create-mode sub-panels**: a new row’s auto PK does not exist in the DB yet —
  pass `null` to relational sub-panels in create mode (403 otherwise; see the
  ASSET CPE panel fix).
- **Auto-PERSON**: every user registration creates a PERSON row — test cleanup
  must remove both.
- **Legacy folders** (`XORCISM_repo/`, `xorcism_web.ps1`, `website_backup/`):
  reference only. Fixes go to `xorcism_ts` / `xorcism_python`.
