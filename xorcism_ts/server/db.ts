/**
 * db.ts — SQLite connection pool with a PLUGGABLE synchronous driver.
 *   • better-sqlite3 (default, zero-config) — a local file per logical DB.
 *   • libsql / Turso (opt-in) — the SAME synchronous better-sqlite3-compatible API, but the local
 *     file can be an embedded replica of a remote libSQL/Turso server (HA, replication, backups).
 * Because both drivers expose the identical sync API, the ~1,964 `.prepare()` call sites across the
 * server are unchanged. Select libsql with XORCISM_DB_DRIVER=libsql (after `npm i libsql`) and point
 * a DB at a remote with LIBSQL_SYNC_URL (+ LIBSQL_AUTH_TOKEN), globally or per DB
 * (LIBSQL_<NAME>_SYNC_URL). See docs/DATABASE_BACKENDS_STAGE2.md.
 * Replaces PowerShell Invoke-Sqlite / sqlite3.exe shell calls.
 */

import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import { randomUUID } from "crypto";
import { TOOL_SEED } from "./data/toolsSeed";
import * as vault from "./vault";

// Location of the SQLite databases. OUTSIDE OneDrive: OneDrive replaces the files
// under open handles (stale reads, corrupted WAL, invisible permissions/updates).
// Overridable via the DB_DIR environment variable.
const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";

const DB_NAMES = [
  "XORCISM",
  "XVULNERABILITY",
  "XATTACK",
  "XMALWARE",
  "XINCIDENT",
  "XTHREAT",
  "XOVAL",
  "XWINDOWS",
  "XCOMPLIANCE",
  "XTICKET",
] as const;

export type DbName = (typeof DB_NAMES)[number];

// One connection per database (lazy-created)
const connections = new Map<string, Database.Database>();

// ── Pluggable driver selection ────────────────────────────────────────────────
type DbCtor = new (p: string, o?: Record<string, unknown>) => Database.Database;
let _ctor: DbCtor | null = null;
let _driver: "better-sqlite3" | "libsql" = "better-sqlite3";
function dbCtor(): DbCtor {
  if (_ctor) return _ctor;
  const want = (process.env.XORCISM_DB_DRIVER || (process.env.LIBSQL_SYNC_URL ? "libsql" : "better-sqlite3")).toLowerCase();
  if (want === "libsql") {
    try {
      // libsql exposes a better-sqlite3-compatible synchronous Database (with embedded replicas).
      const libsql = require("libsql"); // eslint-disable-line @typescript-eslint/no-var-requires
      _ctor = ((libsql.default ?? libsql) as unknown) as DbCtor;
      _driver = "libsql";
      console.log("[db] driver: libsql (synchronous, embedded-replica capable)");
      return _ctor;
    } catch (e) {
      console.warn(`[db] XORCISM_DB_DRIVER=libsql but the 'libsql' package is not installed (${(e as Error).message}). Run 'npm i libsql'. Falling back to better-sqlite3.`);
    }
  }
  _ctor = (Database as unknown) as DbCtor;
  _driver = "better-sqlite3";
  return _ctor;
}
/** The active DB driver ("better-sqlite3" | "libsql") — for diagnostics/health. */
export function dbDriver(): string { dbCtor(); return _driver; }

export function getDb(name: string): Database.Database {
  const upper = name.toUpperCase();
  if (connections.has(upper)) return connections.get(upper)!;

  const Ctor = dbCtor();
  const dbPath = path.join(DB_DIR, `${upper}.db`);
  const opts: Record<string, unknown> = { readonly: false, fileMustExist: true };

  // libsql embedded replica: the local file mirrors a remote libSQL/Turso DB, kept current by
  // db.sync(). Configure per DB (LIBSQL_<NAME>_SYNC_URL) or globally (LIBSQL_SYNC_URL).
  let replica = false;
  if (_driver === "libsql") {
    const syncUrl = process.env[`LIBSQL_${upper}_SYNC_URL`] || process.env.LIBSQL_SYNC_URL;
    const authToken = process.env[`LIBSQL_${upper}_AUTH_TOKEN`] || process.env.LIBSQL_AUTH_TOKEN;
    if (syncUrl) { opts.syncUrl = syncUrl; if (authToken) opts.authToken = authToken; delete opts.fileMustExist; replica = true; }
  }

  if (!replica && !fs.existsSync(dbPath)) throw new Error(`Unknown database: ${name}`);

  const db = new Ctor(dbPath, opts);
  try {
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000"); // waits for the lock (e.g. during an import) instead of failing
    // Performance pragmas (safe with WAL). synchronous=NORMAL drops a fsync per commit (durable under
    // WAL, only loses the last txn on OS crash — acceptable here); a larger page cache + memory temp
    // store + memory-mapped I/O cut read latency on the synchronous hot path that serves page queries.
    db.pragma("synchronous = NORMAL");
    db.pragma("cache_size = -16000");   // ~16 MB page cache per connection (negative = KiB)
    db.pragma("temp_store = MEMORY");    // temp B-trees / sorts in RAM, not on disk
    db.pragma("mmap_size = 268435456");  // 256 MB memory-mapped I/O (fewer read syscalls)
  } catch { /* libsql embedded replicas manage journaling themselves; pragmas may be no-ops */ }
  if (replica) { try { (db as unknown as { sync?: () => void }).sync?.(); } catch (e) { console.warn(`[db] ${upper} initial replica sync failed: ${(e as Error).message}`); } }
  connections.set(upper, db);
  return db;
}

/**
 * Atomically allocate the next primary-key id for a table — the race-free replacement for the
 * `SELECT COALESCE(MAX(id),0)+1` pattern. A per-`table.column` counter in XSEQ is bumped by a single
 * `UPDATE … RETURNING` that also never drops below the table's live MAX (so it stays correct even
 * when other writers — the Python importers, seed scripts — insert without the sequence). The UPDATE
 * takes the write lock, so it is safe across processes / under libsql multi-writer (on the
 * single-process better-sqlite3 default the old pattern was already safe; this makes it correct
 * everywhere). Table/column are sanitized to identifier chars (defense in depth; they are constants).
 */
export function allocId(db: Database.Database, table: string, idCol: string): number {
  const t = String(table).replace(/[^A-Za-z0-9_]/g, "");
  const c = String(idCol).replace(/[^A-Za-z0-9_]/g, "");
  const key = `${t}.${c}`;
  try {
    db.exec("CREATE TABLE IF NOT EXISTS XSEQ (SeqName TEXT PRIMARY KEY, Val INTEGER NOT NULL DEFAULT 0)");
    db.prepare("INSERT OR IGNORE INTO XSEQ(SeqName, Val) VALUES (?, 0)").run(key);
    const row = db.prepare(
      `UPDATE XSEQ SET Val = MAX(Val + 1, (SELECT COALESCE(MAX("${c}"),0)+1 FROM "${t}")) WHERE SeqName=? RETURNING Val`
    ).get(key) as { Val: number } | undefined;
    if (row && Number.isInteger(row.Val)) return row.Val;
  } catch { /* fall back to the legacy (single-process-safe) allocation below */ }
  return (db.prepare(`SELECT COALESCE(MAX("${c}"),0)+1 AS n FROM "${t}"`).get() as { n: number }).n;
}

/** Periodically refresh libsql embedded replicas. No-op unless libsql + a sync URL are configured. */
let _syncTimer: ReturnType<typeof setInterval> | null = null;
export function startReplicaSync(): void {
  const hasSyncUrl = !!process.env.LIBSQL_SYNC_URL || Object.keys(process.env).some((k) => /^LIBSQL_.*_SYNC_URL$/.test(k));
  if (_syncTimer || dbDriver() !== "libsql" || !hasSyncUrl) return;
  const secs = Math.max(5, Number(process.env.LIBSQL_SYNC_SECONDS) || 30);
  _syncTimer = setInterval(() => {
    for (const [nm, db] of connections) { try { (db as unknown as { sync?: () => void }).sync?.(); } catch (e) { console.warn(`[db] replica sync ${nm}: ${(e as Error).message}`); } }
  }, secs * 1000);
  console.log(`[db] libsql embedded-replica sync every ${secs}s`);
}

// "Schema" databases (referential / domain) built from the
// databases/<NAME>_sqlite.sql files (generated by create_databases.ps1). They are
// auto-created at first startup if missing; combined with the ensure*Db()
// (XID/XCOMPLIANCE/XTICKET/XJOB/XAGENT), ALL the XORCISM databases are thus
// created automatically at the server's first launch.
const SCHEMA_DB_NAMES = [
  "XORCISM", "XVULNERABILITY", "XATTACK", "XMALWARE",
  "XINCIDENT", "XTHREAT", "XOVAL", "XWINDOWS",
] as const;
const SCHEMA_SQL_DIR = path.resolve(__dirname, "../../../databases");

/**
 * Creates in DB_DIR the missing "schema" databases from their
 * databases/<NAME>_sqlite.sql file. Idempotent (ignores databases already present).
 * Builds in a temporary file then renames: an interrupted creation
 * never leaves a half-built database at the final location.
 */
export function ensureSchemaDbs(): void {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  for (const name of SCHEMA_DB_NAMES) {
    const dbPath = path.join(DB_DIR, `${name}.db`);
    if (fs.existsSync(dbPath)) continue; // already present
    const sqlPath = path.join(SCHEMA_SQL_DIR, `${name}_sqlite.sql`);
    if (!fs.existsSync(sqlPath)) {
      console.warn(`[db] ${name}_sqlite.sql introuvable — base ${name} non créée (lancez create_databases.ps1)`);
      continue;
    }
    const tmpPath = dbPath + ".building";
    try {
      for (const f of [tmpPath, tmpPath + "-wal", tmpPath + "-shm"]) {
        try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch { /* ignore */ }
      }
      const sql = fs.readFileSync(sqlPath, "utf-8").replace(/^﻿/, ""); // strips the BOM
      const db = new Database(tmpPath); // fresh file
      try {
        db.exec(sql);
      } finally {
        db.close();
      }
      fs.renameSync(tmpPath, dbPath);
      console.log(`[db] base ${name} créée (schéma depuis ${name}_sqlite.sql)`);
    } catch (e) {
      console.warn(`[db] création de ${name} échouée : ${(e as Error).message}`);
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch { /* ignore */ }
    }
  }
}

// ── Pre-population (reference data) at first startup ─────────────────
//
// Inserts reference rows into the tables AFTER their creation. Idempotent:
// a row already present (per `match`) is never re-inserted, so seedData()
// can run at every startup without duplicating.
//
// ➜ To pre-populate a table, simply add an entry to SEED_DATA:
//      { db, table, match: { <uniqueness key> }, values: { <columns to insert> } }
//   `match` is used for the existence check (idempotence); `values` is inserted
//   verbatim (absent columns stay at NULL / the table's default).
interface SeedRow {
  db: string;
  table: string;
  match: Record<string, unknown>;
  values: Record<string, unknown>;
}

const SEED_DATA: SeedRow[] = [
  // Root vocabulary "XORCISM" (referenced by default by VocabularyID throughout
  // the model).
  {
    db: "XORCISM",
    table: "VOCABULARY",
    match: { VocabularyID: 1 },
    values: { VocabularyID: 1, VocabularyName: "XORCISM" },
  },
];

/** Pre-inserts the missing reference data (idempotent). */
export function seedData(): void {
  for (const s of SEED_DATA) {
    const safeTbl = s.table.replace(/[^A-Za-z0-9_]/g, "");
    try {
      const db = getDb(s.db);
      const tableExists = db
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
        .get(safeTbl);
      if (!tableExists) {
        console.warn(`[seed] ${s.db}.${s.table} absente — ligne ignorée`);
        continue;
      }
      const whereCols = Object.keys(s.match);
      const where = whereCols.map((c) => `"${c}" = ?`).join(" AND ");
      const present = db
        .prepare(`SELECT 1 FROM "${safeTbl}" WHERE ${where} LIMIT 1`)
        .get(...Object.values(s.match));
      if (present) continue; // already seeded
      const cols = Object.keys(s.values);
      const colSql = cols.map((c) => `"${c.replace(/[^A-Za-z0-9_]/g, "")}"`).join(", ");
      const placeholders = cols.map(() => "?").join(", ");
      db.prepare(`INSERT INTO "${safeTbl}" (${colSql}) VALUES (${placeholders})`).run(
        ...Object.values(s.values)
      );
      console.log(`[seed] ${s.db}.${s.table} ← ${JSON.stringify(s.values)}`);
    } catch (e) {
      console.warn(`[seed] ${s.db}.${s.table} : ${(e as Error).message}`);
    }
  }
  seedTools(); // populate the TOOL catalogue on a fresh install
}

/**
 * Seeds the XORCISM.TOOL catalogue (security tools) on first run. Idempotent and
 * non-destructive: only runs when the table exists and is EMPTY, so it never
 * overwrites a user's curated tools. TOOL is a global (non-tenant-scoped) reference.
 */
export function seedTools(): void {
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='TOOL'").get()) return;
    const cols = new Set((db.prepare(`PRAGMA table_info("TOOL")`).all() as { name: string }[]).map((c) => c.name));
    const now = nowTs();
    // On a fresh install, insert from ToolID 1. On an already-seeded DB, only insert the catalogue
    // entries whose ToolName is missing (so appending to TOOL_SEED auto-adds new tools), keyed by name.
    const existing = new Set((db.prepare('SELECT ToolName FROM "TOOL"').all() as { ToolName: string }[]).map((r) => String(r.ToolName)));
    const toAdd = TOOL_SEED.filter((t) => !existing.has(t.name));
    if (!toAdd.length) return;
    const insert = db.prepare(
      `INSERT INTO "TOOL" (ToolID, ToolGUID, ToolName, ToolDescription, Category, ToolURL, CreatedDate, ValidFromDate, VocabularyID, isEncrypted)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)`
    );
    const tx = db.transaction((tools: { name: string; description: string; category: string; url: string }[]) => {
      let id = allocId(db, "TOOL", "ToolID");
      for (const t of tools) {
        insert.run(id++, randomUUID(), t.name.slice(0, 200), t.description || null,
          cols.has("Category") ? (t.category || null) : null, cols.has("ToolURL") ? (t.url || null) : null, now, now);
      }
    });
    tx(toAdd);
    console.log(`[seed] XORCISM.TOOL ← +${toAdd.length} tools (${existing.size} existing)`);
  } catch (e) {
    console.warn(`[seed] TOOL: ${(e as Error).message}`);
  }
}

/**
 * XORCISM.TOOLDOCUMENT — link table associating a TOOL with a DOCUMENT, carrying the
 * provenance (PersonID who linked it), a validity window (ValidFrom/ValidUntil) and a
 * confidence level/reason. Created idempotently at boot so existing installs gain it; the
 * same DDL lives in databases/XORCISM_sqlite.sql for fresh installs. Non-tenant-scoped
 * (mirrors the global TOOL catalogue reference).
 */
export function ensureToolDocumentTable(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS "TOOLDOCUMENT" (
    "ToolDocumentID" INTEGER PRIMARY KEY,
    "ToolDocumentGUID" TEXT,
    "ToolID" INTEGER,
    "DocumentID" INTEGER,
    "CreatedDate" DATE,
    "PersonID" INTEGER,
    "ValidFrom" DATE,
    "ValidUntil" DATE,
    "ConfidenceLevel" TEXT,
    "ConfidenceReasonID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_tooldocument_tool ON "TOOLDOCUMENT"("ToolID");
  CREATE INDEX IF NOT EXISTS ix_tooldocument_document ON "TOOLDOCUMENT"("DocumentID");`);
}

/**
 * XORCISM.ORGANISATIONRISKSCORE — per-organisation risk-score history (one row per recorded
 * value over time), the organisation-level analogue of RISKSCORE (per-tenant) and ASSETRISKSCORE
 * (per-asset). Created idempotently at boot so existing installs gain it; the same DDL lives in
 * databases/XORCISM_sqlite.sql for fresh installs.
 */
export function ensureOrganisationRiskScoreTable(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS "ORGANISATIONRISKSCORE" (
    "EnterpriseRiskScoreID" INTEGER PRIMARY KEY,
    "CreatedDate" DATE,
    "OrganisationID" INTEGER,
    "RiskScore" REAL
  );
  CREATE INDEX IF NOT EXISTS ix_organisationriskscore_org ON "ORGANISATIONRISKSCORE"("OrganisationID");`);
}

/**
 * XORCISM.TOOLSTAR — per-user "stars" (favorites) on the TOOL catalogue, GitHub-style.
 * One row per (UserID, ToolID); a tool's star count is COUNT(*) across all users (global,
 * like GitHub — NOT tenant-scoped). UserID references the XID user (no cross-DB FK).
 * Created idempotently at boot; same DDL in databases/XORCISM_sqlite.sql for fresh installs.
 */
export function ensureToolStarTable(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS "TOOLSTAR" (
    "StarID" INTEGER PRIMARY KEY,
    "ToolID" INTEGER NOT NULL,
    "UserID" INTEGER NOT NULL,
    "CreatedDate" TEXT
  );
  CREATE UNIQUE INDEX IF NOT EXISTS ux_toolstar_user_tool ON "TOOLSTAR"("UserID","ToolID");
  CREATE INDEX IF NOT EXISTS ix_toolstar_tool ON "TOOLSTAR"("ToolID");`);
}

export function listDatabases(): string[] {
  return fs
    .readdirSync(DB_DIR)
    .filter((f) => f.endsWith(".db"))
    .map((f) => f.replace(".db", ""))
    // XID (users/permissions) is managed via the Admin page, not the explorer
    .filter((name) => name.toUpperCase() !== "XID")
    .sort();
}

/**
 * Consistent backup (SQLite online backup) of all the .db databases in DB_DIR
 * to DB_DIR/backups/<timestamp>/. Handles the WAL; the server can stay running.
 */
export async function backupDatabases(): Promise<{
  dir: string;
  files: { name: string; bytes: number }[];
}> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const destDir = path.join(DB_DIR, "backups", stamp);
  fs.mkdirSync(destDir, { recursive: true });
  const files: { name: string; bytes: number }[] = [];
  for (const f of fs.readdirSync(DB_DIR)) {
    if (!f.toLowerCase().endsWith(".db")) continue;
    const dst = path.join(destDir, f);
    const src = new Database(path.join(DB_DIR, f), { readonly: true });
    try {
      await src.backup(dst); // online backup (consistent, handles WAL)
    } finally {
      src.close();
    }
    files.push({ name: f, bytes: fs.statSync(dst).size });
  }
  return { dir: destDir, files };
}

// ── CVE → assets correlation (via CPE) ────────────────────────────────────────
/** Product key "vendor:product" of a CPE string (2.2 or 2.3); null otherwise. */
export function cpeProductKey(cpe: string): string | null {
  const s = (cpe || "").trim().toLowerCase();
  if (s.startsWith("cpe:2.3:")) {
    const f = s.split(":"); // cpe:2.3:part:vendor:product:version:…
    if (f.length >= 5 && f[3] && f[4] && f[3] !== "*" && f[4] !== "*") return `${f[3]}:${f[4]}`;
  } else if (s.startsWith("cpe:/")) {
    const f = s.slice(5).split(":"); // part:vendor:product:version
    if (f.length >= 3 && f[1] && f[2] && f[1] !== "*" && f[2] !== "*") return `${f[1]}:${f[2]}`;
  }
  return null;
}

/**
 * Correlates CVEs to assets by CPE matching at the product level
 * (vendor:product): assets (CPEFORASSET→CPE) × affected CVEs (VULNERABILITYFORCPE)
 * → ASSETVULNERABILITY links (deduplicated, TenantID stamped from the asset).
 * NB: matching at the product level (no version-range evaluation)
 * — to be treated as a pre-selection to validate.
 */
export function correlateCveToAssets(): {
  links: number; assetsMatched: number; cvesMatched: number; assetCpes: number; cveCpes: number;
} {
  const xo = getDb("XORCISM");
  const xv = getDb("XVULNERABILITY");

  const assetCpes = xo
    .prepare(
      `SELECT f.AssetID AS aid, a.TenantID AS tid, c.CPEName AS cpe
       FROM CPEFORASSET f JOIN CPE c ON c.CPEID = f.CPEID
       JOIN ASSET a ON a.AssetID = f.AssetID WHERE c.CPEName IS NOT NULL`
    )
    .all() as { aid: number; tid: number | null; cpe: string }[];
  const keyToAssets = new Map<string, Map<number, number | null>>();
  for (const r of assetCpes) {
    const k = cpeProductKey(r.cpe);
    if (!k) continue;
    if (!keyToAssets.has(k)) keyToAssets.set(k, new Map());
    keyToAssets.get(k)!.set(r.aid, r.tid);
  }
  if (!keyToAssets.size)
    return { links: 0, assetsMatched: 0, cvesMatched: 0, assetCpes: assetCpes.length, cveCpes: 0 };

  const vfc = xv
    .prepare(`SELECT VulnerabilityID AS vid, CPEID AS cpe FROM VULNERABILITYFORCPE WHERE CPEID IS NOT NULL`)
    .all() as { vid: number; cpe: unknown }[];

  const pairs: { aid: number; tid: number | null; vid: number }[] = [];
  const matchedAssets = new Set<number>();
  const matchedCves = new Set<number>();
  for (const r of vfc) {
    const k = cpeProductKey(String(r.cpe));
    if (!k) continue;
    const assets = keyToAssets.get(k);
    if (!assets) continue;
    for (const [aid, tid] of assets) {
      pairs.push({ aid, tid, vid: r.vid });
      matchedAssets.add(aid);
      matchedCves.add(r.vid);
    }
  }

  const existing = new Set(
    (xo.prepare(`SELECT AssetID || ':' || VulnerabilityID AS k FROM ASSETVULNERABILITY`).all() as { k: string }[])
      .map((x) => x.k)
  );
  let nextId =
    allocId(xo, "ASSETVULNERABILITY", "AssetVulnerabilityID");
  const now = nowTs();
  const ins = xo.prepare(
    `INSERT INTO ASSETVULNERABILITY (AssetVulnerabilityID, AssetID, VulnerabilityID, CreatedDate, Status, TenantID)
     VALUES (?, ?, ?, ?, 'open', ?)`
  );
  let links = 0;
  xo.transaction(() => {
    for (const p of pairs) {
      const key = `${p.aid}:${p.vid}`;
      if (existing.has(key)) continue;
      existing.add(key);
      ins.run(nextId++, p.aid, p.vid, now, p.tid);
      links++;
    }
  })();
  return {
    links, assetsMatched: matchedAssets.size, cvesMatched: matchedCves.size,
    assetCpes: assetCpes.length, cveCpes: vfc.length,
  };
}

/**
 * Records a snapshot of an asset's financial value into
 * ASSETFINANCIALVALUE (CreatedDate/ValidFrom/ValidUntil = now). PersonID
 * resolved from the user's e-mail (best-effort). Deduplicates
 * identical consecutive snapshots (same value + currency) to avoid noise.
 * Returns true if a record was created.
 */
export function recordAssetFinancialValue(
  assetId: number, value: number, currency: string | null, email?: string | null
): boolean {
  if (!Number.isFinite(assetId) || assetId <= 0 || !Number.isFinite(value)) return false;
  const db = getDb("XORCISM");
  const last = db
    .prepare(
      `SELECT FinancialValue, Currency FROM ASSETFINANCIALVALUE
       WHERE AssetID = ? ORDER BY AssetFinancialValueID DESC LIMIT 1`
    )
    .get(assetId) as { FinancialValue: number; Currency: string | null } | undefined;
  if (last && Number(last.FinancialValue) === Math.round(value) && (last.Currency ?? "") === (currency ?? "")) {
    return false; // identical to the last snapshot → no duplicate
  }
  let personId: number | null = null;
  if (email) {
    const p = db.prepare(`SELECT PersonID FROM PERSON WHERE Email = ? LIMIT 1`).get(email) as
      | { PersonID: number } | undefined;
    personId = p?.PersonID ?? null;
  }
  const now = nowTs();
  const nextId =
    allocId(db, "ASSETFINANCIALVALUE", "AssetFinancialValueID");
  db.prepare(
    `INSERT INTO ASSETFINANCIALVALUE
       (AssetFinancialValueID, AssetID, FinancialValue, Currency, CreatedDate, ValidFrom, ValidUntil, PersonID)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(nextId, assetId, Math.round(value), currency, now, now, now, personId);
  return true;
}

// ── CPE (manual entry compliant with the CPE naming convention) ─────────────
// CPE 2.3 "formatted string": cpe:2.3:<part>:<10 components> (11 attributes in
// total: part, vendor, product, version, update, edition, language, sw_edition,
// target_sw, target_hw, other).
// CPE 2.2 "URI": cpe:/<part>:<up to 6 components>. part ∈ {a,o,h}.
const CPE23_RE = /^cpe:2\.3:[aho](:[^:\s]+){10}$/i;
const CPE22_RE = /^cpe:\/[aho](:[^:/\s]*){1,6}$/i;

/** Checks that a string complies with the CPE naming convention (2.2 or 2.3). */
export function isValidCpe(s: string): boolean {
  const v = (s || "").trim();
  return CPE23_RE.test(v) || CPE22_RE.test(v);
}

/** Fetches (or creates) a CPE entry by name in XORCISM.CPE; returns its ID. */
export function getOrCreateCpe(name: string): { id: number; name: string; created: boolean } {
  const db = getDb("XORCISM");
  const ex = db.prepare(`SELECT CPEID FROM CPE WHERE CPEName = ? LIMIT 1`).get(name) as
    | { CPEID: number } | undefined;
  if (ex) return { id: ex.CPEID, name, created: false };
  const nextId = allocId(db, "CPE", "CPEID");
  db.prepare(`INSERT INTO CPE (CPEID, CPEName, CreatedDate) VALUES (?, ?, ?)`).run(nextId, name, nowTs());
  return { id: nextId, name, created: true };
}

/**
 * Distinct values (lowercase) for the CPE builder:
 *  - vendors  ← XORCISM.VENDOR.VendorName
 *  - products ← XORCISM.PRODUCT.ProductName
 * Used as suggestions (datalist); free entry remains possible.
 */
export function getCpeBuilderOptions(): { vendors: string[]; products: string[] } {
  const db = getDb("XORCISM");
  const distinctLower = (table: string, col: string): string[] => {
    try {
      const rows = db
        .prepare(
          `SELECT DISTINCT LOWER(TRIM(${col})) AS v FROM ${table}
           WHERE ${col} IS NOT NULL AND TRIM(${col}) <> ''
           ORDER BY v COLLATE NOCASE LIMIT 5000`
        )
        .all() as { v: string }[];
      return rows.map((r) => r.v).filter(Boolean);
    } catch {
      return []; // table missing (e.g. VENDOR not yet created)
    }
  };
  return { vendors: distinctLower("VENDOR", "VendorName"), products: distinctLower("PRODUCT", "ProductName") };
}

// ── OCIL: questions of a questionnaire (QUESTIONFORQUESTIONNAIRE link) ────────

/** IDs of the questions linked to a questionnaire (in display order). */
export function getQuestionnaireQuestionIds(questionnaireId: number): number[] {
  return (getDb("XCOMPLIANCE")
    .prepare(
      `SELECT QuestionID FROM QUESTIONFORQUESTIONNAIRE WHERE QuestionnaireID = ?
       ORDER BY COALESCE(DisplayOrder, 999999), QuestionForQuestionnaireID`
    )
    .all(questionnaireId) as { QuestionID: number }[]).map((r) => r.QuestionID);
}

// Export of a questionnaire for Excel: all its questions (display order) with
// the linked ANSWER answers (via ANSWERFORQUESTION). One row per
// (question, answer) pair; a question without an answer → one row with empty answer fields.
export function getQuestionnaireExport(
  questionnaireId: number
): { name: string; rows: Record<string, unknown>[] } {
  const db = getDb("XCOMPLIANCE");
  const qn = db
    .prepare('SELECT QuestionnaireName FROM "QUESTIONNAIRE" WHERE QuestionnaireID = ?')
    .get(questionnaireId) as { QuestionnaireName?: string } | undefined;
  const name = qn?.QuestionnaireName || `questionnaire_${questionnaireId}`;
  const questions = db
    .prepare(
      `SELECT q.QuestionID, q.QuestionName, q.QuestionText, q.QuestionType, q.QuestionDescription
       FROM "QUESTIONFORQUESTIONNAIRE" qfq
       JOIN "QUESTION" q ON q.QuestionID = qfq.QuestionID
       WHERE qfq.QuestionnaireID = ?
       ORDER BY COALESCE(qfq.DisplayOrder, 999999), qfq.QuestionForQuestionnaireID`
    )
    .all(questionnaireId) as {
    QuestionID: number; QuestionName: unknown; QuestionText: unknown;
    QuestionType: unknown; QuestionDescription: unknown;
  }[];
  const ansStmt = db.prepare(
    `SELECT a.AnswerID, a.Answer, afq.Result
     FROM "ANSWERFORQUESTION" afq
     JOIN "ANSWER" a ON a.AnswerID = afq.AnswerID
     WHERE afq.QuestionID = ?
     ORDER BY COALESCE(afq.DisplayOrder, 999999), afq.AnswerForQuestionID`
  );
  const rows: Record<string, unknown>[] = [];
  for (const q of questions) {
    const base = {
      QuestionID: q.QuestionID,
      QuestionName: q.QuestionName ?? "",
      QuestionText: q.QuestionText ?? "",
      QuestionType: q.QuestionType ?? "",
      QuestionDescription: q.QuestionDescription ?? "",
    };
    const answers = ansStmt.all(q.QuestionID) as { AnswerID: number; Answer: unknown; Result: unknown }[];
    if (!answers.length) {
      rows.push({ ...base, AnswerID: "", Answer: "", Result: "" });
    } else {
      for (const a of answers) {
        rows.push({ ...base, AnswerID: a.AnswerID, Answer: a.Answer ?? "", Result: a.Result ?? "" });
      }
    }
  }
  return { name, rows };
}

/** Replaces the whole set of questions linked to a questionnaire (order = position). */
export function setQuestionnaireQuestions(questionnaireId: number, questionIds: number[]): void {
  const db = getDb("XCOMPLIANCE");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM QUESTIONFORQUESTIONNAIRE WHERE QuestionnaireID = ?").run(questionnaireId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(QuestionForQuestionnaireID),0) AS m FROM QUESTIONFORQUESTIONNAIRE").get() as { m: number }).m;
    const ins = db.prepare(
      "INSERT INTO QUESTIONFORQUESTIONNAIRE (QuestionForQuestionnaireID, QuestionnaireID, QuestionID, DisplayOrder, CreatedDate) VALUES (?,?,?,?,?)"
    );
    let ord = 0;
    for (const qid of questionIds) {
      if (!Number.isInteger(qid) || qid <= 0) continue;
      maxId++;
      ins.run(maxId, questionnaireId, qid, ord++, nowTs());
    }
  });
  tx();
}

// ── OCIL: evidence linked to an answer (ANSWEREVIDENCE) ───────────────────────

/** IDs of the evidence (EVIDENCE) linked to an answer. */
export function getAnswerEvidenceIds(answerId: number): number[] {
  return (getDb("XCOMPLIANCE")
    .prepare("SELECT EvidenceID FROM ANSWEREVIDENCE WHERE AnswerID = ? ORDER BY AnswerEvidenceID")
    .all(answerId) as { EvidenceID: number }[]).map((r) => r.EvidenceID);
}

/** Replaces the whole set of evidence linked to an answer. */
export function setAnswerEvidences(answerId: number, evidenceIds: number[]): void {
  const db = getDb("XCOMPLIANCE");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ANSWEREVIDENCE WHERE AnswerID = ?").run(answerId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(AnswerEvidenceID),0) AS m FROM ANSWEREVIDENCE").get() as { m: number }).m;
    const ins = db.prepare("INSERT INTO ANSWEREVIDENCE (AnswerEvidenceID, AnswerID, EvidenceID, CreatedDate) VALUES (?,?,?,?)");
    for (const eid of evidenceIds) {
      if (!Number.isInteger(eid) || eid <= 0) continue;
      maxId++;
      ins.run(maxId, answerId, eid, nowTs());
    }
  });
  tx();
}

/** Creates (or fetches by name) a QUESTION in XCOMPLIANCE; returns its ID. */
export function createQuestion(name: string): { id: number; name: string; created: boolean } {
  const db = getDb("XCOMPLIANCE");
  const ex = db.prepare("SELECT QuestionID FROM QUESTION WHERE QuestionName = ? LIMIT 1").get(name) as
    | { QuestionID: number } | undefined;
  if (ex) return { id: ex.QuestionID, name, created: false };
  const id = allocId(db, "QUESTION", "QuestionID");
  db.prepare(
    "INSERT INTO QUESTION (QuestionID, QuestionGUID, QuestionName, QuestionText, QuestionType, CreatedDate) VALUES (?,?,?,?,?,?)"
  ).run(id, randomUUID(), name, name, "boolean", nowTs());
  return { id, name, created: true };
}

/**
 * Imports a complete questionnaire from mapped Excel/CSV rows: creates the
 * QUESTIONNAIRE, then for each row a QUESTION and the QUESTIONFORQUESTIONNAIRE link.
 * Each `question` is an already-mapped object { QuestionName, QuestionText?,
 * QuestionDescription?, QuestionType?, DefaultAnswer?, DisplayOrder? }. Transactional.
 */
export function importQuestionnaireFromExcel(
  name: string,
  fileName: string,
  questions: Record<string, unknown>[],
  tenantId: number | null = null
): { questionnaireId: number; questions: number } {
  const db = getDb("XCOMPLIANCE");
  const clean = (v: unknown): string => (v == null ? "" : String(v)).trim();
  const tx = db.transaction(() => {
    const qId = allocId(db, "QUESTIONNAIRE", "QuestionnaireID");
    const qName = clean(name) || clean(fileName) || `questionnaire_${qId}`;
    db.prepare(
      "INSERT INTO QUESTIONNAIRE (QuestionnaireID, QuestionnaireName, FileName, CreatedDate, TenantID) VALUES (?,?,?,?,?)"
    ).run(qId, qName.slice(0, 300), clean(fileName).slice(0, 300), nowTs(), tenantId);

    let maxQ = (db.prepare("SELECT COALESCE(MAX(QuestionID),0) AS m FROM QUESTION").get() as { m: number }).m;
    let maxLink = (db.prepare("SELECT COALESCE(MAX(QuestionForQuestionnaireID),0) AS m FROM QUESTIONFORQUESTIONNAIRE").get() as { m: number }).m;
    const insQ = db.prepare(
      "INSERT INTO QUESTION (QuestionID, QuestionGUID, QuestionName, QuestionText, QuestionDescription, QuestionType, DefaultAnswer, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)"
    );
    const insLink = db.prepare(
      "INSERT INTO QUESTIONFORQUESTIONNAIRE (QuestionForQuestionnaireID, QuestionnaireID, QuestionID, DisplayOrder, CreatedDate, TenantID) VALUES (?,?,?,?,?,?)"
    );
    let count = 0;
    let ord = 0;
    for (const r of questions) {
      const nm = clean(r.QuestionName) || clean(r.QuestionText);
      if (!nm) continue; // row without a label: ignored
      const text = clean(r.QuestionText) || nm;
      const type = clean(r.QuestionType) || "boolean";
      maxQ++;
      insQ.run(maxQ, randomUUID(), nm.slice(0, 500), text, clean(r.QuestionDescription), type.slice(0, 50), clean(r.DefaultAnswer).slice(0, 500), nowTs(), tenantId);
      const ordRaw = clean(r.DisplayOrder);
      const ordNum = ordRaw !== "" && !Number.isNaN(Number(ordRaw)) ? Number(ordRaw) : ord;
      maxLink++;
      insLink.run(maxLink, qId, maxQ, ordNum, nowTs(), tenantId);
      ord++;
      count++;
    }
    return { questionnaireId: qId, questions: count };
  });
  return tx();
}

/** Creates (or fetches by name) an EVIDENCE in XCOMPLIANCE; returns its ID. */
export function createEvidence(name: string): { id: number; name: string; created: boolean } {
  const db = getDb("XCOMPLIANCE");
  const ex = db.prepare("SELECT EvidenceID FROM EVIDENCE WHERE EvidenceName = ? LIMIT 1").get(name) as
    | { EvidenceID: number } | undefined;
  if (ex) return { id: ex.EvidenceID, name, created: false };
  const id = allocId(db, "EVIDENCE", "EvidenceID");
  db.prepare("INSERT INTO EVIDENCE (EvidenceID, EvidenceName, CreatedDate) VALUES (?,?,?)").run(id, name, nowTs());
  return { id, name, created: true };
}

// ── MITRE ATT&CK: matrix for the dedicated view (reads XTHREAT.ATTACK*) ───────────
// The order of the tactics (columns) comes from ATTACKTACTIC.MatrixOrder, populated
// at import from x-mitre-matrix.tactic_refs (official order, version-proof).
interface AttackTech { attackId: string; name: string; url: string | null; subtechniques: { attackId: string; name: string; url: string | null }[] }
export interface AttackMatrix {
  domain: string;
  tactics: { attackId: string; name: string; shortName: string; url: string | null; techniques: AttackTech[] }[];
}

export function getAttackMatrix(domain: string): AttackMatrix {
  const db = getDb("XTHREAT");
  const tactics = db.prepare(
    `SELECT AttackID, Name, ShortName, URL FROM ATTACKTACTIC WHERE Domain=? AND COALESCE(Deprecated,0)=0
     ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, Name`
  ).all(domain) as { AttackID: string; Name: string; ShortName: string; URL: string | null }[];

  const top = db.prepare(
    `SELECT tt.TacticShortName AS short, t.AttackID AS aid, t.Name AS name, t.URL AS url
     FROM ATTACKTECHNIQUETACTIC tt JOIN ATTACKTECHNIQUE t ON t.AttackTechniqueID = tt.AttackTechniqueID
     WHERE t.Domain=? AND COALESCE(t.Deprecated,0)=0 AND COALESCE(t.IsSubtechnique,0)=0
     ORDER BY t.AttackID`
  ).all(domain) as { short: string; aid: string; name: string; url: string | null }[];

  const subs = db.prepare(
    `SELECT AttackID AS aid, Name AS name, URL AS url, ParentAttackID AS parent
     FROM ATTACKTECHNIQUE WHERE Domain=? AND COALESCE(IsSubtechnique,0)=1 AND COALESCE(Deprecated,0)=0
     ORDER BY AttackID`
  ).all(domain) as { aid: string; name: string; url: string | null; parent: string | null }[];
  const subsByParent = new Map<string, { attackId: string; name: string; url: string | null }[]>();
  for (const s of subs) {
    if (!s.parent) continue;
    if (!subsByParent.has(s.parent)) subsByParent.set(s.parent, []);
    subsByParent.get(s.parent)!.push({ attackId: s.aid, name: s.name, url: s.url });
  }

  const byTactic = new Map<string, AttackTech[]>();
  for (const r of top) {
    if (!byTactic.has(r.short)) byTactic.set(r.short, []);
    byTactic.get(r.short)!.push({ attackId: r.aid, name: r.name, url: r.url, subtechniques: subsByParent.get(r.aid) ?? [] });
  }

  return {
    domain,
    tactics: tactics.map((t) => ({
      attackId: t.AttackID, name: t.Name, shortName: t.ShortName, url: t.URL,
      techniques: byTactic.get(t.ShortName) ?? [],
    })),
  };
}

// ── THREAT ↔ ATT&CK techniques (THREATTTP link table, XTHREAT database) ──────
function ensureThreatTtp(db: Database.Database): void {
  db.exec(`CREATE TABLE IF NOT EXISTS THREATTTP (
    ThreatTTPID INTEGER PRIMARY KEY,
    ThreatID INTEGER, AttackTechniqueID INTEGER, AttackID TEXT, CreatedDate TEXT,
    UNIQUE(ThreatID, AttackTechniqueID))`);
}

/** Search ATT&CK techniques (by AttackID or name) — limited. */
export function searchAttackTechniques(q: string, limit = 50): {
  AttackTechniqueID: number; AttackID: string; Name: string; Domain: string; IsSubtechnique: number;
}[] {
  const like = `%${q}%`;
  return getDb("XTHREAT").prepare(
    `SELECT AttackTechniqueID, AttackID, Name, Domain, IsSubtechnique FROM ATTACKTECHNIQUE
     WHERE COALESCE(Deprecated,0)=0 AND (AttackID LIKE ? OR Name LIKE ?)
     ORDER BY (AttackID = ?) DESC, AttackID LIMIT ?`
  ).all(like, like, q, Math.min(Math.max(limit, 1), 200)) as never;
}

/** ATT&CK techniques linked to a THREAT (with resolved labels). */
export function getThreatTtps(threatId: number): {
  AttackTechniqueID: number; AttackID: string; Name: string; Domain: string;
}[] {
  const db = getDb("XTHREAT");
  ensureThreatTtp(db);
  return db.prepare(
    `SELECT tt.AttackTechniqueID AS AttackTechniqueID, t.AttackID AS AttackID, t.Name AS Name, t.Domain AS Domain
     FROM THREATTTP tt JOIN ATTACKTECHNIQUE t ON t.AttackTechniqueID = tt.AttackTechniqueID
     WHERE tt.ThreatID = ? ORDER BY t.AttackID`
  ).all(threatId) as never;
}

/** Replaces the whole set of ATT&CK techniques linked to a THREAT. */
export function setThreatTtps(threatId: number, techniqueIds: number[]): void {
  const db = getDb("XTHREAT");
  ensureThreatTtp(db);
  const aidOf = db.prepare("SELECT AttackID FROM ATTACKTECHNIQUE WHERE AttackTechniqueID = ?");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATTTP WHERE ThreatID = ?").run(threatId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(ThreatTTPID),0) AS m FROM THREATTTP").get() as { m: number }).m;
    const ins = db.prepare("INSERT OR IGNORE INTO THREATTTP (ThreatTTPID, ThreatID, AttackTechniqueID, AttackID, CreatedDate) VALUES (?,?,?,?,?)");
    for (const id of techniqueIds) {
      if (!Number.isInteger(id) || id <= 0) continue;
      const r = aidOf.get(id) as { AttackID: string } | undefined;
      maxId++;
      ins.run(maxId, threatId, id, r?.AttackID ?? null, nowTs());
    }
  });
  tx();
}

/** Financial value history of an asset (by AssetName), sorted by date. */
export function assetFinancialHistory(assetName: string): {
  asset: string; points: { date: string; value: number; currency: string | null }[];
} {
  const db = getDb("XORCISM");
  const rows = db
    .prepare(
      `SELECT f.CreatedDate AS date, f.FinancialValue AS value, f.Currency AS currency
       FROM ASSETFINANCIALVALUE f JOIN ASSET a ON a.AssetID = f.AssetID
       WHERE a.AssetName = ? ORDER BY f.CreatedDate, f.AssetFinancialValueID`
    )
    .all(assetName) as { date: string; value: number; currency: string | null }[];
  return { asset: assetName, points: rows };
}

export function listTables(dbName: string): string[] {
  const db = getDb(dbName);
  const rows = db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
    .all() as { name: string }[];
  return rows.map((r) => r.name);
}

export function getSchema(dbName: string, table: string): object[] {
  const db = getDb(dbName);
  // Sanitize table name
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  return db.prepare(`PRAGMA table_info("${safeTbl}")`).all() as object[];
}

// ── Multi-tenant: isolation of operational data ───────────────────
//
// Chosen model: a TenantID column on the "per-tenant" operational tables.
// Reads/writes are filtered by TenantID for a tenant user;
// the super-admin (System tenant) is not filtered (sees everything).
//
// Key = "DB.TABLE" in UPPERCASE.
export const TENANT_SCOPED_TABLES = new Set<string>([
  "XORCISM.ASSET",
  "XORCISM.CLOUDFINDING",
  "XORCISM.ASSETCONTROL",
  "XORCISM.BACKUPPLAN",
  "XORCISM.BACKUPTEST",
  "XOVAL.OVALRESULTS",
  "XORCISM.IDENTITY",
  "XORCISM.IDENTITYPERSON",
  "XORCISM.BIAAUDIT",
  "XORCISM.BIAENTRY",
  "XORCISM.CPEFORASSET",
  "XORCISM.ASSETVULNERABILITY",
  "XORCISM.THREATMODEL",
  "XORCISM.THREATMODELASSET",
  "XORCISM.THREATMODELTHREAT",
  "XORCISM.THREATMODELCONTROL",
  "XORCISM.RISKSCORE",
  "XORCISM.TRAININGFORPERSON",
  "XINCIDENT.INCIDENT",
  "XINCIDENT.INCIDENTFORASSET",
  "XINCIDENT.ALERT",
  "XINCIDENT.ALERTFORASSET",
  "XINCIDENT.ALERTEVIDENCE",
  "XCOMPLIANCE.AUDIT",
  // ── GRC (full multi-tenant isolation) ──
  "XCOMPLIANCE.FOLDER",
  "XCOMPLIANCE.PERIMETER",
  "XCOMPLIANCE.FRAMEWORK",
  "XCOMPLIANCE.REQUIREMENTNODE",
  "XCOMPLIANCE.REFERENCECONTROL",
  "XCOMPLIANCE.APPLIEDCONTROL",
  "XCOMPLIANCE.COMPLIANCEASSESSMENT",
  "XCOMPLIANCE.REQUIREMENTASSESSMENT",
  "XCOMPLIANCE.REQUIREMENTASSESSMENTCONTROL",
  "XCOMPLIANCE.REQUIREMENTASSESSMENTEVIDENCE",
  "XCOMPLIANCE.RISKMATRIX",
  "XCOMPLIANCE.RISKASSESSMENT",
  "XCOMPLIANCE.RISKSCENARIO",
  "XCOMPLIANCE.RISKSCENARIOCONTROL",
  "XCOMPLIANCE.RISKSCENARIOASSET",
  "XCOMPLIANCE.RISKACCEPTANCE",
  "XCOMPLIANCE.SECURITYEXCEPTION",
  "XCOMPLIANCE.GRCTHREAT",
  "XCOMPLIANCE.RISKREGISTER",
  "XCOMPLIANCE.RISKREGISTERENTRY",
  "XCOMPLIANCE.RISKREGISTERENTRYASSET",
  "XCOMPLIANCE.RISKREGISTERENTRYCONTROL",
  // ── EBIOS Risk Manager (multi-tenant isolation) ──
  "XCOMPLIANCE.EBIOSBUSINESSVALUE",
  "XCOMPLIANCE.EBIOSSUPPORTINGASSET",
  "XCOMPLIANCE.EBIOSFEAREDEVENT",
  "XCOMPLIANCE.EBIOSRISKSOURCE",
  "XCOMPLIANCE.EBIOSSTAKEHOLDER",
  // ── OCIL questionnaires (multi-tenant isolation) ──
  "XCOMPLIANCE.QUESTIONNAIRE",
  "XCOMPLIANCE.QUESTION",
  "XCOMPLIANCE.QUESTIONFORQUESTIONNAIRE",
  "XCOMPLIANCE.ANSWER",
  "XCOMPLIANCE.ANSWERFORQUESTION",
  // ── Questionnaire runner / journey (guided responses; multi-tenant isolation) ──
  "XCOMPLIANCE.QUESTIONNAIRERUN",
  "XCOMPLIANCE.QUESTIONNAIRERESPONSE",
  // ── TPRM (third-party risk; multi-tenant isolation) ──
  "XCOMPLIANCE.TPRMVENDOR",
  "XCOMPLIANCE.TPRMFINDING",
  // ── Zero Trust maturity (ZTFUNCTION is global reference; assessments are tenant-scoped) ──
  "XCOMPLIANCE.ZTMATURITYASSESSMENT",
  "XCOMPLIANCE.ZTMATURITYITEM",
  "XORCISM.IDENTITYSIGNIN",
  "XORCISM.IDENTITYDETECTION",
  "XORCISM.ACCESSCAMPAIGN",
  "XORCISM.ACCESSREVIEWITEM",
  "XCOMPLIANCE.ZTPOLICY",
  // ── Crisis management / tabletop exercises (multi-tenant isolation) ──
  "XCOMPLIANCE.CRISISSCENARIO",
  "XCOMPLIANCE.EXERCISEINJECT",
  "XCOMPLIANCE.EXERCISEPARTICIPANT",
  "XCOMPLIANCE.EXERCISELOG",
  "XCOMPLIANCE.AUDITFINDINGREMEDIATION",
  // ── FAIR-MAM materiality assessments (multi-tenant isolation; FAIRMAMCATEGORY is global reference) ──
  "XCOMPLIANCE.FAIRMAMASSESSMENT",
  "XCOMPLIANCE.FAIRMAMLINEITEM",
  // ── PQCMM post-quantum-crypto maturity assessments (PQCMMLEVEL is global reference) ──
  "XCOMPLIANCE.PQCMMASSESSMENT",
  // ── SCA / SBOM (Software Composition Analysis; multi-tenant isolation) ──
  "XORCISM.SBOM",
  "XORCISM.COMPONENT",
  "XORCISM.COMPONENTDEPENDENCY",
  // ── Tooling catalogue (multi-tenant isolation) ──
  "XORCISM.TOOL",
  // ── Policy & document management (multi-tenant isolation) ──
  "XORCISM.POLICY",
  "XCOMPLIANCE.DOCUMENT",
]);

export const TENANT_COL = "TenantID";

export function isTenantScoped(dbName: string, table: string): boolean {
  return TENANT_SCOPED_TABLES.has(`${dbName.toUpperCase()}.${table.toUpperCase()}`);
}

// Cache "DB.TABLE" → does the TenantID column actually exist in the database?
const tenantColCache = new Map<string, boolean>();

export function tableHasTenantCol(dbName: string, table: string): boolean {
  const key = `${dbName.toUpperCase()}.${table.toUpperCase()}`;
  if (tenantColCache.has(key)) return tenantColCache.get(key)!;
  let has = false;
  try {
    const db = getDb(dbName);
    const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
    const cols = db.prepare(`PRAGMA table_info("${safeTbl}")`).all() as { name: string }[];
    has = cols.some((c) => c.name === TENANT_COL);
  } catch {
    has = false;
  }
  tenantColCache.set(key, has);
  return has;
}

/** Should this query be filtered by tenant? (scoped table + column present + scope provided) */
function shouldScope(dbName: string, table: string, tenantScope?: number | null): boolean {
  return (
    tenantScope != null &&
    isTenantScoped(dbName, table) &&
    tableHasTenantCol(dbName, table)
  );
}

/**
 * Reads the TenantID of a parent row (e.g. ASSET in XORCISM, INCIDENT in
 * XINCIDENT), when the TenantID column exists. Used for isolating the
 * linking endpoints: we check that the caller is indeed allowed to target this
 * parent, and we inherit its TenantID for the junction rows.
 *
 * Returns:
 *   - the TenantID (number) if the row exists and carries a tenant;
 *   - null if the TenantID column does not exist yet (isolation not active),
 *     if the row is not found, or if its TenantID is NULL.
 */
export function rowTenant(
  dbName: string,
  table: string,
  idCol: string,
  idVal: number
): number | null {
  if (!tableHasTenantCol(dbName, table)) return null;
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const safeCol = idCol.replace(/[^a-zA-Z0-9_]/g, "");
  const r = db
    .prepare(`SELECT "${TENANT_COL}" AS t FROM "${safeTbl}" WHERE "${safeCol}" = ?`)
    .get(idVal) as { t: unknown } | undefined;
  return normTenant(r?.t);
}

/**
 * Normalizes a TenantID value: NULL, undefined or an empty/blank string →
 * `null`; otherwise a number. Prevents legacy data (TenantID = '' written
 * by mistake into an integer column) from skewing the isolation comparisons.
 */
export function normTenant(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "string" && v.trim() === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * Best-effort migration: adds the TenantID column (+ index) to the scoped
 * operational tables. Tolerates failure (e.g. XORCISM database locked by an
 * import in progress) — the column will be added at the next startup. The
 * tableHasTenantCol guard avoids any invalid query while the column is missing.
 */
export function ensureTenantColumns(): void {
  for (const key of TENANT_SCOPED_TABLES) {
    const [dbName, table] = key.split(".");
    let db: Database.Database | null = null;
    try {
      db = getDb(dbName);
      // Short lock wait: if the database is busy (import in progress), we
      // give up quickly and retry at the next startup (instead of blocking 5s).
      db.pragma("busy_timeout = 1200");
      const exists = (
        db
          .prepare("SELECT 1 AS n FROM sqlite_master WHERE type='table' AND name=?")
          .get(table) as { n: number } | undefined
      );
      if (!exists) continue;
      const cols = db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[];
      if (!cols.some((c) => c.name === TENANT_COL)) {
        db.prepare(`ALTER TABLE "${table}" ADD COLUMN "${TENANT_COL}" INTEGER`).run();
      }
      db.prepare(
        `CREATE INDEX IF NOT EXISTS "ix_${table}_tenant" ON "${table}" ("${TENANT_COL}")`
      ).run();
      tenantColCache.set(key, true);
    } catch (e) {
      // Database probably locked (import) — retry at the next startup.
      console.warn(`[tenant] ${key}: colonne TenantID non ajoutée pour l'instant (${(e as Error).message})`);
    } finally {
      // Restore the connection's normal wait timeout.
      try {
        db?.pragma("busy_timeout = 5000");
      } catch {
        /* ignore */
      }
    }
  }
}

export function queryRows(
  dbName: string,
  table: string,
  limit: number,
  offset: number,
  sort?: string,
  dir?: string,
  search?: string,
  tenantScope?: number | null,
  vocabId?: number | null,
  filters?: Record<string, string>
): { total: number; rows: object[] } {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");

  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  const validCols = schema.map((c) => c.name);

  // ORDER BY clause
  let orderClause = "";
  if (sort && validCols.includes(sort)) {
    const safeDir = dir === "desc" ? "DESC" : "ASC";
    orderClause = `ORDER BY "${sort}" ${safeDir}`;
  }

  // WHERE: LIKE search (all columns) + tenant isolation + vocabulary filter
  const conditions: string[] = [];
  const whereParams: unknown[] = [];
  if (search && search.trim()) {
    const term = `%${search.trim()}%`;
    conditions.push("(" + validCols.map((c) => `"${c}" LIKE ?`).join(" OR ") + ")");
    validCols.forEach(() => whereParams.push(term));
  }
  // Per-column filters (LIKE): only keeps real columns (anti-injection)
  if (filters) {
    for (const [col, raw] of Object.entries(filters)) {
      const val = String(raw ?? "").trim();
      if (val && validCols.includes(col)) {
        conditions.push(`"${col}" LIKE ?`);
        whereParams.push(`%${val}%`);
      }
    }
  }
  if (shouldScope(dbName, table, tenantScope)) {
    conditions.push(`"${TENANT_COL}" = ?`);
    whereParams.push(tenantScope);
  }
  // Vocabulary filter (only if the table has a VocabularyID column)
  if (vocabId != null && validCols.includes("VocabularyID")) {
    conditions.push(`"VocabularyID" = ?`);
    whereParams.push(vocabId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const total = (
    db
      .prepare(`SELECT COUNT(*) as cnt FROM "${safeTbl}" ${whereClause}`)
      .get(...whereParams) as { cnt: number }
  ).cnt;

  const rows = db
    .prepare(
      // "rowid AS rowid": for tables whose PK is an INTEGER PRIMARY KEY
      // (an alias of rowid), "SELECT rowid, *" would return two columns of the same name
      // and the row object would lose its "rowid" key. The alias forces a distinct
      // "rowid" column (essential for editing/deleting).
      `SELECT rowid AS rowid, * FROM "${safeTbl}" ${whereClause} ${orderClause} LIMIT ? OFFSET ?`
    )
    .all(...whereParams, limit, offset) as object[];

  // Decryption (or 🔒 masking) of the encrypted fields for display.
  vault.decryptRows(rows as Record<string, unknown>[]);

  return { total, rows };
}

export function exportRows(
  dbName: string,
  table: string,
  sort?: string,
  dir?: string,
  maxRows = 50000,
  tenantScope?: number | null,
  vocabId?: number | null
): { rows: object[]; total: number; truncated: boolean } {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");

  const schemaCols = (
    db.prepare(`PRAGMA table_info("${safeTbl}")`).all() as { name: string }[]
  ).map((c) => c.name);

  let orderClause = "";
  if (sort && schemaCols.includes(sort)) {
    const safeDir = dir === "desc" ? "DESC" : "ASC";
    orderClause = `ORDER BY "${sort}" ${safeDir}`;
  }

  const conditions: string[] = [];
  const whereParams: unknown[] = [];
  if (shouldScope(dbName, table, tenantScope)) {
    conditions.push(`"${TENANT_COL}" = ?`);
    whereParams.push(tenantScope);
  }
  if (vocabId != null && schemaCols.includes("VocabularyID")) {
    conditions.push(`"VocabularyID" = ?`);
    whereParams.push(vocabId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const total = (
    db.prepare(`SELECT COUNT(*) as cnt FROM "${safeTbl}" ${whereClause}`).get(...whereParams) as {
      cnt: number;
    }
  ).cnt;

  const rows = db
    .prepare(`SELECT rowid AS rowid, * FROM "${safeTbl}" ${whereClause} ${orderClause} LIMIT ?`)
    .all(...whereParams, maxRows) as object[];

  return { rows, total, truncated: total > maxRows };
}

// RISKREGISTERENTRY: the risk level (inherent/current/residual) is derived
// automatically from probability × impact (scale 1–5 → 1–25). Server source of
// truth: recomputed on every write, whatever values are received.
const RISK_LEVEL_TRIPLES: ReadonlyArray<readonly [string, string, string]> = [
  ["InherentRiskLevel", "InherentProbability", "InherentImpact"],
  ["CurrentRiskLevel", "CurrentProbability", "CurrentImpact"],
  ["ResidualRiskLevel", "ResidualProbability", "ResidualImpact"],
];

function applyRiskRegisterLevels(
  db: Database.Database,
  table: string,
  rowid: number | null,
  row: Record<string, unknown>
): void {
  if (table.toUpperCase() !== "RISKREGISTERENTRY") return;
  let existing: Record<string, unknown> | null | undefined;
  // Effective value after the operation: the one provided if the column is in the
  // request, otherwise (partial update) the one already in the database.
  const eff = (col: string): unknown => {
    if (col in row) return row[col];
    if (existing === undefined) {
      existing =
        rowid == null
          ? null
          : ((db.prepare('SELECT * FROM "RISKREGISTERENTRY" WHERE rowid = ?').get(rowid) ??
              null) as Record<string, unknown> | null);
    }
    return existing ? existing[col] : undefined;
  };
  const toInt = (v: unknown): number | null => {
    if (v === undefined || v === null || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? Math.trunc(n) : null;
  };
  for (const [levelCol, probCol, impactCol] of RISK_LEVEL_TRIPLES) {
    const p = toInt(eff(probCol));
    const i = toInt(eff(impactCol));
    row[levelCol] = p != null && i != null ? p * i : null;
  }
}

/**
 * EBIOS RM — threat level of a stakeholder (ecosystem mapping),
 * computed automatically on write (ThreatLevel/Zone read-only on the form side):
 *   exposure          = dependency × penetration
 *   cyber reliability = maturity × trust
 *   threat level      = exposure / cyber reliability
 *   zone: Danger if ≥ 1.5; Watch if ≥ 0.5; otherwise Control.
 * If one of the 4 criteria is missing/zero, ThreatLevel and Zone are reset to NULL.
 */
function applyEbiosStakeholderLevel(
  db: Database.Database,
  table: string,
  rowid: number | null,
  row: Record<string, unknown>
): void {
  if (table.toUpperCase() !== "EBIOSSTAKEHOLDER") return;
  let existing: Record<string, unknown> | null | undefined;
  const eff = (col: string): unknown => {
    if (col in row) return row[col];
    if (existing === undefined) {
      existing =
        rowid == null
          ? null
          : ((db.prepare('SELECT * FROM "EBIOSSTAKEHOLDER" WHERE rowid = ?').get(rowid) ??
              null) as Record<string, unknown> | null);
    }
    return existing ? existing[col] : undefined;
  };
  const num = (v: unknown): number | null => {
    if (v === undefined || v === null || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  const dep = num(eff("Dependency")), pen = num(eff("Penetration"));
  const mat = num(eff("Maturity")), trust = num(eff("Trust"));
  if (dep == null || pen == null || mat == null || trust == null) {
    row["ThreatLevel"] = null;
    row["Zone"] = null;
    return;
  }
  const tl = Math.round(((dep * pen) / (mat * trust)) * 100) / 100;
  row["ThreatLevel"] = tl;
  row["Zone"] = tl >= 1.5 ? "Danger" : tl >= 0.5 ? "Watch" : "Control";
}

export function insertRow(
  dbName: string,
  table: string,
  row: Record<string, unknown>,
  tenantScope?: number | null
): string | number | null {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");

  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string; type: string; pk: number }[];

  applyRiskRegisterLevels(db, table, null, row); // derived risk levels
  applyEbiosStakeholderLevel(db, table, null, row); // EBIOS: threat level + zone

  // Multi-tenant: forces the current user's TenantID (scoped table).
  // The super-admin (tenantScope null) forces nothing (can target any tenant).
  if (shouldScope(dbName, table, tenantScope)) {
    row[TENANT_COL] = tenantScope;
  } else if (TENANT_COL in row) {
    // Never persist an empty TenantID ('' / blank) in an integer column:
    // store a valid number, otherwise NULL (avoids creating "orphan" data).
    const n = normTenant(row[TENANT_COL]);
    if (n == null) delete row[TENANT_COL];
    else row[TENANT_COL] = n;
  }

  // Key auto-increment: the XORCISM tables have no PRIMARY KEY
  // declared in the database (pk=0 everywhere); by convention the 1st column is the ID.
  // If that integer column has no provided value, we assign it MAX+1.
  const pkCol = schema.find((c) => c.pk === 1) ?? schema[0];
  if (pkCol && /int/i.test(pkCol.type)) {
    const cur = row[pkCol.name];
    if (cur === undefined || cur === null || cur === "") {
      const r = db
        .prepare(`SELECT COALESCE(MAX("${pkCol.name}"), 0) + 1 AS n FROM "${safeTbl}"`)
        .get() as { n: number };
      row[pkCol.name] = r.n;
    }
  }

  // Auto-fills the date columns (CreatedDate, ValidFromDate) with the
  // current date if they exist and no value was provided.
  const autoDateNames = [
    "createddate", "created_date", "datecreated",
    "validfromdate", "valid_from_date",
  ];
  const today = new Date().toISOString().replace("T", " ").slice(0, 19);
  for (const c of schema) {
    if (autoDateNames.includes(c.name.toLowerCase())) {
      const cur = row[c.name];
      if (cur === undefined || cur === null || cur === "") {
        row[c.name] = today;
      }
    }
  }

  // isEncrypted: default value 0 if the column exists and is not provided.
  const encCol = schema.find((c) => c.name.toLowerCase() === "isencrypted");
  if (encCol) {
    const cur = row[encCol.name];
    if (cur === undefined || cur === null || cur === "") {
      row[encCol.name] = 0;
    }
  }

  // VocabularyID: default value 1 (vocabulary XORCISM) if not provided.
  const vocabCol = schema.find((c) => c.name.toLowerCase() === "vocabularyid");
  if (vocabCol) {
    const cur = row[vocabCol.name];
    if (cur === undefined || cur === null || cur === "") {
      row[vocabCol.name] = 1;
    }
  }

  // Encrypt sensitive fields (vault) before writing — no-op if not configured.
  vault.encryptRowForWrite(table, row, new Set(schema.map((c) => c.name)));

  const cols = Object.keys(row)
    .map((c) => `"${c}"`)
    .join(", ");
  const placeholders = Object.keys(row)
    .map(() => "?")
    .join(", ");
  db.prepare(`INSERT INTO "${safeTbl}" (${cols}) VALUES (${placeholders})`).run(
    ...Object.values(row)
  );
  // Returns the assigned identifier (provided PK or MAX+1) — useful for "foreign" creation.
  return pkCol ? ((row[pkCol.name] as string | number | null) ?? null) : null;
}

/**
 * Returns the next identifier for a table's integer primary key:
 * { column, value } where value = MAX(pk)+1. For a textual (or absent) PK,
 * value is null (no auto-increment possible).
 */
export function nextId(
  dbName: string,
  table: string
): { column: string | null; value: number | null } {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string; type: string; pk: number }[];
  const pkCol = schema.find((c) => c.pk === 1) ?? schema[0];
  if (!pkCol) return { column: null, value: null };
  if (!/int/i.test(pkCol.type)) return { column: pkCol.name, value: null };
  const r = db
    .prepare(`SELECT COALESCE(MAX("${pkCol.name}"), 0) + 1 AS n FROM "${safeTbl}"`)
    .get() as { n: number };
  return { column: pkCol.name, value: r.n };
}

/**
 * Counts the rows where `col` equals exactly `value` (case-insensitive).
 * Used for the "*Name" duplicate check at creation. `col` is validated against
 * the real schema before interpolation. Returns a sample of the existing PK.
 */
export function nameExists(
  dbName: string,
  table: string,
  col: string,
  value: string
): { exists: boolean; count: number } {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  if (!schema.some((c) => c.name === col)) throw new Error("Unknown column");
  const r = db
    .prepare(`SELECT COUNT(*) AS n FROM "${safeTbl}" WHERE "${col}" = ? COLLATE NOCASE`)
    .get(value) as { n: number };
  return { exists: r.n > 0, count: r.n };
}

/**
 * Lookup for foreign-key-style dropdown lists:
 * returns [{ id, label }] from (idCol, labelCol) of a table, sorted by label.
 */
export function lookup(
  dbName: string,
  table: string,
  idCol: string,
  labelCol: string
): { id: unknown; label: unknown }[] {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  const valid = new Set(schema.map((c) => c.name));
  if (!valid.has(idCol) || !valid.has(labelCol))
    throw new Error("Unknown idCol/labelCol");
  return db
    .prepare(
      `SELECT "${idCol}" AS id, "${labelCol}" AS label
       FROM "${safeTbl}"
       WHERE "${idCol}" IS NOT NULL
       ORDER BY "${labelCol}" COLLATE NOCASE`
    )
    .all() as { id: unknown; label: unknown }[];
}

/**
 * Lookup of a SINGLE value: label (labelCol) of the row whose idCol = idVal.
 * For large tables (e.g. VULNERABILITY ~ 355k rows) where preloading
 * the whole lookup table would be prohibitive. Returns null if not found.
 */
export function lookupOne(
  dbName: string,
  table: string,
  idCol: string,
  idVal: string | number,
  labelCol: string
): string | null {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  const valid = new Set(schema.map((c) => c.name));
  if (!valid.has(idCol) || !valid.has(labelCol))
    throw new Error("Unknown idCol/labelCol");
  const r = db
    .prepare(`SELECT "${labelCol}" AS label FROM "${safeTbl}" WHERE "${idCol}" = ? LIMIT 1`)
    .get(idVal) as { label: unknown } | undefined;
  if (!r) return null;
  return r.label == null ? null : String(r.label);
}
// Labels of SEVERAL rows in one query (lazy, bounded to the visible rows
// of a grid: avoids N lookup-one calls on a large table).
export function lookupMany(
  dbName: string,
  table: string,
  idCol: string,
  labelCol: string,
  ids: (string | number)[]
): { id: unknown; label: unknown }[] {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  const valid = new Set(schema.map((c) => c.name));
  if (!valid.has(idCol) || !valid.has(labelCol))
    throw new Error("Unknown idCol/labelCol");
  const uniq = Array.from(new Set(ids.map((v) => String(v)))).filter((v) => v !== "");
  if (!uniq.length) return [];
  const placeholders = uniq.map(() => "?").join(",");
  return db
    .prepare(
      `SELECT "${idCol}" AS id, "${labelCol}" AS label
       FROM "${safeTbl}"
       WHERE "${idCol}" IN (${placeholders})`
    )
    .all(...uniq) as { id: unknown; label: unknown }[];
}
// ONE full row (with rowid) by column=value — to edit a row of a
// target table from another view (e.g. clickable VULReferential). Exact, not LIKE.
export function getRowById(
  dbName: string,
  table: string,
  idCol: string,
  idVal: string | number
): Record<string, unknown> | null {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  if (!schema.some((c) => c.name === idCol)) throw new Error("Unknown idCol");
  const r = db
    .prepare(`SELECT rowid AS rowid, * FROM "${safeTbl}" WHERE "${idCol}" = ? LIMIT 1`)
    .get(idVal) as Record<string, unknown> | undefined;
  return r ?? null;
}

/**
 * Dashboard: number of vulnerabilities per year (VULNERABILITY.VULPublishedDate).
 * Only keeps valid 4-digit years.
 */
export function vulnByYear(): { year: string; count: number }[] {
  const db = getDb("XVULNERABILITY");
  return db
    .prepare(
      `SELECT substr(VULPublishedDate, 1, 4) AS year, COUNT(*) AS count
       FROM VULNERABILITY
       WHERE VULPublishedDate IS NOT NULL
         AND substr(VULPublishedDate, 1, 4) GLOB '[12][0-9][0-9][0-9]'
       GROUP BY year
       ORDER BY year`
    )
    .all() as { year: string; count: number }[];
}

/**
 * Asset financial value: top N assets by FinancialValue + total/count.
 * Tolerates the absence of the column (returns empty).
 */
export function assetFinancialValues(limit = 15): {
  assets: { name: string; value: number }[];
  total: number;
  count: number;
} {
  const db = getDb("XORCISM");
  const cols = new Set(
    (db.prepare(`PRAGMA table_info(ASSET)`).all() as { name: string }[]).map((c) => c.name)
  );
  if (!cols.has("FinancialValue")) return { assets: [], total: 0, count: 0 };
  const assets = db
    .prepare(
      `SELECT AssetName AS name, FinancialValue AS value FROM ASSET
       WHERE FinancialValue IS NOT NULL AND FinancialValue <> 0
       ORDER BY FinancialValue DESC LIMIT ?`
    )
    .all(limit) as { name: string; value: number }[];
  const agg = db
    .prepare(
      `SELECT COALESCE(SUM(FinancialValue), 0) AS total, COUNT(*) AS count
       FROM ASSET WHERE FinancialValue IS NOT NULL AND FinancialValue <> 0`
    )
    .get() as { total: number; count: number };
  return { assets, total: agg.total, count: agg.count };
}

/**
 * Risk exposure: assets ranked by RiskScore × FinancialValue.
 * Quantifies risk in monetary value (top N + total). Tolerates missing columns.
 */
export function assetRiskExposure(limit = 15): {
  assets: { name: string; risk: number; value: number; exposure: number }[];
  totalExposure: number;
  totalValue: number;
  count: number;
} {
  const db = getDb("XORCISM");
  const cols = new Set(
    (db.prepare(`PRAGMA table_info(ASSET)`).all() as { name: string }[]).map((c) => c.name)
  );
  if (!cols.has("FinancialValue") || !cols.has("RiskScore"))
    return { assets: [], totalExposure: 0, totalValue: 0, count: 0 };
  // FinancialValue / RiskScore may be stored as text (empty "", non-numeric):
  // CAST AS REAL normalizes ("" → 0) to exclude empty values and avoid a textual
  // product returning 0. Filters on non-zero numeric financial value.
  const assets = db
    .prepare(
      `SELECT AssetName AS name,
              CAST(COALESCE(RiskScore, 0) AS REAL) AS risk,
              CAST(FinancialValue AS REAL) AS value,
              CAST(COALESCE(RiskScore, 0) AS REAL) * CAST(FinancialValue AS REAL) AS exposure
       FROM ASSET WHERE CAST(FinancialValue AS REAL) <> 0
       ORDER BY exposure DESC LIMIT ?`
    )
    .all(limit) as { name: string; risk: number; value: number; exposure: number }[];
  const agg = db
    .prepare(
      `SELECT COALESCE(SUM(CAST(COALESCE(RiskScore, 0) AS REAL) * CAST(FinancialValue AS REAL)), 0) AS te,
              COALESCE(SUM(CAST(FinancialValue AS REAL)), 0) AS tv, COUNT(*) AS c
       FROM ASSET WHERE CAST(FinancialValue AS REAL) <> 0`
    )
    .get() as { te: number; tv: number; c: number };
  return { assets, totalExposure: agg.te, totalValue: agg.tv, count: agg.c };
}

// ── Attack-surface graph (ASSET ↔ apps / CPEs / vulns / orgs / persons / threats / incidents / tags) ──
export interface AsNode {
  id: string; type: string; label: string; sub?: string;
  db?: string; table?: string; idCol?: string; idVal?: string;
}
export interface AsLink { source: string; target: string; label: string }

function sevFromCvss(c: number): string {
  if (!Number.isFinite(c) || c <= 0) return "";
  if (c >= 9) return "Critical";
  if (c >= 7) return "High";
  if (c >= 4) return "Medium";
  return "Low";
}

/**
 * Builds a tenant-scoped attack-surface graph centered on ASSETs. Each asset is
 * linked to its applications, CPEs/components, vulnerabilities (XVULNERABILITY),
 * owning organisations, responsible persons, threats (XTHREAT), incidents
 * (XINCIDENT), related assets (ASSETFORASSET) and tags. `assetId` focuses on a
 * single asset (its direct neighbourhood); otherwise the whole tenant surface
 * (top assets by risk, capped). Every related-table read is defensive: a missing
 * table/column is skipped rather than failing the whole graph. tenantId=null
 * (super-admin) = no tenant filter.
 */
export function assetAttackSurface(
  tenantId: number | null, assetId?: number | null
): { nodes: AsNode[]; links: AsLink[]; focus: string | null } {
  const xo = getDb("XORCISM");
  const nodes = new Map<string, AsNode>();
  const links: AsLink[] = [];
  const seenLink = new Set<string>();
  const addNode = (n: AsNode): void => { if (!nodes.has(n.id)) nodes.set(n.id, n); };
  const addLink = (s: string, t: string, label: string): void => {
    const k = `${s}|${t}|${label}`;
    if (s && t && s !== t && !seenLink.has(k)) { seenLink.add(k); links.push({ source: s, target: t, label }); }
  };
  const safe = (fn: () => void): void => { try { fn(); } catch { /* table/columns absent */ } };

  // Tenant asset universe (names + risk for nodes, membership for asset↔asset links).
  const tArgs: number[] = [];
  const tWhere = tenantId != null ? "WHERE TenantID = ?" : "";
  if (tenantId != null) tArgs.push(tenantId);
  const nameOf = new Map<number, { name: string; risk: number; crit: string }>();
  for (const a of xo.prepare(
    `SELECT AssetID, AssetName, RiskScore, AssetCriticalityLevel FROM ASSET ${tWhere} LIMIT 5000`
  ).all(...tArgs) as { AssetID: number; AssetName: string; RiskScore: unknown; AssetCriticalityLevel: unknown }[]) {
    nameOf.set(a.AssetID, {
      name: a.AssetName || `Asset #${a.AssetID}`,
      risk: Math.round(Number(a.RiskScore) || 0),
      crit: String(a.AssetCriticalityLevel ?? ""),
    });
  }
  if (assetId && !nameOf.has(assetId) && tenantId == null) {
    const a = xo.prepare(
      "SELECT AssetID, AssetName, RiskScore, AssetCriticalityLevel FROM ASSET WHERE AssetID = ?"
    ).get(assetId) as { AssetID: number; AssetName: string; RiskScore: unknown; AssetCriticalityLevel: unknown } | undefined;
    if (a) nameOf.set(a.AssetID, { name: a.AssetName || `Asset #${a.AssetID}`, risk: Math.round(Number(a.RiskScore) || 0), crit: String(a.AssetCriticalityLevel ?? "") });
  }

  // Focal assets: one asset (focused neighbourhood) or the tenant's top assets by risk (capped).
  const focal: number[] = assetId
    ? (nameOf.has(assetId) ? [assetId] : [])
    : [...nameOf.entries()].sort((x, y) => y[1].risk - x[1].risk).slice(0, 150).map(([id]) => id);
  if (!focal.length) return { nodes: [], links: [], focus: assetId ? `asset:${assetId}` : null };

  const assetNode = (id: number): string => {
    const nid = `asset:${id}`;
    const m = nameOf.get(id);
    if (m) addNode({ id: nid, type: "asset", label: m.name, sub: `risk ${m.risk}${m.crit ? " · " + m.crit : ""}`, db: "XORCISM", table: "ASSET", idCol: "AssetID", idVal: String(id) });
    return nid;
  };
  for (const id of focal) assetNode(id);
  const inC = focal.map(() => "?").join(",");

  // Applications (APPLICATIONFORASSET → APPLICATION)
  safe(() => {
    for (const r of xo.prepare(
      `SELECT fa.AssetID aid, a.ApplicationID id, a.ApplicationName name
       FROM APPLICATIONFORASSET fa JOIN APPLICATION a ON a.ApplicationID = fa.ApplicationID
       WHERE fa.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string }[]) {
      const nid = `app:${r.id}`;
      addNode({ id: nid, type: "application", label: r.name || `App #${r.id}`, db: "XORCISM", table: "APPLICATION", idCol: "ApplicationID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, "runs");
    }
  });

  // CPEs / components (CPEFORASSET → CPE)
  safe(() => {
    for (const r of xo.prepare(
      `SELECT fa.AssetID aid, c.CPEID id, COALESCE(NULLIF(c.CPETitle,''), c.CPEName) name
       FROM CPEFORASSET fa JOIN CPE c ON c.CPEID = fa.CPEID WHERE fa.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string }[]) {
      const nid = `cpe:${r.id}`;
      addNode({ id: nid, type: "cpe", label: r.name || `CPE #${r.id}`, db: "XORCISM", table: "CPE", idCol: "CPEID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, "exposes");
    }
  });

  // Vulnerabilities (ASSETVULNERABILITY → XVULNERABILITY.VULNERABILITY)
  safe(() => {
    const av = xo.prepare(
      `SELECT AssetID aid, VulnerabilityID vid FROM ASSETVULNERABILITY
       WHERE AssetID IN (${inC}) AND COALESCE(FalsePositive,0)=0`).all(...focal) as { aid: number; vid: number }[];
    const vids = [...new Set(av.map((r) => r.vid).filter(Boolean))].slice(0, 900);
    const meta = new Map<number, { label: string; sev: string }>();
    if (vids.length) safe(() => {
      const xv = getDb("XVULNERABILITY");
      const vin = vids.map(() => "?").join(",");
      for (const v of xv.prepare(
        `SELECT VulnerabilityID id, COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID) label,
                CVSSBaseScore cvss, KEV kev FROM VULNERABILITY WHERE VulnerabilityID IN (${vin})`).all(...vids) as { id: number; label: string; cvss: unknown; kev: unknown }[]) {
        meta.set(v.id, { label: v.label, sev: Number(v.kev) > 0 ? "KEV" : sevFromCvss(Number(v.cvss)) });
      }
    });
    const vidSet = new Set(vids);
    for (const r of av) {
      if (!vidSet.has(r.vid)) continue;
      const m = meta.get(r.vid);
      const nid = `vuln:${r.vid}`;
      addNode({ id: nid, type: "vulnerability", label: m?.label || `Vuln #${r.vid}`, sub: m?.sev || undefined, db: "XVULNERABILITY", table: "VULNERABILITY", idCol: "VulnerabilityID", idVal: String(r.vid) });
      addLink(`asset:${r.aid}`, nid, "vulnerable-to");
    }
  });

  // Organisations (ASSETFORORGANISATION → ORGANISATION)
  safe(() => {
    for (const r of xo.prepare(
      `SELECT fo.AssetID aid, o.OrganisationID id, o.OrganisationName name
       FROM ASSETFORORGANISATION fo JOIN ORGANISATION o ON o.OrganisationID = fo.OrganisationID
       WHERE fo.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string }[]) {
      const nid = `org:${r.id}`;
      addNode({ id: nid, type: "organisation", label: r.name || `Org #${r.id}`, db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, "belongs-to");
    }
  });

  // Persons (PERSONFORASSET → PERSON)
  safe(() => {
    for (const r of xo.prepare(
      `SELECT pa.AssetID aid, p.PersonID id, COALESCE(NULLIF(p.FullName,''), p.LastName) name, pa.relationshiptype rel
       FROM PERSONFORASSET pa JOIN PERSON p ON p.PersonID = pa.PersonID WHERE pa.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string; rel: string }[]) {
      const nid = `person:${r.id}`;
      addNode({ id: nid, type: "person", label: r.name || `Person #${r.id}`, db: "XORCISM", table: "PERSON", idCol: "PersonID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, r.rel || "responsible");
    }
  });

  // Threats (XTHREAT.THREATFORASSET → XTHREAT.THREAT)
  safe(() => {
    const xt = getDb("XTHREAT");
    for (const r of xt.prepare(
      `SELECT fa.AssetID aid, th.ThreatID id, th.ThreatName name FROM THREATFORASSET fa
       JOIN THREAT th ON th.ThreatID = fa.ThreatID WHERE fa.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string }[]) {
      const nid = `threat:${r.id}`;
      addNode({ id: nid, type: "threat", label: r.name || `Threat #${r.id}`, db: "XTHREAT", table: "THREAT", idCol: "ThreatID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, "targeted-by");
    }
  });

  // Incidents (XINCIDENT.INCIDENTFORASSET → XINCIDENT.INCIDENT)
  safe(() => {
    const xi = getDb("XINCIDENT");
    for (const r of xi.prepare(
      `SELECT fa.AssetID aid, i.IncidentID id, i.IncidentName name, fa.Compromised comp FROM INCIDENTFORASSET fa
       JOIN INCIDENT i ON i.IncidentID = fa.IncidentID WHERE fa.AssetID IN (${inC})`).all(...focal) as { aid: number; id: number; name: string; comp: unknown }[]) {
      const nid = `incident:${r.id}`;
      const compromised = Number(r.comp) === 1;
      addNode({ id: nid, type: "incident", label: r.name || `Incident #${r.id}`, sub: compromised ? "compromised" : undefined, db: "XINCIDENT", table: "INCIDENT", idCol: "IncidentID", idVal: String(r.id) });
      addLink(`asset:${r.aid}`, nid, compromised ? "compromised-in" : "affected-by");
    }
  });

  // Asset ↔ asset relationships (ASSETFORASSET) — kept within the tenant universe.
  safe(() => {
    for (const r of xo.prepare(
      `SELECT AssetSubjectID s, AssetRefID r, relationshiptype rel FROM ASSETFORASSET
       WHERE AssetSubjectID IN (${inC}) OR AssetRefID IN (${inC})`).all(...focal, ...focal) as { s: number; r: number; rel: string }[]) {
      const s = Number(r.s), rr = Number(r.r);
      if (!s || !rr || !nameOf.has(s) || !nameOf.has(rr)) continue;
      addLink(assetNode(s), assetNode(rr), r.rel || "related-to");
    }
  });

  // Tags (ASSETTAG)
  safe(() => {
    for (const r of xo.prepare(
      `SELECT AssetID aid, Tag tag FROM ASSETTAG WHERE AssetID IN (${inC}) AND COALESCE(Tag,'') <> ''`).all(...focal) as { aid: number; tag: string }[]) {
      const nid = `tag:${String(r.tag).toLowerCase()}`;
      addNode({ id: nid, type: "tag", label: String(r.tag) });
      addLink(`asset:${r.aid}`, nid, "tagged");
    }
  });

  return { nodes: [...nodes.values()], links, focus: assetId ? `asset:${assetId}` : null };
}

/**
 * Dashboard: number of incidents per status (INCIDENT.IncidentStatusID join
 * → INCIDENTSTATUS.IncidentStatusID), XINCIDENT database.
 */
export function incidentsByStatus(): { status: string; count: number }[] {
  const db = getDb("XINCIDENT");
  return db
    .prepare(
      `SELECT s.IncidentStatusName AS status, COUNT(i.IncidentID) AS count
       FROM INCIDENT i
       JOIN INCIDENTSTATUS s ON s.IncidentStatusID = i.IncidentStatusID
       GROUP BY s.IncidentStatusName
       ORDER BY count DESC, s.IncidentStatusName`
    )
    .all() as { status: string; count: number }[];
}

/**
 * Dashboard: number of incidents per asset over a period (filter on
 * INCIDENT.datetime_reported). INCIDENTFORASSET join (XINCIDENT);
 * the asset names come from XORCISM.ASSET (resolved in memory).
 */
export function incidentsByAsset(
  from?: string,
  to?: string
): { asset: string; count: number }[] {
  const xinc = getDb("XINCIDENT");
  const where = ["fa.AssetID IS NOT NULL"];
  const params: string[] = [];
  if (from) {
    where.push("date(i.datetime_reported) >= date(?)");
    params.push(from);
  }
  if (to) {
    where.push("date(i.datetime_reported) <= date(?)");
    params.push(to);
  }
  const rows = xinc
    .prepare(
      `SELECT fa.AssetID AS assetId, COUNT(DISTINCT i.IncidentID) AS count
       FROM INCIDENTFORASSET fa
       JOIN INCIDENT i ON i.IncidentID = fa.IncidentID
       WHERE ${where.join(" AND ")}
       GROUP BY fa.AssetID
       ORDER BY count DESC`
    )
    .all(...params) as { assetId: number; count: number }[];
  if (!rows.length) return [];

  // Resolve the asset names (XORCISM database)
  const ids = rows.map((r) => r.assetId);
  const ph = ids.map(() => "?").join(",");
  const names = getDb("XORCISM")
    .prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${ph})`)
    .all(...ids) as { AssetID: number; AssetName: string }[];
  const nameMap = new Map(names.map((n) => [n.AssetID, n.AssetName]));
  return rows.map((r) => ({
    asset: nameMap.get(r.assetId) || `#${r.assetId}`,
    count: r.count,
  }));
}

/** CPEs linked to an asset (CPEFORASSET → CPE join, XORCISM database). */
export function getAssetCpes(assetId: number): { CPEID: number; CPEName: string }[] {
  const db = getDb("XORCISM");
  return db
    .prepare(
      `SELECT c.CPEID AS CPEID, c.CPEName AS CPEName
       FROM CPEFORASSET fa
       JOIN CPE c ON c.CPEID = fa.CPEID
       WHERE fa.AssetID = ?
       ORDER BY c.CPEName COLLATE NOCASE`
    )
    .all(assetId) as { CPEID: number; CPEName: string }[];
}

export interface VulnCpeRow { CPEID: number; CPEName: string; KnownVulnerable: boolean }
/** CPEs affected by a vulnerability: XVULNERABILITY.VULNERABILITYFORCPE → name resolved in XORCISM.CPE. */
export function getVulnerabilityCpes(vulnerabilityId: number): VulnCpeRow[] {
  let links: { CPEID: number; isKnownVulnerable: number | null }[] = [];
  try {
    links = getDb("XVULNERABILITY")
      .prepare("SELECT CPEID, isKnownVulnerable FROM VULNERABILITYFORCPE WHERE VulnerabilityID = ? AND CPEID IS NOT NULL")
      .all(vulnerabilityId) as { CPEID: number; isKnownVulnerable: number | null }[];
  } catch { return []; } // VULNERABILITYFORCPE absent / DB unavailable
  if (!links.length) return [];
  const ids = [...new Set(links.map((l) => Number(l.CPEID)))];
  const nameById = new Map<number, string>();
  try {
    const ph = ids.map(() => "?").join(",");
    for (const c of getDb("XORCISM").prepare(`SELECT CPEID, CPEName FROM CPE WHERE CPEID IN (${ph})`).all(...ids) as { CPEID: number; CPEName: string }[])
      nameById.set(Number(c.CPEID), c.CPEName);
  } catch { /* CPE names optional — fall back to #id */ }
  const byId = new Map<number, VulnCpeRow>();
  for (const l of links) {
    const id = Number(l.CPEID);
    const kv = l.isKnownVulnerable == null ? true : Number(l.isKnownVulnerable) === 1;
    const ex = byId.get(id);
    if (!ex) byId.set(id, { CPEID: id, CPEName: nameById.get(id) || `#${id}`, KnownVulnerable: kv });
    else if (kv) ex.KnownVulnerable = true;
  }
  return [...byId.values()].sort((a, b) => a.CPEName.localeCompare(b.CPEName));
}

// ── ASSET ↔ OVAL definitions (XORCISM.ASSETOVALDEFINITION ↔ XOVAL.OVALDEFINITION) ──
export interface AssetOvalRow {
  AssetOVALDefinitionID: number;
  OVALDefinitionID: number;
  Pattern: string; // OVALDefinitionIDPattern resolved (cross-database)
  Title: string | null; // OVALDefinitionTitle resolved (cross-database)
  Status: string | null;
}

/** OVAL definitions linked to an asset (pattern + title resolved in XOVAL.OVALDEFINITION). */
export function getAssetOvals(assetId: number): AssetOvalRow[] {
  const links = getDb("XORCISM")
    .prepare(
      "SELECT AssetOVALDefinitionID, OVALDefinitionID, Status FROM ASSETOVALDEFINITION " +
        "WHERE AssetID = ? ORDER BY AssetOVALDefinitionID DESC"
    )
    .all(assetId) as { AssetOVALDefinitionID: number; OVALDefinitionID: number | null; Status: string | null }[];
  if (!links.length) return [];
  const ids = [...new Set(links.map((l) => l.OVALDefinitionID).filter((v): v is number => v != null))];
  const patById = new Map<number, string>();
  const titleById = new Map<number, string>();
  if (ids.length) {
    const ph = ids.map(() => "?").join(",");
    const defs = getDb("XOVAL")
      .prepare(`SELECT OVALDefinitionID, OVALDefinitionIDPattern, OVALDefinitionTitle FROM OVALDEFINITION WHERE OVALDefinitionID IN (${ph})`)
      .all(...ids) as { OVALDefinitionID: number; OVALDefinitionIDPattern: string; OVALDefinitionTitle: string | null }[];
    for (const d of defs) { patById.set(d.OVALDefinitionID, d.OVALDefinitionIDPattern); if (d.OVALDefinitionTitle != null) titleById.set(d.OVALDefinitionID, d.OVALDefinitionTitle); }
  }
  return links.map((l) => ({
    AssetOVALDefinitionID: l.AssetOVALDefinitionID,
    OVALDefinitionID: l.OVALDefinitionID ?? 0,
    Pattern: l.OVALDefinitionID != null ? patById.get(l.OVALDefinitionID) ?? `#${l.OVALDefinitionID}` : "",
    Title: l.OVALDefinitionID != null ? titleById.get(l.OVALDefinitionID) ?? null : null,
    Status: l.Status,
  }));
}

/** Search OVAL definitions (by pattern or title) — limited (large table). */
export function searchOvalDefinitions(
  q: string,
  limit = 50
): { OVALDefinitionID: number; OVALDefinitionIDPattern: string; OVALDefinitionTitle: string }[] {
  const term = `%${q}%`;
  return getDb("XOVAL")
    .prepare(
      `SELECT OVALDefinitionID, OVALDefinitionIDPattern, OVALDefinitionTitle FROM OVALDEFINITION
       WHERE OVALDefinitionIDPattern LIKE ? OR OVALDefinitionTitle LIKE ?
       ORDER BY OVALDefinitionID LIMIT ?`
    )
    .all(term, term, Math.min(limit, 200)) as {
    OVALDefinitionID: number;
    OVALDefinitionIDPattern: string;
    OVALDefinitionTitle: string;
  }[];
}

/** Links an OVAL definition to an asset (idempotent: ignores if already linked). */
export function addAssetOval(assetId: number, ovalDefinitionId: number): void {
  const db = getDb("XORCISM");
  const exists = db
    .prepare("SELECT 1 FROM ASSETOVALDEFINITION WHERE AssetID = ? AND OVALDefinitionID = ?")
    .get(assetId, ovalDefinitionId);
  if (exists) return;
  const maxId = (
    db.prepare("SELECT COALESCE(MAX(AssetOVALDefinitionID),0) AS m FROM ASSETOVALDEFINITION").get() as {
      m: number;
    }
  ).m;
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  db.prepare(
    "INSERT INTO ASSETOVALDEFINITION (AssetOVALDefinitionID, AssetID, OVALDefinitionID, CreatedDate) VALUES (?,?,?,?)"
  ).run(maxId + 1, assetId, ovalDefinitionId, ts);
}

/** Unlinks an OVAL definition from an asset (delete by PK, bounded to the asset). */
export function removeAssetOval(assetId: number, assetOvalDefinitionId: number): void {
  getDb("XORCISM")
    .prepare("DELETE FROM ASSETOVALDEFINITION WHERE AssetOVALDefinitionID = ? AND AssetID = ?")
    .run(assetOvalDefinitionId, assetId);
}

/**
 * Vulnerabilities linked to an asset: VulnerabilityID via XORCISM.ASSETVULNERABILITY,
 * then VULGUID/VULDescription resolved in XVULNERABILITY.VULNERABILITY (cross-database).
 */
export interface VulnRow {
  VulnerabilityID: number;
  VULReferential: string;
  VULReferentialID: string;
  VULGUID: string;
  VULDescription: string;
  // Enriched on the asset-vulnerability view (getAssetVulnerabilities): the junction-row PK
  // (needed to attach a remediation plan), the per-instance patch status, and how many
  // remediation plans already exist for the instance. Optional elsewhere.
  AssetVulnerabilityID?: number;
  PatchStatus?: string | null;
  RemediationCount?: number;
  FalsePositive?: number; // 0/1 — analyst-confirmed false positive (excluded from risk)
}

// ── Tag referential (XORCISM.TAG; name column = TagValue) ─────────────
/** Returns the TagID of a tag by its label, creating it if absent (case-insensitive). */
export function getOrCreateTag(name: string): number {
  const db = getDb("XORCISM");
  const v = String(name ?? "").trim();
  if (!v) return 0;
  const found = db.prepare("SELECT TagID FROM TAG WHERE TagValue = ? COLLATE NOCASE LIMIT 1").get(v) as
    | { TagID: number } | undefined;
  if (found) return found.TagID;
  const id = allocId(db, "TAG", "TagID");
  db.prepare("INSERT INTO TAG (TagID, TagGUID, TagValue, CreatedDate) VALUES (?,?,?,?)")
    .run(id, randomUUID(), v, nowTs());
  return id;
}
/** Distinct tag labels (autocompletion). */
export function listTags(limit = 500): string[] {
  return (getDb("XORCISM")
    .prepare("SELECT DISTINCT TagValue FROM TAG WHERE TagValue IS NOT NULL AND TagValue <> '' ORDER BY TagValue COLLATE NOCASE LIMIT ?")
    .all(limit) as { TagValue: string }[]).map((r) => r.TagValue);
}
// Deduplicates a list of labels (order preserved, empties ignored).
function cleanTagList(tags: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tags) {
    const v = String(t ?? "").trim();
    if (v && !seen.has(v.toLowerCase())) { seen.add(v.toLowerCase()); out.push(v); }
  }
  return out;
}

// Tags of an asset (ASSETTAG, linked by AssetID) — free text, ordered by id.
export function getAssetTags(assetId: number): string[] {
  return (getDb("XORCISM")
    .prepare("SELECT Tag FROM ASSETTAG WHERE AssetID = ? AND Tag IS NOT NULL AND Tag <> '' ORDER BY AssetTagID")
    .all(assetId) as { Tag: string }[]).map((r) => r.Tag);
}
// Replaces the whole set of tags of an asset. Populates the TagID (TAG referential,
// get-or-create) in addition to the text label (Tag).
export function setAssetTags(assetId: number, tags: string[]): void {
  const db = getDb("XORCISM");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t)); // may create in TAG
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ASSETTAG WHERE AssetID = ?").run(assetId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(AssetTagID),0) AS m FROM ASSETTAG").get() as { m: number }).m;
    const ins = db.prepare(
      "INSERT INTO ASSETTAG (AssetTagID, AssetID, TagID, Tag, CreatedDate, ValidFrom) VALUES (?,?,?,?,?,?)"
    );
    clean.forEach((tg, i) => { maxId++; ins.run(maxId, assetId, tagIds[i] || null, tg, ts, today); });
  });
  tx();
}

// Tags of a CONTROL (CONTROLTAG, linked by ControlID). The pre-existing CONTROLTAG is the legacy
// TagID-only shape (label resolved via the XORCISM.TAG referential); we also add a `Tag` text column
// (like ASSETTAG) and prefer it when present. Column-aware so it runs on legacy + fresh schemas.
export function getControlTags(controlId: number): string[] {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLTAG'").get()) return [];
  const cols = new Set((db.prepare(`PRAGMA table_info("CONTROLTAG")`).all() as { name: string }[]).map((c) => c.name));
  if (cols.has("Tag")) {
    return (db.prepare("SELECT Tag FROM CONTROLTAG WHERE ControlID = ? AND Tag IS NOT NULL AND Tag <> '' ORDER BY ControlTagID")
      .all(controlId) as { Tag: string }[]).map((r) => r.Tag);
  }
  const ids = (db.prepare("SELECT TagID FROM CONTROLTAG WHERE ControlID = ? AND TagID IS NOT NULL ORDER BY ControlTagID").all(controlId) as { TagID: number }[]).map((r) => r.TagID);
  if (!ids.length) return [];
  const ph = ids.map(() => "?").join(",");
  const map = new Map((db.prepare(`SELECT TagID, TagValue FROM TAG WHERE TagID IN (${ph})`).all(...ids) as { TagID: number; TagValue: string }[]).map((r) => [r.TagID, r.TagValue]));
  return ids.map((id) => map.get(id)).filter((v): v is string => !!v);
}
export function setControlTags(controlId: number, tags: string[]): void {
  const db = getDb("XORCISM");
  db.exec(`CREATE TABLE IF NOT EXISTS CONTROLTAG (
             ControlTagID INTEGER PRIMARY KEY, ControlID INTEGER, TagID INTEGER, Tag TEXT,
             CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
           CREATE INDEX IF NOT EXISTS ix_controltag_control ON CONTROLTAG(ControlID);`);
  const cols = new Set((db.prepare(`PRAGMA table_info("CONTROLTAG")`).all() as { name: string }[]).map((c) => c.name));
  if (!cols.has("Tag")) { db.exec(`ALTER TABLE "CONTROLTAG" ADD COLUMN "Tag" TEXT`); cols.add("Tag"); }
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t));
  const dateCol = cols.has("ValidFrom") ? "ValidFrom" : (cols.has("ValidFromDate") ? "ValidFromDate" : null);
  const insCols = ["ControlTagID", "ControlID", "TagID", "Tag", "CreatedDate"].filter((c) => cols.has(c));
  if (dateCol) insCols.push(dateCol);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM CONTROLTAG WHERE ControlID = ?").run(controlId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(ControlTagID),0) AS m FROM CONTROLTAG").get() as { m: number }).m;
    const ins = db.prepare(`INSERT INTO CONTROLTAG (${insCols.map((c) => `"${c}"`).join(",")}) VALUES (${insCols.map(() => "?").join(",")})`);
    clean.forEach((tg, i) => {
      maxId++;
      const v: Record<string, unknown> = { ControlTagID: maxId, ControlID: controlId, TagID: tagIds[i] || null, Tag: tg, CreatedDate: ts };
      if (dateCol) v[dateCol] = today;
      ins.run(...insCols.map((c) => v[c]));
    });
  });
  tx();
}

// Tags of a SIGMARULE (SIGMARULETAG in XTHREAT, free-text Tag column — like ASSETTAG). Lets
// analysts tag detection rules (e.g. "ransomware", "tier-1", "needs-tuning") in the explorer.
export function getSigmaRuleTags(sigmaRuleId: number): string[] {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='SIGMARULETAG'").get()) return [];
  return (db.prepare("SELECT Tag FROM SIGMARULETAG WHERE SigmaRuleID = ? AND Tag IS NOT NULL AND Tag <> '' ORDER BY SigmaRuleTagID")
    .all(sigmaRuleId) as { Tag: string }[]).map((r) => r.Tag);
}
export function setSigmaRuleTags(sigmaRuleId: number, tags: string[]): void {
  const db = getDb("XTHREAT");
  db.exec(`CREATE TABLE IF NOT EXISTS SIGMARULETAG (
             SigmaRuleTagID INTEGER PRIMARY KEY, SigmaRuleID INTEGER, Tag TEXT,
             CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
           CREATE INDEX IF NOT EXISTS ix_sigmaruletag_rule ON SIGMARULETAG(SigmaRuleID);`);
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const clean = cleanTagList(tags);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM SIGMARULETAG WHERE SigmaRuleID = ?").run(sigmaRuleId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(SigmaRuleTagID),0) AS m FROM SIGMARULETAG").get() as { m: number }).m;
    const ins = db.prepare("INSERT INTO SIGMARULETAG (SigmaRuleTagID, SigmaRuleID, Tag, CreatedDate, ValidFrom) VALUES (?,?,?,?,?)");
    clean.forEach((tg) => { maxId++; ins.run(maxId, sigmaRuleId, tg, ts, today); });
  });
  tx();
}

// Tags of a VULNERABILITY (legacy VULNERABILITYTAG table: TagID only, no
// text column → the label is resolved via the XORCISM.TAG referential, in 2
// cross-database queries).
export function getVulnerabilityTags(vulnerabilityId: number): string[] {
  const xv = getDb("XVULNERABILITY");
  const ids = (xv
    .prepare("SELECT TagID FROM VULNERABILITYTAG WHERE VulnerabilityID = ? AND TagID IS NOT NULL ORDER BY VulnerabilityTagID")
    .all(vulnerabilityId) as { TagID: number }[]).map((r) => r.TagID);
  if (!ids.length) return [];
  const xo = getDb("XORCISM");
  const ph = ids.map(() => "?").join(",");
  const rows = xo.prepare(`SELECT TagID, TagValue FROM TAG WHERE TagID IN (${ph})`).all(...ids) as
    { TagID: number; TagValue: string }[];
  const map = new Map(rows.map((r) => [r.TagID, r.TagValue]));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const i of ids) { const v = map.get(i); if (v && !seen.has(v)) { seen.add(v); out.push(v); } }
  return out;
}
// Replaces the tags of a VULNERABILITY (shared TAG referential via getOrCreateTag).
export function setVulnerabilityTags(vulnerabilityId: number, tags: string[]): void {
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t)).filter((n) => n > 0);
  const xv = getDb("XVULNERABILITY");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const tx = xv.transaction(() => {
    xv.prepare("DELETE FROM VULNERABILITYTAG WHERE VulnerabilityID = ?").run(vulnerabilityId);
    let maxId = (xv.prepare("SELECT COALESCE(MAX(VulnerabilityTagID),0) AS m FROM VULNERABILITYTAG").get() as { m: number }).m;
    const ins = xv.prepare(
      "INSERT INTO VULNERABILITYTAG (VulnerabilityTagID, VulnerabilityID, TagID, TagGUID, CreatedDate, ValidFromDate) VALUES (?,?,?,?,?,?)"
    );
    for (const tid of tagIds) { maxId++; ins.run(maxId, vulnerabilityId, tid, randomUUID(), ts, today); }
  });
  tx();
}

// Tags of an OVALDEFINITION (OVALDEFINITIONTAG table in XOVAL: TagID only →
// label resolved via the XORCISM.TAG referential, cross-database; like VULNERABILITYTAG).
export function getOvalDefinitionTags(ovalDefinitionId: number): string[] {
  const xv = getDb("XOVAL");
  if (!xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='OVALDEFINITIONTAG'").get()) return [];
  const ids = (xv
    .prepare("SELECT TagID FROM OVALDEFINITIONTAG WHERE OVALDefinitionID = ? AND TagID IS NOT NULL ORDER BY OVALDefinitionTagID")
    .all(ovalDefinitionId) as { TagID: number }[]).map((r) => r.TagID);
  if (!ids.length) return [];
  const xo = getDb("XORCISM");
  const ph = ids.map(() => "?").join(",");
  const rows = xo.prepare(`SELECT TagID, TagValue FROM TAG WHERE TagID IN (${ph})`).all(...ids) as
    { TagID: number; TagValue: string }[];
  const map = new Map(rows.map((r) => [r.TagID, r.TagValue]));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const i of ids) { const v = map.get(i); if (v && !seen.has(v)) { seen.add(v); out.push(v); } }
  return out;
}
// Replaces the tags of an OVALDEFINITION (shared TAG referential via getOrCreateTag).
export function setOvalDefinitionTags(ovalDefinitionId: number, tags: string[]): void {
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t)).filter((n) => n > 0);
  const xv = getDb("XOVAL");
  // Legacy OVALDEFINITIONTAG table (PK NOT auto-incremented → MAX+1; no TagGUID
  // column). The CREATE only serves new databases; on the existing database it is a no-op.
  xv.exec(`CREATE TABLE IF NOT EXISTS OVALDEFINITIONTAG (
    OVALDefinitionTagID INTEGER PRIMARY KEY, OVALDefinitionID INTEGER, TagID INTEGER,
    CreatedDate TEXT, VocabularyID INTEGER, ValidFromDate TEXT, ValidUntilDate TEXT)`);
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const tx = xv.transaction(() => {
    xv.prepare("DELETE FROM OVALDEFINITIONTAG WHERE OVALDefinitionID = ?").run(ovalDefinitionId);
    let maxId = (xv.prepare("SELECT COALESCE(MAX(OVALDefinitionTagID),0) AS m FROM OVALDEFINITIONTAG").get() as { m: number }).m;
    const ins = xv.prepare(
      "INSERT INTO OVALDEFINITIONTAG (OVALDefinitionTagID, OVALDefinitionID, TagID, CreatedDate, ValidFromDate) VALUES (?,?,?,?,?)"
    );
    for (const tid of tagIds) { maxId++; ins.run(maxId, ovalDefinitionId, tid, ts, today); }
  });
  tx();
}

// Tags of a CPE (CPETAG table in XORCISM: TagID only → label resolved via the
// XORCISM.TAG referential, same database). No TagGUID column (like OVALDEFINITIONTAG).
export function getCpeTags(cpeId: number): string[] {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CPETAG'").get()) return [];
  const ids = (xo
    .prepare("SELECT TagID FROM CPETAG WHERE CPEID = ? AND TagID IS NOT NULL ORDER BY CPETagID")
    .all(cpeId) as { TagID: number }[]).map((r) => r.TagID);
  if (!ids.length) return [];
  const ph = ids.map(() => "?").join(",");
  const rows = xo.prepare(`SELECT TagID, TagValue FROM TAG WHERE TagID IN (${ph})`).all(...ids) as
    { TagID: number; TagValue: string }[];
  const map = new Map(rows.map((r) => [r.TagID, r.TagValue]));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const i of ids) { const v = map.get(i); if (v && !seen.has(v)) { seen.add(v); out.push(v); } }
  return out;
}
// Replaces the tags of a CPE (shared TAG referential via getOrCreateTag).
export function setCpeTags(cpeId: number, tags: string[]): void {
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t)).filter((n) => n > 0);
  const xo = getDb("XORCISM");
  xo.exec(`CREATE TABLE IF NOT EXISTS CPETAG (
    CPETagID INTEGER PRIMARY KEY, CPEID INTEGER, TagID INTEGER,
    CreatedDate TEXT, ValidFromDate TEXT, ValidUntilDate TEXT, VocabularyID INTEGER)`);
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM CPETAG WHERE CPEID = ?").run(cpeId);
    let maxId = (xo.prepare("SELECT COALESCE(MAX(CPETagID),0) AS m FROM CPETAG").get() as { m: number }).m;
    const ins = xo.prepare(
      "INSERT INTO CPETAG (CPETagID, CPEID, TagID, CreatedDate, ValidFromDate) VALUES (?,?,?,?,?)"
    );
    for (const tid of tagIds) { maxId++; ins.run(maxId, cpeId, tid, ts, today); }
  });
  tx();
}

// Tags of a CWE (CWETAG table in XORCISM: TagID only → label resolved via the
// XORCISM.TAG referential, same database). No TagGUID column (like CPETAG).
export function getCweTags(cweId: number): string[] {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CWETAG'").get()) return [];
  const ids = (xo
    .prepare("SELECT TagID FROM CWETAG WHERE CWEID = ? AND TagID IS NOT NULL ORDER BY CWETagID")
    .all(cweId) as { TagID: number }[]).map((r) => r.TagID);
  if (!ids.length) return [];
  const ph = ids.map(() => "?").join(",");
  const rows = xo.prepare(`SELECT TagID, TagValue FROM TAG WHERE TagID IN (${ph})`).all(...ids) as
    { TagID: number; TagValue: string }[];
  const map = new Map(rows.map((r) => [r.TagID, r.TagValue]));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const i of ids) { const v = map.get(i); if (v && !seen.has(v)) { seen.add(v); out.push(v); } }
  return out;
}
// Replaces the tags of a CWE (shared TAG referential via getOrCreateTag).
export function setCweTags(cweId: number, tags: string[]): void {
  const clean = cleanTagList(tags);
  const tagIds = clean.map((t) => getOrCreateTag(t)).filter((n) => n > 0);
  const xo = getDb("XORCISM");
  xo.exec(`CREATE TABLE IF NOT EXISTS CWETAG (
    CWETagID INTEGER PRIMARY KEY, CWEID INTEGER, TagID INTEGER,
    CreatedDate TEXT, ValidFromDate TEXT, ValidUntilDate TEXT, VocabularyID INTEGER)`);
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM CWETAG WHERE CWEID = ?").run(cweId);
    let maxId = (xo.prepare("SELECT COALESCE(MAX(CWETagID),0) AS m FROM CWETAG").get() as { m: number }).m;
    const ins = xo.prepare(
      "INSERT INTO CWETAG (CWETagID, CWEID, TagID, CreatedDate, ValidFromDate) VALUES (?,?,?,?,?)"
    );
    for (const tid of tagIds) { maxId++; ins.run(maxId, cweId, tid, ts, today); }
  });
  tx();
}

// Basic email-address shape used both by the ASSET form (client) and the
// server-side harvester below.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Resolves the ORGANISATION the current user belongs to. The XID identity model
 * has no direct OrganisationID, so we resolve in order of decreasing reliability:
 *   1. explicit override — XUSERPREF key "OrganisationID";
 *   2. PERSON linked to the user's email → PERSONFORORGANISATION;
 *   3. the user's tenant name matching an ORGANISATION name / known-as;
 *   4. fallback — the lowest OrganisationID (so the link is never null when at
 *      least one organisation exists).
 * Returns null only when no ORGANISATION exists at all.
 */
export function resolveUserOrganisationId(
  user: { UserID: number; Email?: string; TenantID?: number } | undefined
): number | null {
  if (!user) return null;
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ORGANISATION'").get()) return null;
  // 1. explicit override via user preference
  try {
    const xid = getDb("XID");
    const pref = xid
      .prepare("SELECT PrefValue FROM XUSERPREF WHERE UserID = ? AND PrefKey = 'OrganisationID'")
      .get(user.UserID) as { PrefValue?: string } | undefined;
    const n = pref ? Number(pref.PrefValue) : NaN;
    if (Number.isFinite(n) && n > 0 && xo.prepare("SELECT 1 FROM ORGANISATION WHERE OrganisationID = ?").get(n))
      return n;
  } catch { /* XUSERPREF may be absent */ }
  // 2. PERSON via email → PERSONFORORGANISATION
  const email = (user.Email || "").trim().toLowerCase();
  if (email) {
    try {
      const persons = xo
        .prepare(
          "SELECT PersonID FROM PERSON WHERE LOWER(email) = ? " +
          "UNION SELECT PersonID FROM EMAILFORPERSON WHERE LOWER(emailaddress) = ?"
        )
        .all(email, email) as { PersonID: number }[];
      for (const p of persons) {
        const link = xo
          .prepare(
            "SELECT OrganisationID FROM PERSONFORORGANISATION WHERE PersonID = ? AND OrganisationID IS NOT NULL " +
            "ORDER BY PersonOrganisationID DESC LIMIT 1"
          )
          .get(p.PersonID) as { OrganisationID: number } | undefined;
        if (link && link.OrganisationID) return link.OrganisationID;
      }
    } catch { /* schema variations */ }
  }
  // 3. tenant name ↔ organisation name
  try {
    if (user.TenantID) {
      const ten = getDb("XID")
        .prepare("SELECT TenantName FROM XTENANT WHERE TenantID = ?")
        .get(user.TenantID) as { TenantName?: string } | undefined;
      const tn = (ten?.TenantName || "").trim().toLowerCase();
      if (tn) {
        const org = xo
          .prepare("SELECT OrganisationID FROM ORGANISATION WHERE LOWER(OrganisationName) = ? OR LOWER(OrganisationKnownAs) = ?")
          .get(tn, tn) as { OrganisationID: number } | undefined;
        if (org) return org.OrganisationID;
      }
    }
  } catch { /* ignore */ }
  // 4. fallback: lowest organisation id
  const first = xo.prepare("SELECT MIN(OrganisationID) AS m FROM ORGANISATION").get() as { m: number | null };
  return first && first.m != null ? first.m : null;
}

export interface EmailHarvestResult {
  email: string;
  organisationId: number | null;
  emailInserted: boolean;
  addressInserted: boolean;
  orgLinkInserted: boolean;
}

/**
 * Captures an email address into the directory tables, idempotently:
 *   - EMAIL               : one row per address (EmailID = MAX+1);
 *   - EMAILADDRESS        : one row per address (+GUID, links to EmailID);
 *   - EMAILFORORGANISATION: one row per (address, organisation) pair.
 * A matching record is never duplicated. Returns null if `raw` is not an email.
 */
export function harvestEmailAddress(raw: string, organisationId: number | null): EmailHarvestResult | null {
  const email = String(raw || "").trim();
  if (!EMAIL_RE.test(email)) return null;
  const xo = getDb("XORCISM");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const lower = email.toLowerCase();
  const out: EmailHarvestResult = { email, organisationId, emailInserted: false, addressInserted: false, orgLinkInserted: false };
  const tx = xo.transaction(() => {
    // EMAIL (one row per address)
    let emailId = (xo
      .prepare("SELECT EmailID FROM EMAIL WHERE LOWER(emailaddress) = ? ORDER BY EmailID LIMIT 1")
      .get(lower) as { EmailID: number } | undefined)?.EmailID;
    if (!emailId) {
      emailId = (xo.prepare("SELECT COALESCE(MAX(EmailID),0) AS m FROM EMAIL").get() as { m: number }).m + 1;
      xo.prepare("INSERT INTO EMAIL (EmailID, emailaddress, isEncrypted) VALUES (?,?,0)").run(emailId, email);
      out.emailInserted = true;
    }
    // EMAILADDRESS (one row per address)
    if (!xo.prepare("SELECT 1 FROM EMAILADDRESS WHERE LOWER(emailaddress) = ? LIMIT 1").get(lower)) {
      const maxA = (xo.prepare("SELECT COALESCE(MAX(EmailAddressID),0) AS m FROM EMAILADDRESS").get() as { m: number }).m;
      xo.prepare(
        "INSERT INTO EMAILADDRESS (EmailAddressID, EmailAddressGUID, EmailID, emailaddress, CreatedDate, ValidFromDate, isEncrypted) VALUES (?,?,?,?,?,?,0)"
      ).run(maxA + 1, randomUUID(), emailId, email, ts, today);
      out.addressInserted = true;
    }
    // EMAILFORORGANISATION (one row per address + organisation)
    if (organisationId != null) {
      if (!xo.prepare("SELECT 1 FROM EMAILFORORGANISATION WHERE LOWER(emailaddress) = ? AND OrganisationID = ? LIMIT 1").get(lower, organisationId)) {
        xo.prepare(
          "INSERT INTO EMAILFORORGANISATION (emailaddress, OrganisationID, CreatedDate, ValidFromDate) VALUES (?,?,?,?)"
        ).run(email, organisationId, ts, today);
        out.orgLinkInserted = true;
      }
    }
  });
  tx();
  return out;
}

// ── First-run setup wizard ──────────────────────────────────────────────────
// True on a fresh install: no ORGANISATION exists yet. Used (together with the
// Admin role, checked in the route) to offer the first-run wizard.
export function setupFirstRunNeeded(): boolean {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ORGANISATION'").get())
    return false;
  const n = (xo.prepare("SELECT COUNT(*) AS n FROM ORGANISATION").get() as { n: number }).n;
  return n === 0;
}

// Creates an ASSET (idempotent by name within the tenant) and links it to the
// organisation via ASSETFORORGANISATION (idempotent by asset + organisation).
function ensureAssetLinkedToOrg(
  xo: Database.Database, name: string, description: string,
  organisationId: number, orgGuid: string | null, tenantId: number | null,
  ts: string, today: string
): { assetId: number; created: boolean } {
  const existing = xo
    .prepare(`SELECT AssetID, AssetGUID FROM "ASSET" WHERE AssetName = ? AND (TenantID IS ? OR ? IS NULL) ORDER BY AssetID LIMIT 1`)
    .get(name, tenantId, tenantId) as { AssetID: number; AssetGUID: string } | undefined;
  let assetId: number;
  let assetGuid: string;
  let created = false;
  if (existing) {
    assetId = existing.AssetID;
    assetGuid = existing.AssetGUID || randomUUID();
  } else {
    assetId = allocId(xo, "ASSET", "AssetID");
    assetGuid = randomUUID();
    xo.prepare(
      `INSERT INTO "ASSET" (AssetID, AssetGUID, AssetName, AssetDescription, Enabled, CreatedDate, ValidFromDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?)`
    ).run(assetId, assetGuid, name, description, 1, ts, today, tenantId);
    created = true;
  }
  if (!xo.prepare("SELECT 1 FROM ASSETFORORGANISATION WHERE AssetID = ? AND OrganisationID = ? LIMIT 1").get(assetId, organisationId)) {
    const linkId = allocId(xo, "ASSETFORORGANISATION", "AssetForOrganisationID");
    xo.prepare(
      `INSERT INTO ASSETFORORGANISATION
         (AssetForOrganisationID, OrganisationAssetGUID, OrganisationID, OrganisationGUID, AssetID, AssetGUID, CreatedDate, ValidFromDate)
       VALUES (?,?,?,?,?,?,?,?)`
    ).run(linkId, randomUUID(), organisationId, orgGuid, assetId, assetGuid, ts, today);
  }
  return { assetId, created };
}

// Creates an APPLICATION (idempotent by name — APPLICATION has no TenantID) and
// links it to the organisation via APPLICATIONFORORGANISATION.
function ensureApplicationLinkedToOrg(
  xo: Database.Database, name: string, description: string,
  organisationId: number, orgGuid: string | null, ts: string, today: string
): { applicationId: number; created: boolean } {
  const existing = xo
    .prepare(`SELECT ApplicationID, ApplicationGUID FROM "APPLICATION" WHERE ApplicationName = ? ORDER BY ApplicationID LIMIT 1`)
    .get(name) as { ApplicationID: number; ApplicationGUID: string } | undefined;
  let applicationId: number;
  let appGuid: string;
  let created = false;
  if (existing) {
    applicationId = existing.ApplicationID;
    appGuid = existing.ApplicationGUID || randomUUID();
  } else {
    applicationId = allocId(xo, "APPLICATION", "ApplicationID");
    appGuid = randomUUID();
    xo.prepare(
      `INSERT INTO "APPLICATION" (ApplicationID, ApplicationGUID, ApplicationName, ApplicationDescription, CreatedDate, ValidFromDate)
       VALUES (?,?,?,?,?,?)`
    ).run(applicationId, appGuid, name, description, ts, today);
    created = true;
  }
  if (!xo.prepare("SELECT 1 FROM APPLICATIONFORORGANISATION WHERE ApplicationID = ? AND OrganisationID = ? LIMIT 1").get(applicationId, organisationId)) {
    const linkId = allocId(xo, "APPLICATIONFORORGANISATION", "OrganisationApplicationID");
    xo.prepare(
      `INSERT INTO APPLICATIONFORORGANISATION
         (OrganisationApplicationID, OrganisationApplicationGUID, OrganisationID, OrganisationGUID, ApplicationID, ApplicationGUID, CreatedDate, ValidFromDate)
       VALUES (?,?,?,?,?,?,?,?)`
    ).run(linkId, randomUUID(), organisationId, orgGuid, applicationId, appGuid, ts, today);
  }
  return { applicationId, created };
}

export interface AdminAssetResult {
  adminAssetId: number;   // "XORCISM Admin account" ASSET
  xorcismAssetId: number; // "XORCISM" ASSET
  applicationId: number;  // "XORCISM" APPLICATION
  created: { adminAsset: boolean; xorcismAsset: boolean; application: boolean };
}

/**
 * First-run wizard step 2: for the just-created ORGANISATION, creates (all
 * idempotent, in one transaction, each linked to the organisation):
 *   - the "XORCISM Admin account" ASSET  + ASSETFORORGANISATION
 *   - the "XORCISM" ASSET                + ASSETFORORGANISATION
 *   - the "XORCISM" APPLICATION          + APPLICATIONFORORGANISATION
 */
export function setupCreateAdminAsset(organisationId: number, tenantId: number | null): AdminAssetResult {
  const xo = getDb("XORCISM");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const out: AdminAssetResult = {
    adminAssetId: 0, xorcismAssetId: 0, applicationId: 0,
    created: { adminAsset: false, xorcismAsset: false, application: false },
  };
  const tx = xo.transaction(() => {
    const orgGuid = (xo.prepare("SELECT OrganisationGUID FROM ORGANISATION WHERE OrganisationID = ?")
      .get(organisationId) as { OrganisationGUID?: string } | undefined)?.OrganisationGUID ?? null;
    const admin = ensureAssetLinkedToOrg(xo, "XORCISM Admin account",
      "Initial administrator account asset, created by the XORCISM first-run setup wizard.",
      organisationId, orgGuid, tenantId, ts, today);
    out.adminAssetId = admin.assetId;
    out.created.adminAsset = admin.created;
    const xasset = ensureAssetLinkedToOrg(xo, "XORCISM",
      "The XORCISM platform itself, registered as an asset by the first-run setup wizard.",
      organisationId, orgGuid, tenantId, ts, today);
    out.xorcismAssetId = xasset.assetId;
    out.created.xorcismAsset = xasset.created;
    const app = ensureApplicationLinkedToOrg(xo, "XORCISM",
      "The XORCISM platform application, registered by the first-run setup wizard.",
      organisationId, orgGuid, ts, today);
    out.applicationId = app.applicationId;
    out.created.application = app.created;
  });
  tx();
  return out;
}

// ── ASSET ↔ ORGANISATION (ASSETFORORGANISATION) and ASSET ↔ PERSON (PERSONFORASSET) ──
// Readable person name (FullName, else First+Last, else "Person #id"), `alias`
// being the PERSON table alias used in the query ("" for none).
function personNameExpr(alias: string): string {
  const a = alias ? alias + "." : "";
  return `COALESCE(NULLIF(TRIM(${a}FullName),''), ` +
    `NULLIF(TRIM(COALESCE(${a}FirstName,'')||' '||COALESCE(${a}LastName,'')),''), 'Person #'||${a}PersonID)`;
}

export function searchOrganisations(q: string, limit = 30): { OrganisationID: number; OrganisationName: string }[] {
  const xo = getDb("XORCISM");
  const like = `%${q.trim()}%`;
  return xo.prepare(
    `SELECT OrganisationID, COALESCE(OrganisationName,'Organisation #'||OrganisationID) AS OrganisationName
     FROM ORGANISATION
     WHERE OrganisationName LIKE ? OR OrganisationKnownAs LIKE ? OR CAST(OrganisationID AS TEXT)=?
     ORDER BY OrganisationName LIMIT ?`
  ).all(like, like, q.trim(), limit) as { OrganisationID: number; OrganisationName: string }[];
}

export function searchPersons(q: string, limit = 30): { PersonID: number; PersonName: string }[] {
  const xo = getDb("XORCISM");
  const like = `%${q.trim()}%`;
  return xo.prepare(
    `SELECT PersonID, ${personNameExpr("")} AS PersonName FROM PERSON
     WHERE FullName LIKE ? OR FirstName LIKE ? OR LastName LIKE ? OR email LIKE ? OR CAST(PersonID AS TEXT)=?
     ORDER BY PersonName LIMIT ?`
  ).all(like, like, like, like, q.trim(), limit) as { PersonID: number; PersonName: string }[];
}

export function getDefaultOrganisationForUser(
  user: { UserID: number; Email?: string; TenantID?: number } | undefined
): { OrganisationID: number; OrganisationName: string } | null {
  const id = resolveUserOrganisationId(user);
  if (id == null) return null;
  const r = getDb("XORCISM")
    .prepare("SELECT OrganisationID, COALESCE(OrganisationName,'Organisation #'||OrganisationID) AS OrganisationName FROM ORGANISATION WHERE OrganisationID = ?")
    .get(id) as { OrganisationID: number; OrganisationName: string } | undefined;
  return r ?? null;
}

export function getAssetOrganisations(assetId: number): { OrganisationID: number; OrganisationName: string }[] {
  return getDb("XORCISM").prepare(
    `SELECT afo.OrganisationID AS OrganisationID,
            COALESCE(o.OrganisationName,'Organisation #'||afo.OrganisationID) AS OrganisationName
     FROM ASSETFORORGANISATION afo
     LEFT JOIN ORGANISATION o ON o.OrganisationID = afo.OrganisationID
     WHERE afo.AssetID = ? AND afo.OrganisationID IS NOT NULL
     ORDER BY OrganisationName`
  ).all(assetId) as { OrganisationID: number; OrganisationName: string }[];
}

/** Replaces an asset's ORGANISATION links (DELETE then INSERT into ASSETFORORGANISATION). */
export function setAssetOrganisations(assetId: number, organisationIds: number[]): void {
  const xo = getDb("XORCISM");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const assetGuid = (xo.prepare(`SELECT AssetGUID FROM "ASSET" WHERE AssetID = ?`).get(assetId) as { AssetGUID?: string } | undefined)?.AssetGUID ?? null;
  const ids = Array.from(new Set(organisationIds.filter((n) => Number.isFinite(n) && n > 0)));
  const orgGuidStmt = xo.prepare("SELECT OrganisationGUID FROM ORGANISATION WHERE OrganisationID = ?");
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM ASSETFORORGANISATION WHERE AssetID = ?").run(assetId);
    let maxId = (xo.prepare("SELECT COALESCE(MAX(AssetForOrganisationID),0) AS m FROM ASSETFORORGANISATION").get() as { m: number }).m;
    const ins = xo.prepare(
      `INSERT INTO ASSETFORORGANISATION
         (AssetForOrganisationID, OrganisationAssetGUID, OrganisationID, OrganisationGUID, AssetID, AssetGUID, CreatedDate, ValidFromDate)
       VALUES (?,?,?,?,?,?,?,?)`
    );
    for (const oid of ids) {
      const orgGuid = (orgGuidStmt.get(oid) as { OrganisationGUID?: string } | undefined)?.OrganisationGUID ?? null;
      maxId++;
      ins.run(maxId, randomUUID(), oid, orgGuid, assetId, assetGuid, ts, today);
    }
  });
  tx();
}

export interface AssetPersonRow { PersonID: number; PersonName: string; relationshiptype: string; }

export function getAssetPersons(assetId: number): AssetPersonRow[] {
  return getDb("XORCISM").prepare(
    `SELECT pfa.PersonID AS PersonID,
            COALESCE(${personNameExpr("p")},'Person #'||pfa.PersonID) AS PersonName,
            COALESCE(pfa.relationshiptype,'') AS relationshiptype
     FROM PERSONFORASSET pfa
     LEFT JOIN PERSON p ON p.PersonID = pfa.PersonID
     WHERE pfa.AssetID = ? AND pfa.PersonID IS NOT NULL
     ORDER BY PersonName`
  ).all(assetId) as AssetPersonRow[];
}

/** Replaces an asset's PERSON links (DELETE then INSERT into PERSONFORASSET). One role per person. */
export function setAssetPersons(assetId: number, links: { personId: number; relationshiptype: string }[]): void {
  const xo = getDb("XORCISM");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const byPerson = new Map<number, string>();
  for (const l of links) {
    const pid = Number(l.personId);
    if (Number.isFinite(pid) && pid > 0) byPerson.set(pid, String(l.relationshiptype || "").slice(0, 100));
  }
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM PERSONFORASSET WHERE AssetID = ?").run(assetId);
    const ins = xo.prepare(
      "INSERT INTO PERSONFORASSET (PersonID, AssetID, relationshiptype, CreatedDate, ValidFromDate) VALUES (?,?,?,?,?)"
    );
    for (const [pid, role] of byPerson) ins.run(pid, assetId, role || null, ts, today);
  });
  tx();
}

// Tag cloud (dashboard): frequency of ACTIVE ASSETTAG.Tag — ValidUntil
// empty/beyond today AND ValidFrom empty/<= today. Scoped to the tenant (ASSET
// join) if the caller is isolated; all tenants if super-admin (tenant null).
export function getAssetTagCloud(tenant: number | null): { tag: string; count: number }[] {
  const db = getDb("XORCISM");
  const now = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const where = [
    "t.Tag IS NOT NULL", "t.Tag <> ''",
    "(t.ValidUntil IS NULL OR t.ValidUntil = '' OR t.ValidUntil > @now)",
    "(t.ValidFrom IS NULL OR t.ValidFrom = '' OR t.ValidFrom <= @now)",
  ];
  const params: Record<string, unknown> = { now };
  let join = "";
  if (tenant != null) {
    join = "JOIN ASSET a ON a.AssetID = t.AssetID";
    where.push("a.TenantID = @tenant");
    params.tenant = tenant;
  }
  return db
    .prepare(
      `SELECT t.Tag AS tag, COUNT(*) AS count FROM ASSETTAG t ${join}
       WHERE ${where.join(" AND ")}
       GROUP BY t.Tag ORDER BY count DESC, t.Tag COLLATE NOCASE LIMIT 200`
    )
    .all(params) as { tag: string; count: number }[];
}

export function getAssetVulnerabilities(assetId: number): VulnRow[] {
  const xo = getDb("XORCISM");
  const avCols = new Set((xo.prepare(`PRAGMA table_info("ASSETVULNERABILITY")`).all() as { name: string }[]).map((c) => c.name));
  const hasPatch = avCols.has("PatchStatus");
  const hasFp = avCols.has("FalsePositive");
  const avRows = xo.prepare(
    `SELECT AssetVulnerabilityID, VulnerabilityID${hasPatch ? ", PatchStatus" : ""}${hasFp ? ", FalsePositive" : ""}
     FROM ASSETVULNERABILITY WHERE AssetID = ? AND VulnerabilityID IS NOT NULL
     ORDER BY AssetVulnerabilityID`
  ).all(assetId) as { AssetVulnerabilityID: number; VulnerabilityID: number; PatchStatus?: string | null; FalsePositive?: number }[];
  if (!avRows.length) return [];
  // First junction row wins per vulnerability (a remediation plan attaches to one instance).
  const byVuln = new Map<number, { avId: number; patch: string | null; fp: number }>();
  for (const r of avRows) if (!byVuln.has(r.VulnerabilityID)) byVuln.set(r.VulnerabilityID, { avId: r.AssetVulnerabilityID, patch: r.PatchStatus ?? null, fp: Number(r.FalsePositive) === 1 ? 1 : 0 });

  // Count existing remediation plans per junction instance (so the UI can show "planned").
  const remCount = new Map<number, number>();
  try {
    const rc = new Set((xo.prepare(`PRAGMA table_info("ASSETVULNERABILITYREMEDIATION")`).all() as { name: string }[]).map((c) => c.name));
    if (rc.has("AssetVulnerabilityID")) {
      const avIds = [...byVuln.values()].map((v) => v.avId);
      const ph2 = avIds.map(() => "?").join(",");
      for (const r of xo.prepare(`SELECT AssetVulnerabilityID, COUNT(*) n FROM ASSETVULNERABILITYREMEDIATION WHERE AssetVulnerabilityID IN (${ph2}) GROUP BY AssetVulnerabilityID`).all(...avIds) as { AssetVulnerabilityID: number; n: number }[]) {
        remCount.set(r.AssetVulnerabilityID, r.n);
      }
    }
  } catch { /* remediation table optional */ }

  const vids = [...byVuln.keys()];
  const ph = vids.map(() => "?").join(",");
  const rows = getDb("XVULNERABILITY")
    .prepare(
      `SELECT VulnerabilityID, VULReferential, VULReferentialID, VULGUID, VULDescription
       FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})
       ORDER BY VULReferentialID`
    )
    .all(...vids) as VulnRow[];
  return rows.map((v) => {
    const m = byVuln.get(v.VulnerabilityID);
    return { ...v, AssetVulnerabilityID: m?.avId, PatchStatus: m?.patch ?? null, RemediationCount: m ? (remCount.get(m.avId) || 0) : 0, FalsePositive: m?.fp ?? 0 };
  });
}

/** Search vulnerabilities (by VULReferential / CVE identifier / GUID) — limited. */
export function searchVulnerabilities(q: string, limit = 50): VulnRow[] {
  const term = `%${q}%`;
  return getDb("XVULNERABILITY")
    .prepare(
      `SELECT VulnerabilityID, VULReferential, VULReferentialID, VULGUID, VULDescription
       FROM VULNERABILITY
       WHERE VULReferential LIKE ? OR VULReferentialID LIKE ? OR VULGUID LIKE ?
       ORDER BY VULReferentialID LIMIT ?`
    )
    .all(term, term, term, Math.min(limit, 200)) as VulnRow[];
}

/**
 * Replaces the whole set of vulnerabilities linked to an asset (ASSETVULNERABILITY).
 * Multi-tenant: populates the TenantID of the junction rows (inherited from the parent
 * asset, passed by the route) when the column exists.
 */
export function setAssetVulnerabilities(
  assetId: number,
  vulnIds: number[],
  tenant: number | null = null
): void {
  const db = getDb("XORCISM");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const hasTenant = tableHasTenantCol("XORCISM", "ASSETVULNERABILITY");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ASSETVULNERABILITY WHERE AssetID = ?").run(assetId);
    let maxId = (
      db.prepare("SELECT COALESCE(MAX(AssetVulnerabilityID), 0) AS m FROM ASSETVULNERABILITY").get() as {
        m: number;
      }
    ).m;
    const ins = hasTenant
      ? db.prepare(
          `INSERT INTO ASSETVULNERABILITY (AssetVulnerabilityID, AssetID, VulnerabilityID, CreatedDate, "${TENANT_COL}") VALUES (?,?,?,?,?)`
        )
      : db.prepare(
          "INSERT INTO ASSETVULNERABILITY (AssetVulnerabilityID, AssetID, VulnerabilityID, CreatedDate) VALUES (?,?,?,?)"
        );
    for (const vid of vulnIds) {
      if (vid == null) continue;
      maxId++;
      if (hasTenant) ins.run(maxId, assetId, vid, ts, tenant);
      else ins.run(maxId, assetId, vid, ts);
    }
  });
  tx();
}

/**
 * Replaces the whole set of CPEs linked to an asset (CPEFORASSET, XORCISM database).
 * Multi-tenant: populates the TenantID of the junction rows (inherited from the parent
 * asset, passed by the route) when the column exists.
 */
export function setAssetCpes(
  assetId: number,
  cpeIds: number[],
  tenant: number | null = null
): void {
  const db = getDb("XORCISM");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const hasTenant = tableHasTenantCol("XORCISM", "CPEFORASSET");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM CPEFORASSET WHERE AssetID = ?").run(assetId);
    let maxId = (
      db.prepare("SELECT COALESCE(MAX(AssetCPEID), 0) AS m FROM CPEFORASSET").get() as {
        m: number;
      }
    ).m;
    const ins = hasTenant
      ? db.prepare(
          `INSERT INTO CPEFORASSET (AssetCPEID, AssetID, CPEID, CreatedDate, isEncrypted, "${TENANT_COL}")
           VALUES (?,?,?,?,?,?)`
        )
      : db.prepare(
          `INSERT INTO CPEFORASSET (AssetCPEID, AssetID, CPEID, CreatedDate, isEncrypted)
           VALUES (?,?,?,?,?)`
        );
    for (const cid of cpeIds) {
      if (cid == null) continue;
      maxId++;
      if (hasTenant) ins.run(maxId, assetId, cid, ts, 0, tenant);
      else ins.run(maxId, assetId, cid, ts, 0);
    }
  });
  tx();
}

// ── INCIDENT ↔ ASSET links (INCIDENTFORASSET junction table, XINCIDENT database) ──

export function getIncidentAssets(incidentId: number): number[] {
  const db = getDb("XINCIDENT");
  return (
    db
      .prepare('SELECT AssetID FROM INCIDENTFORASSET WHERE IncidentID = ? AND AssetID IS NOT NULL')
      .all(incidentId) as { AssetID: number }[]
  ).map((r) => r.AssetID);
}

// ── ALERT ↔ ASSET impacted-assets links (ALERTFORASSET, Defender "Select entities") ──
export function getAlertAssets(alertId: number): number[] {
  const db = getDb("XINCIDENT");
  return (
    db.prepare('SELECT AssetID FROM ALERTFORASSET WHERE AlertID = ? AND AssetID IS NOT NULL')
      .all(alertId) as { AssetID: number }[]
  ).map((r) => r.AssetID);
}

/** Replaces the whole set of impacted assets of an alert (DELETE then INSERT); stamps TenantID. */
export function setAlertAssets(alertId: number, assetIds: number[], tenant: number | null = null): void {
  const db = getDb("XINCIDENT");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ALERTFORASSET WHERE AlertID = ?").run(alertId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(AssetAlertID), 0) AS m FROM ALERTFORASSET").get() as { m: number }).m;
    const ins = db.prepare(
      `INSERT OR IGNORE INTO ALERTFORASSET (AssetAlertID, AlertID, AssetID, CreatedDate, "${TENANT_COL}") VALUES (?,?,?,?,?)`
    );
    for (const aid of assetIds) {
      if (aid == null) continue;
      maxId++;
      ins.run(maxId, alertId, aid, ts, tenant);
    }
  });
  tx();
}

// ── THREAT ↔ ASSET link (XTHREAT.THREATFORASSET) ────────────────────────────
export function getThreatAssets(threatId: number): number[] {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='THREATFORASSET'").get()) return [];
  return (
    db.prepare("SELECT AssetID FROM THREATFORASSET WHERE ThreatID = ? AND AssetID IS NOT NULL").all(threatId) as { AssetID: number }[]
  ).map((r) => r.AssetID);
}

/** Replaces the whole set of assets linked to a threat (DELETE then INSERT); stamps TenantID. */
export function setThreatAssets(threatId: number, assetIds: number[], tenant: number | null = null): void {
  const db = getDb("XTHREAT");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATFORASSET WHERE ThreatID = ?").run(threatId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(AssetThreatID),0) AS m FROM THREATFORASSET").get() as { m: number }).m;
    const ins = db.prepare(
      "INSERT INTO THREATFORASSET (AssetThreatID, ThreatID, AssetID, CreatedDate, ValidFrom, TenantID) VALUES (?,?,?,?,?,?)"
    );
    for (const aid of Array.from(new Set(assetIds))) {
      if (aid == null) continue;
      maxId++;
      ins.run(maxId, threatId, aid, ts, today, tenant);
    }
  });
  tx();
}

/** ASSET list with their ASSETTAG tags (comma-joined), for the tag-filterable picker. */
export function getAssetsWithTags(tenant: number | null = null): { AssetID: number; AssetName: string; Tags: string }[] {
  return getDb("XORCISM").prepare(
    `SELECT a.AssetID AS AssetID, COALESCE(a.AssetName,'#'||a.AssetID) AS AssetName,
            COALESCE((SELECT GROUP_CONCAT(DISTINCT t.Tag) FROM ASSETTAG t WHERE t.AssetID = a.AssetID AND t.Tag IS NOT NULL AND TRIM(t.Tag) <> ''),'') AS Tags
     FROM ASSET a
     WHERE (? IS NULL OR a.TenantID = ? OR a.TenantID IS NULL)
     ORDER BY a.AssetName`
  ).all(tenant, tenant) as { AssetID: number; AssetName: string; Tags: string }[];
}

/** Bulk-creates THREATFORASSET rows: one per asset for the given threat (skips existing asset+threat pairs). */
export function bulkCreateThreatForAsset(
  threatId: number, assetIds: number[],
  opts: { relationship?: string; validFrom?: string; validUntil?: string; personId?: number | null },
  tenant: number | null = null
): { created: number; skipped: number } {
  const xt = getDb("XTHREAT");
  const ts = nowTs();
  const today = new Date().toISOString().slice(0, 10);
  const ids = Array.from(new Set(assetIds.filter((n) => Number.isFinite(n) && n > 0)));
  let created = 0, skipped = 0;
  const tx = xt.transaction(() => {
    let maxId = (xt.prepare("SELECT COALESCE(MAX(AssetThreatID),0) AS m FROM THREATFORASSET").get() as { m: number }).m;
    const dup = xt.prepare("SELECT 1 FROM THREATFORASSET WHERE AssetID = ? AND ThreatID = ? LIMIT 1");
    const ins = xt.prepare(
      `INSERT INTO THREATFORASSET (AssetThreatID, AssetID, ThreatID, CreatedDate, PersonID, Relationship, ValidFrom, ValidUntil, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?)`
    );
    for (const aid of ids) {
      if (dup.get(aid, threatId)) { skipped++; continue; }
      maxId++;
      ins.run(maxId, aid, threatId, ts, opts.personId ?? null, opts.relationship || null,
        opts.validFrom || today, opts.validUntil || null, tenant);
      created++;
    }
  });
  tx();
  return { created, skipped };
}

/**
 * Replaces the whole set of assets linked to an incident (DELETE then INSERT).
 * Multi-tenant: populates the TenantID of the junction rows (inherited from
 * the parent incident, passed by the route) when the column exists.
 */
// ── INCIDENT ↔ THREATACTOR link (XTHREAT.THREATACTORFORINCIDENT table) ──────────
// An incident (XINCIDENT) references a threat actor (XTHREAT) by its name →
// the corresponding ThreatActorID is stored in the link table (XTHREAT).

/** Name of the threat actor currently linked to an incident ("" if none). */
export function getIncidentThreatActor(incidentId: number): string {
  const db = getDb("XTHREAT");
  const r = db
    .prepare(
      `SELECT a.ThreatActorName AS name
         FROM THREATACTORFORINCIDENT l
         JOIN THREATACTOR a ON a.ThreatActorID = l.ThreatActorID
        WHERE l.IncidentID = ? AND l.ThreatActorID IS NOT NULL
        ORDER BY l.IncidentThreatActorID
        LIMIT 1`
    )
    .get(incidentId) as { name?: string } | undefined;
  return r && r.name ? String(r.name) : "";
}

/**
 * Replaces the INCIDENT ↔ THREATACTOR link: deletes all the
 * THREATACTORFORINCIDENT rows for this incident, then (if the name matches an
 * existing actor) recreates one row with the ThreatActorID resolved from the name.
 * A free-text name that is not recognized creates no row.
 */
export function setIncidentThreatActor(incidentId: number, actorName: string): void {
  const db = getDb("XTHREAT");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATACTORFORINCIDENT WHERE IncidentID = ?").run(incidentId);
    const name = (actorName || "").trim();
    if (!name) return;
    const actor = db
      .prepare(
        "SELECT ThreatActorID AS id, ThreatActorGUID AS guid FROM THREATACTOR WHERE ThreatActorName = ? LIMIT 1"
      )
      .get(name) as { id?: number; guid?: string } | undefined;
    if (!actor || actor.id == null) return; // unknown name: no link
    const maxId = (
      db
        .prepare("SELECT COALESCE(MAX(IncidentThreatActorID),0) AS m FROM THREATACTORFORINCIDENT")
        .get() as { m: number }
    ).m;
    db.prepare(
      `INSERT INTO THREATACTORFORINCIDENT
         (IncidentThreatActorID, IncidentID, ThreatActorID, ThreatActorGUID, CreatedDate, isEncrypted)
       VALUES (?,?,?,?,?,0)`
    ).run(maxId + 1, incidentId, actor.id, actor.guid ?? null, ts);
  });
  tx();
}

// ── AUDIT ↔ ASSET link (XORCISM.ASSETAUDIT table) ──────────────────────────────
// An audit (XCOMPLIANCE) references assets (XORCISM) via ASSETAUDIT (XORCISM).

/** AssetIDs linked to an audit. */
export function getAuditAssets(auditId: number): number[] {
  const db = getDb("XORCISM");
  return (
    db
      .prepare('SELECT AssetID FROM ASSETAUDIT WHERE AuditID = ? AND AssetID IS NOT NULL')
      .all(auditId) as { AssetID: number }[]
  ).map((r) => r.AssetID);
}

/** Findings breakdown for one audit (severity + status + open/overdue) — for the AUDIT form chart. */
export function getAuditFindingStats(auditId: number): { total: number; open: number; overdue: number; bySeverity: Record<string, number>; byStatus: Record<string, number> } {
  const out = { total: 0, open: 0, overdue: 0, bySeverity: {} as Record<string, number>, byStatus: {} as Record<string, number> };
  let rows: Record<string, unknown>[] = [];
  try { rows = getDb("XCOMPLIANCE").prepare("SELECT * FROM AUDITFINDING WHERE AuditID = ?").all(auditId) as Record<string, unknown>[]; }
  catch { return out; }
  const today = new Date().toISOString().slice(0, 10);
  const normSev = (s: string): string => {
    const t = (s || "").toLowerCase();
    if (/crit/.test(t)) return "Critical";
    if (/high|élev|elev/.test(t)) return "High";
    if (/med|moy/.test(t)) return "Medium";
    if (/low|faible|minor/.test(t)) return "Low";
    if (/info/.test(t)) return "Info";
    return s ? s : "Unrated";
  };
  for (const r of rows) {
    out.total++;
    const sev = normSev(String(r.Severity ?? r.FindingCriticity ?? ""));
    out.bySeverity[sev] = (out.bySeverity[sev] || 0) + 1;
    const st = String(r.WorkflowStatus ?? r.FindingStatus ?? "").trim() || "Unspecified";
    out.byStatus[st] = (out.byStatus[st] || 0) + 1;
    const closed = /clos|resolv|done|complet|remediat|accept|false[- ]?pos|n\/?a/i.test(`${r.FindingStatus ?? ""} ${r.WorkflowStatus ?? ""}`);
    if (!closed) { out.open++; const due = r.DueDate ? String(r.DueDate).slice(0, 10) : ""; if (due && due < today) out.overdue++; }
  }
  return out;
}

/** Replaces an audit's ASSET links (DELETE then INSERT the chosen assets). */
export function setAuditAssets(auditId: number, assetIds: number[]): void {
  const db = getDb("XORCISM");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ASSETAUDIT WHERE AuditID = ?").run(auditId);
    let maxId = (
      db.prepare("SELECT COALESCE(MAX(AssetAuditID),0) AS m FROM ASSETAUDIT").get() as { m: number }
    ).m;
    const ins = db.prepare(
      "INSERT INTO ASSETAUDIT (AssetAuditID, AssetID, AuditID, Date) VALUES (?,?,?,?)"
    );
    for (const aid of assetIds) {
      if (aid == null) continue;
      maxId++;
      ins.run(maxId, aid, auditId, ts);
    }
  });
  tx();
}

/** Audits linked to an asset (AuditID + AuditName resolved in XCOMPLIANCE.AUDIT). */
export function getAssetAudits(assetId: number): { AuditID: number; AuditName: string }[] {
  const ids = (
    getDb("XORCISM")
      .prepare("SELECT AuditID FROM ASSETAUDIT WHERE AssetID = ? AND AuditID IS NOT NULL")
      .all(assetId) as { AuditID: number }[]
  ).map((r) => r.AuditID);
  if (!ids.length) return [];
  const ph = ids.map(() => "?").join(",");
  const rows = getDb("XCOMPLIANCE")
    .prepare(`SELECT AuditID, AuditName FROM AUDIT WHERE AuditID IN (${ph})`)
    .all(...ids) as { AuditID: number; AuditName: string }[];
  const byId = new Map(rows.map((r) => [r.AuditID, r.AuditName]));
  return ids.map((id) => ({ AuditID: id, AuditName: byId.get(id) ?? `#${id}` }));
}

/** Replaces an asset's AUDIT links (DELETE then INSERT the chosen audits). */
export function setAssetAudits(assetId: number, auditIds: number[]): void {
  const db = getDb("XORCISM");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM ASSETAUDIT WHERE AssetID = ?").run(assetId);
    let maxId = (
      db.prepare("SELECT COALESCE(MAX(AssetAuditID),0) AS m FROM ASSETAUDIT").get() as { m: number }
    ).m;
    const ins = db.prepare(
      "INSERT INTO ASSETAUDIT (AssetAuditID, AssetID, AuditID, Date) VALUES (?,?,?,?)"
    );
    for (const aid of auditIds) {
      if (aid == null) continue;
      maxId++;
      ins.run(maxId, assetId, aid, ts);
    }
  });
  tx();
}

// ── Asset geolocations (XORCISM.ASSETGEOLOCATION table) ────────────────
export interface AssetGeoRow {
  AssetGeoLocationID: number;
  GeoLocationID: number | null;
  Location: string; // address/coordinates resolved from GEOLOCATION
  CollectionTimestamp: string | null;
  CreatedDate: string | null;
}

/** Geolocations linked to an asset (GeoLocationID resolved into a readable address). */
export function getAssetGeolocations(assetId: number): AssetGeoRow[] {
  const db = getDb("XORCISM");
  const rows = db
    .prepare(
      "SELECT AssetGeoLocationID, GeoLocationID, CollectionTimestamp, CreatedDate " +
        "FROM ASSETGEOLOCATION WHERE AssetID = ? ORDER BY AssetGeoLocationID DESC"
    )
    .all(assetId) as {
    AssetGeoLocationID: number;
    GeoLocationID: number | null;
    CollectionTimestamp: string | null;
    CreatedDate: string | null;
  }[];
  if (!rows.length) return [];

  const ids = [...new Set(rows.map((r) => r.GeoLocationID).filter((v): v is number => v != null))];
  const labelById = new Map<number, string>();
  if (ids.length) {
    const ph = ids.map(() => "?").join(",");
    const geos = db
      .prepare(
        "SELECT GeoLocationID, street_address, city, state, postal_code, country, latitude, longitude " +
          `FROM GEOLOCATION WHERE GeoLocationID IN (${ph})`
      )
      .all(...ids) as Record<string, unknown>[];
    for (const g of geos) {
      const parts = [g.street_address, g.city, g.state, g.postal_code, g.country]
        .map((v) => (v == null ? "" : String(v).trim()))
        .filter(Boolean);
      let label = parts.join(", ");
      if (g.latitude != null && g.latitude !== "" && g.longitude != null && g.longitude !== "") {
        label += (label ? " " : "") + `(${g.latitude}, ${g.longitude})`;
      }
      labelById.set(Number(g.GeoLocationID), label || `#${g.GeoLocationID}`);
    }
  }
  return rows.map((r) => ({
    AssetGeoLocationID: r.AssetGeoLocationID,
    GeoLocationID: r.GeoLocationID,
    Location: r.GeoLocationID != null ? labelById.get(r.GeoLocationID) ?? `#${r.GeoLocationID}` : "",
    CollectionTimestamp: r.CollectionTimestamp,
    CreatedDate: r.CreatedDate,
  }));
}

export function setIncidentAssets(
  incidentId: number,
  assetIds: number[],
  tenant: number | null = null
): void {
  const db = getDb("XINCIDENT");
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  const hasTenant = tableHasTenantCol("XINCIDENT", "INCIDENTFORASSET");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM INCIDENTFORASSET WHERE IncidentID = ?").run(incidentId);
    let maxId = (
      db.prepare("SELECT COALESCE(MAX(AssetIncidentID), 0) AS m FROM INCIDENTFORASSET").get() as {
        m: number;
      }
    ).m;
    const ins = hasTenant
      ? db.prepare(
          `INSERT INTO INCIDENTFORASSET
             (AssetIncidentID, AssetID, IncidentID, CreatedDate, isEncrypted, VocabularyID, "${TENANT_COL}")
           VALUES (?,?,?,?,?,?,?)`
        )
      : db.prepare(
          `INSERT INTO INCIDENTFORASSET
             (AssetIncidentID, AssetID, IncidentID, CreatedDate, isEncrypted, VocabularyID)
           VALUES (?,?,?,?,?,?)`
        );
    for (const aid of assetIds) {
      if (aid == null) continue;
      maxId++;
      if (hasTenant) ins.run(maxId, aid, incidentId, ts, 0, 1, tenant);
      else ins.run(maxId, aid, incidentId, ts, 0, 1);
    }
  });
  tx();
}

// ── THREATAGENT ↔ CATEGORY (via THREATAGENTCATEGORY, XTHREAT; CATEGORY labels, XORCISM) ──

/**
 * Category options for a threat agent: CategoryName (CATEGORY, XORCISM)
 * of the "allowed" categories (CategoryID present in THREATAGENTCATEGORY, XTHREAT)
 * filtered by the selected vocabulary (CATEGORY.VocabularyID). Cross-database.
 */
export function threatAgentCategoryOptions(vocabId: number): { id: number; label: string }[] {
  const allowed = (
    getDb("XTHREAT")
      .prepare('SELECT DISTINCT CategoryID FROM THREATAGENTCATEGORY WHERE CategoryID IS NOT NULL')
      .all() as { CategoryID: number }[]
  ).map((r) => r.CategoryID);
  if (!allowed.length) return [];
  const ph = allowed.map(() => "?").join(",");
  return getDb("XORCISM")
    .prepare(
      `SELECT CategoryID AS id, CategoryName AS label FROM CATEGORY
       WHERE CategoryID IN (${ph}) AND VocabularyID = ?
       ORDER BY CategoryName COLLATE NOCASE`
    )
    .all(...allowed, vocabId) as { id: number; label: string }[];
}

/** Category linked to a threat agent (0 or 1) — returns the CategoryID or null. */
export function getThreatAgentCategory(threatAgentId: number): number | null {
  const r = getDb("XTHREAT")
    .prepare(
      `SELECT CategoryID FROM THREATAGENTCATEGORY
       WHERE ThreatAgentID = ? AND CategoryID IS NOT NULL
       ORDER BY ThreatAgentCategoryID LIMIT 1`
    )
    .get(threatAgentId) as { CategoryID: number } | undefined;
  return r ? r.CategoryID : null;
}

/**
 * Replaces a threat agent's category link: deletes its links (ThreatAgentID = ?)
 * then inserts the new one if categoryId is provided. Does not touch the master rows
 * (ThreatAgentID NULL) that define the allowed set.
 */
export function setThreatAgentCategory(threatAgentId: number, categoryId: number | null): void {
  const db = getDb("XTHREAT");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATAGENTCATEGORY WHERE ThreatAgentID = ?").run(threatAgentId);
    if (categoryId != null) {
      const maxId = (
        db.prepare("SELECT COALESCE(MAX(ThreatAgentCategoryID), 0) AS m FROM THREATAGENTCATEGORY").get() as {
          m: number;
        }
      ).m;
      db.prepare(
        "INSERT INTO THREATAGENTCATEGORY (ThreatAgentCategoryID, CategoryID, ThreatAgentID) VALUES (?,?,?)"
      ).run(maxId + 1, categoryId, threatAgentId);
    }
  });
  tx();
}

export function updateRow(
  dbName: string,
  table: string,
  rowid: number,
  row: Record<string, unknown>,
  tenantScope?: number | null
): void {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");

  // Validate columns against schema to prevent injection
  const schema = db
    .prepare(`PRAGMA table_info("${safeTbl}")`)
    .all() as { name: string }[];
  const validCols = new Set(schema.map((c) => c.name));

  applyRiskRegisterLevels(db, table, rowid, row); // derived risk levels
  applyEbiosStakeholderLevel(db, table, rowid, row); // EBIOS: threat level + zone

  // Encrypt sensitive fields (vault) before updating.
  vault.encryptRowForWrite(table, row, validCols);

  const scoped = shouldScope(dbName, table, tenantScope);
  // A tenant user cannot reassign the row to another tenant.
  const entries = Object.entries(row).filter(
    ([k]) => validCols.has(k) && !(scoped && k === TENANT_COL)
  );
  if (!entries.length) throw new Error("No valid columns to update");

  const sets = entries.map(([k]) => `"${k}" = ?`).join(", ");
  // Normalizes an empty TenantID ('' / blank) → NULL (never an empty string in the database).
  const values = entries.map(([k, v]) => (k === TENANT_COL ? normTenant(v) : v));

  // Tenant guard: WHERE rowid = ? AND TenantID = ? (another tenant's row
  // is not modified — affected rows = 0).
  const whereTenant = scoped ? ` AND "${TENANT_COL}" = ?` : "";
  const tail = scoped ? [rowid, tenantScope] : [rowid];
  db.prepare(`UPDATE "${safeTbl}" SET ${sets} WHERE rowid = ?${whereTenant}`).run(
    ...values,
    ...tail
  );
}

export function deleteRow(
  dbName: string,
  table: string,
  rowid: number,
  tenantScope?: number | null
): void {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  const scoped = shouldScope(dbName, table, tenantScope);
  const whereTenant = scoped ? ` AND "${TENANT_COL}" = ?` : "";
  const params = scoped ? [rowid, tenantScope] : [rowid];
  db.prepare(`DELETE FROM "${safeTbl}" WHERE rowid = ?${whereTenant}`).run(...params);
}

/**
 * Empties a table ("replace" mode of the import). For a tenant user,
 * deletes only ITS rows (scoped table); super-admin / non-scoped table:
 * full deletion. Returns the number of deleted rows.
 */
export function clearTable(
  dbName: string,
  table: string,
  tenantScope?: number | null
): number {
  const db = getDb(dbName);
  const safeTbl = table.replace(/[^a-zA-Z0-9_]/g, "");
  if (shouldScope(dbName, table, tenantScope)) {
    return db.prepare(`DELETE FROM "${safeTbl}" WHERE "${TENANT_COL}" = ?`).run(tenantScope).changes;
  }
  return db.prepare(`DELETE FROM "${safeTbl}"`).run().changes;
}

// ── Threat models ────────────────────────────────────────────────────────────────
// 4 tables in XORCISM.db (isolated per tenant):
//   THREATMODEL          — the model (scope, methodology, status, risk)
//   THREATMODELASSET     — assets in scope (model ↔ ASSET link)
//   THREATMODELTHREAT    — identified threats (STRIDE, likelihood/impact, status)
//   THREATMODELCONTROL   — mitigations (threat ↔ CONTROL link)

/**
 * Creates the XCOMPLIANCE.db database and its audit tables (AUDIT, AUDITFINDING,
 * AUDITREPORT) if they don't exist. The database is then auto-discovered by
 * listDatabases() and usable via the explorer. Idempotent.
 */
export function ensureComplianceDb(): void {
  const dbPath = path.join(DB_DIR, "XCOMPLIANCE.db");
  const db = new Database(dbPath); // creates the file if it doesn't exist
  try {
    db.pragma("journal_mode = WAL");
    db.exec(`
      CREATE TABLE IF NOT EXISTS AUDIT (
        AuditID INTEGER PRIMARY KEY,
        AuditGUID TEXT, AuditName TEXT, AuditDate TEXT, AuditStatus TEXT, AuditorName TEXT,
        AuditDescription TEXT, AuditCategory TEXT, AuditScope TEXT, AuditType TEXT, AuditClosureDate TEXT,
        TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS AUDITFINDING (
        AuditFindingID INTEGER PRIMARY KEY,
        AuditFindingGUID TEXT, FindingName TEXT, FindingDescription TEXT, FindingDate TEXT,
        FindingStatus TEXT, FindingStakeholder TEXT, FindingCriticity TEXT);
      CREATE TABLE IF NOT EXISTS AUDITREPORT (
        AuditReportID INTEGER PRIMARY KEY,
        AuditReportGUID TEXT, ReportName TEXT, ReportDescription TEXT, ReportDate TEXT,
        ReportAuthor TEXT, ReportClient TEXT, ReportStatus TEXT, PersonID INTEGER);
      CREATE TABLE IF NOT EXISTS EVIDENCE (
        EvidenceID INTEGER PRIMARY KEY,
        EvidenceName TEXT, EvidenceDescription TEXT, EvidenceDate TEXT, CreatedDate TEXT,
        ValidFrom TEXT, ValidUntil TEXT, EvidenceURL TEXT, Validity TEXT, EvidenceFile TEXT);
      CREATE TABLE IF NOT EXISTS AUDITEVIDENCE (
        AuditEvidenceID INTEGER PRIMARY KEY,
        AuditEvidenceGUID TEXT, AuditID INTEGER, EvidenceID INTEGER, CreatedDate TEXT,
        ConfidenceLevel TEXT, Status TEXT);
      CREATE TABLE IF NOT EXISTS DOCUMENT (
        DocumentID INTEGER PRIMARY KEY,
        DocumentGUID TEXT, DocumentName TEXT, DocumentDescription TEXT, DocumentDate TEXT,
        Author TEXT, ValidFrom TEXT, ValidUntil TEXT, DocumentURL TEXT,
        Version TEXT, DocumentFile TEXT);
      CREATE TABLE IF NOT EXISTS AUDITDOCUMENT (
        AuditDocumentID INTEGER PRIMARY KEY,
        AuditID INTEGER, DocumentID INTEGER, CreatedDate TEXT, ConfidenceLevel TEXT,
        ValidFrom TEXT, ValidUntil TEXT);
      CREATE TABLE IF NOT EXISTS DOCUMENTPERSON (
        DocumentPersonID INTEGER PRIMARY KEY,
        DocumentID INTEGER, PersonID INTEGER, Role TEXT, CreatedDate TEXT,
        ValidFrom TEXT, ValidUntil TEXT);
      CREATE TABLE IF NOT EXISTS QUESTIONNAIRE (
        QuestionnaireID INTEGER PRIMARY KEY,
        QuestionnaireName TEXT, QuestionnaireDescription TEXT,
        CreatedDate TEXT, ValidFrom TEXT, ValidUntil TEXT);
      CREATE TABLE IF NOT EXISTS QUESTION (
        QuestionID INTEGER PRIMARY KEY,
        QuestionGUID TEXT, QuestionName TEXT, QuestionDescription TEXT,
        PersonID INTEGER, OrganisationID INTEGER,
        CreatedDate TEXT, ModifiedDate TEXT, ValidFrom TEXT, ValidUntil TEXT);
      CREATE TABLE IF NOT EXISTS ANSWER (
        AnswerID INTEGER PRIMARY KEY,
        AnswerGUID TEXT, Answer TEXT, AnswerNotes TEXT,
        CreatedDate TEXT, ModifiedDate TEXT, PersonID INTEGER,
        ValidFrom TEXT, ValidUntil TEXT, ConfidenceLevel TEXT, TrustLevel TEXT);
      CREATE TABLE IF NOT EXISTS QUESTIONFORQUESTIONNAIRE (
        QuestionForQuestionnaireID INTEGER PRIMARY KEY,
        QuestionnaireID INTEGER, QuestionID INTEGER,
        CreatedDate TEXT, VocabularyID INTEGER);
      CREATE TABLE IF NOT EXISTS NOTIFICATIONREGULATOR (
        NotificationRegulatorID INTEGER PRIMARY KEY,
        NotificationName TEXT, NotificationDescription TEXT, OrganisationID INTEGER,
        Regulation TEXT, CreatedDate TEXT, ModifiedDate TEXT, Notified DATE,
        PersonID INTEGER, ValidFrom DATE, ValidUntil DATE, ConfidenceLevel TEXT,
        IncidentID INTEGER);
      CREATE TABLE IF NOT EXISTS QUESTIONNAIREFORORGANISATION (
        QuestionnaireOrganisationID INTEGER PRIMARY KEY,
        QuestionnaireID INTEGER, OrganisationID INTEGER, Relationship TEXT,
        CreatedDate DATE, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
    `);
    ensureGrcSchema(db);
    ensureOcilSchema(db); // OCIL 2.0-compatible questionnaires/questions/answers
    ensureCrisisSchema(db); // crisis-management: tabletop exercises (AUDIT subtype) + scenarios/injects/participants
    ensureFindingRemediationSchema(db); // remediation plans / actions per AUDITFINDING
  } finally {
    db.close(); // getDb() will reopen the database with its own pragmas
  }
}

/** Crisis management (hybrid model): a tabletop exercise (TTX) is an AUDIT row with
 *  AuditType='Tabletop Exercise' (so it reuses AUDITFINDING as exercise observations /
 *  improvement actions and AUDITDOCUMENT for the after-action report). On top of that:
 *   - CRISISSCENARIO : a reusable scenario template library (ransomware, breach, DDoS…).
 *   - EXERCISEINJECT : the timeline of events. A template inject has ScenarioID set and
 *     AuditID NULL; launching an exercise copies the template's injects with AuditID set.
 *   - EXERCISEPARTICIPANT : the people/roles taking part in an exercise (by AuditID).
 *  All tenant-scoped (see TENANT_SCOPED_TABLES); created idempotently at boot. */
function ensureCrisisSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS CRISISSCENARIO (
      ScenarioID INTEGER PRIMARY KEY,
      ScenarioGUID TEXT, ScenarioName TEXT, ScenarioType TEXT, Description TEXT,
      Severity TEXT, Objectives TEXT, ThreatActor TEXT, AttackTechniques TEXT,
      Refs TEXT, IsTemplate INTEGER DEFAULT 1, Source TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS EXERCISEINJECT (
      InjectID INTEGER PRIMARY KEY,
      InjectGUID TEXT, AuditID INTEGER, ScenarioID INTEGER, StepOrder INTEGER,
      InjectTime TEXT, Title TEXT, Description TEXT, InjectType TEXT,
      ExpectedAction TEXT, ActualResponse TEXT, Status TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS EXERCISEPARTICIPANT (
      ParticipantID INTEGER PRIMARY KEY,
      ParticipantGUID TEXT, AuditID INTEGER, PersonID INTEGER, ParticipantName TEXT,
      CrisisRole TEXT, Team TEXT, Attended INTEGER,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS EXERCISELOG (
      LogID INTEGER PRIMARY KEY,
      LogGUID TEXT, AuditID INTEGER, InjectID INTEGER, ParticipantID INTEGER,
      EventType TEXT, Channel TEXT, Message TEXT, LoggedAt TEXT, ByUser TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_exerciseinject_audit ON EXERCISEINJECT(AuditID);
    CREATE INDEX IF NOT EXISTS ix_exerciseinject_scenario ON EXERCISEINJECT(ScenarioID);
    CREATE INDEX IF NOT EXISTS ix_exerciseparticipant_audit ON EXERCISEPARTICIPANT(AuditID);
    CREATE INDEX IF NOT EXISTS ix_crisisscenario_tenant ON CRISISSCENARIO(TenantID);
    CREATE INDEX IF NOT EXISTS ix_exerciselog_audit ON EXERCISELOG(AuditID);
  `);
  // OpenAEV-style enrichment (idempotent column adds): timed multi-channel injects
  // (email / SMS / WhatsApp / phone / media …), participant contact details for messaging,
  // and inject-delivery timestamps. New reactions/timeline live in EXERCISELOG above.
  const addCol = (table: string, col: string, decl: string): void => {
    const have = new Set((db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name));
    if (!have.has(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
  };
  addCol("EXERCISEINJECT", "Channel", "TEXT");
  addCol("EXERCISEINJECT", "OffsetMinutes", "INTEGER");
  addCol("EXERCISEINJECT", "Sender", "TEXT");
  addCol("EXERCISEINJECT", "Recipients", "TEXT");
  addCol("EXERCISEINJECT", "Subject", "TEXT");
  addCol("EXERCISEINJECT", "DeliveredDate", "TEXT");
  addCol("EXERCISEPARTICIPANT", "Email", "TEXT");
  addCol("EXERCISEPARTICIPANT", "Phone", "TEXT");
}

/**
 * Makes the questionnaire/question/answer model OCIL 2.0-compatible (NIST IR 7692).
 * Renames ANSWERQUESTION → ANSWERFORQUESTION ("X FOR Y" convention) and adds the
 * missing OCIL columns (idempotent: conditional ALTERs). See server/ocil.ts.
 */
function ensureOcilSchema(db: Database.Database): void {
  const tables = new Set(
    (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map((t) => t.name)
  );
  if (tables.has("ANSWERQUESTION") && !tables.has("ANSWERFORQUESTION")) {
    db.exec("ALTER TABLE ANSWERQUESTION RENAME TO ANSWERFORQUESTION");
    const cols = (db.prepare("PRAGMA table_info(ANSWERFORQUESTION)").all() as { name: string }[]).map((c) => c.name);
    if (cols.includes("AnswerQuestionID") && !cols.includes("AnswerForQuestionID")) {
      db.exec("ALTER TABLE ANSWERFORQUESTION RENAME COLUMN AnswerQuestionID TO AnswerForQuestionID");
    }
  }
  db.exec(`CREATE TABLE IF NOT EXISTS ANSWERFORQUESTION (
    AnswerForQuestionID INTEGER PRIMARY KEY,
    QuestionID INTEGER, AnswerID INTEGER, CreatedDate TEXT, PersonID INTEGER);`);

  // Evidence attached to an answer (renamed ANSWEREVIDENCES → ANSWEREVIDENCE).
  if (tables.has("ANSWEREVIDENCES") && !tables.has("ANSWEREVIDENCE")) {
    db.exec("ALTER TABLE ANSWEREVIDENCES RENAME TO ANSWEREVIDENCE");
    const cols = (db.prepare("PRAGMA table_info(ANSWEREVIDENCE)").all() as { name: string }[]).map((c) => c.name);
    if (cols.includes("AnswerEvidencesID") && !cols.includes("AnswerEvidenceID")) {
      db.exec("ALTER TABLE ANSWEREVIDENCE RENAME COLUMN AnswerEvidencesID TO AnswerEvidenceID");
    }
  }
  db.exec(`CREATE TABLE IF NOT EXISTS ANSWEREVIDENCE (
    AnswerEvidenceID INTEGER PRIMARY KEY,
    AnswerID INTEGER, EvidenceID INTEGER, CreatedDate TEXT, PersonID INTEGER, ConfidenceLevel TEXT);`);

  const addCols = (table: string, cols: [string, string][]): void => {
    const have = new Set((db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name));
    for (const [c, type] of cols) if (!have.has(c)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${c} ${type}`);
  };
  // QUESTIONNAIRE = ocil:questionnaire (title=Name, description=Description)
  addCols("QUESTIONNAIRE", [["OcilId", "TEXT"], ["Revision", "TEXT"], ["Operator", "TEXT"], ["Language", "TEXT"], ["FileName", "TEXT"]]);
  // QUESTION = ocil:boolean/choice/numeric/string_question (+ result test_action)
  addCols("QUESTION", [
    ["OcilId", "TEXT"], ["Revision", "TEXT"], ["QuestionType", "TEXT"], ["QuestionText", "TEXT"],
    ["DefaultAnswer", "TEXT"], ["Model", "TEXT"], ["ResultWhenTrue", "TEXT"], ["ResultWhenFalse", "TEXT"],
  ]);
  // ANSWER = ocil:choice (Answer = choice label)
  addCols("ANSWER", [["OcilId", "TEXT"]]);
  // questionnaire↔question link: order + test_action id
  addCols("QUESTIONFORQUESTIONNAIRE", [["DisplayOrder", "INTEGER"], ["TestActionOcilId", "TEXT"]]);
  // answer(choice)↔question link: OCIL result when this choice is selected
  addCols("ANSWERFORQUESTION", [["Result", "TEXT"], ["DisplayOrder", "INTEGER"]]);
  db.exec("CREATE INDEX IF NOT EXISTS ix_qforq_q ON QUESTIONFORQUESTIONNAIRE(QuestionnaireID)");
  db.exec("CREATE INDEX IF NOT EXISTS ix_afq_q ON ANSWERFORQUESTION(QuestionID)");
}

/**
 * GRC (Governance, Risk & Compliance) schema in XCOMPLIANCE — model inspired by
 * CISO Assistant (intuitem): perimeters/folders, frameworks and
 * requirements, reference/applied controls, compliance assessments and their
 * per-requirement answers, risk matrices, risk assessments and scenarios,
 * risk acceptances and security exceptions. Idempotent.
 */
/** Remediation plans / corrective actions for audit findings (1 finding → many plans).
 *  XCOMPLIANCE; tenant-scoped. Sibling of ASSETVULNERABILITYREMEDIATION (patch plans). */
function ensureFindingRemediationSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS AUDITFINDINGREMEDIATION (
      RemediationID INTEGER PRIMARY KEY,
      RemediationGUID TEXT, AuditFindingID INTEGER, RemediationName TEXT, Description TEXT,
      RemediationType TEXT, Status TEXT, Priority TEXT, OwnerPersonID INTEGER,
      TargetDate TEXT, CompletedDate TEXT, Progress INTEGER,
      CreatedDate TEXT, CreatedBy TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_auditfindingremediation_finding ON AUDITFINDINGREMEDIATION(AuditFindingID);
  `);
}

function ensureGrcSchema(db: Database.Database): void {
  db.exec(`
    -- Organisation / scope of application
    CREATE TABLE IF NOT EXISTS FOLDER (
      FolderID INTEGER PRIMARY KEY, FolderGUID TEXT, Name TEXT, Description TEXT,
      ParentFolderID INTEGER, ContentType TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS PERIMETER (
      PerimeterID INTEGER PRIMARY KEY, PerimeterGUID TEXT, Name TEXT, Description TEXT,
      FolderID INTEGER, Ref TEXT, Status TEXT, LifecycleStatus TEXT, CreatedDate TEXT, TenantID INTEGER);

    -- Frameworks (standards) and hierarchical requirements
    CREATE TABLE IF NOT EXISTS FRAMEWORK (
      FrameworkID INTEGER PRIMARY KEY, FrameworkGUID TEXT, Name TEXT, Description TEXT,
      Provider TEXT, Version TEXT, URN TEXT, Ref TEXT, Locale TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS REQUIREMENTNODE (
      RequirementNodeID INTEGER PRIMARY KEY, RequirementNodeGUID TEXT, FrameworkID INTEGER,
      ParentRequirementNodeID INTEGER, URN TEXT, Ref TEXT, Name TEXT, Description TEXT,
      OrderID INTEGER, Depth INTEGER, Assessable INTEGER, CreatedDate TEXT, TenantID INTEGER);

    -- Controls (reference catalogue + applied controls)
    CREATE TABLE IF NOT EXISTS REFERENCECONTROL (
      ReferenceControlID INTEGER PRIMARY KEY, ReferenceControlGUID TEXT, Name TEXT, Description TEXT,
      Category TEXT, Function TEXT, Provider TEXT, URN TEXT, Ref TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS APPLIEDCONTROL (
      AppliedControlID INTEGER PRIMARY KEY, AppliedControlGUID TEXT, Name TEXT, Description TEXT,
      ReferenceControlID INTEGER, Category TEXT, Function TEXT, Status TEXT, Priority INTEGER,
      Effort TEXT, Cost REAL, OwnerPersonID INTEGER, FolderID INTEGER,
      StartDate TEXT, ETA TEXT, ExpiryDate TEXT, CreatedDate TEXT, TenantID INTEGER);

    -- Compliance assessments (audit of a perimeter against a framework)
    CREATE TABLE IF NOT EXISTS COMPLIANCEASSESSMENT (
      ComplianceAssessmentID INTEGER PRIMARY KEY, ComplianceAssessmentGUID TEXT, Name TEXT, Description TEXT,
      FrameworkID INTEGER, PerimeterID INTEGER, Status TEXT, Version TEXT, AuthorPersonID INTEGER,
      Date TEXT, DueDate TEXT, Score INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS REQUIREMENTASSESSMENT (
      RequirementAssessmentID INTEGER PRIMARY KEY, RequirementAssessmentGUID TEXT,
      ComplianceAssessmentID INTEGER, RequirementNodeID INTEGER, Status TEXT, Result TEXT,
      Score INTEGER, IsScored INTEGER, Observation TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS REQUIREMENTASSESSMENTCONTROL (
      RequirementAssessmentControlID INTEGER PRIMARY KEY,
      RequirementAssessmentID INTEGER, AppliedControlID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS REQUIREMENTASSESSMENTEVIDENCE (
      RequirementAssessmentEvidenceID INTEGER PRIMARY KEY,
      RequirementAssessmentID INTEGER, EvidenceID INTEGER, CreatedDate TEXT, TenantID INTEGER);

    -- Risk: matrices, assessments, scenarios, treatments
    CREATE TABLE IF NOT EXISTS RISKMATRIX (
      RiskMatrixID INTEGER PRIMARY KEY, RiskMatrixGUID TEXT, Name TEXT, Description TEXT,
      Definition TEXT, ProbabilityCount INTEGER, ImpactCount INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKASSESSMENT (
      RiskAssessmentID INTEGER PRIMARY KEY, RiskAssessmentGUID TEXT, Name TEXT, Description TEXT,
      PerimeterID INTEGER, RiskMatrixID INTEGER, Status TEXT, Version TEXT, AuthorPersonID INTEGER,
      Date TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKSCENARIO (
      RiskScenarioID INTEGER PRIMARY KEY, RiskScenarioGUID TEXT, RiskAssessmentID INTEGER, Ref TEXT,
      Name TEXT, Description TEXT, ThreatID INTEGER, ThreatName TEXT, ExistingControls TEXT,
      CurrentProbability INTEGER, CurrentImpact INTEGER, CurrentRiskLevel INTEGER,
      ResidualProbability INTEGER, ResidualImpact INTEGER, ResidualRiskLevel INTEGER,
      TreatmentStrategy TEXT, Justification TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKSCENARIOCONTROL (
      RiskScenarioControlID INTEGER PRIMARY KEY,
      RiskScenarioID INTEGER, AppliedControlID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKSCENARIOASSET (
      RiskScenarioAssetID INTEGER PRIMARY KEY,
      RiskScenarioID INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER);

    -- Governance: risk acceptances, exceptions, threat library
    CREATE TABLE IF NOT EXISTS RISKACCEPTANCE (
      RiskAcceptanceID INTEGER PRIMARY KEY, RiskAcceptanceGUID TEXT, Name TEXT, Description TEXT,
      RiskScenarioID INTEGER, ApproverPersonID INTEGER, Status TEXT, Justification TEXT,
      AcceptedDate TEXT, ExpiryDate TEXT, RevokedDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS SECURITYEXCEPTION (
      SecurityExceptionID INTEGER PRIMARY KEY, SecurityExceptionGUID TEXT, Name TEXT, Description TEXT,
      Ref TEXT, Status TEXT, Severity TEXT, OwnerPersonID INTEGER, ApproverPersonID INTEGER,
      ExpiryDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS GRCTHREAT (
      ThreatID INTEGER PRIMARY KEY, ThreatGUID TEXT, Name TEXT, Description TEXT,
      Provider TEXT, URN TEXT, Ref TEXT, CreatedDate TEXT, TenantID INTEGER);

    -- ── Risk Register + links to XORCISM ──────────────
    -- A register (RISKREGISTER) groups identified risks (RISKREGISTERENTRY).
    -- XORCISM links: RiskOwnerPersonID → PERSON, AssetID → ASSET,
    -- VulnerabilityID → XVULNERABILITY; m:n to ASSET and APPLIEDCONTROL.
    CREATE TABLE IF NOT EXISTS RISKREGISTER (
      RiskRegisterID INTEGER PRIMARY KEY, RiskRegisterGUID TEXT, Name TEXT, Description TEXT,
      PerimeterID INTEGER, OwnerPersonID INTEGER, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKREGISTERENTRY (
      RiskRegisterEntryID INTEGER PRIMARY KEY, RiskRegisterEntryGUID TEXT,
      RiskRegisterID INTEGER, Ref TEXT, Title TEXT, Description TEXT, Category TEXT,
      RiskOwnerPersonID INTEGER,            -- XORCISM.PERSON
      AssetID INTEGER,                      -- XORCISM.ASSET (main asset)
      ThreatID INTEGER, ThreatName TEXT,    -- threat (GRCTHREAT / XTHREAT)
      VulnerabilityID INTEGER,              -- XVULNERABILITY.VULNERABILITY
      InherentProbability INTEGER, InherentImpact INTEGER, InherentRiskLevel INTEGER,
      CurrentProbability INTEGER, CurrentImpact INTEGER, CurrentRiskLevel INTEGER,
      ResidualProbability INTEGER, ResidualImpact INTEGER, ResidualRiskLevel INTEGER,
      TreatmentStrategy TEXT, TreatmentPlan TEXT, Justification TEXT, Status TEXT,
      IdentifiedDate TEXT, ReviewDate TEXT, TargetDate TEXT, ClosedDate TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKREGISTERENTRYASSET (
      RiskRegisterEntryAssetID INTEGER PRIMARY KEY,
      RiskRegisterEntryID INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS RISKREGISTERENTRYCONTROL (
      RiskRegisterEntryControlID INTEGER PRIMARY KEY,
      RiskRegisterEntryID INTEGER, AppliedControlID INTEGER, CreatedDate TEXT, TenantID INTEGER);

    -- Indexes on the most-traversed foreign keys
    CREATE INDEX IF NOT EXISTS ix_reqnode_framework ON REQUIREMENTNODE(FrameworkID);
    CREATE INDEX IF NOT EXISTS ix_reqassess_assessment ON REQUIREMENTASSESSMENT(ComplianceAssessmentID);
    CREATE INDEX IF NOT EXISTS ix_reqassess_node ON REQUIREMENTASSESSMENT(RequirementNodeID);
    CREATE INDEX IF NOT EXISTS ix_riskscenario_assessment ON RISKSCENARIO(RiskAssessmentID);
    CREATE INDEX IF NOT EXISTS ix_appliedcontrol_ref ON APPLIEDCONTROL(ReferenceControlID);
    CREATE INDEX IF NOT EXISTS ix_rrentry_register ON RISKREGISTERENTRY(RiskRegisterID);
    CREATE INDEX IF NOT EXISTS ix_rrentryasset_entry ON RISKREGISTERENTRYASSET(RiskRegisterEntryID);
    CREATE INDEX IF NOT EXISTS ix_rrentryctrl_entry ON RISKREGISTERENTRYCONTROL(RiskRegisterEntryID);
  `);
}

/**
 * Creates the XTICKET.db database and its tables (ticketing tool) if they don't
 * exist: TICKET, TICKETCOMMENT, TICKETCATEGORY, TICKETATTACHMENT. Idempotent.
 */
export function ensureTicketDb(): void {
  const dbPath = path.join(DB_DIR, "XTICKET.db");
  const db = new Database(dbPath); // creates the file if it doesn't exist
  try {
    db.pragma("journal_mode = WAL");
    db.exec(`
      CREATE TABLE IF NOT EXISTS TICKET (
        TicketID INTEGER PRIMARY KEY,
        TicketGUID TEXT, TicketNumber TEXT, Subject TEXT, Description TEXT,
        Status TEXT, Priority TEXT, Severity TEXT, TicketType TEXT, CategoryID INTEGER,
        RequesterName TEXT, RequesterEmail TEXT, AssigneeName TEXT, Tags TEXT,
        CreatedDate TEXT, UpdatedDate TEXT, DueDate TEXT, ResolvedDate TEXT, ClosedDate TEXT,
        Resolution TEXT);
      CREATE TABLE IF NOT EXISTS TICKETCOMMENT (
        TicketCommentID INTEGER PRIMARY KEY,
        TicketCommentGUID TEXT, TicketID INTEGER, Author TEXT, Body TEXT,
        IsInternal INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS TICKETCATEGORY (
        TicketCategoryID INTEGER PRIMARY KEY,
        TicketCategoryName TEXT, Description TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS TICKETATTACHMENT (
        TicketAttachmentID INTEGER PRIMARY KEY,
        TicketID INTEGER, FileName TEXT, FilePath TEXT, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_ticketcomment_ticket ON TICKETCOMMENT(TicketID);
      CREATE INDEX IF NOT EXISTS ix_ticketattachment_ticket ON TICKETATTACHMENT(TicketID);
    `);
  } finally {
    db.close();
  }
}

export function ensureThreatModelTables(): void {
  const db = getDb("XORCISM");
  // Idempotent renaming of the APPLICATIONWHITELISTENTRY columns (old → new
  // names). BEFORE the db.exec: the index creation references the new name.
  const aweExists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='APPLICATIONWHITELISTENTRY'")
    .get();
  if (aweExists) {
    const c = new Set(
      (db.prepare("PRAGMA table_info(APPLICATIONWHITELISTENTRY)").all() as { name: string }[]).map((x) => x.name)
    );
    if (c.has("AppWhitelistEntry") && !c.has("AppWhitelistEntryID"))
      db.exec("ALTER TABLE APPLICATIONWHITELISTENTRY RENAME COLUMN AppWhitelistEntry TO AppWhitelistEntryID");
    if (c.has("AppWhitelistID") && !c.has("ApplicationWhitelistID"))
      db.exec("ALTER TABLE APPLICATIONWHITELISTENTRY RENAME COLUMN AppWhitelistID TO ApplicationWhitelistID");
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS THREATMODEL (
      ThreatModelID INTEGER PRIMARY KEY,
      ThreatModelGUID TEXT, ThreatModelName TEXT, Description TEXT,
      Methodology TEXT, Status TEXT, Scope TEXT, RiskLevel TEXT, Owner TEXT,
      CreatedDate TEXT, VocabularyID INTEGER, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS THREATMODELASSET (
      ThreatModelAssetID INTEGER PRIMARY KEY,
      ThreatModelID INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS THREATMODELTHREAT (
      ThreatModelThreatID INTEGER PRIMARY KEY,
      ThreatModelID INTEGER, Title TEXT, STRIDECategory TEXT, Description TEXT,
      ThreatAgentID INTEGER, AttackPattern TEXT, Likelihood TEXT, Impact TEXT,
      RiskScore TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS THREATMODELCONTROL (
      ThreatModelControlID INTEGER PRIMARY KEY,
      ThreatModelThreatID INTEGER, ControlID INTEGER, Status TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    -- Attack trees (Schneier-style): a root goal decomposed via AND/OR gates into leaf attacks.
    CREATE TABLE IF NOT EXISTS ATTACKTREE (
      AttackTreeID INTEGER PRIMARY KEY, AttackTreeGUID TEXT,
      Name TEXT, Goal TEXT, Description TEXT, ThreatModelID INTEGER,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS ATTACKTREENODE (
      AttackTreeNodeID INTEGER PRIMARY KEY, AttackTreeID INTEGER, ParentNodeID INTEGER,
      Label TEXT, Gate TEXT,                 -- 'AND' | 'OR' for internal nodes, '' for leaves
      Description TEXT, Likelihood TEXT,      -- leaf feasibility: High/Medium/Low (or numeric 0-1)
      Cost TEXT, Difficulty TEXT, Mitigated INTEGER DEFAULT 0,
      MitigationNote TEXT, AttackPattern TEXT, SortOrder INTEGER DEFAULT 0,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_attacktree_tenant ON ATTACKTREE(TenantID);
    CREATE INDEX IF NOT EXISTS ix_attacktreenode_tree ON ATTACKTREENODE(AttackTreeID);
    -- ASSET ↔ OVAL definition link (configuration assessment results)
    CREATE TABLE IF NOT EXISTS ASSETOVALDEFINITION (
      AssetOVALDefinitionID INTEGER PRIMARY KEY,
      AssetID INTEGER, OVALDefinitionID INTEGER, Status TEXT, ConfidenceLevel TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil TEXT);
    CREATE TABLE IF NOT EXISTS ASSETFINANCIALVALUE (
      AssetFinancialValueID INTEGER PRIMARY KEY,
      AssetID INTEGER, FinancialValue INTEGER, Currency TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil TEXT, PersonID INTEGER);
    -- Publishers/vendors (feeds the CPE builder: vendor field)
    CREATE TABLE IF NOT EXISTS VENDOR (
      VendorID INTEGER PRIMARY KEY,
      VendorName TEXT, VendorDescription TEXT, VendorURL TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil TEXT,
      Source TEXT, ConfidenceLevel TEXT, TrustLevel TEXT);
    -- Remediations attached to an ASSET↔vulnerability link (ASSETVULNERABILITY)
    CREATE TABLE IF NOT EXISTS ASSETVULNERABILITYREMEDIATION (
      AssetVulnerabilityRemediationID INTEGER PRIMARY KEY,
      AssetVulnerabilityID INTEGER, RemediationName TEXT, RemediationDescription TEXT,
      CreatedDate TEXT, PersonID INTEGER, ValidFrom DATE, ValidUntil DATE);
    -- Asset tags
    CREATE TABLE IF NOT EXISTS ASSETTAG (
      AssetTagID INTEGER PRIMARY KEY,
      AssetID INTEGER, TagID INTEGER, Tag TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
    -- Entries of an application whitelist (APPLICATIONWHITELIST ↔ APPLICATION)
    CREATE TABLE IF NOT EXISTS APPLICATIONWHITELISTENTRY (
      AppWhitelistEntryID INTEGER PRIMARY KEY,
      ApplicationWhitelistID INTEGER, ApplicationID INTEGER,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER, ConfidenceLevel TEXT);
    -- Entries of an application blacklist (APPLICATIONBLACKLIST ↔ APPLICATION)
    CREATE TABLE IF NOT EXISTS APPLICATIONBLACKLISTENTRY (
      AppBlacklistEntryID INTEGER PRIMARY KEY,
      ApplicationBlacklistID INTEGER, ApplicationID INTEGER,
      CreatedDate TEXT, PersonID INTEGER, ValidFrom DATE, ValidUntil DATE, VocabularyID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_tmasset_model ON THREATMODELASSET(ThreatModelID);
    CREATE INDEX IF NOT EXISTS ix_tmthreat_model ON THREATMODELTHREAT(ThreatModelID);
    CREATE INDEX IF NOT EXISTS ix_tmcontrol_threat ON THREATMODELCONTROL(ThreatModelThreatID);
    CREATE INDEX IF NOT EXISTS ix_assetoval_asset ON ASSETOVALDEFINITION(AssetID);
    CREATE INDEX IF NOT EXISTS ix_assetfinval_asset ON ASSETFINANCIALVALUE(AssetID);
    CREATE INDEX IF NOT EXISTS ix_vendor_name ON VENDOR(VendorName);
    CREATE INDEX IF NOT EXISTS ix_avremediation_av ON ASSETVULNERABILITYREMEDIATION(AssetVulnerabilityID);
    CREATE INDEX IF NOT EXISTS ix_assettag_asset ON ASSETTAG(AssetID);
    CREATE INDEX IF NOT EXISTS ix_appwlentry_wl ON APPLICATIONWHITELISTENTRY(ApplicationWhitelistID);
    CREATE INDEX IF NOT EXISTS ix_appblentry_bl ON APPLICATIONBLACKLISTENTRY(ApplicationBlacklistID);
  `);
  // APPLICATIONWHITELIST (legacy table, originally PK-only): idempotent addition of
  // descriptive/metadata fields (ALTER, we don't recreate the legacy table).
  const awExists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='APPLICATIONWHITELIST'")
    .get();
  if (awExists) {
    const have = new Set(
      (db.prepare("PRAGMA table_info(APPLICATIONWHITELIST)").all() as { name: string }[]).map((c) => c.name)
    );
    const cols: [string, string][] = [
      ["AppWhitelistName", "TEXT"], ["AppWhitelistDescription", "TEXT"],
      ["CreatedDate", "TEXT"], ["ValidFrom", "DATE"], ["ValidUntil", "DATE"],
      ["PersonID", "INTEGER"], ["VocabularyID", "INTEGER"],
    ];
    for (const [c, type] of cols) {
      if (!have.has(c)) db.exec(`ALTER TABLE APPLICATIONWHITELIST ADD COLUMN ${c} ${type}`);
    }
  }
  // APPLICATIONBLACKLIST (legacy table, originally PK-only): idempotent addition of
  // descriptive/metadata fields (ALTER, we don't recreate the legacy table).
  const blExists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='APPLICATIONBLACKLIST'")
    .get();
  if (blExists) {
    const have = new Set(
      (db.prepare("PRAGMA table_info(APPLICATIONBLACKLIST)").all() as { name: string }[]).map((c) => c.name)
    );
    const cols: [string, string][] = [
      ["AppBlacklistName", "TEXT"], ["AppBlacklistDescription", "TEXT"],
      ["CreatedDate", "TEXT"], ["PersonID", "INTEGER"],
      ["ValidFrom", "DATE"], ["ValidUntil", "DATE"], ["ConfidenceLevel", "TEXT"],
    ];
    for (const [c, type] of cols) {
      if (!have.has(c)) db.exec(`ALTER TABLE APPLICATIONBLACKLIST ADD COLUMN ${c} ${type}`);
    }
  }
  ensureNotificationSchema(db);
  ensureValidFromDateType(db);
}

/**
 * XTHREAT tables created at startup if missing. IOC = indicator of compromise,
 * STIX 2.1-compatible ("indicator" SDO by default): business fields + STIX fields
 * (StixID, Pattern, SpecVersion, modified, revoked, JSON lists…).
 */
// ── XINCIDENT.ALERT (security alerts, optionally linked to an INCIDENT) ──
// Created at boot (idempotent). Tenant-scoped (see TENANT_SCOPED_TABLES):
// ensureTenantColumns() adds the ix_ALERT_tenant index; the TenantID column is
// declared here so brand-new databases already have it.
// The metadata mirrors Microsoft Defender XDR's "manually create an incident/alert"
// fields (severity, status, category, ATT&CK techniques, recommended actions,
// service/detection source, classification, determination, assignee, tags).
export function ensureIncidentTables(): void {
  const db = getDb("XINCIDENT");
  db.exec(`
    CREATE TABLE IF NOT EXISTS ALERT (
      AlertID INTEGER PRIMARY KEY,
      AlertGUID TEXT, AlertName TEXT, AlertDescription TEXT,
      Severity TEXT, Status TEXT, Category TEXT, AttackTechniques TEXT, RecommendedActions TEXT,
      ServiceSource TEXT DEFAULT 'XORCISM', DetectionSource TEXT DEFAULT 'Manual',
      Classification TEXT, Determination TEXT, AssignedTo TEXT, Tags TEXT,
      ExternalID TEXT, ExternalUrl TEXT,
      PersonID INTEGER, CreatedDate DATE, IncidentID INTEGER, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_alert_incident ON ALERT(IncidentID);
    -- Defender "Select entities": impacted assets + related evidence on an alert.
    CREATE TABLE IF NOT EXISTS ALERTFORASSET (
      AssetAlertID INTEGER PRIMARY KEY, AlertID INTEGER, AssetID INTEGER,
      Relationship TEXT, CreatedDate TEXT, TenantID INTEGER, UNIQUE(AlertID, AssetID));
    CREATE INDEX IF NOT EXISTS ix_alertforasset_alert ON ALERTFORASSET(AlertID);
    CREATE TABLE IF NOT EXISTS ALERTEVIDENCE (
      AlertEvidenceID INTEGER PRIMARY KEY, AlertID INTEGER, EvidenceType TEXT, EvidenceValue TEXT,
      EvidenceDescription TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_alertevidence_alert ON ALERTEVIDENCE(AlertID);
  `);
  // Idempotent column add (extends pre-existing tables; legacy INCIDENT is ALTERed,
  // never recreated — cf. the XORCISM legacy-tables convention).
  const addCol = (table: string, col: string, type: string): void => {
    const have = new Set(
      (db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)
    );
    if (!have.has(col)) db.exec(`ALTER TABLE "${table}" ADD COLUMN ${col} ${type}`);
  };
  // ALERT: Defender XDR alert metadata on databases created before these columns.
  for (const [c, t] of [
    ["Severity", "TEXT"], ["Status", "TEXT"], ["Category", "TEXT"], ["AttackTechniques", "TEXT"],
    ["RecommendedActions", "TEXT"], ["ServiceSource", "TEXT DEFAULT 'XORCISM'"],
    ["DetectionSource", "TEXT DEFAULT 'Manual'"], ["Classification", "TEXT"], ["Determination", "TEXT"],
    ["AssignedTo", "TEXT"], ["Tags", "TEXT"], ["ExternalID", "TEXT"], ["ExternalUrl", "TEXT"],
  ] as [string, string][]) addCol("ALERT", c, t);
  // (DetectionSource, ExternalID) = idempotency key for connector-imported alerts (SOC tools:
  // TheHive / ServiceNow / PagerDuty / Opsgenie / Zammad → runner.import_incidents). Created AFTER
  // the column migration above so a pre-ExternalID ALERT table doesn't crash the boot.
  db.exec("CREATE INDEX IF NOT EXISTS ix_alert_extid ON ALERT(DetectionSource, ExternalID)");
  // INCIDENT (legacy): Defender-aligned metadata added by ALTER.
  for (const [c, t] of [
    ["Severity", "TEXT"], ["AttackTechniques", "TEXT"], ["Classification", "TEXT"],
    ["Determination", "TEXT"], ["AssignedTo", "TEXT"], ["Tags", "TEXT"], ["RecommendedActions", "TEXT"],
  ] as [string, string][]) addCol("INCIDENT", c, t);
}

export function ensureThreatTables(): void {
  const db = getDb("XTHREAT");
  db.exec(`
    CREATE TABLE IF NOT EXISTS IOC (
      IOCID INTEGER PRIMARY KEY,
      IOCGUID TEXT, IOCName TEXT, IOCDescription TEXT, CreatedDate TEXT,
      IOCtype TEXT DEFAULT 'indicator', OrganisationID INTEGER, PersonID INTEGER,
      created_by_ref TEXT, ValidFrom DATE, ValidUntil DATE,
      -- STIX 2.1 compatibility (indicator / observable)
      StixID TEXT, SpecVersion TEXT DEFAULT '2.1', ModifiedDate TEXT,
      Pattern TEXT, PatternType TEXT DEFAULT 'stix', PatternVersion TEXT,
      IndicatorTypes TEXT, KillChainPhases TEXT, Labels TEXT,
      ExternalReferences TEXT, ObjectMarkingRefs TEXT,
      Confidence INTEGER, Revoked INTEGER DEFAULT 0, Lang TEXT,
      VocabularyID INTEGER, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_ioc_stixid ON IOC(StixID);
    CREATE INDEX IF NOT EXISTS ix_ioc_type ON IOC(IOCtype);
    -- MITRE D3FEND (defensive countermeasures) — populated by import_d3fend.py.
    CREATE TABLE IF NOT EXISTS D3FENDTACTIC (
      D3FENDTacticID INTEGER PRIMARY KEY, ShortName TEXT UNIQUE, Name TEXT,
      Definition TEXT, MatrixOrder INTEGER, URL TEXT);
    CREATE TABLE IF NOT EXISTS D3FENDTECHNIQUE (
      D3FENDTechniqueID INTEGER PRIMARY KEY, D3FENDID TEXT UNIQUE, Name TEXT,
      Definition TEXT, TacticShortName TEXT, ParentD3FENDID TEXT,
      IsSubtechnique INTEGER DEFAULT 0, URL TEXT);
    CREATE TABLE IF NOT EXISTS D3FENDATTACKMAP (
      D3FENDAttackMapID INTEGER PRIMARY KEY, D3FENDID TEXT, AttackID TEXT, Relationship TEXT,
      UNIQUE(D3FENDID, AttackID, Relationship));
    CREATE INDEX IF NOT EXISTS ix_d3tech_tactic ON D3FENDTECHNIQUE(TacticShortName);
    CREATE INDEX IF NOT EXISTS ix_d3map_d3 ON D3FENDATTACKMAP(D3FENDID);
    CREATE INDEX IF NOT EXISTS ix_d3map_attack ON D3FENDATTACKMAP(AttackID);
    -- Threat hunts (HuntReference = hunt link/source; extended fields
    -- for the novasky.io import via import_hunts.py).
    CREATE TABLE IF NOT EXISTS HUNT (
      HuntID INTEGER PRIMARY KEY,
      HuntGUID TEXT, HuntName TEXT, HuntDescription TEXT, CreatedDate DATE,
      HuntReference TEXT, ValidFrom DATE, ValidUntil DATE,
      HuntStatus TEXT, HuntDate DATE, HuntTool TEXT, AttackTags TEXT,
      HuntFindings TEXT, HuntSource TEXT);
    -- Hunt hypotheses (hunt ideas; novasky.io import via import_hypotheses.py).
    CREATE TABLE IF NOT EXISTS HYPOTHESIS (
      HypothesisID INTEGER PRIMARY KEY,
      HypothesisGUID TEXT, HypothesisName TEXT, HypothesisDescription TEXT,
      CreatedDate DATE, ValidFromDate DATE, ValidUntil DATE, ConfidenceLevel TEXT);
    -- Threat reports (CTI report entity). ThreatReportFileName/Source hold the
    -- uploaded PDF's name and the report source (PDF ingestion → IOC/THREATACTOR).
    CREATE TABLE IF NOT EXISTS THREATREPORT (
      ThreatReportID INTEGER PRIMARY KEY,
      ThreatReportGUID TEXT, ThreatReportName TEXT, ThreatReportDescription TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER,
      ThreatReportFileName TEXT, ThreatReportSource TEXT);
    -- Sigma detection rules (YAML source + cached SPL/KQL/EQL conversions).
    CREATE TABLE IF NOT EXISTS SIGMARULE (
      SigmaRuleID INTEGER PRIMARY KEY,
      SigmaRuleGUID TEXT, SigmaRuleName TEXT, SigmaRuleDescription TEXT,
      SigmaYaml TEXT, LogSource TEXT, Level TEXT, Status TEXT, Author TEXT,
      SigmaReference TEXT, AttackTags TEXT,
      SplQuery TEXT, KqlQuery TEXT, EqlQuery TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
    -- YARA detection rules (malware classification). YaraSource = the full rule text; the
    -- store is the "support" side of YARA in XORCISM (browsable in the explorer, served to
    -- agents at /api/agent/yara-rules, imported by import_yara.py / the yara connector).
    CREATE TABLE IF NOT EXISTS YARARULE (
      YaraRuleID INTEGER PRIMARY KEY,
      YaraRuleGUID TEXT, YaraRuleName TEXT, YaraRuleDescription TEXT,
      YaraSource TEXT, Namespace TEXT, Tags TEXT, Meta TEXT, Author TEXT,
      YaraReference TEXT, AttackTags TEXT, StringCount INTEGER, Status TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
    CREATE INDEX IF NOT EXISTS ix_yararule_ref ON YARARULE(YaraReference);
    CREATE INDEX IF NOT EXISTS ix_yararule_name ON YARARULE(YaraRuleName);
    -- HUNT ↔ ATT&CK techniques links (derived from HUNT.AttackTags) and HUNT ↔ IOC.
    CREATE TABLE IF NOT EXISTS HUNTATTACK (
      HuntAttackID INTEGER PRIMARY KEY, HuntID INTEGER, AttackID TEXT,
      AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(HuntID, AttackID));
    CREATE TABLE IF NOT EXISTS HUNTIOC (
      HuntIOCID INTEGER PRIMARY KEY, HuntID INTEGER, IOCID INTEGER,
      Relationship TEXT, CreatedDate DATE, UNIQUE(HuntID, IOCID));
    CREATE INDEX IF NOT EXISTS ix_huntattack_hunt ON HUNTATTACK(HuntID);
    CREATE INDEX IF NOT EXISTS ix_huntattack_aid ON HUNTATTACK(AttackID);
    CREATE INDEX IF NOT EXISTS ix_huntioc_hunt ON HUNTIOC(HuntID);
    -- A3M — Agentic AI Attack Matrix (cyberriskevaluator.com), populated by import_a3m.py.
    CREATE TABLE IF NOT EXISTS A3MTACTIC (
      A3MTacticID INTEGER PRIMARY KEY, Name TEXT UNIQUE, MatrixOrder INTEGER, URL TEXT);
    CREATE TABLE IF NOT EXISTS A3MTECHNIQUE (
      A3MTechniqueID INTEGER PRIMARY KEY, AATID TEXT UNIQUE, Name TEXT, Description TEXT,
      TacticName TEXT, MatrixOrder INTEGER, URL TEXT);
    CREATE INDEX IF NOT EXISTS ix_a3mtech_tactic ON A3MTECHNIQUE(TacticName);
    -- Mitigant Threat Catalog — cloud (AWS) attack-technique matrix (threats.mitigant.io,
    -- derived from the AWS Threat Technique Catalog), populated by import_mitigant.py.
    CREATE TABLE IF NOT EXISTS MITIGANTTACTIC (
      MitigantTacticID INTEGER PRIMARY KEY, TacticKey TEXT UNIQUE, Name TEXT, MitreTacticID TEXT, MatrixOrder INTEGER);
    -- TechID is NOT unique: the catalog legitimately repeats a technique id across (and within)
    -- tactics, so the matrix keeps all rows; the importer does a full replace.
    CREATE TABLE IF NOT EXISTS MITIGANTTECHNIQUE (
      MitigantTechniqueID INTEGER PRIMARY KEY, TechID TEXT, Title TEXT, Description TEXT,
      TacticKey TEXT, Severity TEXT, Service TEXT, MitreID TEXT, Commands TEXT, CloudTrail TEXT,
      MatrixOrder INTEGER, URL TEXT);
    CREATE INDEX IF NOT EXISTS ix_mitiganttech_tactic ON MITIGANTTECHNIQUE(TacticKey);
    CREATE INDEX IF NOT EXISTS ix_mitiganttech_service ON MITIGANTTECHNIQUE(Service);
    CREATE INDEX IF NOT EXISTS ix_mitiganttech_id ON MITIGANTTECHNIQUE(TechID);
    -- SAIF — Google Secure AI Framework risk map (saif.google), populated by import_saif.py.
    CREATE TABLE IF NOT EXISTS SAIFCOMPONENT (
      SaifComponentID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Description TEXT,
      MatrixOrder INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS SAIFCONTROL (
      SaifControlID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Category TEXT, Description TEXT,
      CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS SAIFRISK (
      SaifRiskID INTEGER PRIMARY KEY, SaifID TEXT, Name TEXT UNIQUE, Description TEXT,
      Component TEXT, ResponsibleParty TEXT, Controls TEXT, MatrixOrder INTEGER, URL TEXT,
      CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_saifrisk_component ON SAIFRISK(Component);
    -- Community threat-intel reports (detections.ai Intel Exchange), imported by
    -- the detections-ai connector. Idempotent by IntelReference (source URL).
    CREATE TABLE IF NOT EXISTS INTELEXCHANGE (
      IntelID INTEGER PRIMARY KEY,
      IntelGUID TEXT, IntelName TEXT, IntelDescription TEXT, CreatedDate DATE,
      IntelReference TEXT, IntelExternalID TEXT, IntelAuthor TEXT, IntelDate DATE,
      IntelSource TEXT, AttackTags TEXT, ActorTags TEXT, MalwareTags TEXT,
      CveTags TEXT, IntelTags TEXT, Views INTEGER, ValidFrom DATE, ValidUntil DATE);
    CREATE INDEX IF NOT EXISTS ix_intelexchange_ref ON INTELEXCHANGE(IntelReference);
    -- INTELEXCHANGE ↔ ATT&CK techniques (derived from INTELEXCHANGE.AttackTags).
    CREATE TABLE IF NOT EXISTS INTELEXCHANGEATTACK (
      IntelAttackID INTEGER PRIMARY KEY, IntelID INTEGER, AttackID TEXT,
      AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(IntelID, AttackID));
    CREATE INDEX IF NOT EXISTS ix_intelattack_intel ON INTELEXCHANGEATTACK(IntelID);
    CREATE INDEX IF NOT EXISTS ix_intelattack_aid ON INTELEXCHANGEATTACK(AttackID);
    -- Curated CTI RSS feeds shown on /threat-feeds (server fetches & parses them).
    CREATE TABLE IF NOT EXISTS THREATFEED (
      ThreatFeedID INTEGER PRIMARY KEY,
      ThreatFeedGUID TEXT, ThreatFeedName TEXT, FeedURL TEXT UNIQUE, SiteURL TEXT,
      ThreatFeedDescription TEXT, Category TEXT, Vendor TEXT,
      Enabled INTEGER DEFAULT 1, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_threatfeed_enabled ON THREATFEED(Enabled);
    -- THREATFORASSET: links a THREAT to an ASSET (with relationship + validity + tenant).
    CREATE TABLE IF NOT EXISTS THREATFORASSET (
      AssetThreatID INTEGER PRIMARY KEY,
      AssetID INTEGER, ThreatID INTEGER, CreatedDate TEXT, PersonID INTEGER,
      Relationship TEXT, ValidFrom TEXT, ValidUntil TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_threatforasset_asset ON THREATFORASSET(AssetID);
    CREATE INDEX IF NOT EXISTS ix_threatforasset_threat ON THREATFORASSET(ThreatID);
    -- WATCHLIST: terms (keyword / actor / CVE) the analyst tracks across the feed.
    -- The feed poller alerts (NOTIFICATION) the owner when new reporting matches.
    CREATE TABLE IF NOT EXISTS WATCHLIST (
      WatchlistID INTEGER PRIMARY KEY,
      Term TEXT, WatchType TEXT DEFAULT 'keyword', WatchlistName TEXT,
      UserID INTEGER, Enabled INTEGER DEFAULT 1, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_watchlist_enabled ON WATCHLIST(Enabled);
    -- PIR: standing priority intelligence requirements (CTI tasking).
    CREATE TABLE IF NOT EXISTS PIR (
      PIRID INTEGER PRIMARY KEY,
      PIRName TEXT, PIRDescription TEXT, Priority TEXT DEFAULT 'Medium',
      Keywords TEXT, Status TEXT DEFAULT 'Active', PersonID INTEGER,
      CreatedDate TEXT, ValidFrom TEXT, ValidUntil TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_pir_status ON PIR(Status);
  `);
  seedThreatFeeds(db);
  // THREATREPORT PDF-ingestion + feed-ingestion + enrichment columns on existing DBs.
  const trCols = new Set((db.prepare(`PRAGMA table_info("THREATREPORT")`).all() as { name: string }[]).map((c) => c.name));
  for (const [n, ty] of [["ThreatReportFileName", "TEXT"], ["ThreatReportSource", "TEXT"],
    ["ThreatReportReference", "TEXT"], ["CveTags", "TEXT"], ["AiSummary", "TEXT"]] as const) {
    if (!trCols.has(n)) db.exec(`ALTER TABLE "THREATREPORT" ADD COLUMN "${n}" ${ty}`);
  }
  db.exec("CREATE INDEX IF NOT EXISTS ix_threatreport_ref ON THREATREPORT(ThreatReportReference)");
}

// ── CTI: watchlists, IOC/CVE extraction, brief building ──────────────────────
// CVE references (precise, low-noise) and common IOC shapes pulled from free text.
const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;
const SHA_RE = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;

export function extractCves(text: string): string[] {
  const out = new Set<string>();
  for (const m of String(text || "").matchAll(CVE_RE)) out.add(m[0].toUpperCase());
  return [...out];
}
export function extractHashes(text: string): string[] {
  const out = new Set<string>();
  for (const m of String(text || "").matchAll(SHA_RE)) out.add(m[0].toLowerCase());
  return [...out];
}

export interface WatchTerm { WatchlistID: number; Term: string; WatchType: string; UserID: number | null; TenantID: number | null; }
export function getActiveWatchlist(): WatchTerm[] {
  const xt = getDb("XTHREAT");
  if (!xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='WATCHLIST'").get()) return [];
  return xt.prepare(
    "SELECT WatchlistID, Term, COALESCE(WatchType,'keyword') AS WatchType, UserID, TenantID FROM WATCHLIST WHERE Enabled = 1 AND Term IS NOT NULL AND TRIM(Term) <> ''"
  ).all() as WatchTerm[];
}

/** A watch term matches a report's text. CVE terms match the exact CVE token; others substring. */
export function watchTermMatches(term: WatchTerm, haystack: string, cves: string[]): boolean {
  const t = (term.Term || "").trim().toLowerCase();
  if (!t) return false;
  if ((term.WatchType || "").toLowerCase() === "cve") {
    return cves.some((c) => c.toLowerCase() === t) || cves.some((c) => c.toLowerCase().includes(t));
  }
  return haystack.toLowerCase().includes(t);
}

// ── PIR (Priority Intelligence Requirements): keyword tasking for new reporting ──
export interface PirTerm { PIRID: number; PIRName: string; Keywords: string; PersonID: number | null; TenantID: number | null; }

/** Active PIRs that carry keywords (used by the feed poller to alert the owner). */
export function getActivePirs(): PirTerm[] {
  const xt = getDb("XTHREAT");
  if (!xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PIR'").get()) return [];
  return xt.prepare(
    `SELECT PIRID, COALESCE(PIRName,'PIR') AS PIRName, Keywords, PersonID, TenantID FROM PIR
     WHERE lower(COALESCE(Status,'active')) IN ('active','on hold','draft')
       AND Keywords IS NOT NULL AND TRIM(Keywords) <> ''`
  ).all() as PirTerm[];
}

/** First PIR keyword (comma-separated) found in the report text, or null. */
export function pirMatches(keywords: string, haystack: string): string | null {
  const hay = (haystack || "").toLowerCase();
  for (const k of String(keywords || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    if (hay.includes(k)) return k;
  }
  return null;
}

// ── Curated trusted CTI RSS feeds (seeded once into THREATFEED) ──────────────
const TRUSTED_CTI_FEEDS: [string, string, string, string, string][] = [
  // [Name, FeedURL, SiteURL, Category, Vendor]
  ["The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "https://thehackernews.com", "News", "The Hacker News"],
  ["BleepingComputer", "https://www.bleepingcomputer.com/feed/", "https://www.bleepingcomputer.com", "News", "BleepingComputer"],
  ["Krebs on Security", "https://krebsonsecurity.com/feed/", "https://krebsonsecurity.com", "News", "Brian Krebs"],
  ["Google Threat Intelligence (GTIG/Mandiant)", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "https://cloud.google.com/blog/topics/threat-intelligence", "Vendor research", "Google / Mandiant"],
  ["Cisco Talos", "https://blog.talosintelligence.com/rss/", "https://blog.talosintelligence.com", "Vendor research", "Cisco Talos"],
  ["Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/", "https://unit42.paloaltonetworks.com", "Vendor research", "Palo Alto Networks"],
  ["Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "https://www.microsoft.com/security/blog", "Vendor research", "Microsoft"],
  ["CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "https://www.cisa.gov/news-events/cybersecurity-advisories", "Government", "CISA"],
  ["SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml", "https://isc.sans.edu", "Community", "SANS ISC"],
  ["Securelist (Kaspersky)", "https://securelist.com/feed/", "https://securelist.com", "Vendor research", "Kaspersky"],
  ["ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "https://www.welivesecurity.com", "Vendor research", "ESET"],
  ["Check Point Research", "https://research.checkpoint.com/feed/", "https://research.checkpoint.com", "Vendor research", "Check Point"],
  ["Sophos News", "https://news.sophos.com/en-us/feed/", "https://news.sophos.com", "Vendor research", "Sophos"],
  ["Recorded Future", "https://www.recordedfuture.com/feed", "https://www.recordedfuture.com/blog", "Vendor research", "Recorded Future"],
  ["Dark Reading", "https://www.darkreading.com/rss.xml", "https://www.darkreading.com", "News", "Dark Reading"],
  ["Schneier on Security", "https://www.schneier.com/feed/atom/", "https://www.schneier.com", "Community", "Bruce Schneier"],
  ["Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml", "https://www.malwarebytes.com/blog", "Vendor research", "Malwarebytes"],
  ["Rapid7 Blog", "https://www.rapid7.com/blog/rss/", "https://www.rapid7.com/blog", "Vendor research", "Rapid7"],
  ["Security Affairs", "https://securityaffairs.com/feed", "https://securityaffairs.com", "News", "Pierluigi Paganini"],
  ["The DFIR Report", "https://thedfirreport.com/feed/", "https://thedfirreport.com", "Community", "The DFIR Report"],
  ["NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "https://www.ncsc.gov.uk", "Government", "NCSC UK"],
  ["CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/", "https://www.crowdstrike.com/blog", "Vendor research", "CrowdStrike"],
  ["SentinelOne Labs", "https://www.sentinelone.com/labs/feed/", "https://www.sentinelone.com/labs", "Vendor research", "SentinelOne"],
  ["Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default", "https://googleprojectzero.blogspot.com", "Vendor research", "Google Project Zero"],
  ["CERT-FR (ANSSI)", "https://www.cert.ssi.gouv.fr/feed/", "https://www.cert.ssi.gouv.fr", "Government", "ANSSI / CERT-FR"],
  ["CERT-EU", "https://cert.europa.eu/publications/threat-intelligence-rss", "https://cert.europa.eu", "Government", "CERT-EU"],
  ["CyberScoop", "https://cyberscoop.com/feed/", "https://cyberscoop.com", "News", "CyberScoop"],
  ["The Record", "https://therecord.media/feed/", "https://therecord.media", "News", "Recorded Future News"],
  ["Graham Cluley", "https://grahamcluley.com/feed/", "https://grahamcluley.com", "Community", "Graham Cluley"],
  ["The Register — Security", "https://www.theregister.com/security/headlines.atom", "https://www.theregister.com/security", "News", "The Register"],
  ["Volexity", "https://www.volexity.com/blog/feed/", "https://www.volexity.com/blog", "Vendor research", "Volexity"],
  ["WithSecure Labs", "https://labs.withsecure.com/content/labs/rss.xml", "https://labs.withsecure.com", "Vendor research", "WithSecure"],
  ["r/netsec", "https://www.reddit.com/r/netsec/.rss", "https://www.reddit.com/r/netsec", "Community", "Reddit r/netsec"],
];

/** Seeds THREATFEED with the trusted CTI RSS feeds once (idempotent by FeedURL). */
function seedThreatFeeds(db: Database.Database): void {
  // Idempotent top-up: INSERT OR IGNORE on the UNIQUE FeedURL adds the curated feeds
  // on a fresh setup AND tops up existing DBs with any newly-added feeds.
  let id = (db.prepare("SELECT COALESCE(MAX(ThreatFeedID),0) AS m FROM THREATFEED").get() as { m: number }).m;
  const ins = db.prepare(
    `INSERT OR IGNORE INTO THREATFEED
       (ThreatFeedID, ThreatFeedGUID, ThreatFeedName, FeedURL, SiteURL, Category, Vendor, Enabled, CreatedDate)
     VALUES (?,?,?,?,?,?,?,1,?)`
  );
  const tx = db.transaction(() => {
    for (const [name, url, site, cat, vendor] of TRUSTED_CTI_FEEDS) {
      id += 1;
      ins.run(id, randomUUID(), name, url, site, cat, vendor, nowTs());
    }
  });
  tx();
}

export interface A3mTech { aatId: string; name: string; description: string | null }
export interface A3mMatrix { tactics: { name: string; techniques: A3mTech[] }[] }

/** A3M matrix (Agentic AI Attack Matrix): tactics (matrix order) → AAT-#### techniques. */
export function getA3mMatrix(): A3mMatrix {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='A3MTECHNIQUE'").get())
    return { tactics: [] };
  const tactics = db.prepare("SELECT Name AS name FROM A3MTACTIC ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, Name").all() as { name: string }[];
  const techs = db.prepare("SELECT AATID AS aatId, Name AS name, Description AS description, TacticName AS tac FROM A3MTECHNIQUE ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, AATID").all() as { aatId: string; name: string; description: string | null; tac: string }[];
  const byTactic = new Map<string, A3mTech[]>();
  for (const t of techs) {
    if (!byTactic.has(t.tac)) byTactic.set(t.tac, []);
    byTactic.get(t.tac)!.push({ aatId: t.aatId, name: t.name, description: t.description });
  }
  // Known tactics first (order), then any orphan tactic present in the techniques.
  const ordered = tactics.map((t) => t.name);
  for (const k of byTactic.keys()) if (!ordered.includes(k)) ordered.push(k);
  return { tactics: ordered.map((name) => ({ name, techniques: byTactic.get(name) ?? [] })).filter((t) => t.techniques.length || tactics.some((x) => x.name === t.name)) };
}

export interface MitigantTech { techId: string; title: string; description: string | null; severity: string | null; service: string | null; mitre: string | null; commands: string[]; cloudtrail: string[]; }
export interface MitigantMatrix {
  tactics: { key: string; name: string; mitre: string | null; techniques: MitigantTech[] }[];
  summary: { techniques: number; tactics: number; services: number; bySeverity: Record<string, number> };
}

/** Mitigant Threat Catalog: cloud (AWS) attack tactics (matrix order) → techniques (with AWS CLI commands + CloudTrail events). */
export function getMitigantMatrix(): MitigantMatrix {
  const db = getDb("XTHREAT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='MITIGANTTECHNIQUE'").get())
    return { tactics: [], summary: { techniques: 0, tactics: 0, services: 0, bySeverity: {} } };
  const tactics = db.prepare("SELECT TacticKey AS key, Name AS name, MitreTacticID AS mitre FROM MITIGANTTACTIC ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, Name").all() as { key: string; name: string; mitre: string | null }[];
  const techs = db.prepare("SELECT TechID AS techId, Title AS title, Description AS description, TacticKey AS tac, Severity AS severity, Service AS service, MitreID AS mitre, Commands AS commands, CloudTrail AS cloudtrail FROM MITIGANTTECHNIQUE ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, TechID").all() as { techId: string; title: string; description: string | null; tac: string; severity: string | null; service: string | null; mitre: string | null; commands: string | null; cloudtrail: string | null }[];
  const parse = (s: string | null): string[] => { try { const a = JSON.parse(s || "[]"); return Array.isArray(a) ? a.map(String) : []; } catch { return []; } };
  const byTactic = new Map<string, MitigantTech[]>();
  const services = new Set<string>(); const bySeverity: Record<string, number> = {};
  for (const t of techs) {
    if (!byTactic.has(t.tac)) byTactic.set(t.tac, []);
    byTactic.get(t.tac)!.push({ techId: t.techId, title: t.title, description: t.description, severity: t.severity, service: t.service, mitre: t.mitre, commands: parse(t.commands), cloudtrail: parse(t.cloudtrail) });
    if (t.service) services.add(t.service);
    const sev = String(t.severity || "unknown").toLowerCase(); bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  }
  const known = new Map(tactics.map((t) => [t.key, t] as const));
  const order = tactics.map((t) => t.key);
  for (const k of byTactic.keys()) if (!order.includes(k)) order.push(k);
  const out = order.map((key) => {
    const t = known.get(key);
    return { key, name: t?.name || key.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), mitre: t?.mitre ?? null, techniques: byTactic.get(key) ?? [] };
  }).filter((t) => t.techniques.length || known.has(t.key));
  return { tactics: out, summary: { techniques: techs.length, tactics: out.length, services: services.size, bySeverity } };
}

/**
 * Adapts the existing XTHREAT tables to the characteristic properties of OpenCTI/STIX:
 *  - common properties on entities (SDO): Confidence (0-100), TLP marking, Labels,
 *    CreatedByRef author, ExternalReferences, Revoked, Aliases;
 *  - indicators (IOC): Score (x_opencti_score 0-100), Detection, TLP;
 *  - relationships (SRO): Confidence, TLP, Labels, CreatedByRef;
 *  - SIGHTING table (observation: "X seen by/at Y", counter + time window).
 * Idempotent (ALTER ADD COLUMN if absent; CREATE TABLE IF NOT EXISTS). Called at boot.
 */
/** Admiralty / NATO source-grading scales (STANAG 2511): source reliability A-F, info credibility 1-6. */
export const ADMIRALTY_RELIABILITY: Record<string, string> = {
  A: "A — Completely reliable", B: "B — Usually reliable", C: "C — Fairly reliable",
  D: "D — Not usually reliable", E: "E — Unreliable", F: "F — Reliability cannot be judged",
};
export const ADMIRALTY_CREDIBILITY: Record<string, string> = {
  "1": "1 — Confirmed", "2": "2 — Probably true", "3": "3 — Possibly true",
  "4": "4 — Doubtful", "5": "5 — Improbable", "6": "6 — Cannot be judged",
};

/** Combine an Admiralty source-reliability (A-F) and info-credibility (1-6) into a grade ("B2") and a
 *  0-100 confidence. F / 6 ("cannot be judged") yield no confidence signal. */
export function admiraltyGrade(reliability?: string | null, credibility?: string | null): { grade: string; confidence: number | null; label: string } {
  const r = String(reliability || "").trim().toUpperCase().slice(0, 1);
  const c = String(credibility || "").trim().slice(0, 1);
  const rOk = r.length === 1 && "ABCDEF".includes(r), cOk = c.length === 1 && "123456".includes(c);
  if (!rOk && !cOk) return { grade: "", confidence: null, label: "Ungraded" };
  const grade = `${rOk ? r : "?"}${cOk ? c : "?"}`;
  // A..E -> 5..1, F -> 0 (no judgement); 1..5 -> 5..1, 6 -> 0
  const rScore = r === "F" ? null : rOk ? 5 - "ABCDE".indexOf(r) : null;
  const cScore = c === "6" ? null : cOk ? 6 - Number(c) : null;
  const parts = [rScore, cScore].filter((x): x is number => x !== null);
  const confidence = parts.length ? Math.round((100 * parts.reduce((a, b) => a + b, 0)) / (5 * parts.length)) : null;
  return { grade, confidence, label: `${ADMIRALTY_RELIABILITY[r] || "?"} / ${ADMIRALTY_CREDIBILITY[c] || "?"}` };
}

export function ensureOpenctiColumns(): void {
  const db = getDb("XTHREAT");
  const tableExists = (t: string): boolean =>
    !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  const addCols = (table: string, cols: Record<string, string>): void => {
    if (!tableExists(table)) return;
    const existing = new Set(
      (db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)
    );
    for (const [name, type] of Object.entries(cols)) {
      if (!existing.has(name)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${name}" ${type}`);
    }
  };

  const COMMON: Record<string, string> = {
    Confidence: "INTEGER", TLP: "TEXT", Labels: "TEXT",
    CreatedByRef: "TEXT", ExternalReferences: "TEXT", Revoked: "INTEGER DEFAULT 0",
  };
  for (const t of ["THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKGROUP",
    "ATTACKSOFTWARE", "ATTACKTECHNIQUE", "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "THREATREPORT"]) {
    addCols(t, COMMON);
  }
  // Aliases for the entities that don't already have them (ATTACKGROUP/SOFTWARE have them).
  for (const t of ["THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKTECHNIQUE",
    "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "THREATREPORT"]) {
    addCols(t, { Aliases: "TEXT" });
  }
  addCols("IOC", { TLP: "TEXT", Score: "INTEGER", Detection: "INTEGER DEFAULT 0" });
  addCols("RELATIONSHIP", { Confidence: "INTEGER", TLP: "TEXT", Labels: "TEXT", CreatedByRef: "TEXT" });

  // Workflow status (OpenCTI) on the entities + indicators.
  for (const t of ["THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKGROUP", "ATTACKSOFTWARE",
    "ATTACKTECHNIQUE", "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "IOC", "THREATREPORT"]) {
    addCols(t, { WorkflowStatus: "TEXT" });
  }

  // Admiralty / NATO source-reliability grading on intel exchanges & reports (source A-F x credibility 1-6).
  for (const t of ["INTELEXCHANGE", "THREATREPORT", "THREATACTOR", "THREATCAMPAIGN"]) {
    addCols(t, { SourceReliability: "TEXT", InfoCredibility: "TEXT" });
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS SIGHTING (
      SightingID INTEGER PRIMARY KEY, SightingGUID TEXT, Name TEXT,
      SightingOfRef TEXT, IOCID INTEGER, WhereSightedRef TEXT,
      Count INTEGER DEFAULT 1, FirstSeen DATE, LastSeen DATE,
      Confidence INTEGER, TLP TEXT, Labels TEXT, Negative INTEGER DEFAULT 0,
      Description TEXT, CreatedByRef TEXT, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_sighting_ioc ON SIGHTING(IOCID);
    -- Observables (SCO) + "based-on" relationship indicator↔observable (OpenCTI core).
    CREATE TABLE IF NOT EXISTS OBSERVABLE (
      ObservableID INTEGER PRIMARY KEY, ObservableGUID TEXT, StixID TEXT,
      ObservableType TEXT, Value TEXT, Description TEXT, Labels TEXT, TLP TEXT,
      Score INTEGER, CreatedByRef TEXT, ExternalReferences TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
    CREATE INDEX IF NOT EXISTS ix_observable_type ON OBSERVABLE(ObservableType);
    CREATE TABLE IF NOT EXISTS INDICATOROBSERVABLE (
      IndicatorObservableID INTEGER PRIMARY KEY, IOCID INTEGER, ObservableID INTEGER,
      Relationship TEXT DEFAULT 'based-on', Confidence INTEGER, CreatedDate DATE,
      UNIQUE(IOCID, ObservableID));
    CREATE INDEX IF NOT EXISTS ix_indobs_ioc ON INDICATOROBSERVABLE(IOCID);
    CREATE INDEX IF NOT EXISTS ix_indobs_obs ON INDICATOROBSERVABLE(ObservableID);
  `);
}

/**
 * Adversary emulation / security validation module (BAS — like AttackIQ,
 * SafeBreach, Cymulate, OpenBAS/OpenAEV):
 *  - EMULATIONSCENARIO : emulation plan (linked to an adversary, kill-chain phase).
 *  - ATOMICTEST        : ATT&CK-mapped atomic test (Atomic Red Team / Caldera style).
 *  - SCENARIOTEST      : ordered tests of a scenario (the "injects").
 *  - EMULATIONRUN      : execution/evaluation of a scenario on a target.
 *  - EMULATIONRESULT   : result per test (Prevented/Detected/Logged/…) = control validation.
 * Idempotent (CREATE IF NOT EXISTS). Called at boot.
 */
export function ensureEmulationTables(): void {
  const db = getDb("XTHREAT");
  db.exec(`
    CREATE TABLE IF NOT EXISTS EMULATIONSCENARIO (
      ScenarioID INTEGER PRIMARY KEY, ScenarioGUID TEXT, Name TEXT, Description TEXT,
      AdversaryRef TEXT, KillChainPhase TEXT, Status TEXT,
      Confidence INTEGER, TLP TEXT, Labels TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
    CREATE TABLE IF NOT EXISTS ATOMICTEST (
      AtomicTestID INTEGER PRIMARY KEY, AtomicGUID TEXT UNIQUE, Name TEXT, Description TEXT,
      AttackID TEXT, AttackTechniqueID INTEGER, Platform TEXT, Executor TEXT,
      Command TEXT, Cleanup TEXT, Source TEXT, ExternalReferences TEXT, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_atomic_attack ON ATOMICTEST(AttackID);
    CREATE TABLE IF NOT EXISTS SCENARIOTEST (
      ScenarioTestID INTEGER PRIMARY KEY, ScenarioID INTEGER, AtomicTestID INTEGER,
      StepOrder INTEGER, CreatedDate DATE, UNIQUE(ScenarioID, AtomicTestID));
    CREATE TABLE IF NOT EXISTS EMULATIONRUN (
      RunID INTEGER PRIMARY KEY, RunGUID TEXT, ScenarioID INTEGER, Name TEXT,
      TargetAssetID INTEGER, Status TEXT, RunDate DATE, Score INTEGER, CreatedDate DATE);
    CREATE TABLE IF NOT EXISTS EMULATIONRESULT (
      EmulationResultID INTEGER PRIMARY KEY, RunID INTEGER, AtomicTestID INTEGER,
      AttackID TEXT, Outcome TEXT, DetectedBy TEXT, Notes TEXT, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_emresult_run ON EMULATIONRESULT(RunID);
    CREATE INDEX IF NOT EXISTS ix_emresult_attack ON EMULATIONRESULT(AttackID);
  `);
}

interface AttackCoverage { tests: number; detected: number; prevented: number; status: string }

/**
 * Validation coverage per ATT&CK technique (BAS heatmap): number of atomic tests
 * and emulation results (prevented/detected) per AttackID. status = prevented >
 * detected > tested. Keys = AttackID (techniques AND sub-techniques); the client aggregates.
 */
export function getAttackCoverage(): { byAttackId: Record<string, AttackCoverage> } {
  const db = getDb("XTHREAT");
  const has = (t: string): boolean => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  const out: Record<string, AttackCoverage> = {};
  const ensure = (k: string): AttackCoverage => (out[k] ||= { tests: 0, detected: 0, prevented: 0, status: "" });
  if (has("ATOMICTEST")) {
    for (const r of db.prepare("SELECT AttackID AS aid, COUNT(*) AS c FROM ATOMICTEST WHERE AttackID IS NOT NULL AND AttackID<>'' GROUP BY AttackID").all() as { aid: string; c: number }[]) {
      ensure(String(r.aid)).tests = r.c;
    }
  }
  if (has("EMULATIONRESULT")) {
    for (const r of db.prepare("SELECT AttackID AS aid, Outcome AS o, COUNT(*) AS c FROM EMULATIONRESULT WHERE AttackID IS NOT NULL AND AttackID<>'' GROUP BY AttackID, Outcome").all() as { aid: string; o: string; c: number }[]) {
      const v = ensure(String(r.aid));
      const o = String(r.o || "").toLowerCase();
      if (/prevent|block/.test(o)) v.prevented += r.c;
      else if (/detect|alert|logg/.test(o)) v.detected += r.c;
    }
  }
  for (const v of Object.values(out)) v.status = v.prevented ? "prevented" : v.detected ? "detected" : v.tests ? "tested" : "";
  return { byAttackId: out };
}

// ── LLM ATT&CK Navigator (Anthropic) — AI-enablement layer over ATT&CK ────────
const LLM_ATTACK_META = {
  source: "https://red.anthropic.com/2026/attack-navigator/",
  accounts: 832, observations: 13873, subtechniques: 482,
  version: "MITRE ATT&CK v18 (Enterprise + Mobile)",
  window: "Mar 2025 – Mar 2026",
  aries: "AI Risk Enablement Score (ARiES) 0–100 = Threat (0–35) + Vulnerability (0–35) + Impact (0–30)",
};
export interface LlmAttackTech { name: string; tactic: string; actorCount: number | null; prevalence: number | null; ariesMean: number | null }

/**
 * The Anthropic "LLM ATT&CK Navigator" as a per-technique AI-enablement layer
 * (XTHREAT.LLMATTACKTECHNIQUE, seeded by import_llm_attack.py). Keyed by AttackID
 * so the /attack matrix can overlay it (prevalence heatmap). Empty if not imported.
 */
export function getLlmAttackLayer(): {
  byAttackId: Record<string, LlmAttackTech>; techniques: number; maxPrevalence: number; meta: typeof LLM_ATTACK_META;
} {
  const db = getDb("XTHREAT");
  const out: Record<string, LlmAttackTech> = {};
  let max = 0;
  try {
    for (const r of db.prepare(
      "SELECT AttackID, Name, TacticName, ActorCount, PrevalencePct, AriesMean FROM LLMATTACKTECHNIQUE"
    ).all() as { AttackID: string; Name: string; TacticName: string; ActorCount: number | null; PrevalencePct: number | null; AriesMean: number | null }[]) {
      out[r.AttackID] = { name: r.Name, tactic: r.TacticName, actorCount: r.ActorCount, prevalence: r.PrevalencePct, ariesMean: r.AriesMean };
      if (r.PrevalencePct && r.PrevalencePct > max) max = r.PrevalencePct;
    }
  } catch { /* table absent — run import_llm_attack.py */ }
  return { byAttackId: out, techniques: Object.keys(out).length, maxPrevalence: max, meta: LLM_ATTACK_META };
}

// ── BIA dependency graph (XORCISM.BIADEPENDENCY between BIAENTRY rows) ─────────
/** Idempotent: directed dependency edges between BIA entries within a BIA audit. */
export function ensureBiaDependency(): void {
  const db = getDb("XORCISM");
  db.exec(`CREATE TABLE IF NOT EXISTS BIADEPENDENCY (
    BIADependencyID INTEGER PRIMARY KEY,
    BIAAuditID INTEGER, FromEntryID INTEGER, ToEntryID INTEGER,
    DependencyType TEXT, Notes TEXT, CreatedDate TEXT, TenantID INTEGER)`);
  db.exec("CREATE INDEX IF NOT EXISTS ix_biadep_audit ON BIADEPENDENCY(BIAAuditID)");
}

export interface BiaNode {
  id: number; label: string; type: string; criticality: string; rto: string; rpo: string; mtd: string;
  riskLevel: string; owner: string; impacts: { fin: string; ops: string; legal: string; rep: string };
}
export interface BiaLink { id: number; source: number; target: number; type: string }

/**
 * Dependency graph for one BIA audit: nodes = BIA entries (assets/processes,
 * with criticality + RTO/RPO/MTD + impact), edges = BIADEPENDENCY (From depends
 * on To). Tenant-scoped via the parent audit. Empty if the audit isn't visible.
 */
export function biaDependencyGraph(tenant: number | null, auditId: number): {
  audit: { BIAAuditID: number; BIAAuditName: string } | null; nodes: BiaNode[]; links: BiaLink[];
} {
  const db = getDb("XORCISM");
  ensureBiaDependency();
  const aWhere = ["BIAAuditID = ?"]; const aArgs: number[] = [auditId];
  if (tenant != null && tableHasTenantCol("XORCISM", "BIAAUDIT")) {
    aWhere.push(`("${TENANT_COL}" = ? OR "${TENANT_COL}" IS NULL)`); aArgs.push(tenant);
  }
  const audit = db.prepare(`SELECT BIAAuditID, BIAAuditName FROM BIAAUDIT WHERE ${aWhere.join(" AND ")}`)
    .get(...aArgs) as { BIAAuditID: number; BIAAuditName: string } | undefined;
  if (!audit) return { audit: null, nodes: [], links: [] };

  const nodes = (db.prepare(
    `SELECT BIAEntryID, AssetName, AssetType, CriticalityLevel, RTO, RPO, MTD, RiskLevel, OwnerName,
            ImpactFinancial, ImpactOperational, ImpactLegal, ImpactReputational
     FROM BIAENTRY WHERE BIAAuditID = ? ORDER BY BIAEntryID`
  ).all(auditId) as Record<string, unknown>[]).map((r) => ({
    id: Number(r.BIAEntryID), label: String(r.AssetName || `Entry #${r.BIAEntryID}`), type: String(r.AssetType || ""),
    criticality: String(r.CriticalityLevel || ""), rto: String(r.RTO ?? ""), rpo: String(r.RPO ?? ""), mtd: String(r.MTD ?? ""),
    riskLevel: String(r.RiskLevel || ""), owner: String(r.OwnerName || ""),
    impacts: { fin: String(r.ImpactFinancial || ""), ops: String(r.ImpactOperational || ""), legal: String(r.ImpactLegal || ""), rep: String(r.ImpactReputational || "") },
  }));
  const ids = new Set(nodes.map((n) => n.id));
  const links = (db.prepare(
    "SELECT BIADependencyID, FromEntryID, ToEntryID, DependencyType FROM BIADEPENDENCY WHERE BIAAuditID = ?"
  ).all(auditId) as Record<string, unknown>[])
    .filter((r) => ids.has(Number(r.FromEntryID)) && ids.has(Number(r.ToEntryID)))
    .map((r) => ({ id: Number(r.BIADependencyID), source: Number(r.FromEntryID), target: Number(r.ToEntryID), type: String(r.DependencyType || "depends-on") }));
  return { audit, nodes, links };
}

// ── Kill chain graph (ATT&CK tactics as ordered phases + an adversary's TTPs) ──
export interface KcTech { attackId: string; name: string }
export interface KcPhase { order: number; attackId: string; name: string; shortName: string; url: string; total: number; used: KcTech[] }

/** ATT&CK groups (intrusion sets) that have at least one "uses" technique — the kill-chain overlay sources. */
export function killChainGroups(): { attackId: string; name: string }[] {
  const db = getDb("XTHREAT");
  try {
    return db.prepare(
      `SELECT g.AttackID AS attackId, g.Name AS name FROM ATTACKGROUP g
       WHERE COALESCE(g.Deprecated,0)=0 AND g.StixID IN
         (SELECT DISTINCT SourceStixID FROM ATTACKRELATIONSHIP WHERE RelationshipType='uses')
       ORDER BY g.Name`
    ).all() as { attackId: string; name: string }[];
  } catch { return []; }
}

/**
 * Kill chain: the enterprise ATT&CK tactics in matrix order (the phases of the
 * kill chain) with the techniques an adversary (ATT&CK group) employs in each.
 * `groupRef` = a group AttackID (e.g. "G0016") or StixID; omitted = the empty
 * backbone (phases + total technique counts only).
 */
export function killChainGraph(groupRef?: string | null): {
  phases: KcPhase[]; group: { attackId: string; name: string; description: string } | null;
  coverage: { covered: number; total: number; techniques: number };
} {
  const db = getDb("XTHREAT");
  const tactics = db.prepare(
    "SELECT AttackTacticID, AttackID, Name, ShortName, MatrixOrder, URL FROM ATTACKTACTIC WHERE Domain='enterprise' ORDER BY MatrixOrder"
  ).all() as { AttackTacticID: number; AttackID: string; Name: string; ShortName: string; MatrixOrder: number; URL: string }[];
  const totals = new Map<number, number>();
  for (const r of db.prepare(
    "SELECT AttackTacticID aid, COUNT(DISTINCT AttackTechniqueID) c FROM ATTACKTECHNIQUETACTIC WHERE Domain='enterprise' GROUP BY AttackTacticID"
  ).all() as { aid: number; c: number }[]) totals.set(r.aid, r.c);

  const used = new Map<number, KcTech[]>();
  let group: { attackId: string; name: string; description: string } | null = null;
  let techCount = 0;
  if (groupRef) {
    const g = db.prepare("SELECT StixID, AttackID, Name, Description FROM ATTACKGROUP WHERE AttackID=? OR StixID=?")
      .get(groupRef, groupRef) as { StixID: string; AttackID: string; Name: string; Description: string } | undefined;
    if (g) {
      group = { attackId: g.AttackID, name: g.Name, description: String(g.Description || "").slice(0, 600) };
      const rows = db.prepare(
        `SELECT DISTINCT tt.AttackTacticID tac, te.AttackID tid, te.Name tname
         FROM ATTACKRELATIONSHIP r
         JOIN ATTACKTECHNIQUE te ON te.StixID = r.TargetStixID
         JOIN ATTACKTECHNIQUETACTIC tt ON tt.AttackTechniqueID = te.AttackTechniqueID
         JOIN ATTACKTACTIC ta ON ta.AttackTacticID = tt.AttackTacticID AND ta.Domain='enterprise'
         WHERE r.RelationshipType='uses' AND r.SourceStixID = ? ORDER BY te.AttackID`
      ).all(g.StixID) as { tac: number; tid: string; tname: string }[];
      const seen = new Set<string>();
      for (const r of rows) {
        (used.get(r.tac) || used.set(r.tac, []).get(r.tac)!).push({ attackId: r.tid, name: r.tname });
        if (!seen.has(r.tid)) { seen.add(r.tid); techCount++; }
      }
    }
  }
  const phases: KcPhase[] = tactics.map((t) => ({
    order: t.MatrixOrder, attackId: t.AttackID, name: t.Name, shortName: t.ShortName, url: t.URL,
    total: totals.get(t.AttackTacticID) || 0, used: used.get(t.AttackTacticID) || [],
  }));
  return { phases, group, coverage: { covered: phases.filter((p) => p.used.length).length, total: phases.length, techniques: techCount } };
}

/**
 * Advanced GRC: extends the existing GRC base (XCOMPLIANCE risk register / audit findings,
 * XORCISM policies) without duplicating it.
 *  - CRQ / FAIR: monetary quantification of risk (frequency × loss → ALE).
 *  - Remediation workflow on the audit findings.
 *  - Policy lifecycle (status, version, owner, effective/review dates).
 * Idempotent (ALTER ADD COLUMN if absent). Called at boot.
 */
/**
 * Core ASSET business fields added on top of the base schema. Idempotent
 * (ALTER ADD COLUMN only if absent); called at boot so existing and fresh DBs
 * both get the column. BusinessValue = ordinal/numeric business importance of
 * the asset (distinct from the monetary FinancialValue).
 */
export function ensureAssetColumns(): void {
  const db = getDb("XORCISM");
  // ASSET ↔ CONTROL mapping: which security controls apply to which asset.
  // Tenant-isolated (XORCISM.ASSETCONTROL in TENANT_SCOPED_TABLES; TenantID added
  // by ensureTenantColumns) + a GUID for STIX/cross-system identity.
  db.exec(`CREATE TABLE IF NOT EXISTS "ASSETCONTROL" (
    "AssetControlID" INTEGER PRIMARY KEY,
    "AssetControlGUID" TEXT,
    "AssetID" INTEGER,
    "ControlID" INTEGER,
    "CreatedDate" DATE,
    "PersonID" INTEGER,
    "Status" TEXT,
    "ValidFrom" DATE,
    "ValidUntil" DATE,
    "ConfidenceLevel" TEXT,
    "ConfidenceReasonID" INTEGER,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_assetcontrol_asset ON "ASSETCONTROL"("AssetID");
  CREATE INDEX IF NOT EXISTS ix_assetcontrol_control ON "ASSETCONTROL"("ControlID");`);
  // Idempotent adds for an ASSETCONTROL created before GUID/TenantID existed.
  {
    const acCols = new Set((db.prepare(`PRAGMA table_info("ASSETCONTROL")`).all() as { name: string }[]).map((c) => c.name));
    if (!acCols.has("AssetControlGUID")) db.exec(`ALTER TABLE "ASSETCONTROL" ADD COLUMN "AssetControlGUID" TEXT`);
    if (!acCols.has("TenantID")) db.exec(`ALTER TABLE "ASSETCONTROL" ADD COLUMN "TenantID" INTEGER`);
  }

  // BACKUPPLAN — define/manage a backup & recovery plan for an ASSET (referenced by
  // ASSET.BackupPlanID). Tenant-isolated (in TENANT_SCOPED_TABLES) + a GUID. Captures
  // the plan type (Manual/Automated…), schedule (Frequency + unit), retention, storage,
  // recovery objectives (RPO/RTO) and the last run / last test.
  db.exec(`CREATE TABLE IF NOT EXISTS "BACKUPPLAN" (
    "BackupPlanID" INTEGER PRIMARY KEY,
    "BackupPlanGUID" TEXT,
    "BackupPlanName" TEXT,
    "Description" TEXT,
    "AssetID" INTEGER,
    "Type" TEXT,
    "Frequency" INTEGER,
    "FrequencyUnit" TEXT,
    "LastRun" DATE,
    "LastTested" DATE,
    "RetentionDays" INTEGER,
    "StorageLocation" TEXT,
    "RPOHours" REAL,
    "RTOHours" REAL,
    "PersonID" INTEGER,
    "Status" TEXT,
    "CreatedDate" DATE,
    "ValidFrom" DATE,
    "ValidUntil" DATE,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_backupplan_asset ON "BACKUPPLAN"("AssetID");`);
  // BACKUPTEST — a log of backup/restore TEST runs against a BACKUPPLAN (manage backup testing):
  // each row records a test (restore / integrity / failover / recovery drill), its result, the RTO/RPO
  // actually achieved, and when the next test is due. Schema-driven CRUD via the explorer.
  db.exec(`CREATE TABLE IF NOT EXISTS "BACKUPTEST" (
    "BackupTestID" INTEGER PRIMARY KEY,
    "BackupTestGUID" TEXT,
    "BackupPlanID" INTEGER,
    "AssetID" INTEGER,
    "TestDate" DATE,
    "TestType" TEXT,
    "Result" TEXT,
    "RTOAchievedHours" REAL,
    "RPOAchievedHours" REAL,
    "DataIntegrityVerified" INTEGER,
    "TestedByPersonID" INTEGER,
    "Findings" TEXT,
    "NextTestDue" DATE,
    "Notes" TEXT,
    "CreatedDate" DATE,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_backuptest_plan ON "BACKUPTEST"("BackupPlanID");
  CREATE INDEX IF NOT EXISTS ix_backuptest_tenant ON "BACKUPTEST"("TenantID");`);
  // Idempotent adds for a BACKUPPLAN created before the management fields existed.
  {
    const have = new Set((db.prepare(`PRAGMA table_info("BACKUPPLAN")`).all() as { name: string }[]).map((c) => c.name));
    const want: Record<string, string> = {
      BackupPlanGUID: "TEXT", BackupPlanName: "TEXT", Description: "TEXT", Type: "TEXT",
      Frequency: "INTEGER", FrequencyUnit: "TEXT", LastRun: "DATE", LastTested: "DATE",
      RetentionDays: "INTEGER", StorageLocation: "TEXT", RPOHours: "REAL", RTOHours: "REAL", TenantID: "INTEGER",
    };
    for (const [n, t] of Object.entries(want)) if (!have.has(n)) db.exec(`ALTER TABLE "BACKUPPLAN" ADD COLUMN "${n}" ${t}`);
  }
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSET'").get()) return;
  const existing = new Set(
    (db.prepare(`PRAGMA table_info("ASSET")`).all() as { name: string }[]).map((c) => c.name)
  );
  const cols: Record<string, string> = {
    BusinessValue: "INTEGER",
    Backed: "INTEGER",        // backed up? boolean (0/1)
    BackupPlanID: "INTEGER",  // FK-style reference to a backup plan
    MFAEnabled: "INTEGER",    // multi-factor auth implemented on this asset? boolean (0/1)
  };
  for (const [n, t] of Object.entries(cols)) {
    if (!existing.has(n)) db.exec(`ALTER TABLE "ASSET" ADD COLUMN "${n}" ${t}`);
  }
  // ASSETVULNERABILITY: FalsePositive flag (0/1) + CVE-match provenance (confidence/source/token) — idempotent.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get()) {
    const avCols = new Set(
      (db.prepare(`PRAGMA table_info("ASSETVULNERABILITY")`).all() as { name: string }[]).map((c) => c.name)
    );
    if (!avCols.has("FalsePositive")) db.exec(`ALTER TABLE "ASSETVULNERABILITY" ADD COLUMN "FalsePositive" INTEGER DEFAULT 0`);
    // CVE→asset auto-match provenance (lets users audit/triage keyword vs CPE matches and tune precision).
    if (!avCols.has("MatchConfidence")) db.exec(`ALTER TABLE "ASSETVULNERABILITY" ADD COLUMN "MatchConfidence" TEXT`); // High|Medium|Low
    if (!avCols.has("MatchSource")) db.exec(`ALTER TABLE "ASSETVULNERABILITY" ADD COLUMN "MatchSource" TEXT`);         // cpe|cpe-pair|cpe-keyword|tag
    if (!avCols.has("MatchedToken")) db.exec(`ALTER TABLE "ASSETVULNERABILITY" ADD COLUMN "MatchedToken" TEXT`);       // the token/CPE that matched
  }
  // ASSETFORORGANISATION.Relationship (free text describing the asset↔org relationship) — idempotent.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETFORORGANISATION'").get()) {
    const afoCols = new Set(
      (db.prepare(`PRAGMA table_info("ASSETFORORGANISATION")`).all() as { name: string }[]).map((c) => c.name)
    );
    if (!afoCols.has("Relationship")) {
      db.exec(`ALTER TABLE "ASSETFORORGANISATION" ADD COLUMN "Relationship" TEXT`);
    }
  }
}

/**
 * Make XORCISM.ASSET.AssetID a real INTEGER PRIMARY KEY. The legacy table ships AssetID as
 * `INTEGER NOT NULL` WITHOUT a primary key, so it is not a rowid alias and SQLite won't
 * auto-assign it on INSERT (the "NOT NULL constraint failed: ASSET.AssetID" quirk shared with
 * CPE/CPEFORASSET/COMPONENT). SQLite can't add a PK via ALTER, so this rebuilds the table:
 * recreate ASSET with the same columns (AssetID → PRIMARY KEY), copy all rows, drop, rename and
 * recreate the indexes — inside one transaction. Idempotent: a no-op once AssetID is already a PK.
 * Must run AFTER ensureAssetColumns() so the rebuilt table includes every added column.
 */
export function ensureAssetPrimaryKey(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  const info = db.prepare(`PRAGMA table_info("ASSET")`).all() as { name: string; pk: number }[];
  if (!info.length) return;                                   // table absent
  if (info.some((c) => c.name === "AssetID" && c.pk > 0)) return; // already a PK → done
  const ddl = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='ASSET'").get() as { sql: string } | undefined;
  if (!ddl?.sql) return;
  const idx = (db.prepare("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='ASSET' AND sql IS NOT NULL").all() as { sql: string }[]).map((r) => r.sql);
  const newSql = ddl.sql
    .replace(/CREATE TABLE\s+"?ASSET"?/i, 'CREATE TABLE "ASSET_pkmig"')
    .replace(/"AssetID"\s+INTEGER\s+NOT\s+NULL\s*,/i, '"AssetID" INTEGER PRIMARY KEY,');
  if (!newSql.includes("ASSET_pkmig") || !/"AssetID"\s+INTEGER\s+PRIMARY\s+KEY/i.test(newSql)) {
    console.warn("[db] ensureAssetPrimaryKey: could not transform ASSET DDL — left unchanged");
    return;
  }
  db.pragma("foreign_keys = OFF");
  try {
    const rebuild = db.transaction(() => {
      db.exec(newSql);
      db.exec('INSERT INTO "ASSET_pkmig" SELECT * FROM "ASSET"');
      db.exec('DROP TABLE "ASSET"');
      db.exec('ALTER TABLE "ASSET_pkmig" RENAME TO "ASSET"');
      for (const i of idx) db.exec(i);
    });
    rebuild();
    console.log("[db] ASSET.AssetID is now a PRIMARY KEY (table rebuilt, data preserved)");
  } catch (e) {
    console.warn(`[db] ensureAssetPrimaryKey failed: ${(e as Error).message}`);
  } finally {
    db.pragma("foreign_keys = ON");
  }
}

/**
 * OVAL scan results — the XOR agent's OpenSCAP (`oscap oval eval`) verdicts.
 * The native OVAL "results" model tables (XOVAL.OVALRESULTS / OVALRESULTSTYPE) are
 * skeletal EF scaffolds (no asset/definition granularity), so we EXTEND OVALRESULTS
 * into a usable per-(asset × definition) verdict row and seed the OVAL result-value
 * enum. Each row keeps the OVAL definition id-pattern + its class (vulnerability /
 * inventory / compliance / patch) so results can be sliced per asset/class/date.
 * Idempotent (CREATE table if the whole XOVAL schema is missing + conditional ALTER).
 */
export function ensureOvalScanTables(): void {
  let db: Database.Database;
  try { db = getDb("XOVAL"); } catch { return; }
  // Create OVALRESULTS if the XOVAL schema was never built (fresh install).
  db.exec(`CREATE TABLE IF NOT EXISTS "OVALRESULTS" (
    "OVALResultsID" INTEGER PRIMARY KEY, "GeneratorTypeID" INTEGER, "OVALDefaultDirectivesID" INTEGER,
    "OVALDefinitionsID" INTEGER, "OVALResultsTypeID" INTEGER, "signature" TEXT
  );`);
  const rc = new Set((db.prepare(`PRAGMA table_info("OVALRESULTS")`).all() as { name: string }[]).map((c) => c.name));
  const want: Record<string, string> = {
    AssetID: "INTEGER", OVALDefinitionID: "INTEGER", OVALDefinitionIDPattern: "TEXT",
    ResultValue: "TEXT", ClassValue: "TEXT", Title: "TEXT", Severity: "TEXT",
    ScanDate: "DATE", AgentName: "TEXT", TenantID: "INTEGER",
  };
  for (const [n, t] of Object.entries(want)) if (!rc.has(n)) db.exec(`ALTER TABLE "OVALRESULTS" ADD COLUMN "${n}" ${t}`);
  db.exec(`CREATE INDEX IF NOT EXISTS ix_ovalresults_asset ON "OVALRESULTS"("AssetID");
           CREATE INDEX IF NOT EXISTS ix_ovalresults_scan ON "OVALRESULTS"("ScanDate");
           CREATE INDEX IF NOT EXISTS ix_ovalresults_class ON "OVALRESULTS"("ClassValue");`);

  // Seed the OVAL result-value enum (oval-results-5 ResultEnumeration).
  db.exec(`CREATE TABLE IF NOT EXISTS "OVALRESULTSTYPE" ("OVALResultsTypeId" INTEGER PRIMARY KEY);`);
  const tc = new Set((db.prepare(`PRAGMA table_info("OVALRESULTSTYPE")`).all() as { name: string }[]).map((c) => c.name));
  if (!tc.has("ResultValue")) db.exec(`ALTER TABLE "OVALRESULTSTYPE" ADD COLUMN "ResultValue" TEXT`);
  const RESULT_VALUES = ["true", "false", "error", "unknown", "not evaluated", "not applicable"];
  const have = new Set((db.prepare(`SELECT ResultValue FROM OVALRESULTSTYPE WHERE ResultValue IS NOT NULL`).all() as { ResultValue: string }[]).map((r) => r.ResultValue));
  let nextId = (db.prepare(`SELECT COALESCE(MAX(OVALResultsTypeId),0) m FROM OVALRESULTSTYPE`).get() as { m: number }).m;
  const ins = db.prepare(`INSERT INTO OVALRESULTSTYPE (OVALResultsTypeId, ResultValue) VALUES (?, ?)`);
  for (const v of RESULT_VALUES) if (!have.has(v)) ins.run(++nextId, v);
}

/**
 * Identity & Access Management (IAM) registry — XORCISM.IDENTITY + the
 * XORCISM.IDENTITYPERSON junction. One inventory for BOTH human identities
 * (mapped to PERSON via IDENTITYPERSON) and non-human identities / NHI
 * (AI agents, APIs, containers, service accounts, hardcoded credentials,
 * certificates, devices, workloads…). Non-human identities can bind to a
 * host ASSET (AssetID) and are made accountable through an OwnerPersonID.
 * Tenant-isolated (both tables in TENANT_SCOPED_TABLES) + GUIDs for
 * cross-system identity. Idempotent: CREATE IF NOT EXISTS + conditional ALTER.
 */
export function ensureIdentityTables(): void {
  const db = getDb("XORCISM");
  db.exec(`CREATE TABLE IF NOT EXISTS "IDENTITY" (
    "IdentityID" INTEGER PRIMARY KEY,
    "IdentityGUID" TEXT,
    "IdentityName" TEXT,
    "IdentityType" TEXT,
    "IdentityClass" TEXT,
    "Description" TEXT,
    "Status" TEXT,
    "OwnerPersonID" INTEGER,
    "AssetID" INTEGER,
    "Provider" TEXT,
    "ExternalID" TEXT,
    "PrivilegeLevel" TEXT,
    "Environment" TEXT,
    "CredentialType" TEXT,
    "MFAEnabled" TEXT,
    "LastRotatedDate" DATE,
    "ExpiryDate" DATE,
    "LastUsedDate" DATE,
    "RiskLevel" TEXT,
    "CreatedDate" DATE,
    "ModifiedDate" DATE,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_identity_owner ON "IDENTITY"("OwnerPersonID");
  CREATE INDEX IF NOT EXISTS ix_identity_asset ON "IDENTITY"("AssetID");
  CREATE INDEX IF NOT EXISTS ix_identity_type ON "IDENTITY"("IdentityType");

  CREATE TABLE IF NOT EXISTS "IDENTITYPERSON" (
    "IdentityPersonID" INTEGER PRIMARY KEY,
    "IdentityPersonGUID" TEXT,
    "IdentityID" INTEGER,
    "PersonID" INTEGER,
    "RelationshipType" TEXT,
    "CreatedDate" DATE,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_identityperson_identity ON "IDENTITYPERSON"("IdentityID");
  CREATE INDEX IF NOT EXISTS ix_identityperson_person ON "IDENTITYPERSON"("PersonID");`);

  // Idempotent adds for tables created before a column existed.
  const addCols = (table: string, cols: Record<string, string>): void => {
    const have = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(cols)) if (!have.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  addCols("IDENTITY", {
    IdentityGUID: "TEXT", IdentityClass: "TEXT", Status: "TEXT", OwnerPersonID: "INTEGER", AssetID: "INTEGER",
    Provider: "TEXT", ExternalID: "TEXT", PrivilegeLevel: "TEXT", Environment: "TEXT", CredentialType: "TEXT",
    MFAEnabled: "TEXT", LastRotatedDate: "DATE", ExpiryDate: "DATE", LastUsedDate: "DATE", RiskLevel: "TEXT",
    ModifiedDate: "DATE", TenantID: "INTEGER",
  });
  addCols("IDENTITYPERSON", { IdentityPersonGUID: "TEXT", RelationshipType: "TEXT", TenantID: "INTEGER" });
}

/**
 * Core VULNERABILITY columns added on top of the base schema. Idempotent
 * (ALTER ADD COLUMN only if absent); called at boot so existing and fresh DBs
 * both get the column. EPSS = Exploit Prediction Scoring System probability (0–1).
 */
export function ensureVulnerabilityColumns(): void {
  const db = getDb("XVULNERABILITY");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='VULNERABILITY'").get()) return;
  const existing = new Set(
    (db.prepare(`PRAGMA table_info("VULNERABILITY")`).all() as { name: string }[]).map((c) => c.name)
  );
  const cols: Record<string, string> = {
    EPSS: "REAL", FalsePositive: "INTEGER DEFAULT 0",
    // SSVC (CISA Stakeholder-Specific Vulnerability Categorization) — the 4 decision
    // points + the computed CISA-level decision (Track / Track* / Attend / Act) + vector.
    SsvcExploitation: "TEXT", SsvcAutomatable: "TEXT", SsvcTechnicalImpact: "TEXT",
    SsvcMissionWellbeing: "TEXT", SsvcDecision: "TEXT", SsvcVector: "TEXT", SsvcDecisionDate: "DATE",
    // ENISA EU Vulnerability Database (EUVD, NIS2) cross-reference: the EUVD-YYYY-NNNNN id
    // and its public page URL. Populated by the `euvd` connector (runner.import_euvd).
    EUVDId: "TEXT", EUVDUrl: "TEXT",
  };
  for (const [n, t] of Object.entries(cols)) {
    if (!existing.has(n)) db.exec(`ALTER TABLE "VULNERABILITY" ADD COLUMN "${n}" ${t}`);
  }
  try { db.exec(`CREATE INDEX IF NOT EXISTS ix_vuln_euvd ON "VULNERABILITY"("EUVDId")`); } catch { /* index best-effort */ }
}

/**
 * Sensitivity / data-classification labels on DOCUMENT records. Builds on the existing
 * `Classification` field (Public / Internal / Confidential / Restricted) — adding it to the
 * general XORCISM.DOCUMENT (the GRC XCOMPLIANCE.DOCUMENT already has it) — and adds a `TLP`
 * sharing marker (Traffic Light Protocol 2.0) to both. Idempotent; called at boot. The allowed
 * values + colours live client-side (app.ts STATIC_DATALIST_* / GRID_VALUE_COLORS).
 */
/**
 * Org-chart + directory fields on PERSON, aligned with Microsoft Entra ID / Active Directory
 * attributes so an imported directory can drive an org chart. Adds the manager edge
 * (ManagerPersonID, self-referential) + the common Graph/AD user attributes. Idempotent; boot.
 */
/**
 * Security-awareness training + phishing-simulation schema (KnowBe4-style). Reuses the legacy
 * TRAINING (course catalogue) + TRAININGFORPERSON (enrollment), enriching them, and adds
 * PHISHINGSIMULATION (campaigns) + PHISHINGRESULT (per-recipient sent/opened/clicked/reported).
 * Idempotent; called at boot.
 */
export function ensureAwarenessTables(): void {
  const db = getDb("XORCISM");
  const addCols = (table: string, cols: Record<string, string>): void => {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return;
    const existing = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(cols)) if (!existing.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS PHISHINGSIMULATION (
        PhishingSimulationID INTEGER PRIMARY KEY, PhishingSimulationGUID TEXT,
        Name TEXT, Theme TEXT, Template TEXT, Difficulty TEXT, Status TEXT, Description TEXT,
        LandingPageURL TEXT, SentDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS PHISHINGRESULT (
        PhishingResultID INTEGER PRIMARY KEY, PhishingSimulationID INTEGER, PersonID INTEGER,
        Sent INTEGER DEFAULT 1, Opened INTEGER DEFAULT 0, Clicked INTEGER DEFAULT 0,
        SubmittedData INTEGER DEFAULT 0, ReportedPhish INTEGER DEFAULT 0,
        DateSent TEXT, DateClicked TEXT, DateReported TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_phishresult_sim ON PHISHINGRESULT(PhishingSimulationID);
      CREATE INDEX IF NOT EXISTS ix_phishresult_person ON PHISHINGRESULT(PersonID);
      CREATE INDEX IF NOT EXISTS ix_phishsim_tenant ON PHISHINGSIMULATION(TenantID);`);
    addCols("TRAINING", { Category: "TEXT", DurationMinutes: "INTEGER", Provider: "TEXT", ContentURL: "TEXT", Required: "INTEGER DEFAULT 0", PassingScore: "INTEGER", TenantID: "INTEGER", CreatedDate: "TEXT" });
    addCols("TRAININGFORPERSON", { Score: "INTEGER", DueDate: "TEXT", AssignedDate: "TEXT" });
  } catch { /* best-effort */ }
}

/**
 * Multi-engine malware scan store (XMALWARE) — a normalized scan record (MALWARESCAN) with one row
 * per engine queried (MALWARESCANENGINE: VirusTotal / ANY.RUN / Kaspersky OpenTIP / Avira /
 * FortiGuard / Jotti …). Targets are hashes / URLs / domains / IPs / DOCUMENT blobs; results feed
 * CTI (links to XTHREAT.OBSERVABLE) and the DOCUMENT register (XORCISM.DOCUMENT).
 */
export function ensureMalwareScanTables(): void {
  try {
    const db = getDb("XMALWARE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS MALWARESCAN (
        ScanID INTEGER PRIMARY KEY, ScanGUID TEXT,
        Target TEXT, TargetType TEXT, Md5 TEXT, Sha1 TEXT, Sha256 TEXT,
        DocumentID INTEGER, ObservableID INTEGER,
        Verdict TEXT, Score INTEGER, Positives INTEGER, Total INTEGER,
        EnginesQueried INTEGER, EnginesLive INTEGER,
        Summary TEXT, Source TEXT, TenantID INTEGER, CreatedBy TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS MALWARESCANENGINE (
        EngineResultID INTEGER PRIMARY KEY, ScanID INTEGER, Engine TEXT,
        Verdict TEXT, Detection TEXT, Score INTEGER, Positives INTEGER, Total INTEGER,
        Category TEXT, Link TEXT, Live INTEGER DEFAULT 0, Raw TEXT, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_malscan_tenant ON MALWARESCAN(TenantID);
      CREATE INDEX IF NOT EXISTS ix_malscan_sha256 ON MALWARESCAN(Sha256);
      CREATE INDEX IF NOT EXISTS ix_malscan_doc ON MALWARESCAN(DocumentID);
      CREATE INDEX IF NOT EXISTS ix_malscaneng_scan ON MALWARESCANENGINE(ScanID);`);
  } catch { /* best-effort */ }
}

/**
 * Cloud compliance checker (CSPM) — XORCISM.CLOUDFINDING stores the per-check results of the built-in
 * AWS compliance checker (CIS AWS Foundations subset: IAM password policy, MFA for IAM users, root
 * access keys / MFA, inactive users, key rotation, CloudTrail & AWS Config enablement…). Fed by
 * POST /api/cloud-security/aws-check (a posture snapshot, e.g. from the aws-config / aws-cloudtrail
 * connectors). Tenant-scoped; surfaced on /cloud-security. Idempotent at boot.
 */
export function ensureCloudComplianceTables(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS CLOUDFINDING (
        CloudFindingID INTEGER PRIMARY KEY, FindingGUID TEXT,
        Provider TEXT, Account TEXT, CheckID TEXT, Title TEXT, Service TEXT, Category TEXT,
        Severity TEXT, Status TEXT, Resource TEXT, Detail TEXT, Remediation TEXT, Benchmark TEXT,
        ScanDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_cloudfinding_tenant ON CLOUDFINDING(TenantID);
      CREATE INDEX IF NOT EXISTS ix_cloudfinding_acct ON CLOUDFINDING(Provider, Account);
      CREATE INDEX IF NOT EXISTS ix_cloudfinding_status ON CLOUDFINDING(Status);`);
  } catch { /* best-effort */ }
}

/**
 * Guided compliance-journey wizard (XCOMPLIANCE). A COMPLIANCEJOURNEY is a per-tenant program to
 * reach compliance with a framework (ISO 27001/42001, SOC 2, NIST CSF/800-53, NIS2, DORA, CRA,
 * MiCA, FedRAMP, GDPR…); COMPLIANCEJOURNEYSTEP is the materialized phased checklist, each step
 * deep-linking into the module that does the work (risk, controls, policies, audits, evidence…).
 * Sits above the existing FRAMEWORK / COMPLIANCEASSESSMENT model (a journey can spawn one).
 */
export function ensureComplianceJourneyTables(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS COMPLIANCEJOURNEY (
        JourneyID INTEGER PRIMARY KEY, JourneyGUID TEXT,
        FrameworkKey TEXT, FrameworkName TEXT, Name TEXT, Scope TEXT, Owner TEXT,
        Status TEXT, StartedDate TEXT, TargetDate TEXT,
        ComplianceAssessmentID INTEGER, AuditID INTEGER,
        TenantID INTEGER, CreatedBy TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS COMPLIANCEJOURNEYSTEP (
        StepID INTEGER PRIMARY KEY, JourneyID INTEGER,
        PhaseOrder INTEGER, Phase TEXT, StepOrder INTEGER,
        Title TEXT, Description TEXT, Link TEXT,
        Status TEXT DEFAULT 'todo', Notes TEXT, CompletedDate TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_journey_tenant ON COMPLIANCEJOURNEY(TenantID);
      CREATE INDEX IF NOT EXISTS ix_journeystep_journey ON COMPLIANCEJOURNEYSTEP(JourneyID);`);
  } catch { /* best-effort */ }
}

/**
 * Guided questionnaire runner / journey (XCOMPLIANCE). A QUESTIONNAIRERUN is a per-tenant guided
 * pass over an existing QUESTIONNAIRE (OCIL questionnaires, the CSA AI-CAIQ TPRM questionnaire, …):
 * the wizard materializes one QUESTIONNAIRERESPONSE per linked QUESTION (grouped into sections by
 * control-domain prefix), captures an answer + comment + evidence per question, tracks completion
 * and a conformance score, and can be submitted/reviewed. Sits above the read-only QUESTIONNAIRE /
 * QUESTION / QUESTIONFORQUESTIONNAIRE definition model — same shape as the compliance-journey wizard.
 */
export function ensureQuestionnaireRunTables(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS QUESTIONNAIRERUN (
        RunID INTEGER PRIMARY KEY, RunGUID TEXT,
        QuestionnaireID INTEGER, QuestionnaireName TEXT,
        Name TEXT, Subject TEXT, Respondent TEXT, Owner TEXT,
        Status TEXT DEFAULT 'in_progress', StartedDate TEXT, TargetDate TEXT, SubmittedDate TEXT,
        Score INTEGER, Conformance INTEGER,
        TenantID INTEGER, CreatedBy TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS QUESTIONNAIRERESPONSE (
        ResponseID INTEGER PRIMARY KEY, RunID INTEGER,
        QuestionID INTEGER, Section TEXT, DisplayOrder INTEGER,
        Answer TEXT, Comment TEXT, Evidence TEXT,
        AnsweredDate TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_qrun_tenant ON QUESTIONNAIRERUN(TenantID);
      CREATE INDEX IF NOT EXISTS ix_qresp_run ON QUESTIONNAIRERESPONSE(RunID);`);
  } catch { /* best-effort */ }
}

/**
 * Third-Party Risk Management (TPRM) — Panorays/Vendict-style vendor risk (XCOMPLIANCE). A
 * TPRMVENDOR carries the inherent risk (data sensitivity x business criticality -> tier), an
 * outside-in PostureScore/Grade (from a safe external probe -> TPRMFINDING rows), the security
 * questionnaire conformance (linked QUESTIONNAIRERUN), and the computed residual risk + review
 * cadence. TPRMFINDING holds findings from any source (external posture, questionnaire gap, breach,
 * AI). Dedicated tables (NOT the CPE-publisher VENDOR table) so the vendor list stays clean.
 */
export function ensureTprmTables(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS TPRMVENDOR (
        VendorID INTEGER PRIMARY KEY, VendorGUID TEXT,
        Name TEXT, Domain TEXT, Description TEXT, Category TEXT, ServicesProvided TEXT,
        ContactName TEXT, ContactEmail TEXT, Owner TEXT,
        Tier TEXT, DataSensitivity TEXT, BusinessCriticality TEXT,
        Status TEXT DEFAULT 'onboarding',
        UsesAI INTEGER DEFAULT 0, AIUseDescription TEXT,
        InherentRisk INTEGER, PostureScore INTEGER, PostureGrade TEXT,
        QuestionnaireRunID INTEGER, QuestionnaireConformance INTEGER,
        ResidualRisk INTEGER, ResidualTier TEXT,
        LastAssessedDate TEXT, NextReviewDate TEXT, ReviewCadenceDays INTEGER DEFAULT 365,
        TenantID INTEGER, CreatedBy TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS TPRMFINDING (
        FindingID INTEGER PRIMARY KEY, FindingGUID TEXT, VendorID INTEGER,
        Source TEXT, Category TEXT, Title TEXT, Detail TEXT,
        Severity TEXT, Status TEXT DEFAULT 'open', Evidence TEXT,
        CreatedDate TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_tprmvendor_tenant ON TPRMVENDOR(TenantID);
      CREATE INDEX IF NOT EXISTS ix_tprmfinding_vendor ON TPRMFINDING(VendorID);`);
  } catch { /* best-effort */ }
}

/**
 * Zero Trust Maturity (CISA ZTMM v2.0) (XCOMPLIANCE). ZTFUNCTION is the seeded global catalogue
 * (5 pillars + 3 cross-cutting capabilities × functions × 4 maturity stages); ZTMATURITYASSESSMENT
 * is a per-tenant assessment header; ZTMATURITYITEM is one row per function (current/target/auto
 * stage). The /zero-trust cockpit also derives per-pillar maturity from live XORCISM signals and a
 * fused trust score from the identity & asset inventories — see zerotrust.ts.
 */
export function ensureZeroTrustTables(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS ZTFUNCTION (
        FunctionID INTEGER PRIMARY KEY, FunctionKey TEXT UNIQUE, Pillar TEXT, PillarKey TEXT,
        IsCrossCutting INTEGER DEFAULT 0, Name TEXT, Description TEXT,
        Stage0 TEXT, Stage1 TEXT, Stage2 TEXT, Stage3 TEXT, DisplayOrder INTEGER);
      CREATE TABLE IF NOT EXISTS ZTMATURITYASSESSMENT (
        AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, Name TEXT, Scope TEXT, Owner TEXT,
        Status TEXT DEFAULT 'in_progress', OverallStage REAL, Score INTEGER, TargetStage INTEGER DEFAULT 3,
        StartedDate TEXT, TargetDate TEXT, TenantID INTEGER, CreatedBy TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS ZTMATURITYITEM (
        ItemID INTEGER PRIMARY KEY, AssessmentID INTEGER, FunctionKey TEXT, Pillar TEXT, PillarKey TEXT,
        CurrentStage INTEGER, TargetStage INTEGER, AutoStage INTEGER, Notes TEXT, Evidence TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_ztassessment_tenant ON ZTMATURITYASSESSMENT(TenantID);
      CREATE INDEX IF NOT EXISTS ix_ztitem_assessment ON ZTMATURITYITEM(AssessmentID);`);
  } catch { /* best-effort */ }
}

/**
 * Sign-in / access telemetry (XORCISM) — the continuous-verification signal that matures the Zero
 * Trust Identity pillar. IDENTITYSIGNIN holds normalized sign-in events ingested by the inbound
 * IdP/ZTNA connectors (entra-signin, okta-signin, …); zerotrust.ts sessionRisk() derives per-identity
 * behavioral risk (MFA-less sign-ins, failed bursts, impossible travel, IdP-flagged risk).
 */
export function ensureZtSigninTable(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS IDENTITYSIGNIN (
        SigninID INTEGER PRIMARY KEY, SigninGUID TEXT,
        IdentityName TEXT, IdentityID INTEGER,
        Timestamp TEXT, SourceIP TEXT, Country TEXT, City TEXT, Device TEXT, ClientApp TEXT,
        MFAUsed TEXT, Result TEXT, FailureReason TEXT, RiskLevel TEXT,
        Source TEXT, ExternalID TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_signin_identity ON IDENTITYSIGNIN(IdentityName);
      CREATE INDEX IF NOT EXISTS ix_signin_extid ON IDENTITYSIGNIN(Source, ExternalID);`);
  } catch { /* best-effort */ }
}

/**
 * Zero Trust policy register (XCOMPLIANCE) — the access policies modeled as data (NIST SP 800-207
 * Policy Engine view). ZTPOLICY holds conditional-access / ZTNA policies ingested by the inbound
 * connectors (entra-conditional-access, …): subject × resource × conditions × grant controls. Feeds
 * the /zero-trust Automation/Governance pillar signals. XORCISM models & measures policy; it does
 * not enforce it (the IdP/ZTNA does).
 */
export function ensureZtPolicyTable(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS ZTPOLICY (
        PolicyID INTEGER PRIMARY KEY, PolicyGUID TEXT, Name TEXT, Source TEXT, ExternalID TEXT,
        State TEXT, Subjects TEXT, Resources TEXT, Conditions TEXT, GrantControls TEXT,
        RequireMfa INTEGER, RequireCompliantDevice INTEGER, Block INTEGER,
        TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_ztpolicy_extid ON ZTPOLICY(Source, ExternalID);`);
  } catch { /* best-effort */ }
}

/**
 * Identity Threat Detection & Response (ITDR) — XORCISM.IDENTITYDETECTION holds the detections raised
 * by the itdr.ts engine (rule-based detectors over IDENTITYSIGNIN telemetry + IDENTITY posture),
 * each mapped to a MITRE ATT&CK technique with a recommended response and an analyst workflow status.
 * Idempotent re-scans upsert by (DedupKey, TenantID); a resolved/dismissed detection is preserved.
 */
export function ensureItdrTables(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS IDENTITYDETECTION (
        DetectionID INTEGER PRIMARY KEY, DetectionGUID TEXT,
        RuleKey TEXT, DedupKey TEXT, Title TEXT, Severity TEXT,
        Tactic TEXT, Technique TEXT, TechniqueName TEXT,
        IdentityName TEXT, IdentityID INTEGER, SourceIP TEXT, Country TEXT,
        Evidence TEXT, EventCount INTEGER,
        Status TEXT, ResponseAction TEXT,
        FirstSeen TEXT, LastSeen TEXT, ResolvedDate TEXT, ResolvedBy TEXT, Notes TEXT,
        IncidentAlertID INTEGER, TenantID INTEGER, CreatedDate TEXT, ModifiedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_itdr_dedup ON IDENTITYDETECTION(DedupKey, TenantID);
      CREATE INDEX IF NOT EXISTS ix_itdr_status ON IDENTITYDETECTION(Status);
      CREATE INDEX IF NOT EXISTS ix_itdr_identity ON IDENTITYDETECTION(IdentityName);`);
  } catch { /* best-effort */ }
}

/**
 * Identity Governance & Administration (IGA / IDMS) — access certification campaigns over the IDENTITY
 * inventory. ACCESSCAMPAIGN is a recertification campaign (scoped to e.g. all privileged identities);
 * ACCESSREVIEWITEM is one identity under review, snapshotted at campaign creation, with the reviewer's
 * certify / revoke / delegate decision. This is the access-review layer ([[identity-iam]] is inventory,
 * itdr is detection) — the SailPoint/Saviynt recertification capability.
 */
export function ensureIdGovTables(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS ACCESSCAMPAIGN (
        CampaignID INTEGER PRIMARY KEY, CampaignGUID TEXT, Name TEXT, Description TEXT,
        Scope TEXT, Status TEXT, DueDate TEXT, ItemCount INTEGER,
        CreatedBy TEXT, CreatedDate TEXT, CompletedDate TEXT, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS ACCESSREVIEWITEM (
        ItemID INTEGER PRIMARY KEY, ItemGUID TEXT, CampaignID INTEGER,
        IdentityID INTEGER, IdentityName TEXT, Snapshot TEXT,
        Decision TEXT, Reviewer TEXT, DecidedDate TEXT, Comment TEXT, Actioned INTEGER DEFAULT 0,
        TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_reviewitem_campaign ON ACCESSREVIEWITEM(CampaignID);
      CREATE INDEX IF NOT EXISTS ix_reviewitem_identity ON ACCESSREVIEWITEM(IdentityID);`);
  } catch { /* best-effort */ }
}

export function ensurePersonOrgChartColumns(): void {
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PERSON'").get()) return;
    const existing = new Set((db.prepare(`PRAGMA table_info("PERSON")`).all() as { name: string }[]).map((c) => c.name));
    const cols: Record<string, string> = {
      ManagerPersonID: "INTEGER",      // org-chart parent edge (Entra: manager / AD: manager)
      JobTitle: "TEXT",                // Entra jobTitle
      Department: "TEXT",              // Entra department
      CompanyName: "TEXT",             // Entra companyName
      OfficeLocation: "TEXT",          // Entra officeLocation
      UserPrincipalName: "TEXT",       // Entra userPrincipalName (UPN)
      EmployeeID: "TEXT",              // Entra employeeId
      EmployeeType: "TEXT",            // Entra employeeType (Employee/Contractor…)
      EntraObjectID: "TEXT",           // Entra/Azure AD object id (immutable GUID)
      ObjectGUID: "TEXT",              // on-prem AD objectGUID
      OnPremisesSamAccountName: "TEXT",// AD sAMAccountName
      UsageLocation: "TEXT",           // Entra usageLocation (ISO country)
      MobilePhone: "TEXT", BusinessPhone: "TEXT",
      AccountEnabled: "INTEGER",       // Entra accountEnabled (1/0)
      TenantID: "INTEGER",             // tenant scope (PERSON was historically a global directory)
    };
    for (const [n, t] of Object.entries(cols)) {
      if (!existing.has(n)) db.exec(`ALTER TABLE "PERSON" ADD COLUMN "${n}" ${t}`);
    }
    try { db.exec(`CREATE INDEX IF NOT EXISTS ix_person_manager ON "PERSON"("ManagerPersonID")`); } catch { /* best-effort */ }
    try { db.exec(`CREATE INDEX IF NOT EXISTS ix_person_entra ON "PERSON"("EntraObjectID")`); } catch { /* best-effort */ }
  } catch { /* PERSON absent */ }
}

export function ensureDocumentSensitivity(): void {
  for (const dbName of ["XORCISM", "XCOMPLIANCE"]) {
    try {
      const db = getDb(dbName);
      if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='DOCUMENT'").get()) continue;
      const existing = new Set((db.prepare(`PRAGMA table_info("DOCUMENT")`).all() as { name: string }[]).map((c) => c.name));
      for (const [n, t] of Object.entries({ Classification: "TEXT", TLP: "TEXT" })) {
        if (!existing.has(n)) db.exec(`ALTER TABLE "DOCUMENT" ADD COLUMN "${n}" ${t}`);
      }
    } catch { /* DOCUMENT absent on this deployment */ }
  }
}

export function ensureGrcColumns(): void {
  const addCols = (dbName: string, table: string, cols: Record<string, string>): void => {
    const db = getDb(dbName);
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return;
    const existing = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(cols)) if (!existing.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  // CRQ / FAIR — monetary quantification (risk register + risk scenarios).
  const CRQ = {
    LossEventFrequency: "REAL", SingleLossExpectancy: "REAL", AnnualizedLossExpectancy: "REAL",
    PrimaryLoss: "REAL", SecondaryLoss: "REAL", Currency: "TEXT",
  };
  addCols("XCOMPLIANCE", "RISKREGISTERENTRY", CRQ);
  addCols("XCOMPLIANCE", "RISKSCENARIO", { LossEventFrequency: "REAL", AnnualizedLossExpectancy: "REAL", Currency: "TEXT" });
  // Remediation workflow for audit findings.
  addCols("XCOMPLIANCE", "AUDITFINDING", {
    WorkflowStatus: "TEXT", Severity: "TEXT", RemediationPlan: "TEXT",
    RemediationOwnerPersonID: "INTEGER", DueDate: "DATE",
    // which assessment dimension produced this finding (design / documentation / operating effectiveness).
    AssessmentType: "TEXT",
  });
  // Audit assessment dimension (ISAE 3000 / SOC 2): an audit can assess control DESIGN (is the control
  // designed to meet the objective), DOCUMENTATION (do the policy/procedure artefacts exist & are
  // adequate), and/or OPERATING EFFECTIVENESS (does it operate over a period). Default 'Operating
  // Effectiveness' is applied lazily by the compliance module, not here, to leave existing audits as-is.
  addCols("XCOMPLIANCE", "AUDIT", { AssessmentType: "TEXT" });
  // Policy lifecycle (GRC) + document/management-system metadata (ISO 42001 / 27001 …).
  addCols("XORCISM", "POLICY", {
    Status: "TEXT", WorkflowStatus: "TEXT", Version: "TEXT", PolicyReference: "TEXT",
    OwnerPersonID: "INTEGER", ApprovedByPersonID: "INTEGER", EffectiveDate: "DATE", ReviewDate: "DATE",
    // management-system context: which framework/clause this policy supports, its category,
    // classification, language (en/fr…) and full markdown body.
    Category: "TEXT", Framework: "TEXT", Clause: "TEXT", Classification: "TEXT",
    Language: "TEXT", Scope: "TEXT", PolicyContent: "TEXT", ApprovedDate: "DATE",
    // publication + user-acceptance: when a policy was published and whether users must acknowledge it.
    PublishedDate: "DATE", RequiresAcknowledgement: "INTEGER",
    // ISO documentation pyramid: a governed document is a Policy / Standard / Procedure / Guideline,
    // and a child document implements a parent (Procedure → Standard → Policy). DocumentType defaults
    // to 'Policy' for existing rows so the policy register is unchanged.
    DocumentType: "TEXT", ParentPolicyID: "INTEGER",
  });
  try { getDb("XORCISM").prepare("UPDATE POLICY SET DocumentType='Policy' WHERE DocumentType IS NULL OR DocumentType=''").run(); } catch { /* best-effort default */ }
  // Document register (records / evidence) lifecycle — mirror the policy fields so the
  // governance view can treat DOCUMENT as a controlled-document register.
  addCols("XCOMPLIANCE", "DOCUMENT", {
    Status: "TEXT", Category: "TEXT", DocumentType: "TEXT", Classification: "TEXT",
    Framework: "TEXT", Language: "TEXT", PolicyReference: "TEXT", RelatedPolicyID: "INTEGER",
    OwnerPersonID: "INTEGER", ReviewDate: "DATE",
    ExternalID: "TEXT", Source: "TEXT", TenantID: "INTEGER",  // GRC connector imports (Vanta/Drata/…)
  });
  // TPRM — third-party assessment via questionnaire (QUESTIONNAIREFORORGANISATION).
  addCols("XCOMPLIANCE", "QUESTIONNAIREFORORGANISATION", {
    Status: "TEXT", AssessmentType: "TEXT", RiskRating: "TEXT", Score: "INTEGER",
    VendorCriticality: "TEXT", DueDate: "DATE", CompletedDate: "DATE",
  });
}

/**
 * XORCISM.POLICYACKNOWLEDGEMENT — per-user acceptance of a published policy. One row per
 * (PolicyID, UserID, PolicyVersion): re-publishing a policy at a new version requires users to
 * re-acknowledge. User identity is denormalized (UserID/Email/Name) since XUSER lives in the
 * XID database. Created idempotently at boot.
 */
export function ensurePolicyAckTable(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS "POLICYACKNOWLEDGEMENT" (
    "AcknowledgementID" INTEGER PRIMARY KEY,
    "AcknowledgementGUID" TEXT,
    "PolicyID" INTEGER,
    "UserID" INTEGER,
    "UserEmail" TEXT,
    "UserName" TEXT,
    "PolicyVersion" TEXT,
    "AcknowledgedDate" TEXT,
    "Method" TEXT,
    "IPAddress" TEXT,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_polack_policy ON "POLICYACKNOWLEDGEMENT"(PolicyID);
  CREATE INDEX IF NOT EXISTS ix_polack_user ON "POLICYACKNOWLEDGEMENT"(UserID);`);
}

/**
 * XORCISM.POLICYVERSION — immutable version history of a policy. A snapshot row is written each
 * time a policy is published (and on demand), capturing the content + lifecycle metadata of that
 * version so prior versions can be reviewed, compared, and restored. Editor identity is
 * denormalized (XUSER lives in the XID db). Created idempotently at boot.
 */
export function ensurePolicyVersionTable(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS "POLICYVERSION" (
    "PolicyVersionID" INTEGER PRIMARY KEY,
    "PolicyVersionGUID" TEXT,
    "PolicyID" INTEGER,
    "Version" TEXT,
    "Status" TEXT,
    "PolicyName" TEXT,
    "PolicyContent" TEXT,
    "Scope" TEXT,
    "EffectiveDate" DATE,
    "PublishedDate" DATE,
    "ChangeNote" TEXT,
    "ChangedByUserID" INTEGER,
    "ChangedByName" TEXT,
    "CreatedDate" TEXT,
    "TenantID" INTEGER
  );
  CREATE INDEX IF NOT EXISTS ix_polver_policy ON "POLICYVERSION"(PolicyID);`);
}

/**
 * EBIOS Risk Manager (ANSSI, ISO 27005-compatible) — integration of the cyber
 * risk analysis method (inspired by ACRA, https://github.com/bdudout/acra)
 * into XCOMPLIANCE, by REUSING the existing risk base:
 *   - RISKASSESSMENT = the EBIOS study (Methodology='EBIOS RM', Workshop 1..5).
 *   - RISKSCENARIO   = strategic scenarios (workshop 3) + operational ones (workshop 4)
 *       via the added EBIOS columns (ScenarioType, RiskSourceID, FearedEventID,
 *       StakeholderID, Likelihood, Severity, AttackPath).
 *   - RISKMATRIX / RISKACCEPTANCE = matrix (likelihood × severity) + acceptance.
 *   - FRAMEWORK / REFERENCECONTROL / APPLIEDCONTROL = security measures (workshop 5).
 *   - PERIMETER = scope of the study.
 * + entities specific to EBIOS (workshops 1-3) absent from the base:
 *   EBIOSBUSINESSVALUE (business value), EBIOSSUPPORTINGASSET (supporting asset; optional
 *   link → XORCISM.ASSET), EBIOSFEAREDEVENT (feared event + DICT + severity),
 *   EBIOSRISKSOURCE (risk source / targeted objective SR/OV), EBIOSSTAKEHOLDER
 *   (stakeholder / ecosystem mapping).
 * Idempotent (CREATE IF NOT EXISTS + conditional ALTER). Called at boot.
 */
export function ensureEbiosTables(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS EBIOSBUSINESSVALUE (
      BusinessValueID INTEGER PRIMARY KEY, BusinessValueGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, Description TEXT,
      Nature TEXT, OwnerPersonID INTEGER, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS EBIOSSUPPORTINGASSET (
      SupportingAssetID INTEGER PRIMARY KEY, SupportingAssetGUID TEXT,
      RiskAssessmentID INTEGER, BusinessValueID INTEGER, AssetID INTEGER,
      Name TEXT, Description TEXT, Type TEXT, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS EBIOSFEAREDEVENT (
      FearedEventID INTEGER PRIMARY KEY, FearedEventGUID TEXT,
      RiskAssessmentID INTEGER, BusinessValueID INTEGER, Name TEXT, Description TEXT,
      ImpactAvailability INTEGER, ImpactIntegrity INTEGER, ImpactConfidentiality INTEGER,
      ImpactTraceability INTEGER, Consequences TEXT, Severity INTEGER,
      CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS EBIOSRISKSOURCE (
      RiskSourceID INTEGER PRIMARY KEY, RiskSourceGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, Category TEXT, Objective TEXT,
      Motivation INTEGER, Resources INTEGER, Activity INTEGER, Pertinence INTEGER,
      Retained INTEGER, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS EBIOSSTAKEHOLDER (
      StakeholderID INTEGER PRIMARY KEY, StakeholderGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, Category TEXT, Type TEXT,
      Dependency INTEGER, Penetration INTEGER, Maturity INTEGER, Trust INTEGER,
      ThreatLevel REAL, Zone TEXT, CreatedDate TEXT, TenantID INTEGER
    );
  `);
  // Reuse: marks the EBIOS study and enriches the risk scenarios.
  const addCols = (table: string, cols: Record<string, string>): void => {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return;
    const existing = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(cols)) if (!existing.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  addCols("RISKASSESSMENT", { Methodology: "TEXT", Workshop: "INTEGER", ExpressMode: "INTEGER" });
  addCols("RISKSCENARIO", {
    ScenarioType: "TEXT", RiskSourceID: "INTEGER", FearedEventID: "INTEGER",
    StakeholderID: "INTEGER", Likelihood: "INTEGER", Severity: "INTEGER", AttackPath: "TEXT",
  });
}

/**
 * FAIR-MAM — the FAIR Institute's Materiality Assessment Model. Decomposes a cyber loss event's
 * magnitude into 10 standardized cost categories (with sub-categories), classified by FAIR loss
 * form (primary / secondary) and party (first-party / third-party). Extends the existing CRQ/FAIR
 * on XCOMPLIANCE.RISKREGISTERENTRY (PrimaryLoss/SecondaryLoss/SingleLossExpectancy) with the
 * detailed breakdown + a materiality determination. Created idempotently at boot:
 *   FAIRMAMCATEGORY  — the reference taxonomy (global, seeded once; like the TOOL catalogue)
 *   FAIRMAMASSESSMENT — a materiality assessment (tenant-scoped)
 *   FAIRMAMLINEITEM  — per-category min/most-likely/max loss estimate (PERT) (tenant-scoped)
 */
export function ensureFairMamTables(): void {
  let db: Database.Database;
  try { db = getDb("XCOMPLIANCE"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS FAIRMAMCATEGORY (
      CategoryID INTEGER PRIMARY KEY, Code TEXT, Name TEXT, ParentCode TEXT,
      LossType TEXT, Party TEXT, Description TEXT, SortOrder INTEGER, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS FAIRMAMASSESSMENT (
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, Name TEXT, ScenarioRef TEXT,
      RiskRegisterEntryID INTEGER, IncidentID INTEGER, Currency TEXT,
      MaterialityThreshold REAL, RevenueBasis REAL, Status TEXT, Determination TEXT,
      PersonID INTEGER, CreatedDate TEXT, ValidFrom TEXT, ValidUntil TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS FAIRMAMLINEITEM (
      LineItemID INTEGER PRIMARY KEY, AssessmentID INTEGER, CategoryID INTEGER,
      Minimum REAL, MostLikely REAL, Maximum REAL, Notes TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_fairmamlineitem_assessment ON FAIRMAMLINEITEM(AssessmentID);
    CREATE INDEX IF NOT EXISTS ix_fairmamassessment_tenant ON FAIRMAMASSESSMENT(TenantID);
    -- FAIR frequency side: Threat/Loss Event Frequency estimation by Monte Carlo over PERT factors.
    -- LEF = TEF × Vulnerability ; TEF = Contact Frequency × Probability of Action ;
    -- Vulnerability = P(Threat Capability > Resistance Strength). Optional loss magnitude → ALE.
    CREATE TABLE IF NOT EXISTS FAIRTEFASSESSMENT (
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, Name TEXT, ScenarioRef TEXT,
      RiskRegisterEntryID INTEGER, FairMamAssessmentID INTEGER, ThreatCommunity TEXT, Iterations INTEGER, Currency TEXT,
      CfMin REAL, CfMl REAL, CfMax REAL, PoaMin REAL, PoaMl REAL, PoaMax REAL,
      TcapMin REAL, TcapMl REAL, TcapMax REAL, RsMin REAL, RsMl REAL, RsMax REAL,
      LossMagnitude REAL, TefMean REAL, VulnMean REAL, LefMean REAL, LefP10 REAL, LefP50 REAL, LefP90 REAL,
      AleMean REAL, AleP90 REAL, Status TEXT, PersonID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_fairtefassessment_tenant ON FAIRTEFASSESSMENT(TenantID);
  `);

  // Seed the FAIR-MAM taxonomy once (idempotent: only when empty). 10 primary categories
  // (P##) + sub-categories, FAIR loss form + party classification.
  if ((db.prepare("SELECT COUNT(*) AS c FROM FAIRMAMCATEGORY").get() as { c: number }).c > 0) return;
  type Cat = [code: string, name: string, parent: string | null, loss: "primary" | "secondary", party: "first-party" | "third-party", desc: string];
  const TAX: Cat[] = [
    // ── Primary loss (first-party, direct) ──
    ["IR", "Incident Response", null, "primary", "first-party", "Costs to detect, investigate, contain and manage the event."],
    ["IR.FOR", "Forensics & Investigation", "IR", "primary", "first-party", "Internal/external DFIR, root-cause analysis."],
    ["IR.LEG", "Legal Counsel (Breach Coach)", "IR", "primary", "first-party", "Privileged legal guidance through the response."],
    ["IR.NOT", "Notification & Call Center", "IR", "primary", "first-party", "Notifying affected parties + inbound support."],
    ["IR.MON", "Credit / Identity Monitoring", "IR", "primary", "first-party", "Monitoring/protection services for affected individuals."],
    ["IR.PR", "Public Relations / Crisis Comms", "IR", "primary", "first-party", "Managing public and stakeholder communications."],
    ["EXT", "Cyber Extortion", null, "primary", "first-party", "Ransom and the cost of responding to extortion."],
    ["EXT.RAN", "Ransom Payment", "EXT", "primary", "first-party", "The extortion payment itself (where made)."],
    ["EXT.NEG", "Negotiation & Recovery Services", "EXT", "primary", "first-party", "Specialist negotiation, decryption, recovery."],
    ["BI", "Business Interruption", null, "primary", "first-party", "Lost income and added cost while operations are degraded."],
    ["BI.INC", "Lost Net Income", "BI", "primary", "first-party", "Profit lost during the period of impairment."],
    ["BI.EXP", "Extra Expense", "BI", "primary", "first-party", "Added cost to keep operating / accelerate recovery."],
    ["BI.DEP", "Dependent / Contingent BI", "BI", "primary", "first-party", "Interruption via a third party you depend on."],
    ["DAR", "Digital Asset Restoration", null, "primary", "first-party", "Restoring or recreating damaged data and systems."],
    ["DAR.DATA", "Data Recreation", "DAR", "primary", "first-party", "Re-creating lost or corrupted data."],
    ["DAR.SYS", "Software / System Restoration", "DAR", "primary", "first-party", "Rebuilding/replacing systems and software."],
    // ── Secondary loss (third-party / stakeholder reactions) ──
    ["PSL", "Information Privacy & Security Liability", null, "secondary", "third-party", "Third-party claims for privacy/security failures."],
    ["PSL.DEF", "Defense Costs", "PSL", "secondary", "third-party", "Cost to defend privacy/security litigation."],
    ["PSL.SET", "Settlements / Judgments", "PSL", "secondary", "third-party", "Class-action settlements, judgments."],
    ["NSL", "Network Security Liability", null, "secondary", "third-party", "Liability for harm to third parties (malware spread, DoS, unauthorized access)."],
    ["CML", "Communications & Media Liability", null, "secondary", "third-party", "Defamation, IP/copyright infringement in content."],
    ["REG", "Regulatory Defense & Penalties", null, "secondary", "third-party", "Regulatory investigations, defense and fines."],
    ["REG.DEF", "Regulatory Defense", "REG", "secondary", "third-party", "Cost to respond to/defend regulatory inquiries."],
    ["REG.FIN", "Fines & Penalties", "REG", "secondary", "third-party", "GDPR / HIPAA / state-AG / SEC penalties."],
    ["PCI", "PCI Fines, Expenses & Costs", null, "secondary", "third-party", "Card-brand fines, assessments and reissuance."],
    ["PCI.FIN", "Card-Brand Fines", "PCI", "secondary", "third-party", "Fines levied by the card networks."],
    ["PCI.ASM", "Assessments & Reissuance", "PCI", "secondary", "third-party", "Operational reimbursement + card reissuance."],
    ["REP", "Reputation Damage", null, "secondary", "first-party", "Lost future value from damaged stakeholder trust."],
    ["REP.CHU", "Customer Churn / Lost Revenue", "REP", "secondary", "first-party", "Customers lost and future revenue forgone."],
    ["REP.CAP", "Increased Cost of Capital / Brand", "REP", "secondary", "first-party", "Higher financing cost, brand impairment."],
  ];
  const ins = db.prepare(
    `INSERT INTO FAIRMAMCATEGORY (CategoryID, Code, Name, ParentCode, LossType, Party, Description, SortOrder)
     VALUES (?,?,?,?,?,?,?,?)`);
  const tx = db.transaction(() => { TAX.forEach((c, i) => ins.run(i + 1, c[0], c[1], c[2], c[3], c[4], c[5], i + 1)); });
  tx();
  console.log(`[seed] XCOMPLIANCE.FAIRMAMCATEGORY ← ${TAX.length} FAIR-MAM categories`);
}

/**
 * PQCMM — the PKI Consortium's Post-Quantum Cryptography Maturity Model (product-centric
 * quantum-readiness levels 0-5). Assess each product / service / asset that relies on
 * cryptography against the model, track current vs target maturity, and roll up the
 * organisation's quantum-readiness posture. Created idempotently at boot:
 *   PQCMMLEVEL      — the 6 reference levels (global, seeded once)
 *   PQCMMASSESSMENT — a per-subject maturity assessment (tenant-scoped)
 */
export function ensurePqcmmTables(): void {
  let db: Database.Database;
  try { db = getDb("XCOMPLIANCE"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS PQCMMLEVEL (
      LevelID INTEGER PRIMARY KEY, Level INTEGER, Name TEXT, Summary TEXT, Criteria TEXT, SortOrder INTEGER);
    CREATE TABLE IF NOT EXISTS PQCMMASSESSMENT (
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, SubjectType TEXT, SubjectName TEXT, AssetID INTEGER,
      CurrentLevel INTEGER, TargetLevel INTEGER, Standard TEXT, CryptoAgile INTEGER, ZeroLegacy INTEGER, HasCBOM INTEGER,
      Evidence TEXT, Notes TEXT, OwnerPersonID INTEGER, Status TEXT, AssessedDate TEXT, ReviewDate TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_pqcmmassessment_tenant ON PQCMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_pqcmmassessment_asset ON PQCMMASSESSMENT(AssetID);
  `);
  if ((db.prepare("SELECT COUNT(*) AS c FROM PQCMMLEVEL").get() as { c: number }).c > 0) return;
  const LEVELS: [level: number, name: string, summary: string, criteria: string][] = [
    [0, "None", "No post-quantum cryptography. The product relies entirely on classical, quantum-vulnerable algorithms (RSA, ECC, DH).", "No quantum-safe capability."],
    [1, "Initial", "Quantum-safe algorithms/features are available for testing and evaluation; configured manually or via beta options.", "PQC available for test/eval; manual or beta configuration."],
    [2, "Foundational", "Quantum-safe algorithms are supported in core functionality and production-ready, and demonstrate compatibility with relevant standards.", "PQC in core/production; standards-compatible."],
    [3, "Advanced", "Foundational + a full cryptographic use-case inventory; non-quantum-safe features documented & flagged for risk; SBOM produced/maintained; crypto-agility (swap algorithms without major redesign).", "Crypto inventory; SBOM; non-quantum-safe flagged; crypto-agile."],
    [4, "Managed", "Advanced + a Cryptographic Bill of Materials (CBOM: algorithms, key sizes, usage context); Zero-Legacy capability (can disable ALL non-quantum-safe algorithms); hybrid/composite algorithm support indicated.", "CBOM; Zero-Legacy capable; hybrid/composite support."],
    [5, "Optimized", "Managed + quantum-safe algorithms are the default; benchmarked & tuned for performance; primarily NIST-approved PQC standards; implementations from independently verified / certified sources.", "PQC default; NIST-approved; benchmarked; verified/certified."],
  ];
  const ins = db.prepare("INSERT INTO PQCMMLEVEL (LevelID, Level, Name, Summary, Criteria, SortOrder) VALUES (?,?,?,?,?,?)");
  const tx = db.transaction(() => { LEVELS.forEach((l, i) => ins.run(i + 1, l[0], l[1], l[2], l[3], i)); });
  tx();
  console.log(`[seed] XCOMPLIANCE.PQCMMLEVEL ← ${LEVELS.length} PQCMM levels`);
}

/**
 * SCA — Software Composition Analysis over the existing CPE / CPEFORASSET / APPLICATION
 * inventory, with first-class SBOM (Software Bill of Materials) support for the two most
 * widely used standards: CycloneDX (OWASP) and SPDX (Linux Foundation). An imported SBOM
 * is stored as an SBOM document + its constituent COMPONENT rows (rich metadata: PURL,
 * CPE, version, license, supplier, hash, scope) + the COMPONENTDEPENDENCY edges (for the
 * composition graph). Components are linked back to the asset's CPE inventory (CPEFORASSET)
 * so SCA findings feed the same exposure pipeline. Created idempotently at boot (all in
 * XORCISM, alongside CPE/CPEFORASSET/APPLICATION/SOFTWARE):
 *   SBOM                — one imported/exported bill of materials (tenant-scoped)
 *   COMPONENT           — the pre-existing skeletal table, enriched with SBOM columns (tenant-scoped)
 *   COMPONENTDEPENDENCY — dependency edges between components (tenant-scoped, for the graph)
 */
export function ensureScaTables(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS SBOM (
      SbomID INTEGER PRIMARY KEY, SbomGUID TEXT, Name TEXT, Format TEXT, SpecVersion TEXT,
      SerialNumber TEXT, SubjectName TEXT, SubjectVersion TEXT, AssetID INTEGER, ApplicationID INTEGER,
      ComponentCount INTEGER, VulnerableCount INTEGER, LicenseCount INTEGER, Source TEXT, ToolName TEXT,
      Notes TEXT, PersonID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS COMPONENTDEPENDENCY (
      DependencyID INTEGER PRIMARY KEY, SbomID INTEGER, FromRef TEXT, ToRef TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_sbom_tenant ON SBOM(TenantID);
    CREATE INDEX IF NOT EXISTS ix_sbom_asset ON SBOM(AssetID);
    CREATE INDEX IF NOT EXISTS ix_componentdependency_sbom ON COMPONENTDEPENDENCY(SbomID);
  `);
  // The legacy COMPONENT table ships skeletal as `ComponentID INTEGER NOT NULL` (NOT a PRIMARY
  // KEY → not an auto-rowid alias, so INSERTs without an explicit id fail). It's unused (0 rows);
  // rebuild it with a proper INTEGER PRIMARY KEY before enriching it, so SBOM imports can insert.
  const compInfo = db.prepare(`PRAGMA table_info("COMPONENT")`).all() as { name: string; pk: number }[];
  if (compInfo.length) {
    const idIsPk = compInfo.some((c) => c.name === "ComponentID" && c.pk > 0);
    const rowCount = (db.prepare(`SELECT COUNT(*) AS c FROM "COMPONENT"`).get() as { c: number }).c;
    if (!idIsPk && rowCount === 0) {
      db.exec(`DROP TABLE "COMPONENT"; CREATE TABLE "COMPONENT" ("ComponentID" INTEGER PRIMARY KEY)`);
    }
  }
  // Enrich the pre-existing skeletal COMPONENT table (it ships with just ComponentID).
  const addCols = (table: string, cols: Record<string, string>): void => {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) {
      db.exec(`CREATE TABLE "${table}" ("${table}ID" INTEGER PRIMARY KEY)`);
    }
    const existing = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(cols)) if (!existing.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  addCols("COMPONENT", {
    ComponentGUID: "TEXT", SbomID: "INTEGER", Name: "TEXT", Version: "TEXT", ComponentType: "TEXT",
    PURL: "TEXT", CPE: "TEXT", CPEID: "INTEGER", Supplier: "TEXT", Publisher: "TEXT", "Group": "TEXT",
    License: "TEXT", Hash: "TEXT", BOMRef: "TEXT", Scope: "TEXT", Description: "TEXT",
    AssetID: "INTEGER", CreatedDate: "TEXT", TenantID: "INTEGER",
  });
  db.exec("CREATE INDEX IF NOT EXISTS ix_component_sbom ON COMPONENT(SbomID); CREATE INDEX IF NOT EXISTS ix_component_tenant ON COMPONENT(TenantID);");
}

/**
 * EBIOS RM dashboard: list of studies (RISKASSESSMENT marked EBIOS) with,
 * per study, the count of each workshop's objects (business values, supporting assets,
 * feared events, risk sources, stakeholders, strategic / operational scenarios)
 * + the max severity, and global statistics.
 */
export function getEbiosDashboard(): { studies: Record<string, unknown>[]; stats: Record<string, unknown> } {
  const db = getDb("XCOMPLIANCE");
  const has = (t: string): boolean => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  if (!has("RISKASSESSMENT")) return { studies: [], stats: { total: 0 } };
  const studies = db.prepare(
    `SELECT RiskAssessmentID AS id, Name AS name, Description AS description, Status AS status,
            Workshop AS workshop, ExpressMode AS express, Date AS date
     FROM RISKASSESSMENT WHERE COALESCE(Methodology,'') LIKE 'EBIOS%' ORDER BY RiskAssessmentID DESC`
  ).all() as Record<string, any>[];
  const cnt = (table: string, id: number): number => {
    if (!has(table)) return 0;
    return (db.prepare(`SELECT COUNT(*) c FROM "${table}" WHERE RiskAssessmentID=?`).get(id) as { c: number }).c;
  };
  const scen = (id: number, where: string): number => has("RISKSCENARIO")
    ? (db.prepare(`SELECT COUNT(*) c FROM RISKSCENARIO WHERE RiskAssessmentID=? AND ${where}`).get(id) as { c: number }).c : 0;
  const out = studies.map((s) => {
    const counts = {
      businessValues: cnt("EBIOSBUSINESSVALUE", s.id),
      supportingAssets: cnt("EBIOSSUPPORTINGASSET", s.id),
      fearedEvents: cnt("EBIOSFEAREDEVENT", s.id),
      riskSources: cnt("EBIOSRISKSOURCE", s.id),
      stakeholders: cnt("EBIOSSTAKEHOLDER", s.id),
      strategicScenarios: scen(s.id, "COALESCE(ScenarioType,'strategic')='strategic'"),
      operationalScenarios: scen(s.id, "ScenarioType='operational'"),
    };
    const maxSeverity = has("EBIOSFEAREDEVENT")
      ? (db.prepare("SELECT COALESCE(MAX(Severity),0) m FROM EBIOSFEAREDEVENT WHERE RiskAssessmentID=?").get(s.id) as { m: number }).m : 0;
    return { ...s, counts, maxSeverity };
  });
  const sum = (f: (s: any) => number): number => out.reduce((n, s) => n + f(s), 0);
  const stats = {
    total: out.length,
    businessValues: sum((s) => s.counts.businessValues),
    scenarios: sum((s) => s.counts.strategicScenarios + s.counts.operationalScenarios),
    riskSources: sum((s) => s.counts.riskSources),
  };
  return { studies: out, stats };
}

/**
 * Create a RISKASSESSMENT (risk-assessment study) from a guided form — the friendly path that
 * replaces dumping the user into the raw explorer insert. Sets Methodology (so EBIOS studies
 * surface on the EBIOS dashboard, which filters Methodology LIKE 'EBIOS%') and, for EBIOS,
 * starts at Workshop 1. Column-aware (only writes columns the table actually has) + GUID + tenant.
 */
export function createRiskAssessment(
  p: { name: string; description?: string; methodology?: string; status?: string; expressMode?: boolean;
       authorPersonId?: number | null; perimeterId?: number | null; version?: string; date?: string },
  tenant: number | null,
): { id: number } {
  ensureEbiosTables(); // make sure Methodology/Workshop/ExpressMode exist before inserting
  const db = getDb("XCOMPLIANCE");
  const cols = new Set((db.prepare(`PRAGMA table_info("RISKASSESSMENT")`).all() as { name: string }[]).map((c) => c.name));
  const now = new Date().toISOString();
  const methodology = (p.methodology || "EBIOS RM").trim();
  const isEbios = /^ebios/i.test(methodology);
  const candidate: Record<string, unknown> = {
    RiskAssessmentGUID: randomUUID(),
    Name: (p.name || "Untitled risk assessment").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Methodology: methodology.slice(0, 120),
    Status: (p.status || "Draft").slice(0, 60),
    ExpressMode: p.expressMode ? 1 : 0,
    Workshop: isEbios ? 1 : null,
    AuthorPersonID: p.authorPersonId ?? null,
    PerimeterID: p.perimeterId ?? null,
    Version: (p.version || "").slice(0, 40) || null,
    Date: p.date || now.slice(0, 10),
    CreatedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => cols.has(k));
  const sql = `INSERT INTO RISKASSESSMENT (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = db.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

/**
 * NIST SP 800-30 (Guide for Conducting Risk Assessments) — the US federal counterpart of
 * EBIOS RM, integrated the same way: REUSE the existing risk base
 *   - RISKASSESSMENT = the 800-30 risk assessment (Methodology='NIST SP 800-30').
 * + 800-30-specific entities (Rev.1 model, Appendix D-H tasks):
 *   NIST80030THREATSOURCE — threat sources (adversarial: capability/intent/targeting;
 *       non-adversarial: range of effects), Appendix D.
 *   NIST80030THREATEVENT  — threat events a source can initiate + likelihood of initiation,
 *       Appendix E.
 *   NIST80030VULNERABILITY— vulnerabilities & predisposing conditions (severity, pervasiveness),
 *       Appendix F.
 *   NIST80030RISK         — the determined risks: threat event × vulnerability → overall
 *       likelihood × impact → risk level (Appendix I, Table I-2), + risk response.
 * Levels are the 800-30 semi-quantitative scale 1..5 = Very Low / Low / Moderate / High / Very
 * High. Idempotent (CREATE IF NOT EXISTS); called at boot.
 */
export function ensureNist80030Tables(): void {
  ensureEbiosTables(); // guarantees RISKASSESSMENT.Methodology exists (shared marker column)
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS NIST80030THREATSOURCE (
      ThreatSourceID INTEGER PRIMARY KEY, ThreatSourceGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, SourceType TEXT, Category TEXT,
      Capability INTEGER, Intent INTEGER, Targeting INTEGER, RangeOfEffects TEXT,
      Relevance INTEGER, Description TEXT, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS NIST80030THREATEVENT (
      ThreatEventID INTEGER PRIMARY KEY, ThreatEventGUID TEXT,
      RiskAssessmentID INTEGER, ThreatSourceID INTEGER, Name TEXT, Description TEXT,
      Relevance TEXT, LikelihoodInitiation INTEGER, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS NIST80030VULNERABILITY (
      NistVulnID INTEGER PRIMARY KEY, NistVulnGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, Description TEXT, PredisposingCondition TEXT,
      Severity INTEGER, Pervasiveness INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER
    );
    CREATE TABLE IF NOT EXISTS NIST80030RISK (
      RiskID INTEGER PRIMARY KEY, RiskGUID TEXT,
      RiskAssessmentID INTEGER, Name TEXT, Description TEXT,
      ThreatSourceID INTEGER, ThreatEventID INTEGER, NistVulnID INTEGER,
      LikelihoodInitiation INTEGER, LikelihoodImpact INTEGER, OverallLikelihood INTEGER,
      ImpactLevel INTEGER, RiskLevel INTEGER, RiskResponse TEXT, Notes TEXT,
      CreatedDate TEXT, TenantID INTEGER
    );
    CREATE INDEX IF NOT EXISTS ix_n30src_ra ON NIST80030THREATSOURCE(RiskAssessmentID);
    CREATE INDEX IF NOT EXISTS ix_n30evt_ra ON NIST80030THREATEVENT(RiskAssessmentID);
    CREATE INDEX IF NOT EXISTS ix_n30vuln_ra ON NIST80030VULNERABILITY(RiskAssessmentID);
    CREATE INDEX IF NOT EXISTS ix_n30risk_ra ON NIST80030RISK(RiskAssessmentID);
  `);
}

// NIST SP 800-30 Rev.1, Appendix I, Table I-2 — Level of Risk (combination of overall
// likelihood [rows] and level of impact [cols]); scale 1..5 = VL/L/M/H/VH. Returns 1..5.
const NIST_RISK_MATRIX: Record<number, number[]> = {
  5: [1, 2, 3, 4, 5], // likelihood Very High
  4: [1, 2, 3, 4, 5], // High
  3: [1, 2, 3, 3, 4], // Moderate
  2: [1, 2, 2, 2, 3], // Low
  1: [1, 1, 1, 2, 2], // Very Low
};
export function nistRiskLevel(overallLikelihood: number, impact: number): number {
  const l = Math.min(5, Math.max(1, Math.round(overallLikelihood)));
  const i = Math.min(5, Math.max(1, Math.round(impact)));
  return NIST_RISK_MATRIX[l][i - 1];
}

/**
 * NIST SP 800-30 dashboard: every 800-30 assessment (RISKASSESSMENT marked 'NIST SP 800-30')
 * with, per assessment, the count of threat sources / threat events / vulnerabilities / risks,
 * the highest risk level and the distribution of risks by level — plus global stats. The
 * friendly home for 800-30 (the EBIOS-RM counterpart) replacing the raw explorer grid.
 */
export function getNist80030Dashboard(tenant: number | null): { assessments: Record<string, unknown>[]; stats: Record<string, unknown> } {
  const db = getDb("XCOMPLIANCE");
  const has = (t: string): boolean => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  if (!has("RISKASSESSMENT")) return { assessments: [], stats: { total: 0 } };
  const tw = tenant != null ? `AND COALESCE(TenantID,${tenant})=${tenant}` : "";
  const rows = db.prepare(
    `SELECT RiskAssessmentID AS id, Name AS name, Description AS description, Status AS status, Date AS date
     FROM RISKASSESSMENT WHERE COALESCE(Methodology,'') LIKE 'NIST SP 800-30%' ${tw}
     ORDER BY RiskAssessmentID DESC`
  ).all() as Record<string, any>[];
  const cnt = (table: string, id: number): number => has(table)
    ? (db.prepare(`SELECT COUNT(*) c FROM "${table}" WHERE RiskAssessmentID=?`).get(id) as { c: number }).c : 0;
  const out = rows.map((s) => {
    const counts = {
      threatSources: cnt("NIST80030THREATSOURCE", s.id),
      threatEvents: cnt("NIST80030THREATEVENT", s.id),
      vulnerabilities: cnt("NIST80030VULNERABILITY", s.id),
      risks: cnt("NIST80030RISK", s.id),
    };
    const byLevel: Record<number, number> = {};
    let maxRisk = 0;
    if (has("NIST80030RISK")) {
      for (const r of db.prepare("SELECT COALESCE(RiskLevel,0) lvl, COUNT(*) c FROM NIST80030RISK WHERE RiskAssessmentID=? GROUP BY RiskLevel").all(s.id) as { lvl: number; c: number }[]) {
        if (r.lvl > 0) byLevel[r.lvl] = r.c;
        if (r.lvl > maxRisk) maxRisk = r.lvl;
      }
    }
    return { ...s, counts, byLevel, maxRisk };
  });
  const sum = (f: (s: any) => number): number => out.reduce((n, s) => n + f(s), 0);
  const stats = {
    total: out.length,
    threatSources: sum((s) => s.counts.threatSources),
    threatEvents: sum((s) => s.counts.threatEvents),
    vulnerabilities: sum((s) => s.counts.vulnerabilities),
    risks: sum((s) => s.counts.risks),
    highRisks: out.reduce((n, s) => n + Object.entries(s.byLevel as Record<string, number>).reduce((m, [lvl, c]) => m + (Number(lvl) >= 4 ? c : 0), 0), 0),
  };
  return { assessments: out, stats };
}

/**
 * Create a NIST SP 800-30 risk assessment from a guided form (the 800-30 counterpart of the
 * EBIOS guided create). Forces Methodology='NIST SP 800-30' so it surfaces on the 800-30
 * dashboard; reuses createRiskAssessment (column-aware INSERT + GUID + tenant). Ensures the
 * 800-30 entity tables exist so the assessment can be populated afterward.
 */
export function createNist80030Assessment(
  p: { name: string; description?: string; status?: string; authorPersonId?: number | null; date?: string },
  tenant: number | null,
): { id: number } {
  ensureNist80030Tables();
  return createRiskAssessment({
    name: p.name, description: p.description, methodology: "NIST SP 800-30",
    status: p.status, authorPersonId: p.authorPersonId ?? null, date: p.date,
  }, tenant);
}

/**
 * Asset Monitoring — uptime / health / SSL monitoring of assets (inspired by CheckCle). Native
 * monitors live in XORCISM (asset-linked); the checkcle connector imports CheckCle's services /
 * servers / SSL certificates / incidents into the same tables. Created idempotently at boot:
 *   MONITORINGCHECK    — a monitor on an asset (type http/ping/tcp/dns/ssl/server + current status,
 *                        uptime %, response time, SSL expiry).
 *   MONITORINGINCIDENT — an up/down incident (open when ResolvedAt is NULL).
 */
export function ensureMonitoringTables(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS MONITORINGCHECK (
      CheckID INTEGER PRIMARY KEY, CheckGUID TEXT, AssetID INTEGER, Name TEXT,
      CheckType TEXT, Target TEXT, IntervalSeconds INTEGER, CronExpression TEXT, Enabled INTEGER DEFAULT 1,
      Status TEXT, UptimePercent REAL, ResponseTimeMs INTEGER, LastCheckedAt TEXT, LastStatusChange TEXT,
      SSLExpiryDate DATE, SSLIssuer TEXT, OwnerPersonID INTEGER, Source TEXT, ExternalID TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS MONITORINGINCIDENT (
      IncidentID INTEGER PRIMARY KEY, IncidentGUID TEXT, CheckID INTEGER, AssetID INTEGER,
      Title TEXT, Status TEXT, Severity TEXT, StartedAt TEXT, ResolvedAt TEXT, DurationMinutes INTEGER,
      Description TEXT, Source TEXT, ExternalID TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_moncheck_asset ON MONITORINGCHECK(AssetID);
    CREATE INDEX IF NOT EXISTS ix_moncheck_status ON MONITORINGCHECK(Status);
    CREATE INDEX IF NOT EXISTS ix_moninc_check ON MONITORINGINCIDENT(CheckID);
  `);
  // CronExpression on pre-existing MONITORINGCHECK tables (optional cron periodicity per monitor).
  if (!new Set((db.prepare(`PRAGMA table_info("MONITORINGCHECK")`).all() as { name: string }[]).map((c) => c.name)).has("CronExpression"))
    db.exec(`ALTER TABLE "MONITORINGCHECK" ADD COLUMN "CronExpression" TEXT`);
}

/**
 * NIST SP 800-53 control management — the per-tenant implementation/status layer over the
 * already-imported 800-53 Rev 5 catalogue (XORCISM.CONTROL, VocabularyID=7, ~1196 controls).
 * The catalogue stays read-only (a shared reference); each tenant records ONE implementation
 * status per control here (org-wide). Also ensures the 800-53 baseline-membership columns on
 * CONTROL (Low/Moderate/High/Privacy), populated by import_nist80053_baselines.py — added here
 * defensively so the management page never crashes when the importer hasn't been run yet.
 * Called at boot.
 */
export function ensureControlImplementationTables(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS CONTROLIMPLEMENTATION (
      ControlImplementationID INTEGER PRIMARY KEY, ControlImplementationGUID TEXT,
      ControlID INTEGER, Status TEXT, Responsibility TEXT, Narrative TEXT,
      OwnerPersonID INTEGER, TargetDate DATE, LastReviewedDate TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_ctrlimpl_control ON CONTROLIMPLEMENTATION(ControlID);
    CREATE INDEX IF NOT EXISTS ix_ctrlimpl_tenant ON CONTROLIMPLEMENTATION(TenantID);
    -- Crosswalks: an 800-53 control mapped to another framework object (ATT&CK technique, D3FEND, CSF…).
    -- Global reference facts (no tenant), filled by import_attack_80053_mappings.py et al.
    CREATE TABLE IF NOT EXISTS CONTROLMAPPING (
      MappingID INTEGER PRIMARY KEY, MappingGUID TEXT, ControlID INTEGER, Framework TEXT,
      ExternalID TEXT, ExternalName TEXT, Relationship TEXT, Source TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_ctrlmap_control ON CONTROLMAPPING(ControlID);
    CREATE INDEX IF NOT EXISTS ix_ctrlmap_fw ON CONTROLMAPPING(Framework);
    -- Plan of Action & Milestones — a control deficiency tracked to closure (per tenant).
    CREATE TABLE IF NOT EXISTS CONTROLPOAM (
      PoamID INTEGER PRIMARY KEY, PoamGUID TEXT, ControlID INTEGER, Title TEXT, WeaknessDescription TEXT,
      Severity TEXT, Status TEXT, RemediationPlan TEXT, Milestones TEXT, OwnerPersonID INTEGER,
      ScheduledCompletionDate DATE, ActualCompletionDate DATE, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_ctrlpoam_control ON CONTROLPOAM(ControlID);
    CREATE INDEX IF NOT EXISTS ix_ctrlpoam_tenant ON CONTROLPOAM(TenantID);
    -- Free-text tags on a control (mirrors ASSETTAG), for the CONTROL form tag-picker.
    CREATE TABLE IF NOT EXISTS CONTROLTAG (
      ControlTagID INTEGER PRIMARY KEY, ControlID INTEGER, TagID INTEGER, Tag TEXT,
      CreatedDate TEXT, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_controltag_control ON CONTROLTAG(ControlID);
  `);
  // 800-53 baseline membership + rich control text live on the (shared) catalogue rows — global NIST facts.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROL'").get()) {
    const have = new Set((db.prepare(`PRAGMA table_info("CONTROL")`).all() as { name: string }[]).map((c) => c.name));
    const ctrlCols: Record<string, string> = {
      BaselineLow: "INTEGER", BaselineModerate: "INTEGER", BaselineHigh: "INTEGER", BaselinePrivacy: "INTEGER",
      Statement: "TEXT", Guidance: "TEXT", Params: "TEXT", RelatedControls: "TEXT",
    };
    for (const [col, type] of Object.entries(ctrlCols)) if (!have.has(col)) db.exec(`ALTER TABLE "CONTROL" ADD COLUMN "${col}" ${type}`);
  }
  // Per-tenant assessment (SP 800-53A) lives alongside the implementation record.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLIMPLEMENTATION'").get()) {
    const have = new Set((db.prepare(`PRAGMA table_info("CONTROLIMPLEMENTATION")`).all() as { name: string }[]).map((c) => c.name));
    const a: Record<string, string> = { AssessmentResult: "TEXT", AssessedDate: "TEXT", AssessorPersonID: "INTEGER", AssessmentRemarks: "TEXT" };
    for (const [col, type] of Object.entries(a)) if (!have.has(col)) db.exec(`ALTER TABLE "CONTROLIMPLEMENTATION" ADD COLUMN "${col}" ${type}`);
  }
  // Free-text Tag column on the (legacy, TagID-only) CONTROLTAG, for the CONTROL form tag-picker.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLTAG'").get() &&
      !new Set((db.prepare(`PRAGMA table_info("CONTROLTAG")`).all() as { name: string }[]).map((c) => c.name)).has("Tag"))
    db.exec(`ALTER TABLE "CONTROLTAG" ADD COLUMN "Tag" TEXT`);
}

/**
 * CIS Benchmarks — consensus secure-configuration baselines (under Configuration Management), kept in
 * XOVAL alongside the OVAL/SCAP content. CISBENCHMARK = a benchmark (e.g. "CIS Ubuntu 22.04 LTS v2.0.0"),
 * CISBENCHMARKRECOMMENDATION = its recommendations (numbered, L1/L2), CISBENCHMARKRESULT = per-asset
 * pass/fail from a CIS-CAT scan. Catalogue seeded by import_cis_benchmarks.py; results via CIS-CAT import
 * / the cis-cat connector. Called at boot.
 */
export function ensureCisBenchmarkTables(): void {
  let db: Database.Database;
  try { db = getDb("XOVAL"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS CISBENCHMARK (
      BenchmarkID INTEGER PRIMARY KEY, BenchmarkGUID TEXT, Name TEXT, Version TEXT, Platform TEXT,
      Category TEXT, Source TEXT, ExternalID TEXT, RecommendationCount INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CISBENCHMARKRECOMMENDATION (
      RecommendationID INTEGER PRIMARY KEY, RecommendationGUID TEXT, BenchmarkID INTEGER, Number TEXT,
      Title TEXT, Level TEXT, Section TEXT, Description TEXT, Remediation TEXT, AssessmentType TEXT,
      ExternalID TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CISBENCHMARKRESULT (
      ResultID INTEGER PRIMARY KEY, ResultGUID TEXT, BenchmarkID INTEGER, RecommendationID INTEGER,
      RecommendationNumber TEXT, AssetID INTEGER, Result TEXT, Severity TEXT, CheckedAt TEXT,
      Source TEXT, ExternalID TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_cisrec_benchmark ON CISBENCHMARKRECOMMENDATION(BenchmarkID);
    CREATE INDEX IF NOT EXISTS ix_cisres_benchmark ON CISBENCHMARKRESULT(BenchmarkID);
    CREATE INDEX IF NOT EXISTS ix_cisres_asset ON CISBENCHMARKRESULT(AssetID);
  `);
}

/**
 * Trust Center — a Drata-style public-facing security posture page, driven by live data, with a
 * shareable read-only view at /trust/<slug>. One config row per tenant (XCOMPLIANCE.TRUSTCENTER):
 * slug, enabled, branding, sub-processors + published frameworks (JSON), and which live panels to
 * show. The public view only ever exposes aggregate posture (coverage %, framework status, uptime) —
 * never asset/control detail. Called at boot.
 */
export function ensureTrustCenterTables(): void {
  let db: Database.Database;
  try { db = getDb("XCOMPLIANCE"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS TRUSTCENTER (
      TrustCenterID INTEGER PRIMARY KEY, TenantID INTEGER, Slug TEXT, Enabled INTEGER DEFAULT 0,
      CompanyName TEXT, Title TEXT, Intro TEXT, ContactEmail TEXT, Subprocessors TEXT, Frameworks TEXT,
      ShowControls INTEGER DEFAULT 1, ShowUptime INTEGER DEFAULT 1, ShowPolicies INTEGER DEFAULT 1,
      UpdatedAt TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_trustcenter_slug ON TRUSTCENTER(Slug);
    CREATE INDEX IF NOT EXISTS ix_trustcenter_tenant ON TRUSTCENTER(TenantID);
  `);
}

/**
 * Patch Management — make patch status, SLAs and remediation plans first-class on the EXISTING
 * vulnerability-remediation model (no new core tables). Patch status is per-asset-vulnerability
 * (you patch a CVE on a given asset), so it lives on ASSETVULNERABILITY; the remediation plan
 * reuses the legacy ASSETVULNERABILITYREMEDIATION. Idempotent ALTERs (the legacy tables ship thin):
 *   ASSETVULNERABILITY            += PatchStatus / PatchedDate / TargetDate / RemediationOwnerPersonID / Priority
 *   ASSETVULNERABILITYREMEDIATION += Status / RemediationType / TargetDate / Priority / TenantID
 * Called at boot.
 */
export function ensurePatchTables(): void {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return; }
  const add = (table: string, want: Record<string, string>): void => {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) return;
    const have = new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
    for (const [n, t] of Object.entries(want)) if (!have.has(n)) db.exec(`ALTER TABLE "${table}" ADD COLUMN "${n}" ${t}`);
  };
  add("ASSETVULNERABILITY", {
    PatchStatus: "TEXT", PatchedDate: "DATE", TargetDate: "DATE", RemediationOwnerPersonID: "INTEGER", Priority: "TEXT",
  });
  add("ASSETVULNERABILITYREMEDIATION", {
    Status: "TEXT", RemediationType: "TEXT", TargetDate: "DATE", Priority: "TEXT", TenantID: "INTEGER",
  });
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITYREMEDIATION'").get()) {
    db.exec("CREATE INDEX IF NOT EXISTS ix_avr_av ON ASSETVULNERABILITYREMEDIATION(AssetVulnerabilityID);");
  }
}

/**
 * OT / ICS / SCADA / IoT Security — IEC 62443 & NIST SP 800-82 assessments. OT assessments REUSE
 * XCOMPLIANCE.AUDIT (AuditType='OT Security', AuditCategory = the standard) + AUDITFINDING, exactly
 * like Compliance / Crisis Management — no AUDIT change needed. This adds the IEC 62443 structural
 * entities (created idempotently at boot; **phased** — the schema is in place now, the UI fleshes it
 * out over time): zones & conduits with target/achieved/capable Security Levels (SL 1-4) and Purdue
 * levels, and a zone↔asset link. OT assets themselves are identified by ASSETTAG tags (ot/ics/scada/iot).
 */
export function ensureOtSecurityTables(): void {
  let db: Database.Database;
  try { db = getDb("XCOMPLIANCE"); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS OTZONE (
      ZoneID INTEGER PRIMARY KEY, ZoneGUID TEXT, AuditID INTEGER, Name TEXT, Description TEXT,
      PurdueLevel TEXT, Criticality TEXT,
      SecurityLevelTarget INTEGER, SecurityLevelAchieved INTEGER, SecurityLevelCapability INTEGER,
      AssetCount INTEGER, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS OTCONDUIT (
      ConduitID INTEGER PRIMARY KEY, ConduitGUID TEXT, AuditID INTEGER, Name TEXT, Description TEXT,
      FromZoneID INTEGER, ToZoneID INTEGER, Protocols TEXT,
      SecurityLevelTarget INTEGER, SecurityLevelAchieved INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS OTZONEASSET (
      ZoneAssetID INTEGER PRIMARY KEY, ZoneID INTEGER, AssetID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_otzone_audit ON OTZONE(AuditID);
    CREATE INDEX IF NOT EXISTS ix_otconduit_audit ON OTCONDUIT(AuditID);
    CREATE INDEX IF NOT EXISTS ix_otzoneasset_zone ON OTZONEASSET(ZoneID);
  `);
}

/**
 * Threat-modeling dashboard: every THREATMODEL (scope, methodology, status, risk) with, per model,
 * the count of in-scope assets (THREATMODELASSET), identified threats (THREATMODELTHREAT), open
 * threats and mitigations (THREATMODELCONTROL via the model's threats). Tenant-visible (own +
 * legacy NULL; super-admin = all). The friendly home replacing the raw THREATMODEL explorer grid.
 */
export function getThreatModelDashboard(tenant: number | null): { models: Record<string, unknown>[]; stats: Record<string, unknown> } {
  let db: Database.Database;
  try { db = getDb("XORCISM"); } catch { return { models: [], stats: { total: 0 } }; }
  const has = (t: string): boolean => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  if (!has("THREATMODEL")) return { models: [], stats: { total: 0 } };
  const vis = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const models = db.prepare(
    `SELECT ThreatModelID AS id, ThreatModelName AS name, Description AS description, Methodology AS methodology,
            Status AS status, Scope AS scope, RiskLevel AS riskLevel, Owner AS owner, CreatedDate AS createdDate
     FROM THREATMODEL ${vis} ORDER BY ThreatModelID DESC`,
  ).all() as Record<string, any>[];
  const cnt = (table: string, id: number): number =>
    has(table) ? (db.prepare(`SELECT COUNT(*) c FROM "${table}" WHERE ThreatModelID=?`).get(id) as { c: number }).c : 0;
  const CLOSED = /closed|mitigat|resolv|accepted|done|ferm/i;
  const out = models.map((m) => {
    const threats = has("THREATMODELTHREAT")
      ? (db.prepare("SELECT Status FROM THREATMODELTHREAT WHERE ThreatModelID=?").all(m.id) as { Status: string }[]) : [];
    const openThreats = threats.filter((t) => !CLOSED.test(String(t.Status ?? ""))).length;
    const mitigations = has("THREATMODELCONTROL") && has("THREATMODELTHREAT")
      ? (db.prepare(`SELECT COUNT(*) c FROM THREATMODELCONTROL c JOIN THREATMODELTHREAT t ON t.ThreatModelThreatID = c.ThreatModelThreatID WHERE t.ThreatModelID=?`).get(m.id) as { c: number }).c : 0;
    return { ...m, counts: { assets: cnt("THREATMODELASSET", m.id), threats: threats.length, openThreats, mitigations } };
  });
  const sum = (f: (m: any) => number): number => out.reduce((n, m) => n + f(m), 0);
  return {
    models: out,
    stats: {
      total: out.length,
      threats: sum((m) => m.counts.threats),
      openThreats: sum((m) => m.counts.openThreats),
      mitigations: sum((m) => m.counts.mitigations),
    },
  };
}

/**
 * Create a THREATMODEL from a guided form — the friendly path that replaces the raw explorer
 * insert (and sidesteps the phantom-PK link-panel trap, since child links are added after save).
 * Column-aware INSERT + GUID + tenant. ThreatModelID is a real INTEGER PRIMARY KEY.
 */
export function createThreatModel(
  p: { name: string; description?: string; methodology?: string; status?: string; scope?: string; riskLevel?: string; owner?: string },
  tenant: number | null,
): { id: number } {
  const db = getDb("XORCISM");
  const cols = new Set((db.prepare(`PRAGMA table_info("THREATMODEL")`).all() as { name: string }[]).map((c) => c.name));
  const now = new Date().toISOString();
  const candidate: Record<string, unknown> = {
    ThreatModelGUID: randomUUID(),
    ThreatModelName: (p.name || "Untitled threat model").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Methodology: (p.methodology || "STRIDE").slice(0, 80),
    Status: (p.status || "Draft").slice(0, 60),
    Scope: p.scope ? String(p.scope).slice(0, 2000) : null,
    RiskLevel: p.riskLevel ? String(p.riskLevel).slice(0, 40) : null,
    Owner: p.owner ? String(p.owner).slice(0, 200) : null,
    CreatedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => cols.has(k));
  const sql = `INSERT INTO THREATMODEL (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = db.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

/**
 * TPRM (Third-Party Risk Management) dashboard: third-party assessments based on
 * QUESTIONNAIREFORORGANISATION (XCOMPLIANCE). Resolves the organisation/questionnaire/
 * owner names (cross-database) + number of questions, and aggregates statistics.
 */
export function getTprmDashboard(): { assessments: Record<string, unknown>[]; stats: Record<string, unknown> } {
  const xc = getDb("XCOMPLIANCE");
  if (!xc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='QUESTIONNAIREFORORGANISATION'").get())
    return { assessments: [], stats: { total: 0 } };
  const rows = xc.prepare(
    `SELECT QuestionnaireOrganisationID AS id, QuestionnaireID AS qid, OrganisationID AS oid, PersonID AS pid,
            Relationship, Status, AssessmentType, RiskRating, Score, VendorCriticality, DueDate, CompletedDate, CreatedDate
     FROM QUESTIONNAIREFORORGANISATION ORDER BY QuestionnaireOrganisationID DESC`
  ).all() as Record<string, any>[];
  const qNames = new Map<number, string>();
  for (const q of xc.prepare("SELECT QuestionnaireID, QuestionnaireName FROM QUESTIONNAIRE").all() as Record<string, any>[]) qNames.set(q.QuestionnaireID, q.QuestionnaireName);
  const qCounts = new Map<number, number>();
  try { for (const c of xc.prepare("SELECT QuestionnaireID, COUNT(*) c FROM QUESTIONFORQUESTIONNAIRE GROUP BY QuestionnaireID").all() as Record<string, any>[]) qCounts.set(c.QuestionnaireID, c.c); } catch { /* table missing */ }
  const xo = getDb("XORCISM");
  const orgNames = new Map<number, string>();
  for (const o of xo.prepare("SELECT OrganisationID, OrganisationName FROM ORGANISATION").all() as Record<string, any>[]) orgNames.set(o.OrganisationID, o.OrganisationName);
  const personNames = new Map<number, string>();
  for (const p of xo.prepare("SELECT PersonID, FullName FROM PERSON").all() as Record<string, any>[]) personNames.set(p.PersonID, p.FullName);
  const today = new Date().toISOString().slice(0, 10);
  const assessments = rows.map((r) => ({
    id: r.id,
    organisation: orgNames.get(r.oid) || (r.oid ? `#${r.oid}` : ""),
    questionnaire: qNames.get(r.qid) || (r.qid ? `#${r.qid}` : ""),
    questions: qCounts.get(r.qid) || 0,
    relationship: r.Relationship || "", status: r.Status || "", type: r.AssessmentType || "",
    riskRating: r.RiskRating || "", score: r.Score, criticality: r.VendorCriticality || "",
    dueDate: r.DueDate || "", completedDate: r.CompletedDate || "", owner: personNames.get(r.pid) || "",
    overdue: !!(r.DueDate && r.DueDate < today && !r.CompletedDate && String(r.Status || "").toLowerCase() !== "completed"),
  }));
  const tally = (vals: string[]): Record<string, number> => {
    const m: Record<string, number> = {};
    for (const v of vals) m[v || "—"] = (m[v || "—"] || 0) + 1;
    return m;
  };
  const scores = assessments.map((a) => Number(a.score)).filter((n) => Number.isFinite(n));
  const stats = {
    total: assessments.length,
    byStatus: tally(assessments.map((a) => a.status)),
    byRisk: tally(assessments.map((a) => a.riskRating)),
    overdue: assessments.filter((a) => a.overdue).length,
    avgScore: scores.length ? Math.round(scores.reduce((x, y) => x + y, 0) / scores.length) : null,
  };
  return { assessments, stats };
}

/**
 * Bug Bounty program management (XVULNERABILITY):
 *  - BUGBOUNTYPROGRAM      : program (platform, status, policy, reward range).
 *  - BUGBOUNTYSCOPE        : in-scope / out-of-scope perimeter.
 *  - BUGBOUNTYRESEARCHER   : researchers/hunters.
 *  - BUGBOUNTYSUBMISSION   : submissions (linked to VULNERABILITY), triage→resolution cycle.
 *  - BUGBOUNTYREWARD       : rewards/payments.
 *  - BUGBOUNTYREWARDTIER   : reward scale per severity.
 * Idempotent (CREATE IF NOT EXISTS). Called at boot.
 */
export function ensureBugBountyTables(): void {
  const db = getDb("XVULNERABILITY");
  db.exec(`
    CREATE TABLE IF NOT EXISTS BUGBOUNTYPROGRAM (
      ProgramID INTEGER PRIMARY KEY, ProgramGUID TEXT, Name TEXT, Description TEXT,
      Platform TEXT, Status TEXT, PolicyURL TEXT, ScopeDescription TEXT,
      OrganisationID INTEGER, MinReward REAL, MaxReward REAL, Currency TEXT,
      StartDate DATE, EndDate DATE, CreatedDate DATE);
    CREATE TABLE IF NOT EXISTS BUGBOUNTYSCOPE (
      ScopeID INTEGER PRIMARY KEY, ProgramID INTEGER, Target TEXT, ScopeType TEXT,
      AssetType TEXT, Description TEXT, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_bbscope_prog ON BUGBOUNTYSCOPE(ProgramID);
    CREATE TABLE IF NOT EXISTS BUGBOUNTYRESEARCHER (
      ResearcherID INTEGER PRIMARY KEY, ResearcherGUID TEXT, Handle TEXT, FullName TEXT,
      Platform TEXT, ProfileURL TEXT, Email TEXT, Reputation TEXT, Country TEXT, CreatedDate DATE);
    CREATE TABLE IF NOT EXISTS BUGBOUNTYSUBMISSION (
      SubmissionID INTEGER PRIMARY KEY, SubmissionGUID TEXT, ProgramID INTEGER, ResearcherID INTEGER,
      Title TEXT, Description TEXT, Severity TEXT, CVSSBaseScore REAL, Status TEXT,
      VulnerabilityID INTEGER, CWEID TEXT, Target TEXT, RewardAmount REAL, Currency TEXT,
      DuplicateOfSubmissionID INTEGER, SubmittedDate DATE, TriagedDate DATE, ResolvedDate DATE, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_bbsub_prog ON BUGBOUNTYSUBMISSION(ProgramID);
    CREATE INDEX IF NOT EXISTS ix_bbsub_vuln ON BUGBOUNTYSUBMISSION(VulnerabilityID);
    CREATE TABLE IF NOT EXISTS BUGBOUNTYREWARD (
      RewardID INTEGER PRIMARY KEY, SubmissionID INTEGER, ResearcherID INTEGER, ProgramID INTEGER,
      Amount REAL, Currency TEXT, RewardType TEXT, Status TEXT, PaidDate DATE, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_bbreward_sub ON BUGBOUNTYREWARD(SubmissionID);
    CREATE TABLE IF NOT EXISTS BUGBOUNTYREWARDTIER (
      RewardTierID INTEGER PRIMARY KEY, ProgramID INTEGER, Severity TEXT,
      MinReward REAL, MaxReward REAL, Currency TEXT, CreatedDate DATE);
    CREATE INDEX IF NOT EXISTS ix_bbtier_prog ON BUGBOUNTYREWARDTIER(ProgramID);
  `);
}

/**
 * Builds a STIX 2.1 bundle from the XTHREAT hunts: each HUNT becomes a
 * custom `x-hunt` object, linked (relationship "hunts") to the ATT&CK techniques
 * (via HUNTATTACK, `attack-pattern` nodes reusing the real StixID when known) and
 * to the IOCs (via HUNTIOC, `indicator` nodes). Loaded by the STIX Graph page.
 */
export function getHuntsStixBundle(huntId?: number): { type: string; id: string; spec_version: string; objects: unknown[] } {
  const db = getDb("XTHREAT");
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const has = (n: string): boolean =>
    !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(n);
  const objects: Record<string, unknown>[] = [];
  const bundle = { type: "bundle", id: `bundle--${randomUUID()}`, spec_version: "2.1", objects };
  if (!has("HUNT")) return bundle;

  const huntCols = "SELECT HuntID, HuntGUID, HuntName, HuntDescription, HuntReference, HuntSource, HuntStatus, HuntTool FROM HUNT";
  const hunts = (huntId != null && Number.isFinite(huntId)
    ? db.prepare(`${huntCols} WHERE HuntID = ?`).all(huntId)
    : db.prepare(huntCols).all()) as Record<string, any>[];
  const huntStix = new Map<number, string>();
  for (const h of hunts) {
    const id = `x-hunt--${uuidRe.test(h.HuntGUID || "") ? h.HuntGUID : randomUUID()}`;
    huntStix.set(h.HuntID, id);
    const obj: Record<string, unknown> = { type: "x-hunt", spec_version: "2.1", id, name: h.HuntName || `Hunt ${h.HuntID}` };
    if (h.HuntDescription) obj.description = h.HuntDescription;
    if (h.HuntReference) obj.external_references = [{ source_name: h.HuntSource || "novasky.io", url: h.HuntReference }];
    if (h.HuntStatus) obj.x_status = h.HuntStatus;
    if (h.HuntTool) obj.x_tool = h.HuntTool;
    objects.push(obj);
  }

  // HUNT → ATT&CK techniques
  if (has("HUNTATTACK")) {
    const techTable = has("ATTACKTECHNIQUE");
    const apByAttackId = new Map<string, string>();
    const links = db.prepare("SELECT HuntID, AttackID, AttackTechniqueID FROM HUNTATTACK").all() as Record<string, any>[];
    for (const l of links) {
      const src = huntStix.get(l.HuntID);
      if (!src || !l.AttackID) continue;
      let apId = apByAttackId.get(l.AttackID);
      if (!apId) {
        let stixId: string | null = null, name: string | null = null;
        if (techTable && l.AttackTechniqueID != null) {
          const t = db.prepare("SELECT StixID, Name FROM ATTACKTECHNIQUE WHERE AttackTechniqueID=?").get(l.AttackTechniqueID) as Record<string, any> | undefined;
          if (t) { stixId = t.StixID; name = t.Name; }
        }
        apId = (typeof stixId === "string" && stixId.startsWith("attack-pattern--")) ? stixId : `attack-pattern--${randomUUID()}`;
        apByAttackId.set(l.AttackID, apId);
        objects.push({
          type: "attack-pattern", spec_version: "2.1", id: apId, name: name || l.AttackID,
          external_references: [{ source_name: "mitre-attack", external_id: l.AttackID }],
        });
      }
      objects.push({ type: "relationship", spec_version: "2.1", id: `relationship--${randomUUID()}`, relationship_type: "hunts", source_ref: src, target_ref: apId });
    }
  }

  // HUNT → IOC indicators
  if (has("HUNTIOC") && has("IOC")) {
    const iocStix = new Map<number, string>();
    const links = db.prepare("SELECT HuntID, IOCID, Relationship FROM HUNTIOC").all() as Record<string, any>[];
    for (const l of links) {
      const src = huntStix.get(l.HuntID);
      if (!src || l.IOCID == null) continue;
      let iid = iocStix.get(l.IOCID);
      if (!iid) {
        const ioc = db.prepare("SELECT StixID, IOCName, Pattern, IOCDescription FROM IOC WHERE IOCID=?").get(l.IOCID) as Record<string, any> | undefined;
        if (!ioc) continue;
        iid = (typeof ioc.StixID === "string" && ioc.StixID.startsWith("indicator--")) ? ioc.StixID : `indicator--${randomUUID()}`;
        iocStix.set(l.IOCID, iid);
        const o: Record<string, unknown> = { type: "indicator", spec_version: "2.1", id: iid, name: ioc.IOCName || `IOC ${l.IOCID}` };
        if (ioc.Pattern) { o.pattern = ioc.Pattern; o.pattern_type = "stix"; }
        if (ioc.IOCDescription) o.description = ioc.IOCDescription;
        objects.push(o);
      }
      objects.push({ type: "relationship", spec_version: "2.1", id: `relationship--${randomUUID()}`, relationship_type: l.Relationship || "hunts", source_ref: src, target_ref: iid });
    }
  }

  return bundle;
}

/**
 * STIX 2.1 bundle of the XTHREAT threat reports (THREATREPORT). Each report becomes
 * a STIX `report` SDO; the ATT&CK techniques (Txxxx) and CVEs mentioned in its
 * name/description are emitted as attack-pattern / vulnerability objects and added
 * to the report's object_refs (so the report links to them in the STIX Graph).
 */
export function getReportsStixBundle(reportId?: number): { type: string; id: string; spec_version: string; objects: unknown[] } {
  const db = getDb("XTHREAT");
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const has = (n: string): boolean =>
    !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(n);
  const objects: Record<string, unknown>[] = [];
  const bundle = { type: "bundle", id: `bundle--${randomUUID()}`, spec_version: "2.1", objects };
  if (!has("THREATREPORT")) return bundle;

  const techTable = has("ATTACKTECHNIQUE");
  const apByAttackId = new Map<string, string>(); // AttackID → attack-pattern STIX id
  const vulnByCve = new Map<string, string>();     // CVE → vulnerability STIX id
  const attackRe = /\bT\d{4}(?:\.\d{3})?\b/g;
  const cveRe = /\bCVE-\d{4}-\d{4,7}\b/gi;

  const resolveTechnique = (attackId: string): string => {
    let apId = apByAttackId.get(attackId);
    if (apId) return apId;
    let stixId: string | null = null, name: string | null = null;
    if (techTable) {
      const t = db.prepare("SELECT StixID, Name FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1").get(attackId) as Record<string, any> | undefined;
      if (t) { stixId = t.StixID; name = t.Name; }
    }
    apId = (typeof stixId === "string" && stixId.startsWith("attack-pattern--")) ? stixId : `attack-pattern--${randomUUID()}`;
    apByAttackId.set(attackId, apId);
    objects.push({
      type: "attack-pattern", spec_version: "2.1", id: apId, name: name || attackId,
      external_references: [{ source_name: "mitre-attack", external_id: attackId }],
    });
    return apId;
  };
  const resolveCve = (cve: string): string => {
    const key = cve.toUpperCase();
    let vId = vulnByCve.get(key);
    if (vId) return vId;
    vId = `vulnerability--${randomUUID()}`;
    vulnByCve.set(key, vId);
    objects.push({
      type: "vulnerability", spec_version: "2.1", id: vId, name: key,
      external_references: [{ source_name: "cve", external_id: key }],
    });
    return vId;
  };

  const reportCols = "SELECT ThreatReportID, ThreatReportGUID, ThreatReportName, ThreatReportDescription, CreatedDate FROM THREATREPORT";
  const reports = (reportId != null && Number.isFinite(reportId)
    ? db.prepare(`${reportCols} WHERE ThreatReportID = ?`).all(reportId)
    : db.prepare(reportCols).all()) as Record<string, any>[];
  for (const r of reports) {
    const id = `report--${uuidRe.test(r.ThreatReportGUID || "") ? r.ThreatReportGUID : randomUUID()}`;
    const text = `${r.ThreatReportName || ""} ${r.ThreatReportDescription || ""}`;
    const refs = new Set<string>();
    for (const m of text.match(attackRe) || []) refs.add(resolveTechnique(m));
    for (const m of text.match(cveRe) || []) refs.add(resolveCve(m));
    const obj: Record<string, unknown> = {
      type: "report", spec_version: "2.1", id,
      name: r.ThreatReportName || `Report ${r.ThreatReportID}`,
      report_types: ["threat-report"],
      published: r.CreatedDate || new Date().toISOString(),
      object_refs: refs.size ? [...refs] : [id], // STIX requires ≥1 ref
    };
    if (r.ThreatReportDescription) obj.description = r.ThreatReportDescription;
    objects.push(obj);
    for (const ref of refs) {
      objects.push({ type: "relationship", spec_version: "2.1", id: `relationship--${randomUUID()}`, relationship_type: "refers-to", source_ref: id, target_ref: ref });
    }
  }

  return bundle;
}

// Default D3FEND tactics (official matrix order) — fallback if the table is
// empty/missing (before import) so the view at least displays the columns.
const D3FEND_TACTICS: { short: string; name: string }[] = [
  { short: "Model", name: "Model" }, { short: "Harden", name: "Harden" },
  { short: "Detect", name: "Detect" }, { short: "Isolate", name: "Isolate" },
  { short: "Deceive", name: "Deceive" }, { short: "Evict", name: "Evict" },
  { short: "Restore", name: "Restore" },
];

export interface D3fendSub { d3fendId: string; name: string; url: string | null; attackIds: string[] }
export interface D3fendTech { d3fendId: string; name: string; url: string | null; attackIds: string[]; subtechniques: D3fendSub[] }
export interface D3fendTactic { name: string; shortName: string; definition: string | null; techniques: D3fendTech[] }
export interface D3fendMatrix { tactics: D3fendTactic[] }

// D3FEND matrix (tactics → techniques → sub-techniques) + ATT&CK mappings.
export function getD3fendMatrix(): D3fendMatrix {
  const db = getDb("XTHREAT");
  const exists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='D3FENDTECHNIQUE'")
    .get();
  if (!exists) {
    return { tactics: D3FEND_TACTICS.map((t) => ({ name: t.name, shortName: t.short, definition: null, techniques: [] })) };
  }
  let tactics = db
    .prepare("SELECT ShortName AS short, Name AS name, Definition AS def FROM D3FENDTACTIC ORDER BY CASE WHEN MatrixOrder IS NULL THEN 1 ELSE 0 END, MatrixOrder, Name")
    .all() as { short: string; name: string; def: string | null }[];
  if (!tactics.length) tactics = D3FEND_TACTICS.map((t) => ({ short: t.short, name: t.name, def: null }));

  // ATT&CK mappings per D3FENDID
  const mapRows = db.prepare("SELECT D3FENDID AS d3, AttackID AS aid FROM D3FENDATTACKMAP").all() as
    { d3: string; aid: string }[];
  const attackByD3 = new Map<string, string[]>();
  for (const m of mapRows) {
    if (!attackByD3.has(m.d3)) attackByD3.set(m.d3, []);
    if (m.aid && !attackByD3.get(m.d3)!.includes(m.aid)) attackByD3.get(m.d3)!.push(m.aid);
  }
  const subs = db
    .prepare("SELECT D3FENDID AS d3, Name AS name, URL AS url, ParentD3FENDID AS parent FROM D3FENDTECHNIQUE WHERE COALESCE(IsSubtechnique,0)=1 ORDER BY D3FENDID")
    .all() as { d3: string; name: string; url: string | null; parent: string | null }[];
  const subsByParent = new Map<string, D3fendSub[]>();
  for (const s of subs) {
    if (!s.parent) continue;
    if (!subsByParent.has(s.parent)) subsByParent.set(s.parent, []);
    subsByParent.get(s.parent)!.push({ d3fendId: s.d3, name: s.name, url: s.url, attackIds: attackByD3.get(s.d3) ?? [] });
  }
  // D3FEND nests over 3+ levels: we flatten all descendants under their base
  // technique (standard matrix presentation), not just the direct children.
  const descendantsOf = (base: string): D3fendSub[] => {
    const acc: D3fendSub[] = [];
    const seen = new Set<string>();
    const walk = (d3: string) => {
      for (const s of subsByParent.get(d3) ?? []) {
        if (seen.has(s.d3fendId)) continue;
        seen.add(s.d3fendId);
        acc.push(s);
        walk(s.d3fendId);
      }
    };
    walk(base);
    return acc;
  };
  const top = db
    .prepare("SELECT D3FENDID AS d3, Name AS name, URL AS url, TacticShortName AS tac FROM D3FENDTECHNIQUE WHERE COALESCE(IsSubtechnique,0)=0 ORDER BY D3FENDID")
    .all() as { d3: string; name: string; url: string | null; tac: string | null }[];
  const byTactic = new Map<string, D3fendTech[]>();
  for (const r of top) {
    const tac = r.tac ?? "";
    if (!byTactic.has(tac)) byTactic.set(tac, []);
    byTactic.get(tac)!.push({ d3fendId: r.d3, name: r.name, url: r.url, attackIds: attackByD3.get(r.d3) ?? [], subtechniques: descendantsOf(r.d3) });
  }
  return {
    tactics: tactics.map((t) => ({ name: t.name, shortName: t.short, definition: t.def, techniques: byTactic.get(t.short) ?? [] })),
  };
}

/**
 * Retypes the ValidFrom column to DATE for the relevant XORCISM tables. SQLite
 * does not allow ALTERing a column's type: we rebuild each table
 * (CREATE/INSERT/DROP/RENAME) preserving columns, PK, NOT NULL, DEFAULT, the
 * data and the indexes. Idempotent (ignores tables already in DATE). None of
 * the targeted tables is referenced by a foreign key (verified).
 */
function ensureValidFromDateType(db: Database.Database): void {
  const TABLES = [
    "TRAINING", "TRAININGFORPERSON", "ASSETTHREAT", "ASSETAUDIT",
    "ASSETAUDITFINDING", "ASSETOVALDEFINITION", "ASSETFINANCIALVALUE", "VENDOR",
  ];
  interface Col { name: string; type: string; notnull: number; dflt_value: string | null; pk: number }
  const fkOn = db.pragma("foreign_keys", { simple: true }) as number;
  let toggled = false;
  try {
    for (const table of TABLES) {
      if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) continue;
      const cols = db.prepare(`PRAGMA table_info("${table}")`).all() as Col[];
      const vf = cols.find((c) => c.name === "ValidFrom");
      if (!vf || (vf.type || "").toUpperCase() === "DATE") continue; // absent or already DATE
      if (!toggled) { db.pragma("foreign_keys = OFF"); toggled = true; }
      const pkCols = cols.filter((c) => c.pk).sort((a, b) => a.pk - b.pk);
      const colDef = (c: Col): string => {
        let d = `"${c.name}" ${c.name === "ValidFrom" ? "DATE" : (c.type || "")}`.trimEnd();
        if (pkCols.length === 1 && c.pk) d += " PRIMARY KEY";
        if (c.notnull) d += " NOT NULL";
        if (c.dflt_value != null) d += " DEFAULT " + c.dflt_value;
        return d;
      };
      const defs = cols.map(colDef);
      if (pkCols.length > 1) defs.push(`PRIMARY KEY (${pkCols.map((c) => `"${c.name}"`).join(", ")})`);
      const colList = cols.map((c) => `"${c.name}"`).join(", ");
      const idxs = db.prepare(
        "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL"
      ).all(table) as { sql: string }[];
      const tmp = `${table}__retype`;
      db.transaction(() => {
        db.exec(`DROP TABLE IF EXISTS "${tmp}"`);
        db.exec(`CREATE TABLE "${tmp}" (${defs.join(", ")})`);
        db.exec(`INSERT INTO "${tmp}" (${colList}) SELECT ${colList} FROM "${table}"`);
        db.exec(`DROP TABLE "${table}"`);
        db.exec(`ALTER TABLE "${tmp}" RENAME TO "${table}"`);
        for (const ix of idxs) { try { db.exec(ix.sql); } catch { /* index recreated as needed */ } }
      })();
      console.log(`[db] ${table}.ValidFrom retypé en DATE`);
    }
  } finally {
    if (toggled) db.pragma(`foreign_keys = ${fkOn ? "ON" : "OFF"}`);
  }
}

/**
 * Schema of the NOTIFICATION table. A legacy NOTIFICATION table exists in the
 * original XORCISM schema (NotificationMessage/UserID/ImportanceID, without read
 * tracking). We reuse it and complete it via idempotent ALTERs rather than
 * recreating it. On a blank database, the CREATE lays down the full schema directly.
 */
function ensureNotificationSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS NOTIFICATION (
      NotificationID INTEGER PRIMARY KEY,
      NotificationGUID TEXT, UserID INTEGER, Title TEXT, NotificationMessage TEXT,
      Level TEXT, Link TEXT, Source TEXT,
      IsRead INTEGER DEFAULT 0, ReadDate TEXT, CreatedDate TEXT, TenantID INTEGER);
  `);
  const have = new Set(
    (db.prepare("PRAGMA table_info(NOTIFICATION)").all() as { name: string }[]).map((c) => c.name)
  );
  const wanted: [string, string][] = [
    ["Title", "TEXT"], ["NotificationMessage", "TEXT"], ["Level", "TEXT"],
    ["Link", "TEXT"], ["Source", "TEXT"], ["IsRead", "INTEGER DEFAULT 0"],
    ["ReadDate", "TEXT"], ["TenantID", "INTEGER"],
  ];
  for (const [col, type] of wanted) {
    if (!have.has(col)) db.exec(`ALTER TABLE NOTIFICATION ADD COLUMN ${col} ${type}`);
  }
  db.exec("CREATE INDEX IF NOT EXISTS ix_notif_user ON NOTIFICATION(UserID, IsRead)");
}

/**
 * Per-user rules controlling which events auto-create notifications (managed from the user
 * Settings panel → see server/notifrules.ts for the event catalogue + dispatch engine).
 * One row per (UserID, EventKey): Enabled toggle + a minimum severity threshold (MinLevel).
 * Absence of a row means "use the event's catalogue default".
 */
export function ensureNotificationRuleTable(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS NOTIFICATIONRULE (
        RuleID INTEGER PRIMARY KEY, RuleGUID TEXT, UserID INTEGER, EventKey TEXT,
        Enabled INTEGER DEFAULT 1, MinLevel TEXT DEFAULT 'info',
        CreatedDate TEXT, UpdatedDate TEXT, TenantID INTEGER);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_notifrule_user_event ON NOTIFICATIONRULE(UserID, EventKey);`);
  } catch { /* best-effort */ }
}

/**
 * SOC operations schema (XINCIDENT) — analyst rota / on-call (SOCSHIFT), an escalation procedure
 * (ESCALATIONPOLICY + ordered ESCALATIONTIER with ack/resolve timeouts) and its per-incident log
 * (INCIDENTESCALATION), and an IR-playbook library (PLAYBOOK + PLAYBOOKSTEP, NIST SP 800-61 phases)
 * materialized onto an incident as INCIDENTPLAYBOOKSTEP. INCIDENT gains acknowledge_datetime (for
 * MTTA), EscalationTier, PlaybookID and AssignedPersonID. See server/soc.ts for the cockpit + KPIs.
 */
export function ensureSocTables(): void {
  try {
    const db = getDb("XINCIDENT");
    db.exec(`
      CREATE TABLE IF NOT EXISTS SOCSHIFT (
        ShiftID INTEGER PRIMARY KEY, ShiftGUID TEXT, PersonID INTEGER, PersonName TEXT,
        Tier TEXT, ShiftDate TEXT, StartTime TEXT, EndTime TEXT, OnCall INTEGER DEFAULT 0,
        Status TEXT, Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS ESCALATIONPOLICY (
        PolicyID INTEGER PRIMARY KEY, PolicyGUID TEXT, Name TEXT, Description TEXT,
        IsDefault INTEGER DEFAULT 0, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS ESCALATIONTIER (
        TierID INTEGER PRIMARY KEY, PolicyID INTEGER, Level INTEGER, Name TEXT, TargetRole TEXT,
        AckMinutes INTEGER, ResolveMinutes INTEGER, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS INCIDENTESCALATION (
        EscalationID INTEGER PRIMARY KEY, IncidentID INTEGER, FromTier TEXT, ToTier TEXT,
        Reason TEXT, ByPerson TEXT, ToPerson TEXT, EscalatedAt TEXT, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS PLAYBOOK (
        PlaybookID INTEGER PRIMARY KEY, PlaybookGUID TEXT, Name TEXT, Category TEXT,
        Description TEXT, Severity TEXT, StepCount INTEGER, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS PLAYBOOKSTEP (
        StepID INTEGER PRIMARY KEY, PlaybookID INTEGER, Phase TEXT, StepOrder INTEGER,
        Title TEXT, Description TEXT, Role TEXT, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS INCIDENTPLAYBOOKSTEP (
        RunStepID INTEGER PRIMARY KEY, IncidentID INTEGER, PlaybookID INTEGER, Phase TEXT,
        StepOrder INTEGER, Title TEXT, Description TEXT, Status TEXT DEFAULT 'todo',
        CompletedBy TEXT, CompletedAt TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_socshift_tenant ON SOCSHIFT(TenantID);
      CREATE INDEX IF NOT EXISTS ix_socshift_person ON SOCSHIFT(PersonID);
      CREATE INDEX IF NOT EXISTS ix_esctier_policy ON ESCALATIONTIER(PolicyID);
      CREATE INDEX IF NOT EXISTS ix_incesc_incident ON INCIDENTESCALATION(IncidentID);
      CREATE INDEX IF NOT EXISTS ix_pbstep_playbook ON PLAYBOOKSTEP(PlaybookID);
      CREATE INDEX IF NOT EXISTS ix_incpbstep_incident ON INCIDENTPLAYBOOKSTEP(IncidentID);`);
    if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) {
      const have = new Set((db.prepare(`PRAGMA table_info("INCIDENT")`).all() as { name: string }[]).map((c) => c.name));
      for (const [n, t] of [["acknowledge_datetime", "TEXT"], ["EscalationTier", "TEXT"], ["PlaybookID", "INTEGER"], ["AssignedPersonID", "INTEGER"]] as [string, string][])
        if (!have.has(n)) db.exec(`ALTER TABLE "INCIDENT" ADD COLUMN "${n}" ${t}`);
    }
  } catch { /* best-effort */ }
}

/** SOC-CMM self-assessment (XINCIDENT): aspect catalogue (5 domains) + per-tenant maturity scores. */
export function ensureSocCmmTables(): void {
  try {
    getDb("XINCIDENT").exec(`
      CREATE TABLE IF NOT EXISTS SOCCMMASPECT (
        AspectID INTEGER PRIMARY KEY, Domain TEXT, Aspect TEXT, Description TEXT, Weight REAL DEFAULT 1, SortOrder INTEGER);
      CREATE TABLE IF NOT EXISTS SOCCMMSCORE (
        ScoreID INTEGER PRIMARY KEY, AspectID INTEGER, Maturity INTEGER, Importance INTEGER DEFAULT 3,
        Notes TEXT, AssessedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_soccmm_score ON SOCCMMSCORE(AspectID, TenantID);`);
  } catch { /* best-effort */ }
}

/** CERT / CSIRT operations (XINCIDENT): forensic cases, chain-of-custody log, CERT activities. */
export function ensureCertOpsTables(): void {
  try {
    getDb("XINCIDENT").exec(`
      CREATE TABLE IF NOT EXISTS FORENSICCASE (
        CaseID INTEGER PRIMARY KEY, CaseGUID TEXT, CaseNumber TEXT, Title TEXT, IncidentID INTEGER,
        Status TEXT, Severity TEXT, Examiner TEXT, ExaminerPersonID INTEGER, Description TEXT,
        Methodology TEXT, OpenedDate TEXT, ClosedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS FORENSICEVIDENCE (
        EvidenceID INTEGER PRIMARY KEY, EvidenceGUID TEXT, CaseID INTEGER, ExhibitNumber TEXT, Description TEXT,
        EvidenceType TEXT, Source TEXT, AcquisitionTool TEXT, Sha256 TEXT, Md5 TEXT, Size TEXT,
        Status TEXT, CollectedBy TEXT, CollectedAt TEXT, StorageLocation TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS CUSTODYEVENT (
        CustodyID INTEGER PRIMARY KEY, EvidenceID INTEGER, CaseID INTEGER, Action TEXT, FromParty TEXT, ToParty TEXT,
        Purpose TEXT, Hash TEXT, HashVerified INTEGER, At TEXT, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS CERTACTIVITY (
        ActivityID INTEGER PRIMARY KEY, ActivityGUID TEXT, Title TEXT, ActivityType TEXT, Service TEXT,
        Status TEXT, Priority TEXT, IncidentID INTEGER, CaseID INTEGER, AssignedTo TEXT, Description TEXT,
        DueDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_fcase_tenant ON FORENSICCASE(TenantID);
      CREATE INDEX IF NOT EXISTS ix_fevid_case ON FORENSICEVIDENCE(CaseID);
      CREATE INDEX IF NOT EXISTS ix_custody_evid ON CUSTODYEVENT(EvidenceID);
      CREATE INDEX IF NOT EXISTS ix_certact_tenant ON CERTACTIVITY(TenantID);`);
  } catch { /* best-effort */ }
}

/** Governance (XCOMPLIANCE) — NIST CSF 2.0 Govern (GV) subcategory register + per-tenant status. */
export function ensureGovernanceTables(): void {
  try {
    getDb("XCOMPLIANCE").exec(`
      CREATE TABLE IF NOT EXISTS GOVERNANCEITEM (
        ItemID INTEGER PRIMARY KEY, Category TEXT, CategoryCode TEXT, SubCode TEXT, Title TEXT, Description TEXT, SortOrder INTEGER);
      CREATE TABLE IF NOT EXISTS GOVERNANCESTATUS (
        StatusID INTEGER PRIMARY KEY, ItemID INTEGER, Status TEXT, Maturity INTEGER, OwnerPersonID INTEGER,
        Evidence TEXT, Notes TEXT, ReviewDate TEXT, TenantID INTEGER, UpdatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_govstatus ON GOVERNANCESTATUS(ItemID, TenantID);`);
  } catch { /* best-effort */ }
}

/** OWASP AI Exchange / agentic threat catalogue (XTHREAT) for the AI threat advisor in threat modeling. */
export function ensureAiThreatTables(): void {
  try {
    getDb("XTHREAT").exec(`
      CREATE TABLE IF NOT EXISTS AIEXCHANGETHREAT (
        ThreatID INTEGER PRIMARY KEY, ThreatGUID TEXT, Ref TEXT, Name TEXT, Category TEXT, Lifecycle TEXT,
        Impact TEXT, Description TEXT, Controls TEXT, AppliesTo TEXT, Source TEXT, URL TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_aithreat_cat ON AIEXCHANGETHREAT(Category);`);
  } catch { /* best-effort */ }
}

/**
 * Network flow (NetFlow/IPFIX) around ASSET — discovery & monitoring, useful for the SOC.
 * ASSETSERVICE = a listening service (the ASSET↔SERVICE relationship: protocol/port/service seen on
 * an asset). NETWORKSESSION = a reconstructed network session/flow (protocol, source↔destination
 * assets+IPs+ports, bytes/packets, first/last seen, state). Fed by the obserae connector (NetFlow
 * collector cartography + sessions). Surfaced at /network-sessions.
 */
export function ensureNetflowTables(): void {
  try {
    getDb("XORCISM").exec(`
      CREATE TABLE IF NOT EXISTS ASSETSERVICE (
        AssetServiceID INTEGER PRIMARY KEY, AssetID INTEGER, Protocol TEXT, Port INTEGER, ServiceName TEXT,
        Banner TEXT, FlowCount INTEGER DEFAULT 0, FirstSeen TEXT, LastSeen TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS NETWORKSESSION (
        NetworkSessionID INTEGER PRIMARY KEY, SessionGUID TEXT, SrcAssetID INTEGER, DstAssetID INTEGER,
        SrcIP TEXT, DstIP TEXT, Protocol TEXT, SrcPort INTEGER, DstPort INTEGER, ServiceName TEXT,
        Bytes INTEGER, Packets INTEGER, Flows INTEGER, Direction TEXT, State TEXT,
        FirstSeen TEXT, LastSeen TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_assetservice ON ASSETSERVICE(AssetID, Protocol, Port);
      CREATE INDEX IF NOT EXISTS ix_netsession_src ON NETWORKSESSION(SrcAssetID);
      CREATE INDEX IF NOT EXISTS ix_netsession_dst ON NETWORKSESSION(DstAssetID);
      CREATE INDEX IF NOT EXISTS ix_netsession_tenant ON NETWORKSESSION(TenantID);`);
  } catch { /* best-effort */ }
}

/**
 * Vulnerability Operations Center (XVULNERABILITY) — runs remediation as an operations function.
 * VOCSLATIER = a configurable remediation-SLA policy (days per severity/KEV tier); VOCCAMPAIGN =
 * remediation campaigns/sprints over a scope of vulnerabilities; VOCEXCEPTION = the formal risk-
 * acceptance / exception register (justification, approver, expiry). The operational backlog + KPIs
 * are computed over XORCISM.ASSETVULNERABILITY cross-enriched with XVULNERABILITY.VULNERABILITY.
 */
export function ensureVocTables(): void {
  try {
    getDb("XVULNERABILITY").exec(`
      CREATE TABLE IF NOT EXISTS VOCSLATIER (
        SlaID INTEGER PRIMARY KEY, Tier TEXT, RemediationDays INTEGER, Label TEXT, SortOrder INTEGER, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS VOCCAMPAIGN (
        CampaignID INTEGER PRIMARY KEY, CampaignGUID TEXT, Name TEXT, Description TEXT, Scope TEXT,
        TargetDate TEXT, OwnerPersonID INTEGER, Status TEXT, StartDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS VOCEXCEPTION (
        ExceptionID INTEGER PRIMARY KEY, ExceptionGUID TEXT, VulnerabilityID INTEGER, AssetVulnerabilityID INTEGER,
        Scope TEXT, Title TEXT, Justification TEXT, CompensatingControl TEXT, RequestedBy TEXT, ApprovedBy TEXT,
        Status TEXT, ExpiryDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_vocsla_tenant ON VOCSLATIER(TenantID);
      CREATE INDEX IF NOT EXISTS ix_voccamp_tenant ON VOCCAMPAIGN(TenantID);
      CREATE INDEX IF NOT EXISTS ix_vocexc_tenant ON VOCEXCEPTION(TenantID);`);
  } catch { /* best-effort */ }
}

/**
 * Vulnerability-management posture history (XVULNERABILITY) — one row per (tenant, day) capturing
 * the day's headline VM KPIs (open backlog, KEV/exploitable/critical open, risk-weighted exposure,
 * SLA compliance %, overdue, MTTR, remediation coverage, unassigned). Written on first sight of a
 * day then kept fresh — a clean daily time series that turns the point-in-time VOC into trend lines.
 * Feeds the /vm-report executive briefing (risk-reduction-over-time + data-driven myth-busting).
 */
export function ensureVmTrendsTables(): void {
  try {
    getDb("XVULNERABILITY").exec(`
      CREATE TABLE IF NOT EXISTS VMSNAPSHOT (
        SnapshotID INTEGER PRIMARY KEY, TenantID INTEGER, SnapshotDate TEXT,
        OpenCount INTEGER, TotalCount INTEGER, RemediatedCount INTEGER,
        KevOpen INTEGER, ExploitableOpen INTEGER, CriticalOpen INTEGER, HighOpen INTEGER,
        RiskExposure REAL, SlaCompliance INTEGER, OverdueCount INTEGER, MttrDays INTEGER,
        Coverage INTEGER, UnassignedOpen INTEGER, Source TEXT, CreatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_vmsnapshot ON VMSNAPSHOT(TenantID, SnapshotDate);
      CREATE INDEX IF NOT EXISTS ix_vmsnapshot_tenant ON VMSNAPSHOT(TenantID);`);
  } catch { /* best-effort */ }
}

/**
 * CTEM — Continuous Threat Exposure Management (XVULNERABILITY). Support for the ctem.org
 * (SecureCoders) standardized exposure-identifier taxonomy: a "CVE/CWE for exposures" — vendor-neutral
 * identifiers (CTEM-<CAT>-<n>) across 8 categories, run through a 3-stage program (Discover →
 * Prioritize → Remediate). CTEMIDENTIFIER = the reference catalogue (global, seeded from the embedded
 * list / refreshed from ctem.org/source.json). CTEMEXPOSURE = the tenant's observed exposures
 * classified against an identifier and tracked through the stages. Surfaced at /ctem.
 */
export function ensureCtemTables(): void {
  try {
    getDb("XVULNERABILITY").exec(`
      CREATE TABLE IF NOT EXISTS CTEMIDENTIFIER (
        CtemIdentifierID INTEGER PRIMARY KEY, CtemId TEXT, Title TEXT, CategoryCode TEXT, Category TEXT,
        Description TEXT, Link TEXT, Version TEXT, UpdatedDate TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS CTEMEXPOSURE (
        ExposureID INTEGER PRIMARY KEY, ExposureGUID TEXT, CtemId TEXT, Title TEXT, CategoryCode TEXT,
        Stage TEXT, Severity TEXT, Status TEXT, AssetID INTEGER, RemediationOwnerPersonID INTEGER,
        Source TEXT, Evidence TEXT, FirstSeen TEXT, LastSeen TEXT, DiscoveredDate TEXT, RemediatedDate TEXT,
        TenantID INTEGER, CreatedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_ctemidentifier ON CTEMIDENTIFIER(CtemId);
      CREATE INDEX IF NOT EXISTS ix_ctemexposure_tenant ON CTEMEXPOSURE(TenantID);
      CREATE INDEX IF NOT EXISTS ix_ctemexposure_ctemid ON CTEMEXPOSURE(CtemId);`);
  } catch { /* best-effort */ }
}

/**
 * Lossless STIX / IOC retention (XTHREAT). XORCISM normalizes STIX into relational tables, which is
 * great for joins but loses the original object (any unmodeled property/extension is dropped). This
 * adds the "store the original, index what you query" layer:
 *   - a RawJson column on the CTI tables (OBSERVABLE / IOC / INTELEXCHANGE) for inline retention;
 *   - a central STIXOBJECT store keyed by StixID holding the full original object;
 *   - an FTS5 full-text index (STIXOBJECT_FTS) over name / value / the whole payload, so IOC values
 *     and any nested field are searchable.
 * Powers GET /api/stix/object/:stixId, GET /api/stix/search and POST /api/stix/ingest (see stixstore.ts).
 */
export function ensureStixObjectStore(): void {
  try {
    const db = getDb("XTHREAT");
    const addRaw = (t: string): void => {
      try {
        if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t)) return;
        const have = new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name));
        if (!have.has("RawJson")) db.exec(`ALTER TABLE "${t}" ADD COLUMN "RawJson" TEXT`);
      } catch { /* table absent on this deployment */ }
    };
    addRaw("OBSERVABLE"); addRaw("IOC"); addRaw("INTELEXCHANGE");
    db.exec(`
      CREATE TABLE IF NOT EXISTS STIXOBJECT (
        StixObjectID INTEGER PRIMARY KEY, StixID TEXT, StixType TEXT, SpecVersion TEXT, Name TEXT,
        RawJson TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT, ModifiedDate TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_stixobject ON STIXOBJECT(StixID);
      CREATE INDEX IF NOT EXISTS ix_stixobject_type ON STIXOBJECT(StixType);
      CREATE INDEX IF NOT EXISTS ix_stixobject_tenant ON STIXOBJECT(TenantID);`);
    try { db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS STIXOBJECT_FTS USING fts5(stixId UNINDEXED, stixType, name, value, content, tokenize='porter unicode61');`); }
    catch (e) { console.warn(`[stix] FTS5 unavailable, search disabled: ${(e as Error).message}`); }
  } catch { /* best-effort */ }
}

/**
 * DevSecOps operations (XORCISM) — manage security in the SDLC/CI-CD pipeline as an operational
 * function. DEVSECOPSAPP = an application / repository under DevSecOps (optionally linked to the
 * existing APPLICATION + ASSET). DEVSECOPSSCAN = a pipeline security scan across the standard scan
 * classes (SAST / DAST / SCA / Secrets / IaC / Container) with a tool (semgrep, gitleaks, trivy,
 * burpwn, …) and per-severity finding counts + gate result. DEVSECOPSGATE = the security-gate policy
 * (per app or global) — the max allowed severity per scan class and whether it blocks the pipeline.
 * Surfaced at /devsecops.
 */
export function ensureDevSecOpsTables(): void {
  try {
    const db = getDb("XORCISM");
    db.exec(`
      CREATE TABLE IF NOT EXISTS DEVSECOPSAPP (
        AppID INTEGER PRIMARY KEY, AppGUID TEXT, Name TEXT, Repo TEXT, Language TEXT, Team TEXT,
        OwnerPersonID INTEGER, Criticality TEXT, PipelineUrl TEXT, DefaultBranch TEXT,
        ApplicationID INTEGER, AssetID INTEGER, AsvsLevel INTEGER, Status TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS DEVSECOPSSCAN (
        ScanID INTEGER PRIMARY KEY, ScanGUID TEXT, AppID INTEGER, ScanType TEXT, Tool TEXT, Status TEXT,
        Critical INTEGER DEFAULT 0, High INTEGER DEFAULT 0, Medium INTEGER DEFAULT 0, Low INTEGER DEFAULT 0,
        Findings INTEGER DEFAULT 0, GatePassed INTEGER, Branch TEXT, Ref TEXT, Url TEXT, RanAt TEXT,
        DurationSec INTEGER, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS DEVSECOPSGATE (
        GateID INTEGER PRIMARY KEY, AppID INTEGER, ScanType TEXT, MaxSeverity TEXT,
        BlockOnFail INTEGER DEFAULT 1, Enabled INTEGER DEFAULT 1, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS DEVSECOPSASVS (
        DevsecopsAsvsID INTEGER PRIMARY KEY, AppID INTEGER, Shortcode TEXT, Status TEXT, Notes TEXT,
        VerifiedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_devsecopsapp_tenant ON DEVSECOPSAPP(TenantID);
      CREATE INDEX IF NOT EXISTS ix_devsecopsscan_app ON DEVSECOPSSCAN(AppID);
      CREATE INDEX IF NOT EXISTS ix_devsecopsgate_tenant ON DEVSECOPSGATE(TenantID);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_devsecopsasvs ON DEVSECOPSASVS(AppID, Shortcode);`);
    // AsvsLevel added after the table shipped → column-aware ALTER for existing deployments
    try { const have = new Set((db.prepare(`PRAGMA table_info("DEVSECOPSAPP")`).all() as { name: string }[]).map((c) => c.name)); if (!have.has("AsvsLevel")) db.exec(`ALTER TABLE DEVSECOPSAPP ADD COLUMN AsvsLevel INTEGER`); } catch { /* */ }
  } catch { /* best-effort */ }
}

/**
 * Purple / Red / Blue Team Operations (XTHREAT) — VECTR-style purple-team exercises mapped to
 * MITRE ATT&CK. TEAMEXERCISE = a campaign; EXERCISETESTCASE = one ATT&CK technique with the red
 * offensive action and the blue outcome (prevented / detected / logged / missed) + detection time,
 * for prevention/detection/visibility efficiency metrics. TEAMCAPABILITY = red/blue/purple
 * capability & capacity management.
 */
export function ensureTeamOpsTables(): void {
  try {
    getDb("XTHREAT").exec(`
      CREATE TABLE IF NOT EXISTS TEAMEXERCISE (
        ExerciseID INTEGER PRIMARY KEY, ExerciseGUID TEXT, Name TEXT, ExerciseType TEXT,
        Objective TEXT, ThreatActor TEXT, Status TEXT, StartDate TEXT, EndDate TEXT,
        TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS EXERCISETESTCASE (
        TestCaseID INTEGER PRIMARY KEY, ExerciseID INTEGER, AttackID TEXT, Technique TEXT, Tactic TEXT,
        OffensiveAction TEXT, OffensiveTool TEXT, ExpectedDefense TEXT, Outcome TEXT,
        Prevented INTEGER DEFAULT 0, Detected INTEGER DEFAULT 0, Logged INTEGER DEFAULT 0,
        DetectionTimeMin INTEGER, DetectionSource TEXT, ResponseAction TEXT, SigmaRuleID INTEGER,
        Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS TEAMCAPABILITY (
        CapabilityID INTEGER PRIMARY KEY, Team TEXT, Name TEXT, Category TEXT, Maturity INTEGER,
        Capacity TEXT, Tooling TEXT, OwnerPersonID INTEGER, Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_teamex_tenant ON TEAMEXERCISE(TenantID);
      CREATE INDEX IF NOT EXISTS ix_testcase_ex ON EXERCISETESTCASE(ExerciseID);
      CREATE INDEX IF NOT EXISTS ix_teamcap_tenant ON TEAMCAPABILITY(TenantID);`);
  } catch { /* best-effort */ }
}

/** Cybersecurity workforce framework (XORCISM) — NICE + ENISA ECSF role catalogue, assignable to PERSON. */
export function ensureWorkforceTables(): void {
  try {
    getDb("XORCISM").exec(`
      CREATE TABLE IF NOT EXISTS WORKROLE (
        WorkRoleID INTEGER PRIMARY KEY, WorkRoleGUID TEXT, Framework TEXT, Code TEXT, Name TEXT, Category TEXT,
        Description TEXT, Tasks TEXT, Skills TEXT, Knowledge TEXT, URL TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS PERSONWORKROLE (
        PersonWorkRoleID INTEGER PRIMARY KEY, PersonID INTEGER, WorkRoleID INTEGER, Proficiency TEXT,
        Primary_ INTEGER DEFAULT 0, Notes TEXT, AssignedDate TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_workrole_fw ON WORKROLE(Framework);
      CREATE INDEX IF NOT EXISTS ix_pwr_person ON PERSONWORKROLE(PersonID);`);
  } catch { /* best-effort */ }
}

// ── User notifications ─────────────────────────────────────────────────
export interface NotificationInput {
  userId: number;
  title: string;
  message?: string | null;
  level?: string;        // info | success | warning | error
  link?: string | null;  // route/URL to open on click
  source?: string | null;
  tenantId?: number | null;
}
export interface NotificationRow {
  NotificationID: number; Title: string; Message: string | null;
  Level: string | null; Link: string | null; Source: string | null;
  IsRead: number; CreatedDate: string | null;
}

/** Creates a notification for a user; returns its ID. */
export function createNotification(n: NotificationInput): number {
  const db = getDb("XORCISM");
  const id = allocId(db, "NOTIFICATION", "NotificationID");
  db.prepare(
    `INSERT INTO NOTIFICATION
       (NotificationID, NotificationGUID, UserID, Title, NotificationMessage, Level, Link, Source, IsRead, ReadDate, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,0,NULL,?,?)`
  ).run(id, randomUUID(), n.userId, n.title, n.message ?? null,
    n.level ?? "info", n.link ?? null, n.source ?? null, nowTs(), n.tenantId ?? null);
  return id;
}

/** Broadcasts the same notification to several users; returns the number created. */
export function notifyUsers(userIds: number[], n: Omit<NotificationInput, "userId">): number {
  let c = 0;
  for (const uid of userIds) { if (Number.isInteger(uid) && uid > 0) { createNotification({ ...n, userId: uid }); c++; } }
  return c;
}

/**
 * Iterates over the uncorrected ASSETVULNERABILITY rows (Status = 0) and, for those whose
 * linked VULNERABILITY is in the KEV catalogue (VULNERABILITY.KEV = 1), creates a
 * "New ASSETVULNERABILITY for KEV" notification for the user. Idempotent:
 * deduplicated by link (a unique deep link per AssetVulnerabilityID) → no
 * duplicate on each ASSET save. Bounded to the tenant if the caller is scoped.
 * Returns the number of notifications created.
 */
export function checkForNewKevVulnerabilityAndNotify(
  userId: number,
  tenant: number | null
): number {
  const xo = getDb("XORCISM");
  // Uncorrected rows (Status=0). Absent/NULL Status → treated as 0 (Unpatched).
  const rows = xo
    .prepare(
      `SELECT AssetVulnerabilityID, AssetID, VulnerabilityID FROM "ASSETVULNERABILITY"
       WHERE COALESCE(CAST(Status AS INTEGER), 0) = 0 AND VulnerabilityID IS NOT NULL` +
        (tenant != null ? ` AND TenantID = ?` : ``)
    )
    .all(...(tenant != null ? [tenant] : [])) as
    { AssetVulnerabilityID: number; AssetID: number; VulnerabilityID: number }[];
  if (!rows.length) return 0;

  // KEV of the linked vulnerabilities (XVULNERABILITY) in batches (chunked IN).
  const xv = getDb("XVULNERABILITY");
  const ids = Array.from(new Set(rows.map((r) => r.VulnerabilityID)));
  const kev = new Set<number>();
  for (let i = 0; i < ids.length; i += 500) {
    const chunk = ids.slice(i, i + 500);
    const ph = chunk.map(() => "?").join(",");
    const found = xv
      .prepare(`SELECT VulnerabilityID FROM "VULNERABILITY" WHERE KEV = 1 AND VulnerabilityID IN (${ph})`)
      .all(...chunk) as { VulnerabilityID: number }[];
    for (const f of found) kev.add(f.VulnerabilityID);
  }
  if (!kev.size) return 0;

  const seen = xo.prepare("SELECT 1 FROM NOTIFICATION WHERE UserID = ? AND Link = ? LIMIT 1");
  let created = 0;
  for (const av of rows) {
    if (!kev.has(av.VulnerabilityID)) continue;
    const link = `/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=AssetVulnerabilityID&filterVal=${av.AssetVulnerabilityID}`;
    if (seen.get(userId, link)) continue; // already notified for this link
    createNotification({
      userId,
      title: "New ASSETVULNERABILITY for KEV",
      message: `Asset #${av.AssetID} · Vulnerability #${av.VulnerabilityID} (KEV) is Unpatched.`,
      level: "warning",
      link,
      source: "kev-check",
      tenantId: tenant,
    });
    created++;
  }
  return created;
}

/** Recent notifications of a user (most recent first). */
export function listNotifications(userId: number, limit = 30): NotificationRow[] {
  return getDb("XORCISM")
    .prepare(
      `SELECT NotificationID, Title, NotificationMessage AS Message, Level, Link, Source, IsRead, CreatedDate
       FROM NOTIFICATION WHERE UserID = ? ORDER BY NotificationID DESC LIMIT ?`
    )
    .all(userId, Math.min(Math.max(limit, 1), 100)) as NotificationRow[];
}

export function unreadNotificationCount(userId: number): number {
  return (getDb("XORCISM")
    .prepare("SELECT COUNT(*) AS n FROM NOTIFICATION WHERE UserID = ? AND IsRead = 0")
    .get(userId) as { n: number }).n;
}

export function markNotificationRead(userId: number, id: number): boolean {
  const r = getDb("XORCISM")
    .prepare("UPDATE NOTIFICATION SET IsRead = 1, ReadDate = ? WHERE NotificationID = ? AND UserID = ?")
    .run(nowTs(), id, userId);
  return r.changes > 0;
}

export function markAllNotificationsRead(userId: number): number {
  const r = getDb("XORCISM")
    .prepare("UPDATE NOTIFICATION SET IsRead = 1, ReadDate = ? WHERE UserID = ? AND IsRead = 0")
    .run(nowTs(), userId);
  return r.changes;
}

const nowTs = (): string => new Date().toISOString().replace("T", " ").slice(0, 19);

/** Assets (ASSET) in a threat model's scope. */
export function getThreatModelAssets(modelId: number): { AssetID: number; AssetName: string }[] {
  return getDb("XORCISM")
    .prepare(
      `SELECT a.AssetID AS AssetID, a.AssetName AS AssetName
       FROM THREATMODELASSET ta JOIN ASSET a ON a.AssetID = ta.AssetID
       WHERE ta.ThreatModelID = ? ORDER BY a.AssetName COLLATE NOCASE`
    )
    .all(modelId) as { AssetID: number; AssetName: string }[];
}

export function setThreatModelAssets(modelId: number, assetIds: number[], tenant: number | null = null): void {
  const db = getDb("XORCISM");
  const hasTenant = tableHasTenantCol("XORCISM", "THREATMODELASSET");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATMODELASSET WHERE ThreatModelID = ?").run(modelId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(ThreatModelAssetID),0) AS m FROM THREATMODELASSET").get() as { m: number }).m;
    const ins = hasTenant
      ? db.prepare("INSERT INTO THREATMODELASSET (ThreatModelAssetID,ThreatModelID,AssetID,CreatedDate,TenantID) VALUES (?,?,?,?,?)")
      : db.prepare("INSERT INTO THREATMODELASSET (ThreatModelAssetID,ThreatModelID,AssetID,CreatedDate) VALUES (?,?,?,?)");
    for (const aid of assetIds) {
      if (aid == null) continue;
      maxId++;
      if (hasTenant) ins.run(maxId, modelId, aid, nowTs(), tenant);
      else ins.run(maxId, modelId, aid, nowTs());
    }
  });
  tx();
}

/** Threats (THREATMODELTHREAT) of a threat model — summary list. */
export interface ThreatRow {
  ThreatModelThreatID: number; Title: string; STRIDECategory: string;
  Likelihood: string; Impact: string; RiskScore: string; Status: string;
}
export function getThreatModelThreats(modelId: number): ThreatRow[] {
  return getDb("XORCISM")
    .prepare(
      `SELECT ThreatModelThreatID, Title, STRIDECategory, Likelihood, Impact, RiskScore, Status
       FROM THREATMODELTHREAT WHERE ThreatModelID = ? ORDER BY ThreatModelThreatID`
    )
    .all(modelId) as ThreatRow[];
}

/** Creates a threat in a model; returns its id. */
export function addThreatModelThreat(modelId: number, t: Record<string, unknown>, tenant: number | null = null): number {
  const db = getDb("XORCISM");
  const hasTenant = tableHasTenantCol("XORCISM", "THREATMODELTHREAT");
  const id = allocId(db, "THREATMODELTHREAT", "ThreatModelThreatID");
  const cols = ["ThreatModelThreatID", "ThreatModelID", "Title", "STRIDECategory", "Description",
    "ThreatAgentID", "AttackPattern", "Likelihood", "Impact", "RiskScore", "Status", "CreatedDate"];
  const vals: unknown[] = [id, modelId, t.Title ?? null, t.STRIDECategory ?? null, t.Description ?? null,
    t.ThreatAgentID ?? null, t.AttackPattern ?? null, t.Likelihood ?? null, t.Impact ?? null,
    t.RiskScore ?? null, t.Status ?? null, nowTs()];
  if (hasTenant) { cols.push("TenantID"); vals.push(tenant); }
  db.prepare(`INSERT INTO THREATMODELTHREAT (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`).run(...vals);
  return id;
}

/** Mitigation controls (CONTROL) linked to a threat. */
export function getThreatControls(threatId: number): { ControlID: number; ControlName: string }[] {
  return getDb("XORCISM")
    .prepare(
      `SELECT c.ControlID AS ControlID, c.ControlName AS ControlName
       FROM THREATMODELCONTROL tc JOIN CONTROL c ON c.ControlID = tc.ControlID
       WHERE tc.ThreatModelThreatID = ? ORDER BY c.ControlName COLLATE NOCASE`
    )
    .all(threatId) as { ControlID: number; ControlName: string }[];
}

export function setThreatControls(threatId: number, controlIds: number[], tenant: number | null = null): void {
  const db = getDb("XORCISM");
  const hasTenant = tableHasTenantCol("XORCISM", "THREATMODELCONTROL");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM THREATMODELCONTROL WHERE ThreatModelThreatID = ?").run(threatId);
    let maxId = (db.prepare("SELECT COALESCE(MAX(ThreatModelControlID),0) AS m FROM THREATMODELCONTROL").get() as { m: number }).m;
    const ins = hasTenant
      ? db.prepare("INSERT INTO THREATMODELCONTROL (ThreatModelControlID,ThreatModelThreatID,ControlID,Status,CreatedDate,TenantID) VALUES (?,?,?,?,?,?)")
      : db.prepare("INSERT INTO THREATMODELCONTROL (ThreatModelControlID,ThreatModelThreatID,ControlID,Status,CreatedDate) VALUES (?,?,?,?,?)");
    for (const cid of controlIds) {
      if (cid == null) continue;
      maxId++;
      if (hasTenant) ins.run(maxId, threatId, cid, "Proposed", nowTs(), tenant);
      else ins.run(maxId, threatId, cid, "Proposed", nowTs());
    }
  });
  tx();
}
