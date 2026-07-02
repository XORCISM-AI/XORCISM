/**
 * assets.ts — Asset Management inventory + governance worklist.
 *
 * The counterpart of identities.ts for ASSET: one pane over the asset estate that
 * resolves each asset's owner, exposure, backup posture, control & BIA coverage and
 * open vulnerability load (cross-DB to XVULNERABILITY for KEV / critical / SSVC), then
 * derives the governance findings a security team acts on — crown jewels exposed to the
 * Internet, critical assets without a backup, owner-less (unaccountable) assets, assets
 * carrying KEV/critical vulnerabilities, missing controls/BIA, PII at risk, and stale or
 * end-of-life assets — each with a 0-100 risk score.
 *
 * Read-only inventory; a guided createAsset() backs the "New asset" modal (the friendly
 * path replacing the raw explorer insert). Full ASSET CRUD stays in the schema-driven explorer.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export interface AssetRow {
  id: number;
  name: string;
  criticality: string;
  owner: string | null;
  environment: string;             // Cloud / Virtual / Third-party / On-premises
  exposure: "Internet" | "Internal";
  backed: boolean;
  backupPlan: boolean;
  pii: boolean;
  businessValue: number | null;
  financialValue: number | null;
  riskScore: number | null;
  os: string;
  address: string;
  vulns: { open: number; kev: number; critical: number };
  controls: number;
  hasBia: boolean;
  lastChecked: string | null;
  flags: string[];
  score: number;                   // 0-100 derived governance/risk priority
  tags: string[];                  // ASSETTAG free-text tags (for filtering + bulk targeting)
  mfaEnabled: boolean;
}

export interface AssetFinding {
  kind: string;
  label: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  assetId: number;
  asset: string;
}

export interface AssetInventory {
  rows: AssetRow[];
  findings: AssetFinding[];
  summary: {
    total: number; crownJewels: number; internetFacing: number; pii: number;
    unbackedCritical: number; noOwner: number; withCriticalVulns: number; stale: number;
    byCriticality: Record<string, number>;
    byEnvironment: Record<string, number>;
  };
}

const EMPTY: AssetInventory = {
  rows: [], findings: [],
  summary: { total: 0, crownJewels: 0, internetFacing: 0, pii: 0, unbackedCritical: 0, noOwner: 0, withCriticalVulns: 0, stale: 0, byCriticality: {}, byEnvironment: {} },
};

const STALE_DAYS = 180;           // not reviewed for longer → hygiene gap
const CRITICAL = /^(high|critical)$/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || String(v ?? "").toLowerCase() === "true"; }
function num(v: unknown): number | null { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; }
const d10 = (v: unknown): string | null => (v ? String(v).slice(0, 10) : null);
function daysSince(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date));
  return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
}

/** Full asset inventory with resolved posture + derived governance findings. */
export function assetInventory(tenant: number | null): AssetInventory {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSET'").get()) return { ...EMPTY };
  const ac = cols("XORCISM", "ASSET");
  const has = (c: string): boolean => ac.has(c);
  const tw = tenant != null && has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const assets = db.prepare(`SELECT * FROM ASSET ${tw}`).all() as Record<string, unknown>[];
  if (!assets.length) return { ...EMPTY };

  // Owner names (PERSON).
  const persons = new Map<number, string>();
  if (cols("XORCISM", "PERSON").has("FullName")) {
    for (const p of db.prepare(`SELECT PersonID, FullName FROM PERSON`).all() as { PersonID: number; FullName: string }[]) persons.set(Number(p.PersonID), p.FullName);
  }
  // Controls per asset (ASSETCONTROL).
  const controlCount = new Map<number, number>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETCONTROL'").get()) {
    const acw = tenant != null && cols("XORCISM", "ASSETCONTROL").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const r of db.prepare(`SELECT AssetID, COUNT(*) n FROM ASSETCONTROL ${acw} GROUP BY AssetID`).all() as { AssetID: number; n: number }[]) controlCount.set(Number(r.AssetID), Number(r.n));
  }
  // BIA coverage (BIAENTRY.AssetID).
  const biaAssets = new Set<number>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='BIAENTRY'").get() && cols("XORCISM", "BIAENTRY").has("AssetID")) {
    for (const r of db.prepare(`SELECT DISTINCT AssetID FROM BIAENTRY WHERE AssetID IS NOT NULL`).all() as { AssetID: number }[]) biaAssets.add(Number(r.AssetID));
  }
  // Free-text tags per asset (ASSETTAG) — drives the client tag filter + bulk targeting.
  const tagByAsset = new Map<number, string[]>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETTAG'").get()) {
    for (const r of db.prepare(`SELECT AssetID aid, Tag tag FROM ASSETTAG WHERE Tag IS NOT NULL AND Tag <> '' ORDER BY AssetTagID`).all() as { aid: number; tag: string }[]) {
      const a = tagByAsset.get(Number(r.aid)) ?? [];
      if (!a.includes(r.tag)) a.push(r.tag);
      tagByAsset.set(Number(r.aid), a);
    }
  }
  // Open vulnerabilities per asset, enriched cross-DB (KEV / critical / SSVC Act-Attend).
  const vulnByAsset = new Map<number, { open: number; kev: number; critical: number }>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get()) {
    const avc = cols("XORCISM", "ASSETVULNERABILITY");
    const fp = avc.has("FalsePositive") ? "AND (FalsePositive IS NULL OR FalsePositive = 0)" : "";
    const avtw = tenant != null && avc.has("TenantID") ? `AND TenantID = ${tenant}` : "";
    const links = db.prepare(`SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${fp} ${avtw}`).all() as { AssetID: number; VulnerabilityID: number }[];
    const meta = new Map<number, { kev: boolean; crit: boolean }>();
    const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)))];
    if (vids.length && cols("XVULNERABILITY", "VULNERABILITY").size) {
      const xv = getDb("XVULNERABILITY");
      const vc = cols("XVULNERABILITY", "VULNERABILITY");
      const sevCol = vc.has("SsvcDecision") ? "SsvcDecision" : "''";
      for (let i = 0; i < vids.length; i += 400) {
        const chunk = vids.slice(i, i + 400);
        const ph = chunk.map(() => "?").join(",");
        const rows = xv.prepare(`SELECT VulnerabilityID, ${vc.has("KEV") ? "KEV" : "0 AS KEV"}, ${vc.has("CVSSBaseScore") ? "CVSSBaseScore" : "NULL AS CVSSBaseScore"}, ${sevCol} AS Ssvc FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { VulnerabilityID: number; KEV: unknown; CVSSBaseScore: unknown; Ssvc: string }[];
        for (const r of rows) {
          const kev = truthy(r.KEV);
          const crit = kev || (num(r.CVSSBaseScore) ?? 0) >= 9 || /act|attend/i.test(String(r.Ssvc ?? ""));
          meta.set(Number(r.VulnerabilityID), { kev, crit });
        }
      }
    }
    for (const l of links) {
      const a = vulnByAsset.get(Number(l.AssetID)) ?? { open: 0, kev: 0, critical: 0 };
      a.open++;
      const m = meta.get(Number(l.VulnerabilityID));
      if (m?.kev) a.kev++;
      if (m?.crit) a.critical++;
      vulnByAsset.set(Number(l.AssetID), a);
    }
  }

  const findings: AssetFinding[] = [];
  const rows: AssetRow[] = assets.map((a) => {
    const id = Number(a.AssetID);
    const name = String(a.AssetName ?? "").trim() || `Asset #${id}`;
    const criticality = String(a.AssetCriticalityLevel ?? "").trim() || "Unrated";
    const isCrit = CRITICAL.test(criticality);
    const ownerId = a.PersonID != null ? Number(a.PersonID) : null;
    const owner = ownerId != null ? (persons.get(ownerId) ?? `#${ownerId}`) : null;
    const exposure: "Internet" | "Internal" = truthy(a.PublicFacing) ? "Internet" : "Internal";
    const environment = truthy(a.cloud) ? "Cloud" : (truthy(a.managedbythirdparty) || truthy(a.hostedbythirdparty)) ? "Third-party" : truthy(a.virtual) ? "Virtual" : "On-premises";
    const backed = truthy(a.Backed);
    const backupPlan = a.BackupPlanID != null && Number(a.BackupPlanID) > 0;
    const pii = truthy(a.HostPII) || truthy(a.personal);
    const enabled = a.Enabled == null || truthy(a.Enabled);
    const v = vulnByAsset.get(id) ?? { open: 0, kev: 0, critical: 0 };
    const ctrls = controlCount.get(id) ?? 0;
    const hasBia = biaAssets.has(id);
    const lastChecked = d10(a.LastCheckedDate);
    const validUntil = d10(a.ValidUntilDate);
    const address = String(a.fqdn || a.hostname || a.ipaddressIPv4 || a.websiteurl || "").trim();

    const flags: string[] = [];
    let score = 0;
    const add = (kind: string, label: string, severity: AssetFinding["severity"], pts: number): void => {
      flags.push(label); score += pts;
      findings.push({ kind, label: `${name}: ${label}`, severity, assetId: id, asset: name });
    };

    if (v.kev) add("kev", `${v.kev} actively-exploited (KEV) vulnerabilit${v.kev > 1 ? "ies" : "y"}`, "Critical", 40);
    else if (v.critical) add("critvuln", `${v.critical} critical vulnerabilit${v.critical > 1 ? "ies" : "y"}`, "High", 22);
    if (exposure === "Internet" && isCrit) add("exposed", "Internet-facing crown jewel", "High", 20);
    if (ownerId == null) add("orphan", "No owner assigned", "High", 15);
    if (isCrit && !backed) add("backup", "Critical asset not backed up", "High", 20);
    else if (isCrit && !backupPlan) add("backupplan", "Critical asset has no backup plan", "Medium", 8);
    if (pii && !backed) add("piibackup", "PII-bearing asset not backed up", "Medium", 10);
    if (isCrit && ctrls === 0) add("nocontrols", "No security controls mapped", "Medium", 10);
    if (isCrit && !hasBia) add("nobia", "Not covered by a BIA", "Medium", 8);
    const stale = daysSince(lastChecked);
    if (enabled && stale != null && stale > STALE_DAYS) add("stale", `Not reviewed for ${stale}d`, "Low", 8);
    const eol = daysSince(validUntil);
    if (eol != null && eol > 0) add("eol", `Past validity / end-of-life (${eol}d)`, "Medium", 10);

    return {
      id, name, criticality, owner, environment, exposure, backed, backupPlan, pii,
      businessValue: num(a.BusinessValue), financialValue: num(a.FinancialValue), riskScore: num(a.RiskScore),
      os: String(a.OSName ?? "").trim(), address, vulns: v, controls: ctrls, hasBia, lastChecked,
      flags, score: Math.min(100, score),
      tags: tagByAsset.get(id) ?? [], mfaEnabled: truthy(a.MFAEnabled),
    };
  });

  rows.sort((x, y) => y.score - x.score || x.name.localeCompare(y.name));
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((x, y) => (sevRank[x.severity] - sevRank[y.severity]) || x.asset.localeCompare(y.asset));

  const byCriticality: Record<string, number> = {};
  const byEnvironment: Record<string, number> = {};
  for (const r of rows) { byCriticality[r.criticality] = (byCriticality[r.criticality] || 0) + 1; byEnvironment[r.environment] = (byEnvironment[r.environment] || 0) + 1; }
  const isCrown = (r: AssetRow): boolean => CRITICAL.test(r.criticality) || (r.businessValue ?? 0) >= 4;

  return {
    rows, findings,
    summary: {
      total: rows.length,
      crownJewels: rows.filter(isCrown).length,
      internetFacing: rows.filter((r) => r.exposure === "Internet").length,
      pii: rows.filter((r) => r.pii).length,
      unbackedCritical: rows.filter((r) => CRITICAL.test(r.criticality) && !r.backed).length,
      noOwner: rows.filter((r) => r.owner == null).length,
      withCriticalVulns: rows.filter((r) => r.vulns.kev > 0 || r.vulns.critical > 0).length,
      stale: rows.filter((r) => r.flags.some((f) => f.startsWith("Not reviewed"))).length,
      byCriticality, byEnvironment,
    },
  };
}

/**
 * Create an ASSET from a guided form — the friendly path that replaces dumping the user into the
 * raw explorer insert (mirrors the Risk Register / Compliance guided creates). Column-aware INSERT
 * (only writes columns the table actually has) + GUID + tenant. AssetID is a real INTEGER PRIMARY
 * KEY (lastInsertRowid works). The governance worklist (assetInventory) surfaces the new asset
 * immediately and flags it (e.g. owner-less, Internet-facing crown jewel) so it lands on the radar.
 */
export function createAsset(
  p: { name: string; description?: string; criticality?: string; os?: string; hostname?: string;
       ip?: string; environment?: string; publicFacing?: boolean; businessValue?: string;
       financialValue?: number | null; currency?: string; hostPii?: boolean; mfaEnabled?: boolean;
       ownerPersonId?: number | null; notes?: string },
  tenant: number | null,
): { id: number } {
  const db = getDb("XORCISM");
  const ac = cols("XORCISM", "ASSET");
  if (!ac.size) throw new Error("ASSET table not available");
  const now = new Date().toISOString();
  const env = (p.environment || "").toLowerCase();
  // Legacy quirk: ASSET.AssetID is INTEGER NOT NULL but NOT a PRIMARY KEY, so SQLite won't
  // auto-assign it (same as CPE/CPEFORASSET/COMPONENT) → allocate MAX+1 explicitly.
  const nextId = allocId(db, "ASSET", "AssetID");
  const candidate: Record<string, unknown> = {
    AssetID: nextId,
    AssetGUID: randomUUID(),
    AssetName: (p.name || "Untitled asset").slice(0, 300),
    AssetDescription: p.description ? String(p.description).slice(0, 4000) : null,
    AssetCriticalityLevel: p.criticality ? String(p.criticality).slice(0, 60) : null,
    OSName: p.os ? String(p.os).slice(0, 200) : null,
    hostname: p.hostname ? String(p.hostname).slice(0, 255) : null,
    ipaddressIPv4: p.ip ? String(p.ip).slice(0, 45) : null,
    // environment is modelled by flags on ASSET (cloud / virtual / managedbythirdparty)
    cloud: env === "cloud" ? 1 : 0,
    virtual: env === "virtual" ? 1 : 0,
    managedbythirdparty: env === "third-party" || env === "thirdparty" ? 1 : 0,
    PublicFacing: p.publicFacing ? 1 : 0,
    BusinessValue: p.businessValue ? String(p.businessValue).slice(0, 60) : null,
    FinancialValue: p.financialValue ?? null,
    Currency: p.currency ? String(p.currency).slice(0, 10) : null,
    HostPII: p.hostPii ? 1 : 0,
    MFAEnabled: p.mfaEnabled ? 1 : 0,
    PersonID: p.ownerPersonId ?? null,
    notes: p.notes ? String(p.notes).slice(0, 4000) : null,
    Enabled: 1,
    CreatedDate: now,
    ValidFromDate: now,
    LastCheckedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => ac.has(k));
  const sql = `INSERT INTO ASSET (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = db.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

// ── Bulk import (Excel / spreadsheet) ─────────────────────────────────────────
// The logical fields a spreadsheet column can be mapped to. Order = the order shown
// in the client mapping UI. `name` is the only required field (the asset's key, also
// used to de-duplicate on upsert). Booleans accept yes/true/1/x/✓/oui (case-insensitive).
export const ASSET_IMPORT_FIELDS = [
  { key: "name", type: "text" },
  { key: "description", type: "text" },
  { key: "criticality", type: "text" },
  { key: "environment", type: "text" },
  { key: "os", type: "text" },
  { key: "hostname", type: "text" },
  { key: "ip", type: "text" },
  { key: "publicFacing", type: "bool" },
  { key: "hostPii", type: "bool" },
  { key: "mfaEnabled", type: "bool" },
  { key: "businessValue", type: "text" },
  { key: "financialValue", type: "number" },
  { key: "currency", type: "text" },
  { key: "notes", type: "text" },
] as const;
type AssetImportField = (typeof ASSET_IMPORT_FIELDS)[number]["key"];
const BOOL_TRUE = new Set(["1", "true", "yes", "y", "x", "t", "✓", "on", "enabled", "oui", "vrai", "actif"]);
const toBool = (v: unknown): boolean => {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  return BOOL_TRUE.has(String(v ?? "").trim().toLowerCase());
};

export interface AssetImportResult {
  created: number; updated: number; skipped: number;
  errors: { row: number; error: string }[];
}

/**
 * Bulk-create (or upsert) assets from already-column-mapped rows. Each row is keyed by the
 * logical field names in ASSET_IMPORT_FIELDS; the Excel→field mapping happens client-side.
 * Rows with no `name` are skipped. With `upsert`, an existing asset of the same name (within
 * the tenant) is updated in place — only the columns the row actually provides are touched.
 */
export function importAssets(
  rows: Record<string, unknown>[],
  tenant: number | null,
  opts: { upsert?: boolean } = {},
): AssetImportResult {
  const db = getDb("XORCISM");
  const ac = cols("XORCISM", "ASSET");
  if (!ac.size) throw new Error("ASSET table not available");
  const out: AssetImportResult = { created: 0, updated: 0, skipped: 0, errors: [] };
  // Upsert lookup by name within the same tenant (IS handles the super-admin null tenant too).
  const findByName = db.prepare("SELECT AssetID FROM ASSET WHERE AssetName = ? COLLATE NOCASE AND TenantID IS ? LIMIT 1");

  const str = (v: unknown): string | undefined => {
    const s = String(v ?? "").trim();
    return s ? s : undefined;
  };
  const provided = (row: Record<string, unknown>, k: AssetImportField): boolean =>
    Object.prototype.hasOwnProperty.call(row, k) && String(row[k] ?? "").trim() !== "";

  const tx = db.transaction((items: Record<string, unknown>[]) => {
    items.forEach((row, i) => {
      const name = String(row.name ?? "").trim();
      if (!name) { out.skipped++; return; }
      try {
        if (opts.upsert) {
          const ex = findByName.get(name, tenant) as { AssetID: number } | undefined;
          if (ex) {
            updateAssetColumns(db, ac, ex.AssetID, row, provided);
            out.updated++;
            return;
          }
        }
        createAsset({
          name,
          description: str(row.description),
          criticality: str(row.criticality),
          environment: str(row.environment),
          os: str(row.os),
          hostname: str(row.hostname),
          ip: str(row.ip),
          publicFacing: provided(row, "publicFacing") ? toBool(row.publicFacing) : false,
          hostPii: provided(row, "hostPii") ? toBool(row.hostPii) : false,
          mfaEnabled: provided(row, "mfaEnabled") ? toBool(row.mfaEnabled) : false,
          businessValue: str(row.businessValue),
          financialValue: provided(row, "financialValue") ? Number(String(row.financialValue).replace(/[^0-9.\-]/g, "")) || null : null,
          currency: str(row.currency),
          notes: str(row.notes),
        }, tenant);
        out.created++;
      } catch (e) { out.errors.push({ row: i + 1, error: String((e as Error).message || e) }); }
    });
  });
  tx(rows);
  return out;
}

// Update only the ASSET columns a mapped import row actually provides (never clobber
// existing data with blanks). Mirrors createAsset's logical-field → column mapping.
function updateAssetColumns(
  db: ReturnType<typeof getDb>, ac: Set<string>, assetId: number,
  row: Record<string, unknown>, provided: (r: Record<string, unknown>, k: AssetImportField) => boolean,
): void {
  const set: Record<string, unknown> = {};
  if (provided(row, "description")) set.AssetDescription = String(row.description).slice(0, 4000);
  if (provided(row, "criticality")) set.AssetCriticalityLevel = String(row.criticality).slice(0, 60);
  if (provided(row, "os")) set.OSName = String(row.os).slice(0, 200);
  if (provided(row, "hostname")) set.hostname = String(row.hostname).slice(0, 255);
  if (provided(row, "ip")) set.ipaddressIPv4 = String(row.ip).slice(0, 45);
  if (provided(row, "environment")) {
    const env = String(row.environment).toLowerCase();
    set.cloud = env === "cloud" ? 1 : 0;
    set.virtual = env === "virtual" ? 1 : 0;
    set.managedbythirdparty = env === "third-party" || env === "thirdparty" ? 1 : 0;
  }
  if (provided(row, "publicFacing")) set.PublicFacing = toBool(row.publicFacing) ? 1 : 0;
  if (provided(row, "hostPii")) set.HostPII = toBool(row.hostPii) ? 1 : 0;
  if (provided(row, "mfaEnabled")) set.MFAEnabled = toBool(row.mfaEnabled) ? 1 : 0;
  if (provided(row, "businessValue")) set.BusinessValue = String(row.businessValue).slice(0, 60);
  if (provided(row, "financialValue")) set.FinancialValue = Number(String(row.financialValue).replace(/[^0-9.\-]/g, "")) || null;
  if (provided(row, "currency")) set.Currency = String(row.currency).slice(0, 10);
  if (provided(row, "notes")) set.notes = String(row.notes).slice(0, 4000);
  const keys = Object.keys(set).filter((k) => ac.has(k));
  if (!keys.length) return;
  if (ac.has("LastCheckedDate")) { set.LastCheckedDate = new Date().toISOString(); keys.push("LastCheckedDate"); }
  db.prepare(`UPDATE ASSET SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE AssetID = ?`)
    .run(...keys.map((k) => set[k]), assetId);
}

// ── Bulk update ───────────────────────────────────────────────────────────────
// The logical fields a bulk update may set, and their kind. Only provided keys are applied;
// every write is tenant-scoped and only touches columns the ASSET table actually has.
export type BulkField = "mfaEnabled" | "publicFacing" | "hostPii" | "backed" | "enabled"
  | "criticality" | "businessValue" | "financialValue" | "currency" | "ownerPersonId" | "environment";
export const BULK_FIELDS: { key: BulkField; type: "bool" | "text" | "number" | "person" | "environment" }[] = [
  { key: "mfaEnabled", type: "bool" }, { key: "publicFacing", type: "bool" }, { key: "hostPii", type: "bool" },
  { key: "backed", type: "bool" }, { key: "enabled", type: "bool" },
  { key: "criticality", type: "text" }, { key: "businessValue", type: "text" }, { key: "environment", type: "environment" },
  { key: "financialValue", type: "number" }, { key: "currency", type: "text" }, { key: "ownerPersonId", type: "person" },
];

export interface BulkFilter { tag?: string; criticality?: string; environment?: string; exposure?: "Internet" | "Internal"; ownerless?: boolean; publicFacing?: boolean; }
export interface BulkResult { matched: number; updated: number; fields: string[]; targeting: "ids" | "filter"; }

/**
 * Bulk-update a set of ASSETs — target them either by explicit `assetIds` (what the UI selects)
 * or by a `filter` (e.g. every asset tagged "endpoint"), then apply the provided `set` fields
 * (e.g. { mfaEnabled: true }). Only whitelisted fields are written, only to columns that exist,
 * always within the caller's tenant. Returns how many matched vs. were updated.
 */
export function bulkUpdateAssets(
  tenant: number | null,
  opts: { assetIds?: number[]; filter?: BulkFilter; set: Record<string, unknown> },
): BulkResult {
  const db = getDb("XORCISM");
  const ac = cols("XORCISM", "ASSET");
  if (!ac.size) throw new Error("ASSET table not available");
  const hasTenant = tenant != null && ac.has("TenantID");

  // 1) Resolve the target AssetIDs.
  let ids: number[] = [];
  let targeting: "ids" | "filter" = "ids";
  if (Array.isArray(opts.assetIds) && opts.assetIds.length) {
    const wanted = [...new Set(opts.assetIds.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n > 0))];
    // Re-validate ownership: only ids that exist within the tenant survive.
    for (let i = 0; i < wanted.length; i += 400) {
      const chunk = wanted.slice(i, i + 400);
      const ph = chunk.map(() => "?").join(",");
      const tw = hasTenant ? "AND TenantID IS ?" : "";
      const rows = db.prepare(`SELECT AssetID FROM ASSET WHERE AssetID IN (${ph}) ${tw}`).all(...chunk, ...(hasTenant ? [tenant] : [])) as { AssetID: number }[];
      ids.push(...rows.map((r) => Number(r.AssetID)));
    }
  } else if (opts.filter) {
    targeting = "filter";
    const f = opts.filter;
    const where: string[] = []; const args: unknown[] = [];
    if (hasTenant) { where.push("a.TenantID IS ?"); args.push(tenant); }
    if (f.criticality) { where.push("a.AssetCriticalityLevel = ? COLLATE NOCASE"); args.push(f.criticality); }
    if (f.exposure) { where.push(f.exposure === "Internet" ? "(a.PublicFacing = 1)" : "(a.PublicFacing IS NULL OR a.PublicFacing = 0)"); }
    if (f.publicFacing === true) where.push("a.PublicFacing = 1");
    if (f.ownerless) where.push("(a.PersonID IS NULL OR a.PersonID = 0)");
    if (f.environment) {
      const env = f.environment.toLowerCase();
      if (env === "cloud") where.push("a.cloud = 1");
      else if (env === "virtual") where.push("a.virtual = 1");
      else if (env === "third-party" || env === "thirdparty") where.push("(a.managedbythirdparty = 1 OR a.hostedbythirdparty = 1)");
      else if (env === "on-premises" || env === "on-prem") where.push("(COALESCE(a.cloud,0)=0 AND COALESCE(a.virtual,0)=0 AND COALESCE(a.managedbythirdparty,0)=0)");
    }
    const tagJoin = f.tag ? "JOIN ASSETTAG t ON t.AssetID = a.AssetID AND t.Tag = ? COLLATE NOCASE" : "";
    if (f.tag) args.unshift(f.tag); // the tag param binds to the JOIN which precedes WHERE
    const sql = `SELECT DISTINCT a.AssetID FROM ASSET a ${tagJoin} ${where.length ? "WHERE " + where.join(" AND ") : ""}`;
    ids = (db.prepare(sql).all(...args) as { AssetID: number }[]).map((r) => Number(r.AssetID));
  }
  const matched = ids.length;
  if (!matched) return { matched: 0, updated: 0, fields: [], targeting };

  // 2) Build the SET clause from the whitelist (provided keys only, existing columns only).
  const set: Record<string, unknown> = {};
  const has = (k: string) => Object.prototype.hasOwnProperty.call(opts.set, k);
  const bool01 = (v: unknown) => (toBool(v) ? 1 : 0);
  if (has("mfaEnabled") && ac.has("MFAEnabled")) set.MFAEnabled = bool01(opts.set.mfaEnabled);
  if (has("publicFacing") && ac.has("PublicFacing")) set.PublicFacing = bool01(opts.set.publicFacing);
  if (has("hostPii") && ac.has("HostPII")) set.HostPII = bool01(opts.set.hostPii);
  if (has("backed") && ac.has("Backed")) set.Backed = bool01(opts.set.backed);
  if (has("enabled") && ac.has("Enabled")) set.Enabled = bool01(opts.set.enabled);
  if (has("criticality") && ac.has("AssetCriticalityLevel")) set.AssetCriticalityLevel = String(opts.set.criticality ?? "").slice(0, 60) || null;
  if (has("businessValue") && ac.has("BusinessValue")) set.BusinessValue = String(opts.set.businessValue ?? "").slice(0, 60) || null;
  if (has("currency") && ac.has("Currency")) set.Currency = String(opts.set.currency ?? "").slice(0, 10) || null;
  if (has("financialValue") && ac.has("FinancialValue")) {
    const raw = opts.set.financialValue;
    set.FinancialValue = raw == null || String(raw).trim() === "" ? null : (Number(String(raw).replace(/[^0-9.\-]/g, "")) || null);
  }
  if (has("ownerPersonId") && ac.has("PersonID")) {
    const raw = opts.set.ownerPersonId;
    set.PersonID = raw == null || String(raw).trim() === "" ? null : (Number(raw) || null);
  }
  if (has("environment") && ac.has("cloud")) {
    const env = String(opts.set.environment ?? "").toLowerCase();
    set.cloud = env === "cloud" ? 1 : 0;
    if (ac.has("virtual")) set.virtual = env === "virtual" ? 1 : 0;
    if (ac.has("managedbythirdparty")) set.managedbythirdparty = (env === "third-party" || env === "thirdparty") ? 1 : 0;
  }
  const keys = Object.keys(set);
  if (!keys.length) return { matched, updated: 0, fields: [], targeting };
  if (ac.has("LastCheckedDate")) { set.LastCheckedDate = new Date().toISOString(); keys.push("LastCheckedDate"); }

  // 3) Apply, chunked, tenant-scoped.
  const assign = keys.map((k) => `"${k}" = ?`).join(", ");
  const vals = keys.map((k) => set[k]);
  let updated = 0;
  const tx = db.transaction((batch: number[]) => {
    for (let i = 0; i < batch.length; i += 400) {
      const chunk = batch.slice(i, i + 400);
      const ph = chunk.map(() => "?").join(",");
      const tw = hasTenant ? "AND TenantID IS ?" : "";
      const r = db.prepare(`UPDATE ASSET SET ${assign} WHERE AssetID IN (${ph}) ${tw}`)
        .run(...vals, ...chunk, ...(hasTenant ? [tenant] : []));
      updated += r.changes;
    }
  });
  tx(ids);
  return { matched, updated, fields: keys.filter((k) => k !== "LastCheckedDate"), targeting };
}
