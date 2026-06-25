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
       financialValue?: number | null; currency?: string; hostPii?: boolean;
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
