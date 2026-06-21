/**
 * cvematch.ts — Continuous CVE → ASSET matching ("New CVEs for ASSET").
 *
 * Links newly-imported CVEs to the assets whose *technologies* they affect, and raises a
 * "New CVEs for ASSET X" notification per affected asset. An asset's technologies are taken from:
 *   • its CPE inventory   — CPEFORASSET → CPE.CPEName, the vendor & product tokens, and
 *   • its tech tags       — ASSETTAG.Tag (free text, e.g. "nginx", "openssl", "postgresql").
 * Matching (per the chosen "CPE + keyword" policy):
 *   • precise CPE link    — VULNERABILITYFORCPE ↔ the asset's CPEID (when that table is populated), and
 *   • keyword             — the technology tokens matched (word-boundary, case-insensitive) against
 *                           the CVE text (VULReferentialID / VULName / VULDescription).
 * Idempotent (skips ASSETVULNERABILITY links that already exist). A watermark (CVEMATCHCURSOR)
 * bounds the "new CVEs" delta so the hourly/import runs only look at freshly-imported CVEs; the
 * on-demand run can rescan a recent window. First run initialises the watermark to the current
 * MAX(VulnerabilityID) (no 200k-row backfill / notification flood).
 */
import { getDb, notifyUsers } from "./db";
import * as xid from "./xid";

const STOP = new Set([
  "", "*", "-", "n/a", "and", "the", "for", "with", "app", "web", "api", "data", "core",
  "server", "client", "service", "system", "tool", "test", "dev", "prod", "all", "none",
]);

function escapeRe(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function normToken(t: string): string { return String(t || "").replace(/_/g, " ").trim().toLowerCase(); }
function nowTs(): string { return new Date().toISOString().slice(0, 19).replace("T", " "); }

/** Vendor + product tokens from a CPE 2.3 (cpe:2.3:a:vendor:product:…) or 2.2 (cpe:/a:vendor:product:…) name. */
function cpeTokens(cpeName: string): string[] {
  const n = String(cpeName || "");
  if (n.startsWith("cpe:2.3:")) {
    const p = n.split(":");                 // [cpe,2.3,part,vendor,product,version,…]
    return [p[3], p[4]].filter(Boolean);
  }
  const p = n.replace(/^cpe:\/?/i, "").split(":"); // [part,vendor,product,version,…]
  return [p[1], p[2]].filter(Boolean);
}

export interface AssetTech {
  assetId: number; name: string; tenantId: number | null;
  keywords: string[]; rx: RegExp | null; cpeIds: Set<number>;
}

/** Build the per-asset technology index (CPE vendor/product tokens + tech tags). */
export function buildAssetTechIndex(tenant: number | null): AssetTech[] {
  const db = getDb("XORCISM");
  const tw = tenant != null ? `WHERE COALESCE(TenantID, ${tenant}) = ${tenant}` : "";
  const assets = db.prepare(`SELECT AssetID id, AssetName name, TenantID t FROM ASSET ${tw}`).all() as { id: number; name: string | null; t: number | null }[];
  const byAsset = new Map<number, { kw: Set<string>; cpe: Set<number>; name: string | null; t: number | null }>();
  for (const a of assets) byAsset.set(a.id, { kw: new Set(), cpe: new Set(), name: a.name, t: a.t });

  for (const r of db.prepare(`SELECT ca.AssetID aid, c.CPEID cid, c.CPEName name FROM CPEFORASSET ca JOIN CPE c ON c.CPEID = ca.CPEID`).all() as { aid: number; cid: number; name: string }[]) {
    const e = byAsset.get(r.aid); if (!e) continue;
    e.cpe.add(r.cid);
    for (const tok of cpeTokens(r.name)) { const n = normToken(tok); if (n.length >= 3 && !STOP.has(n)) e.kw.add(n); }
  }
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETTAG'").get()) {
    for (const r of db.prepare(`SELECT AssetID aid, Tag tag FROM ASSETTAG WHERE Tag IS NOT NULL`).all() as { aid: number; tag: string }[]) {
      const e = byAsset.get(r.aid); if (!e) continue;
      const n = normToken(r.tag); if (n.length >= 3 && !STOP.has(n)) e.kw.add(n);
    }
  }
  const out: AssetTech[] = [];
  for (const [id, e] of byAsset) {
    const keywords = [...e.kw];
    out.push({
      assetId: id, name: e.name || `#${id}`, tenantId: e.t ?? null, keywords, cpeIds: e.cpe,
      rx: keywords.length ? new RegExp("\\b(" + keywords.map(escapeRe).join("|") + ")\\b", "i") : null,
    });
  }
  return out.filter((a) => a.rx || a.cpeIds.size);
}

// ── watermark (CVEMATCHCURSOR, single row id=1) ───────────────────────────────────
export function ensureCveMatchTables(): void {
  let db; try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS CVEMATCHCURSOR (id INTEGER PRIMARY KEY, lastVulnerabilityID INTEGER, lastRunAt TEXT, lastNewLinks INTEGER);`);
  if (!db.prepare("SELECT 1 FROM CVEMATCHCURSOR WHERE id=1").get()) {
    // initialise to the current MAX so the first delta run doesn't backfill the whole CVE DB.
    let maxId = 0;
    try { maxId = (getDb("XVULNERABILITY").prepare("SELECT COALESCE(MAX(VulnerabilityID),0) m FROM VULNERABILITY").get() as { m: number }).m; } catch { /* xvuln absent */ }
    db.prepare("INSERT INTO CVEMATCHCURSOR (id, lastVulnerabilityID, lastRunAt, lastNewLinks) VALUES (1, ?, NULL, 0)").run(maxId);
  }
}
function getWatermark(): number {
  try { return (getDb("XORCISM").prepare("SELECT lastVulnerabilityID v FROM CVEMATCHCURSOR WHERE id=1").get() as { v: number } | undefined)?.v ?? 0; } catch { return 0; }
}
function setWatermark(maxId: number, newLinks: number): void {
  try { getDb("XORCISM").prepare("UPDATE CVEMATCHCURSOR SET lastVulnerabilityID=?, lastRunAt=?, lastNewLinks=? WHERE id=1").run(maxId, nowTs(), newLinks); } catch { /* ignore */ }
}

// ── recipients: users with read access to XORCISM.ASSET in the tenant ──────────────
function assetReaders(tenant: number | null): number[] {
  const out: number[] = [];
  try {
    for (const u of xid.listUsers(tenant) as Record<string, unknown>[]) {
      if (u.IsLockedOut) continue;
      const uid = Number(u.UserID);
      if (!Number.isInteger(uid) || uid <= 0) continue;
      if (xid.isAdmin(uid)) { out.push(uid); continue; }
      const perms = xid.getEffectivePermissions(uid);
      if (perms.get("database:XORCISM")?.CanRead || perms.get("table:XORCISM.ASSET")?.CanRead) out.push(uid);
    }
  } catch { /* RBAC unavailable */ }
  return out;
}

export interface MatchResult { cvesScanned: number; newLinks: number; assetsAffected: number; assetsNotified: number; maxVulnId: number; mode: string; }

/**
 * Match CVEs to assets and create the links + notifications.
 *  - default (no since/days): delta since the watermark (used by the import hook & periodic job).
 *  - { days }: rescan CVEs modified within the last N days (used by the on-demand "rematch").
 *  - { sinceVulnId }: explicit lower bound.
 */
export function matchCves(opts: { tenant?: number | null; sinceVulnId?: number; days?: number; limit?: number; notify?: boolean } = {}): MatchResult {
  const tenant = opts.tenant ?? null;
  const notify = opts.notify !== false;
  const limit = Math.min(opts.limit ?? 50_000, 200_000);
  const usingWatermark = opts.sinceVulnId == null && opts.days == null;
  const since = opts.sinceVulnId ?? (usingWatermark ? getWatermark() : 0);
  const mode = usingWatermark ? "delta" : (opts.days != null ? `${opts.days}d` : `since#${since}`);

  const index = buildAssetTechIndex(tenant);
  const empty: MatchResult = { cvesScanned: 0, newLinks: 0, assetsAffected: 0, assetsNotified: 0, maxVulnId: since, mode };
  if (!index.length) return empty;

  const xo = getDb("XORCISM"); const xv = getDb("XVULNERABILITY");
  let rows: { id: number; ref: string; name: string | null; descr: string | null }[];
  if (opts.days != null) {
    rows = xv.prepare(
      `SELECT VulnerabilityID id, VULReferentialID ref, VULName name, VULDescription descr FROM VULNERABILITY
       WHERE VULReferentialID LIKE 'CVE-%' AND COALESCE(VULModifiedDate, VULPublishedDate, CreatedDate) >= date('now', ?)
       ORDER BY VulnerabilityID LIMIT ?`).all(`-${Math.max(1, Math.round(opts.days))} days`, limit) as typeof rows;
  } else {
    rows = xv.prepare(
      `SELECT VulnerabilityID id, VULReferentialID ref, VULName name, VULDescription descr FROM VULNERABILITY
       WHERE VulnerabilityID > ? AND VULReferentialID LIKE 'CVE-%' ORDER BY VulnerabilityID LIMIT ?`).all(since, limit) as typeof rows;
  }
  if (!rows.length) { if (usingWatermark) setWatermark(since, 0); return { ...empty, cvesScanned: 0 }; }

  // Precise CPE links for the candidate CVEs (VULNERABILITYFORCPE; usually empty today).
  const cveCpe = new Map<number, Set<number>>();
  try {
    if (xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='VULNERABILITYFORCPE'").get()) {
      const ids = rows.map((r) => r.id);
      for (let i = 0; i < ids.length; i += 800) {
        const chunk = ids.slice(i, i + 800);
        const ph = chunk.map(() => "?").join(",");
        for (const r of xv.prepare(`SELECT VulnerabilityID v, CPEID c FROM VULNERABILITYFORCPE WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { v: number; c: number }[]) {
          (cveCpe.get(r.v) ?? cveCpe.set(r.v, new Set()).get(r.v)!).add(r.c);
        }
      }
    }
  } catch { /* table absent / different shape */ }

  const existsAv = xo.prepare("SELECT 1 FROM ASSETVULNERABILITY WHERE AssetID=? AND VulnerabilityID=?");
  const insAv = xo.prepare("INSERT INTO ASSETVULNERABILITY (AssetID, VulnerabilityID, CreatedDate, TenantID, Status) VALUES (?,?,?,?, 'Open')");
  const perAsset = new Map<number, { count: number; name: string; tenant: number | null }>();
  let maxId = since; const now = nowTs();

  const tx = xo.transaction(() => {
    for (const cve of rows) {
      if (cve.id > maxId) maxId = cve.id;
      const hay = `${cve.ref} ${cve.name || ""} ${cve.descr || ""}`;
      const cpes = cveCpe.get(cve.id);
      for (const a of index) {
        const hit = (a.rx ? a.rx.test(hay) : false) || (!!cpes && [...a.cpeIds].some((c) => cpes.has(c)));
        if (!hit) continue;
        if (existsAv.get(a.assetId, cve.id)) continue;
        insAv.run(a.assetId, cve.id, now, a.tenantId);
        const e = perAsset.get(a.assetId) ?? { count: 0, name: a.name, tenant: a.tenantId };
        e.count++; perAsset.set(a.assetId, e);
      }
    }
  });
  tx();

  let newLinks = 0; for (const e of perAsset.values()) newLinks += e.count;
  let assetsNotified = 0;
  if (notify) {
    for (const [aid, e] of perAsset) {
      const recips = assetReaders(e.tenant);
      if (!recips.length) continue;
      notifyUsers(recips, {
        title: `New CVEs for ${e.name}`,
        message: `${e.count} new CVE${e.count > 1 ? "s" : ""} matched this asset's technologies (CPE / tags).`,
        level: "warning", source: "cve-match",
        link: `/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=AssetID&filterVal=${aid}`,
        tenantId: e.tenant,
      });
      assetsNotified++;
    }
  }
  if (usingWatermark) setWatermark(maxId, newLinks);
  return { cvesScanned: rows.length, newLinks, assetsAffected: perAsset.size, assetsNotified, maxVulnId: maxId, mode };
}

// ── periodic matcher (hourly) — catches CVEs from any import path (NVD, OpenCVE, …) ──
let _timer: NodeJS.Timeout | null = null;
export function startCveMatcher(): void {
  if (_timer || process.env.XOR_CVE_MATCH === "0") return;
  _timer = setInterval(() => {
    try {
      const r = matchCves({ tenant: null });
      if (r.newLinks) console.log(`[cvematch] periodic: ${r.newLinks} new link(s) → ${r.assetsNotified} asset(s) notified (scanned ${r.cvesScanned} CVEs, ${r.mode})`);
    } catch (e) { console.warn(`[cvematch] periodic tick: ${(e as Error).message}`); }
  }, 60 * 60 * 1000);
  if (typeof _timer.unref === "function") _timer.unref();
  console.log("[cvematch] periodic CVE→asset matcher started (hourly; XOR_CVE_MATCH=0 to disable)");
}
