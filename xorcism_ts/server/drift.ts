/**
 * drift.ts — Attack-surface drift. Snapshots the external surface (exposed assets +
 * key attributes) and diffs consecutive snapshots: what appeared, vanished, or newly
 * became internet-exposed since last time. Pairs with the OSINT discovery chain
 * (which grows the inventory) to turn discovery into continuous monitoring.
 */
import { allocId, getDb } from "./db";

let ensured = false;
export function ensureDriftTable(): void {
  if (ensured) return;
  getDb("XORCISM").exec(`CREATE TABLE IF NOT EXISTS XSURFACESNAPSHOT(
    SnapshotID INTEGER PRIMARY KEY, TenantID INTEGER, CreatedDate TEXT, CreatedBy INTEGER,
    AssetCount INTEGER, ExposedCount INTEGER, Payload TEXT);
    CREATE INDEX IF NOT EXISTS ix_surfsnap_tenant ON XSURFACESNAPSHOT(TenantID, SnapshotID);`);
  ensured = true;
}
function now(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }
function isPublicV4(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/); if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false; if (a === 172 && b >= 16 && b <= 31) return false; if (a === 169 && b === 254) return false;
  return a > 0 && a < 224;
}

interface SurfAsset { name: string; exposed: boolean; web: string | null; ip: string | null }

function captureSurface(tenant: number | null): SurfAsset[] {
  const xo = getDb("XORCISM");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tcl = tenant != null && aCols.has("TenantID") ? 'WHERE ("TenantID"=? OR "TenantID" IS NULL)' : "";
  const args = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  return (xo.prepare(`SELECT AssetName name, websiteurl web, ipaddressIPv4 ip FROM ASSET ${tcl} LIMIT 5000`).all(...args) as { name: string; web: string | null; ip: string | null }[])
    .map((r) => ({ name: String(r.name || ""), web: r.web ? String(r.web).trim() : null, ip: r.ip ? String(r.ip).trim() : null }))
    .map((r) => ({ ...r, exposed: !!r.web || (!!r.ip && isPublicV4(r.ip)) }))
    .filter((r) => r.name);
}

export function takeSnapshot(tenant: number | null, userId: number): { snapshotId: number; assets: number; exposed: number } {
  ensureDriftTable();
  const surf = captureSurface(tenant);
  const exposed = surf.filter((s) => s.exposed).length;
  const xo = getDb("XORCISM");
  const id = allocId(xo, "XSURFACESNAPSHOT", "SnapshotID");
  xo.prepare("INSERT INTO XSURFACESNAPSHOT (SnapshotID, TenantID, CreatedDate, CreatedBy, AssetCount, ExposedCount, Payload) VALUES (?,?,?,?,?,?,?)")
    .run(id, tenant, now(), userId, surf.length, exposed, JSON.stringify(surf).slice(0, 1_000_000));
  return { snapshotId: id, assets: surf.length, exposed };
}

export interface Drift {
  current: { date: string | null; assets: number; exposed: number } | null;
  previous: { date: string | null; assets: number; exposed: number } | null;
  added: string[]; removed: string[]; newlyExposed: string[]; noLongerExposed: string[];
  snapshots: number;
}

export function surfaceDrift(tenant: number | null): Drift {
  ensureDriftTable();
  const xo = getDb("XORCISM");
  const where = tenant != null ? "WHERE TenantID=? OR TenantID IS NULL" : "";
  const args = tenant != null ? [tenant] : [];
  const snaps = xo.prepare(`SELECT SnapshotID, CreatedDate, AssetCount, ExposedCount, Payload FROM XSURFACESNAPSHOT ${where} ORDER BY SnapshotID DESC LIMIT 2`).all(...args) as { SnapshotID: number; CreatedDate: string; AssetCount: number; ExposedCount: number; Payload: string }[];
  const totalSnaps = (xo.prepare(`SELECT COUNT(*) n FROM XSURFACESNAPSHOT ${where}`).get(...args) as { n: number }).n;
  if (!snaps.length) return { current: null, previous: null, added: [], removed: [], newlyExposed: [], noLongerExposed: [], snapshots: 0 };
  const parse = (s?: { Payload: string }): SurfAsset[] => { try { return s ? JSON.parse(s.Payload) : []; } catch { return []; } };
  const cur = snaps[0], prev = snaps[1];
  const curSurf = parse(cur), prevSurf = parse(prev);
  const curMap = new Map(curSurf.map((s) => [s.name, s])), prevMap = new Map(prevSurf.map((s) => [s.name, s]));
  const added = curSurf.filter((s) => !prevMap.has(s.name)).map((s) => s.name);
  const removed = prevSurf.filter((s) => !curMap.has(s.name)).map((s) => s.name);
  const newlyExposed = curSurf.filter((s) => s.exposed && prevMap.has(s.name) && !prevMap.get(s.name)!.exposed).map((s) => s.name);
  const noLongerExposed = curSurf.filter((s) => !s.exposed && prevMap.has(s.name) && prevMap.get(s.name)!.exposed).map((s) => s.name);
  return {
    current: { date: cur.CreatedDate, assets: cur.AssetCount, exposed: cur.ExposedCount },
    previous: prev ? { date: prev.CreatedDate, assets: prev.AssetCount, exposed: prev.ExposedCount } : null,
    added, removed, newlyExposed, noLongerExposed, snapshots: totalSnaps,
  };
}
