/**
 * monitoring.ts — Asset Monitoring (uptime / health / SSL), inspired by CheckCle.
 *
 * One pane over the availability of your assets: every monitor (HTTP / Ping / TCP / DNS / SSL /
 * Server) with its current status (up/down/warning/paused), uptime %, response time and SSL expiry,
 * plus the open up/down incidents. Native monitors are created here; the checkcle connector imports
 * CheckCle's services/servers/SSL/incidents into the same MONITORINGCHECK / MONITORINGINCIDENT tables.
 * Read inventory + guided createMonitor + a status update (used by the optional checker / connector).
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export const CHECK_TYPES = ["http", "ping", "tcp", "dns", "ssl", "server"];
export const MON_STATUSES = ["up", "down", "warning", "paused", "unknown"];
const SSL_SOON_DAYS = 30;

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const normStatus = (s: string): string => {
  const v = String(s || "").trim().toLowerCase();
  if (/up|ok|online|healthy|operational|200/.test(v)) return "up";
  if (/down|fail|offline|critical|error|5\d\d/.test(v)) return "down";
  if (/warn|degrad|slow/.test(v)) return "warning";
  if (/paus|maint|disabled/.test(v)) return "paused";
  return MON_STATUSES.includes(v) ? v : "unknown";
};

export interface MonitoringInventory { checks: Record<string, unknown>[]; incidents: Record<string, unknown>[]; worklist: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function monitoringInventory(tenant: number | null): MonitoringInventory {
  const db = getDb("XORCISM");
  const empty: MonitoringInventory = { checks: [], incidents: [], worklist: [], summary: { total: 0, up: 0, down: 0, warning: 0, paused: 0, avgUptime: null, sslExpiringSoon: 0, openIncidents: 0, byType: {}, byStatus: {} } };
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='MONITORINGCHECK'").get()) return empty;
  const cc = cols("MONITORINGCHECK");
  const tw = tenant != null && cc.has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const raw = db.prepare(`SELECT * FROM MONITORINGCHECK ${tw} ORDER BY CheckID DESC`).all() as Record<string, any>[];

  const assetName = new Map<number, string>();
  for (const a of db.prepare("SELECT AssetID, AssetName FROM ASSET").all() as { AssetID: number; AssetName: string }[])
    assetName.set(a.AssetID, a.AssetName || `#${a.AssetID}`);

  const checks = raw.map((c) => {
    const status = normStatus(String(c.Status ?? ""));
    const uptime = c.UptimePercent != null && c.UptimePercent !== "" ? Number(c.UptimePercent) : null;
    const sslDays = daysUntil(c.SSLExpiryDate ? String(c.SSLExpiryDate) : null);
    return {
      id: Number(c.CheckID), assetId: c.AssetID != null ? Number(c.AssetID) : null,
      asset: c.AssetID != null ? (assetName.get(Number(c.AssetID)) ?? `#${c.AssetID}`) : "",
      name: String(c.Name ?? "").trim() || `Monitor #${c.CheckID}`,
      type: String(c.CheckType ?? "").trim().toLowerCase() || "http", target: String(c.Target ?? ""),
      enabled: c.Enabled == null ? true : !!Number(c.Enabled), status,
      uptime, responseTime: c.ResponseTimeMs != null && c.ResponseTimeMs !== "" ? Number(c.ResponseTimeMs) : null,
      lastChecked: c.LastCheckedAt ? String(c.LastCheckedAt) : null,
      sslExpiry: c.SSLExpiryDate ? String(c.SSLExpiryDate).slice(0, 10) : null, sslDays,
      source: String(c.Source ?? "manual"),
    };
  });

  // Open incidents (ResolvedAt NULL), enriched with asset/check name.
  let incidents: Record<string, unknown>[] = [];
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='MONITORINGINCIDENT'").get()) {
    const itw = tenant != null && cols("MONITORINGINCIDENT").has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    const checkName = new Map(checks.map((c) => [c.id, c.name]));
    incidents = (db.prepare(`SELECT * FROM MONITORINGINCIDENT WHERE 1=1 ${itw} ORDER BY COALESCE(StartedAt, CreatedDate) DESC LIMIT 100`).all() as Record<string, any>[]).map((i) => ({
      id: Number(i.IncidentID), checkId: i.CheckID != null ? Number(i.CheckID) : null,
      monitor: i.CheckID != null ? (checkName.get(Number(i.CheckID)) ?? `#${i.CheckID}`) : "",
      asset: i.AssetID != null ? (assetName.get(Number(i.AssetID)) ?? "") : "",
      title: String(i.Title ?? "").trim() || "Incident", status: normStatus(String(i.Status ?? "down")),
      severity: String(i.Severity ?? ""), startedAt: i.StartedAt ? String(i.StartedAt) : (i.CreatedDate ? String(i.CreatedDate) : null),
      resolvedAt: i.ResolvedAt ? String(i.ResolvedAt) : null, open: !i.ResolvedAt,
    }));
  }
  const openIncidents = incidents.filter((i) => i.open);

  // Worklist: down monitors, then SSL expiring/expired, then low uptime (<99%).
  const worklist: Record<string, unknown>[] = [];
  for (const c of checks) if (c.enabled && c.status === "down") worklist.push({ kind: "down", id: c.id, monitor: c.name, asset: c.asset, label: `DOWN — ${c.name}${c.asset ? ` (${c.asset})` : ""}`, severity: "Critical" });
  for (const c of checks) if (c.sslDays != null && c.sslDays <= SSL_SOON_DAYS) worklist.push({ kind: "ssl", id: c.id, monitor: c.name, asset: c.asset, label: `SSL ${c.sslDays < 0 ? "EXPIRED" : `expires in ${c.sslDays}d`} — ${c.name}`, severity: c.sslDays < 0 ? "Critical" : c.sslDays <= 7 ? "High" : "Medium" });
  for (const c of checks) if (c.enabled && c.status !== "down" && c.uptime != null && c.uptime < 99) worklist.push({ kind: "uptime", id: c.id, monitor: c.name, asset: c.asset, label: `Low uptime ${c.uptime}% — ${c.name}`, severity: c.uptime < 95 ? "High" : "Medium" });

  const byType: Record<string, number> = {}; const byStatus: Record<string, number> = {};
  for (const c of checks) { byType[c.type] = (byType[c.type] || 0) + 1; byStatus[c.status] = (byStatus[c.status] || 0) + 1; }
  const upt = checks.map((c) => c.uptime).filter((u): u is number => u != null);

  return {
    checks, incidents, worklist,
    summary: {
      total: checks.length,
      up: checks.filter((c) => c.status === "up").length,
      down: checks.filter((c) => c.status === "down").length,
      warning: checks.filter((c) => c.status === "warning").length,
      paused: checks.filter((c) => c.status === "paused" || !c.enabled).length,
      avgUptime: upt.length ? Math.round((upt.reduce((s, u) => s + u, 0) / upt.length) * 100) / 100 : null,
      sslExpiringSoon: checks.filter((c) => c.sslDays != null && c.sslDays <= SSL_SOON_DAYS).length,
      openIncidents: openIncidents.length,
      byType, byStatus,
    },
  };
}

/** Create a monitor on an asset (the guided "Add monitor"). Column-aware INSERT + GUID + tenant. */
export function createMonitor(
  p: { name: string; type?: string; target?: string; assetId?: number | null; intervalSeconds?: number | null;
       cronExpression?: string | null; ownerPersonId?: number | null; sslExpiryDate?: string; enabled?: boolean; source?: string },
  tenant: number | null,
): { id: number } {
  const db = getDb("XORCISM");
  const mc = cols("MONITORINGCHECK");
  if (!mc.size) throw new Error("MONITORINGCHECK table not available");
  const now = new Date().toISOString();
  const nextId = (db.prepare("SELECT COALESCE(MAX(CheckID),0)+1 AS n FROM MONITORINGCHECK").get() as { n: number }).n;
  const type = (p.type || "http").toLowerCase();
  const candidate: Record<string, unknown> = {
    CheckID: nextId, CheckGUID: randomUUID(), AssetID: p.assetId ?? null,
    Name: (p.name || "Untitled monitor").slice(0, 300),
    CheckType: CHECK_TYPES.includes(type) ? type : "http",
    Target: p.target ? String(p.target).slice(0, 500) : null,
    IntervalSeconds: p.intervalSeconds ?? 300, CronExpression: p.cronExpression ? String(p.cronExpression).slice(0, 120) : null,
    Enabled: p.enabled === false ? 0 : 1,
    Status: "unknown", OwnerPersonID: p.ownerPersonId ?? null,
    SSLExpiryDate: p.sslExpiryDate || null, Source: p.source || "manual", CreatedDate: now, TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => mc.has(k));
  db.prepare(`INSERT INTO MONITORINGCHECK (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => candidate[k]));
  return { id: nextId };
}

/**
 * Activate monitoring on an ASSET: derive monitors from the asset's IP / URL / hostname and create
 * them (idempotently — skips targets already monitored for that asset). Builds an HTTP monitor for a
 * website URL (+ an SSL monitor when it's https), a PING monitor for the IPv4 address, and a DNS
 * monitor for an FQDN/hostname. Interval (or an optional cron expression) sets the periodicity.
 */
export function activateMonitoring(
  assetId: number,
  opts: { intervalSeconds?: number | null; cronExpression?: string | null; ownerPersonId?: number | null;
          types?: string[]; target?: string | null },
  tenant: number | null,
): { created: number; skipped: number; monitors: { id: number; type: string; target: string }[] } {
  const db = getDb("XORCISM");
  const ac = cols("ASSET");
  const pick = (...names: string[]): string => {
    for (const n of names) if (ac.has(n)) {
      const v = (db.prepare(`SELECT "${n}" v FROM ASSET WHERE AssetID = ?`).get(assetId) as { v: unknown } | undefined)?.v;
      if (v != null && String(v).trim()) return String(v).trim();
    }
    return "";
  };
  const asset = db.prepare("SELECT AssetName FROM ASSET WHERE AssetID = ?").get(assetId) as { AssetName: string } | undefined;
  if (!asset) throw new Error("asset not found");
  const name = asset.AssetName || `Asset #${assetId}`;

  // Gather candidate targets from the asset's network fields (+ AssetDescription if it looks like a URL).
  const url = pick("websiteurl") || (/^https?:\/\//i.test(pick("AssetDescription")) ? pick("AssetDescription") : "");
  const ipv4 = pick("ipaddressIPv4");
  const host = pick("fqdn", "hostname");
  const isDomain = (h: string): boolean => /\./.test(h) && !/^\d+\.\d+\.\d+\.\d+$/.test(h) && !h.includes(" ");
  const wantTypes = opts.types && opts.types.length ? new Set(opts.types) : null;

  const planned: { type: string; target: string; name: string; ssl?: boolean }[] = [];
  if (opts.target) {
    const t = String(opts.target).trim();
    planned.push({ type: /^https?:\/\//i.test(t) ? "http" : (/^\d+\.\d+\.\d+\.\d+$/.test(t) ? "ping" : "http"), target: t, name: `${name} — ${t}` });
    if (/^https:\/\//i.test(t)) planned.push({ type: "ssl", target: t, name: `${name} — SSL`, ssl: true });
  } else {
    if (url) {
      planned.push({ type: "http", target: url, name: `${name} — HTTP` });
      if (/^https:\/\//i.test(url)) planned.push({ type: "ssl", target: url, name: `${name} — SSL` });
    }
    if (ipv4) planned.push({ type: "ping", target: ipv4, name: `${name} — Ping` });
    if (host && isDomain(host) && host !== url) planned.push({ type: "dns", target: host, name: `${name} — DNS` });
  }

  // Existing monitor targets for this asset (skip duplicates).
  const existing = new Set((db.prepare("SELECT LOWER(CheckType)||'|'||LOWER(COALESCE(Target,'')) k FROM MONITORINGCHECK WHERE AssetID = ?").all(assetId) as { k: string }[]).map((r) => r.k));

  const monitors: { id: number; type: string; target: string }[] = [];
  let skipped = 0;
  for (const m of planned) {
    if (wantTypes && !wantTypes.has(m.type)) continue;
    const key = `${m.type}|${m.target.toLowerCase()}`;
    if (existing.has(key)) { skipped++; continue; }
    const out = createMonitor({
      name: m.name, type: m.type, target: m.target, assetId,
      intervalSeconds: opts.intervalSeconds ?? null, cronExpression: opts.cronExpression ?? null,
      ownerPersonId: opts.ownerPersonId ?? null, source: "asset-activate",
    }, tenant);
    existing.add(key);
    monitors.push({ id: out.id, type: m.type, target: m.target });
  }
  return { created: monitors.length, skipped, monitors };
}

/**
 * Record a check result: update the monitor's status / response time / last-checked, and open or
 * resolve a MONITORINGINCIDENT on an up↔down transition. Used by the optional in-process checker
 * and manual status changes.
 */
export function updateMonitorStatus(checkId: number, status: string, responseTimeMs: number | null, tenant: number | null): { ok: boolean } {
  const db = getDb("XORCISM");
  const mc = cols("MONITORINGCHECK");
  if (!mc.has("Status")) throw new Error("MONITORINGCHECK not available");
  const st = normStatus(status);
  const tw = tenant != null && mc.has("TenantID") ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const prev = db.prepare(`SELECT CheckID, AssetID, Name, Status FROM MONITORINGCHECK WHERE CheckID = ? ${tenant != null && mc.has("TenantID") ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null && mc.has("TenantID") ? [checkId, tenant] : [checkId])) as { CheckID: number; AssetID: number | null; Name: string; Status: string } | undefined;
  if (!prev) return { ok: false };
  const now = new Date().toISOString();
  const args: unknown[] = [st, responseTimeMs, now];
  let setSql = "Status = ?, ResponseTimeMs = ?, LastCheckedAt = ?";
  if (normStatus(prev.Status) !== st) { setSql += ", LastStatusChange = ?"; args.push(now); }
  args.push(checkId);
  if (tw) args.push(tenant);
  db.prepare(`UPDATE MONITORINGCHECK SET ${setSql} WHERE CheckID = ? ${tw}`).run(...args);

  // Incident lifecycle on up↔down transitions.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='MONITORINGINCIDENT'").get()) {
    const wasDown = normStatus(prev.Status) === "down";
    if (st === "down" && !wasDown) {
      const nid = (db.prepare("SELECT COALESCE(MAX(IncidentID),0)+1 AS n FROM MONITORINGINCIDENT").get() as { n: number }).n;
      db.prepare(`INSERT INTO MONITORINGINCIDENT (IncidentID, IncidentGUID, CheckID, AssetID, Title, Status, Severity, StartedAt, Source, CreatedDate, TenantID)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(nid, randomUUID(), checkId, prev.AssetID, `${prev.Name} is DOWN`, "down", "Critical", now, "monitor", now, tenant);
    } else if (st === "up" && wasDown) {
      // resolve the most recent open incident for this monitor.
      const open = db.prepare("SELECT IncidentID, StartedAt FROM MONITORINGINCIDENT WHERE CheckID = ? AND (ResolvedAt IS NULL OR ResolvedAt = '') ORDER BY IncidentID DESC LIMIT 1").get(checkId) as { IncidentID: number; StartedAt: string } | undefined;
      if (open) {
        const dur = open.StartedAt ? Math.max(0, Math.round((Date.parse(now) - Date.parse(open.StartedAt)) / 60000)) : null;
        db.prepare("UPDATE MONITORINGINCIDENT SET ResolvedAt = ?, DurationMinutes = ?, Status = 'up' WHERE IncidentID = ?").run(now, dur, open.IncidentID);
      }
    }
  }
  return { ok: true };
}
