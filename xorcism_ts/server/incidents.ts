/**
 * incidents.ts — Incident Management inventory + governance worklist.
 *
 * The INCIDENT counterpart of assets.ts / identities.ts: one operational pane over the
 * incident queue that resolves each incident's posture (severity, status, owner, age,
 * scoped assets, SLA/RTO breach, confirmed compromise) and derives the response-hygiene
 * findings a SOC lead acts on — open critical incidents, SLA/RTO breaches, unassigned or
 * stale tickets, unclassified / awaiting-determination, unscoped incidents — each with a
 * 0-100 priority score. Reuses the SLA breach analysis (sla.ts incidentSlaView).
 *
 * Read-only; INCIDENT CRUD stays in the schema-driven explorer.
 */
import { getDb } from "./db";
import { incidentSlaView } from "./sla";

export interface IncidentRow {
  id: number;
  name: string;
  severity: string;
  status: string;
  open: boolean;
  assignee: string | null;
  classification: string;
  determination: string;
  reported: string | null;
  durationHours: number | null;
  ageDays: number | null;
  assets: number;
  breached: boolean;
  compromise: boolean;
  flags: string[];
  score: number;
}
export interface IncidentFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; incidentId: number; incident: string; }
export interface IncidentInventory {
  rows: IncidentRow[];
  findings: IncidentFinding[];
  summary: {
    total: number; open: number; criticalOpen: number; breached: number; unassigned: number;
    stale: number; compromises: number; mttrHours: number | null;
    byStatus: Record<string, number>; bySeverity: Record<string, number>;
  };
}

const EMPTY: IncidentInventory = {
  rows: [], findings: [],
  summary: { total: 0, open: 0, criticalOpen: 0, breached: 0, unassigned: 0, stale: 0, compromises: 0, mttrHours: null, byStatus: {}, bySeverity: {} },
};

const STALE_DAYS = 7;
const HIGH_SEV = /^(high|critical|sev[\s-]?[12]|p[12])$/i;
const RESOLVED = /resolv|closed|clos[eé]|remediat|recover|done|terminé|fermé/i;

function cols(table: string): Set<string> {
  try { return new Set((getDb("XINCIDENT").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || /^(y|yes|true|on)$/i.test(String(v ?? "")); }
function daysSince(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
}
const d10 = (v: unknown): string | null => (v ? String(v).slice(0, 10) : null);
const numOrNull = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; };

/** Full incident inventory with resolved posture + derived governance findings. */
export function incidentInventory(tenant: number | null): IncidentInventory {
  const db = getDb("XINCIDENT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) return { ...EMPTY };
  const ic = cols("INCIDENT");
  const tw = tenant != null && ic.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const incs = db.prepare(`SELECT * FROM INCIDENT ${tw}`).all() as Record<string, unknown>[];
  if (!incs.length) return { ...EMPTY };

  // SLA / RTO breach map (reuse the cross-DB SLA analysis).
  const breachedSet = new Set<number>();
  try {
    for (const r of incidentSlaView(tenant).rows) if (r.slaStatus === "breached" || r.rtoStatus === "breached") breachedSet.add(Number(r.incidentId));
  } catch { /* SLA view unavailable */ }
  // Scoped-asset counts.
  const assetCount = new Map<number, number>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENTFORASSET'").get()) {
    for (const r of db.prepare(`SELECT IncidentID, COUNT(*) n FROM INCIDENTFORASSET WHERE AssetID IS NOT NULL GROUP BY IncidentID`).all() as { IncidentID: number; n: number }[]) assetCount.set(Number(r.IncidentID), Number(r.n));
  }

  const findings: IncidentFinding[] = [];
  const durations: number[] = [];
  const rows: IncidentRow[] = incs.map((r) => {
    const id = Number(r.IncidentID);
    const name = String(r.IncidentName ?? "").trim() || `Incident #${id}`;
    const severity = String(r.Severity ?? r.Criticity ?? "").trim() || "Unrated";
    const status = String(r.status ?? r.Status ?? "").trim() || "New";
    const endDt = d10(r.end_datetime);
    const resolved = RESOLVED.test(status) || !!endDt;
    const open = !resolved;
    const assignee = String(r.AssignedTo ?? "").trim() || null;
    const classification = String(r.Classification ?? "").trim();
    const determination = String(r.Determination ?? "").trim();
    const reported = d10(r.datetime_reported ?? r.start_datetime ?? r.CreatedDate);
    const durationHours = numOrNull(r.Duration);
    const ageDays = daysSince(reported);
    const assets = assetCount.get(id) ?? 0;
    const breached = breachedSet.has(id);
    const compromise = truthy(r.security_compromise);
    const isCrit = HIGH_SEV.test(severity);
    if (resolved && durationHours != null) durations.push(durationHours);

    const flags: string[] = [];
    let score = 0;
    const add = (kind: string, label: string, sev: IncidentFinding["severity"], pts: number): void => {
      flags.push(label); score += pts;
      findings.push({ kind, label: `${name}: ${label}`, severity: sev, incidentId: id, incident: name });
    };

    if (compromise && open) add("compromise", "Confirmed security compromise", "Critical", 30);
    if (isCrit && open) add("critopen", `Open ${severity} incident`, "High", 25);
    if (breached) add("breach", "SLA / RTO breached", "High", 20);
    if (open && !assignee) add("unassigned", "Unassigned", "Medium", 12);
    if (open && ageDays != null && ageDays > STALE_DAYS) add("stale", `Open for ${ageDays}d`, "Medium", 10);
    if (open && assets === 0) add("noscope", "No assets scoped", "Low", 6);
    if (open && !classification) add("unclassified", "Unclassified", "Low", 5);
    else if (classification && !determination && open) add("nodetermination", "Awaiting determination", "Low", 4);
    if (resolved && !String(r.corrective_action ?? "").trim()) add("nocorrective", "Resolved without a recorded corrective action", "Low", 4);

    return {
      id, name, severity, status, open, assignee, classification, determination,
      reported, durationHours, ageDays, assets, breached, compromise, flags, score: Math.min(100, score),
    };
  });

  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || a.incident.localeCompare(b.incident));

  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of rows) { byStatus[r.status] = (byStatus[r.status] || 0) + 1; bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1; }
  const mttrHours = durations.length ? Math.round(durations.reduce((s, d) => s + d, 0) / durations.length) : null;

  return {
    rows, findings,
    summary: {
      total: rows.length,
      open: rows.filter((r) => r.open).length,
      criticalOpen: rows.filter((r) => r.open && HIGH_SEV.test(r.severity)).length,
      breached: rows.filter((r) => r.breached).length,
      unassigned: rows.filter((r) => r.open && !r.assignee).length,
      stale: rows.filter((r) => r.flags.some((f) => f.startsWith("Open for"))).length,
      compromises: rows.filter((r) => r.compromise).length,
      mttrHours, byStatus, bySeverity,
    },
  };
}
