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
import { randomUUID } from "crypto";
import { getDb, allocId } from "./db";
import { incidentSlaView } from "./sla";
import { putBlob } from "./blobstore";

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
  evidence: number;
  flags: string[];
  score: number;
}
export interface IncidentFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; incidentId: number; incident: string; }
export interface IncidentInventory {
  rows: IncidentRow[];
  findings: IncidentFinding[];
  summary: {
    total: number; open: number; criticalOpen: number; breached: number; unassigned: number;
    stale: number; compromises: number; mttrHours: number | null; mttdMinutes: number | null;
    byStatus: Record<string, number>; bySeverity: Record<string, number>;
  };
}

const EMPTY: IncidentInventory = {
  rows: [], findings: [],
  summary: { total: 0, open: 0, criticalOpen: 0, breached: 0, unassigned: 0, stale: 0, compromises: 0, mttrHours: null, mttdMinutes: null, byStatus: {}, bySeverity: {} },
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
  // Attached-evidence counts (lightweight per-incident files in the CAS blob store).
  ensureIncidentEvidenceTable();
  const evidenceCount = new Map<number, number>();
  for (const r of db.prepare(`SELECT IncidentID, COUNT(*) n FROM INCIDENTEVIDENCE GROUP BY IncidentID`).all() as { IncidentID: number; n: number }[]) evidenceCount.set(Number(r.IncidentID), Number(r.n));

  const findings: IncidentFinding[] = [];
  const durations: number[] = [];
  const detectDeltas: number[] = []; // MTTD: minutes from start_datetime → detect_datetime
  const pms = (v: unknown): number | null => { if (v == null || v === "") return null; const t = Date.parse(String(v).replace(" ", "T")); return Number.isFinite(t) ? t : null; };
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
    const stMs = pms(r.start_datetime), dtMs = pms(r.detect_datetime);
    if (stMs != null && dtMs != null && dtMs >= stMs) detectDeltas.push((dtMs - stMs) / 60000);

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
      reported, durationHours, ageDays, assets, breached, compromise, evidence: evidenceCount.get(id) ?? 0, flags, score: Math.min(100, score),
    };
  });

  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || a.incident.localeCompare(b.incident));

  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of rows) { byStatus[r.status] = (byStatus[r.status] || 0) + 1; bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1; }
  const mttrHours = durations.length ? Math.round(durations.reduce((s, d) => s + d, 0) / durations.length) : null;
  const mttdMinutes = detectDeltas.length ? Math.round(detectDeltas.reduce((s, d) => s + d, 0) / detectDeltas.length) : null;

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
      mttrHours, mttdMinutes, byStatus, bySeverity,
    },
  };
}

// ── Lightweight per-incident evidence attachments ──────────────────────────────
// A quick way to attach a screenshot / log / export to an incident without opening a full
// forensic case (cert-ops FORENSICEVIDENCE owns chain-of-custody-grade evidence). The file bytes
// live in the content-addressed blob store (XORCISM.FILEBLOB, de-duplicated by sha256); this table
// just links an incident to that blob with the original filename and an optional note.
const MAX_EVIDENCE_BYTES = 15 * 1024 * 1024; // 15 MB/file (base64 ~20 MB, under the 25 MB JSON body limit)

export function ensureIncidentEvidenceTable(): void {
  getDb("XINCIDENT").exec(`
    CREATE TABLE IF NOT EXISTS INCIDENTEVIDENCE (
      EvidenceID INTEGER PRIMARY KEY, EvidenceGUID TEXT, IncidentID INTEGER, FileName TEXT, ContentType TEXT,
      Sha256 TEXT, Size INTEGER, Description TEXT, UploadedByUserID INTEGER, UploadedByName TEXT,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_incevidence_inc ON INCIDENTEVIDENCE(IncidentID);
    CREATE INDEX IF NOT EXISTS ix_incevidence_tenant ON INCIDENTEVIDENCE(TenantID);`);
}

/** Does this incident exist and belong to the caller's tenant? */
function incidentInTenant(incidentId: number, tenant: number | null): boolean {
  const db = getDb("XINCIDENT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) return false;
  const hasTenant = cols("INCIDENT").has("TenantID");
  const sql = hasTenant
    ? "SELECT 1 FROM INCIDENT WHERE IncidentID = ? AND (TenantID = ? OR TenantID IS NULL)"
    : "SELECT 1 FROM INCIDENT WHERE IncidentID = ?";
  return !!db.prepare(sql).get(...(hasTenant ? [incidentId, tenant] : [incidentId]));
}

function evidenceRow(r: any): any {
  return {
    id: r.EvidenceID, incidentId: r.IncidentID, fileName: r.FileName, contentType: r.ContentType,
    sha256: r.Sha256, size: r.Size, description: r.Description, uploadedBy: r.UploadedByName,
    createdDate: r.CreatedDate, downloadUrl: `/api/blob/${r.Sha256}`,
  };
}

export function listIncidentEvidence(incidentId: number, tenant: number | null): any[] | null {
  ensureIncidentEvidenceTable();
  if (!incidentInTenant(incidentId, tenant)) return null;
  return (getDb("XINCIDENT").prepare(
    "SELECT * FROM INCIDENTEVIDENCE WHERE IncidentID = ? ORDER BY EvidenceID DESC"
  ).all(incidentId) as any[]).map(evidenceRow);
}

/** Attach a file (base64) to an incident: store the bytes in the CAS, link via INCIDENTEVIDENCE. */
export function attachIncidentEvidence(
  incidentId: number, tenant: number | null,
  b: { fileName?: string; contentType?: string; dataBase64?: string; description?: string; userId?: number | null; userName?: string },
): { id: number; sha256: string; size: number } | { error: string } {
  ensureIncidentEvidenceTable();
  if (!incidentInTenant(incidentId, tenant)) return { error: "incident not found" };
  const raw = String(b.dataBase64 || "").replace(/^data:[^;]+;base64,/, "");
  if (!raw) return { error: "no file data" };
  let buf: Buffer;
  try { buf = Buffer.from(raw, "base64"); } catch { return { error: "invalid base64" }; }
  if (!buf.length) return { error: "empty file" };
  if (buf.length > MAX_EVIDENCE_BYTES) return { error: `file too large (max ${MAX_EVIDENCE_BYTES / 1024 / 1024} MB)` };
  const name = String(b.fileName || "evidence").slice(0, 260);
  const ct = String(b.contentType || "application/octet-stream").slice(0, 120);
  const put = putBlob(buf, { name, contentType: ct, pin: true }); // pin: evidence is retained, not GC'd
  const db = getDb("XINCIDENT");
  const id = allocId(db, "INCIDENTEVIDENCE", "EvidenceID");
  db.prepare(
    `INSERT INTO INCIDENTEVIDENCE (EvidenceID, EvidenceGUID, IncidentID, FileName, ContentType, Sha256, Size, Description, UploadedByUserID, UploadedByName, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(id, randomUUID(), incidentId, name, ct, put.sha256, put.size, String(b.description || "").slice(0, 1000),
    b.userId ?? null, String(b.userName || "").slice(0, 120), new Date().toISOString(), tenant);
  return { id, sha256: put.sha256, size: put.size };
}

/** Detach (unlink) an evidence file from its incident. The blob itself stays in the CAS (refcounted;
 *  reclaimed later by GC if nothing else references it) — we never hard-delete the bytes here. */
export function detachIncidentEvidence(evidenceId: number, tenant: number | null): { ok: boolean; incidentId: number } | null {
  ensureIncidentEvidenceTable();
  const db = getDb("XINCIDENT");
  const r = db.prepare("SELECT IncidentID, TenantID FROM INCIDENTEVIDENCE WHERE EvidenceID = ?").get(evidenceId) as any;
  if (!r) return null;
  if (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant) return null;
  db.prepare("DELETE FROM INCIDENTEVIDENCE WHERE EvidenceID = ?").run(evidenceId);
  return { ok: true, incidentId: Number(r.IncidentID) };
}
