/**
 * evidencecatalogue.ts — Evidence Catalogue (/evidence-catalogue).
 *
 * A central registry to collect and manage audit / compliance evidence. It builds on the existing
 * EVIDENCE table (XCOMPLIANCE) — extended with the fields a real evidence library needs (type, owner,
 * source, tags, validity window, framework / control reference, and a content-addressed blob pointer) —
 * so an artifact is captured once and reused across audits, controls and compliance activities.
 *
 * Files are stored in the content-addressed blob store (CAS, SHA-256 dedup) and served back via the
 * generic /api/blob/:sha route; alternatively an evidence item can point at a URL. Freshness is tracked
 * from the validity window (valid / expiring-soon / expired). Evidence can be linked to an AUDIT
 * (AUDITEVIDENCE) and carries a control/framework reference for filtering. RBAC: XCOMPLIANCE.AUDIT.
 */
import { getDb, allocId } from "./db";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);
const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
const tw = (tenant: number | null): string => (tenant != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const tp = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

export const EVIDENCE_TYPES = ["Document", "Screenshot", "Log", "Report", "Configuration", "Attestation", "Ticket", "Policy", "Scan result", "Record", "Other"] as const;

/** Create the catalogue: the EVIDENCE table (kept if it already exists) + the extra library columns. */
export function ensureEvidenceCatalogue(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`CREATE TABLE IF NOT EXISTS EVIDENCE (
    EvidenceID INTEGER PRIMARY KEY, EvidenceName TEXT, EvidenceDescription TEXT, EvidenceDate TEXT, CreatedDate TEXT,
    ValidFrom TEXT, ValidUntil TEXT, EvidenceURL TEXT, Validity TEXT, EvidenceFile TEXT);`);
  const cols = new Set((db.prepare(`PRAGMA table_info("EVIDENCE")`).all() as { name: string }[]).map((c) => c.name));
  const add = (c: string, t: string): void => { if (!cols.has(c)) { try { db.exec(`ALTER TABLE EVIDENCE ADD COLUMN ${c} ${t}`); } catch { /* concurrent */ } } };
  add("TenantID", "INTEGER"); add("EvidenceType", "TEXT"); add("Owner", "TEXT"); add("Source", "TEXT"); add("Tags", "TEXT");
  add("BlobSha256", "TEXT"); add("Size", "INTEGER"); add("ContentType", "TEXT"); add("ControlRef", "TEXT"); add("Framework", "TEXT");
  add("ActivityID", "INTEGER"); add("UpdatedDate", "TEXT");
  db.exec(`CREATE INDEX IF NOT EXISTS ix_evidence_tenant ON EVIDENCE(TenantID);
           CREATE TABLE IF NOT EXISTS AUDITEVIDENCE (AuditEvidenceID INTEGER PRIMARY KEY, AuditEvidenceGUID TEXT, AuditID INTEGER, EvidenceID INTEGER, CreatedDate TEXT, ConfidenceLevel TEXT, Status TEXT);`);
}

/** Freshness of one evidence item from its validity window. */
export function freshness(validUntil: string | null): "valid" | "expiring" | "expired" | "none" {
  if (!validUntil) return "none";
  const d = validUntil.slice(0, 10);
  if (d < today()) return "expired";
  const soon = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  return d <= soon ? "expiring" : "valid";
}

export interface EvidenceItem {
  id: number; name: string; description: string | null; type: string | null; owner: string | null; source: string | null;
  tags: string[]; framework: string | null; controlRef: string | null; activityId: number | null;
  validFrom: string | null; validUntil: string | null; evidenceDate: string | null; createdDate: string | null;
  url: string | null; sha256: string | null; size: number | null; contentType: string | null;
  fresh: ReturnType<typeof freshness>; audits: number[];
}

function row2item(r: Record<string, unknown>, audits: number[]): EvidenceItem {
  return {
    id: Number(r.EvidenceID), name: String(r.EvidenceName || ""), description: (r.EvidenceDescription as string) || null,
    type: (r.EvidenceType as string) || null, owner: (r.Owner as string) || null, source: (r.Source as string) || null,
    tags: r.Tags ? String(r.Tags).split(",").map((t) => t.trim()).filter(Boolean) : [],
    framework: (r.Framework as string) || null, controlRef: (r.ControlRef as string) || null,
    activityId: r.ActivityID != null ? Number(r.ActivityID) : null,
    validFrom: (r.ValidFrom as string) || null, validUntil: (r.ValidUntil as string) || null,
    evidenceDate: (r.EvidenceDate as string) || null, createdDate: (r.CreatedDate as string) || null,
    url: (r.EvidenceURL as string) || null, sha256: (r.BlobSha256 as string) || null,
    size: r.Size != null ? Number(r.Size) : null, contentType: (r.ContentType as string) || null,
    fresh: freshness((r.ValidUntil as string) || null), audits,
  };
}

/** The catalogue payload: items + KPIs + filter facets. */
export function evidenceCatalogue(tenant: number | null): {
  items: EvidenceItem[];
  summary: { total: number; valid: number; expiring: number; expired: number; noValidity: number; withFile: number; byType: Record<string, number> };
  types: readonly string[];
} {
  ensureEvidenceCatalogue();
  const db = getDb("XCOMPLIANCE");
  const rows = db.prepare(`SELECT * FROM EVIDENCE WHERE ${tw(tenant)} ORDER BY COALESCE(UpdatedDate, CreatedDate) DESC, EvidenceID DESC`).all(...tp(tenant)) as Record<string, unknown>[];
  const items = rows.map((r) => {
    const audits = (db.prepare("SELECT AuditID FROM AUDITEVIDENCE WHERE EvidenceID = ?").all(Number(r.EvidenceID)) as { AuditID: number }[]).map((a) => a.AuditID);
    return row2item(r, audits);
  });
  const byType: Record<string, number> = {};
  for (const it of items) { const k = it.type || "Other"; byType[k] = (byType[k] || 0) + 1; }
  const summary = {
    total: items.length,
    valid: items.filter((i) => i.fresh === "valid").length,
    expiring: items.filter((i) => i.fresh === "expiring").length,
    expired: items.filter((i) => i.fresh === "expired").length,
    noValidity: items.filter((i) => i.fresh === "none").length,
    withFile: items.filter((i) => i.sha256).length,
    byType,
  };
  return { items, summary, types: EVIDENCE_TYPES };
}

export function createEvidenceItem(tenant: number | null, p: Record<string, unknown>): EvidenceItem {
  ensureEvidenceCatalogue();
  if (!p.name || !String(p.name).trim()) throw new Error("name required");
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "EVIDENCE", "EvidenceID");
  const ts = now();
  db.prepare(`INSERT INTO EVIDENCE (EvidenceID, EvidenceName, EvidenceDescription, EvidenceType, Owner, Source, Tags, Framework, ControlRef, ActivityID,
      ValidFrom, ValidUntil, EvidenceDate, EvidenceURL, BlobSha256, Size, ContentType, TenantID, CreatedDate, UpdatedDate)
    VALUES (@id,@name,@desc,@type,@owner,@source,@tags,@framework,@control,@activity,@vf,@vu,@edate,@url,@sha,@size,@ct,@tenant,@now,@now)`).run({
    id, name: String(p.name).slice(0, 300), desc: s(p.description), type: s(p.type, 60), owner: s(p.owner, 160), source: s(p.source, 300),
    tags: s(p.tags, 500), framework: s(p.framework, 160), control: s(p.controlRef, 160), activity: p.activityId != null && String(p.activityId) !== "" ? Number(p.activityId) : null,
    vf: s(p.validFrom, 10), vu: s(p.validUntil, 10), edate: s(p.evidenceDate, 10) || today(), url: s(p.url, 1000),
    sha: s(p.sha256, 64), size: p.size != null ? Number(p.size) : null, ct: s(p.contentType, 120), tenant: tenant ?? null, now: ts,
  });
  return getEvidence(tenant, id)!;
}

export function updateEvidenceItem(tenant: number | null, id: number, patch: Record<string, unknown>): EvidenceItem {
  ensureEvidenceCatalogue();
  const map: Record<string, string> = { name: "EvidenceName", description: "EvidenceDescription", type: "EvidenceType", owner: "Owner",
    source: "Source", tags: "Tags", framework: "Framework", controlRef: "ControlRef", validFrom: "ValidFrom", validUntil: "ValidUntil",
    evidenceDate: "EvidenceDate", url: "EvidenceURL", activityId: "ActivityID" };
  const sets: string[] = []; const args: Record<string, unknown> = { id, now: now() };
  for (const [k, col] of Object.entries(map)) {
    if (k in patch) { sets.push(`${col} = @${k}`); args[k] = k === "activityId" ? (patch[k] != null && String(patch[k]) !== "" ? Number(patch[k]) : null) : s(patch[k], k === "description" ? 4000 : 500); }
  }
  if (!sets.length) return getEvidence(tenant, id)!;
  getDb("XCOMPLIANCE").prepare(`UPDATE EVIDENCE SET ${sets.join(", ")}, UpdatedDate = @now WHERE EvidenceID = @id AND ${tw(tenant)}`).run({ ...args, ...(tenant != null ? { t: tenant } : {}) }, ...tp(tenant));
  return getEvidence(tenant, id)!;
}

export function deleteEvidenceItem(tenant: number | null, id: number): void {
  ensureEvidenceCatalogue();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM AUDITEVIDENCE WHERE EvidenceID = ?").run(id);
  db.prepare(`DELETE FROM EVIDENCE WHERE EvidenceID = ? AND ${tw(tenant)}`).run(id, ...tp(tenant));
}

export function getEvidence(tenant: number | null, id: number): EvidenceItem | null {
  ensureEvidenceCatalogue();
  const db = getDb("XCOMPLIANCE");
  const r = db.prepare(`SELECT * FROM EVIDENCE WHERE EvidenceID = ? AND ${tw(tenant)}`).get(id, ...tp(tenant)) as Record<string, unknown> | undefined;
  if (!r) return null;
  const audits = (db.prepare("SELECT AuditID FROM AUDITEVIDENCE WHERE EvidenceID = ?").all(id) as { AuditID: number }[]).map((a) => a.AuditID);
  return row2item(r, audits);
}

/** Link / unlink an evidence item to an AUDIT (AUDITEVIDENCE). */
export function linkEvidenceToAudit(tenant: number | null, evidenceId: number, auditId: number): void {
  ensureEvidenceCatalogue();
  const db = getDb("XCOMPLIANCE");
  const exists = db.prepare("SELECT 1 FROM AUDITEVIDENCE WHERE AuditID = ? AND EvidenceID = ? LIMIT 1").get(auditId, evidenceId);
  if (exists) return;
  const id = allocId(db, "AUDITEVIDENCE", "AuditEvidenceID");
  db.prepare("INSERT INTO AUDITEVIDENCE (AuditEvidenceID, AuditID, EvidenceID, CreatedDate, Status) VALUES (?,?,?,?,'linked')").run(id, auditId, evidenceId, now());
}
export function unlinkEvidenceFromAudit(_tenant: number | null, evidenceId: number, auditId: number): void {
  getDb("XCOMPLIANCE").prepare("DELETE FROM AUDITEVIDENCE WHERE AuditID = ? AND EvidenceID = ?").run(auditId, evidenceId);
}

/** The audits available to link (id + name), for the picker. */
export function auditsForPicker(tenant: number | null): { id: number; name: string }[] {
  const db = getDb("XCOMPLIANCE");
  try {
    return (db.prepare(`SELECT AuditID id, COALESCE(AuditName, 'Audit #' || AuditID) name FROM AUDIT WHERE ${tw(tenant)} ORDER BY AuditID DESC LIMIT 200`).all(...tp(tenant)) as { id: number; name: string }[]);
  } catch { return []; }
}
