/**
 * findingremediation.ts — remediation plans / corrective actions for audit findings.
 *
 * One AUDITFINDING → many AUDITFINDINGREMEDIATION rows (a plan: name, type, status, owner,
 * target date, progress). Sibling of patchmgmt.ts's ASSETVULNERABILITYREMEDIATION. Creating a
 * plan also nudges the parent finding's workflow/owner/due-date so the compliance worklist reflects
 * that remediation is under way. All in XCOMPLIANCE; tenant-checked.
 */
import { allocId, getDb } from "./db";
import { randomUUID } from "crypto";

const CLOSED = /implement|verif|clos|done|complet|resolv/i;
export const REMEDIATION_STATUSES = ["Planned", "In progress", "Implemented", "Verified", "Closed", "Cancelled"];
export const REMEDIATION_TYPES = ["Corrective", "Preventive", "Compensating", "Mitigation", "Risk acceptance"];
export const REMEDIATION_PRIORITIES = ["Critical", "High", "Medium", "Low"];

function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function tw(tenant: number | null): string { return tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""; }
function ta(tenant: number | null): number[] { return tenant != null ? [tenant] : []; }
function now(): string { return new Date().toISOString(); }

/** The finding row (column-aware) or null. AUDITFINDING has no TenantID — visibility is via its audit. */
function getFinding(cc: ReturnType<typeof getDb>, findingId: number): Record<string, unknown> | null {
  try { return (cc.prepare("SELECT * FROM AUDITFINDING WHERE AuditFindingID = ?").get(findingId) as Record<string, unknown> | undefined) ?? null; }
  catch { return null; }
}

function ownerNames(): Map<string, string> {
  const m = new Map<string, string>();
  try { for (const p of getDb("XORCISM").prepare("SELECT PersonID, FullName FROM PERSON").all() as { PersonID: number; FullName: string }[]) m.set(String(p.PersonID), p.FullName || `#${p.PersonID}`); }
  catch { /* PERSON optional */ }
  return m;
}

export function listFindingRemediations(findingId: number, tenant: number | null): any | null {
  const cc = getDb("XCOMPLIANCE");
  const f = getFinding(cc, findingId);
  if (!f) return null;
  const owners = ownerNames();
  let plans: any[] = [];
  try {
    plans = (cc.prepare(`SELECT * FROM AUDITFINDINGREMEDIATION WHERE AuditFindingID = ? ${tw(tenant)} ORDER BY RemediationID DESC`).all(findingId, ...ta(tenant)) as Record<string, unknown>[]).map((r) => ({
      id: Number(r.RemediationID), name: String(r.RemediationName ?? ""), description: String(r.Description ?? ""),
      type: String(r.RemediationType ?? ""), status: String(r.Status ?? "Planned"), priority: String(r.Priority ?? ""),
      ownerPersonId: r.OwnerPersonID != null ? Number(r.OwnerPersonID) : null, owner: r.OwnerPersonID != null ? (owners.get(String(r.OwnerPersonID)) || `#${r.OwnerPersonID}`) : "",
      targetDate: r.TargetDate ? String(r.TargetDate).slice(0, 10) : null, completedDate: r.CompletedDate ? String(r.CompletedDate).slice(0, 10) : null,
      progress: r.Progress != null && r.Progress !== "" ? Number(r.Progress) : null, createdDate: r.CreatedDate ? String(r.CreatedDate).slice(0, 10) : null, createdBy: String(r.CreatedBy ?? ""),
    }));
  } catch { plans = []; }
  const open = plans.filter((p) => !CLOSED.test(p.status) && !/cancel/i.test(p.status)).length;
  const audit = (() => { try { return String((cc.prepare("SELECT AuditName FROM AUDIT WHERE AuditID = ?").get(f.AuditID) as { AuditName?: string } | undefined)?.AuditName ?? ""); } catch { return ""; } })();
  return {
    finding: { id: findingId, name: String(f.FindingName ?? "") || `Finding #${findingId}`, audit, auditId: f.AuditID != null ? Number(f.AuditID) : null,
      severity: String(f.Severity ?? f.FindingCriticity ?? ""), status: String(f.FindingStatus ?? ""), workflow: String(f.WorkflowStatus ?? ""),
      remediationPlan: String(f.RemediationPlan ?? "") },
    plans, statuses: REMEDIATION_STATUSES, types: REMEDIATION_TYPES, priorities: REMEDIATION_PRIORITIES,
    summary: { total: plans.length, open, done: plans.length - open },
  };
}

export function createFindingRemediation(findingId: number, p: { name?: string; description?: string; type?: string; status?: string; priority?: string; ownerPersonId?: number | null; targetDate?: string }, tenant: number | null, userId?: string): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  const f = getFinding(cc, findingId);
  if (!f) throw new Error("finding not found");
  const rc = cols("AUDITFINDINGREMEDIATION");
  if (!rc.size) throw new Error("AUDITFINDINGREMEDIATION not available");
  const id = allocId(cc, "AUDITFINDINGREMEDIATION", "RemediationID");
  const status = REMEDIATION_STATUSES.includes(String(p.status)) ? String(p.status) : "Planned";
  const rec: Record<string, unknown> = {
    RemediationID: id, RemediationGUID: randomUUID(), AuditFindingID: findingId,
    RemediationName: String(p.name ?? "").slice(0, 300) || "Remediation plan", Description: p.description ? String(p.description).slice(0, 4000) : null,
    RemediationType: p.type ?? "Corrective", Status: status, Priority: p.priority ?? null,
    OwnerPersonID: p.ownerPersonId ?? null, TargetDate: p.targetDate || null,
    CompletedDate: CLOSED.test(status) ? now().slice(0, 10) : null, Progress: CLOSED.test(status) ? 100 : 0,
    CreatedDate: now(), CreatedBy: userId ?? null, TenantID: tenant,
  };
  const keys = Object.keys(rec).filter((k) => rc.has(k));
  cc.prepare(`INSERT INTO AUDITFINDINGREMEDIATION (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));

  // nudge the parent finding so the compliance worklist reflects "remediation under way"
  try {
    const fc = cols("AUDITFINDING");
    const sets: string[] = []; const vals: unknown[] = [];
    if (fc.has("WorkflowStatus") && !/progress|cours|remed|implement/i.test(String(f.WorkflowStatus ?? ""))) { sets.push("WorkflowStatus = ?"); vals.push("In Progress"); }
    if (fc.has("RemediationOwnerPersonID") && f.RemediationOwnerPersonID == null && p.ownerPersonId != null) { sets.push("RemediationOwnerPersonID = ?"); vals.push(p.ownerPersonId); }
    if (fc.has("DueDate") && (f.DueDate == null || f.DueDate === "") && p.targetDate) { sets.push("DueDate = ?"); vals.push(p.targetDate); }
    if (fc.has("RemediationPlan") && !String(f.RemediationPlan ?? "").trim()) { sets.push("RemediationPlan = ?"); vals.push(rec.RemediationName); }
    if (sets.length) cc.prepare(`UPDATE AUDITFINDING SET ${sets.join(", ")} WHERE AuditFindingID = ?`).run(...vals, findingId);
  } catch { /* finding nudge best-effort */ }
  return { id };
}

export function updateFindingRemediation(id: number, patch: { name?: string; description?: string; type?: string; status?: string; priority?: string; ownerPersonId?: number | null; targetDate?: string; progress?: number }, tenant: number | null): { ok: boolean } {
  const cc = getDb("XCOMPLIANCE");
  const row = cc.prepare(`SELECT * FROM AUDITFINDINGREMEDIATION WHERE RemediationID = ? ${tw(tenant)}`).get(id, ...ta(tenant)) as Record<string, unknown> | undefined;
  if (!row) return { ok: false };
  const rc = cols("AUDITFINDINGREMEDIATION");
  const sets: string[] = []; const vals: unknown[] = [];
  const put = (col: string, val: unknown): void => { if (rc.has(col)) { sets.push(`"${col}" = ?`); vals.push(val); } };
  if (patch.name != null) put("RemediationName", String(patch.name).slice(0, 300));
  if (patch.description != null) put("Description", String(patch.description).slice(0, 4000));
  if (patch.type != null) put("RemediationType", String(patch.type));
  if (patch.priority != null) put("Priority", String(patch.priority));
  if (patch.ownerPersonId !== undefined) put("OwnerPersonID", patch.ownerPersonId);
  if (patch.targetDate != null) put("TargetDate", patch.targetDate || null);
  if (patch.progress != null && Number.isFinite(Number(patch.progress))) put("Progress", Math.max(0, Math.min(100, Number(patch.progress))));
  if (patch.status != null && REMEDIATION_STATUSES.includes(String(patch.status))) {
    const st = String(patch.status); put("Status", st);
    if (CLOSED.test(st)) { put("CompletedDate", now().slice(0, 10)); if (patch.progress == null) put("Progress", 100); }
    else put("CompletedDate", null);
  }
  if (!sets.length) return { ok: true };
  cc.prepare(`UPDATE AUDITFINDINGREMEDIATION SET ${sets.join(", ")} WHERE RemediationID = ?`).run(...vals, id);
  return { ok: true };
}

export function deleteFindingRemediation(id: number, tenant: number | null): { ok: boolean } {
  const cc = getDb("XCOMPLIANCE");
  const r = cc.prepare(`DELETE FROM AUDITFINDINGREMEDIATION WHERE RemediationID = ? ${tw(tenant)}`).run(id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/** plans count per finding id (for the compliance worklist). Map<findingId,{plans,open}>. */
export function remediationCounts(findingIds: number[], tenant: number | null): Map<number, { plans: number; open: number }> {
  const out = new Map<number, { plans: number; open: number }>();
  const ids = [...new Set(findingIds.filter(Boolean))];
  if (!ids.length) return out;
  try {
    const cc = getDb("XCOMPLIANCE");
    const ph = ids.map(() => "?").join(",");
    for (const r of cc.prepare(`SELECT AuditFindingID, Status FROM AUDITFINDINGREMEDIATION WHERE AuditFindingID IN (${ph}) ${tw(tenant)}`).all(...ids, ...ta(tenant)) as { AuditFindingID: number; Status: string }[]) {
      const e = out.get(Number(r.AuditFindingID)) ?? { plans: 0, open: 0 };
      e.plans++; if (!CLOSED.test(r.Status || "") && !/cancel/i.test(r.Status || "")) e.open++;
      out.set(Number(r.AuditFindingID), e);
    }
  } catch { /* table optional */ }
  return out;
}
