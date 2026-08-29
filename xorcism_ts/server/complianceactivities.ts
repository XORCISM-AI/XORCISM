/**
 * complianceactivities.ts — Compliance Activity Calendar & Reminders (/compliance-calendar).
 *
 * Plan and get reminded about recurring audit / compliance activities that are broader than a formal
 * audit programme (which /audit-planning already covers): account security reviews, access recerts,
 * policy reviews, attestations, DR tests, control self-assessments, etc. Each COMPLIANCEACTIVITY has a
 * cadence, a next-due date, a lead time and an assignee; a daily reminder tick notifies the assignee
 * ahead of the due date (in-app NOTIFICATION + the compliance.audit_due event) and marks overdue items.
 * Completing an activity logs the occurrence (with optional evidence) and advances the next due date.
 *
 * Complements [[audit-planning]] (formal audits) and feeds the [[evidence-catalogue]] (an occurrence can
 * reference the evidence it produced). RBAC: XCOMPLIANCE.AUDIT.
 */
import { getDb, createNotification } from "./db";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);
const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
const numOrNull = (v: unknown): number | null => (v != null && String(v).trim() !== "" && !Number.isNaN(Number(v)) ? Number(v) : null);
const tw = (t: number | null): string => (t != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const tp = (t: number | null): number[] => (t != null ? [t] : []);

export const CADENCES = ["once", "weekly", "monthly", "quarterly", "semiannual", "annual", "custom"] as const;
export const ACTIVITY_CATEGORIES = ["Internal audit", "External audit", "Access review", "Account security review", "Policy review",
  "Risk assessment", "Control self-assessment", "Attestation", "DR / BCP test", "Penetration test", "Vendor review", "Training / awareness", "Certification", "Other"] as const;
export const ACTIVITY_STATUSES = ["scheduled", "completed", "paused"] as const;

export function ensureComplianceActivities(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS COMPLIANCEACTIVITY (
      ActivityID INTEGER PRIMARY KEY AUTOINCREMENT, TenantID INTEGER,
      Name TEXT NOT NULL, Category TEXT, Description TEXT, OwnerName TEXT, AssigneeUserID INTEGER,
      Framework TEXT, ControlRef TEXT, Cadence TEXT, IntervalDays INTEGER,
      NextDueDate TEXT, LeadTimeDays INTEGER, LastCompletedDate TEXT, Status TEXT,
      ReminderSentFor TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_compact_tenant ON COMPLIANCEACTIVITY(TenantID);
    CREATE INDEX IF NOT EXISTS ix_compact_due ON COMPLIANCEACTIVITY(NextDueDate);
    CREATE TABLE IF NOT EXISTS COMPLIANCEACTIVITYLOG (
      LogID INTEGER PRIMARY KEY AUTOINCREMENT, ActivityID INTEGER, TenantID INTEGER,
      DueDate TEXT, CompletedDate TEXT, CompletedBy TEXT, Notes TEXT, EvidenceID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_compactlog_act ON COMPLIANCEACTIVITYLOG(ActivityID);`);
}

/** Advance a YYYY-MM-DD date by one cadence period. */
export function advanceDue(dateISO: string, cadence: string, intervalDays: number | null): string | null {
  const d = new Date(dateISO + "T00:00:00Z");
  const addMonths = (n: number): void => { d.setUTCMonth(d.getUTCMonth() + n); };
  switch (cadence) {
    case "weekly": d.setUTCDate(d.getUTCDate() + 7); break;
    case "monthly": addMonths(1); break;
    case "quarterly": addMonths(3); break;
    case "semiannual": addMonths(6); break;
    case "annual": addMonths(12); break;
    case "custom": d.setUTCDate(d.getUTCDate() + Math.max(1, intervalDays || 30)); break;
    case "once": default: return null;
  }
  return d.toISOString().slice(0, 10);
}

/** Derived display status: overdue / due-soon (within lead time) / scheduled — or completed/paused. */
export function displayStatus(a: { status: string; nextDueDate: string | null; leadTimeDays: number | null }): "overdue" | "due-soon" | "scheduled" | "completed" | "paused" {
  if (a.status === "completed") return "completed";
  if (a.status === "paused") return "paused";
  if (!a.nextDueDate) return "scheduled";
  const due = a.nextDueDate.slice(0, 10), t = today();
  if (due < t) return "overdue";
  const lead = new Date(Date.now() + (a.leadTimeDays ?? 7) * 86400000).toISOString().slice(0, 10);
  return due <= lead ? "due-soon" : "scheduled";
}

export interface Activity {
  activityId: number; name: string; category: string | null; description: string | null; ownerName: string | null;
  assigneeUserId: number | null; framework: string | null; controlRef: string | null; cadence: string; intervalDays: number | null;
  nextDueDate: string | null; leadTimeDays: number | null; lastCompletedDate: string | null; status: string;
  display: ReturnType<typeof displayStatus>; log: { logId: number; dueDate: string | null; completedDate: string | null; completedBy: string | null; notes: string | null; evidenceId: number | null }[];
}

function row2a(r: Record<string, unknown>, log: Activity["log"]): Activity {
  const a = {
    activityId: Number(r.ActivityID), name: String(r.Name || ""), category: (r.Category as string) || null,
    description: (r.Description as string) || null, ownerName: (r.OwnerName as string) || null,
    assigneeUserId: r.AssigneeUserID != null ? Number(r.AssigneeUserID) : null, framework: (r.Framework as string) || null,
    controlRef: (r.ControlRef as string) || null, cadence: String(r.Cadence || "once"), intervalDays: r.IntervalDays != null ? Number(r.IntervalDays) : null,
    nextDueDate: (r.NextDueDate as string) || null, leadTimeDays: r.LeadTimeDays != null ? Number(r.LeadTimeDays) : 7,
    lastCompletedDate: (r.LastCompletedDate as string) || null, status: String(r.Status || "scheduled"),
  };
  return { ...a, display: displayStatus(a), log };
}

/** The cockpit payload: activities + KPIs + a monthly calendar of upcoming due dates. */
export function complianceCalendar(tenant: number | null): {
  activities: Activity[];
  summary: { total: number; overdue: number; dueSoon: number; scheduled: number; completed: number; paused: number; due30: number };
  calendar: { date: string; activityId: number; name: string; display: string }[];
  cadences: readonly string[]; categories: readonly string[];
} {
  ensureComplianceActivities();
  const db = getDb("XCOMPLIANCE");
  const rows = db.prepare(`SELECT * FROM COMPLIANCEACTIVITY WHERE ${tw(tenant)} ORDER BY COALESCE(NextDueDate,'9999'), ActivityID`).all(...tp(tenant)) as Record<string, unknown>[];
  const activities = rows.map((r) => {
    const log = (db.prepare("SELECT LogID, DueDate, CompletedDate, CompletedBy, Notes, EvidenceID FROM COMPLIANCEACTIVITYLOG WHERE ActivityID = ? ORDER BY LogID DESC LIMIT 20").all(Number(r.ActivityID)) as Record<string, unknown>[])
      .map((l) => ({ logId: Number(l.LogID), dueDate: (l.DueDate as string) || null, completedDate: (l.CompletedDate as string) || null, completedBy: (l.CompletedBy as string) || null, notes: (l.Notes as string) || null, evidenceId: l.EvidenceID != null ? Number(l.EvidenceID) : null }));
    return row2a(r, log);
  });
  const d30 = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const summary = {
    total: activities.length,
    overdue: activities.filter((a) => a.display === "overdue").length,
    dueSoon: activities.filter((a) => a.display === "due-soon").length,
    scheduled: activities.filter((a) => a.display === "scheduled").length,
    completed: activities.filter((a) => a.display === "completed").length,
    paused: activities.filter((a) => a.display === "paused").length,
    due30: activities.filter((a) => a.nextDueDate && a.nextDueDate.slice(0, 10) <= d30 && a.display !== "completed" && a.display !== "paused").length,
  };
  const calendar = activities.filter((a) => a.nextDueDate && a.status === "scheduled")
    .map((a) => ({ date: a.nextDueDate!.slice(0, 10), activityId: a.activityId, name: a.name, display: a.display }));
  return { activities, summary, calendar, cadences: CADENCES, categories: ACTIVITY_CATEGORIES };
}

export function getActivity(tenant: number | null, id: number): Activity | null {
  ensureComplianceActivities();
  const db = getDb("XCOMPLIANCE");
  const r = db.prepare(`SELECT * FROM COMPLIANCEACTIVITY WHERE ActivityID = ? AND ${tw(tenant)}`).get(id, ...tp(tenant)) as Record<string, unknown> | undefined;
  if (!r) return null;
  const log = (db.prepare("SELECT LogID, DueDate, CompletedDate, CompletedBy, Notes, EvidenceID FROM COMPLIANCEACTIVITYLOG WHERE ActivityID = ? ORDER BY LogID DESC LIMIT 20").all(id) as Record<string, unknown>[])
    .map((l) => ({ logId: Number(l.LogID), dueDate: (l.DueDate as string) || null, completedDate: (l.CompletedDate as string) || null, completedBy: (l.CompletedBy as string) || null, notes: (l.Notes as string) || null, evidenceId: l.EvidenceID != null ? Number(l.EvidenceID) : null }));
  return row2a(r, log);
}

export function createActivity(tenant: number | null, p: Record<string, unknown>): Activity {
  ensureComplianceActivities();
  if (!p.name || !String(p.name).trim()) throw new Error("name required");
  const cadence = CADENCES.includes(String(p.cadence) as (typeof CADENCES)[number]) ? String(p.cadence) : "annual";
  const db = getDb("XCOMPLIANCE");
  const r = db.prepare(`INSERT INTO COMPLIANCEACTIVITY (TenantID, Name, Category, Description, OwnerName, AssigneeUserID, Framework, ControlRef,
      Cadence, IntervalDays, NextDueDate, LeadTimeDays, Status, CreatedDate, UpdatedDate)
    VALUES (@tenant,@name,@cat,@desc,@owner,@assignee,@framework,@control,@cadence,@interval,@due,@lead,'scheduled',@now,@now)`).run({
    tenant: tenant ?? null, name: String(p.name).slice(0, 300), cat: s(p.category, 60), desc: s(p.description), owner: s(p.ownerName, 160),
    assignee: numOrNull(p.assigneeUserId), framework: s(p.framework, 160), control: s(p.controlRef, 160), cadence,
    interval: numOrNull(p.intervalDays), due: s(p.nextDueDate, 10), lead: numOrNull(p.leadTimeDays) ?? 7, now: now(),
  });
  return getActivity(tenant, Number(r.lastInsertRowid))!;
}

export function updateActivity(tenant: number | null, id: number, patch: Record<string, unknown>): Activity {
  ensureComplianceActivities();
  const map: Record<string, string> = { name: "Name", category: "Category", description: "Description", ownerName: "OwnerName",
    assigneeUserId: "AssigneeUserID", framework: "Framework", controlRef: "ControlRef", cadence: "Cadence", intervalDays: "IntervalDays",
    nextDueDate: "NextDueDate", leadTimeDays: "LeadTimeDays", status: "Status" };
  const sets: string[] = []; const args: Record<string, unknown> = { id, now: now() };
  for (const [k, col] of Object.entries(map)) {
    if (k in patch) {
      sets.push(`${col} = @${k}`);
      args[k] = ["assigneeUserId", "intervalDays", "leadTimeDays"].includes(k) ? numOrNull(patch[k]) : s(patch[k], k === "description" ? 4000 : 300);
    }
  }
  // Changing the due date clears the dedupe marker so a fresh reminder can fire.
  if ("nextDueDate" in patch) sets.push("ReminderSentFor = NULL");
  if (!sets.length) return getActivity(tenant, id)!;
  getDb("XCOMPLIANCE").prepare(`UPDATE COMPLIANCEACTIVITY SET ${sets.join(", ")}, UpdatedDate = @now WHERE ActivityID = @id AND ${tw(tenant)}`).run(args, ...tp(tenant));
  return getActivity(tenant, id)!;
}

export function deleteActivity(tenant: number | null, id: number): void {
  ensureComplianceActivities();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM COMPLIANCEACTIVITYLOG WHERE ActivityID = ?").run(id);
  db.prepare(`DELETE FROM COMPLIANCEACTIVITY WHERE ActivityID = ? AND ${tw(tenant)}`).run(id, ...tp(tenant));
}

/** Mark an occurrence complete: log it, then advance the next due date by the cadence (or close a one-off). */
export function completeActivity(tenant: number | null, id: number, p: { completedDate?: string; completedBy?: string; notes?: string; evidenceId?: number }): Activity {
  ensureComplianceActivities();
  const a = getActivity(tenant, id);
  if (!a) throw new Error("unknown activity");
  const db = getDb("XCOMPLIANCE");
  const done = (p.completedDate && p.completedDate.slice(0, 10)) || today();
  db.prepare("INSERT INTO COMPLIANCEACTIVITYLOG (ActivityID, TenantID, DueDate, CompletedDate, CompletedBy, Notes, EvidenceID, CreatedDate) VALUES (?,?,?,?,?,?,?,?)")
    .run(id, tenant ?? null, a.nextDueDate, done, s(p.completedBy, 160), s(p.notes), p.evidenceId ?? null, now());
  const next = a.nextDueDate ? advanceDue(a.nextDueDate.slice(0, 10), a.cadence, a.intervalDays) : advanceDue(done, a.cadence, a.intervalDays);
  db.prepare(`UPDATE COMPLIANCEACTIVITY SET LastCompletedDate = ?, NextDueDate = ?, Status = ?, ReminderSentFor = NULL, UpdatedDate = ? WHERE ActivityID = ?`)
    .run(done, next, next ? "scheduled" : "completed", now(), id);
  return getActivity(tenant, id)!;
}

/**
 * Reminder engine — called by a daily tick. For every scheduled activity whose due date is within its
 * lead time (or already overdue) and not yet reminded for that date, notify the assignee (in-app + the
 * compliance.audit_due event) and record the dedupe marker. Best-effort; never throws. Cross-tenant.
 */
export function runComplianceReminders(): { checked: number; reminded: number } {
  ensureComplianceActivities();
  const db = getDb("XCOMPLIANCE");
  let checked = 0, reminded = 0;
  let dispatchEvent: undefined | ((k: string, o: Record<string, unknown>) => unknown);
  try { dispatchEvent = require("./notifrules").dispatchEvent; } catch { /* optional */ }
  const rows = db.prepare("SELECT ActivityID, TenantID, Name, Category, AssigneeUserID, NextDueDate, LeadTimeDays, ReminderSentFor FROM COMPLIANCEACTIVITY WHERE Status = 'scheduled' AND NextDueDate IS NOT NULL").all() as Record<string, unknown>[];
  const t = today();
  for (const r of rows) {
    checked++;
    const due = String(r.NextDueDate).slice(0, 10);
    const lead = new Date(Date.now() + Number(r.LeadTimeDays ?? 7) * 86400000).toISOString().slice(0, 10);
    if (due > lead) continue;                       // not within the reminder window yet
    if (String(r.ReminderSentFor || "") === due) continue; // already reminded for this due date
    const overdue = due < t;
    const title = `${overdue ? "Overdue" : "Upcoming"} compliance activity: ${String(r.Name)}`;
    const message = `${String(r.Category || "Activity")} ${overdue ? "was due" : "is due"} ${due}.`;
    const tenant = r.TenantID != null ? Number(r.TenantID) : null;
    try {
      if (r.AssigneeUserID != null) createNotification({ userId: Number(r.AssigneeUserID), title, message, level: overdue ? "warning" : "info", link: "/compliance-calendar", source: "compliance.activity_due", tenantId: tenant });
      if (dispatchEvent) try { dispatchEvent("compliance.audit_due", { tenant, level: overdue ? "warning" : "info", title, message, link: "/compliance-calendar", dedupeByLink: false }); } catch { /* */ }
      db.prepare("UPDATE COMPLIANCEACTIVITY SET ReminderSentFor = ? WHERE ActivityID = ?").run(due, Number(r.ActivityID));
      reminded++;
    } catch { /* best-effort per row */ }
  }
  return { checked, reminded };
}
