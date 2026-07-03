/**
 * auditplanning.ts — Audit planning / audit programme management (XCOMPLIANCE).
 *
 * A planning layer above the AUDIT table: an AUDITPLAN is an audit programme (typically annual),
 * holding a set of planned audits (AUDITPLANITEM) — each with a type, framework, scope, lead
 * auditor, planned window, recurrence frequency, priority and status. A planned item can be
 * "launched" into a real AUDIT (reusing compliance.createAudit) which links it back; completing a
 * recurring item can auto-schedule the next occurrence. Feeds the /audit-planning cockpit
 * (KPIs + a monthly calendar of the programme + item CRUD).
 */
import { getDb } from "./db";
import { createAudit } from "./compliance";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);
const numOrNull = (v: unknown): number | null => (v != null && String(v).trim() !== "" && !Number.isNaN(Number(v)) ? Number(v) : null);
const strOrNull = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);

export const AUDIT_TYPES = ["Internal", "External", "Certification", "Surveillance", "Supplier", "Self-assessment"] as const;
export const FREQUENCIES = ["one-off", "monthly", "quarterly", "biannual", "annual", "triennial"] as const;
export const ITEM_STATUSES = ["planned", "scheduled", "in-progress", "completed", "deferred", "cancelled"] as const;
export const PLAN_STATUSES = ["draft", "approved", "active", "closed"] as const;

const cols = (table: string): Set<string> => {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
};

export function ensureAuditPlanTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS AUDITPLAN(
      PlanID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, Name TEXT NOT NULL, Year INTEGER, Scope TEXT, Owner TEXT, Framework TEXT,
      Status TEXT DEFAULT 'draft', ApprovedBy TEXT, ApprovedDate TEXT, CreatedBy TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AUDITPLANITEM(
      ItemID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, PlanID INTEGER, Title TEXT NOT NULL, AuditType TEXT, Framework TEXT, Scope TEXT,
      LeadAuditorPersonID INTEGER, AuditorName TEXT, PlannedStartDate TEXT, PlannedEndDate TEXT,
      Frequency TEXT DEFAULT 'one-off', Priority TEXT, Status TEXT DEFAULT 'planned',
      AuditID INTEGER, Notes TEXT, SortOrder INTEGER, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_auditplan_tn ON AUDITPLAN(TenantID);
    CREATE INDEX IF NOT EXISTS ix_auditplanitem_plan ON AUDITPLANITEM(PlanID);
  `);
}

const tw = (tenant: number | null, alias = ""): string => (tenant != null ? `${alias ? alias + "." : ""}TenantID = ${tenant}` : "1=1");
const daysUntil = (d: string | null): number | null => { if (!d) return null; const t = Date.parse(String(d)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000); };

function personNames(): Map<number, string> {
  const m = new Map<number, string>();
  try { for (const p of getDb("XORCISM").prepare("SELECT PersonID, FullName FROM PERSON").all() as { PersonID: number; FullName: string }[]) m.set(Number(p.PersonID), p.FullName); } catch { /* optional */ }
  return m;
}

/** The whole audit-planning cockpit payload: plans, items (resolved), KPIs, a monthly calendar. */
export function getAuditPlanning(tenant: number | null): Record<string, unknown> {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  const plans = cc.prepare(`SELECT * FROM AUDITPLAN WHERE ${tw(tenant)} ORDER BY Year DESC, PlanID DESC`).all() as Record<string, unknown>[];
  const items = cc.prepare(`SELECT * FROM AUDITPLANITEM WHERE ${tw(tenant)} ORDER BY COALESCE(PlannedStartDate,'9999'), COALESCE(SortOrder, ItemID)`).all() as Record<string, unknown>[];
  const names = personNames();
  // Resolve linked-audit name/status + lead auditor.
  const auditIds = items.map((i) => Number(i.AuditID)).filter(Boolean);
  const auditById = new Map<number, { name: string; status: string }>();
  if (auditIds.length && cols("AUDIT").size) {
    const ph = auditIds.slice(0, 500).map(() => "?").join(",");
    for (const a of cc.prepare(`SELECT AuditID, AuditName, AuditStatus FROM AUDIT WHERE AuditID IN (${ph})`).all(...auditIds.slice(0, 500)) as { AuditID: number; AuditName: string; AuditStatus: string }[])
      auditById.set(Number(a.AuditID), { name: String(a.AuditName ?? ""), status: String(a.AuditStatus ?? "") });
  }
  const planName = new Map<number, string>(plans.map((p) => [Number(p.PlanID), String(p.Name ?? "")]));
  for (const it of items) {
    if (it.LeadAuditorPersonID != null) it.LeadAuditorName = names.get(Number(it.LeadAuditorPersonID)) ?? `#${it.LeadAuditorPersonID}`;
    if (it.AuditID != null) { const a = auditById.get(Number(it.AuditID)); it.LinkedAuditName = a?.name; it.LinkedAuditStatus = a?.status; }
    it.PlanName = planName.get(Number(it.PlanID)) ?? "";
    const du = daysUntil(it.PlannedStartDate as string);
    const active = it.Status === "planned" || it.Status === "scheduled";
    it.overdue = active && du != null && du < 0;
    it.upcoming = active && du != null && du >= 0 && du <= 30;
  }

  const active = items.filter((i) => i.Status !== "cancelled");
  const byMonth: Record<string, { total: number; completed: number; overdue: number }> = {};
  for (const i of active) {
    const ym = (i.PlannedStartDate as string || "").slice(0, 7) || "unscheduled";
    const b = byMonth[ym] ?? { total: 0, completed: 0, overdue: 0 };
    b.total++; if (i.Status === "completed") b.completed++; if (i.overdue) b.overdue++;
    byMonth[ym] = b;
  }
  const byType: Record<string, number> = {};
  for (const i of active) { const k = String(i.AuditType ?? "—"); byType[k] = (byType[k] || 0) + 1; }

  const kpis = {
    plans: plans.length,
    planned: active.length,
    upcoming: active.filter((i) => i.upcoming).length,
    overdue: active.filter((i) => i.overdue).length,
    inProgress: active.filter((i) => i.Status === "in-progress").length,
    completed: active.filter((i) => i.Status === "completed").length,
    executed: active.filter((i) => i.AuditID != null).length,
    completionPct: active.length ? Math.round((active.filter((i) => i.Status === "completed").length / active.length) * 100) : null,
  };
  return { plans, items, kpis, byMonth, byType,
    options: { auditTypes: AUDIT_TYPES, frequencies: FREQUENCIES, itemStatuses: ITEM_STATUSES, planStatuses: PLAN_STATUSES } };
}

// ── Plan CRUD ─────────────────────────────────────────────────────────────────
export function createPlan(tenant: number | null, p: { name: string; year?: number | null; scope?: string; owner?: string; framework?: string; status?: string; createdBy?: string }): { planId: number } {
  ensureAuditPlanTables();
  const name = String(p.name || "").trim(); if (!name) throw new Error("plan name required");
  const status = PLAN_STATUSES.includes(p.status as never) ? p.status! : "draft";
  const r = getDb("XCOMPLIANCE").prepare(`INSERT INTO AUDITPLAN (TenantID, Name, Year, Scope, Owner, Framework, Status, CreatedBy, CreatedDate, UpdatedDate)
      VALUES (@tn,@name,@year,@scope,@owner,@fw,@st,@cb,@now,@now)`)
    .run({ tn: tenant, name: name.slice(0, 300), year: numOrNull(p.year) ?? new Date().getFullYear(), scope: strOrNull(p.scope), owner: strOrNull(p.owner, 200), fw: strOrNull(p.framework, 200), st: status, cb: strOrNull(p.createdBy, 120), now: now() });
  return { planId: Number(r.lastInsertRowid) };
}
const PLAN_FIELDS: Record<string, string> = { name: "Name", year: "Year", scope: "Scope", owner: "Owner", framework: "Framework", status: "Status" };
export function updatePlan(tenant: number | null, id: number, patch: Record<string, unknown>): { ok: boolean } {
  ensureAuditPlanTables();
  const sets: string[] = []; const args: Record<string, unknown> = { id, now: now() };
  for (const [k, col] of Object.entries(PLAN_FIELDS)) if (k in patch) { sets.push(`${col} = @${k}`); args[k] = k === "year" ? numOrNull(patch[k]) : (k === "name" ? String(patch[k]).slice(0, 300) : strOrNull(patch[k])); }
  if ("approve" in patch && patch.approve) { sets.push("ApprovedBy = @ab", "ApprovedDate = @ad", "Status = 'approved'"); args.ab = strOrNull(patch.approver, 120) || "approved"; args.ad = now(); }
  if (!sets.length) return { ok: false };
  const r = getDb("XCOMPLIANCE").prepare(`UPDATE AUDITPLAN SET ${sets.join(", ")}, UpdatedDate = @now WHERE PlanID = @id AND ${tw(tenant)}`).run(args);
  return { ok: r.changes > 0 };
}
export function deletePlan(tenant: number | null, id: number): { ok: true } {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  cc.prepare(`DELETE FROM AUDITPLANITEM WHERE PlanID = ? AND ${tw(tenant)}`).run(id);
  cc.prepare(`DELETE FROM AUDITPLAN WHERE PlanID = ? AND ${tw(tenant)}`).run(id);
  return { ok: true };
}

// ── Item CRUD ─────────────────────────────────────────────────────────────────
export function createItem(tenant: number | null, planId: number, p: Record<string, unknown>): { itemId: number } {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  const title = String(p.title || "").trim(); if (!title) throw new Error("item title required");
  const nextSort = (cc.prepare(`SELECT COALESCE(MAX(SortOrder),0)+1 s FROM AUDITPLANITEM WHERE PlanID = ?`).get(planId) as { s: number }).s;
  const r = cc.prepare(`INSERT INTO AUDITPLANITEM (TenantID, PlanID, Title, AuditType, Framework, Scope, LeadAuditorPersonID, AuditorName,
      PlannedStartDate, PlannedEndDate, Frequency, Priority, Status, Notes, SortOrder, CreatedDate, UpdatedDate)
      VALUES (@tn,@plan,@title,@type,@fw,@scope,@lead,@auditor,@ps,@pe,@freq,@prio,@st,@notes,@sort,@now,@now)`)
    .run({ tn: tenant, plan: planId, title: title.slice(0, 300),
      type: AUDIT_TYPES.includes(p.auditType as never) ? p.auditType : strOrNull(p.auditType, 80),
      fw: strOrNull(p.framework, 200), scope: strOrNull(p.scope, 2000),
      lead: numOrNull(p.leadAuditorPersonId), auditor: strOrNull(p.auditorName, 200),
      ps: strOrNull(p.plannedStartDate, 40), pe: strOrNull(p.plannedEndDate, 40),
      freq: FREQUENCIES.includes(p.frequency as never) ? p.frequency : "one-off",
      prio: strOrNull(p.priority, 40), st: ITEM_STATUSES.includes(p.status as never) ? p.status : "planned",
      notes: strOrNull(p.notes), sort: nextSort, now: now() });
  return { itemId: Number(r.lastInsertRowid) };
}
const ITEM_FIELDS: Record<string, string> = {
  title: "Title", auditType: "AuditType", framework: "Framework", scope: "Scope", leadAuditorPersonId: "LeadAuditorPersonID",
  auditorName: "AuditorName", plannedStartDate: "PlannedStartDate", plannedEndDate: "PlannedEndDate", frequency: "Frequency",
  priority: "Priority", status: "Status", notes: "Notes",
};
export function updateItem(tenant: number | null, id: number, patch: Record<string, unknown>): { ok: boolean; scheduledNext?: number } {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  const before = cc.prepare(`SELECT * FROM AUDITPLANITEM WHERE ItemID = ? AND ${tw(tenant)}`).get(id) as Record<string, unknown> | undefined;
  if (!before) return { ok: false };
  const sets: string[] = []; const args: Record<string, unknown> = { id, now: now() };
  for (const [k, col] of Object.entries(ITEM_FIELDS)) if (k in patch) {
    sets.push(`${col} = @${k}`);
    args[k] = k === "leadAuditorPersonId" ? numOrNull(patch[k]) : (k === "title" ? String(patch[k]).slice(0, 300) : strOrNull(patch[k]));
  }
  if (!sets.length) return { ok: false };
  cc.prepare(`UPDATE AUDITPLANITEM SET ${sets.join(", ")}, UpdatedDate = @now WHERE ItemID = @id`).run(args);
  // Recurrence: newly completed + recurring → schedule the next occurrence.
  let scheduledNext: number | undefined;
  if (patch.status === "completed" && before.Status !== "completed" && before.Frequency && before.Frequency !== "one-off") {
    scheduledNext = scheduleNext(tenant, before);
  }
  return { ok: true, scheduledNext };
}
export function deleteItem(tenant: number | null, id: number): { ok: true } {
  ensureAuditPlanTables();
  getDb("XCOMPLIANCE").prepare(`DELETE FROM AUDITPLANITEM WHERE ItemID = ? AND ${tw(tenant)}`).run(id);
  return { ok: true };
}

const FREQ_MONTHS: Record<string, number> = { monthly: 1, quarterly: 3, biannual: 6, annual: 12, triennial: 36 };
function addMonths(dateStr: string | null, months: number): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(dateStr || "")); if (!m) return null;
  // Pure calendar arithmetic on Y/M/D (no Date object → no timezone drift), clamping the day.
  let y = Number(m[1]); let mo = Number(m[2]) - 1 + months; const d = Number(m[3]);
  y += Math.floor(mo / 12); mo = ((mo % 12) + 12) % 12;
  const lastDay = new Date(Date.UTC(y, mo + 1, 0)).getUTCDate();
  const day = Math.min(d, lastDay);
  return `${y}-${String(mo + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}
/** Clone a completed recurring item forward by its frequency interval (status planned). */
function scheduleNext(tenant: number | null, item: Record<string, unknown>): number {
  const months = FREQ_MONTHS[String(item.Frequency)] ?? 12;
  const { itemId } = createItem(tenant, Number(item.PlanID), {
    title: String(item.Title), auditType: item.AuditType, framework: item.Framework, scope: item.Scope,
    leadAuditorPersonId: item.LeadAuditorPersonID, auditorName: item.AuditorName,
    plannedStartDate: addMonths(item.PlannedStartDate as string, months), plannedEndDate: addMonths(item.PlannedEndDate as string, months),
    frequency: item.Frequency, priority: item.Priority, status: "planned", notes: item.Notes,
  });
  return itemId;
}

/** Launch a planned item into a real AUDIT (compliance.createAudit) and link it back. */
export function launchItem(tenant: number | null, id: number, actor: string): { ok: boolean; auditId?: number } {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  const it = cc.prepare(`SELECT * FROM AUDITPLANITEM WHERE ItemID = ? AND ${tw(tenant)}`).get(id) as Record<string, unknown> | undefined;
  if (!it) return { ok: false };
  if (it.AuditID != null) return { ok: true, auditId: Number(it.AuditID) }; // already launched
  const names = personNames();
  const auditor = String(it.AuditorName ?? "").trim() || (it.LeadAuditorPersonID != null ? names.get(Number(it.LeadAuditorPersonID)) ?? "" : "") || actor;
  const { id: auditId } = createAudit({
    name: String(it.Title), type: String(it.AuditType ?? "") || undefined, category: String(it.Framework ?? "") || undefined,
    status: "In progress", auditor, scope: String(it.Scope ?? "") || undefined,
    description: `Launched from audit plan item #${id}${it.Notes ? ` — ${String(it.Notes).slice(0, 500)}` : ""}`,
    date: String(it.PlannedStartDate ?? "") || undefined,
  }, tenant);
  cc.prepare(`UPDATE AUDITPLANITEM SET AuditID = ?, Status = 'in-progress', UpdatedDate = ? WHERE ItemID = ?`).run(auditId, now(), id);
  return { ok: true, auditId };
}

// ── Demo seed ─────────────────────────────────────────────────────────────────
export function seedAuditPlanDemo(tenant: number): { created: number } {
  ensureAuditPlanTables();
  const cc = getDb("XCOMPLIANCE");
  if ((cc.prepare(`SELECT COUNT(*) c FROM AUDITPLAN WHERE TenantID = ?`).get(tenant) as { c: number }).c > 0) return { created: 0 };
  const year = new Date().getFullYear();
  const { planId } = createPlan(tenant, { name: `Annual audit programme ${year}`, year, framework: "ISO 27001", owner: "CISO", status: "active", createdBy: "seed" });
  const iso = (m: number, d = 1) => `${year}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  const seedItems: Record<string, unknown>[] = [
    { title: "ISMS internal audit — Access control (A.5-A.8)", auditType: "Internal", framework: "ISO 27001", plannedStartDate: iso(2), plannedEndDate: iso(2, 14), frequency: "annual", priority: "High", status: "completed" },
    { title: "Supplier security review — key vendors", auditType: "Supplier", framework: "ISO 27001 A.5.19", plannedStartDate: iso(4), plannedEndDate: iso(4, 21), frequency: "annual", priority: "Medium", status: "planned" },
    { title: "ISO 27001 surveillance audit (certification body)", auditType: "Surveillance", framework: "ISO 27001", plannedStartDate: iso(9), plannedEndDate: iso(9, 3), frequency: "annual", priority: "Critical", status: "scheduled" },
    { title: "SOC 2 Type II readiness assessment", auditType: "External", framework: "SOC 2", plannedStartDate: iso(6), plannedEndDate: iso(6, 30), frequency: "annual", priority: "High", status: "planned" },
    { title: "Business continuity / DR exercise review", auditType: "Internal", framework: "ISO 22301", plannedStartDate: iso(11), plannedEndDate: iso(11, 15), frequency: "annual", priority: "Medium", status: "planned" },
  ];
  for (const it of seedItems) createItem(tenant, planId, it);
  return { created: 1 };
}
