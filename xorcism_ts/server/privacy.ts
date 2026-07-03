/**
 * privacy.ts — GDPR / Data Privacy Officer (DPO) cockpit (/privacy).
 *
 * Operationalizes the DPO's core GDPR obligations over four registers (XCOMPLIANCE):
 *   - PRIVACYPROCESSING — Records of Processing Activities (RoPA, Art 30): purpose, legal basis,
 *     data categories/subjects, recipients, retention, cross-border transfers, security measures.
 *   - DSAR              — Data Subject Access Requests (Art 12/15-22) with the 1-month response clock.
 *   - DPIA              — Data Protection Impact Assessments (Art 35) for high-risk processing.
 *   - PRIVACYBREACH     — personal-data breach register (Art 33/34) with the 72-hour notification clock.
 *
 * The dashboard scores DPO posture and surfaces the worklist a DPO acts on first (overdue DSARs,
 * processing without a legal basis, high-risk processing missing an approved DPIA, breaches past 72h
 * not yet notified). Read-only aggregation + a couple of create paths; all per-tenant.
 */
import { getDb } from "./db";
import { randomUUID } from "crypto";

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const today = (): string => new Date().toISOString().slice(0, 10);
const CLOSED_RX = /complet|closed|done|resolv|fulfil|ferm|clos[eé]/i;

const LEGAL_BASES = ["Consent", "Contract", "Legal obligation", "Vital interests", "Public task", "Legitimate interests"];
const DSAR_TYPES = ["Access", "Rectification", "Erasure", "Restriction", "Portability", "Objection"];
const PROCESSOR_STATUS = ["Active", "Under review", "Terminated"];
const ACTION_STATUS = ["Planned", "Applied", "Not applicable"];
const ACTION_DONE_RX = /appli(qu)?|done|complet|not.?applic|non.?applic/i;
// CNIL / WP29 (WP248) DPIA-trigger criteria — ≥2 met ⇒ a DPIA is mandatory (Art 35).
const DPIA_TRIGGERS: { code: string; label: string }[] = [
  { code: "scoring", label: "Evaluation or scoring (incl. profiling)" },
  { code: "auto-decision", label: "Automated decision with legal / significant effect" },
  { code: "monitoring", label: "Systematic monitoring" },
  { code: "sensitive", label: "Sensitive data or data of a highly personal nature" },
  { code: "large-scale", label: "Large-scale processing" },
  { code: "matching", label: "Matching or combining datasets" },
  { code: "vulnerable", label: "Vulnerable data subjects" },
  { code: "innovative", label: "Innovative use or new technology" },
  { code: "blocking", label: "Prevents exercising a right or a contract" },
];

/** Creates the four privacy registers in XCOMPLIANCE (idempotent). */
export function ensurePrivacyTables(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS PRIVACYPROCESSING (
      ProcessingID INTEGER PRIMARY KEY, ProcessingGUID TEXT, Name TEXT, Purpose TEXT,
      LegalBasis TEXT, DataCategories TEXT, SpecialCategories INTEGER DEFAULT 0, DataSubjects TEXT,
      Recipients TEXT, RetentionPeriod TEXT, CrossBorderTransfer INTEGER DEFAULT 0, TransferSafeguard TEXT,
      SecurityMeasures TEXT, Controller TEXT, ProcessorName TEXT, RiskLevel TEXT, Status TEXT,
      OwnerPersonID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS DSAR (
      RequestID INTEGER PRIMARY KEY, RequestGUID TEXT, SubjectName TEXT, SubjectEmail TEXT,
      RequestType TEXT, ReceivedDate TEXT, DueDate TEXT, Status TEXT, Channel TEXT,
      AssignedTo TEXT, Notes TEXT, CompletedDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS DPIA (
      DpiaID INTEGER PRIMARY KEY, DpiaGUID TEXT, Name TEXT, ProcessingID INTEGER, RiskLevel TEXT,
      NecessityAssessment TEXT, Risks TEXT, Mitigations TEXT, ResidualRisk TEXT, Status TEXT,
      ConsultedDPO INTEGER DEFAULT 0, ReviewDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS PRIVACYBREACH (
      BreachID INTEGER PRIMARY KEY, BreachGUID TEXT, Title TEXT, Description TEXT, DetectedDate TEXT,
      ContainedDate TEXT, AffectedSubjects INTEGER, DataCategories TEXT, Severity TEXT, RiskToSubjects TEXT,
      NotifiedAuthority INTEGER DEFAULT 0, AuthorityNotifiedDate TEXT, NotifiedSubjects INTEGER DEFAULT 0,
      SubjectsNotifiedDate TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    -- Register of processors / sub-processors (GDPR Art 28) — the Art 28 due-diligence checklist.
    CREATE TABLE IF NOT EXISTS PRIVACYPROCESSOR (
      ProcessorID INTEGER PRIMARY KEY, ProcessorGUID TEXT, Name TEXT, Service TEXT, Referent TEXT,
      ClausesVerified INTEGER DEFAULT 0, SecurityAdopted INTEGER DEFAULT 0, MaintainsRoPA INTEGER DEFAULT 0,
      TransfersOutsideEU INTEGER DEFAULT 0, DpoAppointed INTEGER DEFAULT 0, Location TEXT,
      LinkedProcessing TEXT, Status TEXT, Notes TEXT, CreatedDate TEXT, TenantID INTEGER);
    -- Protection actions / action plan — cross-cutting remediation, optionally linked to a register row.
    CREATE TABLE IF NOT EXISTS PRIVACYACTION (
      ActionID INTEGER PRIMARY KEY, ActionGUID TEXT, Name TEXT, Description TEXT, Owner TEXT,
      Priority INTEGER DEFAULT 2, Cost TEXT, Effort TEXT, Status TEXT, DueDate TEXT,
      LinkKind TEXT, LinkRef TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_dsar_tenant ON DSAR(TenantID);
    CREATE INDEX IF NOT EXISTS ix_privproc_tenant ON PRIVACYPROCESSING(TenantID);
    CREATE INDEX IF NOT EXISTS ix_privprocessor_tenant ON PRIVACYPROCESSOR(TenantID);
    CREATE INDEX IF NOT EXISTS ix_privaction_tenant ON PRIVACYACTION(TenantID);
  `);
  // CNIL DPIA-trigger criteria (CSV of DPIA_TRIGGERS codes) on existing RoPA rows.
  try { db.exec(`ALTER TABLE PRIVACYPROCESSING ADD COLUMN DpiaTriggers TEXT`); } catch { /* already present */ }
}

function nextId(table: string, pk: string): number {
  return (getDb("XCOMPLIANCE").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n;
}
const tw = (tenant: number | null): string => (tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "");
const daysBetween = (a: string, b: string): number | null => {
  const ta = Date.parse(a), tb = Date.parse(b); if (!Number.isFinite(ta) || !Number.isFinite(tb)) return null;
  return Math.round((tb - ta) / 86400000);
};

export interface PrivacyWorkItem { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; ref: string }

/** The DPO dashboard: RoPA + DSAR + DPIA + breach posture, plus the prioritized worklist. */
export function privacyDashboard(tenant: number | null): any {
  ensurePrivacyTables();
  const db = getDb("XCOMPLIANCE");
  const t = today();
  const worklist: PrivacyWorkItem[] = [];

  // — RoPA —
  const proc = db.prepare(`SELECT ProcessingID, Name, Purpose, LegalBasis, SpecialCategories, CrossBorderTransfer, TransferSafeguard, RiskLevel, Status, DpiaTriggers FROM PRIVACYPROCESSING ${tw(tenant)} ORDER BY Name`).all() as any[];
  const dpias = db.prepare(`SELECT DpiaID, Name, ProcessingID, RiskLevel, Status, ConsultedDPO FROM DPIA ${tw(tenant)}`).all() as any[];
  const dpiaByProc = new Map<number, any>(); for (const d of dpias) if (d.ProcessingID != null) dpiaByProc.set(num(d.ProcessingID), d);
  const procRows = proc.map((p) => {
    const legal = String(p.LegalBasis ?? "").trim();
    const triggers = String(p.DpiaTriggers ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    // CNIL rule: ≥2 WP248 criteria ⇒ DPIA mandatory; special-category or high risk also require one.
    const high = /high|élev/i.test(String(p.RiskLevel ?? "")) || num(p.SpecialCategories) === 1 || triggers.length >= 2;
    const dpia = dpiaByProc.get(num(p.ProcessingID));
    const dpiaApproved = dpia && /approv/i.test(String(dpia.Status ?? ""));
    if (!legal) worklist.push({ kind: "no-legal-basis", label: `Processing "${p.Name}" has no documented legal basis (GDPR Art 6)`, severity: "High", ref: `ProcessingID ${p.ProcessingID}` });
    if (high && !dpiaApproved) worklist.push({ kind: "missing-dpia", label: `High-risk processing "${p.Name}" lacks an approved DPIA${triggers.length >= 2 ? ` (${triggers.length} CNIL criteria met)` : ""} (Art 35)`, severity: "High", ref: `ProcessingID ${p.ProcessingID}` });
    if (num(p.CrossBorderTransfer) === 1 && !String(p.TransferSafeguard ?? "").trim()) worklist.push({ kind: "transfer", label: `Cross-border transfer for "${p.Name}" has no documented safeguard (Ch. V)`, severity: "Medium", ref: `ProcessingID ${p.ProcessingID}` });
    return { id: num(p.ProcessingID), name: String(p.Name ?? ""), purpose: String(p.Purpose ?? ""), legalBasis: legal, special: num(p.SpecialCategories) === 1, crossBorder: num(p.CrossBorderTransfer) === 1, riskLevel: String(p.RiskLevel ?? ""), hasDpia: !!dpia, dpiaApproved: !!dpiaApproved, dpiaRequired: high, triggers, triggerCount: triggers.length, status: String(p.Status ?? "") };
  });

  // — DSAR (1-month clock) —
  const dsarRaw = db.prepare(`SELECT RequestID, SubjectName, RequestType, ReceivedDate, DueDate, Status, AssignedTo, CompletedDate FROM DSAR ${tw(tenant)} ORDER BY DueDate`).all() as any[];
  const dsars = dsarRaw.map((d) => {
    const closed = CLOSED_RX.test(String(d.Status ?? "")) || !!d.CompletedDate;
    const due = String(d.DueDate ?? "").slice(0, 10);
    const daysLeft = due ? daysBetween(t, due) : null;
    const overdue = !closed && due && due < t;
    if (overdue) worklist.push({ kind: "dsar-overdue", label: `${String(d.RequestType ?? "Request")} request from ${d.SubjectName || "a data subject"} is OVERDUE (due ${due})`, severity: "Critical", ref: `RequestID ${d.RequestID}` });
    else if (!closed && daysLeft != null && daysLeft <= 7) worklist.push({ kind: "dsar-due", label: `${String(d.RequestType ?? "Request")} request from ${d.SubjectName || "a data subject"} due in ${daysLeft}d`, severity: "Medium", ref: `RequestID ${d.RequestID}` });
    return { id: num(d.RequestID), subject: String(d.SubjectName ?? ""), type: String(d.RequestType ?? ""), received: String(d.ReceivedDate ?? "").slice(0, 10), due, status: String(d.Status ?? ""), assignedTo: String(d.AssignedTo ?? ""), closed, overdue: !!overdue, daysLeft };
  });

  // — Breaches (72-hour clock, Art 33) —
  const breachRaw = db.prepare(`SELECT BreachID, Title, DetectedDate, AffectedSubjects, Severity, RiskToSubjects, NotifiedAuthority, AuthorityNotifiedDate, NotifiedSubjects, Status FROM PRIVACYBREACH ${tw(tenant)} ORDER BY DetectedDate DESC`).all() as any[];
  const breaches = breachRaw.map((b) => {
    const detected = String(b.DetectedDate ?? "").slice(0, 10);
    const notified = num(b.NotifiedAuthority) === 1;
    const hoursSince = b.DetectedDate ? (Date.now() - Date.parse(String(b.DetectedDate))) / 3600000 : null;
    const open = !CLOSED_RX.test(String(b.Status ?? ""));
    const highRisk = /high|élev/i.test(String(b.RiskToSubjects ?? "")) || /high|crit/i.test(String(b.Severity ?? ""));
    const breach72 = open && !notified && hoursSince != null && hoursSince > 72;
    if (breach72) worklist.push({ kind: "breach-72h", label: `Breach "${b.Title}" past the 72-hour clock and NOT notified to the supervisory authority (Art 33)`, severity: "Critical", ref: `BreachID ${b.BreachID}` });
    else if (open && !notified && highRisk) worklist.push({ kind: "breach-notify", label: `High-risk breach "${b.Title}" — assess authority + data-subject notification (Art 33/34)`, severity: "High", ref: `BreachID ${b.BreachID}` });
    return { id: num(b.BreachID), title: String(b.Title ?? ""), detected, affected: num(b.AffectedSubjects), severity: String(b.Severity ?? ""), riskToSubjects: String(b.RiskToSubjects ?? ""), notifiedAuthority: notified, notifiedSubjects: num(b.NotifiedSubjects) === 1, status: String(b.Status ?? ""), hoursSinceDetected: hoursSince != null ? Math.round(hoursSince) : null, breached72: !!breach72 };
  });

  // — Processors / sub-processors (Art 28) —
  const procrRaw = db.prepare(`SELECT ProcessorID, Name, Service, Referent, ClausesVerified, SecurityAdopted, MaintainsRoPA, TransfersOutsideEU, DpoAppointed, Location, LinkedProcessing, Status FROM PRIVACYPROCESSOR ${tw(tenant)} ORDER BY Name`).all() as any[];
  const processors = procrRaw.map((p) => {
    const clauses = num(p.ClausesVerified) === 1;
    const transfers = num(p.TransfersOutsideEU) === 1;
    const terminated = /terminat|résili|ferm|clos/i.test(String(p.Status ?? ""));
    if (!terminated && !clauses) worklist.push({ kind: "processor-no-dpa", label: `Processor "${p.Name}" has no verified Art 28 processing agreement`, severity: "High", ref: `ProcessorID ${p.ProcessorID}` });
    else if (!terminated && transfers) worklist.push({ kind: "processor-transfer", label: `Processor "${p.Name}" transfers data outside the EU — verify Chapter V safeguards`, severity: "Medium", ref: `ProcessorID ${p.ProcessorID}` });
    return { id: num(p.ProcessorID), name: String(p.Name ?? ""), service: String(p.Service ?? ""), referent: String(p.Referent ?? ""), clausesVerified: clauses, securityAdopted: num(p.SecurityAdopted) === 1, maintainsRopa: num(p.MaintainsRoPA) === 1, transfersOutsideEU: transfers, dpoAppointed: num(p.DpoAppointed) === 1, location: String(p.Location ?? ""), linkedProcessing: String(p.LinkedProcessing ?? ""), status: String(p.Status ?? "") };
  });

  // — Protection actions / action plan —
  const actRaw = db.prepare(`SELECT ActionID, Name, Owner, Priority, Status, DueDate, LinkKind, LinkRef FROM PRIVACYACTION ${tw(tenant)} ORDER BY Priority, DueDate`).all() as any[];
  const actions = actRaw.map((a) => {
    const st = String(a.Status ?? "");
    const done = ACTION_DONE_RX.test(st);
    const due = String(a.DueDate ?? "").slice(0, 10);
    const overdue = !done && !!due && due < t;
    if (overdue) worklist.push({ kind: "action-overdue", label: `Protection action "${a.Name}" is overdue (due ${due})`, severity: "Medium", ref: `ActionID ${a.ActionID}` });
    return { id: num(a.ActionID), name: String(a.Name ?? ""), owner: String(a.Owner ?? ""), priority: num(a.Priority) || 2, status: st, due, linkKind: String(a.LinkKind ?? ""), linkRef: String(a.LinkRef ?? ""), done, overdue };
  });

  // — Posture score (0–100, higher = better) —
  const dsarOverdue = dsars.filter((d) => d.overdue).length;
  const procNoBasis = procRows.filter((p) => !p.legalBasis).length;
  const dpiaGaps = procRows.filter((p) => p.dpiaRequired && !p.dpiaApproved).length;
  const breach72 = breaches.filter((b) => b.breached72).length;
  const processorsNoClauses = processors.filter((p) => !p.clausesVerified && !/terminat|résili|ferm|clos/i.test(p.status)).length;
  const actionsOverdue = actions.filter((a) => a.overdue).length;
  let score = 100;
  score -= dsarOverdue * 12 + procNoBasis * 8 + dpiaGaps * 6 + breach72 * 20 + processorsNoClauses * 6 + actionsOverdue * 3;
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  worklist.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  return {
    summary: {
      processing: procRows.length, processingNoBasis: procNoBasis,
      dsarTotal: dsars.length, dsarOpen: dsars.filter((d) => !d.closed).length, dsarOverdue,
      dpiaTotal: dpias.length, dpiaApproved: dpias.filter((d) => /approv/i.test(d.Status ?? "")).length, dpiaGaps,
      breaches: breaches.length, breachesUnnotified: breaches.filter((b) => !b.notifiedAuthority && !CLOSED_RX.test(b.status)).length, breach72,
      processors: processors.length, processorsNoClauses,
      actionsTotal: actions.length, actionsOpen: actions.filter((a) => !a.done).length, actionsOverdue, actionsApplied: actions.filter((a) => a.done).length,
      score, grade,
    },
    processing: procRows, dsars, dpias: dpias.map((d) => ({ id: num(d.DpiaID), name: String(d.Name ?? ""), processingId: d.ProcessingID != null ? num(d.ProcessingID) : null, riskLevel: String(d.RiskLevel ?? ""), status: String(d.Status ?? ""), consultedDpo: num(d.ConsultedDPO) === 1 })),
    breaches, processors, actions,
    worklist: worklist.slice(0, 40),
    legalBases: LEGAL_BASES, dsarTypes: DSAR_TYPES, processorStatuses: PROCESSOR_STATUS, actionStatuses: ACTION_STATUS, dpiaTriggers: DPIA_TRIGGERS,
  };
}

export function createProcessing(p: { name: string; purpose?: string; legalBasis?: string; dataCategories?: string; specialCategories?: boolean; dataSubjects?: string; recipients?: string; retention?: string; crossBorder?: boolean; transferSafeguard?: string; riskLevel?: string; controller?: string; dpiaTriggers?: string[] }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYPROCESSING", "ProcessingID");
  const validCodes = new Set(DPIA_TRIGGERS.map((t) => t.code));
  const triggers = (p.dpiaTriggers || []).map((s) => String(s).trim()).filter((s) => validCodes.has(s)).join(",");
  db.prepare(`INSERT INTO PRIVACYPROCESSING (ProcessingID, ProcessingGUID, Name, Purpose, LegalBasis, DataCategories, SpecialCategories, DataSubjects, Recipients, RetentionPeriod, CrossBorderTransfer, TransferSafeguard, RiskLevel, Controller, Status, DpiaTriggers, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.name.trim(), (p.purpose || "").trim(), (p.legalBasis || "").trim(), (p.dataCategories || "").trim(), p.specialCategories ? 1 : 0, (p.dataSubjects || "").trim(), (p.recipients || "").trim(), (p.retention || "").trim(), p.crossBorder ? 1 : 0, (p.transferSafeguard || "").trim(), (p.riskLevel || "Medium").trim(), (p.controller || "").trim(), "Active", triggers, new Date().toISOString(), tenant);
  return { id };
}

/** Register a processor / sub-processor (GDPR Art 28). */
export function createProcessor(p: { name: string; service?: string; referent?: string; clausesVerified?: boolean; securityAdopted?: boolean; maintainsRopa?: boolean; transfersOutsideEU?: boolean; dpoAppointed?: boolean; location?: string; linkedProcessing?: string; status?: string; notes?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYPROCESSOR", "ProcessorID");
  db.prepare(`INSERT INTO PRIVACYPROCESSOR (ProcessorID, ProcessorGUID, Name, Service, Referent, ClausesVerified, SecurityAdopted, MaintainsRoPA, TransfersOutsideEU, DpoAppointed, Location, LinkedProcessing, Status, Notes, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.name.trim(), (p.service || "").trim(), (p.referent || "").trim(), p.clausesVerified ? 1 : 0, p.securityAdopted ? 1 : 0, p.maintainsRopa ? 1 : 0, p.transfersOutsideEU ? 1 : 0, p.dpoAppointed ? 1 : 0, (p.location || "").trim(), (p.linkedProcessing || "").trim(), (p.status || "Active").trim(), (p.notes || "").trim(), new Date().toISOString(), tenant);
  return { id };
}

/** Create a protection action / action-plan item, optionally linked to another register row. */
export function createAction(p: { name: string; description?: string; owner?: string; priority?: number; cost?: string; effort?: string; status?: string; dueDate?: string; linkKind?: string; linkRef?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYACTION", "ActionID");
  const prio = [1, 2, 3].includes(Number(p.priority)) ? Number(p.priority) : 2;
  db.prepare(`INSERT INTO PRIVACYACTION (ActionID, ActionGUID, Name, Description, Owner, Priority, Cost, Effort, Status, DueDate, LinkKind, LinkRef, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.name.trim(), (p.description || "").trim(), (p.owner || "").trim(), prio, (p.cost || "").trim(), (p.effort || "").trim(), (p.status || "Planned").trim(), (p.dueDate || "").slice(0, 10), (p.linkKind || "").trim(), (p.linkRef || "").trim(), new Date().toISOString(), tenant);
  return { id };
}

export function updateActionStatus(id: number, status: string, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT TenantID FROM PRIVACYACTION WHERE ActionID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!row || (tenant != null && row.TenantID != null && num(row.TenantID) !== tenant)) return false;
  db.prepare("UPDATE PRIVACYACTION SET Status = ? WHERE ActionID = ?").run(status, id);
  return true;
}

export function createDsar(p: { subjectName: string; subjectEmail?: string; requestType?: string; receivedDate?: string; channel?: string; assignedTo?: string; notes?: string }, tenant: number | null): { id: number; dueDate: string } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("DSAR", "RequestID");
  const received = (p.receivedDate || today()).slice(0, 10);
  const due = new Date(Date.parse(received) + 30 * 86400000).toISOString().slice(0, 10); // GDPR: 1 month
  db.prepare(`INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, SubjectEmail, RequestType, ReceivedDate, DueDate, Status, Channel, AssignedTo, Notes, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.subjectName.trim(), (p.subjectEmail || "").trim(), (p.requestType || "Access").trim(), received, due, "New", (p.channel || "").trim(), (p.assignedTo || "").trim(), (p.notes || "").trim(), new Date().toISOString(), tenant);
  return { id, dueDate: due };
}

export function updateDsarStatus(id: number, status: string, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT TenantID FROM DSAR WHERE RequestID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!row || (tenant != null && row.TenantID != null && num(row.TenantID) !== tenant)) return false;
  const completed = CLOSED_RX.test(status) ? today() : null;
  db.prepare("UPDATE DSAR SET Status = ?, CompletedDate = ? WHERE RequestID = ?").run(status, completed, id);
  return true;
}

export function recordBreach(p: { title: string; description?: string; detectedDate?: string; affectedSubjects?: number; dataCategories?: string; severity?: string; riskToSubjects?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYBREACH", "BreachID");
  db.prepare(`INSERT INTO PRIVACYBREACH (BreachID, BreachGUID, Title, Description, DetectedDate, AffectedSubjects, DataCategories, Severity, RiskToSubjects, NotifiedAuthority, NotifiedSubjects, Status, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.title.trim(), (p.description || "").trim(), (p.detectedDate || new Date().toISOString()), num(p.affectedSubjects), (p.dataCategories || "").trim(), (p.severity || "Medium").trim(), (p.riskToSubjects || "").trim(), 0, 0, "Open", new Date().toISOString(), tenant);
  return { id };
}

/**
 * Bulk-import a normalized MADIS export (produced by the `madis` connector).
 * Idempotent by name per register (re-runs skip existing rows in the same tenant scope).
 */
export function importMadis(payload: { processing?: any[]; processors?: any[]; dsar?: any[]; breaches?: any[]; actions?: any[] }, tenant: number | null): { processing: number; processors: number; dsar: number; breaches: number; actions: number } {
  ensurePrivacyTables();
  const db = getDb("XCOMPLIANCE");
  const out = { processing: 0, processors: 0, dsar: 0, breaches: 0, actions: 0 };
  const exists = (table: string, col: string, val: string): boolean =>
    !!db.prepare(`SELECT 1 FROM ${table} WHERE ${col} = ? AND (TenantID = ? OR (? IS NULL AND TenantID IS NULL)) LIMIT 1`).get(val, tenant, tenant);
  for (const p of payload.processing || []) {
    const name = String(p.name || p.Name || "").trim(); if (!name || exists("PRIVACYPROCESSING", "Name", name)) continue;
    createProcessing({ name, purpose: p.purpose, legalBasis: p.legalBasis, dataCategories: p.dataCategories, specialCategories: !!p.specialCategories, dataSubjects: p.dataSubjects, recipients: p.recipients, retention: p.retention, crossBorder: !!p.crossBorder, transferSafeguard: p.transferSafeguard, riskLevel: p.riskLevel, controller: p.controller, dpiaTriggers: Array.isArray(p.dpiaTriggers) ? p.dpiaTriggers : undefined }, tenant); out.processing++;
  }
  for (const p of payload.processors || []) {
    const name = String(p.name || p.Name || "").trim(); if (!name || exists("PRIVACYPROCESSOR", "Name", name)) continue;
    createProcessor({ name, service: p.service, referent: p.referent, clausesVerified: !!p.clausesVerified, securityAdopted: !!p.securityAdopted, maintainsRopa: !!p.maintainsRopa, transfersOutsideEU: !!p.transfersOutsideEU, dpoAppointed: !!p.dpoAppointed, location: p.location, linkedProcessing: p.linkedProcessing, status: p.status, notes: p.notes }, tenant); out.processors++;
  }
  for (const d of payload.dsar || []) {
    const subj = String(d.subjectName || d.SubjectName || "").trim(); if (!subj) continue;
    createDsar({ subjectName: subj, subjectEmail: d.subjectEmail, requestType: d.requestType, receivedDate: d.receivedDate, channel: d.channel, assignedTo: d.assignedTo, notes: d.notes }, tenant); out.dsar++;
  }
  for (const b of payload.breaches || []) {
    const title = String(b.title || b.Title || "").trim(); if (!title || exists("PRIVACYBREACH", "Title", title)) continue;
    recordBreach({ title, description: b.description, detectedDate: b.detectedDate, affectedSubjects: b.affectedSubjects, dataCategories: b.dataCategories, severity: b.severity, riskToSubjects: b.riskToSubjects }, tenant); out.breaches++;
  }
  for (const a of payload.actions || []) {
    const name = String(a.name || a.Name || "").trim(); if (!name || exists("PRIVACYACTION", "Name", name)) continue;
    createAction({ name, description: a.description, owner: a.owner, priority: a.priority, cost: a.cost, effort: a.effort, status: a.status, dueDate: a.dueDate, linkKind: a.linkKind, linkRef: a.linkRef }, tenant); out.actions++;
  }
  return out;
}

/** Demo seed (tenant only) — a realistic RoPA + DSARs + a DPIA + a breach for the DPO cockpit. */
export function seedPrivacy(tenant: number): { processing: number; dsar: number; dpia: number; breach: number; processors: number; actions: number } {
  ensurePrivacyTables();
  const db = getDb("XCOMPLIANCE");
  const existing = num((db.prepare("SELECT COUNT(*) n FROM PRIVACYPROCESSING WHERE TenantID = ?").get(tenant) as { n: number }).n);
  if (existing) return { processing: 0, dsar: 0, dpia: 0, breach: 0, processors: 0, actions: 0 };
  const p1 = createProcessing({ name: "Customer CRM", purpose: "Manage customer relationships and orders", legalBasis: "Contract", dataCategories: "Name, email, phone, order history", dataSubjects: "Customers", recipients: "Sales, CRM SaaS processor", retention: "Account life + 3 years", riskLevel: "Medium", controller: "Acme Corp" }, tenant).id;
  const p2 = createProcessing({ name: "HR & payroll", purpose: "Employee administration and payroll", legalBasis: "Legal obligation", dataCategories: "Identity, bank details, health (sick leave)", specialCategories: true, dataSubjects: "Employees", retention: "Employment + 5 years", riskLevel: "High", controller: "Acme Corp", dpiaTriggers: ["sensitive", "large-scale"] }, tenant).id;
  createProcessing({ name: "Website analytics", purpose: "Audience measurement", dataCategories: "IP, device, behavior", dataSubjects: "Website visitors", crossBorder: true, riskLevel: "Medium", dpiaTriggers: ["monitoring", "large-scale"] }, tenant); // no legal basis + transfer + 2 CNIL triggers (DPIA required) → worklist
  // DSARs — one overdue, one due soon, one completed
  const back = (d: number): string => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
  db.prepare("INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, RequestType, ReceivedDate, DueDate, Status, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(nextId("DSAR", "RequestID"), randomUUID(), "Jane Doe", "Erasure", back(40), back(10), "InProgress", new Date().toISOString(), tenant); // overdue
  createDsar({ subjectName: "John Smith", requestType: "Access", receivedDate: back(25) }, tenant); // due in ~5d
  db.prepare("INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, RequestType, ReceivedDate, DueDate, Status, CompletedDate, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(nextId("DSAR", "RequestID"), randomUUID(), "Marie Curie", "Portability", back(50), back(20), "Completed", back(22), new Date().toISOString(), tenant);
  // DPIA for the high-risk HR processing (draft → triggers no gap once approved; leave Draft to show the gap closing path)
  db.prepare("INSERT INTO DPIA (DpiaID, DpiaGUID, Name, ProcessingID, RiskLevel, Status, ConsultedDPO, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(nextId("DPIA", "DpiaID"), randomUUID(), "DPIA — HR & payroll (special category data)", p2, "High", "Approved", 1, new Date().toISOString(), tenant);
  // a breach within the 72h window (not yet past)
  recordBreach({ title: "Misdirected email with customer list", description: "An export was emailed to the wrong recipient.", detectedDate: new Date(Date.now() - 20 * 3600000).toISOString(), affectedSubjects: 240, dataCategories: "Name, email", severity: "Medium", riskToSubjects: "Low" }, tenant);
  // Processors (Art 28) — one compliant, one missing a DPA (worklist), one transferring outside EU
  createProcessor({ name: "Acme CRM Cloud", service: "CRM hosting (SaaS)", referent: "Vendor DPO", clausesVerified: true, securityAdopted: true, maintainsRopa: true, transfersOutsideEU: false, dpoAppointed: true, location: "France", linkedProcessing: "Customer CRM", status: "Active" }, tenant);
  createProcessor({ name: "Offshore Payroll BPO", service: "Payroll processing", referent: "Ops manager", clausesVerified: false, securityAdopted: true, maintainsRopa: false, transfersOutsideEU: true, dpoAppointed: false, location: "India", linkedProcessing: "HR & payroll", status: "Under review" }, tenant); // no verified Art 28 DPA → worklist
  createProcessor({ name: "Web Analytics Cloud", service: "Audience measurement", clausesVerified: true, securityAdopted: true, transfersOutsideEU: true, dpoAppointed: true, location: "USA", linkedProcessing: "Website analytics", status: "Active" }, tenant); // transfer outside EU → worklist
  // Action plan — one overdue, two planned, linked to the gaps above ("back" is defined above with the DSARs)
  const fwd = (d: number): string => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
  createAction({ name: "Sign Art 28 DPA with Offshore Payroll BPO", description: "Execute a compliant data processing agreement.", owner: "DPO", priority: 1, status: "Planned", dueDate: back(5), linkKind: "processor", linkRef: "Offshore Payroll BPO" }, tenant); // overdue
  createAction({ name: "Document the legal basis for Website analytics", owner: "Marketing", priority: 2, status: "Planned", dueDate: fwd(20), linkKind: "processing", linkRef: "Website analytics" }, tenant);
  createAction({ name: "Put Standard Contractual Clauses in place for US analytics transfer", owner: "DPO", priority: 2, status: "Planned", dueDate: fwd(30), linkKind: "processor", linkRef: "Web Analytics Cloud" }, tenant);
  void p1;
  return { processing: 3, dsar: 3, dpia: 1, breach: 1, processors: 3, actions: 3 };
}
