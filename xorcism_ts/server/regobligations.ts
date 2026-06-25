/**
 * regobligations.ts — Regulatory obligations & compliance calendar (/reg-calendar).
 *
 * A deadline-driven view over the regulations that matter in 2026 (EU AI Act, DORA, NIS2, CRA,
 * GDPR…): each obligation = regulation → reference (article) → due date → owner → status → mapped
 * control + evidence. Surfaces a countdown calendar (overdue / due-soon / upcoming), per-regulation
 * posture and a worklist. Ships a tenant-NULL **reference catalogue** of the key EU milestones
 * (seeded at boot) so the calendar is useful on day one; organisations add their own tenant
 * obligations and track status on them. XCOMPLIANCE.REGOBLIGATION. compliance:read scope.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);

export function ensureRegObligationTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS REGOBLIGATION (
      ObligationID INTEGER PRIMARY KEY, ObligationGUID TEXT,
      Regulation TEXT, Reference TEXT, Title TEXT, Description TEXT, Category TEXT,
      DueDate TEXT, RecurrenceMonths INTEGER, Status TEXT, Owner TEXT,
      ControlRef TEXT, Jurisdiction TEXT, Priority TEXT, EvidenceUrl TEXT,
      TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_regobl_tenant ON REGOBLIGATION(TenantID);
    CREATE INDEX IF NOT EXISTS ix_regobl_due ON REGOBLIGATION(DueDate);
  `);
}

/** Key EU/global regulatory milestones (reference catalogue, tenant-NULL). Dates are the official
 *  applicability dates as published; ongoing duties carry no due date (RecurrenceMonths set). */
const CATALOGUE: Array<Omit<Obligation, "id" | "guid" | "tenant" | "status">> = [
  // ── EU AI Act (Reg. 2024/1689) ──
  { regulation: "EU AI Act", reference: "Art. 5", title: "Prohibited AI practices ban applies", description: "Unacceptable-risk AI systems (social scoring, manipulative, untargeted scraping…) are banned.", category: "AI governance", dueDate: "2025-02-02", recurrenceMonths: null, owner: "", controlRef: "AICM", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "EU AI Act", reference: "Ch. V", title: "GPAI model obligations apply", description: "General-purpose AI model providers: technical documentation, copyright policy, training-data summary; systemic-risk models add evaluations + incident reporting.", category: "AI governance", dueDate: "2025-08-02", recurrenceMonths: null, owner: "", controlRef: "SAIF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "EU AI Act", reference: "Annex III", title: "High-risk AI system obligations apply", description: "Risk management, data governance, logging, human oversight, accuracy/robustness, conformity assessment + registration for Annex III high-risk systems.", category: "AI governance", dueDate: "2026-08-02", recurrenceMonths: null, owner: "", controlRef: "AICM", jurisdiction: "EU", priority: "Critical", evidenceUrl: "" },
  { regulation: "EU AI Act", reference: "Art. 113", title: "Full applicability (incl. Annex I high-risk)", description: "Remaining provisions apply, including high-risk systems that are safety components under Annex I product legislation.", category: "AI governance", dueDate: "2027-08-02", recurrenceMonths: null, owner: "", controlRef: "AICM", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  // ── DORA (Reg. 2022/2554) ──
  { regulation: "DORA", reference: "Art. 1", title: "DORA applies to financial entities", description: "Digital Operational Resilience Act in force: ICT risk management, incident reporting, resilience testing, third-party risk, information sharing.", category: "Operational resilience", dueDate: "2025-01-17", recurrenceMonths: null, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "Critical", evidenceUrl: "" },
  { regulation: "DORA", reference: "Art. 28", title: "Register of Information submission", description: "Maintain and submit the Register of Information on contractual arrangements with ICT third-party providers (annual cadence to the competent authority).", category: "Third-party risk", dueDate: "2026-04-30", recurrenceMonths: 12, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "DORA", reference: "Art. 24-27", title: "Threat-Led Penetration Testing (TLPT)", description: "Advanced resilience testing (TLPT) for significant entities, at least every 3 years.", category: "Resilience testing", dueDate: null, recurrenceMonths: 36, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "DORA", reference: "Art. 19", title: "Major ICT-related incident reporting", description: "Initial notification, intermediate and final reports for major ICT incidents within regulatory deadlines.", category: "Incident reporting", dueDate: null, recurrenceMonths: null, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  // ── NIS2 (Dir. 2022/2555) ──
  { regulation: "NIS2", reference: "Art. 41", title: "National transposition deadline", description: "Member States transpose NIS2 into national law; essential/important entities fall in scope.", category: "Cyber risk management", dueDate: "2024-10-17", recurrenceMonths: null, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "Critical", evidenceUrl: "" },
  { regulation: "NIS2", reference: "Art. 23", title: "Significant incident — 24h early warning", description: "Early warning within 24h, incident notification within 72h, final report within 1 month for significant incidents.", category: "Incident reporting", dueDate: null, recurrenceMonths: null, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "NIS2", reference: "Art. 21", title: "Cybersecurity risk-management measures", description: "Implement the 10 baseline measures (risk analysis, incident handling, BC, supply-chain, crypto, MFA…); management bodies accountable.", category: "Cyber risk management", dueDate: null, recurrenceMonths: null, owner: "", controlRef: "ReCyF", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  // ── CRA (Reg. 2024/2847) ──
  { regulation: "Cyber Resilience Act", reference: "Art. 14", title: "Reporting of exploited vulnerabilities applies", description: "Manufacturers must report actively exploited vulnerabilities and severe incidents to ENISA/CSIRT (early warning 24h).", category: "Product security", dueDate: "2026-09-11", recurrenceMonths: null, owner: "", controlRef: "ASVS", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "Cyber Resilience Act", reference: "Art. 71", title: "Main obligations apply (CE marking)", description: "Products with digital elements meet essential cybersecurity requirements, SBOM, vulnerability handling and CE conformity.", category: "Product security", dueDate: "2027-12-11", recurrenceMonths: null, owner: "", controlRef: "ASVS", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  // ── GDPR (Reg. 2016/679) ──
  { regulation: "GDPR", reference: "Art. 33", title: "Personal-data breach notification (72h)", description: "Notify the supervisory authority of a personal-data breach within 72 hours of becoming aware.", category: "Privacy", dueDate: null, recurrenceMonths: null, owner: "", controlRef: "ISO 27701", jurisdiction: "EU", priority: "High", evidenceUrl: "" },
  { regulation: "GDPR", reference: "Art. 30", title: "Records of Processing Activities (RoPA)", description: "Maintain and keep current the Records of Processing Activities.", category: "Privacy", dueDate: null, recurrenceMonths: 12, owner: "", controlRef: "ISO 27701", jurisdiction: "EU", priority: "Medium", evidenceUrl: "" },
];

export interface Obligation {
  id: number; guid: string; regulation: string; reference: string; title: string; description: string;
  category: string; dueDate: string | null; recurrenceMonths: number | null; status: string; owner: string;
  controlRef: string; jurisdiction: string; priority: string; evidenceUrl: string; tenant: number | null;
}

export function seedRegObligationCatalogue(): void {
  ensureRegObligationTables();
  const db = getDb("XCOMPLIANCE");
  const existing = new Set(
    (db.prepare("SELECT Regulation || '|' || Reference AS k FROM REGOBLIGATION WHERE TenantID IS NULL").all() as { k: string }[]).map((r) => r.k)
  );
  const ins = db.prepare(
    `INSERT INTO REGOBLIGATION (ObligationID, ObligationGUID, Regulation, Reference, Title, Description, Category,
       DueDate, RecurrenceMonths, Status, Owner, ControlRef, Jurisdiction, Priority, EvidenceUrl, TenantID, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)`
  );
  const add = db.transaction(() => {
    let id = allocId(db, "REGOBLIGATION", "ObligationID");
    for (const c of CATALOGUE) {
      if (existing.has(`${c.regulation}|${c.reference}`)) continue;
      ins.run(id++, randomUUID(), c.regulation, c.reference, c.title, c.description, c.category,
        c.dueDate, c.recurrenceMonths, "Reference", c.owner, c.controlRef, c.jurisdiction, c.priority, c.evidenceUrl, now());
    }
  });
  add();
}

function daysUntil(due: string | null): number | null {
  if (!due) return null;
  const d = Date.parse(due); if (Number.isNaN(d)) return null;
  return Math.ceil((d - Date.parse(today())) / 86400000);
}

/** Effective status for display: stored status wins for Met/N-A/In progress; otherwise derived from the date. */
export function displayStatus(o: Obligation): string {
  const s = (o.status || "").toLowerCase();
  if (s === "met" || s === "n/a" || s === "not applicable") return o.status;
  const d = daysUntil(o.dueDate);
  if (d == null) return o.recurrenceMonths ? "Ongoing" : (o.status === "Reference" ? "Ongoing" : (o.status || "Tracked"));
  if (d < 0) return "Overdue";
  if (d <= 30) return "Due soon";
  if (d <= 90) return "Upcoming";
  return "Scheduled";
}

function rowToObl(r: any): Obligation {
  return {
    id: r.ObligationID, guid: r.ObligationGUID, regulation: r.Regulation, reference: r.Reference,
    title: r.Title, description: r.Description, category: r.Category, dueDate: r.DueDate,
    recurrenceMonths: r.RecurrenceMonths, status: r.Status, owner: r.Owner, controlRef: r.ControlRef,
    jurisdiction: r.Jurisdiction, priority: r.Priority, evidenceUrl: r.EvidenceUrl, tenant: r.TenantID,
  };
}

export function listObligations(tenant: number | null): Obligation[] {
  ensureRegObligationTables();
  return (getDb("XCOMPLIANCE").prepare(
    "SELECT * FROM REGOBLIGATION WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY Regulation, Reference"
  ).all(tenant) as any[]).map(rowToObl);
}

export function regCalendar(tenant: number | null): any {
  const obls = listObligations(tenant).map((o) => ({ ...o, effectiveStatus: displayStatus(o), daysUntil: daysUntil(o.dueDate) }));
  const isOpen = (s: string): boolean => !["Met", "N/A", "Not applicable", "Ongoing", "Reference"].includes(s);
  const summary = {
    total: obls.length,
    regulations: new Set(obls.map((o) => o.regulation)).size,
    overdue: obls.filter((o) => o.effectiveStatus === "Overdue").length,
    dueSoon: obls.filter((o) => o.effectiveStatus === "Due soon").length,
    upcoming: obls.filter((o) => o.effectiveStatus === "Upcoming").length,
    met: obls.filter((o) => o.status === "Met").length,
    open: obls.filter((o) => isOpen(o.effectiveStatus)).length,
  };
  const byRegulation = Object.values(obls.reduce((acc: Record<string, any>, o) => {
    const k = o.regulation;
    acc[k] = acc[k] || { regulation: k, total: 0, overdue: 0, dueSoon: 0, met: 0, nextDue: null as string | null };
    acc[k].total++;
    if (o.effectiveStatus === "Overdue") acc[k].overdue++;
    if (o.effectiveStatus === "Due soon") acc[k].dueSoon++;
    if (o.status === "Met") acc[k].met++;
    if (o.dueDate && (o.daysUntil ?? -1) >= 0 && (!acc[k].nextDue || o.dueDate < acc[k].nextDue)) acc[k].nextDue = o.dueDate;
    return acc;
  }, {})).sort((a: any, b: any) => b.overdue - a.overdue || b.dueSoon - a.dueSoon);
  // upcoming-deadline calendar: dated obligations, soonest first (overdue + future), capped
  const calendar = obls
    .filter((o) => o.dueDate)
    .sort((a, b) => (a.dueDate! < b.dueDate! ? -1 : 1))
    .slice(0, 40);
  return { summary, byRegulation, calendar, obligations: obls };
}

export function createObligation(tenant: number | null, b: Record<string, any>): number {
  ensureRegObligationTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "REGOBLIGATION", "ObligationID");
  db.prepare(
    `INSERT INTO REGOBLIGATION (ObligationID, ObligationGUID, Regulation, Reference, Title, Description, Category,
       DueDate, RecurrenceMonths, Status, Owner, ControlRef, Jurisdiction, Priority, EvidenceUrl, TenantID, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(id, randomUUID(), String(b.regulation || "Custom").slice(0, 120), String(b.reference || "").slice(0, 120),
    String(b.title || "Obligation").slice(0, 300), String(b.description || "").slice(0, 2000), String(b.category || "").slice(0, 120),
    b.dueDate || null, b.recurrenceMonths != null ? Number(b.recurrenceMonths) : null, String(b.status || "Not started"),
    String(b.owner || "").slice(0, 200), String(b.controlRef || "").slice(0, 200), String(b.jurisdiction || "").slice(0, 80),
    String(b.priority || "Medium"), String(b.evidenceUrl || "").slice(0, 500), tenant, now());
  return id;
}

/** Update status/owner/evidence on a tenant-owned obligation (the NULL-tenant catalogue is read-only). */
export function updateObligation(tenant: number | null, id: number, b: Record<string, any>): boolean {
  ensureRegObligationTables();
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT TenantID FROM REGOBLIGATION WHERE ObligationID=?").get(id) as { TenantID: number | null } | undefined;
  if (!row) return false;
  if (row.TenantID == null) {
    // adopt the reference obligation into the tenant before editing
    const src = db.prepare("SELECT * FROM REGOBLIGATION WHERE ObligationID=?").get(id) as any;
    const newId = allocId(db, "REGOBLIGATION", "ObligationID");
    db.prepare(
      `INSERT INTO REGOBLIGATION (ObligationID, ObligationGUID, Regulation, Reference, Title, Description, Category,
         DueDate, RecurrenceMonths, Status, Owner, ControlRef, Jurisdiction, Priority, EvidenceUrl, TenantID, CreatedDate)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(newId, randomUUID(), src.Regulation, src.Reference, src.Title, src.Description, src.Category, src.DueDate,
      src.RecurrenceMonths, String(b.status || "In progress"), String(b.owner || ""), src.ControlRef, src.Jurisdiction,
      src.Priority, String(b.evidenceUrl || ""), tenant, now());
    return true;
  }
  if (tenant != null && row.TenantID !== tenant) return false;
  const sets: string[] = [], vals: any[] = [];
  for (const [col, key] of [["Status", "status"], ["Owner", "owner"], ["EvidenceUrl", "evidenceUrl"], ["DueDate", "dueDate"], ["Priority", "priority"]] as const) {
    if (b[key] !== undefined) { sets.push(`${col}=?`); vals.push(b[key]); }
  }
  if (!sets.length) return true;
  vals.push(id);
  db.prepare(`UPDATE REGOBLIGATION SET ${sets.join(", ")} WHERE ObligationID=?`).run(...vals);
  return true;
}
