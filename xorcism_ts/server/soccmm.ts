/**
 * soccmm.ts — SOC-CMM (SOC Capability Maturity Model, soc-cmm.com) advanced self-assessment.
 *
 * Faithful to the SOC-CMM 2.x model: 5 domains / 26 aspects. Maturity is scored on a continuous
 * 0–5 scale (CMMI-style) for every aspect; Capability is scored on a 0–3 scale for the two "purple"
 * domains only — Technology and Services (capability = SOC output / service delivery, maturity =
 * internal process). Each aspect carries an importance weight; domain and overall scores are the
 * importance-weighted means (continuous, not staged). Produces a maturity radar (5 domains), a
 * capability radar (2 domains), coverage, and a gap worklist (below-target × importance).
 *
 * Data lives in XINCIDENT: SOCCMMASPECT (the 26-aspect catalogue, self-seeded to the official set),
 * SOCCMMSCORE (per-tenant maturity/capability/importance/notes) and SOCCMMASSESSMENT (one header per
 * tenant: SOC scope, self vs 3rd-party, assessor, targets). Results are entered per aspect via
 * saveScore and read back scored by domain.
 */
import { allocId, getDb } from "./db";

export const MATURITY = ["Non-existent", "Initial", "Managed", "Defined", "Quantitatively managed", "Optimizing"];
export const CAPABILITY = ["None", "Limited", "Adequate", "Comprehensive"]; // 0–3
export const DOMAINS = ["Business", "People", "Process", "Technology", "Services"];
export const CAP_DOMAINS = ["Technology", "Services"]; // domains also assessed for capability

// The official SOC-CMM 26 aspects: [domain, aspect, capable, description]. (soc-cmm.com, v2.x)
export const ASPECTS: [string, string, boolean, string][] = [
  ["Business", "Business Drivers", false, "The business needs and risk drivers that justify and steer the SOC."],
  ["Business", "Customers", false, "The SOC's customers, their requirements and satisfaction."],
  ["Business", "Charter", false, "A formal, sponsored charter/mandate defining the SOC's authority, scope and services."],
  ["Business", "Governance", false, "Executive governance, steering, decision rights and oversight of the SOC."],
  ["Business", "Privacy & policy", false, "Privacy, legal and policy requirements embedded in SOC operations."],
  ["People", "Employees", false, "Adequate, sustainable staffing across shifts and tiers, with well-being."],
  ["People", "Roles and Hierarchy", false, "Clear analyst tiers, roles, responsibilities and reporting lines."],
  ["People", "People Management", false, "Managing performance, career paths, retention and team development."],
  ["People", "Knowledge Management", false, "Capturing, sharing and maintaining SOC knowledge and documentation."],
  ["People", "Training & Education", false, "Ongoing technical training, exercises and skills development."],
  ["Process", "SOC Management", false, "SOC planning, quality assurance and continual improvement processes."],
  ["Process", "Operations & Facilities", false, "Day-to-day operational processes and the SOC facilities/environment."],
  ["Process", "Reporting & Communication", false, "Reporting, KPIs (MTTD/MTTA/MTTR) and stakeholder communication."],
  ["Process", "Use Case Management", false, "A managed lifecycle for detection use cases from request to retirement."],
  ["Process", "Detection Engineering & Validation", false, "Engineering, testing and validating detection content and coverage."],
  ["Technology", "SIEM / UEBA", true, "The SIEM/UEBA platform: log coverage, health, correlation and analytics."],
  ["Technology", "NDR", true, "Network detection & response: visibility, coverage and tuning."],
  ["Technology", "EDR", true, "Endpoint detection & response: coverage, tuning and response actions."],
  ["Technology", "SOAR", true, "Security orchestration, automation & response of repetitive workflows."],
  ["Services", "Security Monitoring", true, "Continuous monitoring, alert triage and escalation."],
  ["Services", "Security Incident Management", true, "Handling, containment, eradication and recovery of incidents."],
  ["Services", "Security Analysis & Forensics", true, "Deep analysis, malware analysis and digital forensics."],
  ["Services", "Threat Intelligence", true, "Producing and operationalising actionable CTI."],
  ["Services", "Threat Hunting", true, "Proactive, hypothesis-driven hunting for undetected threats."],
  ["Services", "Vulnerability Management", true, "Identifying, prioritising and driving remediation of vulnerabilities."],
  ["Services", "Log Management", true, "Collection, retention, normalisation and quality of log sources."],
];

const r1 = (x: number | null): number | null => (x == null ? null : Math.round(x * 10) / 10);
const clampStep = (v: number, lo: number, hi: number, step = 0.5): number =>
  Math.max(lo, Math.min(hi, Math.round(v / step) * step));

function cols(db: any, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as any[]).map((c) => c.name)); } catch { return new Set(); }
}

/** Self-migrate the schema (capability + assessment header) and seed the official 26 aspects. */
export function ensureAdvanced(): void {
  const db = getDb("XINCIDENT");
  db.exec(`CREATE TABLE IF NOT EXISTS SOCCMMASPECT (AspectID INTEGER PRIMARY KEY, Domain TEXT, Aspect TEXT, Description TEXT, Weight REAL DEFAULT 1, SortOrder INTEGER);
    CREATE TABLE IF NOT EXISTS SOCCMMSCORE (ScoreID INTEGER PRIMARY KEY, AspectID INTEGER, Maturity REAL, Importance INTEGER DEFAULT 3, Notes TEXT, AssessedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_soccmm_score ON SOCCMMSCORE(AspectID, TenantID);`);
  // Assessment header: surrogate PK (NOT TenantID — an INTEGER PRIMARY KEY coerces a NULL super-admin
  // tenant into an auto rowid, hiding the row). Migrate a legacy TenantID-PK table if present.
  const ai = db.prepare(`PRAGMA table_info("SOCCMMASSESSMENT")`).all() as any[];
  if (ai.length && ai.some((c) => c.name === "TenantID" && c.pk)) { try { db.exec("DROP TABLE SOCCMMASSESSMENT"); } catch { /* ignore */ } }
  db.exec(`CREATE TABLE IF NOT EXISTS SOCCMMASSESSMENT (AsmtID INTEGER PRIMARY KEY, TenantID INTEGER, ScopeName TEXT, AssessType TEXT, Assessor TEXT, TargetMaturity REAL DEFAULT 3, TargetCapability REAL DEFAULT 2, Notes TEXT, AssessedDate TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_soccmm_asmt ON SOCCMMASSESSMENT(IFNULL(TenantID,-1));`);
  if (!cols(db, "SOCCMMASPECT").has("Capable")) { try { db.exec("ALTER TABLE SOCCMMASPECT ADD COLUMN Capable INTEGER DEFAULT 0"); } catch { /* exists */ } }
  if (!cols(db, "SOCCMMSCORE").has("Capability")) { try { db.exec("ALTER TABLE SOCCMMSCORE ADD COLUMN Capability REAL"); } catch { /* exists */ } }

  // Seed / migrate the aspect catalogue to the official 26 (replace if the set differs from ours).
  const have = db.prepare("SELECT Domain, Aspect FROM SOCCMMASPECT ORDER BY SortOrder").all() as any[];
  const sig = have.map((h) => `${h.Domain}|${h.Aspect}`).join("~");
  const want = ASPECTS.map((a) => `${a[0]}|${a[1]}`).join("~");
  if (sig !== want) {
    db.exec("DELETE FROM SOCCMMSCORE; DELETE FROM SOCCMMASPECT;"); // aspect ids change → clear stale scores
    const ins = db.prepare("INSERT INTO SOCCMMASPECT (AspectID, Domain, Aspect, Description, Capable, Weight, SortOrder) VALUES (?,?,?,?,?,1,?)");
    ASPECTS.forEach((a, i) => ins.run(i + 1, a[0], a[1], a[3], a[2] ? 1 : 0, i));
  }
}

const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "IFNULL(TenantID,-1)=IFNULL(?,-1)");

/** Importance-weighted mean of a numeric field over a scored list. */
function weightedMean(list: { v: number | null; imp: number }[]): number | null {
  const scored = list.filter((x) => x.v != null);
  if (!scored.length) return null;
  const wsum = scored.reduce((s, x) => s + x.imp, 0) || scored.length;
  return scored.reduce((s, x) => s + (x.v as number) * x.imp, 0) / wsum;
}

export function soccmmInventory(tenant: number | null): any {
  ensureAdvanced();
  const db = getDb("XINCIDENT");
  const aspects = db.prepare("SELECT AspectID, Domain, Aspect, Description, COALESCE(Capable,0) Capable FROM SOCCMMASPECT ORDER BY SortOrder").all() as any[];
  const scores = new Map<number, any>();
  const sargs = tenant != null ? [tenant] : [];
  for (const s of db.prepare(`SELECT * FROM SOCCMMSCORE WHERE ${tw(tenant)}`).all(...sargs) as any[]) scores.set(Number(s.AspectID), s);

  const hdr = (db.prepare(`SELECT * FROM SOCCMMASSESSMENT WHERE ${tw(tenant)}`).get(...sargs) as any) || {};
  const targetM = hdr.TargetMaturity != null ? Number(hdr.TargetMaturity) : 3;
  const targetC = hdr.TargetCapability != null ? Number(hdr.TargetCapability) : 2;

  const rows = aspects.map((a) => {
    const s = scores.get(Number(a.AspectID));
    return {
      id: Number(a.AspectID), domain: String(a.Domain), aspect: String(a.Aspect), description: String(a.Description ?? ""),
      capable: !!Number(a.Capable),
      maturity: s && s.Maturity != null ? Number(s.Maturity) : null,
      capability: s && s.Capability != null ? Number(s.Capability) : null,
      importance: s && s.Importance != null ? Number(s.Importance) : 3,
      notes: s ? String(s.Notes ?? "") : "",
    };
  });

  const byDomain = DOMAINS.map((d) => {
    const list = rows.filter((r) => r.domain === d);
    const mat = weightedMean(list.map((r) => ({ v: r.maturity, imp: r.importance })));
    const capList = list.filter((r) => r.capable);
    const cap = CAP_DOMAINS.includes(d) ? weightedMean(capList.map((r) => ({ v: r.capability, imp: r.importance }))) : null;
    return {
      domain: d, capable: CAP_DOMAINS.includes(d), aspects: list.length,
      scored: list.filter((r) => r.maturity != null).length,
      maturity: r1(mat), capability: r1(cap),
    };
  });

  const overallM = weightedMean(rows.map((r) => ({ v: r.maturity, imp: r.importance })));
  const capRows = rows.filter((r) => r.capable);
  const overallC = weightedMean(capRows.map((r) => ({ v: r.capability, imp: r.importance })));

  const worklist = rows
    .filter((r) => r.maturity != null && (r.maturity < targetM || (r.capable && r.capability != null && r.capability < targetC)))
    .map((r) => ({
      id: r.id, domain: r.domain, aspect: r.aspect, maturity: r.maturity, capability: r.capable ? r.capability : null,
      importance: r.importance, gap: r1(Math.max(0, targetM - (r.maturity || 0))),
      capGap: r.capable && r.capability != null ? r1(Math.max(0, targetC - r.capability)) : null,
    }))
    .sort((a, b) => (b.importance - a.importance) || ((b.gap || 0) - (a.gap || 0)))
    .slice(0, 30);

  const scoredCount = rows.filter((r) => r.maturity != null).length;
  return {
    maturityLevels: MATURITY, capabilityLevels: CAPABILITY, capDomains: CAP_DOMAINS,
    assessment: {
      scopeName: hdr.ScopeName || "", assessType: hdr.AssessType || "self", assessor: hdr.Assessor || "",
      targetMaturity: targetM, targetCapability: targetC, notes: hdr.Notes || "", assessedDate: hdr.AssessedDate || "",
    },
    domains: byDomain, rows,
    maturityRadar: byDomain.map((d) => ({ domain: d.domain, value: d.maturity, target: targetM })),
    capabilityRadar: byDomain.filter((d) => d.capable).map((d) => ({ domain: d.domain, value: d.capability, target: targetC })),
    summary: {
      overallMaturity: r1(overallM), overallCapability: r1(overallC), target: targetM, targetCapability: targetC,
      aspects: rows.length, scored: scoredCount, coverage: rows.length ? Math.round((scoredCount / rows.length) * 100) : 0,
      belowTarget: rows.filter((r) => r.maturity != null && r.maturity < targetM).length,
      capBelowTarget: capRows.filter((r) => r.capability != null && r.capability < targetC).length,
    },
    worklist,
  };
}

export function saveScore(aspectId: number, p: { maturity?: number; capability?: number; importance?: number; notes?: string }, tenant: number | null): boolean {
  ensureAdvanced();
  const db = getDb("XINCIDENT");
  const asp = db.prepare("SELECT COALESCE(Capable,0) Capable FROM SOCCMMASPECT WHERE AspectID = ?").get(aspectId) as { Capable: number } | undefined;
  if (!asp) return false;
  const now = new Date().toISOString();
  const ex = db.prepare(`SELECT ScoreID FROM SOCCMMSCORE WHERE AspectID = ? AND ${tw(tenant)}`).get(aspectId, ...(tenant != null ? [tenant] : [])) as { ScoreID: number } | undefined;
  const mat = p.maturity != null ? clampStep(p.maturity, 0, 5) : null;
  const cap = p.capability != null && Number(asp.Capable) ? clampStep(p.capability, 0, 3) : null;
  const imp = p.importance != null ? Math.max(1, Math.min(5, Math.round(p.importance))) : null;
  if (ex) {
    const sets: string[] = ["AssessedDate = ?"]; const vals: unknown[] = [now];
    if (mat != null) { sets.push("Maturity = ?"); vals.push(mat); }
    if (p.capability != null && Number(asp.Capable)) { sets.push("Capability = ?"); vals.push(cap); }
    if (imp != null) { sets.push("Importance = ?"); vals.push(imp); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
    vals.push(ex.ScoreID);
    db.prepare(`UPDATE SOCCMMSCORE SET ${sets.join(", ")} WHERE ScoreID = ?`).run(...vals);
  } else {
    const id = allocId(db, "SOCCMMSCORE", "ScoreID");
    db.prepare("INSERT INTO SOCCMMSCORE (ScoreID, AspectID, Maturity, Capability, Importance, Notes, AssessedDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(id, aspectId, mat ?? 0, cap, imp ?? 3, String(p.notes ?? "").slice(0, 1000), now, tenant, now);
  }
  return true;
}

export function saveAssessment(tenant: number | null, p: { scopeName?: string; assessType?: string; assessor?: string; targetMaturity?: number; targetCapability?: number; notes?: string }): boolean {
  ensureAdvanced();
  const db = getDb("XINCIDENT");
  const now = new Date().toISOString();
  const ex = db.prepare(`SELECT TenantID FROM SOCCMMASSESSMENT WHERE ${tw(tenant)}`).get(...(tenant != null ? [tenant] : [])) as any;
  const tM = p.targetMaturity != null ? clampStep(p.targetMaturity, 0, 5) : null;
  const tC = p.targetCapability != null ? clampStep(p.targetCapability, 0, 3) : null;
  const at = p.assessType === "3rd-party" ? "3rd-party" : (p.assessType === "self" ? "self" : null);
  if (ex) {
    const sets: string[] = ["AssessedDate = ?"]; const vals: unknown[] = [now];
    if (p.scopeName != null) { sets.push("ScopeName = ?"); vals.push(String(p.scopeName).slice(0, 200)); }
    if (at) { sets.push("AssessType = ?"); vals.push(at); }
    if (p.assessor != null) { sets.push("Assessor = ?"); vals.push(String(p.assessor).slice(0, 200)); }
    if (tM != null) { sets.push("TargetMaturity = ?"); vals.push(tM); }
    if (tC != null) { sets.push("TargetCapability = ?"); vals.push(tC); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 2000)); }
    db.prepare(`UPDATE SOCCMMASSESSMENT SET ${sets.join(", ")} WHERE ${tw(tenant)}`).run(...vals, ...(tenant != null ? [tenant] : []));
  } else {
    db.prepare("INSERT INTO SOCCMMASSESSMENT (TenantID, ScopeName, AssessType, Assessor, TargetMaturity, TargetCapability, Notes, AssessedDate) VALUES (?,?,?,?,?,?,?,?)")
      .run(tenant, String(p.scopeName ?? "").slice(0, 200), at || "self", String(p.assessor ?? "").slice(0, 200), tM ?? 3, tC ?? 2, String(p.notes ?? "").slice(0, 2000), now);
  }
  return true;
}

export function seedSocCmm(tenant: number): { aspects: number; scores: number } {
  ensureAdvanced();
  const db = getDb("XINCIDENT");
  const aspectCount = (db.prepare("SELECT COUNT(*) n FROM SOCCMMASPECT").get() as { n: number }).n;
  let sc = 0;
  if (!(db.prepare(`SELECT COUNT(*) n FROM SOCCMMSCORE WHERE ${tw(tenant)}`).get(tenant) as { n: number }).n) {
    saveAssessment(tenant, { scopeName: "Enterprise SOC (demo)", assessType: "self", assessor: "SOC manager", targetMaturity: 3, targetCapability: 2 });
    const aspects = db.prepare("SELECT AspectID, Domain, COALESCE(Capable,0) Capable FROM SOCCMMASPECT ORDER BY SortOrder").all() as any[];
    const baseM: Record<string, number> = { Business: 2.5, People: 2, Process: 3, Technology: 3.5, Services: 3 };
    for (const a of aspects) {
      const m = clampStep(baseM[a.Domain] + (((a.AspectID * 7) % 3) - 1) * 0.5, 0, 5);
      const cap = a.Capable ? clampStep(2 + (((a.AspectID * 5) % 3) - 1) * 0.5, 0, 3) : undefined;
      const imp = 2 + ((a.AspectID * 3) % 4);
      saveScore(a.AspectID, { maturity: m, capability: cap, importance: Math.min(5, imp) }, tenant); sc++;
    }
  }
  return { aspects: aspectCount, scores: sc };
}
