/**
 * soccmm.ts — SOC-CMM (SOC Capability Maturity Model, soc-cmm.com) self-assessment.
 * Five domains (Business, People, Process, Technology, Services), each with aspects scored on a
 * 0–5 maturity scale (CMMI-style) and an importance weight; rolls up to per-domain and overall
 * maturity, a radar, and an improvement worklist (low maturity × high importance).
 */
import { allocId, getDb } from "./db";

export const MATURITY = ["Non-existent", "Initial", "Managed", "Defined", "Quantitatively managed", "Optimizing"];

// domain → aspects (a representative SOC-CMM subset): [domain, aspect, description]
export const ASPECTS: [string, string, string][] = [
  ["Business", "SOC mandate & charter", "A formal, sponsored mandate defining the SOC's authority and scope."],
  ["Business", "Governance & sponsorship", "Executive sponsorship, steering and decision rights for the SOC."],
  ["Business", "Service portfolio", "A defined catalogue of services the SOC delivers to its customers."],
  ["Business", "Budget & funding", "Sustainable funding aligned to the SOC's mandate and growth."],
  ["Business", "Privacy & legal", "Privacy, legal and regulatory requirements embedded in SOC operations."],
  ["People", "Staffing & headcount", "Adequate, sustainable staffing across shifts and tiers."],
  ["People", "Roles & responsibilities", "Clear analyst tiers, roles and a responsibility (RACI) model."],
  ["People", "Training & education", "Ongoing technical training and exercises for analysts."],
  ["People", "Certification", "Relevant certifications maintained across the team."],
  ["People", "Talent retention", "Career paths, rotation and retention of skilled staff."],
  ["Process", "SOC management", "Management processes: planning, QA, continual improvement."],
  ["Process", "Incident management", "A defined incident-handling process with triage and escalation."],
  ["Process", "Detection engineering", "Managed use-case / detection-rule lifecycle."],
  ["Process", "Threat intelligence", "A CTI process feeding detection and response."],
  ["Process", "Reporting & metrics", "KPIs (MTTD/MTTA/MTTR) and reporting to stakeholders."],
  ["Technology", "SIEM / analytics", "A maintained SIEM with healthy log coverage."],
  ["Technology", "Endpoint detection (EDR)", "Endpoint detection & response coverage and tuning."],
  ["Technology", "Network detection (NDR)", "Network detection and visibility."],
  ["Technology", "SOAR / automation", "Orchestration and automation of repetitive response."],
  ["Technology", "Threat-intel platform", "A TIP integrating and operationalizing CTI."],
  ["Services", "Security monitoring", "Continuous monitoring and alert triage."],
  ["Services", "Incident response", "Responding to and recovering from incidents."],
  ["Services", "Threat hunting", "Proactive, hypothesis-driven hunting."],
  ["Services", "Vulnerability management", "Identifying and driving remediation of vulnerabilities."],
  ["Services", "Threat intelligence", "Producing and disseminating actionable CTI."],
];
const DOMAINS = ["Business", "People", "Process", "Technology", "Services"];

function cols(db: any, t: string): Set<string> { try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as any[]).map((c) => c.name)); } catch { return new Set(); } }
const r1 = (x: number | null) => (x == null ? null : Math.round(x * 10) / 10);

export function soccmmInventory(tenant: number | null): any {
  const db = getDb("XINCIDENT");
  const aspects = db.prepare("SELECT AspectID, Domain, Aspect, Description FROM SOCCMMASPECT ORDER BY SortOrder").all() as any[];
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const scores = new Map<number, any>();
  for (const s of (tenant != null ? db.prepare(`SELECT * FROM SOCCMMSCORE ${tw}`).all(tenant) : db.prepare("SELECT * FROM SOCCMMSCORE").all()) as any[]) scores.set(Number(s.AspectID), s);

  const rows = aspects.map((a) => {
    const s = scores.get(Number(a.AspectID));
    return { id: Number(a.AspectID), domain: String(a.Domain), aspect: String(a.Aspect), description: String(a.Description ?? ""),
      maturity: s && s.Maturity != null ? Number(s.Maturity) : null, importance: s && s.Importance != null ? Number(s.Importance) : 3, notes: s ? String(s.Notes ?? "") : "" };
  });
  const byDomain = DOMAINS.map((d) => {
    const list = rows.filter((r) => r.domain === d);
    const scored = list.filter((r) => r.maturity != null);
    const avg = scored.length ? scored.reduce((s, r) => s + (r.maturity || 0), 0) / scored.length : null;
    return { domain: d, aspects: list.length, scored: scored.length, maturity: r1(avg) };
  });
  const allScored = rows.filter((r) => r.maturity != null);
  const overall = allScored.length ? r1(allScored.reduce((s, r) => s + (r.maturity || 0), 0) / allScored.length) : null;
  const worklist = rows.filter((r) => r.maturity != null && r.maturity <= 2 && r.importance >= 3)
    .sort((a, b) => (b.importance - a.importance) || (a.maturity! - b.maturity!))
    .map((r) => ({ id: r.id, domain: r.domain, aspect: r.aspect, maturity: r.maturity, importance: r.importance, gap: 3 - (r.maturity || 0) })).slice(0, 30);

  return {
    levels: MATURITY, domains: byDomain, rows,
    summary: { overall, target: 3, aspects: rows.length, scored: allScored.length, coverage: rows.length ? Math.round((allScored.length / rows.length) * 100) : 0, belowTarget: rows.filter((r) => r.maturity != null && r.maturity < 3).length },
    worklist,
  };
}

export function saveScore(aspectId: number, p: { maturity?: number; importance?: number; notes?: string }, tenant: number | null): boolean {
  const db = getDb("XINCIDENT");
  if (!db.prepare("SELECT 1 FROM SOCCMMASPECT WHERE AspectID = ?").get(aspectId)) return false;
  const now = new Date().toISOString();
  const ex = db.prepare("SELECT ScoreID FROM SOCCMMSCORE WHERE AspectID = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(aspectId, tenant) as { ScoreID: number } | undefined;
  const mat = p.maturity != null ? Math.max(0, Math.min(5, Math.round(p.maturity))) : null;
  const imp = p.importance != null ? Math.max(1, Math.min(5, Math.round(p.importance))) : null;
  if (ex) {
    const sets: string[] = ["AssessedDate = ?"]; const vals: unknown[] = [now];
    if (mat != null) { sets.push("Maturity = ?"); vals.push(mat); }
    if (imp != null) { sets.push("Importance = ?"); vals.push(imp); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
    vals.push(ex.ScoreID);
    db.prepare(`UPDATE SOCCMMSCORE SET ${sets.join(", ")} WHERE ScoreID = ?`).run(...vals);
  } else {
    const id = allocId(db, "SOCCMMSCORE", "ScoreID");
    db.prepare("INSERT INTO SOCCMMSCORE (ScoreID, AspectID, Maturity, Importance, Notes, AssessedDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?)")
      .run(id, aspectId, mat ?? 0, imp ?? 3, String(p.notes ?? "").slice(0, 1000), now, tenant, now);
  }
  return true;
}

export function seedSocCmm(tenant: number): { aspects: number; scores: number } {
  const db = getDb("XINCIDENT");
  let a = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM SOCCMMASPECT").get() as { n: number }).n) {
    let id = 1;
    const ins = db.prepare("INSERT INTO SOCCMMASPECT (AspectID, Domain, Aspect, Description, Weight, SortOrder) VALUES (?,?,?,?,1,?)");
    ASPECTS.forEach((x, i) => { ins.run(id++, x[0], x[1], x[2], i); a++; });
  }
  // demo scores: realistic mid-maturity profile for tenant
  let sc = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM SOCCMMSCORE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    const aspects = db.prepare("SELECT AspectID, Domain, Aspect FROM SOCCMMASPECT ORDER BY SortOrder").all() as any[];
    const base: Record<string, number> = { Business: 2, People: 2, Process: 3, Technology: 3, Services: 3 };
    for (const asp of aspects) {
      const m = Math.max(0, Math.min(5, base[asp.Domain] + ((asp.AspectID * 7) % 3) - 1));
      const imp = 2 + ((asp.AspectID * 3) % 4); // 2..5
      saveScore(asp.AspectID, { maturity: m, importance: Math.min(5, imp) }, tenant); sc++;
    }
  }
  return { aspects: a, scores: sc };
}
