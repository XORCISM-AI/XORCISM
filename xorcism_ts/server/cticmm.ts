/**
 * cticmm.ts — CTI-CMM (Cyber Threat Intelligence Capability Maturity Model, cti-cmm.org) assessment.
 *
 * Replicates the CTI-CMM assessment tool: the 11 stakeholder-aligned domains, each broken into CTI
 * use cases, scored on the CTI0–CTI3 maturity scale (Pre-Foundational / Foundational / Advanced /
 * Leading). Because not every domain services every organisation, each domain can be marked
 * out-of-scope. Domain maturity = mean of its in-scope use-case scores; overall maturity = the mean
 * across in-scope domains (as the tool does). Produces a per-domain radar and a gap worklist
 * (use cases below the target level). Named assessments so a CTI program can track over time.
 *
 * Tables in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like aisvs.ts / cc.ts). Only the CTI-CMM structure
 * (domains + use cases) is baked in data/cticmmCatalogue.ts — the 230 © normative practice
 * statements are not reproduced; score each use case against the official book.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { CTICMM_CATALOGUE, CtiDomain } from "./data/cticmmCatalogue";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");
export const CTI_LEVELS = ["CTI0", "CTI1", "CTI2", "CTI3"] as const;      // 0..3
export const CTI_LEVEL_NAMES = ["Pre-Foundational", "Foundational", "Advanced", "Leading"];
export const CTI_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

const DOMAINS = CTICMM_CATALOGUE.domains;
const UC = new Map<string, { domain: string; targetLevel: number }>();
for (const d of DOMAINS) for (const u of d.useCases) UC.set(u.id, { domain: d.code, targetLevel: u.targetLevel });
const round1 = (n: number | null): number | null => (n == null ? null : Math.round(n * 10) / 10);

export function ensureCtiCmmTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS CTICMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, ProgramName TEXT, Assessor TEXT, TargetLevel INTEGER DEFAULT 2, Status TEXT,
      Score REAL, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CTICMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, UseCaseId TEXT, Domain TEXT,
      Level REAL, Notes TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CTICMMDOMAIN(
      RowID INTEGER PRIMARY KEY, AssessmentID INTEGER, DomainCode TEXT, Applicable INTEGER DEFAULT 1);
    CREATE INDEX IF NOT EXISTS ix_cticmm_tenant ON CTICMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_cticmmscore_assess ON CTICMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_cticmmscore ON CTICMMSCORE(AssessmentID, UseCaseId);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_cticmmdomain ON CTICMMDOMAIN(AssessmentID, DomainCode);
  `);
}

export function cticmmCatalogue(): typeof CTICMM_CATALOGUE { return CTICMM_CATALOGUE; }

// ── scoring ─────────────────────────────────────────────────────────────────────
export interface CtiScore {
  overall: number | null; target: number; scored: number; total: number; coverage: number;
  domainsInScope: number; belowTarget: number;
  domains: { code: string; name: string; applicable: boolean; maturity: number | null; scored: number; total: number }[];
  radar: { domain: string; value: number | null; target: number }[];
  worklist: { useCaseId: string; domain: string; useCase: string; level: number | null; target: number; gap: number }[];
}

export function scoreAssessment(target: number, scores: Map<string, number>, naDomains: Set<string>): CtiScore {
  const ucName = new Map<string, string>();
  for (const d of DOMAINS) for (const u of d.useCases) ucName.set(u.id, u.name);

  const domains = DOMAINS.map((d) => {
    const applicable = !naDomains.has(d.code);
    const list = d.useCases.map((u) => scores.get(u.id)).filter((v): v is number => v != null);
    const mat = applicable && list.length ? list.reduce((s, v) => s + v, 0) / list.length : null;
    return { code: d.code, name: d.name, applicable, maturity: round1(mat), scored: list.length, total: d.useCases.length };
  });

  const scopedDomains = domains.filter((d) => d.applicable);
  const scoredDomains = scopedDomains.filter((d) => d.maturity != null);
  const overall = scoredDomains.length ? round1(scoredDomains.reduce((s, d) => s + (d.maturity as number), 0) / scoredDomains.length) : null;

  const totalUc = DOMAINS.filter((d) => !naDomains.has(d.code)).reduce((n, d) => n + d.useCases.length, 0);
  const scoredUc = [...scores.keys()].filter((id) => UC.has(id) && !naDomains.has(UC.get(id)!.domain)).length;

  const worklist: CtiScore["worklist"] = [];
  for (const [id, meta] of UC) {
    if (naDomains.has(meta.domain)) continue;
    const v = scores.get(id);
    if (v != null && v < target) {
      worklist.push({ useCaseId: id, domain: meta.domain, useCase: ucName.get(id) || id, level: v, target, gap: round1(target - v) as number });
    }
  }
  worklist.sort((a, b) => b.gap - a.gap);

  return {
    overall, target, scored: scoredUc, total: totalUc,
    coverage: totalUc ? Math.round((scoredUc / totalUc) * 100) : 0,
    domainsInScope: scopedDomains.length,
    belowTarget: worklist.length,
    domains,
    radar: domains.map((d) => ({ domain: d.code, value: d.applicable ? d.maturity : null, target })),
    worklist: worklist.slice(0, 30),
  };
}

// ── assessments ─────────────────────────────────────────────────────────────────
export interface CtiAssessmentRow {
  id: number; name: string; programName: string; assessor: string; targetLevel: number; status: string;
  overall: number | null; scored: number; total: number; belowTarget: number; notes: string;
  createdDate: string; updatedDate: string;
}

function scoresFor(db: ReturnType<typeof getDb>, id: number): Map<string, number> {
  return new Map((db.prepare("SELECT UseCaseId, Level FROM CTICMMSCORE WHERE AssessmentID=?").all(id) as { UseCaseId: string; Level: number }[])
    .filter((r) => r.Level != null).map((r) => [r.UseCaseId, Number(r.Level)]));
}
function naFor(db: ReturnType<typeof getDb>, id: number): Set<string> {
  return new Set((db.prepare("SELECT DomainCode FROM CTICMMDOMAIN WHERE AssessmentID=? AND Applicable=0").all(id) as { DomainCode: string }[]).map((r) => r.DomainCode));
}
function notesFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT UseCaseId, Notes FROM CTICMMSCORE WHERE AssessmentID=?").all(id) as { UseCaseId: string; Notes: string }[]).map((r) => [r.UseCaseId, r.Notes || ""]));
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): CtiAssessmentRow {
  const sc = scoreAssessment(r.TargetLevel || 2, scoresFor(db, r.AssessmentID), naFor(db, r.AssessmentID));
  return {
    id: r.AssessmentID, name: r.Name || "", programName: r.ProgramName || "", assessor: r.Assessor || "",
    targetLevel: r.TargetLevel || 2, status: r.Status || "draft", overall: sc.overall, scored: sc.scored,
    total: sc.total, belowTarget: sc.belowTarget, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function cticmmDashboard(tenant: number | null): any {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM CTICMMASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.scored > 0 && a.overall != null);
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      completed: assessments.filter((a) => a.status === "completed").length,
      avgMaturity: scored.length ? round1(scored.reduce((n, a) => n + (a.overall as number), 0) / scored.length) : null,
      openGaps: assessments.reduce((n, a) => n + a.belowTarget, 0),
    },
    catalogue: { version: CTICMM_CATALOGUE.version, domains: DOMAINS.length, useCases: DOMAINS.reduce((n, d) => n + d.useCases.length, 0) },
  };
}

export function cticmmDetail(id: number, tenant: number | null): any {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM CTICMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const scores = scoresFor(db, id), na = naFor(db, id), notes = notesFor(db, id);
  const sc = scoreAssessment(r.TargetLevel || 2, scores, na);
  const domains = DOMAINS.map((d: CtiDomain) => {
    const ds = sc.domains.find((x) => x.code === d.code)!;
    return {
      code: d.code, name: d.name, purpose: d.purpose, mission: d.mission, dataSources: d.dataSources,
      applicable: !na.has(d.code), maturity: ds.maturity, scored: ds.scored, total: ds.total,
      useCases: d.useCases.map((u) => ({
        id: u.id, name: u.name, cti1: u.cti1, cti2: u.cti2, cti3: u.cti3, practices: u.practices, targetLevel: u.targetLevel,
        level: scores.has(u.id) ? scores.get(u.id) : null, notes: notes.get(u.id) || "",
      })),
    };
  });
  return { assessment: rowToAssessment(db, r), score: sc, levels: CTI_LEVELS, levelNames: CTI_LEVEL_NAMES, domains };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "CTICMMASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  const tgt = Math.max(1, Math.min(3, Number(b.targetLevel) || 2));
  db.prepare(
    `INSERT INTO CTICMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, ProgramName, Assessor,
       TargetLevel, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "CTI-CMM assessment", s("programName", 200), s("assessor", 200),
    tgt, "draft", 0, s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM CTICMMSCORE WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM CTICMMDOMAIN WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM CTICMMASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM CTICMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", programName: "ProgramName", assessor: "Assessor", notes: "Notes" };
  for (const [k, c] of Object.entries(map)) if (k in b) { sets.push(`${c}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("targetLevel" in b) { sets.push("TargetLevel=?"); vals.push(Math.max(1, Math.min(3, Number(b.targetLevel) || 2))); }
  if ("status" in b && (CTI_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE CTICMMASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  refreshScore(db, id);
  return { ok: true };
}

/** Score one use case on CTI0–CTI3 ("" / null clears it). */
export function setScore(id: number, useCaseId: string, level: number | null, notes?: string): { ok: boolean; error?: string } {
  ensureCtiCmmTables();
  const meta = UC.get(useCaseId);
  if (!meta) return { ok: false, error: `unknown use case ${useCaseId}` };
  const db = getDb("XCOMPLIANCE");
  const lvl = level == null ? null : Math.max(0, Math.min(3, Math.round(level * 2) / 2));
  const ex = db.prepare("SELECT ScoreID, Level, Notes FROM CTICMMSCORE WHERE AssessmentID=? AND UseCaseId=?").get(id, useCaseId) as any;
  if (lvl == null && notes == null) {
    if (ex) db.prepare("DELETE FROM CTICMMSCORE WHERE ScoreID=?").run(ex.ScoreID);
  } else if (ex) {
    db.prepare("UPDATE CTICMMSCORE SET Level=?, Notes=?, UpdatedDate=? WHERE ScoreID=?")
      .run(lvl != null ? lvl : ex.Level, notes != null ? String(notes).slice(0, 2000) : ex.Notes, now(), ex.ScoreID);
  } else {
    db.prepare("INSERT INTO CTICMMSCORE (ScoreID, AssessmentID, UseCaseId, Domain, Level, Notes, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
      .run(allocId(db, "CTICMMSCORE", "ScoreID"), id, useCaseId, meta.domain, lvl, notes != null ? String(notes).slice(0, 2000) : "", now());
  }
  refreshScore(db, id);
  return { ok: true };
}

export function setDomainApplicable(id: number, domainCode: string, applicable: boolean): { ok: boolean; error?: string } {
  ensureCtiCmmTables();
  if (!DOMAINS.some((d) => d.code === domainCode)) return { ok: false, error: "unknown domain" };
  const db = getDb("XCOMPLIANCE");
  const ex = db.prepare("SELECT RowID FROM CTICMMDOMAIN WHERE AssessmentID=? AND DomainCode=?").get(id, domainCode) as any;
  if (ex) db.prepare("UPDATE CTICMMDOMAIN SET Applicable=? WHERE RowID=?").run(applicable ? 1 : 0, ex.RowID);
  else db.prepare("INSERT INTO CTICMMDOMAIN (RowID, AssessmentID, DomainCode, Applicable) VALUES (?,?,?,?)")
    .run(allocId(db, "CTICMMDOMAIN", "RowID"), id, domainCode, applicable ? 1 : 0);
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const r = db.prepare("SELECT TargetLevel FROM CTICMMASSESSMENT WHERE AssessmentID=?").get(id) as { TargetLevel: number } | undefined;
  if (!r) return;
  const sc = scoreAssessment(r.TargetLevel || 2, scoresFor(db, id), naFor(db, id));
  const status = sc.scored === 0 ? "draft" : sc.scored >= sc.total ? "completed" : "in-progress";
  db.prepare("UPDATE CTICMMASSESSMENT SET Score=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.overall ?? 0, status, now(), id);
}

// ── demo ──────────────────────────────────────────────────────────────────────────
export function seedCtiCmmDemo(tenant: number): void {
  ensureCtiCmmTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Enterprise CTI program (CTI-CMM)";
  if (db.prepare("SELECT 1 FROM CTICMMASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, programName: "Global Threat Intelligence", assessor: "Head of CTI", targetLevel: 2 });
  // mark FRAUD out of scope; score the rest with a realistic profile
  setDomainApplicable(id, "FRAUD", false);
  const pattern = [2, 2, 1, 3, 2, 1, 2, 3, 1, 2];
  let i = 0;
  for (const d of DOMAINS) {
    if (d.code === "FRAUD") continue;
    for (const u of d.useCases) { if (i % 5 !== 4) setScore(id, u.id, pattern[i % pattern.length]); i++; }
  }
  db.prepare("UPDATE CTICMMASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
