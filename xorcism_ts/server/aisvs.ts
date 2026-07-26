/**
 * aisvs.ts — OWASP AISVS (AI Security Verification Standard) verification-assessment cockpit (/aisvs).
 *
 * The AISVS is the AI-security counterpart of the OWASP ASVS: 16 parts, 203 auditable questions
 * (192 official control references) covering training-data integrity, input validation, model
 * lifecycle, infra/deployment, access control, supply chain, output safety, memory/vector DBs,
 * agentic orchestration, MCP security, adversarial robustness and monitoring — each control graded
 * for assurance level L1/L2/L3 and carrying a weight and cross-framework mappings (ISO 27001, NIST
 * CSF 2.0, NIS2, EU AI Act).
 *
 * This turns it into a weighted verification AUDIT: pick a target level (L1/L2/L3) to scope the
 * controls, answer each with the AISVS maturity scale (fully / largely / partial / planned / not /
 * n-a), attach evidence, and read back the weighted verification score per part and overall, the
 * gaps, and the EU-AI-Act coverage. Both an audit instrument and an AI-security-management view.
 *
 * Tables live in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like cra.ts / smematurity.ts / miniciso.ts).
 * The 203 questions + mappings are baked in data/aisvsCatalogue.ts (single source of truth).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { AISVS_CATALOGUE, AisvsControl } from "./data/aisvsCatalogue";

const now = (): string => new Date().toISOString();
export const AISVS_LEVELS = ["L1", "L2", "L3"] as const;
export const AISVS_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

/** The AISVS maturity answer scale (verbatim from "HOW TO ANSWER THIS CONTROL") → an effectiveness
 * fraction used for the weighted verification score. `na` is excluded from the denominator. */
export const AISVS_ANSWERS = [
  { key: "fully", label: "Fully implemented", eff: 1 },
  { key: "largely", label: "Largely implemented", eff: 0.75 },
  { key: "partial", label: "Partially implemented", eff: 0.4 },
  { key: "planned", label: "Planned", eff: 0.15 },
  { key: "not", label: "Not implemented", eff: 0 },
  { key: "na", label: "Not applicable", eff: -1 },     // eff -1 == excluded
] as const;
const EFF = new Map<string, number>(AISVS_ANSWERS.map((a) => [a.key, a.eff]));

const REFS = new Map<string, AisvsControl>();
for (const c of AISVS_CATALOGUE.controls) REFS.set(c.ref, c);

/** Controls in scope for a target level: L1→L1 only, L2→L1+L2, L3→everything (levels are cumulative). */
export function scopeFor(level: string): AisvsControl[] {
  const want = level === "L1" ? ["L1"] : level === "L2" ? ["L1", "L2"] : ["L1", "L2", "L3"];
  return AISVS_CATALOGUE.controls.filter((c) => c.levels.some((l) => want.includes(l)));
}

export function ensureAisvsTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS AISVSASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, SystemName TEXT, TargetLevel TEXT, Assessor TEXT, Status TEXT,
      Score REAL, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AISVSANSWER(
      AnswerID INTEGER PRIMARY KEY, AssessmentID INTEGER, Ref TEXT, PartNum INTEGER,
      Answer TEXT, Evidence TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_aisvsassess_tenant ON AISVSASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aisvsanswer_assess ON AISVSANSWER(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_aisvsanswer_ref ON AISVSANSWER(AssessmentID, Ref);
  `);
}
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");
const round1 = (n: number): number => Math.round(n * 10) / 10;

export function aisvsCatalogue(): { version: string; source: string; levels: readonly string[];
  answers: typeof AISVS_ANSWERS; parts: { num: number; name: string; total: number; controls: AisvsControl[] }[] } {
  const parts = AISVS_CATALOGUE.parts.map((p) => {
    const controls = AISVS_CATALOGUE.controls.filter((c) => c.part === p.num);
    return { num: p.num, name: p.name, total: controls.length, controls };
  });
  return { version: AISVS_CATALOGUE.version, source: AISVS_CATALOGUE.source, levels: AISVS_LEVELS, answers: AISVS_ANSWERS, parts };
}

// ── scoring ───────────────────────────────────────────────────────────────────
export interface AisvsScore {
  targetLevel: string; scope: number; answered: number; verification: number;
  parts: { num: number; name: string; scope: number; answered: number; verification: number;
    weight: number; earned: number; fully: number; gaps: number }[];
  answers: Record<string, string>; distribution: Record<string, number>;
  gaps: number; naCount: number; aiActInScope: number;
}

export function scoreAssessment(level: string, ans: Map<string, string>): AisvsScore {
  const scope = scopeFor(level);
  const inScope = new Set(scope.map((c) => c.ref));
  const parts = AISVS_CATALOGUE.parts.map((p) => {
    const ctrls = scope.filter((c) => c.part === p.num);
    let weight = 0, earned = 0, answered = 0, fully = 0, gaps = 0;
    for (const c of ctrls) {
      const a = ans.get(c.ref);
      const eff = a ? EFF.get(a) ?? null : null;
      if (a) answered++;
      if (eff === -1) continue;                     // n/a → out of the denominator
      weight += c.weight;
      if (eff != null && eff >= 0) earned += c.weight * eff;
      if (a === "fully") fully++;
      if (a && a !== "fully" && eff !== -1) gaps++;
    }
    return { num: p.num, name: p.name, scope: ctrls.length, answered, weight, earned,
      verification: weight > 0 ? Math.round((earned / weight) * 100) : 0, fully, gaps };
  }).filter((p) => p.scope > 0);
  const totalWeight = parts.reduce((n, p) => n + p.weight, 0);
  const totalEarned = parts.reduce((n, p) => n + p.earned, 0);
  const distribution: Record<string, number> = {};
  for (const a of AISVS_ANSWERS) distribution[a.key] = 0;
  let naCount = 0, gaps = 0;
  for (const [ref, a] of ans) { if (!inScope.has(ref)) continue; distribution[a] = (distribution[a] || 0) + 1; if (a === "na") naCount++; else if (a !== "fully") gaps++; }
  return {
    targetLevel: level, scope: scope.length,
    answered: [...ans.keys()].filter((r) => inScope.has(r)).length,
    verification: totalWeight > 0 ? Math.round((totalEarned / totalWeight) * 100) : 0,
    parts, answers: Object.fromEntries([...ans.entries()].filter(([r]) => inScope.has(r))),
    distribution, gaps, naCount,
    aiActInScope: scope.filter((c) => c.aiAct).length,
  };
}

// ── assessments ────────────────────────────────────────────────────────────────
export interface AisvsAssessmentRow {
  id: number; name: string; systemName: string; targetLevel: string; assessor: string; status: string;
  verification: number; scope: number; answered: number; gaps: number; notes: string;
  createdDate: string; updatedDate: string;
}

function answersFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT Ref, Answer FROM AISVSANSWER WHERE AssessmentID=?").all(id) as { Ref: string; Answer: string }[])
    .map((r) => [r.Ref, r.Answer]));
}
function evidenceFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT Ref, Evidence FROM AISVSANSWER WHERE AssessmentID=?").all(id) as { Ref: string; Evidence: string }[])
    .map((r) => [r.Ref, r.Evidence || ""]));
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): AisvsAssessmentRow {
  const sc = scoreAssessment(r.TargetLevel || "L1", answersFor(db, r.AssessmentID));
  return {
    id: r.AssessmentID, name: r.Name || "", systemName: r.SystemName || "", targetLevel: r.TargetLevel || "L1",
    assessor: r.Assessor || "", status: r.Status || "draft", verification: sc.verification, scope: sc.scope,
    answered: sc.answered, gaps: sc.gaps, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function aisvsDashboard(tenant: number | null): {
  assessments: AisvsAssessmentRow[];
  summary: { assessments: number; completed: number; avgVerification: number; l3: number; openGaps: number };
  catalogue: { version: string; parts: number; controls: number; questions: number };
} {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM AISVSASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.answered > 0);
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      completed: assessments.filter((a) => a.status === "completed").length,
      avgVerification: scored.length ? Math.round(scored.reduce((n, a) => n + a.verification, 0) / scored.length) : 0,
      l3: assessments.filter((a) => a.targetLevel === "L3").length,
      openGaps: assessments.reduce((n, a) => n + a.gaps, 0),
    },
    catalogue: { version: AISVS_CATALOGUE.version, parts: AISVS_CATALOGUE.parts.length,
      controls: new Set(AISVS_CATALOGUE.controls.map((c) => c.ref.replace(/\.[a-z]$/, ""))).size,
      questions: AISVS_CATALOGUE.controls.length },
  };
}

export function aisvsDetail(id: number, tenant: number | null): {
  assessment: AisvsAssessmentRow; score: AisvsScore;
  parts: { num: number; name: string; verification: number; controls: any[] }[];
} | null {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM AISVSASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const level = r.TargetLevel || "L1";
  const ans = answersFor(db, id); const ev = evidenceFor(db, id);
  const sc = scoreAssessment(level, ans);
  const scope = new Set(scopeFor(level).map((c) => c.ref));
  const parts = sc.parts.map((p) => ({
    num: p.num, name: p.name, verification: p.verification,
    controls: AISVS_CATALOGUE.controls.filter((c) => c.part === p.num && scope.has(c.ref)).map((c) => ({
      ref: c.ref, title: c.title, levels: c.levels, weight: c.weight, requirement: c.requirement,
      question: c.question, evidence: c.evidence, iso27001: c.iso27001, nistCsf: c.nistCsf, nis2: c.nis2, aiAct: c.aiAct,
      answer: ans.get(c.ref) || "", evidenceNote: ev.get(c.ref) || "",
    })),
  }));
  return { assessment: rowToAssessment(db, r), score: sc, parts };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "AISVSASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  const level = AISVS_LEVELS.includes(s("targetLevel") as any) ? s("targetLevel") : "L2";
  db.prepare(
    `INSERT INTO AISVSASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, SystemName, TargetLevel,
       Assessor, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "AISVS verification assessment", s("systemName", 200),
    level, s("assessor", 200), "draft", 0, s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM AISVSANSWER WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM AISVSASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM AISVSASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", systemName: "SystemName", assessor: "Assessor", notes: "Notes" };
  for (const [k, col] of Object.entries(map)) if (k in b) { sets.push(`${col}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("targetLevel" in b && AISVS_LEVELS.includes(String(b.targetLevel) as any)) { sets.push("TargetLevel=?"); vals.push(String(b.targetLevel)); }
  if ("status" in b && (AISVS_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE AISVSASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  refreshScore(db, id);
  return { ok: true };
}

export function setAnswer(id: number, ref: string, answer: string, evidence?: string): { ok: boolean; error?: string } {
  ensureAisvsTables();
  const c = REFS.get(ref);
  if (!c) return { ok: false, error: `unknown control ${ref}` };
  const valid = answer === "" || AISVS_ANSWERS.some((a) => a.key === answer);
  if (!valid) return { ok: false, error: "invalid answer" };
  const db = getDb("XCOMPLIANCE");
  if (answer === "" && evidence == null) {
    db.prepare("DELETE FROM AISVSANSWER WHERE AssessmentID=? AND Ref=?").run(id, ref);
  } else {
    const ex = db.prepare("SELECT AnswerID, Answer, Evidence FROM AISVSANSWER WHERE AssessmentID=? AND Ref=?").get(id, ref) as { AnswerID: number; Answer: string; Evidence: string } | undefined;
    if (ex) {
      db.prepare("UPDATE AISVSANSWER SET Answer=?, Evidence=?, UpdatedDate=? WHERE AnswerID=?")
        .run(answer || ex.Answer, evidence != null ? String(evidence).slice(0, 3000) : ex.Evidence, now(), ex.AnswerID);
    } else {
      db.prepare("INSERT INTO AISVSANSWER (AnswerID, AssessmentID, Ref, PartNum, Answer, Evidence, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
        .run(allocId(db, "AISVSANSWER", "AnswerID"), id, ref, c.part, answer, evidence != null ? String(evidence).slice(0, 3000) : "", now());
    }
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const r = db.prepare("SELECT TargetLevel FROM AISVSASSESSMENT WHERE AssessmentID=?").get(id) as { TargetLevel: string } | undefined;
  if (!r) return;
  const sc = scoreAssessment(r.TargetLevel || "L1", answersFor(db, id));
  const status = sc.answered === 0 ? "draft" : sc.answered >= sc.scope ? "completed" : "in-progress";
  db.prepare("UPDATE AISVSASSESSMENT SET Score=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.verification, status, now(), id);
}

/** Import a filled AISVS assessment (connector path): answers by ref. */
export function importAssessment(tenant: number | null, payload: {
  name?: string; systemName?: string; targetLevel?: string; assessor?: string;
  answers: { ref: string; answer: string; evidence?: string }[];
}): { id: number; imported: number; created: boolean } {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const name = (payload.name || "AISVS verification assessment").slice(0, 300);
  const args = tenant == null ? [name] : [name, tenant];
  const found = db.prepare(`SELECT AssessmentID FROM AISVSASSESSMENT WHERE Name=? AND ${tw(tenant)}`).get(...args) as { AssessmentID: number } | undefined;
  const id = found ? found.AssessmentID : createAssessment(tenant, payload).id;
  if (found) updateAssessment(id, tenant, payload);
  let imported = 0;
  for (const a of payload.answers || []) {
    if (REFS.has(a.ref) && AISVS_ANSWERS.some((x) => x.key === a.answer)) { setAnswer(id, a.ref, a.answer, a.evidence); imported++; }
  }
  return { id, imported, created: !found };
}

// ── demo ────────────────────────────────────────────────────────────────────
export function seedAisvsDemo(tenant: number): void {
  ensureAisvsTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — LLM assistant AISVS verification (L2)";
  if (db.prepare("SELECT 1 FROM AISVSASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, systemName: "Customer support LLM assistant", targetLevel: "L2", assessor: "AI security lead" });
  // score a representative sample across the parts so the demo shows a partial verification profile
  const seedAns: Record<string, string> = {};
  const scope = scopeFor("L2");
  const pattern = ["fully", "fully", "largely", "partial", "planned", "not", "fully", "largely", "na", "partial"];
  scope.forEach((c, i) => { if (i % 3 !== 2) seedAns[c.ref] = pattern[i % pattern.length]; });   // ~2/3 answered
  for (const [ref, a] of Object.entries(seedAns)) setAnswer(id, ref, a);
  db.prepare("UPDATE AISVSASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
