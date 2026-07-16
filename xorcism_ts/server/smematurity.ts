/**
 * smematurity.ts — ENISA SME Cyber Resilience Maturity Assessment cockpit (/cra-maturity).
 *
 * A faithful, native replication of ENISA's "SME Cyber Resilience Maturity Assessment Model"
 * (July 2026) and its Excel self-check tool. An SME scores 25 questions across five domains
 * (governance, risk/security-by-design, vulnerability & patch, product lifecycle, awareness) on
 * the 1-5 anchored rubric; the engine computes each domain average, the overall score, the RAG
 * flag per question, the overall maturity band (Basic / Intermediate / Advanced) and a prioritised
 * improvement roadmap drawn from the model's Annex B checklist for the current band.
 *
 * It is a maturity self-check, NOT a compliance proof — an advanced score does not replace CRA
 * legal obligations (ENISA is explicit on this). The five domains map onto CRA Annex I / Articles
 * 13-14 (see SME_CATALOGUE[].cra), so this cockpit is a companion to /cra-compliance (cra.ts) and
 * /common-criteria (cc.ts). The question/rubric/checklist content lives in
 * data/smeMaturityCatalogue.ts (the single source of truth, also the connector's import shape).
 *
 * Tables live in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like cra.ts / cc.ts / ess8.ts).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { SME_CATALOGUE, SmeBand } from "./data/smeMaturityCatalogue";

const now = (): string => new Date().toISOString();
export const SME_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

export interface SmeCatalogueView {
  title: string; version: string; source: string;
  levels: typeof SME_CATALOGUE.levels; bands: SmeBand[];
  domains: { domain: string; key: string; name: string; cra: string;
    questions: { ref: string; question: string; anchors: string[] }[] }[];
}

export function ensureSmeTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS SMEMATURITYASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, ProductScope TEXT, Assessor TEXT, Status TEXT,
      OverallScore REAL, Band TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS SMEMATURITYANSWER(
      AnswerID INTEGER PRIMARY KEY, AssessmentID INTEGER, Ref TEXT, DomainKey TEXT,
      Score INTEGER, Evidence TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_smeassess_tenant ON SMEMATURITYASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_smeanswer_assess ON SMEMATURITYANSWER(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_smeanswer_ref ON SMEMATURITYANSWER(AssessmentID, Ref);
  `);
}

const tw = (tenant: number | null): string => (tenant == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

// ── scoring ─────────────────────────────────────────────────────────────────
const REFS = new Map<string, { domainKey: string; domain: string }>();
for (const d of SME_CATALOGUE.domains) for (const q of d.questions) REFS.set(q.ref, { domainKey: d.key, domain: d.domain });
const TOTAL_QUESTIONS = REFS.size;
const round1 = (n: number): number => Math.round(n * 10) / 10;

/** ENISA band for an overall/domain score (Basic 1-2.5, Intermediate 2.6-3.9, Advanced 4-5). */
export function bandFor(score: number): SmeBand {
  // scores below the first band's max fall to BASIC; use max thresholds so the 2.5/2.6 & 3.9/4.0
  // boundaries match the published table exactly.
  const bands = SME_CATALOGUE.bands;
  for (const b of bands) if (score <= b.max + 1e-9) return b;
  return bands[bands.length - 1];
}

/** Per-question RAG: 1-2 needs work, 3 moderate, 4-5 good (ENISA Pivots sheet). */
export function ragFor(score: number): { key: string; label: string } {
  if (score >= 4) return { key: "good", label: "Good" };
  if (score >= 3) return { key: "moderate", label: "Moderate" };
  return { key: "needs-work", label: "Needs Work" };
}

export function smeCatalogue(): SmeCatalogueView {
  return {
    title: SME_CATALOGUE.title, version: SME_CATALOGUE.version, source: SME_CATALOGUE.source,
    levels: SME_CATALOGUE.levels, bands: SME_CATALOGUE.bands,
    domains: SME_CATALOGUE.domains.map((d) => ({
      domain: d.domain, key: d.key, name: d.name, cra: d.cra,
      questions: d.questions.map((q) => ({ ref: q.ref, question: q.question, anchors: q.anchors })),
    })),
  };
}

// ── assessments ─────────────────────────────────────────────────────────────
export interface SmeAssessmentRow {
  id: number; name: string; orgName: string; productScope: string; assessor: string;
  status: string; overallScore: number; band: string; bandLabel: string; answered: number;
  total: number; notes: string; createdDate: string; updatedDate: string;
}

function answersFor(db: ReturnType<typeof getDb>, id: number): Map<string, { score: number; evidence: string }> {
  const rows = db.prepare("SELECT Ref, Score, Evidence FROM SMEMATURITYANSWER WHERE AssessmentID=?").all(id) as
    { Ref: string; Score: number; Evidence: string }[];
  return new Map(rows.map((r) => [r.Ref, { score: r.Score, evidence: r.Evidence || "" }]));
}

/** Domain averages + overall score for one assessment (mean of answered questions per ENISA §Step 2). */
export function scoreAssessment(ans: Map<string, { score: number }>): {
  overall: number; answered: number; total: number;
  domains: { key: string; domain: string; name: string; avg: number; answered: number; gapTo5: number; band: string }[];
  distribution: number[]; atOrAboveL3: number; belowL3: number;
} {
  const domains = SME_CATALOGUE.domains.map((d) => {
    const scores = d.questions.map((q) => ans.get(q.ref)?.score).filter((s): s is number => typeof s === "number" && s >= 1);
    const avg = scores.length ? round1(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    return { key: d.key, domain: d.domain, name: d.name, avg, answered: scores.length,
      gapTo5: scores.length ? round1(5 - avg) : 5, band: bandFor(avg || 1).key };
  });
  const all = [...ans.values()].map((v) => v.score).filter((s) => s >= 1);
  const overall = all.length ? round1(all.reduce((a, b) => a + b, 0) / all.length) : 0;
  const distribution = [0, 0, 0, 0, 0];
  for (const s of all) if (s >= 1 && s <= 5) distribution[s - 1]++;
  return {
    overall, answered: all.length, total: TOTAL_QUESTIONS, domains, distribution,
    atOrAboveL3: all.filter((s) => s >= 3).length, belowL3: all.filter((s) => s < 3).length,
  };
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): SmeAssessmentRow {
  const ans = answersFor(db, r.AssessmentID);
  const sc = scoreAssessment(ans);
  const b = bandFor(sc.overall || 1);
  return {
    id: r.AssessmentID, name: r.Name || "", orgName: r.OrgName || "", productScope: r.ProductScope || "",
    assessor: r.Assessor || "", status: r.Status || "draft", overallScore: sc.overall,
    band: sc.answered ? b.key : "", bandLabel: sc.answered ? b.label : "", answered: sc.answered,
    total: TOTAL_QUESTIONS, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function smeDashboard(tenant: number | null): {
  assessments: SmeAssessmentRow[];
  summary: { assessments: number; completed: number; avgScore: number; advanced: number; intermediate: number; basic: number };
  catalogue: { domains: number; questions: number };
} {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM SMEMATURITYASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.answered > 0);
  const avg = scored.length ? round1(scored.reduce((n, a) => n + a.overallScore, 0) / scored.length) : 0;
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      completed: assessments.filter((a) => a.status === "completed").length,
      avgScore: avg,
      advanced: scored.filter((a) => a.band === "ADVANCED").length,
      intermediate: scored.filter((a) => a.band === "INTERMEDIATE").length,
      basic: scored.filter((a) => a.band === "BASIC").length,
    },
    catalogue: { domains: SME_CATALOGUE.domains.length, questions: TOTAL_QUESTIONS },
  };
}

/** The prioritised improvement roadmap: the current band's Annex B checklist, lowest domains first. */
export function roadmapFor(band: string, domainAvgs: { key: string; domain: string; avg: number }[]): {
  band: string; bandSummary: string; groups: { domain: string; avg: number; priority: boolean; actions: string[] }[];
} {
  const cat = SME_CATALOGUE;
  const items = cat.checklist[band] || cat.checklist.BASIC;
  const bandMeta = cat.bands.find((b) => b.key === band) || cat.bands[0];
  // map a checklist "domain" label (Governance/Risk Mgmt/...) back to a model domain key for ordering
  const byLabel = new Map<string, { key: string; avg: number }>();
  for (const d of cat.domains) for (const cl of d.checklistDomains) {
    const da = domainAvgs.find((x) => x.key === d.key);
    byLabel.set(cl, { key: d.key, avg: da ? da.avg : 0 });
  }
  const grouped = new Map<string, string[]>();
  for (const it of items) (grouped.get(it.domain) || grouped.set(it.domain, []).get(it.domain)!).push(it.action);
  const groups = [...grouped.entries()].map(([domain, actions]) => {
    const meta = byLabel.get(domain);
    const avg = meta ? meta.avg : 99;               // General/Planning sort last (no model domain)
    return { domain, avg, priority: avg > 0 && avg < 2.5, actions };
  }).sort((a, b) => a.avg - b.avg);                 // ENISA: prioritise domains where scores are lowest (< 2.5)
  return { band, bandSummary: bandMeta.summary, groups };
}

export function smeAssessmentDetail(id: number, tenant: number | null): {
  assessment: SmeAssessmentRow;
  score: ReturnType<typeof scoreAssessment>;
  answers: Record<string, { score: number; evidence: string }>;
  questions: { ref: string; domainKey: string; domain: string; question: string; anchors: string[]; score: number; rag: string; evidence: string }[];
  roadmap: ReturnType<typeof roadmapFor>;
} | null {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM SMEMATURITYASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const ans = answersFor(db, id);
  const sc = scoreAssessment(ans);
  const questions: any[] = [];
  for (const d of SME_CATALOGUE.domains) for (const q of d.questions) {
    const a = ans.get(q.ref);
    questions.push({
      ref: q.ref, domainKey: d.key, domain: d.name, question: q.question, anchors: q.anchors,
      score: a?.score ?? 0, rag: a ? ragFor(a.score).key : "", evidence: a?.evidence ?? "",
    });
  }
  const band = sc.answered ? bandFor(sc.overall).key : "BASIC";
  return {
    assessment: rowToAssessment(db, r), score: sc,
    answers: Object.fromEntries([...ans.entries()]),
    questions, roadmap: roadmapFor(band, sc.domains),
  };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "SMEMATURITYASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  db.prepare(
    `INSERT INTO SMEMATURITYASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, ProductScope,
       Assessor, Status, OverallScore, Band, Notes, CreatedDate, UpdatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "SME CRA maturity self-check", s("orgName", 200),
    s("productScope", 500), s("assessor", 200), "draft", 0, "", s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM SMEMATURITYANSWER WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM SMEMATURITYASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

/** Persist a single answer (score 1-5, or 0 to clear) and refresh the cached overall score/band. */
export function setAnswer(id: number, ref: string, score: number, evidence?: string): { ok: boolean; error?: string } {
  ensureSmeTables();
  if (!REFS.has(ref)) return { ok: false, error: `unknown question ${ref}` };
  if (!(Number.isInteger(score) && score >= 0 && score <= 5)) return { ok: false, error: "score must be 0-5" };
  const db = getDb("XCOMPLIANCE");
  const meta = REFS.get(ref)!;
  if (score === 0) {
    db.prepare("DELETE FROM SMEMATURITYANSWER WHERE AssessmentID=? AND Ref=?").run(id, ref);
  } else {
    const existing = db.prepare("SELECT AnswerID FROM SMEMATURITYANSWER WHERE AssessmentID=? AND Ref=?").get(id, ref) as { AnswerID: number } | undefined;
    if (existing) {
      db.prepare("UPDATE SMEMATURITYANSWER SET Score=?, Evidence=?, UpdatedDate=? WHERE AnswerID=?")
        .run(score, evidence != null ? String(evidence).slice(0, 2000) : "", now(), existing.AnswerID);
    } else {
      db.prepare("INSERT INTO SMEMATURITYANSWER (AnswerID, AssessmentID, Ref, DomainKey, Score, Evidence, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
        .run(allocId(db, "SMEMATURITYANSWER", "AnswerID"), id, ref, meta.domainKey, score,
          evidence != null ? String(evidence).slice(0, 2000) : "", now());
    }
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const sc = scoreAssessment(answersFor(db, id));
  const band = sc.answered ? bandFor(sc.overall).key : "";
  const status = sc.answered === 0 ? "draft" : sc.answered >= TOTAL_QUESTIONS ? "completed" : "in-progress";
  db.prepare("UPDATE SMEMATURITYASSESSMENT SET OverallScore=?, Band=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.overall, band, status, now(), id);
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT AssessmentID FROM SMEMATURITYASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args);
  if (!r) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", orgName: "OrgName", productScope: "ProductScope", assessor: "Assessor", notes: "Notes" };
  for (const [k, col] of Object.entries(map)) if (k in b) { sets.push(`${col}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("status" in b && (SME_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE SMEMATURITYASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  return { ok: true };
}

// ── connector ingest ────────────────────────────────────────────────────────
/** Upsert an assessment + its answers from a parsed ENISA export (runner import_sme_maturity). */
export function importAssessment(tenant: number | null, payload: {
  name?: string; orgName?: string; productScope?: string; assessor?: string;
  externalId?: string; answers: { ref: string; score: number; evidence?: string }[];
}): { id: number; imported: number; created: boolean } {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const name = (payload.name || "ENISA SME CRA maturity self-check").slice(0, 300);
  // idempotent by (tenant, Name) so re-importing the same file updates one row
  const args = tenant == null ? [name] : [name, tenant];
  const found = db.prepare(`SELECT AssessmentID FROM SMEMATURITYASSESSMENT WHERE Name=? AND ${tw(tenant)}`).get(...args) as { AssessmentID: number } | undefined;
  const id = found ? found.AssessmentID : createAssessment(tenant, payload).id;
  if (found) updateAssessment(id, tenant, payload);
  let imported = 0;
  for (const a of payload.answers || []) {
    if (REFS.has(a.ref) && Number.isInteger(a.score) && a.score >= 1 && a.score <= 5) {
      setAnswer(id, a.ref, a.score, a.evidence);
      imported++;
    }
  }
  return { id, imported, created: !found };
}

// ── demo ────────────────────────────────────────────────────────────────────
/** Seed the ENISA worked example (overall 3.0 → INTERMEDIATE) for a tenant, idempotently. */
export function seedSmeDemo(tenant: number): void {
  ensureSmeTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Product B CRA maturity self-check";
  if (db.prepare("SELECT 1 FROM SMEMATURITYASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, {
    name, orgName: "Acme Widgets (SME)", productScope: "Product B — connected sensor gateway",
    assessor: "CRA compliance owner",
  });
  // the exact scores from ENISA's worked example tool (overall 74/25 = 2.96 → 3.0, INTERMEDIATE)
  const demo: Record<string, number> = {
    "1.1": 1, "1.2": 3, "1.3": 1, "1.4": 3, "1.5": 1,
    "2.1": 1, "2.2": 2, "2.3": 2, "2.4": 4, "2.5": 5,
    "3.1": 5, "3.2": 3, "3.3": 5, "3.4": 4, "3.5": 5,
    "4.1": 1, "4.2": 2, "4.3": 3, "4.4": 4, "4.5": 4,
    "5.1": 1, "5.2": 4, "5.3": 3, "5.4": 2, "5.5": 5,
  };
  for (const [ref, s] of Object.entries(demo)) setAnswer(id, ref, s);
  db.prepare("UPDATE SMEMATURITYASSESSMENT SET Status='completed' WHERE AssessmentID=?").run(id);
}
