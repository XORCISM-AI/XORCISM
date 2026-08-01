/**
 * inform.ts — MITRE CTID INFORM: Threat-Informed Defense (TID) maturity assessment (/inform).
 *
 * Replicates the INFORM assessment tool (ctid.mitre.org/inform, Apache 2.0): three weighted
 * dimensions — Cyber Threat Intelligence (35%), Defensive Measures (40%), Test & Evaluation (25%) —
 * each decomposed into components. Each component is a question answered by picking the achieved
 * maturity level (ordered least-to-most threat-informed → 0..max points). A dimension's score is the
 * percentage of its possible points earned; the overall TID score is the weighted sum of the three
 * dimension scores. Produces a per-dimension radar and a gap worklist (components below max, by
 * weighted gap). Named assessments so a program can track improvement over time.
 *
 * Tables in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like aisvs.ts / cticmm.ts).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { INFORM_CATALOGUE } from "./data/informCatalogue";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");
export const INFORM_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

const DIMS = INFORM_CATALOGUE.dimensions;
const COMP = new Map<string, { dim: string; max: number; name: string }>();
for (const d of DIMS) for (const c of d.components) COMP.set(c.id, { dim: d.code, max: Math.max(1, c.levels.length - 1), name: c.name });
const round1 = (n: number | null): number | null => (n == null ? null : Math.round(n * 10) / 10);

export function ensureInformTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS INFORMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Status TEXT, Score REAL, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS INFORMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, ComponentId TEXT, Dimension TEXT, Level INTEGER, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_inform_tenant ON INFORMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_informscore_assess ON INFORMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_informscore ON INFORMSCORE(AssessmentID, ComponentId);
  `);
}

export function informCatalogue(): typeof INFORM_CATALOGUE { return INFORM_CATALOGUE; }

// ── scoring ─────────────────────────────────────────────────────────────────────
export interface InformScore {
  overall: number | null; scored: number; total: number; coverage: number; belowMax: number;
  dimensions: { code: string; name: string; weight: number; score: number | null; scored: number; total: number; earned: number; possible: number }[];
  radar: { domain: string; value: number | null; target: number }[];
  worklist: { componentId: string; dimension: string; component: string; level: number; max: number; gap: number }[];
}

export function scoreAssessment(sel: Map<string, number>): InformScore {
  const dims = DIMS.map((d) => {
    let earned = 0, possible = 0, scored = 0;
    for (const c of d.components) {
      const max = Math.max(1, c.levels.length - 1);
      possible += max;
      const v = sel.get(c.id);
      if (v != null) { earned += Math.max(0, Math.min(max, v)); scored++; }
    }
    return { code: d.code, name: d.name, weight: d.weight, earned, possible, scored, total: d.components.length,
      score: possible > 0 ? round1((earned / possible) * 100) : null };
  });
  const anyScored = dims.some((d) => d.scored > 0);
  const overall = anyScored ? round1(dims.reduce((s, d) => s + (d.score ?? 0) * d.weight, 0)) : null;

  const worklist: InformScore["worklist"] = [];
  for (const [id, v] of sel) {
    const m = COMP.get(id); if (!m) continue;
    if (v < m.max) worklist.push({ componentId: id, dimension: m.dim, component: m.name, level: v, max: m.max, gap: m.max - v });
  }
  const wDim = new Map(DIMS.map((d) => [d.code, d.weight]));
  worklist.sort((a, b) => (b.gap * (wDim.get(b.dimension) || 0)) - (a.gap * (wDim.get(a.dimension) || 0)));

  const total = DIMS.reduce((n, d) => n + d.components.length, 0);
  const scoredN = [...sel.keys()].filter((id) => COMP.has(id)).length;
  return {
    overall, scored: scoredN, total, coverage: total ? Math.round((scoredN / total) * 100) : 0,
    belowMax: worklist.length, dimensions: dims,
    radar: dims.map((d) => ({ domain: d.code, value: d.score, target: 100 })),
    worklist: worklist.slice(0, 30),
  };
}

// ── assessments ─────────────────────────────────────────────────────────────────
export interface InformAssessmentRow {
  id: number; name: string; orgName: string; assessor: string; status: string;
  overall: number | null; scored: number; total: number; belowMax: number; notes: string; createdDate: string; updatedDate: string;
}
function selFor(db: ReturnType<typeof getDb>, id: number): Map<string, number> {
  return new Map((db.prepare("SELECT ComponentId, Level FROM INFORMSCORE WHERE AssessmentID=?").all(id) as { ComponentId: string; Level: number }[])
    .filter((r) => r.Level != null).map((r) => [r.ComponentId, Number(r.Level)]));
}
function notesFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT ComponentId, Notes FROM INFORMSCORE WHERE AssessmentID=?").all(id) as { ComponentId: string; Notes: string }[]).map((r) => [r.ComponentId, r.Notes || ""]));
}
function rowToAssessment(db: ReturnType<typeof getDb>, r: any): InformAssessmentRow {
  const sc = scoreAssessment(selFor(db, r.AssessmentID));
  return { id: r.AssessmentID, name: r.Name || "", orgName: r.OrgName || "", assessor: r.Assessor || "", status: r.Status || "draft",
    overall: sc.overall, scored: sc.scored, total: sc.total, belowMax: sc.belowMax, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "" };
}

export function informDashboard(tenant: number | null): any {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM INFORMASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.overall != null);
  return {
    assessments,
    summary: {
      assessments: assessments.length, completed: assessments.filter((a) => a.status === "completed").length,
      avgScore: scored.length ? round1(scored.reduce((n, a) => n + (a.overall as number), 0) / scored.length) : null,
      openGaps: assessments.reduce((n, a) => n + a.belowMax, 0),
    },
    catalogue: { version: INFORM_CATALOGUE.version, dimensions: DIMS.length, components: DIMS.reduce((n, d) => n + d.components.length, 0) },
  };
}

export function informDetail(id: number, tenant: number | null): any {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM INFORMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const sel = selFor(db, id), notes = notesFor(db, id);
  const sc = scoreAssessment(sel);
  const dimensions = DIMS.map((d) => {
    const ds = sc.dimensions.find((x) => x.code === d.code)!;
    return {
      code: d.code, name: d.name, weight: d.weight, score: ds.score, scored: ds.scored, total: ds.total,
      components: d.components.map((c) => ({
        id: c.id, name: c.name, description: c.description, question: c.question, levels: c.levels,
        max: Math.max(1, c.levels.length - 1), level: sel.has(c.id) ? sel.get(c.id) : null, notes: notes.get(c.id) || "",
      })),
    };
  });
  return { assessment: rowToAssessment(db, r), score: sc, dimensions };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "INFORMASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  db.prepare(`INSERT INTO INFORMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, Assessor, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), tenant, s("name", 300) || "INFORM threat-informed defense assessment", s("orgName", 200), s("assessor", 200), "draft", 0, s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM INFORMSCORE WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM INFORMASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM INFORMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", orgName: "OrgName", assessor: "Assessor", notes: "Notes" };
  for (const [k, c] of Object.entries(map)) if (k in b) { sets.push(`${c}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("status" in b && (INFORM_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE INFORMASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  return { ok: true };
}

/** Set a component's achieved level (index into its levels; "" / null clears). */
export function setScore(id: number, componentId: string, level: number | null, notes?: string): { ok: boolean; error?: string } {
  ensureInformTables();
  const m = COMP.get(componentId);
  if (!m) return { ok: false, error: `unknown component ${componentId}` };
  const db = getDb("XCOMPLIANCE");
  const lvl = level == null ? null : Math.max(0, Math.min(m.max, Math.round(level)));
  const ex = db.prepare("SELECT ScoreID, Level, Notes FROM INFORMSCORE WHERE AssessmentID=? AND ComponentId=?").get(id, componentId) as any;
  if (lvl == null && notes == null) {
    if (ex) db.prepare("DELETE FROM INFORMSCORE WHERE ScoreID=?").run(ex.ScoreID);
  } else if (ex) {
    db.prepare("UPDATE INFORMSCORE SET Level=?, Notes=?, UpdatedDate=? WHERE ScoreID=?")
      .run(lvl != null ? lvl : ex.Level, notes != null ? String(notes).slice(0, 2000) : ex.Notes, now(), ex.ScoreID);
  } else {
    db.prepare("INSERT INTO INFORMSCORE (ScoreID, AssessmentID, ComponentId, Dimension, Level, Notes, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
      .run(allocId(db, "INFORMSCORE", "ScoreID"), id, componentId, m.dim, lvl, notes != null ? String(notes).slice(0, 2000) : "", now());
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const sc = scoreAssessment(selFor(db, id));
  const status = sc.scored === 0 ? "draft" : sc.scored >= sc.total ? "completed" : "in-progress";
  db.prepare("UPDATE INFORMASSESSMENT SET Score=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.overall ?? 0, status, now(), id);
}

// ── demo ──────────────────────────────────────────────────────────────────────────
export function seedInformDemo(tenant: number): void {
  ensureInformTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Threat-Informed Defense (INFORM)";
  if (db.prepare("SELECT 1 FROM INFORMASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, orgName: "Enterprise SOC (demo)", assessor: "Head of detection" });
  let i = 0;
  for (const d of DIMS) for (const c of d.components) {
    if (i % 5 !== 4) { const max = Math.max(1, c.levels.length - 1); setScore(id, c.id, Math.min(max, 1 + ((i * 3) % (max + 1)))); }
    i++;
  }
  db.prepare("UPDATE INFORMASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
