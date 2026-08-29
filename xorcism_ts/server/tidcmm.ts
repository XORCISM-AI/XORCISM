/**
 * tidcmm.ts — TID-CMM (Threat-Informed Detection Capability Maturity Model, tid-cmm.com) assessment.
 *
 * TID-CMM (author Reza Adineh, v1.5.0, CC BY 4.0) is the DETECTION companion to TIR-CMM: it measures
 * whether detection is driven by adversary behaviour, whether the telemetry exists to see it, and
 * whether any of it has been proven to work. Eight weighted domains (TI/TM/DC/DE/AV/AA/IR/GV) hold 58
 * sub-capabilities scored 0–5 against per-level descriptors (or NA = formally scoped out). Domain score
 * = weighted mean of in-scope sub-capabilities; overall = domain-weighted mean → band L0–L5. Assessment
 * tiers cap the ceiling (rapid→L3, structured/evidence-based uncapped). Aligned to MITRE ATT&CK v19.2
 * and crosswalked to NIST CSF 2.0 and SOC-CMM. Companion response model: TIR-CMM (see tircmm.ts).
 *
 * Tables in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like tircmm.ts / cticmm.ts). Model baked in
 * data/tidCmmModel.ts (fetched from tid-cmm.com/api/model.json; refresh via import_tidcmm.py).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { TID_CMM_MODEL } from "./data/tidCmmModel";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");
// assessment tiers are described in the model text, not the JSON: rapid caps at L3, the two deeper tiers uncapped.
export const TID_TIERS = [
  { id: "rapid", name: "Rapid self-assessment", ceiling: "L3", desc: "Directional only." },
  { id: "structured", name: "Structured self-assessment", ceiling: null, desc: "Defensible internally." },
  { id: "evidence", name: "Evidence-based assessment", ceiling: null, desc: "Defensible externally." },
];
export const TID_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

const M: any = TID_CMM_MODEL;
const DOMAINS: any[] = M.domains;
const round1 = (n: number | null): number | null => (n == null ? null : Math.round(n * 10) / 10);

interface SubMeta { domain: string; domainWeight: number; weight: number; name: string; levels: any }
const SUB = new Map<string, SubMeta>();
for (const d of DOMAINS) for (const s of d.subcapabilities)
  SUB.set(s.id, { domain: d.id, domainWeight: d.weight, weight: s.weight, name: s.name, levels: s.levels });

const tierCeiling = (tierId: string): number => {
  const t = TID_TIERS.find((x) => x.id === tierId);
  const c = t && t.ceiling ? Number(String(t.ceiling).replace(/[^0-9]/g, "")) : NaN;
  return Number.isFinite(c) ? c : 6;
};
const bandFor = (score: number | null): { id: string; name: string } | null => {
  if (score == null) return null;
  const b = M.scoring.maturity_band.find((x: any) => score >= x.min && score <= x.max) || M.scoring.maturity_band[M.scoring.maturity_band.length - 1];
  return b ? { id: "L" + Math.floor(b.min), name: b.band } : null;
};

export function ensureTidCmmTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS TIDCMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Tier TEXT, TargetLevel INTEGER DEFAULT 3, Status TEXT,
      Score REAL, Band TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS TIDCMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, SubCapId TEXT, Domain TEXT,
      Level REAL, NA INTEGER DEFAULT 0, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_tidcmm_tenant ON TIDCMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_tidcmmscore_assess ON TIDCMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_tidcmmscore ON TIDCMMSCORE(AssessmentID, SubCapId);
  `);
}

export function tidcmmModel(): typeof TID_CMM_MODEL { return TID_CMM_MODEL; }

// ── scoring ─────────────────────────────────────────────────────────────────────
export interface TidScore {
  overall: number | null; band: { id: string; name: string } | null; target: number; tier: string; ceiling: number;
  scored: number; na: number; total: number; coverage: number; belowTarget: number;
  domains: { code: string; name: string; weight: number; score: number | null; scored: number; na: number; total: number }[];
  radar: { domain: string; value: number | null; target: number }[];
  worklist: { subId: string; domain: string; name: string; level: number; target: number; gap: number; guidance: string }[];
}

export function scoreAssessment(tier: string, target: number, scores: Map<string, { level: number | null; na: boolean }>): TidScore {
  const ceil = tierCeiling(tier);
  const domScores = DOMAINS.map((d) => {
    let wsum = 0, acc = 0, scored = 0, na = 0;
    for (const s of d.subcapabilities) {
      const v = scores.get(s.id);
      if (!v) continue;
      if (v.na) { na++; continue; }
      if (v.level == null) continue;
      acc += Math.min(v.level, ceil) * s.weight; wsum += s.weight; scored++;
    }
    return { code: d.id, name: d.name, weight: d.weight, score: wsum > 0 ? round1(acc / wsum) : null, scored, na, total: d.subcapabilities.length };
  });

  const scoredDoms = domScores.filter((d) => d.score != null);
  let overall: number | null = null;
  if (scoredDoms.length) {
    const w = scoredDoms.reduce((n, d) => n + d.weight, 0);
    overall = round1(Math.min(ceil, scoredDoms.reduce((n, d) => n + (d.score as number) * d.weight, 0) / w));
  }

  const worklist: TidScore["worklist"] = [];
  let scoredN = 0, naN = 0;
  for (const [id, v] of scores) {
    const meta = SUB.get(id); if (!meta) continue;
    if (v.na) { naN++; continue; }
    if (v.level == null) continue;
    scoredN++;
    const eff = Math.min(v.level, ceil);
    if (eff < target) worklist.push({
      subId: id, domain: meta.domain, name: meta.name, level: v.level, target,
      gap: round1(target - eff) as number, guidance: (meta.levels && meta.levels[String(target)]) || "",
    });
  }
  worklist.sort((a, b) => (b.gap * (SUB.get(b.subId)!.domainWeight * SUB.get(b.subId)!.weight)) - (a.gap * (SUB.get(a.subId)!.domainWeight * SUB.get(a.subId)!.weight)));

  const total = DOMAINS.reduce((n, d) => n + d.subcapabilities.length, 0);
  return {
    overall, band: bandFor(overall), target, tier, ceiling: ceil,
    scored: scoredN, na: naN, total, coverage: total ? Math.round(((scoredN + naN) / total) * 100) : 0,
    belowTarget: worklist.length, domains: domScores,
    radar: domScores.map((d) => ({ domain: d.code, value: d.score, target })),
    worklist: worklist.slice(0, 30),
  };
}

// ── assessments ─────────────────────────────────────────────────────────────────
function scoresFor(db: ReturnType<typeof getDb>, id: number): Map<string, { level: number | null; na: boolean }> {
  const m = new Map<string, { level: number | null; na: boolean }>();
  for (const r of db.prepare("SELECT SubCapId, Level, NA FROM TIDCMMSCORE WHERE AssessmentID=?").all(id) as any[])
    m.set(r.SubCapId, { level: r.Level != null ? Number(r.Level) : null, na: !!r.NA });
  return m;
}
function notesFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT SubCapId, Notes FROM TIDCMMSCORE WHERE AssessmentID=?").all(id) as any[]).map((r) => [r.SubCapId, r.Notes || ""]));
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): any {
  const sc = scoreAssessment(r.Tier || "structured", r.TargetLevel || 3, scoresFor(db, r.AssessmentID));
  return {
    id: r.AssessmentID, name: r.Name || "", orgName: r.OrgName || "", assessor: r.Assessor || "",
    tier: r.Tier || "structured", targetLevel: r.TargetLevel || 3, status: r.Status || "draft",
    overall: sc.overall, band: sc.band, scored: sc.scored, na: sc.na, total: sc.total, belowTarget: sc.belowTarget,
    notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function tidcmmDashboard(tenant: number | null): any {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM TIDCMMASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.scored > 0 && a.overall != null);
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      completed: assessments.filter((a) => a.status === "completed").length,
      avgScore: scored.length ? round1(scored.reduce((n, a) => n + (a.overall as number), 0) / scored.length) : null,
      openGaps: assessments.reduce((n, a) => n + a.belowTarget, 0),
    },
    model: { name: M.model.name, version: M.model.version, domains: DOMAINS.length,
      subCapabilities: DOMAINS.reduce((n, d) => n + d.subcapabilities.length, 0),
      bands: M.scoring.maturity_band, tiers: TID_TIERS, levels: M.levels, attack: M.alignment.attack,
      crosswalks: M.alignment.crosswalks, licence: M.model.licence, companion: "TIR-CMM" },
  };
}

export function tidcmmDetail(id: number, tenant: number | null): any {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM TIDCMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const scores = scoresFor(db, id), notes = notesFor(db, id);
  const sc = scoreAssessment(r.Tier || "structured", r.TargetLevel || 3, scores);
  const domains = DOMAINS.map((d) => {
    const ds = sc.domains.find((x) => x.code === d.id)!;
    return {
      code: d.id, name: d.name, weight: d.weight, intent: d.intent, antiPattern: d.anti_pattern, ceilingRule: d.ceiling_rule,
      score: ds.score, scored: ds.scored, na: ds.na, total: ds.total,
      subCapabilities: d.subcapabilities.map((s: any) => {
        const v = scores.get(s.id);
        return {
          id: s.id, name: s.name, weight: s.weight, question: s.question, levels: s.levels,
          level: v && !v.na ? v.level : null, na: !!(v && v.na), notes: notes.get(s.id) || "",
        };
      }),
    };
  });
  return {
    assessment: rowToAssessment(db, r), score: sc, domains,
    bands: M.scoring.maturity_band, levels: M.levels, tiers: TID_TIERS, constraints: M.scoring.constraints,
    crosswalks: M.alignment.crosswalks, attack: M.alignment.attack, companion: "TIR-CMM",
  };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "TIDCMMASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  const tier = TID_TIERS.some((t) => t.id === String(b.tier)) ? String(b.tier) : "structured";
  const tgt = Math.max(1, Math.min(5, Number(b.targetLevel) || 3));
  db.prepare(
    `INSERT INTO TIDCMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, Assessor,
       Tier, TargetLevel, Status, Score, Band, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "TID-CMM assessment", s("orgName", 200), s("assessor", 200),
    tier, tgt, "draft", 0, "L0", s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM TIDCMMSCORE WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM TIDCMMASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM TIDCMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", orgName: "OrgName", assessor: "Assessor", notes: "Notes" };
  for (const [k, c] of Object.entries(map)) if (k in b) { sets.push(`${c}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("tier" in b && TID_TIERS.some((t) => t.id === String(b.tier))) { sets.push("Tier=?"); vals.push(String(b.tier)); }
  if ("targetLevel" in b) { sets.push("TargetLevel=?"); vals.push(Math.max(1, Math.min(5, Number(b.targetLevel) || 3))); }
  if ("status" in b && (TID_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE TIDCMMASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  refreshScore(db, id);
  return { ok: true };
}

/** Score one sub-capability: Level 0–5, or NA (scoped out). level null + na false + no notes clears it. */
export function setScore(id: number, subId: string, level: number | null, na?: boolean, notes?: string): { ok: boolean; error?: string } {
  ensureTidCmmTables();
  if (!SUB.has(subId)) return { ok: false, error: `unknown sub-capability ${subId}` };
  const db = getDb("XCOMPLIANCE");
  const meta = SUB.get(subId)!;
  const lvl = na ? null : (level == null ? null : Math.max(0, Math.min(5, Math.round(level))));
  const naFlag = na ? 1 : 0;
  const ex = db.prepare("SELECT ScoreID, Level, NA, Notes FROM TIDCMMSCORE WHERE AssessmentID=? AND SubCapId=?").get(id, subId) as any;
  if (lvl == null && !na && notes == null) {
    if (ex) db.prepare("DELETE FROM TIDCMMSCORE WHERE ScoreID=?").run(ex.ScoreID);
  } else if (ex) {
    db.prepare("UPDATE TIDCMMSCORE SET Level=?, NA=?, Notes=?, UpdatedDate=? WHERE ScoreID=?")
      .run(na != null || level != null ? lvl : ex.Level, na != null ? naFlag : ex.NA, notes != null ? String(notes).slice(0, 2000) : ex.Notes, now(), ex.ScoreID);
  } else {
    db.prepare("INSERT INTO TIDCMMSCORE (ScoreID, AssessmentID, SubCapId, Domain, Level, NA, Notes, UpdatedDate) VALUES (?,?,?,?,?,?,?,?)")
      .run(allocId(db, "TIDCMMSCORE", "ScoreID"), id, subId, meta.domain, lvl, naFlag, notes != null ? String(notes).slice(0, 2000) : "", now());
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const r = db.prepare("SELECT Tier, TargetLevel FROM TIDCMMASSESSMENT WHERE AssessmentID=?").get(id) as any;
  if (!r) return;
  const sc = scoreAssessment(r.Tier || "structured", r.TargetLevel || 3, scoresFor(db, id));
  const addressed = sc.scored + sc.na;
  const status = addressed === 0 ? "draft" : addressed >= sc.total ? "completed" : "in-progress";
  db.prepare("UPDATE TIDCMMASSESSMENT SET Score=?, Band=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.overall ?? 0, sc.band ? sc.band.id : "L0", status, now(), id);
}

// ── demo ────────────────────────────────────────────────────────────────────────
export function seedTidCmmDemo(tenant: number): void {
  ensureTidCmmTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Threat-Informed Detection (TID-CMM)";
  if (db.prepare("SELECT 1 FROM TIDCMMASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, orgName: "Enterprise SOC (demo)", assessor: "Head of detection", tier: "structured", targetLevel: 3 });
  const pat = [3, 2, 4, 3, 2, 3, 4, 2, 3, 3];
  let i = 0;
  for (const d of DOMAINS) for (const s of d.subcapabilities) {
    if (i % 7 === 6) setScore(id, s.id, null, true);       // occasionally scope out (NA)
    else if (i % 6 !== 5) setScore(id, s.id, pat[i % pat.length]);
    i++;
  }
  db.prepare("UPDATE TIDCMMASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
