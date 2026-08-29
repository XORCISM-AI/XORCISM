/**
 * tircmm.ts — TIR-CMM (Threat-Informed Response Capability Maturity Model, tir-cmm.com) assessment.
 *
 * TIR-CMM (author Reza Adineh, v1.0, model CC BY-ND 4.0) measures whether an organisation can CONTAIN a
 * detected attack inside the adversary's breakout window — and prove it. Eight weighted domains
 * (RP/RA/RE/CE/AO/FI/RV/RG) hold 58 sub-capabilities, each scored 0–5 against a Level-3 ("threat-informed")
 * anchor. Two signature mechanics are enforced:
 *   • Evidence cap (constraint R3): every sub-capability's score is capped by its evidence grade —
 *     VC0 assertion→1, VC1 design→2, VC2 implemented & tested→4, VC3 repeatably validated→5. A blank
 *     grade is treated as VC0 (cap 1). "A high evidence grade permits a high score; it does not create one."
 *   • Assessment-tier ceiling (R7): Pulse caps at L3, Baseline at L4, Assurance uncapped.
 * Domain score = evidence-capped weighted mean of its sub-capabilities; overall = domain-weighted mean,
 * then band L0–L5. Produces a per-domain radar, a weighted gap worklist (each with its remediation action),
 * and the model's crosswalk to NIST CSF 2.0 / 800-61 / ISO / RE&CT / D3FEND / SOC-CMM (its referenced models).
 * Companion model: TID-CMM (detection); parent operating model: UTIOM.
 *
 * Tables in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like cticmm.ts / inform.ts). Model baked in
 * data/tirCmmModel.ts (fetched from tir-cmm.com; refresh via import_tircmm.py --refresh-model).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { TIR_CMM_MODEL } from "./data/tirCmmModel";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");
export const TIR_TIERS = ["pulse", "baseline", "assurance"] as const;
export const TIR_EVIDENCE = ["", "VC0", "VC1", "VC2", "VC3"] as const;
export const TIR_STATUS = ["draft", "in-progress", "completed", "archived"] as const;

const M: any = TIR_CMM_MODEL;
const DOMAINS: any[] = M.domains;
const round1 = (n: number | null): number | null => (n == null ? null : Math.round(n * 10) / 10);

// sub-capability index (id → domain, weights, anchor, action)
interface SubMeta { domain: string; domainWeight: number; weight: number; name: string; anchor: string; evidenceExpect: string; action: any }
const SUB = new Map<string, SubMeta>();
for (const d of DOMAINS) for (const s of d.sub_capabilities)
  SUB.set(s.id, { domain: d.id, domainWeight: d.weight, weight: s.weight, name: s.name, anchor: s.anchor_3 || "", evidenceExpect: s.evidence || "", action: s.action || null });

// evidence grade → score cap (R3). Blank/unknown → VC0 (cap 1).
const EV_CAP = new Map<string, number>(M.evidence.map((e: any) => [e.vc, e.cap]));
const evCap = (vc: string): number => EV_CAP.get(vc) ?? 1;
// assessment-tier ceiling (R7): "L3"→3, "L4"→4, null→6 (uncapped)
const tierCeiling = (tierId: string): number => {
  const t = M.assessment_tiers.find((x: any) => x.id === tierId);
  const c = t && t.ceiling ? Number(String(t.ceiling).replace(/[^0-9]/g, "")) : NaN;
  return Number.isFinite(c) ? c : 6;
};
const bandFor = (score: number | null): { id: string; name: string } | null => {
  if (score == null) return null;
  const b = M.bands.find((x: any) => score >= x.min && score <= x.max) || M.bands[M.bands.length - 1];
  return b ? { id: b.id, name: b.name } : null;
};

export function ensureTirCmmTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS TIRCMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Tier TEXT, TargetLevel INTEGER DEFAULT 3, Status TEXT,
      Score REAL, Band TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS TIRCMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, SubCapId TEXT, Domain TEXT,
      Level REAL, Evidence TEXT, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_tircmm_tenant ON TIRCMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_tircmmscore_assess ON TIRCMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_tircmmscore ON TIRCMMSCORE(AssessmentID, SubCapId);
  `);
}

export function tircmmModel(): typeof TIR_CMM_MODEL { return TIR_CMM_MODEL; }

// ── scoring ─────────────────────────────────────────────────────────────────────
export interface TirScore {
  overall: number | null; band: { id: string; name: string } | null; target: number; tier: string; ceiling: number;
  scored: number; total: number; coverage: number; belowTarget: number; evidenceCapped: number;
  domains: { code: string; name: string; weight: number; score: number | null; scored: number; total: number }[];
  radar: { domain: string; value: number | null; target: number }[];
  worklist: { subId: string; domain: string; name: string; level: number; effective: number; evidence: string; target: number; gap: number; action: any }[];
}

export function scoreAssessment(tier: string, target: number, scores: Map<string, { level: number; evidence: string }>): TirScore {
  const ceil = tierCeiling(tier);
  const domScores = DOMAINS.map((d) => {
    let wsum = 0, acc = 0, scored = 0;
    for (const s of d.sub_capabilities) {
      const v = scores.get(s.id);
      if (!v || v.level == null) continue;
      const eff = Math.min(v.level, evCap(v.evidence || ""), ceil);
      acc += eff * s.weight; wsum += s.weight; scored++;
    }
    const score = wsum > 0 ? acc / wsum : null;
    return { code: d.id, name: d.name, weight: d.weight, score: round1(score), scored, total: d.sub_capabilities.length };
  });

  const scoredDoms = domScores.filter((d) => d.score != null);
  let overall: number | null = null;
  if (scoredDoms.length) {
    const w = scoredDoms.reduce((n, d) => n + d.weight, 0);
    overall = round1(Math.min(ceil, scoredDoms.reduce((n, d) => n + (d.score as number) * d.weight, 0) / w));
  }

  const worklist: TirScore["worklist"] = [];
  let capped = 0, scoredN = 0;
  for (const [id, v] of scores) {
    const meta = SUB.get(id); if (!meta || v.level == null) continue;
    scoredN++;
    const cap = Math.min(evCap(v.evidence || ""), ceil);
    const eff = Math.min(v.level, cap);
    if (eff < v.level) capped++;
    if (eff < target) worklist.push({
      subId: id, domain: meta.domain, name: meta.name, level: v.level, effective: eff, evidence: v.evidence || "VC0",
      target, gap: round1(target - eff) as number, action: meta.action,
    });
  }
  worklist.sort((a, b) => (b.gap * (SUB.get(b.subId)!.domainWeight * SUB.get(b.subId)!.weight)) - (a.gap * (SUB.get(a.subId)!.domainWeight * SUB.get(a.subId)!.weight)));

  const total = DOMAINS.reduce((n, d) => n + d.sub_capabilities.length, 0);
  return {
    overall, band: bandFor(overall), target, tier, ceiling: ceil,
    scored: scoredN, total, coverage: total ? Math.round((scoredN / total) * 100) : 0,
    belowTarget: worklist.length, evidenceCapped: capped,
    domains: domScores,
    radar: domScores.map((d) => ({ domain: d.code, value: d.score, target })),
    worklist: worklist.slice(0, 30),
  };
}

// ── assessments ─────────────────────────────────────────────────────────────────
function scoresFor(db: ReturnType<typeof getDb>, id: number): Map<string, { level: number; evidence: string }> {
  const m = new Map<string, { level: number; evidence: string }>();
  for (const r of db.prepare("SELECT SubCapId, Level, Evidence FROM TIRCMMSCORE WHERE AssessmentID=?").all(id) as any[])
    if (r.Level != null) m.set(r.SubCapId, { level: Number(r.Level), evidence: r.Evidence || "" });
  return m;
}
function notesFor(db: ReturnType<typeof getDb>, id: number): Map<string, string> {
  return new Map((db.prepare("SELECT SubCapId, Notes FROM TIRCMMSCORE WHERE AssessmentID=?").all(id) as any[]).map((r) => [r.SubCapId, r.Notes || ""]));
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): any {
  const sc = scoreAssessment(r.Tier || "baseline", r.TargetLevel || 3, scoresFor(db, r.AssessmentID));
  return {
    id: r.AssessmentID, name: r.Name || "", orgName: r.OrgName || "", assessor: r.Assessor || "",
    tier: r.Tier || "baseline", targetLevel: r.TargetLevel || 3, status: r.Status || "draft",
    overall: sc.overall, band: sc.band, scored: sc.scored, total: sc.total, belowTarget: sc.belowTarget,
    evidenceCapped: sc.evidenceCapped, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function tircmmDashboard(tenant: number | null): any {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM TIRCMMASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
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
    model: { name: M.name, version: M.version, domains: DOMAINS.length, subCapabilities: M.domains.reduce((n: number, d: any) => n + d.sub_capabilities.length, 0),
      bands: M.bands, tiers: M.assessment_tiers, evidence: M.evidence, companion: M.companion, parent: M.parent, licence: M.licence },
  };
}

export function tircmmDetail(id: number, tenant: number | null): any {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM TIRCMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const scores = scoresFor(db, id), notes = notesFor(db, id);
  const sc = scoreAssessment(r.Tier || "baseline", r.TargetLevel || 3, scores);
  const cw = new Map(M.crosswalk.map((c: any) => [c.d, c]));
  const domains = DOMAINS.map((d) => {
    const ds = sc.domains.find((x) => x.code === d.id)!;
    return {
      code: d.id, name: d.name, weight: d.weight, question: d.question, note: d.note,
      score: ds.score, scored: ds.scored, total: ds.total, crosswalk: cw.get(d.id) || null,
      subCapabilities: d.sub_capabilities.map((s: any) => {
        const v = scores.get(s.id);
        const eff = v && v.level != null ? Math.min(v.level, evCap(v.evidence || ""), sc.ceiling) : null;
        return {
          id: s.id, name: s.name, weight: s.weight, anchor: s.anchor_3, evidenceExpect: s.evidence, action: s.action,
          level: v && v.level != null ? v.level : null, evidence: v ? (v.evidence || "") : "",
          effective: eff, notes: notes.get(s.id) || "",
        };
      }),
    };
  });
  return {
    assessment: rowToAssessment(db, r), score: sc, domains,
    bands: M.bands, evidence: M.evidence, tiers: M.assessment_tiers, constraints: M.constraints,
    stages: M.stages, assetClasses: M.asset_classes, companion: M.companion, parent: M.parent,
  };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "TIRCMMASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  const tier = (TIR_TIERS as readonly string[]).includes(String(b.tier)) ? String(b.tier) : "baseline";
  const tgt = Math.max(1, Math.min(5, Number(b.targetLevel) || 3));
  db.prepare(
    `INSERT INTO TIRCMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, Assessor,
       Tier, TargetLevel, Status, Score, Band, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "TIR-CMM assessment", s("orgName", 200), s("assessor", 200),
    tier, tgt, "draft", 0, "L0", s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM TIRCMMSCORE WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM TIRCMMASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM TIRCMMASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", orgName: "OrgName", assessor: "Assessor", notes: "Notes" };
  for (const [k, c] of Object.entries(map)) if (k in b) { sets.push(`${c}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("tier" in b && (TIR_TIERS as readonly string[]).includes(String(b.tier))) { sets.push("Tier=?"); vals.push(String(b.tier)); }
  if ("targetLevel" in b) { sets.push("TargetLevel=?"); vals.push(Math.max(1, Math.min(5, Number(b.targetLevel) || 3))); }
  if ("status" in b && (TIR_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE TIRCMMASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  refreshScore(db, id);
  return { ok: true };
}

/** Score one sub-capability: Level 0–5 + Evidence VC0–VC3 (both null + no notes clears it). */
export function setScore(id: number, subId: string, level: number | null, evidence?: string, notes?: string): { ok: boolean; error?: string } {
  ensureTirCmmTables();
  if (!SUB.has(subId)) return { ok: false, error: `unknown sub-capability ${subId}` };
  const db = getDb("XCOMPLIANCE");
  const lvl = level == null ? null : Math.max(0, Math.min(5, Math.round(level)));
  const ev = evidence != null && (TIR_EVIDENCE as readonly string[]).includes(evidence) ? evidence : undefined;
  const meta = SUB.get(subId)!;
  const ex = db.prepare("SELECT ScoreID, Level, Evidence, Notes FROM TIRCMMSCORE WHERE AssessmentID=? AND SubCapId=?").get(id, subId) as any;
  if (lvl == null && ev == null && notes == null) {
    if (ex) db.prepare("DELETE FROM TIRCMMSCORE WHERE ScoreID=?").run(ex.ScoreID);
  } else if (ex) {
    db.prepare("UPDATE TIRCMMSCORE SET Level=?, Evidence=?, Notes=?, UpdatedDate=? WHERE ScoreID=?")
      .run(lvl != null ? lvl : ex.Level, ev != null ? ev : ex.Evidence, notes != null ? String(notes).slice(0, 2000) : ex.Notes, now(), ex.ScoreID);
  } else {
    db.prepare("INSERT INTO TIRCMMSCORE (ScoreID, AssessmentID, SubCapId, Domain, Level, Evidence, Notes, UpdatedDate) VALUES (?,?,?,?,?,?,?,?)")
      .run(allocId(db, "TIRCMMSCORE", "ScoreID"), id, subId, meta.domain, lvl, ev || "", notes != null ? String(notes).slice(0, 2000) : "", now());
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const r = db.prepare("SELECT Tier, TargetLevel FROM TIRCMMASSESSMENT WHERE AssessmentID=?").get(id) as any;
  if (!r) return;
  const sc = scoreAssessment(r.Tier || "baseline", r.TargetLevel || 3, scoresFor(db, id));
  const status = sc.scored === 0 ? "draft" : sc.scored >= sc.total ? "completed" : "in-progress";
  db.prepare("UPDATE TIRCMMASSESSMENT SET Score=?, Band=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.overall ?? 0, sc.band ? sc.band.id : "L0", status, now(), id);
}

// ── demo ────────────────────────────────────────────────────────────────────────
export function seedTirCmmDemo(tenant: number): void {
  ensureTirCmmTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Threat-Informed Response (TIR-CMM)";
  if (db.prepare("SELECT 1 FROM TIRCMMASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, orgName: "Enterprise SOC (demo)", assessor: "Head of IR", tier: "baseline", targetLevel: 3 });
  // realistic profile: level 2–4 with matching evidence grades, some sub-caps left unscored
  const lvlPat = [3, 2, 4, 3, 2, 3, 4, 2, 3, 3];
  const evPat = ["VC2", "VC1", "VC2", "VC2", "VC1", "VC2", "VC3", "VC1", "VC2", "VC2"];
  let i = 0;
  for (const d of DOMAINS) for (const s of d.sub_capabilities) {
    if (i % 6 !== 5) setScore(id, s.id, lvlPat[i % lvlPat.length], evPat[i % evPat.length]);
    i++;
  }
  db.prepare("UPDATE TIRCMMASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
