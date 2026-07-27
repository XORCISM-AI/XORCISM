/**
 * ncaEcc.ts — Saudi NCA ECC Implementation & Evidence cockpit (/nca-ecc).
 *
 * Turns the NCA "Guide to ECC Implementation" (GECC 2:2024) into an actionable implementation &
 * audit-evidence tracker: the 108 ECC main controls (grouped by the 4 domains / 28 subdomains),
 * each carrying the official objective, control text, relevant cybersecurity tools, implementation
 * guidelines and — the key value — the EXPECTED DELIVERABLES the assessor/auditor looks for.
 *
 * An entity creates an assessment, sets each control's implementation status (not-started /
 * in-progress / implemented / not-applicable), assigns an owner, and checks off the expected
 * deliverables it has produced. The cockpit scores implementation % (overall + per domain, weighted:
 * implemented=1, in-progress=0.5, n/a excluded) and evidence readiness % (deliverables produced /
 * expected). Tables live in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like aisvs.ts / cc.ts).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { GECC_CATALOGUE, GeccControl } from "./data/geccCatalogue";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

export const ECC_STATUS = [
  { key: "implemented", label: "Implemented", weight: 1 },
  { key: "in-progress", label: "In progress", weight: 0.5 },
  { key: "not-started", label: "Not started", weight: 0 },
  { key: "not-applicable", label: "Not applicable", weight: -1 }, // excluded from denominator
] as const;
export const ECC_ASSESS_STATUS = ["draft", "in-progress", "completed", "archived"] as const;
const WEIGHT = new Map<string, number>(ECC_STATUS.map((s) => [s.key, s.weight]));

const CONTROLS = GECC_CATALOGUE.controls;
const REFS = new Map<string, GeccControl>(CONTROLS.map((c) => [c.ref, c]));
const DELIV_COUNT = new Map<string, number>(CONTROLS.map((c) => [c.ref, c.deliverables.length]));

export function ensureNcaEccTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS NCAECCASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, EntityName TEXT, Scope TEXT, Assessor TEXT, Status TEXT,
      Score REAL, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS NCAECCCONTROL(
      ControlRowID INTEGER PRIMARY KEY, AssessmentID INTEGER, Ref TEXT, Domain TEXT,
      Status TEXT, Owner TEXT, EvidenceNote TEXT, DeliverablesDone TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_ncaecc_tenant ON NCAECCASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_ncaeccctl_assess ON NCAECCCONTROL(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_ncaeccctl_ref ON NCAECCCONTROL(AssessmentID, Ref);
  `);
}

export function geccCatalogue(): typeof GECC_CATALOGUE { return GECC_CATALOGUE; }

// ── scoring ──────────────────────────────────────────────────────────────────────
export interface EccControlState { status: string; deliverablesDone: number[] }
export interface EccScore {
  implementation: number; evidence: number; total: number; assessed: number; applicable: number;
  implemented: number; inProgress: number; notStarted: number; na: number;
  deliverablesExpected: number; deliverablesProduced: number;
  domains: { num: string; name: string; total: number; implementation: number; evidence: number;
    implemented: number; assessed: number; applicable: number }[];
  statusCounts: Record<string, number>;
}

export function scoreAssessment(states: Map<string, EccControlState>): EccScore {
  const domAgg = new Map<string, { w: number; d: number; impl: number; assessed: number; app: number; total: number;
    delExp: number; delProd: number }>();
  for (const dmn of GECC_CATALOGUE.domains) domAgg.set(dmn.num, { w: 0, d: 0, impl: 0, assessed: 0, app: 0, total: 0, delExp: 0, delProd: 0 });
  const sc: Record<string, number> = { implemented: 0, "in-progress": 0, "not-started": 0, "not-applicable": 0 };
  let delExp = 0, delProd = 0;

  for (const c of CONTROLS) {
    const dm = domAgg.get(c.domain)!; dm.total++;
    const st = states.get(c.ref);
    const status = st?.status || "";
    if (status) sc[status] = (sc[status] || 0) + 1;
    const w = status ? WEIGHT.get(status) ?? null : null;
    const applicable = status !== "not-applicable";
    if (applicable) {
      dm.app++; dm.d++;                              // denominator: all applicable controls
      if (w != null && w >= 0) dm.impl += w;
      // evidence: expected deliverables for applicable controls
      const exp = DELIV_COUNT.get(c.ref) || 0;
      const done = (st?.deliverablesDone || []).filter((i) => i >= 0 && i < exp).length;
      dm.delExp += exp; dm.delProd += done; delExp += exp; delProd += done;
    }
    if (status && status !== "not-applicable") dm.assessed++;
  }

  const domains = GECC_CATALOGUE.domains.map((dmn) => {
    const a = domAgg.get(dmn.num)!;
    return {
      num: dmn.num, name: dmn.name, total: a.total,
      implementation: a.d > 0 ? Math.round((a.impl / a.d) * 100) : 0,
      evidence: a.delExp > 0 ? Math.round((a.delProd / a.delExp) * 100) : 0,
      implemented: 0, assessed: a.assessed, applicable: a.app,
    };
  });
  // per-domain implemented count
  for (const c of CONTROLS) if (states.get(c.ref)?.status === "implemented") {
    const d = domains.find((x) => x.num === c.domain); if (d) d.implemented++;
  }

  const totApp = domains.reduce((n, d) => n + d.applicable, 0);
  const totImpl = [...domAgg.values()].reduce((n, a) => n + a.impl, 0);
  const applicableDenom = [...domAgg.values()].reduce((n, a) => n + a.d, 0);
  const assessed = sc.implemented + sc["in-progress"] + sc["not-started"] + sc["not-applicable"];
  return {
    implementation: applicableDenom > 0 ? Math.round((totImpl / applicableDenom) * 100) : 0,
    evidence: delExp > 0 ? Math.round((delProd / delExp) * 100) : 0,
    total: CONTROLS.length, assessed, applicable: totApp,
    implemented: sc.implemented, inProgress: sc["in-progress"], notStarted: sc["not-started"], na: sc["not-applicable"],
    deliverablesExpected: delExp, deliverablesProduced: delProd,
    domains, statusCounts: sc,
  };
}

// ── assessments ──────────────────────────────────────────────────────────────────
export interface EccAssessmentRow {
  id: number; name: string; entityName: string; scope: string; assessor: string; status: string;
  implementation: number; evidence: number; assessed: number; total: number; notes: string;
  createdDate: string; updatedDate: string;
}

function statesFor(db: ReturnType<typeof getDb>, id: number): Map<string, EccControlState> {
  const rows = db.prepare("SELECT Ref, Status, DeliverablesDone FROM NCAECCCONTROL WHERE AssessmentID=?").all(id) as
    { Ref: string; Status: string; DeliverablesDone: string }[];
  const m = new Map<string, EccControlState>();
  for (const r of rows) {
    let done: number[] = [];
    try { done = JSON.parse(r.DeliverablesDone || "[]"); if (!Array.isArray(done)) done = []; } catch { done = []; }
    m.set(r.Ref, { status: r.Status || "", deliverablesDone: done });
  }
  return m;
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): EccAssessmentRow {
  const sc = scoreAssessment(statesFor(db, r.AssessmentID));
  return {
    id: r.AssessmentID, name: r.Name || "", entityName: r.EntityName || "", scope: r.Scope || "",
    assessor: r.Assessor || "", status: r.Status || "draft", implementation: sc.implementation, evidence: sc.evidence,
    assessed: sc.assessed, total: sc.total, notes: r.Notes || "", createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function ncaEccDashboard(tenant: number | null): {
  assessments: EccAssessmentRow[];
  summary: { assessments: number; completed: number; avgImplementation: number; avgEvidence: number };
  catalogue: { version: string; domains: number; subdomains: number; controls: number; deliverables: number };
} {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM NCAECCASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  const scored = assessments.filter((a) => a.assessed > 0);
  const avg = (f: (a: EccAssessmentRow) => number) => scored.length ? Math.round(scored.reduce((n, a) => n + f(a), 0) / scored.length) : 0;
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      completed: assessments.filter((a) => a.status === "completed").length,
      avgImplementation: avg((a) => a.implementation), avgEvidence: avg((a) => a.evidence),
    },
    catalogue: {
      version: GECC_CATALOGUE.version, domains: GECC_CATALOGUE.domains.length,
      subdomains: GECC_CATALOGUE.subdomains.length, controls: CONTROLS.length,
      deliverables: CONTROLS.reduce((n, c) => n + c.deliverables.length, 0),
    },
  };
}

export function ncaEccDetail(id: number, tenant: number | null): {
  assessment: EccAssessmentRow; score: EccScore;
  domains: { num: string; name: string; implementation: number; evidence: number; subdomains: any[] }[];
} | null {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM NCAECCASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const states = statesFor(db, id);
  const meta = new Map((db.prepare("SELECT Ref, Owner, EvidenceNote FROM NCAECCCONTROL WHERE AssessmentID=?").all(id) as
    { Ref: string; Owner: string; EvidenceNote: string }[]).map((x) => [x.Ref, x]));
  const sc = scoreAssessment(states);
  const domains = GECC_CATALOGUE.domains.map((dmn) => {
    const ds = sc.domains.find((x) => x.num === dmn.num)!;
    const subs = GECC_CATALOGUE.subdomains.filter((s) => s.domain === dmn.num).map((s) => ({
      code: s.code, name: s.name, objective: s.objective,
      controls: CONTROLS.filter((c) => c.subdomain === s.code).map((c) => {
        const st = states.get(c.ref); const md = meta.get(c.ref);
        return {
          ref: c.ref, text: c.text, tools: c.tools, guidelines: c.guidelines, deliverables: c.deliverables,
          subcontrols: c.subcontrols,
          status: st?.status || "", owner: md?.Owner || "", evidenceNote: md?.EvidenceNote || "",
          deliverablesDone: st?.deliverablesDone || [],
        };
      }),
    }));
    return { num: dmn.num, name: dmn.name, implementation: ds.implementation, evidence: ds.evidence, subdomains: subs };
  });
  return { assessment: rowToAssessment(db, r), score: sc, domains };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "NCAECCASSESSMENT", "AssessmentID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  db.prepare(
    `INSERT INTO NCAECCASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, EntityName, Scope,
       Assessor, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "NCA ECC implementation assessment", s("entityName", 200),
    s("scope", 400), s("assessor", 200), "draft", 0, s("notes", 2000), now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM NCAECCCONTROL WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM NCAECCASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM NCAECCASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  const map: Record<string, string> = { name: "Name", entityName: "EntityName", scope: "Scope", assessor: "Assessor", notes: "Notes" };
  for (const [k, col] of Object.entries(map)) if (k in b) { sets.push(`${col}=?`); vals.push(String(b[k] ?? "").slice(0, 2000)); }
  if ("status" in b && (ECC_ASSESS_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE NCAECCASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  return { ok: true };
}

/** Set a control's status / owner / evidence note / produced-deliverable indices. */
export function setControl(id: number, ref: string, patch: { status?: string; owner?: string; evidenceNote?: string; deliverablesDone?: number[] }):
  { ok: boolean; error?: string } {
  ensureNcaEccTables();
  const c = REFS.get(ref);
  if (!c) return { ok: false, error: `unknown control ${ref}` };
  if (patch.status != null && patch.status !== "" && !ECC_STATUS.some((s) => s.key === patch.status))
    return { ok: false, error: "invalid status" };
  const db = getDb("XCOMPLIANCE");
  const ex = db.prepare("SELECT ControlRowID, Status, Owner, EvidenceNote, DeliverablesDone FROM NCAECCCONTROL WHERE AssessmentID=? AND Ref=?")
    .get(id, ref) as any;
  const exp = c.deliverables.length;
  const done = patch.deliverablesDone != null
    ? JSON.stringify([...new Set(patch.deliverablesDone.filter((i) => Number.isInteger(i) && i >= 0 && i < exp))].sort((a, b) => a - b))
    : (ex?.DeliverablesDone ?? "[]");
  const status = patch.status != null ? patch.status : (ex?.Status ?? "");
  const owner = patch.owner != null ? String(patch.owner).slice(0, 200) : (ex?.Owner ?? "");
  const note = patch.evidenceNote != null ? String(patch.evidenceNote).slice(0, 3000) : (ex?.EvidenceNote ?? "");
  // If everything is cleared, drop the row.
  if (!status && !owner && !note && (done === "[]")) {
    if (ex) db.prepare("DELETE FROM NCAECCCONTROL WHERE ControlRowID=?").run(ex.ControlRowID);
  } else if (ex) {
    db.prepare("UPDATE NCAECCCONTROL SET Status=?, Owner=?, EvidenceNote=?, DeliverablesDone=?, UpdatedDate=? WHERE ControlRowID=?")
      .run(status, owner, note, done, now(), ex.ControlRowID);
  } else {
    db.prepare("INSERT INTO NCAECCCONTROL (ControlRowID, AssessmentID, Ref, Domain, Status, Owner, EvidenceNote, DeliverablesDone, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(allocId(db, "NCAECCCONTROL", "ControlRowID"), id, ref, c.domain, status, owner, note, done, now());
  }
  refreshScore(db, id);
  return { ok: true };
}

function refreshScore(db: ReturnType<typeof getDb>, id: number): void {
  const sc = scoreAssessment(statesFor(db, id));
  const status = sc.assessed === 0 ? "draft" : sc.assessed >= sc.total ? "completed" : "in-progress";
  db.prepare("UPDATE NCAECCASSESSMENT SET Score=?, Status=CASE WHEN Status='archived' THEN 'archived' ELSE ? END, UpdatedDate=? WHERE AssessmentID=?")
    .run(sc.implementation, status, now(), id);
}

// ── demo ─────────────────────────────────────────────────────────────────────────
export function seedNcaEccDemo(tenant: number): void {
  ensureNcaEccTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Government entity ECC implementation";
  if (db.prepare("SELECT 1 FROM NCAECCASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, { name, entityName: "Ministry ICT (demo)", scope: "All ECC domains (1-4)", assessor: "CISO office" });
  const pattern = ["implemented", "implemented", "in-progress", "not-started", "implemented", "not-applicable", "in-progress"];
  CONTROLS.forEach((c, i) => {
    if (i % 4 === 3) return; // leave ~1/4 unassessed
    const status = pattern[i % pattern.length];
    const exp = c.deliverables.length;
    const done = status === "implemented" && exp ? c.deliverables.map((_, k) => k).filter((k) => k % 2 === 0) : [];
    setControl(id, c.ref, { status, deliverablesDone: done });
  });
  db.prepare("UPDATE NCAECCASSESSMENT SET Status='in-progress' WHERE AssessmentID=?").run(id);
}
