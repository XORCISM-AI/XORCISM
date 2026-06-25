/**
 * control53.ts — NIST SP 800-53 Rev 5 control management.
 *
 * The 800-53 catalogue is imported by import_nist800-53.py -> XORCISM.CONTROL (VocabularyID=7:
 * ~1196 controls, 20 families), enriched with statement/guidance/params/related by
 * import_nist80053_details.py, baseline-tagged by import_nist80053_baselines.py, and crosswalked to
 * ATT&CK by import_attack_80053_mappings.py (CONTROLMAPPING). This module adds the management layer:
 *   - per-tenant implementation status + responsibility + owner + narrative + target (CONTROLIMPLEMENTATION),
 *   - per-tenant SP 800-53A assessment (Satisfied / Other-than-satisfied) on the same record,
 *   - POA&M — control deficiencies tracked to closure (CONTROLPOAM),
 *   - coverage / assessment / POA&M posture + a prioritised gap worklist,
 *   - a per-control detail view (full text + crosswalks + implementation + linked POA&M).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export const CONTROL_STATUSES = [
  "Implemented", "Partially Implemented", "Planned", "Not Implemented", "Not Applicable", "Inherited",
] as const;
export const CONTROL_RESPONSIBILITIES = [
  "Organization", "System", "Shared", "Inherited", "Provider", "Customer",
] as const;
export const ASSESSMENT_RESULTS = ["Satisfied", "Other Than Satisfied", "Not Assessed"] as const;
export const POAM_STATUSES = ["Open", "In Progress", "Delayed", "Completed", "Risk Accepted", "Cancelled"] as const;
export const POAM_SEVERITIES = ["Critical", "High", "Moderate", "Low"] as const;
const POAM_CLOSED = new Set(["Completed", "Risk Accepted", "Cancelled"]);

const VOCAB_800_53 = 7;
const GAP_STATUSES = new Set(["", "Partially Implemented", "Planned", "Not Implemented"]);
const STATUS_GAP_WEIGHT: Record<string, number> = {
  "": 3, "Not Implemented": 4, "Planned": 2, "Partially Implemented": 1,
};

function has(table: string): boolean {
  try { return !!getDb("XORCISM").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); }
  catch { return false; }
}
function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function famCode(ref: string): string { return String(ref || "").split("-")[0].toUpperCase(); }
function titleOf(name: string, ref: string): string {
  const n = String(name || "").trim();
  if (ref && n.toUpperCase().startsWith(ref.toUpperCase() + " ")) return n.slice(ref.length + 1).trim();
  return n;
}
function daysUntil(date: string | null): number | null {
  if (!date) return null; const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
function personNameExpr(table: string): string {
  const pc = cols("PERSON");
  return pc.has("FullName")
    ? "COALESCE(NULLIF(TRIM(FullName),''), NULLIF(TRIM(COALESCE(FirstName,'')||' '||COALESCE(LastName,'')),''), email, 'Person #'||PersonID)"
    : "COALESCE(NULLIF(TRIM(COALESCE(FirstName,'')||' '||COALESCE(LastName,'')),''), email, 'Person #'||PersonID)";
}
function loadPersons(): { persons: { id: number; name: string }[]; nameById: Map<number, string> } {
  const persons: { id: number; name: string }[] = []; const nameById = new Map<number, string>();
  if (has("PERSON")) {
    try {
      for (const p of getDb("XORCISM").prepare(`SELECT PersonID id, ${personNameExpr("PERSON")} name FROM PERSON ORDER BY name LIMIT 1000`).all() as { id: number; name: string }[]) {
        persons.push({ id: Number(p.id), name: String(p.name) }); nameById.set(Number(p.id), String(p.name));
      }
    } catch { /* PERSON shape differs */ }
  }
  return { persons, nameById };
}

interface CtrlRow {
  ControlID: number; ControlName: string; NIST: string; ControlDescription: string;
  BaselineLow: number | null; BaselineModerate: number | null; BaselineHigh: number | null; BaselinePrivacy: number | null;
}
interface ImplRow {
  ControlID: number; Status: string | null; Responsibility: string | null; Narrative: string | null;
  OwnerPersonID: number | null; TargetDate: string | null; LastReviewedDate: string | null;
  AssessmentResult: string | null; AssessedDate: string | null; AssessorPersonID: number | null; AssessmentRemarks: string | null;
}

export interface ControlInventory {
  controls: Record<string, unknown>[];
  families: Record<string, unknown>[];
  gaps: Record<string, unknown>[];
  poam: Record<string, unknown>[];
  persons: { id: number; name: string }[];
  statuses: readonly string[];
  responsibilities: readonly string[];
  assessmentResults: readonly string[];
  poamStatuses: readonly string[];
  poamSeverities: readonly string[];
  summary: Record<string, unknown>;
}

const EMPTY: ControlInventory = {
  controls: [], families: [], gaps: [], poam: [], persons: [],
  statuses: CONTROL_STATUSES, responsibilities: CONTROL_RESPONSIBILITIES, assessmentResults: ASSESSMENT_RESULTS,
  poamStatuses: POAM_STATUSES, poamSeverities: POAM_SEVERITIES,
  summary: { total: 0, loaded: false },
};

export function controlManagementInventory(tenant: number | null): ControlInventory {
  if (!has("CONTROL")) return { ...EMPTY };
  const db = getDb("XORCISM");
  const cc = cols("CONTROL");
  const hasBaseline = ["BaselineLow", "BaselineModerate", "BaselineHigh", "BaselinePrivacy"].every((c) => cc.has(c));
  const baseSel = hasBaseline
    ? "BaselineLow, BaselineModerate, BaselineHigh, BaselinePrivacy"
    : "NULL BaselineLow, NULL BaselineModerate, NULL BaselineHigh, NULL BaselinePrivacy";
  const ctrls = db.prepare(
    `SELECT ControlID, ControlName, NIST, ControlDescription, ${baseSel}
     FROM CONTROL WHERE VocabularyID = ${VOCAB_800_53} AND NIST IS NOT NULL AND TRIM(NIST) <> ''
     ORDER BY ControlID`
  ).all() as CtrlRow[];
  if (!ctrls.length) return { ...EMPTY };

  // Per-tenant implementation + assessment records (one per control).
  const implByControl = new Map<number, ImplRow>();
  if (has("CONTROLIMPLEMENTATION")) {
    const ic = cols("CONTROLIMPLEMENTATION");
    const asmt = ic.has("AssessmentResult") ? ", AssessmentResult, AssessedDate, AssessorPersonID, AssessmentRemarks" : "";
    const where = tenant != null ? "WHERE TenantID = ?" : "WHERE TenantID IS NULL";
    const rows = db.prepare(
      `SELECT ControlID, Status, Responsibility, Narrative, OwnerPersonID, TargetDate, LastReviewedDate${asmt}
       FROM CONTROLIMPLEMENTATION ${where}`
    ).all(...(tenant != null ? [tenant] : [])) as ImplRow[];
    for (const r of rows) implByControl.set(Number(r.ControlID), r);
  }

  // Crosswalk counts: per-control ATT&CK count (shown in the table) + a per-framework breakdown.
  const attackByControl = new Map<number, number>();
  let attackTechniques = 0; let attackTotal = 0;
  const fwBreakdown: Record<string, { total: number; externals: number; controls: number }> = {};
  if (has("CONTROLMAPPING")) {
    for (const r of db.prepare("SELECT ControlID, COUNT(*) n FROM CONTROLMAPPING WHERE Framework='ATT&CK' GROUP BY ControlID").all() as { ControlID: number; n: number }[]) {
      attackByControl.set(Number(r.ControlID), Number(r.n));
    }
    for (const r of db.prepare("SELECT Framework, COUNT(*) total, COUNT(DISTINCT ExternalID) externals, COUNT(DISTINCT ControlID) controls FROM CONTROLMAPPING GROUP BY Framework").all() as { Framework: string; total: number; externals: number; controls: number }[]) {
      fwBreakdown[String(r.Framework)] = { total: Number(r.total), externals: Number(r.externals), controls: Number(r.controls) };
    }
    attackTotal = fwBreakdown["ATT&CK"]?.total || 0;
    attackTechniques = fwBreakdown["ATT&CK"]?.externals || 0;
  }

  const { persons, nameById } = loadPersons();
  const baselinesOf = (r: CtrlRow): string[] => {
    const b: string[] = [];
    if (r.BaselineLow) b.push("L"); if (r.BaselineModerate) b.push("M");
    if (r.BaselineHigh) b.push("H"); if (r.BaselinePrivacy) b.push("P");
    return b;
  };

  const famAgg = new Map<string, { code: string; name: string; total: number; implemented: number; partial: number; planned: number; notImpl: number; na: number; inherited: number; unassigned: number }>();
  const byStatus: Record<string, number> = { Implemented: 0, "Partially Implemented": 0, Planned: 0, "Not Implemented": 0, "Not Applicable": 0, Inherited: 0, Unassigned: 0 };
  const byBaseline: Record<string, { total: number; implemented: number }> = {
    low: { total: 0, implemented: 0 }, moderate: { total: 0, implemented: 0 }, high: { total: 0, implemented: 0 }, privacy: { total: 0, implemented: 0 },
  };
  const assess = { satisfied: 0, otherThanSatisfied: 0, notAssessed: 0, assessed: 0 };
  const controls: Record<string, unknown>[] = [];
  const gaps: Record<string, unknown>[] = [];
  let enhancements = 0;

  for (const r of ctrls) {
    const ref = String(r.NIST).trim();
    const family = String(r.ControlDescription || "").trim() || "—";
    const code = famCode(ref);
    const enh = ref.includes("(");
    if (enh) enhancements++;
    const bl = baselinesOf(r);
    const impl = implByControl.get(Number(r.ControlID));
    const status = (impl?.Status || "").trim();
    const aResult = (impl?.AssessmentResult || "").trim();

    const fa = famAgg.get(family) ?? { code, name: family, total: 0, implemented: 0, partial: 0, planned: 0, notImpl: 0, na: 0, inherited: 0, unassigned: 0 };
    fa.total++;
    if (status === "Implemented") fa.implemented++;
    else if (status === "Partially Implemented") fa.partial++;
    else if (status === "Planned") fa.planned++;
    else if (status === "Not Implemented") fa.notImpl++;
    else if (status === "Not Applicable") fa.na++;
    else if (status === "Inherited") fa.inherited++;
    else fa.unassigned++;
    famAgg.set(family, fa);

    byStatus[status || "Unassigned"] = (byStatus[status || "Unassigned"] || 0) + 1;
    if (aResult === "Satisfied") { assess.satisfied++; assess.assessed++; }
    else if (aResult === "Other Than Satisfied") { assess.otherThanSatisfied++; assess.assessed++; }
    else if (aResult === "Not Assessed") { assess.notAssessed++; }

    const counted = status === "Implemented";
    if (r.BaselineLow) { byBaseline.low.total++; if (counted) byBaseline.low.implemented++; }
    if (r.BaselineModerate) { byBaseline.moderate.total++; if (counted) byBaseline.moderate.implemented++; }
    if (r.BaselineHigh) { byBaseline.high.total++; if (counted) byBaseline.high.implemented++; }
    if (r.BaselinePrivacy) { byBaseline.privacy.total++; if (counted) byBaseline.privacy.implemented++; }

    const ownerId = impl?.OwnerPersonID != null ? Number(impl.OwnerPersonID) : null;
    controls.push({
      id: Number(r.ControlID), ref, title: titleOf(r.ControlName, ref), family, familyCode: code, enhancement: enh,
      baselines: bl, status: status || "", responsibility: (impl?.Responsibility || "").trim(),
      ownerPersonId: ownerId, owner: ownerId != null ? (nameById.get(ownerId) || `Person #${ownerId}`) : "",
      targetDate: impl?.TargetDate ? String(impl.TargetDate).slice(0, 10) : "",
      narrative: impl?.Narrative || "", reviewed: impl?.LastReviewedDate ? String(impl.LastReviewedDate).slice(0, 10) : "",
      assessment: aResult, attackCount: attackByControl.get(Number(r.ControlID)) || 0,
    });

    if (GAP_STATUSES.has(status)) {
      const baseW = r.BaselineLow ? 3 : r.BaselineModerate ? 2 : r.BaselineHigh ? 1 : (hasBaseline ? 0 : 1);
      if (baseW > 0) {
        const score = baseW * 2 + (STATUS_GAP_WEIGHT[status] || 0) + (r.BaselinePrivacy ? 1 : 0);
        gaps.push({ id: Number(r.ControlID), ref, title: titleOf(r.ControlName, ref), family, familyCode: code, baselines: bl, status: status || "Unassigned", score });
      }
    }
  }

  const families = [...famAgg.values()].map((f) => ({
    ...f, coveragePct: f.total ? Math.round(((f.implemented + f.partial * 0.5) / f.total) * 100) : 0,
  })).sort((a, b) => a.code.localeCompare(b.code));
  gaps.sort((a, b) => (Number(b.score) - Number(a.score)) || String(a.ref).localeCompare(String(b.ref)));

  // POA&M (per tenant).
  const poam: Record<string, unknown>[] = [];
  const poamSummary = { total: 0, open: 0, overdue: 0, completed: 0 };
  if (has("CONTROLPOAM")) {
    const where = tenant != null ? "WHERE p.TenantID = ?" : "WHERE p.TenantID IS NULL";
    const rows = db.prepare(
      `SELECT p.PoamID id, p.ControlID controlId, c.NIST ref, p.Title title, p.Severity severity, p.Status status,
              p.OwnerPersonID ownerPersonId, p.ScheduledCompletionDate scheduled, p.ActualCompletionDate actual, p.WeaknessDescription weakness
       FROM CONTROLPOAM p LEFT JOIN CONTROL c ON c.ControlID = p.ControlID ${where} ORDER BY p.PoamID DESC`
    ).all(...(tenant != null ? [tenant] : [])) as Record<string, any>[];
    for (const r of rows) {
      const status = String(r.status || "Open").trim();
      const open = !POAM_CLOSED.has(status);
      const dueIn = daysUntil(r.scheduled ? String(r.scheduled) : null);
      const overdue = open && dueIn != null && dueIn < 0;
      poamSummary.total++;
      if (open) poamSummary.open++; else if (status === "Completed") poamSummary.completed++;
      if (overdue) poamSummary.overdue++;
      poam.push({
        id: Number(r.id), controlId: r.controlId != null ? Number(r.controlId) : null, ref: r.ref || "",
        title: String(r.title || "").trim() || `POA&M #${r.id}`, severity: String(r.severity || "").trim(), status,
        ownerPersonId: r.ownerPersonId != null ? Number(r.ownerPersonId) : null,
        owner: r.ownerPersonId != null ? (nameById.get(Number(r.ownerPersonId)) || `Person #${r.ownerPersonId}`) : "",
        scheduled: r.scheduled ? String(r.scheduled).slice(0, 10) : "", actual: r.actual ? String(r.actual).slice(0, 10) : "",
        overdue, open,
      });
    }
  }

  const total = ctrls.length;
  const implemented = byStatus.Implemented;
  const partial = byStatus["Partially Implemented"];
  const coveragePct = total ? Math.round(((implemented + partial * 0.5) / total) * 100) : 0;

  return {
    controls, families, gaps: gaps.slice(0, 200), poam, persons,
    statuses: CONTROL_STATUSES, responsibilities: CONTROL_RESPONSIBILITIES, assessmentResults: ASSESSMENT_RESULTS,
    poamStatuses: POAM_STATUSES, poamSeverities: POAM_SEVERITIES,
    summary: {
      loaded: true, total, base: total - enhancements, enhancements, familyCount: families.length,
      implemented, partial, planned: byStatus.Planned, notImplemented: byStatus["Not Implemented"],
      notApplicable: byStatus["Not Applicable"], inherited: byStatus.Inherited, unassigned: byStatus.Unassigned,
      assessed: total - byStatus.Unassigned, coveragePct, gapCount: gaps.length,
      baselinesLoaded: hasBaseline && (byBaseline.low.total + byBaseline.moderate.total + byBaseline.high.total + byBaseline.privacy.total) > 0,
      byStatus, byBaseline,
      assessment: assess,
      mappings: { attackTotal, attackTechniques, attackControls: attackByControl.size, loaded: attackTotal > 0, byFramework: fwBreakdown },
      poam: poamSummary,
      textLoaded: cc.has("Statement"),
    },
  };
}

/** Full detail of one control: text + crosswalks + this tenant's implementation/assessment + linked POA&M. */
export function controlDetail(controlId: number, tenant: number | null): Record<string, unknown> | null {
  if (!has("CONTROL")) return null;
  const db = getDb("XORCISM");
  const cc = cols("CONTROL");
  const textSel = cc.has("Statement") ? ", Statement, Guidance, Params, RelatedControls" : "";
  const blSel = cc.has("BaselineLow") ? ", BaselineLow, BaselineModerate, BaselineHigh, BaselinePrivacy" : "";
  const c = db.prepare(`SELECT ControlID, ControlName, NIST, ControlDescription${textSel}${blSel} FROM CONTROL WHERE ControlID = ?`).get(controlId) as Record<string, any> | undefined;
  if (!c) return null;
  const ref = String(c.NIST || "").trim();
  const bl: string[] = [];
  if (c.BaselineLow) bl.push("L"); if (c.BaselineModerate) bl.push("M"); if (c.BaselineHigh) bl.push("H"); if (c.BaselinePrivacy) bl.push("P");

  const mappings: Record<string, { id: string; name: string; rel: string }[]> = {};
  if (has("CONTROLMAPPING")) {
    for (const m of db.prepare("SELECT Framework, ExternalID, ExternalName, Relationship FROM CONTROLMAPPING WHERE ControlID = ? ORDER BY Framework, ExternalID").all(controlId) as Record<string, any>[]) {
      const fw = String(m.Framework || "Other");
      (mappings[fw] ??= []).push({ id: String(m.ExternalID || ""), name: String(m.ExternalName || ""), rel: String(m.Relationship || "") });
    }
  }

  let implementation: Record<string, unknown> | null = null;
  if (has("CONTROLIMPLEMENTATION")) {
    const ic = cols("CONTROLIMPLEMENTATION");
    const asmt = ic.has("AssessmentResult") ? ", AssessmentResult, AssessedDate, AssessorPersonID, AssessmentRemarks" : "";
    const where = tenant != null ? "WHERE ControlID = ? AND TenantID = ?" : "WHERE ControlID = ? AND TenantID IS NULL";
    const r = db.prepare(`SELECT Status, Responsibility, Narrative, OwnerPersonID, TargetDate, LastReviewedDate${asmt} FROM CONTROLIMPLEMENTATION ${where}`)
      .get(...(tenant != null ? [controlId, tenant] : [controlId])) as Record<string, any> | undefined;
    if (r) {
      const { nameById } = loadPersons();
      implementation = {
        status: r.Status || "", responsibility: r.Responsibility || "", narrative: r.Narrative || "",
        ownerPersonId: r.OwnerPersonID ?? null, owner: r.OwnerPersonID != null ? (nameById.get(Number(r.OwnerPersonID)) || "") : "",
        targetDate: r.TargetDate ? String(r.TargetDate).slice(0, 10) : "",
        assessmentResult: r.AssessmentResult || "", assessedDate: r.AssessedDate ? String(r.AssessedDate).slice(0, 10) : "",
        assessorPersonId: r.AssessorPersonID ?? null, assessmentRemarks: r.AssessmentRemarks || "",
      };
    }
  }

  const poam: Record<string, unknown>[] = [];
  if (has("CONTROLPOAM")) {
    const where = tenant != null ? "WHERE ControlID = ? AND TenantID = ?" : "WHERE ControlID = ? AND TenantID IS NULL";
    for (const p of db.prepare(`SELECT PoamID id, Title title, Status status, Severity severity, ScheduledCompletionDate scheduled FROM CONTROLPOAM ${where} ORDER BY PoamID DESC`)
      .all(...(tenant != null ? [controlId, tenant] : [controlId])) as Record<string, any>[]) {
      poam.push({ id: Number(p.id), title: String(p.title || "").trim(), status: String(p.status || "").trim(), severity: String(p.severity || "").trim(), scheduled: p.scheduled ? String(p.scheduled).slice(0, 10) : "" });
    }
  }

  return {
    id: Number(c.ControlID), ref, title: titleOf(c.ControlName, ref), family: String(c.ControlDescription || "").trim(),
    baselines: bl, statement: c.Statement || "", guidance: c.Guidance || "", params: c.Params || "",
    related: String(c.RelatedControls || "").split(",").map((x) => x.trim()).filter(Boolean),
    mappings, implementation, poam,
  };
}

/**
 * Upsert the per-tenant implementation + assessment record for one control (org-wide).
 * Column-aware; MAX+1 id + GUID on insert. `undefined` = leave; empty string = clear the field.
 */
export function setControlImplementation(
  controlId: number,
  p: {
    status?: string; responsibility?: string; narrative?: string; ownerPersonId?: number | null; targetDate?: string | null;
    assessmentResult?: string; assessedDate?: string | null; assessorPersonId?: number | null; assessmentRemarks?: string;
  },
  tenant: number | null,
): { ok: boolean } {
  if (!has("CONTROLIMPLEMENTATION")) return { ok: false };
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT ControlID FROM CONTROL WHERE ControlID = ?").get(controlId)) return { ok: false };

  const status = p.status != null ? String(p.status).trim() : undefined;
  if (status && !CONTROL_STATUSES.includes(status as typeof CONTROL_STATUSES[number])) throw new Error(`invalid status "${status}"`);
  const resp = p.responsibility != null ? String(p.responsibility).trim() : undefined;
  if (resp && !CONTROL_RESPONSIBILITIES.includes(resp as typeof CONTROL_RESPONSIBILITIES[number])) throw new Error(`invalid responsibility "${resp}"`);
  const aResult = p.assessmentResult != null ? String(p.assessmentResult).trim() : undefined;
  if (aResult && !ASSESSMENT_RESULTS.includes(aResult as typeof ASSESSMENT_RESULTS[number])) throw new Error(`invalid assessment result "${aResult}"`);

  const c = cols("CONTROLIMPLEMENTATION");
  const now = new Date().toISOString();
  const set: Record<string, unknown> = {};
  if (status !== undefined && c.has("Status")) set.Status = status || null;
  if (resp !== undefined && c.has("Responsibility")) set.Responsibility = resp || null;
  if (p.narrative !== undefined && c.has("Narrative")) set.Narrative = String(p.narrative).trim() || null;
  if (p.ownerPersonId !== undefined && c.has("OwnerPersonID")) set.OwnerPersonID = p.ownerPersonId != null && String(p.ownerPersonId) !== "" ? Number(p.ownerPersonId) : null;
  if (p.targetDate !== undefined && c.has("TargetDate")) set.TargetDate = p.targetDate ? String(p.targetDate) : null;
  if (aResult !== undefined && c.has("AssessmentResult")) set.AssessmentResult = aResult || null;
  if (p.assessedDate !== undefined && c.has("AssessedDate")) set.AssessedDate = p.assessedDate ? String(p.assessedDate) : null;
  if (p.assessorPersonId !== undefined && c.has("AssessorPersonID")) set.AssessorPersonID = p.assessorPersonId != null && String(p.assessorPersonId) !== "" ? Number(p.assessorPersonId) : null;
  if (p.assessmentRemarks !== undefined && c.has("AssessmentRemarks")) set.AssessmentRemarks = String(p.assessmentRemarks).trim() || null;
  // Stamp an assessment date when a result is set without an explicit date.
  if (set.AssessmentResult && set.AssessedDate === undefined && c.has("AssessedDate")) set.AssessedDate = now.slice(0, 10);
  if (c.has("LastReviewedDate")) set.LastReviewedDate = now;

  const where = tenant != null ? "WHERE ControlID = ? AND TenantID = ?" : "WHERE ControlID = ? AND TenantID IS NULL";
  const existing = db.prepare(`SELECT ControlImplementationID FROM CONTROLIMPLEMENTATION ${where}`)
    .get(...(tenant != null ? [controlId, tenant] : [controlId])) as { ControlImplementationID: number } | undefined;

  if (existing) {
    const keys = Object.keys(set);
    if (!keys.length) return { ok: true };
    db.prepare(`UPDATE CONTROLIMPLEMENTATION SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE ControlImplementationID = ?`)
      .run(...keys.map((k) => set[k]), existing.ControlImplementationID);
    return { ok: true };
  }
  const nextId = allocId(db, "CONTROLIMPLEMENTATION", "ControlImplementationID");
  const insert: Record<string, unknown> = { ControlImplementationID: nextId, ControlID: controlId, ...set };
  if (c.has("ControlImplementationGUID")) insert.ControlImplementationGUID = randomUUID();
  if (c.has("CreatedDate")) insert.CreatedDate = now;
  if (c.has("TenantID")) insert.TenantID = tenant;
  const keys = Object.keys(insert).filter((k) => c.has(k));
  db.prepare(`INSERT INTO CONTROLIMPLEMENTATION (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`)
    .run(...keys.map((k) => insert[k]));
  return { ok: true };
}

/** Create a POA&M item (control deficiency tracked to closure). */
export function createPoam(
  p: { controlId?: number | null; title: string; weaknessDescription?: string; severity?: string; status?: string;
       remediationPlan?: string; milestones?: string; ownerPersonId?: number | null; scheduledCompletionDate?: string | null },
  tenant: number | null,
): { id: number } {
  if (!has("CONTROLPOAM")) throw new Error("POA&M store unavailable");
  const db = getDb("XORCISM");
  const title = String(p.title || "").trim();
  if (!title) throw new Error("title required");
  const severity = p.severity ? String(p.severity).trim() : "";
  if (severity && !POAM_SEVERITIES.includes(severity as typeof POAM_SEVERITIES[number])) throw new Error(`invalid severity "${severity}"`);
  const status = p.status ? String(p.status).trim() : "Open";
  if (!POAM_STATUSES.includes(status as typeof POAM_STATUSES[number])) throw new Error(`invalid status "${status}"`);

  const c = cols("CONTROLPOAM");
  const now = new Date().toISOString();
  const nextId = allocId(db, "CONTROLPOAM", "PoamID");
  const row: Record<string, unknown> = {
    PoamID: nextId, PoamGUID: randomUUID(), ControlID: p.controlId != null && String(p.controlId) !== "" ? Number(p.controlId) : null,
    Title: title, WeaknessDescription: p.weaknessDescription ? String(p.weaknessDescription).trim() : null,
    Severity: severity || null, Status: status, RemediationPlan: p.remediationPlan ? String(p.remediationPlan).trim() : null,
    Milestones: p.milestones ? String(p.milestones).trim() : null,
    OwnerPersonID: p.ownerPersonId != null && String(p.ownerPersonId) !== "" ? Number(p.ownerPersonId) : null,
    ScheduledCompletionDate: p.scheduledCompletionDate ? String(p.scheduledCompletionDate) : null,
    CreatedDate: now, TenantID: tenant,
  };
  const keys = Object.keys(row).filter((k) => c.has(k));
  db.prepare(`INSERT INTO CONTROLPOAM (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`)
    .run(...keys.map((k) => row[k]));
  return { id: nextId };
}

/** Update a POA&M item (status / fields). Tenant-scoped. Completing it stamps ActualCompletionDate. */
export function updatePoam(
  poamId: number,
  p: { title?: string; weaknessDescription?: string; severity?: string; status?: string; remediationPlan?: string;
       milestones?: string; ownerPersonId?: number | null; scheduledCompletionDate?: string | null; actualCompletionDate?: string | null },
  tenant: number | null,
): { ok: boolean } {
  if (!has("CONTROLPOAM")) return { ok: false };
  const db = getDb("XORCISM");
  const where = tenant != null ? "WHERE PoamID = ? AND TenantID = ?" : "WHERE PoamID = ? AND TenantID IS NULL";
  const existing = db.prepare(`SELECT PoamID FROM CONTROLPOAM ${where}`).get(...(tenant != null ? [poamId, tenant] : [poamId]));
  if (!existing) return { ok: false };

  const status = p.status != null ? String(p.status).trim() : undefined;
  if (status && !POAM_STATUSES.includes(status as typeof POAM_STATUSES[number])) throw new Error(`invalid status "${status}"`);
  const severity = p.severity != null ? String(p.severity).trim() : undefined;
  if (severity && !POAM_SEVERITIES.includes(severity as typeof POAM_SEVERITIES[number])) throw new Error(`invalid severity "${severity}"`);

  const c = cols("CONTROLPOAM");
  const set: Record<string, unknown> = {};
  if (p.title !== undefined && c.has("Title")) set.Title = String(p.title).trim();
  if (p.weaknessDescription !== undefined && c.has("WeaknessDescription")) set.WeaknessDescription = String(p.weaknessDescription).trim() || null;
  if (severity !== undefined && c.has("Severity")) set.Severity = severity || null;
  if (status !== undefined && c.has("Status")) set.Status = status;
  if (p.remediationPlan !== undefined && c.has("RemediationPlan")) set.RemediationPlan = String(p.remediationPlan).trim() || null;
  if (p.milestones !== undefined && c.has("Milestones")) set.Milestones = String(p.milestones).trim() || null;
  if (p.ownerPersonId !== undefined && c.has("OwnerPersonID")) set.OwnerPersonID = p.ownerPersonId != null && String(p.ownerPersonId) !== "" ? Number(p.ownerPersonId) : null;
  if (p.scheduledCompletionDate !== undefined && c.has("ScheduledCompletionDate")) set.ScheduledCompletionDate = p.scheduledCompletionDate ? String(p.scheduledCompletionDate) : null;
  if (p.actualCompletionDate !== undefined && c.has("ActualCompletionDate")) set.ActualCompletionDate = p.actualCompletionDate ? String(p.actualCompletionDate) : null;
  if (status === "Completed" && p.actualCompletionDate === undefined && c.has("ActualCompletionDate")) set.ActualCompletionDate = new Date().toISOString().slice(0, 10);

  const keys = Object.keys(set);
  if (!keys.length) return { ok: true };
  db.prepare(`UPDATE CONTROLPOAM SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE PoamID = ?`).run(...keys.map((k) => set[k]), poamId);
  return { ok: true };
}
