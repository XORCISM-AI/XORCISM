/**
 * fairmam.ts — FAIR-MAM (FAIR Materiality Assessment Model) loss-magnitude decomposition +
 * materiality determination.
 *
 * Built on the FAIR Institute's open materiality model: a cyber loss event's single-loss
 * magnitude is decomposed across 10 standardized cost categories (FAIRMAMCATEGORY), each
 * estimated as a PERT distribution (min / most-likely / max). The expected loss per line is
 * E = (min + 4·mostLikely + max) / 6; categories are classified by FAIR loss form (primary /
 * secondary) and party (first-party / third-party). The total is compared to a materiality
 * threshold → Material / Approaching / Not material. Extends the CRQ/FAIR already on
 * XCOMPLIANCE.RISKREGISTERENTRY (PrimaryLoss / SecondaryLoss / SingleLossExpectancy).
 * Read-only inventory; the assessment write is a dedicated endpoint.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface FairMamCategory {
  id: number; code: string; name: string; parent: string | null;
  lossType: "primary" | "secondary"; party: "first-party" | "third-party";
  description: string; sortOrder: number;
}
export interface LineInput { categoryId: number; min?: number; mostLikely?: number; max?: number; notes?: string }
export interface AssessmentRow {
  id: number; name: string; scenarioRef: string | null; currency: string;
  total: number; primary: number; secondary: number; firstParty: number; thirdParty: number;
  threshold: number | null; ratio: number | null; determination: string; lineCount: number;
  createdDate: string | null;
}
export interface FairMamInventory {
  categories: FairMamCategory[];
  assessments: AssessmentRow[];
  risks: { id: number; ref: string; title: string }[];   // open risk-register entries an assessment can write back to
  summary: {
    assessments: number; material: number; approaching: number;
    largestExposure: number; totalExposure: number; currency: string;
    avgPrimaryShare: number | null;
  };
}

/** Open risk-register entries (id/ref/title) an assessment can be linked to + write back to. */
function linkableRisks(tenant: number | null): { id: number; ref: string; title: string }[] {
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return []; }
  if (!has(cc, "RISKREGISTERENTRY")) return [];
  try {
    const rc = new Set((cc.prepare(`PRAGMA table_info("RISKREGISTERENTRY")`).all() as { name: string }[]).map((c) => c.name));
    const tw = tenant != null && rc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    return (cc.prepare(`SELECT RiskRegisterEntryID id, Ref ref, Title title FROM RISKREGISTERENTRY ${tw} ORDER BY RiskRegisterEntryID DESC LIMIT 500`).all() as { id: number; ref: string; title: string }[])
      .map((r) => ({ id: Number(r.id), ref: String(r.ref ?? `R-${r.id}`), title: String(r.title ?? "") }));
  } catch { return []; }
}

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

/** PERT expected value; falls back to most-likely (or the mean of whatever is provided). */
export function pertExpected(min?: number, ml?: number, max?: number): number {
  const lo = Number(min), m = Number(ml), hi = Number(max);
  const hasLo = Number.isFinite(lo), hasM = Number.isFinite(m), hasHi = Number.isFinite(hi);
  if (hasLo && hasM && hasHi) return (lo + 4 * m + hi) / 6;
  if (hasM) return m;
  const vals = [lo, hi].filter((x) => Number.isFinite(x));
  return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
}

export function determination(total: number, threshold: number | null): string {
  if (!threshold || threshold <= 0) return "Unassessed";
  if (total >= threshold) return "Material";
  if (total >= 0.5 * threshold) return "Approaching";
  return "Not material";
}

export function fairMamCategories(_tenant: number | null): FairMamCategory[] {
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return []; }
  if (!has(cc, "FAIRMAMCATEGORY")) return [];
  return (cc.prepare("SELECT CategoryID id, Code code, Name name, ParentCode parent, LossType lossType, Party party, Description description, SortOrder sortOrder FROM FAIRMAMCATEGORY ORDER BY SortOrder").all() as FairMamCategory[]);
}

/** Full FAIR-MAM inventory: the taxonomy + every saved assessment with its computed totals. */
export function fairMamInventory(tenant: number | null): FairMamInventory {
  const categories = fairMamCategories(tenant);
  const risks = linkableRisks(tenant);
  const empty: FairMamInventory = { categories, assessments: [], risks, summary: { assessments: 0, material: 0, approaching: 0, largestExposure: 0, totalExposure: 0, currency: "EUR", avgPrimaryShare: null } };
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return empty; }
  if (!has(cc, "FAIRMAMASSESSMENT") || !categories.length) return empty;

  const catById = new Map(categories.map((c) => [c.id, c]));
  const tw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
  const rows = cc.prepare(`SELECT * FROM FAIRMAMASSESSMENT ${tw} ORDER BY AssessmentID DESC`).all() as Record<string, unknown>[];
  if (!rows.length) return { ...empty, summary: { ...empty.summary } };

  // all line items for these assessments (one query)
  const ids = rows.map((r) => Number(r.AssessmentID));
  const ph = ids.map(() => "?").join(",") || "NULL";
  const lines = has(cc, "FAIRMAMLINEITEM")
    ? cc.prepare(`SELECT AssessmentID, CategoryID, Minimum, MostLikely, Maximum FROM FAIRMAMLINEITEM WHERE AssessmentID IN (${ph})`).all(...ids) as Record<string, unknown>[]
    : [];
  const byAssessment = new Map<number, Record<string, unknown>[]>();
  for (const l of lines) { const a = Number(l.AssessmentID); (byAssessment.get(a) ?? byAssessment.set(a, []).get(a)!).push(l); }

  const assessments: AssessmentRow[] = rows.map((r) => {
    const id = Number(r.AssessmentID);
    const ls = byAssessment.get(id) ?? [];
    let total = 0, primary = 0, secondary = 0, firstParty = 0, thirdParty = 0;
    // preserve a stored 0 (a real estimate); only a NULL column is "not provided".
    const cell = (x: unknown): number | undefined => { if (x == null) return undefined; const n = Number(x); return Number.isFinite(n) ? n : undefined; };
    for (const l of ls) {
      const e = pertExpected(cell(l.Minimum), cell(l.MostLikely), cell(l.Maximum));
      if (!e) continue;
      total += e;
      const cat = catById.get(Number(l.CategoryID));
      if (cat?.lossType === "secondary") secondary += e; else primary += e;
      if (cat?.party === "third-party") thirdParty += e; else firstParty += e;
    }
    const threshold = r.MaterialityThreshold != null ? num(r.MaterialityThreshold) : null;
    return {
      id, name: String(r.Name ?? `Assessment #${id}`), scenarioRef: (r.ScenarioRef as string) ?? null,
      currency: String(r.Currency ?? "EUR"),
      total: Math.round(total), primary: Math.round(primary), secondary: Math.round(secondary),
      firstParty: Math.round(firstParty), thirdParty: Math.round(thirdParty),
      threshold, ratio: threshold ? Math.round((total / threshold) * 100) : null,
      determination: String(r.Determination ?? "") || determination(total, threshold),
      lineCount: ls.length, createdDate: r.CreatedDate ? String(r.CreatedDate).slice(0, 10) : null,
    };
  });

  const material = assessments.filter((a) => a.determination === "Material").length;
  const approaching = assessments.filter((a) => a.determination === "Approaching").length;
  const totals = assessments.map((a) => a.total);
  const shares = assessments.filter((a) => a.total > 0).map((a) => a.primary / a.total);
  return {
    categories, assessments, risks,
    summary: {
      assessments: assessments.length, material, approaching,
      largestExposure: totals.length ? Math.max(...totals) : 0,
      totalExposure: totals.reduce((a, b) => a + b, 0),
      currency: assessments[0]?.currency ?? "EUR",
      avgPrimaryShare: shares.length ? Math.round((shares.reduce((a, b) => a + b, 0) / shares.length) * 100) : null,
    },
  };
}

/** Compute a result from line inputs without persisting (live calculator). */
export function computeFairMam(lines: LineInput[], threshold: number | null): { total: number; primary: number; secondary: number; firstParty: number; thirdParty: number; byCategory: { code: string; name: string; expected: number }[]; determination: string; ratio: number | null } {
  const all = fairMamCategories(null);
  const cats = new Map(all.map((c) => [c.id, c]));
  const byCode = new Map(all.map((c) => [c.code, c]));
  let total = 0, primary = 0, secondary = 0, firstParty = 0, thirdParty = 0;
  const topByCode = new Map<string, { code: string; name: string; expected: number }>();
  for (const l of lines) {
    const e = pertExpected(l.min, l.mostLikely, l.max);
    if (!e) continue;
    const cat = cats.get(Number(l.categoryId));
    total += e;
    if (cat?.lossType === "secondary") secondary += e; else primary += e;
    if (cat?.party === "third-party") thirdParty += e; else firstParty += e;
    // roll up to the top-level category (the line's parent, or itself if it is top-level)
    const topCode = cat?.parent || cat?.code || "?";
    const acc = topByCode.get(topCode) ?? { code: topCode, name: byCode.get(topCode)?.name ?? topCode, expected: 0 };
    acc.expected += e; topByCode.set(topCode, acc);
  }
  return {
    total: Math.round(total), primary: Math.round(primary), secondary: Math.round(secondary),
    firstParty: Math.round(firstParty), thirdParty: Math.round(thirdParty),
    byCategory: [...topByCode.values()].map((c) => ({ ...c, expected: Math.round(c.expected) })).sort((a, b) => b.expected - a.expected),
    determination: determination(total, threshold), ratio: threshold ? Math.round((total / threshold) * 100) : null,
  };
}

/** Persist a FAIR-MAM assessment + its line items; stores the computed determination. */
export function saveFairMamAssessment(
  payload: { name?: string; scenarioRef?: string; riskRegisterEntryId?: number; incidentId?: number; currency?: string; threshold?: number; revenueBasis?: number; lines?: LineInput[] },
  tenant: number | null, userId: number | null,
): { assessmentId: number; total: number; determination: string; ratio: number | null; riskWriteback: { id: number; ref: string; sle: number; primary: number; secondary: number; ale: number | null } | null } {
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const lines = (payload.lines || []).filter((l) => l && l.categoryId && (l.min || l.mostLikely || l.max));
  const threshold = payload.threshold != null && Number.isFinite(Number(payload.threshold)) ? Number(payload.threshold) : null;
  const computed = computeFairMam(lines, threshold);

  const tx = cc.transaction(() => {
    const r = cc.prepare(
      `INSERT INTO FAIRMAMASSESSMENT (AssessmentGUID, Name, ScenarioRef, RiskRegisterEntryID, IncidentID, Currency, MaterialityThreshold, RevenueBasis, Status, Determination, PersonID, CreatedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(randomUUID(), (payload.name || `FAIR-MAM assessment ${now.slice(0, 10)}`).slice(0, 300),
      payload.scenarioRef ? String(payload.scenarioRef).slice(0, 300) : null,
      payload.riskRegisterEntryId ?? null, payload.incidentId ?? null,
      (payload.currency || "EUR").slice(0, 8), threshold, payload.revenueBasis ?? null,
      "Final", computed.determination, userId, now, tenant);
    const aid = Number(r.lastInsertRowid);
    const ins = cc.prepare("INSERT INTO FAIRMAMLINEITEM (AssessmentID, CategoryID, Minimum, MostLikely, Maximum, Notes, TenantID) VALUES (?,?,?,?,?,?,?)");
    for (const l of lines) ins.run(aid, Number(l.categoryId), l.min ?? null, l.mostLikely ?? null, l.max ?? null, l.notes ? String(l.notes).slice(0, 500) : null, tenant);
    return aid;
  });
  const assessmentId = tx();

  // Write the computed magnitude back onto the linked risk register entry: the FAIR-MAM total is
  // the risk's Single Loss Expectancy, with its primary/secondary split; if the risk carries a
  // Loss Event Frequency, derive ALE = SLE × LEF. Best-effort, tenant-guarded.
  let riskWriteback: { id: number; ref: string; sle: number; primary: number; secondary: number; ale: number | null } | null = null;
  const rid = Number(payload.riskRegisterEntryId) || 0;
  if (rid && has(cc, "RISKREGISTERENTRY")) {
    try {
      const rcols = new Set((cc.prepare(`PRAGMA table_info("RISKREGISTERENTRY")`).all() as { name: string }[]).map((c) => c.name));
      const tenantGuard = tenant != null && rcols.has("TenantID") ? " AND TenantID = ?" : "";
      const entry = cc.prepare(`SELECT Ref, LossEventFrequency FROM RISKREGISTERENTRY WHERE RiskRegisterEntryID = ?${tenantGuard}`)
        .get(...(tenantGuard ? [rid, tenant] : [rid])) as { Ref?: string; LossEventFrequency?: unknown } | undefined;
      if (entry) {
        const lef = Number(entry.LossEventFrequency);
        const ale = Number.isFinite(lef) && lef > 0 ? Math.round(computed.total * lef) : null;
        cc.prepare(
          `UPDATE RISKREGISTERENTRY SET SingleLossExpectancy = ?, PrimaryLoss = ?, SecondaryLoss = ?,
             AnnualizedLossExpectancy = COALESCE(?, AnnualizedLossExpectancy), Currency = ?
           WHERE RiskRegisterEntryID = ?${tenantGuard}`,
        ).run(...[computed.total, computed.primary, computed.secondary, ale, (payload.currency || "EUR").slice(0, 8), rid, ...(tenantGuard ? [tenant] : [])]);
        riskWriteback = { id: rid, ref: String(entry.Ref ?? `R-${rid}`), sle: computed.total, primary: computed.primary, secondary: computed.secondary, ale };
      }
    } catch { /* write-back is best-effort */ }
  }

  return { assessmentId, total: computed.total, determination: computed.determination, ratio: computed.ratio, riskWriteback };
}
