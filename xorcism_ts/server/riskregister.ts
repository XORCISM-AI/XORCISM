/**
 * riskregister.ts — Risk Register inventory + governance worklist.
 *
 * The risk-management counterpart of assets.ts / compliance.ts: one pane over the risk register
 * (XCOMPLIANCE.RISKREGISTERENTRY) — each risk's inherent → current → residual level, treatment
 * strategy/owner/review, and its CRQ/FAIR quantification (Annualized Loss Expectancy). The
 * worklist surfaces what matters: high/critical residual risks left untreated, risks accepted
 * without justification, overdue reviews, treatments past their target date and unowned risks.
 * Each risk gets a 0-100 priority score. Read-only; CRUD stays in the schema-driven explorer.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface RiskRow {
  id: number;
  ref: string;
  title: string;
  category: string;
  owner: string | null;
  asset: string | null;
  status: string;
  open: boolean;
  inherent: string;
  current: string;
  residual: string;
  residualRank: number;       // 0 critical … 4 very-low, 5 unrated
  treatment: string;
  hasPlan: boolean;
  ale: number | null;
  sle: number | null;
  currency: string;
  reviewInDays: number | null;
  reviewOverdue: boolean;
  score: number;              // 0-100 priority (higher = worse)
  overAppetite: boolean;      // residual exceeds the category's risk appetite/tolerance
  measures: number;           // count of linked measures from the library
}
export interface RiskFinding {
  id: number; ref: string; title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  reason: string; kind: "untreated" | "accepted" | "review" | "target" | "owner" | "appetite";
  label: string;
}
export interface RiskInventory {
  rows: RiskRow[];
  findings: RiskFinding[];
  summary: {
    risks: number; open: number; closed: number; treatedRate: number | null;
    highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number;
    overAppetite: number;
    quantified: number; totalALE: number; currency: string;
    byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>;
    riskScore: number;        // headline: threat-weighted residual posture (0-100, higher = worse)
  };
}

const EMPTY: RiskInventory = {
  rows: [], findings: [],
  summary: { risks: 0, open: 0, closed: 0, treatedRate: null, highCritical: 0, untreated: 0, accepted: 0, overdueReview: 0, noOwner: 0, overAppetite: 0, quantified: 0, totalALE: 0, currency: "EUR", byLevel: {}, byStatus: {}, byTreatment: {}, byCategory: {}, riskScore: 0 },
};

const CLOSED = /closed|clos[eé]|retir|done|accepted-closed|mitigated|termin[eé]|ferm[eé]/i;
const ACCEPT = /accept/i;
const LEVEL_RANK: Record<string, number> = { critical: 0, "very high": 0, severe: 0, high: 1, élevé: 1, medium: 2, moderate: 2, moyen: 2, low: 3, faible: 3, "very low": 4, "très faible": 4, minimal: 4, info: 4, informational: 4, négligeable: 4 };
const RANK_LABEL = ["Critical", "High", "Medium", "Low", "Very Low", "—"];

function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const cap = (s: string): string => s.replace(/\b\w/g, (c) => c.toUpperCase());

/** Resolve a risk level to {label, rank} from a text level, else from probability × impact.
 *  rank: 0 critical … 4 very-low, 5 unrated. Shared with the enterprise risk-score formula. */
export function levelInfo(text: unknown, prob: unknown, impact: unknown): { label: string; rank: number } {
  const t = String(text ?? "").toLowerCase().trim();
  if (t && LEVEL_RANK[t] != null) return { label: cap(t), rank: LEVEL_RANK[t] };
  const fromScore = (s: number): { label: string; rank: number } => {
    if (s <= 5) { const r = [5, 4, 3, 2, 1, 0][Math.max(0, Math.min(5, Math.round(s)))]; return { label: RANK_LABEL[r], rank: r }; } // 1-5 single scale
    const r = s >= 20 ? 0 : s >= 12 ? 1 : s >= 6 ? 2 : s >= 3 ? 3 : 4;                                                              // 5×5 product
    return { label: RANK_LABEL[r], rank: r };
  };
  const n = Number(t);
  if (Number.isFinite(n) && n > 0) return fromScore(n);
  const p = Number(prob), i = Number(impact);
  if (Number.isFinite(p) && p > 0 && Number.isFinite(i) && i > 0) return fromScore(p * i);
  return { label: "—", rank: 5 };
}

/** Full risk-register inventory + treatment worklist. */
export function riskRegisterInventory(tenant: number | null): RiskInventory {
  const cc = getDb("XCOMPLIANCE");
  if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='RISKREGISTERENTRY'").get()) return { ...EMPTY };
  const rc = cols("RISKREGISTERENTRY");
  const tw = tenant != null && rc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const entries = cc.prepare(`SELECT * FROM RISKREGISTERENTRY ${tw}`).all() as Record<string, unknown>[];
  if (!entries.length) return { ...EMPTY };

  // resolve owners (PERSON) + assets (ASSET), cross-DB best-effort
  const ownerName = new Map<number, string>();
  const assetName = new Map<number, string>();
  try {
    const xo = getDb("XORCISM");
    const oids = [...new Set(entries.map((e) => Number(e.RiskOwnerPersonID)).filter(Boolean))];
    if (oids.length) for (const r of xo.prepare(`SELECT PersonID, FullName FROM PERSON WHERE PersonID IN (${oids.map(() => "?").join(",")})`).all(...oids) as { PersonID: number; FullName: string }[]) ownerName.set(Number(r.PersonID), r.FullName);
    const aids = [...new Set(entries.map((e) => Number(e.AssetID)).filter(Boolean))];
    if (aids.length) for (const r of xo.prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${aids.map(() => "?").join(",")})`).all(...aids) as { AssetID: number; AssetName: string }[]) assetName.set(Number(r.AssetID), r.AssetName);
  } catch { /* PERSON/ASSET absent */ }

  // risk appetite per category (toleranceRank = worst residual rank still acceptable; 0 critical … 4 very-low)
  // and the count of library measures linked to each entry — both best-effort (tables may be absent).
  const appetite = new Map<string, number>();
  const measuresByEntry = new Map<number, number>();
  try {
    ensureRiskGovTables();
    const aw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
    for (const a of cc.prepare(`SELECT Category, ToleranceRank FROM RISKAPPETITE ${aw}`).all() as { Category: string; ToleranceRank: number }[])
      if (a.Category != null && a.ToleranceRank != null) appetite.set(String(a.Category).toLowerCase().trim(), Number(a.ToleranceRank));
    const lw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
    for (const m of cc.prepare(`SELECT RiskRegisterEntryID AS id, COUNT(*) AS n FROM RISKMEASURELINK ${lw} GROUP BY RiskRegisterEntryID`).all() as { id: number; n: number }[])
      measuresByEntry.set(Number(m.id), Number(m.n));
  } catch { /* governance tables not ready */ }

  const today = new Date().toISOString().slice(0, 10);
  const rows: RiskRow[] = [];
  const findings: RiskFinding[] = [];

  for (const e of entries) {
    const id = Number(e.RiskRegisterEntryID);
    const status = String(e.Status ?? "").trim() || "Open";
    const open = !CLOSED.test(status) && !e.ClosedDate;
    const inh = levelInfo(e.InherentRiskLevel, e.InherentProbability, e.InherentImpact);
    const cur = levelInfo(e.CurrentRiskLevel, e.CurrentProbability, e.CurrentImpact);
    // residual falls back to current, then inherent, if not rated
    let res = levelInfo(e.ResidualRiskLevel, e.ResidualProbability, e.ResidualImpact);
    if (res.rank === 5) res = cur.rank !== 5 ? cur : inh;
    const treatment = String(e.TreatmentStrategy ?? "").trim() || "—";
    const hasPlan = !!String(e.TreatmentPlan ?? "").trim();
    const owner = e.RiskOwnerPersonID != null ? (ownerName.get(Number(e.RiskOwnerPersonID)) ?? `Person #${e.RiskOwnerPersonID}`) : null;
    const asset = e.AssetID != null ? (assetName.get(Number(e.AssetID)) ?? null) : null;
    const ale = e.AnnualizedLossExpectancy != null && e.AnnualizedLossExpectancy !== "" ? Number(e.AnnualizedLossExpectancy) : null;
    const sle = e.SingleLossExpectancy != null && e.SingleLossExpectancy !== "" ? Number(e.SingleLossExpectancy) : null;
    const reviewInDays = daysUntil(e.ReviewDate ? String(e.ReviewDate) : null);
    const reviewOverdue = open && reviewInDays != null && reviewInDays < 0 && String(e.ReviewDate).slice(0, 10) < today;
    const targetOverdue = open && e.TargetDate != null && String(e.TargetDate).slice(0, 10) < today;

    // priority score (higher = worse): residual severity + ALE + risk-management gaps
    let score = (5 - res.rank) * 10;                                  // critical 50 … very-low 10 … unrated 0
    if (ale != null && Number.isFinite(ale)) score += Math.min(20, ale / 100_000);
    if (reviewOverdue) score += 10;
    if (open && res.rank <= 1 && !hasPlan && !ACCEPT.test(treatment)) score += 15;
    if (open && !owner) score += 5;
    // over appetite: residual is MORE severe (lower rank) than the category's tolerance allows
    const tol = appetite.get(String(e.Category ?? "").toLowerCase().trim());
    const overAppetite = open && tol != null && res.rank <= 4 && res.rank < tol;
    if (overAppetite) score += 12;
    if (!open) score = Math.round(score * 0.3);                        // closed risks de-prioritised
    score = Math.max(0, Math.min(100, Math.round(score)));

    rows.push({
      id, ref: String(e.Ref ?? "").trim() || `R-${id}`, title: String(e.Title ?? "").trim() || `Risk #${id}`,
      category: String(e.Category ?? "").trim() || "—", owner, asset, status, open,
      inherent: inh.label, current: cur.label, residual: res.label, residualRank: res.rank,
      treatment, hasPlan, ale, sle, currency: String(e.Currency ?? "EUR"),
      reviewInDays, reviewOverdue, score,
      overAppetite, measures: measuresByEntry.get(id) ?? 0,
    });

    if (overAppetite)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank === 0 ? "Critical" : "High", reason: "over-appetite", kind: "appetite", label: `Residual ${res.label} exceeds the risk appetite for "${String(e.Category ?? "—")}"` });

    // worklist
    if (open && res.rank <= 1 && !hasPlan && !ACCEPT.test(treatment))
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank === 0 ? "Critical" : "High", reason: "untreated", kind: "untreated", label: `${res.label} residual risk with no treatment plan` });
    if (open && ACCEPT.test(treatment) && !String(e.Justification ?? "").trim())
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank <= 1 ? "High" : "Medium", reason: "accepted-no-justification", kind: "accepted", label: `Risk accepted without documented justification (${res.label})` });
    if (reviewOverdue)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Medium", reason: "overdue-review", kind: "review", label: `Review overdue by ${-(reviewInDays ?? 0)}d` });
    if (targetOverdue && hasPlan)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Medium", reason: "treatment-overdue", kind: "target", label: `Treatment past its target date, risk still open` });
    if (open && !owner)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Low", reason: "no-owner", kind: "owner", label: `No risk owner assigned` });
  }

  const SEV: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  rows.sort((a, b) => b.score - a.score || a.residualRank - b.residualRank || a.ref.localeCompare(b.ref));
  findings.sort((a, b) => SEV[a.severity] - SEV[b.severity] || a.ref.localeCompare(b.ref));

  const openRows = rows.filter((r) => r.open);
  const byLevel: Record<string, number> = {}, byStatus: Record<string, number> = {}, byTreatment: Record<string, number> = {}, byCategory: Record<string, number> = {};
  for (const r of rows) {
    if (r.open) byLevel[r.residual] = (byLevel[r.residual] || 0) + 1;
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    if (r.treatment !== "—") byTreatment[r.treatment] = (byTreatment[r.treatment] || 0) + 1;
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  }
  const treated = openRows.filter((r) => r.hasPlan || ACCEPT.test(r.treatment)).length;
  // headline residual posture: weight open risks by severity (critical 100 … very-low 20), averaged
  const wScore = openRows.length ? Math.round(openRows.reduce((s, r) => s + (r.residualRank <= 4 ? (5 - r.residualRank) * 20 : 0), 0) / openRows.length) : 0;

  return {
    rows, findings,
    summary: {
      risks: rows.length, open: openRows.length, closed: rows.length - openRows.length,
      treatedRate: openRows.length ? Math.round((treated / openRows.length) * 100) : null,
      highCritical: openRows.filter((r) => r.residualRank <= 1).length,
      untreated: findings.filter((f) => f.kind === "untreated").length,
      accepted: findings.filter((f) => f.kind === "accepted").length,
      overdueReview: findings.filter((f) => f.kind === "review").length,
      noOwner: findings.filter((f) => f.kind === "owner").length,
      overAppetite: rows.filter((r) => r.overAppetite).length,
      quantified: rows.filter((r) => r.ale != null).length,
      totalALE: Math.round(openRows.reduce((s, r) => s + (r.ale ?? 0), 0)),
      currency: rows[0]?.currency ?? "EUR",
      byLevel, byStatus, byTreatment, byCategory,
      riskScore: wScore,
    },
  };
}

/**
 * Create a RISKREGISTERENTRY from a guided form — the friendly path that replaces dumping the
 * user into the raw explorer insert. Captures the essentials (title, category, owner, asset,
 * inherent likelihood × impact, treatment, status, dates), computes InherentRiskLevel = P×I so
 * the posture rolls up immediately (residual falls back to inherent until assessed). Column-aware
 * INSERT + GUID + tenant. RiskRegisterEntryID is a real INTEGER PRIMARY KEY (lastInsertRowid).
 */
export function createRiskRegisterEntry(
  p: { title: string; description?: string; category?: string; ref?: string;
       ownerPersonId?: number | null; assetId?: number | null; probability?: number | null;
       impact?: number | null; treatment?: string; status?: string; reviewDate?: string; targetDate?: string },
  tenant: number | null,
): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  const rc = cols("RISKREGISTERENTRY");
  if (!rc.size) throw new Error("RISKREGISTERENTRY table not available");
  const clamp = (v: unknown): number | null => {
    const n = Math.round(Number(v));
    return Number.isFinite(n) && n >= 1 && n <= 5 ? n : null;
  };
  const prob = clamp(p.probability), impact = clamp(p.impact);
  const now = new Date().toISOString();
  const candidate: Record<string, unknown> = {
    RiskRegisterEntryGUID: randomUUID(),
    Ref: p.ref ? String(p.ref).slice(0, 60) : null,
    Title: (p.title || "Untitled risk").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Category: p.category ? String(p.category).slice(0, 120) : null,
    RiskOwnerPersonID: p.ownerPersonId ?? null,
    AssetID: p.assetId ?? null,
    InherentProbability: prob, InherentImpact: impact,
    InherentRiskLevel: prob != null && impact != null ? prob * impact : null,
    TreatmentStrategy: p.treatment ? String(p.treatment).slice(0, 60) : null,
    Status: (p.status || "Open").slice(0, 60),
    IdentifiedDate: now.slice(0, 10),
    ReviewDate: p.reviewDate || null,
    TargetDate: p.targetDate || null,
    CreatedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => rc.has(k));
  const sql = `INSERT INTO RISKREGISTERENTRY (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = cc.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

// ── Excel/CSV import: Risk Register entries (RISKREGISTERENTRY) + Risk Assessments (RISKASSESSMENT) ──
// The Excel→field mapping happens client-side (the reusable xlsx-import modal); rows arrive keyed by
// these logical field names. Only the title/name is required; "upsert" updates an existing row matched
// by title/name (only the columns the row actually provides are touched — blanks never overwrite).
export const RISK_REGISTER_IMPORT_FIELDS = [
  { key: "title", type: "text" }, { key: "ref", type: "text" }, { key: "category", type: "text" },
  { key: "description", type: "text" }, { key: "status", type: "text" }, { key: "treatment", type: "text" },
  { key: "probability", type: "number" }, { key: "impact", type: "number" },
  { key: "reviewDate", type: "date" }, { key: "targetDate", type: "date" },
] as const;
export const RISK_ASSESSMENT_IMPORT_FIELDS = [
  { key: "name", type: "text" }, { key: "description", type: "text" }, { key: "status", type: "text" },
  { key: "version", type: "text" }, { key: "date", type: "date" },
] as const;

export interface RiskImportResult { created: number; updated: number; skipped: number; errors: { row: number; error: string }[]; }
const _str = (v: unknown): string | undefined => { const s = String(v ?? "").trim(); return s || undefined; };
const _has = (row: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(row, k) && String(row[k] ?? "").trim() !== "";
const _lvl = (v: unknown): number | null => { const n = Math.round(Number(v)); return Number.isFinite(n) && n >= 1 && n <= 5 ? n : null; };

function updateRREntry(cc: ReturnType<typeof getDb>, rc: Set<string>, id: number, row: Record<string, unknown>): void {
  const set: Record<string, unknown> = {};
  if (_has(row, "description")) set.Description = String(row.description).slice(0, 4000);
  if (_has(row, "category")) set.Category = String(row.category).slice(0, 120);
  if (_has(row, "ref")) set.Ref = String(row.ref).slice(0, 60);
  if (_has(row, "status")) set.Status = String(row.status).slice(0, 60);
  if (_has(row, "treatment")) set.TreatmentStrategy = String(row.treatment).slice(0, 60);
  const p = _has(row, "probability") ? _lvl(row.probability) : undefined;
  const im = _has(row, "impact") ? _lvl(row.impact) : undefined;
  if (p !== undefined) set.InherentProbability = p;
  if (im !== undefined) set.InherentImpact = im;
  if (p != null && im != null) set.InherentRiskLevel = p * im;
  if (_has(row, "reviewDate")) set.ReviewDate = String(row.reviewDate);
  if (_has(row, "targetDate")) set.TargetDate = String(row.targetDate);
  const keys = Object.keys(set).filter((k) => rc.has(k));
  if (!keys.length) return;
  cc.prepare(`UPDATE RISKREGISTERENTRY SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE RiskRegisterEntryID = ?`).run(...keys.map((k) => set[k]), id);
}

export function importRiskRegisterEntries(rows: Record<string, unknown>[], tenant: number | null, opts: { upsert?: boolean } = {}): RiskImportResult {
  const cc = getDb("XCOMPLIANCE");
  const rc = cols("RISKREGISTERENTRY");
  if (!rc.size) throw new Error("RISKREGISTERENTRY table not available");
  const out: RiskImportResult = { created: 0, updated: 0, skipped: 0, errors: [] };
  const findByTitle = cc.prepare("SELECT RiskRegisterEntryID id FROM RISKREGISTERENTRY WHERE Title = ? COLLATE NOCASE AND TenantID IS ? LIMIT 1");
  const tx = cc.transaction((items: Record<string, unknown>[]) => {
    items.forEach((row, i) => {
      const title = String(row.title ?? "").trim();
      if (!title) { out.skipped++; return; }
      try {
        if (opts.upsert && rc.has("TenantID")) {
          const ex = findByTitle.get(title, tenant) as { id: number } | undefined;
          if (ex) { updateRREntry(cc, rc, ex.id, row); out.updated++; return; }
        }
        createRiskRegisterEntry({
          title, ref: _str(row.ref), category: _str(row.category), description: _str(row.description),
          status: _str(row.status), treatment: _str(row.treatment),
          probability: _has(row, "probability") ? _lvl(row.probability) : null,
          impact: _has(row, "impact") ? _lvl(row.impact) : null,
          reviewDate: _str(row.reviewDate), targetDate: _str(row.targetDate),
        }, tenant);
        out.created++;
      } catch (e) { out.errors.push({ row: i + 1, error: String((e as Error).message || e) }); }
    });
  });
  tx(rows);
  return out;
}

/** Create a RISKASSESSMENT (the assessment header used by EBIOS / NIST 800-30). Column-aware + GUID. */
export function createRiskAssessment(p: { name: string; description?: string; status?: string; version?: string; date?: string }, tenant: number | null): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  const rc = cols("RISKASSESSMENT");
  if (!rc.size) throw new Error("RISKASSESSMENT table not available");
  const now = new Date().toISOString();
  const candidate: Record<string, unknown> = {
    RiskAssessmentGUID: randomUUID(),
    Name: (p.name || "Untitled assessment").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Status: (p.status || "Draft").slice(0, 60),
    Version: p.version ? String(p.version).slice(0, 40) : null,
    Date: p.date || now.slice(0, 10),
    CreatedDate: now, TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => rc.has(k));
  const r = cc.prepare(`INSERT INTO RISKASSESSMENT (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

export function importRiskAssessments(rows: Record<string, unknown>[], tenant: number | null, opts: { upsert?: boolean } = {}): RiskImportResult {
  const cc = getDb("XCOMPLIANCE");
  const rc = cols("RISKASSESSMENT");
  if (!rc.size) throw new Error("RISKASSESSMENT table not available");
  const out: RiskImportResult = { created: 0, updated: 0, skipped: 0, errors: [] };
  const findByName = cc.prepare("SELECT RiskAssessmentID id FROM RISKASSESSMENT WHERE Name = ? COLLATE NOCASE AND TenantID IS ? LIMIT 1");
  const tx = cc.transaction((items: Record<string, unknown>[]) => {
    items.forEach((row, i) => {
      const name = String(row.name ?? "").trim();
      if (!name) { out.skipped++; return; }
      try {
        if (opts.upsert && rc.has("TenantID")) {
          const ex = findByName.get(name, tenant) as { id: number } | undefined;
          if (ex) {
            const set: Record<string, unknown> = {};
            if (_has(row, "description")) set.Description = String(row.description).slice(0, 4000);
            if (_has(row, "status")) set.Status = String(row.status).slice(0, 60);
            if (_has(row, "version")) set.Version = String(row.version).slice(0, 40);
            if (_has(row, "date")) set.Date = String(row.date);
            const keys = Object.keys(set).filter((k) => rc.has(k));
            if (keys.length) cc.prepare(`UPDATE RISKASSESSMENT SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE RiskAssessmentID = ?`).run(...keys.map((k) => set[k]), ex.id);
            out.updated++; return;
          }
        }
        createRiskAssessment({ name, description: _str(row.description), status: _str(row.status), version: _str(row.version), date: _str(row.date) }, tenant);
        out.created++;
      } catch (e) { out.errors.push({ row: i + 1, error: String((e as Error).message || e) }); }
    });
  });
  tx(rows);
  return out;
}

// ════════════════════════════════════════════════════════════════════════════════
//  Risk-management strategy & appetite (RISKSTRATEGY / RISKAPPETITE) + a reusable
//  library of risk measures (RISKMEASURE) linkable to register entries (RISKMEASURELINK).
// ════════════════════════════════════════════════════════════════════════════════
export const APPETITE_LEVELS = ["Averse", "Minimal", "Cautious", "Open", "Flexible"] as const;
export const MEASURE_TYPES = ["Preventive", "Detective", "Corrective", "Directive", "Compensating"] as const;
export const MEASURE_STATUSES = ["Proposed", "Approved", "Implemented", "Verified", "Retired"] as const;
export const LINK_STATUSES = ["Planned", "In progress", "Implemented", "Verified"] as const;
/** Tolerance ranks the worklist compares against (0 critical … 4 very-low). */
export const TOLERANCE_RANKS = [
  { rank: 0, label: "Critical" }, { rank: 1, label: "High" }, { rank: 2, label: "Medium" }, { rank: 3, label: "Low" }, { rank: 4, label: "Very Low" },
];

export function ensureRiskGovTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS RISKSTRATEGY(
      RiskStrategyID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER,
      Statement TEXT, Objectives TEXT, Methodology TEXT, RiskScale TEXT,
      ReviewCadenceMonths INTEGER, Owner TEXT, ApprovedBy TEXT, ApprovedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS RISKAPPETITE(
      RiskAppetiteID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, Category TEXT, AppetiteLevel TEXT, ToleranceRank INTEGER, Rationale TEXT);
    CREATE TABLE IF NOT EXISTS RISKMEASURE(
      RiskMeasureID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, Ref TEXT, Name TEXT NOT NULL, Description TEXT,
      MeasureType TEXT, Category TEXT, ControlRef TEXT, Effectiveness TEXT, Cost TEXT,
      Status TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS RISKMEASURELINK(
      LinkID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, RiskRegisterEntryID INTEGER, RiskMeasureID INTEGER,
      ImplementationStatus TEXT, CreatedDate TEXT);
    -- Advanced treatment plan (one per risk register entry): the 4T strategy, rationale/acceptance
    -- justification, target residual + date, owner, budget, approval and status — plus a set of
    -- tracked treatment actions/tasks (RISKTREATMENTACTION) each owned, dated and progress-tracked.
    CREATE TABLE IF NOT EXISTS RISKTREATMENTPLAN(
      PlanID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, RiskRegisterEntryID INTEGER,
      Strategy TEXT, Rationale TEXT, TargetResidualLevel TEXT, TargetDate TEXT,
      OwnerPersonID INTEGER, Budget REAL, Currency TEXT, Status TEXT DEFAULT 'draft',
      ApprovedBy TEXT, ApprovedDate TEXT, CreatedBy TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS RISKTREATMENTACTION(
      ActionID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, PlanID INTEGER, RiskRegisterEntryID INTEGER,
      Title TEXT NOT NULL, Description TEXT, ActionOwnerPersonID INTEGER,
      DueDate TEXT, Status TEXT DEFAULT 'todo', Progress INTEGER DEFAULT 0,
      Cost REAL, ControlRef TEXT, RiskMeasureID INTEGER,
      SortOrder INTEGER, CompletedDate TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_riskappetite_tn ON RISKAPPETITE(TenantID, Category);
    CREATE INDEX IF NOT EXISTS ix_riskmeasure_tn ON RISKMEASURE(TenantID, RiskMeasureID);
    CREATE INDEX IF NOT EXISTS ix_riskmeasurelink_entry ON RISKMEASURELINK(RiskRegisterEntryID);
    CREATE INDEX IF NOT EXISTS ix_risktplan_entry ON RISKTREATMENTPLAN(RiskRegisterEntryID);
    CREATE INDEX IF NOT EXISTS ix_risktaction_plan ON RISKTREATMENTACTION(PlanID);
  `);
}

const tw = (tenant: number | null): string => (tenant != null ? `WHERE TenantID = ${tenant}` : "");

/** The strategy + appetite + measures-library payload for the /risk-register page. */
export function getRiskGovernance(tenant: number | null): {
  strategy: Record<string, unknown> | null;
  appetite: Record<string, unknown>[];
  measures: Record<string, unknown>[];
  options: { appetiteLevels: readonly string[]; measureTypes: readonly string[]; measureStatuses: readonly string[]; linkStatuses: readonly string[]; toleranceRanks: { rank: number; label: string }[] };
} {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const strategy = (cc.prepare(`SELECT * FROM RISKSTRATEGY ${tw(tenant)} ORDER BY RiskStrategyID DESC LIMIT 1`).get() as Record<string, unknown>) ?? null;
  const appetite = cc.prepare(`SELECT * FROM RISKAPPETITE ${tw(tenant)} ORDER BY Category`).all() as Record<string, unknown>[];
  // measures with a usage count (how many register entries reference each)
  const measures = cc.prepare(`
    SELECT m.*, (SELECT COUNT(*) FROM RISKMEASURELINK l WHERE l.RiskMeasureID = m.RiskMeasureID) AS usage
    FROM RISKMEASURE m ${tw(tenant)} ORDER BY m.Status, m.Name`).all() as Record<string, unknown>[];
  return { strategy, appetite, measures, options: {
    appetiteLevels: APPETITE_LEVELS, measureTypes: MEASURE_TYPES, measureStatuses: MEASURE_STATUSES, linkStatuses: LINK_STATUSES, toleranceRanks: TOLERANCE_RANKS,
  } };
}

/** Upsert the (single) risk-management strategy for the tenant and replace its appetite rows. */
export function saveRiskStrategy(
  tenant: number | null,
  p: { statement?: string; objectives?: string; methodology?: string; riskScale?: string; reviewCadenceMonths?: number | null;
       owner?: string; approvedBy?: string; approvedDate?: string;
       appetite?: { category: string; appetiteLevel?: string; toleranceRank?: number | null; rationale?: string }[] },
): { ok: true } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
  const existing = cc.prepare(`SELECT RiskStrategyID FROM RISKSTRATEGY ${tw(tenant)} ORDER BY RiskStrategyID DESC LIMIT 1`).get() as { RiskStrategyID: number } | undefined;
  const fields = {
    Statement: s(p.statement), Objectives: s(p.objectives), Methodology: s(p.methodology, 200), RiskScale: s(p.riskScale, 60),
    ReviewCadenceMonths: p.reviewCadenceMonths != null && String(p.reviewCadenceMonths) !== "" ? Math.max(1, Math.min(120, Math.round(Number(p.reviewCadenceMonths)))) : null,
    Owner: s(p.owner, 200), ApprovedBy: s(p.approvedBy, 200), ApprovedDate: s(p.approvedDate, 30), UpdatedDate: now,
  };
  if (existing) {
    cc.prepare(`UPDATE RISKSTRATEGY SET Statement=@Statement, Objectives=@Objectives, Methodology=@Methodology, RiskScale=@RiskScale,
      ReviewCadenceMonths=@ReviewCadenceMonths, Owner=@Owner, ApprovedBy=@ApprovedBy, ApprovedDate=@ApprovedDate, UpdatedDate=@UpdatedDate
      WHERE RiskStrategyID=@id`).run({ ...fields, id: existing.RiskStrategyID });
  } else {
    cc.prepare(`INSERT INTO RISKSTRATEGY (TenantID, Statement, Objectives, Methodology, RiskScale, ReviewCadenceMonths, Owner, ApprovedBy, ApprovedDate, UpdatedDate)
      VALUES (@TenantID,@Statement,@Objectives,@Methodology,@RiskScale,@ReviewCadenceMonths,@Owner,@ApprovedBy,@ApprovedDate,@UpdatedDate)`).run({ ...fields, TenantID: tenant });
  }
  if (Array.isArray(p.appetite)) {
    cc.prepare(`DELETE FROM RISKAPPETITE ${tw(tenant)}`).run();
    const ins = cc.prepare(`INSERT INTO RISKAPPETITE (TenantID, Category, AppetiteLevel, ToleranceRank, Rationale) VALUES (?, ?, ?, ?, ?)`);
    for (const a of p.appetite) {
      const cat = s(a.category, 120); if (!cat) continue;
      const rank = a.toleranceRank != null && String(a.toleranceRank) !== "" ? Math.max(0, Math.min(4, Math.round(Number(a.toleranceRank)))) : null;
      ins.run(tenant, cat, s(a.appetiteLevel, 40), rank, s(a.rationale, 1000));
    }
  }
  return { ok: true };
}

/** Create a measure in the library. */
export function createMeasure(
  tenant: number | null,
  p: { name: string; ref?: string; description?: string; measureType?: string; category?: string; controlRef?: string; effectiveness?: string; cost?: string; status?: string },
): { id: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
  const r = cc.prepare(`INSERT INTO RISKMEASURE (TenantID, Ref, Name, Description, MeasureType, Category, ControlRef, Effectiveness, Cost, Status, CreatedDate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    tenant, s(p.ref, 60), (p.name || "Untitled measure").slice(0, 300), s(p.description), s(p.measureType, 40), s(p.category, 120),
    s(p.controlRef, 120), s(p.effectiveness, 40), s(p.cost, 60), s(p.status, 40) || "Proposed", new Date().toISOString());
  return { id: Number(r.lastInsertRowid) };
}

/** Patch a measure (status / fields). */
export function updateMeasure(tenant: number | null, id: number, patch: Record<string, unknown>): { ok: true } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const map: Record<string, string> = { status: "Status", name: "Name", description: "Description", measureType: "MeasureType", category: "Category", controlRef: "ControlRef", effectiveness: "Effectiveness", cost: "Cost", ref: "Ref" };
  const sets: string[] = []; const vals: unknown[] = [];
  for (const [k, col] of Object.entries(map)) if (k in patch) { sets.push(`"${col}" = ?`); vals.push(patch[k] != null ? String(patch[k]).slice(0, 4000) : null); }
  if (!sets.length) return { ok: true };
  const guard = tenant != null ? ` AND TenantID = ${tenant}` : "";
  cc.prepare(`UPDATE RISKMEASURE SET ${sets.join(", ")} WHERE RiskMeasureID = ?${guard}`).run(...vals, id);
  return { ok: true };
}

/** Measures linked to a register entry (the entry's treatment as concrete measures). */
export function entryMeasures(tenant: number | null, entryId: number): Record<string, unknown>[] {
  ensureRiskGovTables();
  return getDb("XCOMPLIANCE").prepare(`
    SELECT l.LinkID, l.ImplementationStatus, m.RiskMeasureID, m.Ref, m.Name, m.MeasureType, m.Effectiveness, m.Status
    FROM RISKMEASURELINK l JOIN RISKMEASURE m ON m.RiskMeasureID = l.RiskMeasureID
    WHERE l.RiskRegisterEntryID = ?${tenant != null ? ` AND l.TenantID = ${tenant}` : ""} ORDER BY m.Name`).all(entryId) as Record<string, unknown>[];
}

export function linkMeasure(tenant: number | null, entryId: number, measureId: number, status?: string): { id: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const dup = cc.prepare(`SELECT LinkID FROM RISKMEASURELINK WHERE RiskRegisterEntryID = ? AND RiskMeasureID = ?`).get(entryId, measureId) as { LinkID: number } | undefined;
  if (dup) return { id: dup.LinkID };
  const r = cc.prepare(`INSERT INTO RISKMEASURELINK (TenantID, RiskRegisterEntryID, RiskMeasureID, ImplementationStatus, CreatedDate) VALUES (?, ?, ?, ?, ?)`)
    .run(tenant, entryId, measureId, (status && String(status).slice(0, 40)) || "Planned", new Date().toISOString());
  return { id: Number(r.lastInsertRowid) };
}

export function unlinkMeasure(tenant: number | null, linkId: number): { ok: true } {
  ensureRiskGovTables();
  getDb("XCOMPLIANCE").prepare(`DELETE FROM RISKMEASURELINK WHERE LinkID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""}`).run(linkId);
  return { ok: true };
}

export function setLinkStatus(tenant: number | null, linkId: number, status: string): { ok: true } {
  ensureRiskGovTables();
  getDb("XCOMPLIANCE").prepare(`UPDATE RISKMEASURELINK SET ImplementationStatus = ? WHERE LinkID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""}`).run(String(status).slice(0, 40), linkId);
  return { ok: true };
}

// ── Advanced treatment plans ──────────────────────────────────────────────────
// The ISO-27005 / ISO-31000 "risk treatment" 4T strategies + the plan/action lifecycles.
export const TREATMENT_STRATEGIES = ["Mitigate", "Accept", "Transfer", "Avoid"] as const;
export const PLAN_STATUSES = ["draft", "approved", "in-progress", "completed", "on-hold", "cancelled"] as const;
export const ACTION_STATUSES = ["todo", "in-progress", "done", "blocked", "cancelled"] as const;
const ACCEPT_STRAT = /accept|tolerat/i;

const personName = (tenant: number | null): Map<number, string> => {
  const m = new Map<number, string>();
  try { for (const p of getDb("XORCISM").prepare("SELECT PersonID, FullName FROM PERSON").all() as { PersonID: number; FullName: string }[]) m.set(Number(p.PersonID), p.FullName); } catch { /* PERSON optional */ }
  return m;
};
/** Progress = mean of action progress (a done/cancelled action counts 100/—); overdue = a plan past
 *  its target (not completed) or any non-terminal action past its due date. */
function planRollup(plan: Record<string, unknown> | null, actions: Record<string, unknown>[]): { progress: number; overdue: boolean; openActions: number; overdueActions: number } {
  const live = actions.filter((a) => a.Status !== "cancelled");
  const done = actions.filter((a) => a.Status === "done").length;
  const progress = live.length ? Math.round(live.reduce((s, a) => s + (a.Status === "done" ? 100 : Number(a.Progress) || 0), 0) / live.length) : (plan && plan.Status === "completed" ? 100 : 0);
  const overdueActions = actions.filter((a) => a.Status !== "done" && a.Status !== "cancelled" && (daysUntil(a.DueDate as string) ?? 1) < 0).length;
  const planOverdue = !!plan && plan.Status !== "completed" && plan.Status !== "cancelled" && (daysUntil(plan.TargetDate as string) ?? 1) < 0;
  return { progress, overdue: planOverdue || overdueActions > 0, openActions: live.length - done, overdueActions };
}

/** The full treatment plan (header + actions + rollup) for one risk register entry. */
export function getTreatmentPlan(tenant: number | null, entryId: number): {
  entryId: number; plan: Record<string, unknown> | null; actions: Record<string, unknown>[];
  progress: number; overdue: boolean; openActions: number; overdueActions: number;
  options: { strategies: readonly string[]; planStatuses: readonly string[]; actionStatuses: readonly string[] };
} {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const tt = tenant != null ? ` AND TenantID = ${tenant}` : "";
  const plan = (cc.prepare(`SELECT * FROM RISKTREATMENTPLAN WHERE RiskRegisterEntryID = ?${tt} ORDER BY PlanID DESC LIMIT 1`).get(entryId) as Record<string, unknown>) ?? null;
  const names = personName(tenant);
  if (plan && plan.OwnerPersonID != null) plan.OwnerName = names.get(Number(plan.OwnerPersonID)) ?? `#${plan.OwnerPersonID}`;
  const actions = plan
    ? (cc.prepare(`SELECT * FROM RISKTREATMENTACTION WHERE PlanID = ? ORDER BY COALESCE(SortOrder, ActionID)`).all(plan.PlanID) as Record<string, unknown>[])
    : [];
  for (const a of actions) if (a.ActionOwnerPersonID != null) a.OwnerName = names.get(Number(a.ActionOwnerPersonID)) ?? `#${a.ActionOwnerPersonID}`;
  const roll = planRollup(plan, actions);
  return { entryId, plan, actions, ...roll,
    options: { strategies: TREATMENT_STRATEGIES, planStatuses: PLAN_STATUSES, actionStatuses: ACTION_STATUSES } };
}

const numOrNull = (v: unknown): number | null => (v != null && String(v).trim() !== "" && !Number.isNaN(Number(v)) ? Number(v) : null);
const strOrNull = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);

/** Create or update the (single) treatment plan for a risk. Also mirrors the strategy/target onto
 *  RISKREGISTERENTRY so the inventory worklist (hasPlan / treatment / target-overdue) stays coherent. */
export function upsertTreatmentPlan(
  tenant: number | null, entryId: number,
  p: { strategy?: string; rationale?: string; targetResidualLevel?: string; targetDate?: string;
       ownerPersonId?: number | null; budget?: number | null; currency?: string; status?: string; createdBy?: string },
): { planId: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const tt = tenant != null ? ` AND TenantID = ${tenant}` : "";
  const strategy = TREATMENT_STRATEGIES.includes(p.strategy as never) ? p.strategy! : (p.strategy ? String(p.strategy).slice(0, 40) : null);
  const status = PLAN_STATUSES.includes(p.status as never) ? p.status! : "draft";
  const existing = cc.prepare(`SELECT PlanID FROM RISKTREATMENTPLAN WHERE RiskRegisterEntryID = ?${tt} ORDER BY PlanID DESC LIMIT 1`).get(entryId) as { PlanID: number } | undefined;
  let planId: number;
  const fields = {
    strat: strategy, rat: strOrNull(p.rationale), trl: strOrNull(p.targetResidualLevel, 40), td: strOrNull(p.targetDate, 40),
    owner: numOrNull(p.ownerPersonId), budget: numOrNull(p.budget), cur: strOrNull(p.currency, 10) || "EUR", st: status,
  };
  if (existing) {
    cc.prepare(`UPDATE RISKTREATMENTPLAN SET Strategy=@strat, Rationale=@rat, TargetResidualLevel=@trl, TargetDate=@td,
        OwnerPersonID=@owner, Budget=@budget, Currency=@cur, Status=@st, UpdatedDate=@now WHERE PlanID=@id`)
      .run({ ...fields, now, id: existing.PlanID });
    planId = existing.PlanID;
  } else {
    const r = cc.prepare(`INSERT INTO RISKTREATMENTPLAN (TenantID, RiskRegisterEntryID, Strategy, Rationale, TargetResidualLevel, TargetDate,
        OwnerPersonID, Budget, Currency, Status, CreatedBy, CreatedDate, UpdatedDate)
        VALUES (@tn, @entry, @strat, @rat, @trl, @td, @owner, @budget, @cur, @st, @cb, @now, @now)`)
      .run({ ...fields, tn: tenant, entry: entryId, cb: strOrNull(p.createdBy, 120), now });
    planId = Number(r.lastInsertRowid);
  }
  // Mirror onto RISKREGISTERENTRY (best-effort; only columns that exist).
  try {
    const re = getDb("XCOMPLIANCE");
    const rc = new Set((re.prepare(`PRAGMA table_info(RISKREGISTERENTRY)`).all() as { name: string }[]).map((c) => c.name));
    const sets: string[] = []; const args: unknown[] = [];
    if (rc.has("TreatmentStrategy") && strategy) { sets.push("TreatmentStrategy = ?"); args.push(strategy); }
    if (rc.has("TreatmentPlan")) { sets.push("TreatmentPlan = ?"); args.push(strOrNull(p.rationale) || "See structured treatment plan"); }
    if (rc.has("TargetDate") && fields.td) { sets.push("TargetDate = ?"); args.push(fields.td); }
    if (sets.length) { args.push(entryId); re.prepare(`UPDATE RISKREGISTERENTRY SET ${sets.join(", ")} WHERE RiskRegisterEntryID = ?${tt}`).run(...args); }
  } catch { /* mirror is best-effort */ }
  return { planId };
}

/** Approve the plan (records approver + date, flips draft → approved). */
export function approveTreatmentPlan(tenant: number | null, entryId: number, approver: string): { ok: boolean } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const tt = tenant != null ? ` AND TenantID = ${tenant}` : "";
  const r = cc.prepare(`UPDATE RISKTREATMENTPLAN SET ApprovedBy = ?, ApprovedDate = ?, Status = CASE WHEN Status = 'draft' THEN 'approved' ELSE Status END, UpdatedDate = ?
      WHERE RiskRegisterEntryID = ?${tt}`).run(String(approver || "").slice(0, 120), new Date().toISOString(), new Date().toISOString(), entryId);
  return { ok: r.changes > 0 };
}

/** Add a treatment action to a risk's plan (auto-creating a draft plan header if none exists). */
export function addTreatmentAction(
  tenant: number | null, entryId: number,
  p: { title: string; description?: string; actionOwnerPersonId?: number | null; dueDate?: string; status?: string;
       progress?: number | null; cost?: number | null; controlRef?: string; riskMeasureId?: number | null; createdBy?: string },
): { actionId: number; planId: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const title = String(p.title || "").trim();
  if (!title) throw new Error("action title required");
  let plan = cc.prepare(`SELECT PlanID FROM RISKTREATMENTPLAN WHERE RiskRegisterEntryID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""} ORDER BY PlanID DESC LIMIT 1`).get(entryId) as { PlanID: number } | undefined;
  if (!plan) { const { planId } = upsertTreatmentPlan(tenant, entryId, { createdBy: p.createdBy }); plan = { PlanID: planId }; }
  const now = new Date().toISOString();
  const status = ACTION_STATUSES.includes(p.status as never) ? p.status! : "todo";
  const progress = status === "done" ? 100 : Math.max(0, Math.min(100, Number(p.progress) || 0));
  const nextSort = (cc.prepare(`SELECT COALESCE(MAX(SortOrder), 0) + 1 AS s FROM RISKTREATMENTACTION WHERE PlanID = ?`).get(plan.PlanID) as { s: number }).s;
  const r = cc.prepare(`INSERT INTO RISKTREATMENTACTION (TenantID, PlanID, RiskRegisterEntryID, Title, Description, ActionOwnerPersonID,
      DueDate, Status, Progress, Cost, ControlRef, RiskMeasureID, SortOrder, CompletedDate, CreatedDate, UpdatedDate)
      VALUES (@tn, @plan, @entry, @title, @desc, @owner, @due, @st, @prog, @cost, @ctl, @rm, @sort, @done, @now, @now)`)
    .run({ tn: tenant, plan: plan.PlanID, entry: entryId, title: title.slice(0, 300), desc: strOrNull(p.description),
      owner: numOrNull(p.actionOwnerPersonId), due: strOrNull(p.dueDate, 40), st: status, prog: progress,
      cost: numOrNull(p.cost), ctl: strOrNull(p.controlRef, 120), rm: numOrNull(p.riskMeasureId), sort: nextSort,
      done: status === "done" ? now : null, now });
  return { actionId: Number(r.lastInsertRowid), planId: plan.PlanID };
}

/** Update a treatment action (status → done auto-sets progress 100 + completion date). */
export function updateTreatmentAction(tenant: number | null, actionId: number, patch: Record<string, unknown>): { ok: boolean } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const sets: string[] = []; const args: Record<string, unknown> = { id: actionId, now };
  if ("title" in patch) { const t2 = String(patch.title || "").trim(); if (t2) { sets.push("Title = @title"); args.title = t2.slice(0, 300); } }
  if ("description" in patch) { sets.push("Description = @desc"); args.desc = strOrNull(patch.description); }
  if ("actionOwnerPersonId" in patch) { sets.push("ActionOwnerPersonID = @owner"); args.owner = numOrNull(patch.actionOwnerPersonId); }
  if ("dueDate" in patch) { sets.push("DueDate = @due"); args.due = strOrNull(patch.dueDate, 40); }
  if ("cost" in patch) { sets.push("Cost = @cost"); args.cost = numOrNull(patch.cost); }
  if ("controlRef" in patch) { sets.push("ControlRef = @ctl"); args.ctl = strOrNull(patch.controlRef, 120); }
  let statusDone = false;
  if ("status" in patch && ACTION_STATUSES.includes(String(patch.status) as never)) {
    sets.push("Status = @st"); args.st = String(patch.status); statusDone = patch.status === "done";
    if (statusDone) { sets.push("Progress = 100", "CompletedDate = @cd"); args.cd = now; }
    else if (patch.status === "todo" || patch.status === "in-progress" || patch.status === "blocked") { sets.push("CompletedDate = NULL"); }
  }
  if ("progress" in patch && !statusDone) { sets.push("Progress = @prog"); args.prog = Math.max(0, Math.min(100, Number(patch.progress) || 0)); }
  if (!sets.length) return { ok: false };
  sets.push("UpdatedDate = @now");
  const tt = tenant != null ? ` AND TenantID = ${tenant}` : "";
  const r = cc.prepare(`UPDATE RISKTREATMENTACTION SET ${sets.join(", ")} WHERE ActionID = @id${tt}`).run(args);
  return { ok: r.changes > 0 };
}

export function deleteTreatmentAction(tenant: number | null, actionId: number): { ok: true } {
  ensureRiskGovTables();
  getDb("XCOMPLIANCE").prepare(`DELETE FROM RISKTREATMENTACTION WHERE ActionID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""}`).run(actionId);
  return { ok: true };
}
