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
}
export interface RiskFinding {
  id: number; ref: string; title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  reason: string; kind: "untreated" | "accepted" | "review" | "target" | "owner";
  label: string;
}
export interface RiskInventory {
  rows: RiskRow[];
  findings: RiskFinding[];
  summary: {
    risks: number; open: number; closed: number; treatedRate: number | null;
    highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number;
    quantified: number; totalALE: number; currency: string;
    byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>;
    riskScore: number;        // headline: threat-weighted residual posture (0-100, higher = worse)
  };
}

const EMPTY: RiskInventory = {
  rows: [], findings: [],
  summary: { risks: 0, open: 0, closed: 0, treatedRate: null, highCritical: 0, untreated: 0, accepted: 0, overdueReview: 0, noOwner: 0, quantified: 0, totalALE: 0, currency: "EUR", byLevel: {}, byStatus: {}, byTreatment: {}, byCategory: {}, riskScore: 0 },
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
    if (!open) score = Math.round(score * 0.3);                        // closed risks de-prioritised
    score = Math.max(0, Math.min(100, Math.round(score)));

    rows.push({
      id, ref: String(e.Ref ?? "").trim() || `R-${id}`, title: String(e.Title ?? "").trim() || `Risk #${id}`,
      category: String(e.Category ?? "").trim() || "—", owner, asset, status, open,
      inherent: inh.label, current: cur.label, residual: res.label, residualRank: res.rank,
      treatment, hasPlan, ale, sle, currency: String(e.Currency ?? "EUR"),
      reviewInDays, reviewOverdue, score,
    });

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
      quantified: rows.filter((r) => r.ale != null).length,
      totalALE: Math.round(openRows.reduce((s, r) => s + (r.ale ?? 0), 0)),
      currency: rows[0]?.currency ?? "EUR",
      byLevel, byStatus, byTreatment, byCategory,
      riskScore: wScore,
    },
  };
}
