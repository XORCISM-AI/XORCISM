/**
 * controlweight.ts — Control-weight calculator (CapGRC "calculateur de poids de contrôle" model)
 * and its contribution to the EnterpriseRiskScore.
 *
 * Not every control matters equally: a global technical control protecting 100 % of the estate and
 * serving all four security objectives is worth far more than an administrative note covering one
 * asset. CapGRC (capgrc.com/ressources/calculateur-poids-controle) quantifies this as:
 *
 *      PfC = (T × E × PfO × P) / 100
 *
 *   T   Type de contrôle ....... 1 Management/Administrative · 2 Physical · 3 Technical/Operational
 *   E   Étendue d'application .. 1 Individual · 2 Partial · 3 Global
 *   PfO Objectifs de sécurité .. Σ of Confidentiality + Integrity + Availability + Non-repudiation,
 *                                each scored 0–5  →  0–20
 *   P   % des actifs protégés .. (Quantité / Quantité totale) × 100  →  0–100
 *
 * so the weight spans 1–180 (3 × 3 × 20 × 100 / 100 = 180), banded by default
 * Faible ≤ 12 · Moyen ≤ 15 · Élevé > 15 (CapGRC's published defaults, tunable here).
 *
 * The weight is stored per TENANT on CONTROLIMPLEMENTATION — not on the global 6 900-row CONTROL
 * catalogue — because P (the share of *your* estate a control protects) is organisation-specific,
 * and because it then sits next to the implementation Status it must be read with.
 *
 * EnterpriseRiskScore: weight alone is not risk — weight × how well the control is actually
 * implemented is. weightedControlAssurance() turns each weighted control into a signed contribution:
 * an implemented heavy control earns assurance credit, an unimplemented heavy control is a weighted
 * gap that costs more than the credit it would have earned (deliberately asymmetric — a missing
 * critical control is worse news than a present one is good news). See riskscore.ts.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

// ── the CapGRC model ─────────────────────────────────────────────────────────
export const WEIGHT_TYPES = [
  { value: 1, key: "administrative", label: "Management / Administrative" },
  { value: 2, key: "physical", label: "Physical" },
  { value: 3, key: "technical", label: "Technical / Operational" },
] as const;
export const WEIGHT_SCOPES = [
  { value: 1, key: "individual", label: "Individual" },
  { value: 2, key: "partial", label: "Partial" },
  { value: 3, key: "global", label: "Global" },
] as const;
export const SECURITY_OBJECTIVES = [
  { key: "confidentiality", label: "Confidentiality" },
  { key: "integrity", label: "Integrity" },
  { key: "availability", label: "Availability" },
  { key: "nonRepudiation", label: "Non-repudiation" },
] as const;

export const WEIGHT_MIN = 1;
export const WEIGHT_MAX = 180;                     // 3 × 3 × 20 × 100 / 100
/** CapGRC's published default bands ("Faible ≤ 12, Moyen ≤ 15, Élevé > 15"). */
export const WEIGHT_BANDS = { low: 12, medium: 15 };

export interface WeightInput {
  type?: number; scope?: number;
  confidentiality?: number; integrity?: number; availability?: number; nonRepudiation?: number;
  qty?: number; qtyTotal?: number;
}
export interface WeightResult {
  weight: number; band: "low" | "medium" | "high"; bandLabel: string;
  t: number; e: number; pfo: number; p: number; formula: string;
}

const clampInt = (v: unknown, lo: number, hi: number, dflt = lo): number => {
  const n = Math.round(Number(v));
  return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : dflt;
};

/** Band a weight with the (configurable) CapGRC thresholds. */
export function weightBand(weight: number): { band: "low" | "medium" | "high"; label: string } {
  if (weight <= WEIGHT_BANDS.low) return { band: "low", label: "Faible" };
  if (weight <= WEIGHT_BANDS.medium) return { band: "medium", label: "Moyen" };
  return { band: "high", label: "Élevé" };
}

/** PfC = (T × E × PfO × P) / 100, clamped to [1, 180]. */
export function computeWeight(i: WeightInput): WeightResult {
  const t = clampInt(i.type, 1, 3, 1);
  const e = clampInt(i.scope, 1, 3, 1);
  const pfo = clampInt(i.confidentiality, 0, 5, 0) + clampInt(i.integrity, 0, 5, 0)
    + clampInt(i.availability, 0, 5, 0) + clampInt(i.nonRepudiation, 0, 5, 0);   // 0–20
  const qt = Math.max(0, Number(i.qtyTotal) || 0);
  const q = Math.max(0, Number(i.qty) || 0);
  const p = qt > 0 ? Math.max(0, Math.min(100, (q / qt) * 100)) : 0;             // 0–100
  const raw = (t * e * pfo * p) / 100;
  const weight = Math.max(WEIGHT_MIN, Math.min(WEIGHT_MAX, Math.round(raw)));
  const b = weightBand(weight);
  return {
    weight, band: b.band, bandLabel: b.label, t, e, pfo, p: Math.round(p * 10) / 10,
    formula: `PfC = (${t} × ${e} × ${pfo} × ${Math.round(p * 10) / 10}) / 100 = ${Math.round(raw * 10) / 10} → ${weight}`,
  };
}

// ── persistence (per-tenant, on CONTROLIMPLEMENTATION) ───────────────────────
const WEIGHT_COLUMNS: Record<string, string> = {
  WeightType: "INTEGER", WeightScope: "INTEGER",
  ObjConfidentiality: "INTEGER", ObjIntegrity: "INTEGER", ObjAvailability: "INTEGER", ObjNonRepudiation: "INTEGER",
  AssetQty: "INTEGER", AssetQtyTotal: "INTEGER",
  ControlWeight: "INTEGER", WeightBand: "TEXT", WeightUpdatedDate: "TEXT",
};

/** Add the weight columns to CONTROLIMPLEMENTATION (ALTER, never a rebuild — legacy-table rule). */
export function ensureControlWeightColumns(): void {
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLIMPLEMENTATION'").get()) return;
    const have = new Set((db.prepare(`PRAGMA table_info("CONTROLIMPLEMENTATION")`).all() as { name: string }[]).map((c) => c.name));
    for (const [col, typ] of Object.entries(WEIGHT_COLUMNS)) {
      if (!have.has(col)) db.exec(`ALTER TABLE CONTROLIMPLEMENTATION ADD COLUMN ${col} ${typ}`);
    }
  } catch { /* best-effort */ }
}

const now = (): string => new Date().toISOString();

/** Set (or clear) a control's weight for a tenant; creates the CONTROLIMPLEMENTATION row if absent. */
export function setControlWeight(controlId: number, tenant: number | null, i: WeightInput): { ok: boolean; result?: WeightResult; error?: string } {
  ensureControlWeightColumns();
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM CONTROL WHERE ControlID = ?").get(controlId)) return { ok: false, error: "control not found" };
  const r = computeWeight(i);
  const args = tenant == null ? [controlId] : [controlId, tenant];
  const row = db.prepare(
    `SELECT ControlImplementationID FROM CONTROLIMPLEMENTATION WHERE ControlID = ? AND ${tenant == null ? "TenantID IS NULL" : "TenantID = ?"}`,
  ).get(...args) as { ControlImplementationID: number } | undefined;
  const vals = [r.t, r.e, clampInt(i.confidentiality, 0, 5, 0), clampInt(i.integrity, 0, 5, 0),
    clampInt(i.availability, 0, 5, 0), clampInt(i.nonRepudiation, 0, 5, 0),
    Math.max(0, Number(i.qty) || 0), Math.max(0, Number(i.qtyTotal) || 0), r.weight, r.band, now()];
  if (row) {
    db.prepare(
      `UPDATE CONTROLIMPLEMENTATION SET WeightType=?, WeightScope=?, ObjConfidentiality=?, ObjIntegrity=?,
        ObjAvailability=?, ObjNonRepudiation=?, AssetQty=?, AssetQtyTotal=?, ControlWeight=?, WeightBand=?,
        WeightUpdatedDate=? WHERE ControlImplementationID=?`,
    ).run(...vals, row.ControlImplementationID);
  } else {
    const id = (db.prepare("SELECT COALESCE(MAX(ControlImplementationID),0)+1 n FROM CONTROLIMPLEMENTATION").get() as { n: number }).n;
    db.prepare(
      `INSERT INTO CONTROLIMPLEMENTATION (ControlImplementationID, ControlImplementationGUID, ControlID, Status,
        CreatedDate, TenantID, WeightType, WeightScope, ObjConfidentiality, ObjIntegrity, ObjAvailability,
        ObjNonRepudiation, AssetQty, AssetQtyTotal, ControlWeight, WeightBand, WeightUpdatedDate)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(id, randomUUID(), controlId, "", now(), tenant, ...vals);
  }
  return { ok: true, result: r };
}

/** Clear a control's weight for a tenant (keeps the implementation row and its Status). */
export function clearControlWeight(controlId: number, tenant: number | null): { ok: boolean } {
  ensureControlWeightColumns();
  const db = getDb("XORCISM");
  const args = tenant == null ? [controlId] : [controlId, tenant];
  db.prepare(
    `UPDATE CONTROLIMPLEMENTATION SET WeightType=NULL, WeightScope=NULL, ObjConfidentiality=NULL, ObjIntegrity=NULL,
      ObjAvailability=NULL, ObjNonRepudiation=NULL, AssetQty=NULL, AssetQtyTotal=NULL, ControlWeight=NULL,
      WeightBand=NULL, WeightUpdatedDate=NULL
     WHERE ControlID = ? AND ${tenant == null ? "TenantID IS NULL" : "TenantID = ?"}`,
  ).run(...args);
  return { ok: true };
}

// ── EnterpriseRiskScore contribution ─────────────────────────────────────────
/** How much of a control's weight is actually earned, by implementation status. */
export const STATUS_EFFECTIVENESS: Record<string, number> = {
  "Implemented": 1, "Inherited": 0.9, "Partially Implemented": 0.5, "Planned": 0.15,
  "Not Implemented": 0, "": 0,
};
/** A max-weight, fully implemented control earns this much credit (negative = risk reduction). */
const CREDIT_PER_CONTROL = 5;
/** A max-weight, wholly unimplemented control costs this much (asymmetric: gaps bite harder). */
const GAP_PER_CONTROL = 8;
export const ASSURANCE_FLOOR = -40;     // bounded like the audit-credit / threat-model terms
export const ASSURANCE_CEIL = 60;

export interface WeightedControlRow {
  controlId: number; cis: string; name: string; status: string; weight: number; band: string;
  effectiveness: number; credit: number; gap: number; contribution: number;
}
export interface ControlAssurance {
  term: number;                       // the signed EnterpriseRiskScore contribution (clamped)
  rawTerm: number;                    // before clamping
  weighted: number;                   // number of weighted controls counted
  totalWeight: number; earnedWeight: number; coverage: number;   // weighted implementation rate 0–100
  credit: number; gap: number;
  rows: WeightedControlRow[];
}

/** Per-tenant weighted control assurance — the EnterpriseRiskScore's "control weight" driver. */
export function weightedControlAssurance(tenant: number | null, withRows = false): ControlAssurance {
  const empty: ControlAssurance = { term: 0, rawTerm: 0, weighted: 0, totalWeight: 0, earnedWeight: 0, coverage: 0, credit: 0, gap: 0, rows: [] };
  ensureControlWeightColumns();
  let rows: any[] = [];
  try {
    const db = getDb("XORCISM");
    // A super-admin (tenant null) owns the TenantID-NULL rows; a tenant sees its own. The enterprise
    // risk score never reaches here with a null tenant (enterpriseRiskBreakdown guards it), so this
    // only decides what the /control-weight cockpit shows you.
    rows = db.prepare(
      `SELECT ci.ControlID cid, ci.Status st, ci.ControlWeight w, ci.WeightBand band,
              c.CIS cis, c.ControlName nm
         FROM CONTROLIMPLEMENTATION ci JOIN CONTROL c ON c.ControlID = ci.ControlID
        WHERE ${tenant == null ? "ci.TenantID IS NULL" : "ci.TenantID = ?"}
              AND ci.ControlWeight IS NOT NULL AND ci.ControlWeight > 0
              AND LOWER(COALESCE(ci.Status,'')) <> 'not applicable'`,
    ).all(...(tenant == null ? [] : [tenant])) as any[];
  } catch { return empty; }
  if (!rows.length) return empty;

  let credit = 0, gap = 0, totalWeight = 0, earnedWeight = 0;
  const out: WeightedControlRow[] = [];
  for (const r of rows) {
    const w = Math.max(0, Math.min(WEIGHT_MAX, Number(r.w) || 0));
    const status = String(r.st ?? "");
    const eff = STATUS_EFFECTIVENESS[status] ?? 0;
    const nw = w / WEIGHT_MAX;
    const c = -CREDIT_PER_CONTROL * nw * eff;
    const g = GAP_PER_CONTROL * nw * (1 - eff);
    credit += c; gap += g; totalWeight += w; earnedWeight += w * eff;
    if (withRows) {
      out.push({
        controlId: Number(r.cid), cis: String(r.cis ?? ""), name: String(r.nm ?? ""), status,
        weight: w, band: String(r.band ?? weightBand(w).band), effectiveness: eff,
        credit: Math.round(c * 10) / 10, gap: Math.round(g * 10) / 10,
        contribution: Math.round((c + g) * 10) / 10,
      });
    }
  }
  const rawTerm = credit + gap;
  if (withRows) out.sort((a, b) => b.contribution - a.contribution);
  return {
    term: Math.round(Math.max(ASSURANCE_FLOOR, Math.min(ASSURANCE_CEIL, rawTerm))),
    rawTerm: Math.round(rawTerm * 10) / 10,
    weighted: rows.length, totalWeight, earnedWeight: Math.round(earnedWeight),
    coverage: totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0,
    credit: Math.round(credit * 10) / 10, gap: Math.round(gap * 10) / 10, rows: out,
  };
}

// ── cockpit inventory ────────────────────────────────────────────────────────
export function controlWeightInventory(tenant: number | null): any {
  ensureControlWeightColumns();
  const assurance = weightedControlAssurance(tenant, true);
  const dist = { low: 0, medium: 0, high: 0 };
  for (const r of assurance.rows) dist[(r.band as "low" | "medium" | "high") ?? "low"]++;
  let catalogue = 0;
  try { catalogue = (getDb("XORCISM").prepare("SELECT COUNT(*) n FROM CONTROL").get() as { n: number }).n; } catch { /* */ }
  return {
    model: {
      types: WEIGHT_TYPES, scopes: WEIGHT_SCOPES, objectives: SECURITY_OBJECTIVES,
      min: WEIGHT_MIN, max: WEIGHT_MAX, bands: WEIGHT_BANDS,
      bounds: { floor: ASSURANCE_FLOOR, ceil: ASSURANCE_CEIL },
      formula: "PfC = (T × E × PfO × P) / 100",
      source: "CapGRC — calculateur de poids de contrôle",
    },
    assurance: { ...assurance, rows: undefined },
    rows: assurance.rows,
    distribution: dist,
    summary: {
      catalogue, weighted: assurance.weighted, coverage: assurance.coverage,
      totalWeight: assurance.totalWeight, term: assurance.term,
      avgWeight: assurance.weighted ? Math.round(assurance.totalWeight / assurance.weighted) : 0,
    },
  };
}

/** Control catalogue search for the calculator's picker (global CONTROL, optional vocabulary). */
export function searchControls(q: string, limit = 40): { controlId: number; cis: string; name: string; vocabulary: string }[] {
  try {
    const db = getDb("XORCISM");
    const like = `%${String(q || "").trim()}%`;
    return db.prepare(
      `SELECT c.ControlID controlId, COALESCE(c.CIS,'') cis, COALESCE(c.ControlName,'') name,
              COALESCE(v.VocabularyName,'') vocabulary
         FROM CONTROL c LEFT JOIN VOCABULARY v ON v.VocabularyID = c.VocabularyID
        WHERE c.CIS LIKE ? OR c.ControlName LIKE ? ORDER BY c.ControlID LIMIT ?`,
    ).all(like, like, limit) as any[];
  } catch { return []; }
}
