/**
 * riskscore.ts — Periodic computation of the per-ASSET risk score.
 *
 * A loop (every 30 s) recomputes each ASSET's RiskScore, updates
 * ASSET.RiskScore and logs the change in ASSETRISKSCORE (a record is
 * added at the first evaluation then on every value CHANGE — this avoids
 * filling the history table with an identical row every 30 s).
 *
 * Scoring (integer, default 0, never negative):
 *   • If the asset has ≥ 1 uncorrected ASSETVULNERABILITY (AssetVulnerabilityStatusID = 0):
 *       – per vulnerability: +5 ; +10 if VULNERABILITY.KEV > 0 ; +50 if Exploited = 1 ;
 *         +10 if EasilyExploitable = 1 ; +50 if ASSETVULNERABILITY.TotalControl = 1
 *       – asset factors × criticality value (AssetCriticalityLevel → 0.5/0.7/1/2/3/5):
 *         +10× TaskCriticalAsset, +50× PublicFacing, +10× DefenseCriticalAsset,
 *         +10× managedbythirdparty, +10× hostedbythirdparty
 *       – +10 if isEncrypted = 0 ; + 0.01 × FinancialValue
 *   • Hardened (ASSETOVALDEFINITION.Status ∈ {Applied,Patched,Hardened,Compliant}) ...... −10
 *   • per valid ASSETTHREAT (ValidFrom/ValidUntil window) ........... + Criticity × 5
 *   • per "Unresolved/Open" and valid ASSETAUDITFINDING ............ + Criticity × 5
 *   • per open INCIDENTFORASSET (Status ∉ {Closed, Resolved}, XINCIDENT database):
 *         + Criticity × 3 ; +20 if Compromised = 1
 *   • if ASSET.PersonID > 0: per "Completed" and valid TRAININGFORPERSON .. −5
 *
 * Validity window: a NULL/empty bound is treated as "unbounded"
 * (empty ValidFrom = already started; empty ValidUntil = no expiry). Date
 * comparisons use the current date (ISO 'YYYY-MM-DD').
 */
import { getDb, resolveUserOrganisationId } from "./db";
import { levelInfo } from "./riskregister";
import * as xid from "./xid";

const nowTs = (): string => new Date().toISOString().replace("T", " ").slice(0, 19);
const today = (): string => new Date().toISOString().slice(0, 10);

/** Robust conversion to number (NULL / non-numeric text → 0). */
function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Numeric criticality value of an asset (exposure multiplier), based on
 * ASSET.AssetCriticalityLevel (text label or numeric value 0..5). Default 0.
 */
function criticalityValue(raw: unknown): number {
  switch (String(raw ?? "").trim().toLowerCase()) {
    case "very low": case "0": return 0.5;
    case "low": case "1": return 0.7;
    case "medium": case "moderate": case "2": return 1;
    case "high": case "3": return 2;
    case "very high": case "4": return 3;
    case "critical": case "5": return 5;
    default: return 0;
  }
}

export interface RiskComponents {
  vulnerabilities: number; // +5/vuln + KEV/Exploited/EasilyExploitable/TotalControl
  assetFactors: number;    // criticality × exposure + encryption + financial value
  hardening: number;       // −10 if hardened (ASSETOVALDEFINITION)
  threats: number;
  findings: number;
  incidents: number;
  training: number;
  total: number;           // integer, ≥ 0
}

export class AssetRiskScoreCalculator {
  /**
   * Computes (without writing anything) an asset's risk score and the breakdown by
   * category. `d` = current date (ISO); lets you pin the reference for a batch.
   */
  compute(assetId: number, d: string = today()): RiskComponents {
    const xo = getDb("XORCISM");
    const asset = xo
      .prepare(
        'SELECT AssetCriticalityLevel, TaskCriticalAsset, DefenseCriticalAsset, ' +
          'managedbythirdparty, hostedbythirdparty, isEncrypted, PublicFacing, ' +
          'PersonID, FinancialValue, BusinessValue FROM "ASSET" WHERE AssetID = ?'
      )
      .get(assetId) as Record<string, unknown> | undefined;

    const c: RiskComponents = {
      vulnerabilities: 0, assetFactors: 0, hardening: 0,
      threats: 0, findings: 0, incidents: 0, training: 0, total: 0,
    };
    if (!asset) return c;

    // — Uncorrected vulnerabilities (AssetVulnerabilityStatusID = 0 ; NULL treated
    //   as uncorrected) — XORCISM ↔ XVULNERABILITY join —
    const unpatched = xo
      .prepare(
        'SELECT VulnerabilityID, TotalControl FROM "ASSETVULNERABILITY" ' +
          'WHERE AssetID = ? AND COALESCE(CAST(AssetVulnerabilityStatusID AS INTEGER), 0) = 0'
      )
      .all(assetId) as { VulnerabilityID: number; TotalControl: unknown }[];

    if (unpatched.length) {
      const xv = getDb("XVULNERABILITY");
      const getVuln = xv.prepare(
        'SELECT KEV, Exploited, EasilyExploitable FROM "VULNERABILITY" WHERE VulnerabilityID = ?'
      );
      for (const av of unpatched) {
        c.vulnerabilities += 5; // each uncorrected vulnerability
        const v = getVuln.get(av.VulnerabilityID) as
          | { KEV: unknown; Exploited: unknown; EasilyExploitable: unknown }
          | undefined;
        if (v) {
          if (num(v.KEV) > 0) c.vulnerabilities += 10; // KEV catalogue
          if (num(v.Exploited) === 1) c.vulnerabilities += 50; // exploited
          if (num(v.EasilyExploitable) === 1) c.vulnerabilities += 10; // easily exploitable
        }
        if (num(av.TotalControl) === 1) c.vulnerabilities += 50; // total control
      }

      // — Asset factors (applied only if ≥ 1 uncorrected vulnerability) —
      const crit = criticalityValue(asset.AssetCriticalityLevel);
      if (num(asset.TaskCriticalAsset) === 1) c.assetFactors += 10 * crit;
      if (num(asset.PublicFacing) === 1) c.assetFactors += 50 * crit;
      if (num(asset.DefenseCriticalAsset) === 1) c.assetFactors += 10 * crit;
      if (num(asset.managedbythirdparty) === 1) c.assetFactors += 10 * crit;
      if (num(asset.hostedbythirdparty) === 1) c.assetFactors += 10 * crit;
      if (num(asset.isEncrypted) === 0) c.assetFactors += 10; // not encrypted
      const fv = num(asset.FinancialValue);
      if (asset.FinancialValue != null && fv !== 0) c.assetFactors += 0.01 * fv;
    }

    // — Hardening: −10 if ≥ 1 OVAL definition applied/patched/hardened/compliant —
    const hardened = xo
      .prepare(
        'SELECT 1 FROM "ASSETOVALDEFINITION" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) IN ('applied', 'patched', 'hardened', 'compliant') LIMIT 1"
      )
      .get(assetId);
    if (hardened) c.hardening -= 10;

    // — Active threats (validity window) — + Criticity × 5 per row —
    const threats = xo
      .prepare(
        'SELECT Criticity FROM "ASSETTHREAT" WHERE AssetID = ? ' +
          "AND (ValidFrom IS NULL OR ValidFrom = '' OR ValidFrom < ?) " +
          "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
      )
      .all(assetId, d, d) as { Criticity: unknown }[];
    for (const t of threats) c.threats += num(t.Criticity) * 5;

    // — Open/unresolved and valid audit findings — + Criticity × 5 per row —
    const findings = xo
      .prepare(
        'SELECT Criticity FROM "ASSETAUDITFINDING" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) IN ('unresolved', 'open') " +
          "AND (ValidFrom IS NULL OR ValidFrom = '' OR ValidFrom < ?) " +
          "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
      )
      .all(assetId, d, d) as { Criticity: unknown }[];
    for (const f of findings) c.findings += num(f.Criticity) * 5;

    // — Open incidents (XINCIDENT database) — + Criticity × 3 ; +20 if compromised —
    const incidents = getDb("XINCIDENT")
      .prepare(
        'SELECT Criticity, Compromised FROM "INCIDENTFORASSET" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) NOT IN ('closed', 'resolved')"
      )
      .all(assetId) as { Criticity: unknown; Compromised: unknown }[];
    for (const inc of incidents) {
      c.incidents += num(inc.Criticity) * 3;
      if (num(inc.Compromised) === 1) c.incidents += 20; // compromised asset
    }

    // — "Completed" and valid trainings of the responsible person (reduce) —
    const personId = num(asset.PersonID);
    if (personId > 0) {
      const completed = xo
        .prepare(
          'SELECT COUNT(*) AS n FROM "TRAININGFORPERSON" WHERE PersonID = ? ' +
            "AND LOWER(COALESCE(Status, '')) = 'completed' " +
            "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
        )
        .get(personId, d) as { n: number };
      c.training -= num(completed.n) * 5;
    }

    const raw =
      c.vulnerabilities + c.assetFactors + c.hardening +
      c.threats + c.findings + c.incidents + c.training;
    // Business value (1–5) amplifies the threat-driven score as an impact factor
    // (risk = threat × impact). Unset/0 → ×1 (unchanged); BV1→×1.0 … BV5→×2.0.
    const bv = num(asset.BusinessValue);
    const bizFactor = bv > 0 ? 1 + (Math.min(5, Math.max(1, bv)) - 1) * 0.25 : 1;
    c.total = Math.max(0, Math.round(Math.max(0, raw) * bizFactor)); // integer, never negative
    return c;
  }

  /**
   * Computes the score, updates ASSET.RiskScore and adds a row to
   * ASSETRISKSCORE (at the first evaluation then on every value change).
   * Returns the RiskScore.
   */
  computeAndRecord(assetId: number, d: string = today()): number {
    const score = this.compute(assetId, d).total;
    const xo = getDb("XORCISM");

    xo.prepare('UPDATE "ASSET" SET RiskScore = ? WHERE AssetID = ?').run(score, assetId);

    const last = xo
      .prepare(
        'SELECT RiskScore FROM "ASSETRISKSCORE" WHERE AssetID = ? ORDER BY AssetRiskScoreID DESC LIMIT 1'
      )
      .get(assetId) as { RiskScore: unknown } | undefined;

    if (!last || num(last.RiskScore) !== score) {
      const maxId = (
        xo.prepare('SELECT COALESCE(MAX(AssetRiskScoreID), 0) AS m FROM "ASSETRISKSCORE"').get() as {
          m: number;
        }
      ).m;
      xo.prepare(
        'INSERT INTO "ASSETRISKSCORE" (AssetRiskScoreID, AssetID, RiskScore, Date, ConfidenceLevel, TrustLevel) ' +
          "VALUES (?, ?, ?, ?, 3, 4)"
      ).run(maxId + 1, assetId, score, nowTs());
    }
    return score;
  }

  /** Recomputes all ASSETs (a single reference date for the batch). */
  recomputeAll(): number {
    const xo = getDb("XORCISM");
    const ids = (xo.prepare('SELECT AssetID FROM "ASSET"').all() as { AssetID: number }[]).map(
      (r) => r.AssetID
    );
    const d = today();
    let n = 0;
    const tx = xo.transaction(() => {
      for (const id of ids) {
        this.computeAndRecord(id, d);
        n++;
      }
    });
    tx();
    return n;
  }
}

export const riskScoreCalculator = new AssetRiskScoreCalculator();

// ── EnterpriseRiskScore (risk score aggregated per tenant) ────────────────────
//
// A holistic, transparent posture score (integer, ≥ 0) blending the materialized,
// registered and unremediated risk of a tenant, minus credit for demonstrated assurance.
// All component queries are light (per-tenant COUNT/SELECT) so the 30 s loop stays cheap.
//
//   ASSETS        + Σ latest ASSET.RiskScore (technical hygiene — unchanged base)
//   RISK REGISTER + per OPEN entry: residual weight (Crit 40 / High 25 / Med 10 / Low 3 /
//                   VeryLow 1 / unrated 5) + 15 if untreated high-crit + 8 if review overdue
//   INCIDENTS     + per OPEN incident: severity (Crit 30 / High 15 / Med 6 / Low 2) + 15 compromise
//   COMPLIANCE    + min(60, 8 × open high/critical or overdue audit findings)
//   CREDITS       − 5 / finished audit  − 0.5 / training  − round(0.4 × audit-completion%)
//
// Clamped at ≥ 0 and rounded.

const RANK_WEIGHT = [40, 25, 10, 3, 1, 5];             // residual rank 0..5 → risk points
const CLOSED_RX = /closed|clos[eé]|resolv|done|accepted|fixed|termin|ferm/i;
const ACCEPT_RX = /accept/i;
const SEV_WEIGHT = (s: string): number => {
  const v = s.toLowerCase();
  return v.includes("crit") ? 30 : v.includes("high") || v.includes("élev") ? 15 : v.includes("med") || v.includes("moder") || v.includes("moy") ? 6 : v.includes("low") || v.includes("faible") ? 2 : 0;
};

export interface EnterpriseRiskBreakdown {
  total: number;
  assets: number; riskRegister: number; incidents: number; compliance: number; credits: number;
  drivers: { key: string; label: string; value: number }[];   // signed contributors (for charts)
}

/** Full enterprise-risk breakdown for a tenant (the score + its signed contributors). */
export function enterpriseRiskBreakdown(tenantId: number | null): EnterpriseRiskBreakdown {
  const empty: EnterpriseRiskBreakdown = { total: 0, assets: 0, riskRegister: 0, incidents: 0, compliance: 0, credits: 0, drivers: [] };
  if (tenantId == null) return empty;
  const today = new Date().toISOString().slice(0, 10);

  // — ASSETS: Σ latest ASSET.RiskScore —
  const xo = getDb("XORCISM");
  let assets = 0;
  try {
    assets = num((xo.prepare(
      'SELECT COALESCE(SUM(ars.RiskScore), 0) AS s FROM "ASSETRISKSCORE" ars ' +
      'JOIN "ASSET" a ON a.AssetID = ars.AssetID WHERE a.TenantID = ? AND ars.AssetRiskScoreID = ' +
      '(SELECT MAX(x.AssetRiskScoreID) FROM "ASSETRISKSCORE" x WHERE x.AssetID = ars.AssetID)'
    ).get(tenantId) as { s: number }).s);
  } catch { /* no asset history */ }

  // — RISK REGISTER: residual-weighted open entries + untreated/overdue penalties —
  let riskRegister = 0;
  try {
    const cc = getDb("XCOMPLIANCE");
    if (cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='RISKREGISTERENTRY'").get()) {
      const rows = cc.prepare("SELECT ResidualRiskLevel rl, ResidualProbability rp, ResidualImpact ri, CurrentRiskLevel cl, CurrentProbability cp, CurrentImpact ci, TreatmentStrategy ts, TreatmentPlan tp, Justification j, Status st, ClosedDate cd, ReviewDate rv FROM RISKREGISTERENTRY WHERE TenantID = ?").all(tenantId) as Record<string, unknown>[];
      for (const e of rows) {
        if (CLOSED_RX.test(String(e.st ?? "")) || e.cd) continue;
        let rk = levelInfo(e.rl, e.rp, e.ri).rank;
        if (rk === 5) rk = levelInfo(e.cl, e.cp, e.ci).rank;
        riskRegister += RANK_WEIGHT[rk];
        const treat = String(e.ts ?? ""), hasPlan = !!String(e.tp ?? "").trim();
        if (rk <= 1 && !hasPlan && !ACCEPT_RX.test(treat)) riskRegister += 15;     // untreated high/critical
        if (e.rv && String(e.rv).slice(0, 10) < today) riskRegister += 8;          // review overdue
      }
    }
  } catch { /* no risk register */ }

  // — INCIDENTS: open incident severity + compromise —
  let incidents = 0;
  try {
    const xi = getDb("XINCIDENT");
    if (xi.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) {
      const rc = new Set((xi.prepare(`PRAGMA table_info("INCIDENT")`).all() as { name: string }[]).map((c) => c.name));
      if (rc.has("TenantID")) {
        const rows = xi.prepare("SELECT Severity sev, status st, security_compromise sc FROM INCIDENT WHERE TenantID = ?").all(tenantId) as { sev: unknown; st: unknown; sc: unknown }[];
        for (const i of rows) {
          if (CLOSED_RX.test(String(i.st ?? ""))) continue;
          incidents += SEV_WEIGHT(String(i.sev ?? ""));
          if (/yes|true|1|compromis|confirmed/i.test(String(i.sc ?? ""))) incidents += 15;
        }
      }
    }
  } catch { /* no incidents */ }

  // — COMPLIANCE: open high/critical or overdue audit findings (this tenant's audits) —
  let compliance = 0;
  try {
    const cc = getDb("XCOMPLIANCE");
    const fc = new Set((cc.prepare(`PRAGMA table_info("AUDITFINDING")`).all() as { name: string }[]).map((c) => c.name));
    if (fc.size) {
      const sevCol = fc.has("Severity") ? "Severity" : fc.has("FindingCriticity") ? "FindingCriticity" : null;
      const wfCol = fc.has("WorkflowStatus") ? "WorkflowStatus" : null;
      const dueCol = fc.has("DueDate") ? "DueDate" : null;
      const all = cc.prepare(`SELECT f.* FROM AUDITFINDING f JOIN AUDIT a ON a.AuditID = f.AuditID WHERE a.TenantID = ?`).all(tenantId) as Record<string, unknown>[];
      let n = 0;
      for (const f of all) {
        const open = !CLOSED_RX.test(`${f.FindingStatus ?? ""} ${wfCol ? f[wfCol] ?? "" : ""}`);
        if (!open) continue;
        const high = sevCol && /high|crit/i.test(String(f[sevCol] ?? ""));
        const overdue = dueCol && f[dueCol] && String(f[dueCol]).slice(0, 10) < today;
        if (high || overdue) n++;
      }
      compliance = Math.min(60, 8 * n);
    }
  } catch { /* no findings */ }

  // — CREDITS (negative): finished audits, trainings, audit-completion rate —
  let credits = 0;
  try {
    const cc = getDb("XCOMPLIANCE");
    const a = cc.prepare("SELECT COUNT(*) total, SUM(CASE WHEN LOWER(COALESCE(AuditStatus,'')) IN ('completed','closed','finished') THEN 1 ELSE 0 END) done FROM AUDIT WHERE TenantID = ?").get(tenantId) as { total: number; done: number };
    credits += num(a.done) * -5;
    if (num(a.total) > 0) credits += -Math.round(0.4 * (num(a.done) / num(a.total)) * 100);   // completion rate credit (max −40)
  } catch { /* no audits */ }
  try {
    const tr = xo.prepare('SELECT COUNT(*) AS n FROM "TRAININGFORPERSON" WHERE TenantID = ?').get(tenantId) as { n: number };
    credits += num(tr.n) * -0.5;
  } catch { /* no trainings */ }

  const total = Math.max(0, Math.round(assets + riskRegister + incidents + compliance + credits));
  return {
    total, assets: Math.round(assets), riskRegister, incidents, compliance, credits: Math.round(credits),
    drivers: [
      { key: "assets", label: "Asset hygiene", value: Math.round(assets) },
      { key: "riskRegister", label: "Risk register", value: riskRegister },
      { key: "incidents", label: "Open incidents", value: incidents },
      { key: "compliance", label: "Compliance debt", value: compliance },
      { key: "credits", label: "Assurance credits", value: Math.round(credits) },
    ].filter((d) => d.value !== 0),
  };
}

/** Computes (without writing anything) a tenant's EnterpriseRiskScore. */
export function computeEnterpriseRiskScore(tenantId: number | null): number {
  return enterpriseRiskBreakdown(tenantId).total;
}

// ── ORGANISATIONRISKSCORE history (EnterpriseRiskScore over time, per organisation) ──────
//
// One row per (organisation, day): the day's row is created on first sight then kept fresh
// (updated to the latest computed value) — so the table is a clean daily time series, written
// on dashboard load and on the hourly tick. The score for an organisation is its tenant's
// EnterpriseRiskScore (org ↔ tenant). CreatedDate = current date (YYYY-MM-DD).

/** Records the tenant's EnterpriseRiskScore under the given organisation for today (upsert by
 *  (org, date)); returns the score. Safe no-op if the table/organisation is absent. */
export function recordOrganisationRiskScore(organisationId: number, tenantId: number | null): number {
  const score = enterpriseRiskBreakdown(tenantId).total;
  try {
    const xo = getDb("XORCISM");
    if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ORGANISATIONRISKSCORE'").get()) return score;
    const d = today();
    const existing = xo.prepare("SELECT EnterpriseRiskScoreID FROM ORGANISATIONRISKSCORE WHERE OrganisationID = ? AND substr(CreatedDate,1,10) = ?").get(organisationId, d) as { EnterpriseRiskScoreID: number } | undefined;
    if (existing) xo.prepare("UPDATE ORGANISATIONRISKSCORE SET RiskScore = ? WHERE EnterpriseRiskScoreID = ?").run(score, existing.EnterpriseRiskScoreID);
    else xo.prepare("INSERT INTO ORGANISATIONRISKSCORE (CreatedDate, OrganisationID, RiskScore) VALUES (?, ?, ?)").run(d, organisationId, score);
  } catch (e) { console.warn(`[riskscore] org ${organisationId}: ${(e as Error).message}`); }
  return score;
}

/** The EnterpriseRiskScore history for an organisation, since an optional YYYY-MM-DD floor. */
export function organisationRiskHistory(organisationId: number, sinceDate: string | null): { date: string; score: number }[] {
  try {
    const xo = getDb("XORCISM");
    if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ORGANISATIONRISKSCORE'").get()) return [];
    const where = sinceDate ? "AND substr(CreatedDate,1,10) >= ?" : "";
    const args = sinceDate ? [organisationId, sinceDate] : [organisationId];
    return xo.prepare(`SELECT substr(CreatedDate,1,10) AS date, RiskScore AS score FROM ORGANISATIONRISKSCORE WHERE OrganisationID = ? ${where} ORDER BY CreatedDate`).all(...args) as { date: string; score: number }[];
  } catch { return []; }
}

/** Best-effort hourly recording for every tenant's organisation (background path). */
function recordAllOrganisationRiskScores(): void {
  for (const t of xid.listTenants()) {
    try {
      const org = resolveUserOrganisationId({ UserID: 0, TenantID: t.TenantID });
      if (org != null) recordOrganisationRiskScore(org, t.TenantID);
    } catch (e) { console.warn(`[riskscore] org history tenant ${t.TenantID}: ${(e as Error).message}`); }
  }
}

/**
 * Computes a tenant's EnterpriseRiskScore and records its history in RISKSCORE
 * (at the first evaluation then on every value change). Returns the score.
 */
export function recordEnterpriseRiskScore(tenantId: number): number {
  const score = computeEnterpriseRiskScore(tenantId);
  const xo = getDb("XORCISM");
  const last = xo
    .prepare('SELECT RiskScore FROM "RISKSCORE" WHERE TenantID = ? ORDER BY RiskScoreID DESC LIMIT 1')
    .get(tenantId) as { RiskScore: unknown } | undefined;
  if (!last || num(last.RiskScore) !== score) {
    const maxId = (
      xo.prepare('SELECT COALESCE(MAX(RiskScoreID), 0) AS m FROM "RISKSCORE"').get() as { m: number }
    ).m;
    xo.prepare(
      'INSERT INTO "RISKSCORE" (RiskScoreID, RiskScore, Date, TenantID, ConfidenceLevel) VALUES (?, ?, ?, ?, 3)'
    ).run(maxId + 1, score, nowTs(), tenantId);
  }
  return score;
}

/** Recomputes the EnterpriseRiskScore of all tenants. */
function recomputeAllEnterprise(): void {
  for (const t of xid.listTenants()) {
    try {
      recordEnterpriseRiskScore(t.TenantID);
    } catch (e) {
      console.warn(`[riskscore] tenant ${t.TenantID}: ${(e as Error).message}`);
    }
  }
}

let timer: NodeJS.Timeout | null = null;

/** Starts the recompute loop (every 30 s). Idempotent. */
export function startRiskScoreLoop(): void {
  if (timer) return;
  const tick = () => {
    try {
      riskScoreCalculator.recomputeAll(); // ASSETs first (fresh scores)
      recomputeAllEnterprise(); // then the per-tenant aggregate (reads ASSET scores)
    } catch (e) {
      console.warn(`[riskscore] tick: ${(e as Error).message}`);
    }
  };
  tick(); // first computation at startup
  timer = setInterval(tick, 30_000);
  if (typeof timer.unref === "function") timer.unref();

  // EnterpriseRiskScore history → ORGANISATIONRISKSCORE: once at startup, then hourly.
  const orgTick = () => { try { recordAllOrganisationRiskScores(); } catch (e) { console.warn(`[riskscore] org history: ${(e as Error).message}`); } };
  orgTick();
  const orgTimer = setInterval(orgTick, 3_600_000); // hourly
  if (typeof orgTimer.unref === "function") orgTimer.unref();

  console.log(
    "[riskscore] boucle démarrée (ASSET.RiskScore + EnterpriseRiskScore toutes les 30 s ; ORGANISATIONRISKSCORE toutes les heures)"
  );
}
