/**
 * riskscore.ts — Periodic computation of the per-ASSET risk score.
 *
 * A loop (every 30 s) recomputes each ASSET's RiskScore, updates
 * ASSET.RiskScore and logs the change in ASSETRISKSCORE (a record is
 * added at the first evaluation then on every value CHANGE — this avoids
 * filling the history table with an identical row every 30 s).
 *
 * Scoring (integer, default 0, never negative):
 *   • If the asset has ≥ 1 uncorrected ASSETVULNERABILITY (AssetVulnerabilityStatusID = 0), excluding
 *     analyst-confirmed false positives (FalsePositive = 1):
 *       – per vulnerability: +5 ; +10 if VULNERABILITY.KEV > 0 ; +50 if Exploited = 1 ;
 *         +10 if EasilyExploitable = 1 ; +50 if ASSETVULNERABILITY.TotalControl = 1
 *         — then this per-vulnerability subtotal is multiplied by a remediation factor (residual
 *           risk after mitigation effort): Done/Resolved ×0.1, In progress ×0.5, Planned ×0.85,
 *           Deferred/none ×1.0 (the most-mitigating plan wins; overdue plans still bite via 'patch')
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
 *
 * The tenant-level EnterpriseRiskScore (enterpriseRiskBreakdown) sums signed drivers:
 * asset hygiene + risk register + open incidents + compliance debt + overdue patches
 * − assurance credits − threat modeling ± weighted controls (the CapGRC control-weight
 * model, controlweight.ts: heavy implemented controls credit, heavy gaps cost).
 */
import { getDb, resolveUserOrganisationId } from "./db";
import { levelInfo } from "./riskregister";
import { weightedControlAssurance } from "./controlweight";
import { maturityAssurance } from "./maturity";
import { aiRiskExposure } from "./airiskloop";
import { captureVmSnapshot } from "./vmtrends";
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

/**
 * Residual-risk multiplier from an asset-vulnerability's remediation plan status. Risk =
 * exposure × (1 − mitigation effectiveness): active remediation lowers the residual risk of an
 * as-yet-uncorrected vulnerability, while a vulnerability with no plan carries its full weight.
 * The most-mitigating plan wins when several exist. Overdue plans are still penalised separately
 * by the patch component, so slippage is punished even when a plan exists.
 */
function remediationFactor(status: string): number {
  const s = status.toLowerCase();
  if (/done|complete|resolv|patched|fixed|mitigat|closed/.test(s)) return 0.1;  // effectively handled
  if (/progress|wip|started|ongoing/.test(s)) return 0.5;                        // actively worked
  if (/plan/.test(s)) return 0.85;                                               // committed, not started
  return 1.0;                                                                    // deferred / unknown / none
}

/** Best (lowest) remediation factor per AssetVulnerabilityID, from ASSETVULNERABILITYREMEDIATION. */
function remediationFactorByAv(xo: ReturnType<typeof getDb>, avIds: number[]): Map<number, number> {
  const m = new Map<number, number>();
  if (!avIds.length) return m;
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITYREMEDIATION'").get()) return m;
  const rc = new Set((xo.prepare(`PRAGMA table_info("ASSETVULNERABILITYREMEDIATION")`).all() as { name: string }[]).map((c) => c.name));
  if (!rc.has("AssetVulnerabilityID")) return m;
  const statusCol = rc.has("Status") ? "Status" : "''";
  const ph = avIds.map(() => "?").join(",");
  for (const r of xo.prepare(`SELECT AssetVulnerabilityID, ${statusCol} AS Status FROM ASSETVULNERABILITYREMEDIATION WHERE AssetVulnerabilityID IN (${ph})`).all(...avIds) as { AssetVulnerabilityID: number; Status: string }[]) {
    const f = remediationFactor(String(r.Status ?? ""));
    const avid = Number(r.AssetVulnerabilityID);
    const cur = m.get(avid);
    if (cur == null || f < cur) m.set(avid, f);
  }
  return m;
}

export interface RiskComponents {
  vulnerabilities: number; // Σ per-vuln (+5 +KEV/Exploited/EasilyExploitable/TotalControl) × remediation factor; excludes false positives
  assetFactors: number;    // criticality × exposure + encryption + financial value
  hardening: number;       // −10 if hardened (ASSETOVALDEFINITION)
  patch: number;           // +15/overdue patch (ASSETVULNERABILITY past its remediation TargetDate)
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
      vulnerabilities: 0, assetFactors: 0, hardening: 0, patch: 0,
      threats: 0, findings: 0, incidents: 0, training: 0, total: 0,
    };
    if (!asset) return c;

    // — Uncorrected vulnerabilities (AssetVulnerabilityStatusID = 0 ; NULL treated as uncorrected) —
    //   XORCISM ↔ XVULNERABILITY join. Analyst-confirmed false positives are excluded (they are not
    //   real exposure), and each instance's points are scaled by its remediation factor so active
    //   remediation lowers residual risk. —
    const avc = new Set((xo.prepare(`PRAGMA table_info("ASSETVULNERABILITY")`).all() as { name: string }[]).map((x) => x.name));
    const fpClause = avc.has("FalsePositive") ? "AND COALESCE(CAST(FalsePositive AS INTEGER), 0) = 0" : "";
    const unpatched = xo
      .prepare(
        'SELECT AssetVulnerabilityID, VulnerabilityID, TotalControl FROM "ASSETVULNERABILITY" ' +
          `WHERE AssetID = ? AND COALESCE(CAST(AssetVulnerabilityStatusID AS INTEGER), 0) = 0 ${fpClause}`
      )
      .all(assetId) as { AssetVulnerabilityID: number; VulnerabilityID: number; TotalControl: unknown }[];

    if (unpatched.length) {
      const remFactor = remediationFactorByAv(xo, unpatched.map((u) => Number(u.AssetVulnerabilityID)));
      const xv = getDb("XVULNERABILITY");
      const getVuln = xv.prepare(
        'SELECT KEV, Exploited, EasilyExploitable FROM "VULNERABILITY" WHERE VulnerabilityID = ?'
      );
      for (const av of unpatched) {
        let pts = 5; // each uncorrected vulnerability
        const v = getVuln.get(av.VulnerabilityID) as
          | { KEV: unknown; Exploited: unknown; EasilyExploitable: unknown }
          | undefined;
        if (v) {
          if (num(v.KEV) > 0) pts += 10; // KEV catalogue
          if (num(v.Exploited) === 1) pts += 50; // exploited
          if (num(v.EasilyExploitable) === 1) pts += 10; // easily exploitable
        }
        if (num(av.TotalControl) === 1) pts += 50; // total control
        // Mitigation credit: an active remediation plan lowers this instance's residual weight.
        c.vulnerabilities += pts * (remFactor.get(Number(av.AssetVulnerabilityID)) ?? 1);
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

    // — Patch posture: +15 per unpatched ASSETVULNERABILITY past its remediation TargetDate
    //   (the Patch Management SLA is breached). Column-aware; false positives excluded. —
    try {
      if (avc.has("PatchStatus") && avc.has("TargetDate")) {
        // 'Unpatched' contains the substring 'patched' → match exact terminal states, don't LIKE '%patched%'.
        const fp = avc.has("FalsePositive") ? "AND COALESCE(CAST(FalsePositive AS INTEGER),0) = 0" : "";
        const overdue = (xo.prepare(
          'SELECT COUNT(*) n FROM "ASSETVULNERABILITY" WHERE AssetID = ? ' +
          "AND COALESCE(CAST(AssetVulnerabilityStatusID AS INTEGER),0) = 0 " +
          "AND LOWER(COALESCE(PatchStatus,'')) NOT IN ('patched','applied','installed','fixed','remediated','resolved','done') " +
          `${fp} AND TargetDate IS NOT NULL AND TRIM(TargetDate) <> '' AND substr(TargetDate,1,10) < ?`
        ).get(assetId, d) as { n: number }).n;
        c.patch += num(overdue) * 15;
      }
    } catch { /* patch columns absent */ }

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
      c.vulnerabilities + c.assetFactors + c.hardening + c.patch +
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

  /** Recomputes one tenant's ASSETs (the per-tenant path used by the CROC reactive recompute). */
  recomputeTenant(tenantId: number): number {
    const xo = getDb("XORCISM");
    let ids: number[] = [];
    try {
      const hasTenant = (xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).some((c) => c.name === "TenantID");
      ids = (hasTenant
        ? xo.prepare('SELECT AssetID FROM "ASSET" WHERE "TenantID" = ? OR "TenantID" IS NULL').all(tenantId)
        : xo.prepare('SELECT AssetID FROM "ASSET"').all()) as any;
      ids = (ids as unknown as { AssetID: number }[]).map((r) => r.AssetID);
    } catch { return 0; }
    const d = today();
    let n = 0;
    const tx = xo.transaction(() => { for (const id of ids) { this.computeAndRecord(id, d); n++; } });
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
//   ASSETS        + average latest ASSET.RiskScore (per-asset technical hygiene — count-independent,
//                   so a large estate doesn't inflate the headline number; net of false positives and
//                   discounted for in-flight remediation, since ASSET.RiskScore reflects both)
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
  assets: number; riskRegister: number; incidents: number; compliance: number; patch: number; credits: number; threatModels: number;
  controlWeight: number; maturity: number; aiRisk: number;
  maturityDetail?: { index: number | null; sources: { key: string; label: string; pct: number }[] };  // for the driver tooltip
  drivers: { key: string; label: string; value: number }[];   // signed contributors (for charts)
}

/** Full enterprise-risk breakdown for a tenant (the score + its signed contributors). */
export function enterpriseRiskBreakdown(tenantId: number | null): EnterpriseRiskBreakdown {
  const empty: EnterpriseRiskBreakdown = { total: 0, assets: 0, riskRegister: 0, incidents: 0, compliance: 0, patch: 0, credits: 0, threatModels: 0, controlWeight: 0, maturity: 0, aiRisk: 0, drivers: [] };
  if (tenantId == null) return empty;
  const today = new Date().toISOString().slice(0, 10);

  // — ASSETS: average latest ASSET.RiskScore (count-independent hygiene, not a raw sum) —
  const xo = getDb("XORCISM");
  let assets = 0;
  try {
    assets = num((xo.prepare(
      'SELECT COALESCE(AVG(ars.RiskScore), 0) AS s FROM "ASSETRISKSCORE" ars ' +
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

  // — PATCH: overdue patches across the tenant's assets (Patch Management SLA breaches) —
  let patch = 0;
  try {
    const avc = new Set((xo.prepare(`PRAGMA table_info("ASSETVULNERABILITY")`).all() as { name: string }[]).map((c) => c.name));
    const ac = new Set((xo.prepare(`PRAGMA table_info("ASSET")`).all() as { name: string }[]).map((c) => c.name));
    if (avc.has("PatchStatus") && avc.has("TargetDate") && ac.has("TenantID")) {
      const fp = avc.has("FalsePositive") ? "AND COALESCE(CAST(av.FalsePositive AS INTEGER),0) = 0" : "";
      const n = num((xo.prepare(
        'SELECT COUNT(*) n FROM "ASSETVULNERABILITY" av JOIN "ASSET" a ON a.AssetID = av.AssetID ' +
        "WHERE a.TenantID = ? AND COALESCE(CAST(av.AssetVulnerabilityStatusID AS INTEGER),0) = 0 " +
        "AND LOWER(COALESCE(av.PatchStatus,'')) NOT IN ('patched','applied','installed','fixed','remediated','resolved','done') " +
        `${fp} AND av.TargetDate IS NOT NULL AND TRIM(av.TargetDate) <> '' AND substr(av.TargetDate,1,10) < ?`
      ).get(tenantId, today) as { n: number }).n);
      patch = Math.min(80, n * 4);
    }
  } catch { /* no patch columns */ }

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

  // — THREAT-MODEL ASSURANCE (negative): proactive threat modeling that covers assets &
  //   applications reduces risk — like completed audits, but a deliberately SMALLER per-item
  //   weight (−2 per approved model, −1 per asset/application actually covered; capped at −30,
  //   strictly weaker than the audit credit's −5/each and −40 completion cap). THREATMODEL and
  //   its ASSET/APPLICATION coverage links all live in the XORCISM db (the `xo` handle).
  let threatModels = 0;
  try {
    const nApproved = num((xo.prepare(
      "SELECT COUNT(*) n FROM THREATMODEL WHERE TenantID = ? AND LOWER(COALESCE(Status,'')) IN ('approved','completed','closed','done','published','validated')"
    ).get(tenantId) as { n: number }).n);
    let covAssets = 0, covApps = 0;
    try { covAssets = num((xo.prepare("SELECT COUNT(DISTINCT AssetID) n FROM ASSETTHREATMODEL WHERE TenantID = ? AND AssetID IS NOT NULL").get(tenantId) as { n: number }).n); } catch { /* table absent */ }
    try { covApps = num((xo.prepare("SELECT COUNT(DISTINCT ApplicationID) n FROM APPLICATIONTHREATMODEL WHERE TenantID = ? AND ApplicationID IS NOT NULL").get(tenantId) as { n: number }).n); } catch { /* table absent */ }
    threatModels = Math.max(-30, -(2 * nApproved + covAssets + covApps));
  } catch { /* no threat models */ }

  // — CONTROL WEIGHT (signed): the CapGRC control-weight model (controlweight.ts). Each weighted
  //   control contributes weight × implementation-effectiveness as assurance credit (negative) and
  //   weight × (1 − effectiveness) as a weighted control gap (positive). Deliberately asymmetric —
  //   a heavy control left unimplemented costs more than the same control implemented earns — and
  //   clamped to [−40, +60] so it can shift the score without dominating it.
  let controlWeight = 0;
  try { controlWeight = weightedControlAssurance(tenantId).term; } catch { /* no weighted controls */ }

  // — MATURITY (credit, signed ≤ 0): the tenant's security-maturity assessments (SOC-CMM, CTI-CMM,
  //   MITRE INFORM, NIST CSF 2.0) aggregated into a 0–100 index. Higher demonstrated maturity earns a
  //   larger risk reduction (0 → −40); no maturity assessment ⇒ 0 (neutral, never a penalty).
  let maturity = 0;
  let maturityDetail: EnterpriseRiskBreakdown["maturityDetail"];
  try { const m = maturityAssurance(tenantId); maturity = m.term; maturityDetail = { index: m.index, sources: m.sources }; } catch { /* not assessed */ }

  // — AI RISK EXPOSURE (signed ≥ 0): unmitigated high/critical residual AI risks + KRI breaches +
  //   residual accepted without a documented rationale, from the operational AI Risk loop (capped 0→+60).
  let aiRisk = 0;
  try { aiRisk = aiRiskExposure(tenantId).term; } catch { /* no AI risks */ }

  const total = Math.max(0, Math.round(assets + riskRegister + incidents + compliance + patch + credits + threatModels + controlWeight + maturity + aiRisk));
  return {
    total, assets: Math.round(assets), riskRegister, incidents, compliance, patch, credits: Math.round(credits), threatModels: Math.round(threatModels),
    controlWeight, maturity, maturityDetail, aiRisk,
    drivers: [
      { key: "assets", label: "Asset hygiene", value: Math.round(assets) },
      { key: "riskRegister", label: "Risk register", value: riskRegister },
      { key: "incidents", label: "Open incidents", value: incidents },
      { key: "compliance", label: "Compliance debt", value: compliance },
      { key: "patch", label: "Overdue patches", value: patch },
      { key: "credits", label: "Assurance credits", value: Math.round(credits) },
      { key: "threatModels", label: "Threat modeling", value: Math.round(threatModels) },
      { key: "controlWeight", label: "Weighted controls", value: controlWeight },
      { key: "maturity", label: "Maturity assurance", value: maturity },
      { key: "aiRisk", label: "AI risk exposure", value: aiRisk },
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

/** Best-effort daily VM posture snapshot (VMSNAPSHOT) for every tenant — feeds /vm-report trends so
 *  the risk-reduction history accrues even when nobody opens the report (upsert per (tenant, day)). */
function recordAllVmSnapshots(): void {
  for (const t of xid.listTenants()) {
    try { captureVmSnapshot(t.TenantID); } catch (e) { console.warn(`[riskscore] vm snapshot tenant ${t.TenantID}: ${(e as Error).message}`); }
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

/**
 * Full per-tenant recompute on demand — everything the polling crons did, scoped to one tenant.
 * This is the CROC reactive-recompute entry point: a material loop event recomputes that tenant's
 * ASSET scores + EnterpriseRiskScore + org history + VM posture snapshot within seconds, so the
 * crons become a sparse safety net rather than the primary driver. Best-effort; never throws.
 */
export function recomputeTenant(tenantId: number): void {
  try { riskScoreCalculator.recomputeTenant(tenantId); } catch { /* */ }
  try { recordEnterpriseRiskScore(tenantId); } catch { /* */ }
  try { const org = resolveUserOrganisationId({ UserID: 0, TenantID: tenantId }); if (org != null) recordOrganisationRiskScore(org, tenantId); } catch { /* */ }
  try { captureVmSnapshot(tenantId); } catch { /* */ }
}

let timer: NodeJS.Timeout | null = null;

/**
 * Starts the risk-score recompute loop. With XOR_RISKSCORE_EVENT_DRIVEN=1 (the default) the loop is
 * event-driven primary: the CROC reactive recompute carries the load and these timers run sparsely as
 * a backstop for changes that do not emit loop events (manual edits, bulk imports). Set the flag to 0
 * (or tune XOR_RISKSCORE_INTERVAL_MS / XOR_RISKSCORE_ORG_INTERVAL_MS) to restore frequent polling.
 */
export function startRiskScoreLoop(): void {
  if (timer) return;
  const eventDriven = String(process.env.XOR_RISKSCORE_EVENT_DRIVEN ?? "1") !== "0";
  const assetMs = Number(process.env.XOR_RISKSCORE_INTERVAL_MS) || (eventDriven ? 1_800_000 : 30_000);      // 30 min vs 30 s
  const orgMs = Number(process.env.XOR_RISKSCORE_ORG_INTERVAL_MS) || (eventDriven ? 21_600_000 : 3_600_000); // 6 h vs 1 h
  const tick = () => {
    try {
      riskScoreCalculator.recomputeAll(); // ASSETs first (fresh scores)
      recomputeAllEnterprise(); // then the per-tenant aggregate (reads ASSET scores)
    } catch (e) {
      console.warn(`[riskscore] tick: ${(e as Error).message}`);
    }
  };
  tick(); // first computation at startup

  timer = setInterval(tick, assetMs);
  if (typeof timer.unref === "function") timer.unref();

  // EnterpriseRiskScore history → ORGANISATIONRISKSCORE + VM posture history → VMSNAPSHOT.
  const orgTick = () => {
    try { recordAllOrganisationRiskScores(); } catch (e) { console.warn(`[riskscore] org history: ${(e as Error).message}`); }
    try { recordAllVmSnapshots(); } catch (e) { console.warn(`[riskscore] vm history: ${(e as Error).message}`); }
  };
  orgTick();
  const orgTimer = setInterval(orgTick, orgMs);
  if (typeof orgTimer.unref === "function") orgTimer.unref();

  console.log(
    eventDriven
      ? `[riskscore] event-driven mode: CROC reactive recompute is primary; safety-net polling assets/${Math.round(assetMs / 60000)}min, org+VM/${Math.round(orgMs / 3600000)}h`
      : `[riskscore] polling mode: ASSET+EnterpriseRiskScore/${Math.round(assetMs / 1000)}s, ORGANISATIONRISKSCORE+VM/${Math.round(orgMs / 60000)}min`
  );
}
