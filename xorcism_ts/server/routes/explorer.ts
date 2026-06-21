/**
 * explorer.ts — Routes for the generic database explorer.
 * RBAC/CRUD access control per table (Admin = full access) + logging.
 */

import { Router, Request, Response } from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  listDatabases,
  listTables,
  getSchema,
  updateRow,
  queryRows,
  exportRows,
  insertRow,
  deleteRow,
  clearTable,
  nextId,
  nameExists,
  lookup,
  lookupOne,
  lookupMany,
  getRowById,
  checkForNewKevVulnerabilityAndNotify,
  vulnByYear,
  assetFinancialValues,
  assetRiskExposure,
  assetAttackSurface,
  recordAssetFinancialValue,
  assetFinancialHistory,
  getOrCreateCpe,
  isValidCpe,
  getCpeBuilderOptions,
  getQuestionnaireQuestionIds,
  setQuestionnaireQuestions,
  getQuestionnaireExport,
  createQuestion,
  importQuestionnaireFromExcel,
  getAnswerEvidenceIds,
  setAnswerEvidences,
  createEvidence,
  getAttackMatrix,
  getAttackCoverage,
  getLlmAttackLayer,
  killChainGroups,
  killChainGraph,
  searchAttackTechniques,
  getD3fendMatrix,
  getA3mMatrix,
  getHuntsStixBundle,
  getReportsStixBundle,
  getThreatTtps,
  setThreatTtps,
  incidentsByStatus,
  incidentsByAsset,
  getIncidentAssets,
  setIncidentAssets,
  getAlertAssets,
  setAlertAssets,
  getThreatAssets,
  setThreatAssets,
  getAssetsWithTags,
  bulkCreateThreatForAsset,
  getIncidentThreatActor,
  setIncidentThreatActor,
  getAuditAssets,
  setAuditAssets,
  getAssetAudits,
  setAssetAudits,
  getAssetGeolocations,
  getAssetOvals,
  searchOvalDefinitions,
  addAssetOval,
  removeAssetOval,
  getAssetCpes,
  setAssetCpes,
  getAssetVulnerabilities,
  searchVulnerabilities,
  setAssetVulnerabilities,
  getAssetTags,
  setAssetTags,
  getAssetTagCloud,
  listTags,
  getVulnerabilityTags,
  setVulnerabilityTags,
  getCpeTags,
  setCpeTags,
  getCweTags,
  setCweTags,
  getControlTags,
  setControlTags,
  resolveUserOrganisationId,
  harvestEmailAddress,
  setupFirstRunNeeded,
  setupCreateAdminAsset,
  searchOrganisations,
  searchPersons,
  getDefaultOrganisationForUser,
  getAssetOrganisations,
  setAssetOrganisations,
  getAssetPersons,
  setAssetPersons,
  getOvalDefinitionTags,
  setOvalDefinitionTags,
  getTprmDashboard,
  getEbiosDashboard,
  createRiskAssessment,
  getNist80030Dashboard,
  createNist80030Assessment,
  getThreatModelDashboard,
  createThreatModel,
  threatAgentCategoryOptions,
  getThreatAgentCategory,
  setThreatAgentCategory,
  rowTenant,
  tableHasTenantCol,
  isTenantScoped,
  getThreatModelAssets,
  setThreatModelAssets,
  getThreatModelThreats,
  addThreatModelThreat,
  getThreatControls,
  setThreatControls,
  getDb,
} from "../db";
import { userCan, clientIp, deniedFields } from "../auth";
import * as xid from "../xid";
import { tr } from "../i18n";
import { computeEnterpriseRiskScore, enterpriseRiskBreakdown, recordOrganisationRiskScore, organisationRiskHistory } from "../riskscore";
import { levelInfo } from "../riskregister";
import { assetInventory } from "../assets";
import { identityInventory } from "../identities";
import { incidentInventory } from "../incidents";
import { complianceInventory } from "../compliance";
import { tidInventory } from "../tid";
import { crisisInventory } from "../crisis";
import { riskRegisterInventory } from "../riskregister";
import { pqcmmInventory } from "../pqcmm";
import { patchInventory } from "../patchmgmt";

// Removes the forbidden columns from a row object (keeps rowid)
function stripCols(row: Record<string, unknown>, denied: Set<string>): Record<string, unknown> {
  if (!denied.size) return row;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(row)) if (k === "rowid" || !denied.has(k)) out[k] = row[k];
  return out;
}

const router = Router();

// Multi-tenant: data isolation scope for the current request.
// Super-admin (System tenant) → null = no filter (sees everything); otherwise the
// user's tenant. The db.ts functions ignore this scope for non-scoped tables
// and while the TenantID column does not exist (tableHasTenantCol guard).
function tenantScope(req: Request): number | null {
  const u = req.user!;
  return u.isSuperAdmin ? null : u.tenantId ?? null;
}

// Tenant to STAMP on a created row: always the session's one
// (including super-admin → System tenant), because the TenantID field is no longer
// entered in the forms. Read filtering, however, stays "everything" for
// the super-admin (cf. tenantScope).
function sessionTenant(req: Request): number | null {
  return req.user!.tenantId ?? null;
}

// Denies access (403) and logs the attempt
function deny(req: Request, res: Response, action: string, db: string, table?: string): void {
  xid.addAudit({
    userId: req.user?.UserID ?? null,
    action: "access_denied",
    resourceType: "table",
    resourceKey: table ? `${db}.${table}` : db,
    detail: action,
    ip: clientIp(req),
  });
  res.status(403).json({ error: tr(req, "err.accessDenied") });
}

/**
 * Multi-tenant — linking endpoints: checks that the parent row (asset /
 * incident) targeted by the caller indeed belongs to its tenant, then returns the
 * TenantID to inherit on the junction rows.
 *
 *   - Super-admin (null scope): no filter; we return the parent's real TenantID
 *     (may be a number or null) to populate the junction correctly.
 *   - Tenant user: as long as the TenantID column exists on the parent,
 *     we deny (403 + audit) if the parent doesn't belong to its tenant (another
 *     tenant's row, NULL TenantID, or parent not found). If the column
 *     doesn't exist yet (import in progress), isolation is inactive and we
 *     let it through — consistent with the generic CRUD.
 *
 * Returns `{ tenant }` if access is allowed, or `null` after emitting the
 * 403 response (the route must then stop).
 */
function parentTenantOr403(
  req: Request,
  res: Response,
  dbName: string,
  table: string,
  idCol: string,
  idVal: number,
  action: string
): { tenant: number | null } | null {
  const scope = tenantScope(req);
  // rowTenant already normalizes '' / blank → null and returns a number otherwise.
  const parent = rowTenant(dbName, table, idCol, idVal);
  if (scope == null) return { tenant: parent }; // super-admin: not filtered
  // Isolation aligned with the list filtering (isTenantScoped + column present).
  // parent == null = inherited/unassigned (shared) row → accessible to all
  // tenants (otherwise a phantom 403 on its sub-resources, e.g. ASSET form
  // panels). We only deny if the parent EXPLICITLY belongs to another tenant.
  if (
    isTenantScoped(dbName, table) &&
    tableHasTenantCol(dbName, table) &&
    parent != null &&
    parent !== scope
  ) {
    deny(req, res, action, dbName, table);
    return null;
  }
  return { tenant: scope };
}

// GET /api/databases — filtered to the readable databases
router.get("/databases", (req: Request, res: Response) => {
  const user = req.user!;
  let dbs = listDatabases();
  if (!user.isAdmin) {
    dbs = dbs.filter(
      (db) => userCan(user, "read", db) || listTables(db).some((t) => userCan(user, "read", db, t))
    );
  }
  res.json(dbs);
});

// GET /api/tables?db=X — filtered to the readable tables
router.get("/tables", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  if (!db) return void res.status(400).json({ error: "db required" });
  const user = req.user!;
  let tabs = listTables(db);
  if (!user.isAdmin) {
    // userCan(…, table) applies the table rule if it exists (targeted denial possible),
    // otherwise falls back to the database right.
    tabs = tabs.filter((t) => userCan(user, "read", db, t));
  }
  res.json(tabs);
});

// GET /api/schema?db=X&table=Y
router.get("/schema", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  if (!db || !table)
    return void res.status(400).json({ error: "db and table required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  // Masks the columns forbidden for reading (field-level)
  const denied = deniedFields(req.user, db, table, "read");
  const schema = (getSchema(db, table) as { name: string }[]).filter((c) => !denied.has(c.name));
  res.json(schema);
});

// GET /api/rows
router.get("/rows", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const limit = Math.min(Number(req.query.limit) || 100, 1000);
  const offset = Number(req.query.offset) || 0;
  const sort = req.query.sort ? String(req.query.sort) : undefined;
  const dir = req.query.dir ? String(req.query.dir) : undefined;
  const search = req.query.search ? String(req.query.search) : undefined;
  const vocab = req.query.vocab ? Number(req.query.vocab) : null;
  // Per-column filters: JSON { "Column": "value" } (LIKE). Validated/bounded in db.ts.
  let filters: Record<string, string> | undefined;
  if (req.query.filters) {
    try {
      const parsed = JSON.parse(String(req.query.filters));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        filters = {};
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === "string") filters[k] = v;
        }
      }
    } catch {
      /* invalid JSON: filters are ignored */
    }
  }

  if (!db || !table)
    return void res.status(400).json({ error: "db and table required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);

  const result = queryRows(db, table, limit, offset, sort, dir, search, tenantScope(req), vocab, filters);
  const denied = deniedFields(req.user, db, table, "read");
  if (denied.size) {
    result.rows = (result.rows as Record<string, unknown>[]).map((r) => stripCols(r, denied));
  }
  res.json(result);
});

// GET /api/export
router.get("/export", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const sort = req.query.sort ? String(req.query.sort) : undefined;
  const dir = req.query.dir ? String(req.query.dir) : undefined;
  const vocab = req.query.vocab ? Number(req.query.vocab) : null;

  if (!db || !table)
    return void res.status(400).json({ error: "db and table required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);

  const result = exportRows(db, table, sort, dir, 50000, tenantScope(req), vocab);
  const deniedR = deniedFields(req.user, db, table, "read");
  if (deniedR.size) {
    result.rows = (result.rows as Record<string, unknown>[]).map((r) => stripCols(r, deniedR));
  }
  xid.addAudit({
    userId: req.user!.UserID,
    action: "export",
    resourceType: "table",
    resourceKey: `${db}.${table}`,
    ip: clientIp(req),
  });
  res.json({ ...result, limit: 50000 });
});

// GET /api/dashboard/risk-score — EnterpriseRiskScore of the current tenant (live computation)
router.get("/dashboard/risk-score", (req: Request, res: Response) => {
  const tenantId = req.user!.tenantId;
  res.json({ score: computeEnterpriseRiskScore(tenantId), tenantId });
});

// GET /api/dashboard/vuln-by-year — aggregate (any authenticated user)
router.get("/dashboard/vuln-by-year", (_req: Request, res: Response) => {
  res.json(vulnByYear());
});

// GET /api/dashboard/kpis — security-posture KPI strip, aggregating the governance
// module summaries (asset / identity / incident / compliance) + the enterprise risk score.
router.get("/dashboard/kpis", (req: Request, res: Response) => {
  const tenant = req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);
  const safe = <T>(fn: () => T): T | null => { try { return fn(); } catch { return null; } };
  const a = safe(() => assetInventory(tenant).summary);
  const i = safe(() => identityInventory(tenant).summary);
  const inc = safe(() => incidentInventory(tenant).summary);
  const c = safe(() => complianceInventory(tenant).summary);
  const t = safe(() => tidInventory(tenant).summary);
  const cr = safe(() => crisisInventory(tenant).summary);
  const rr = safe(() => riskRegisterInventory(tenant).summary);
  const pq = safe(() => pqcmmInventory(tenant).summary);
  const pm = safe(() => patchInventory(tenant).summary);
  res.json({
    riskScore: safe(() => computeEnterpriseRiskScore(req.user!.tenantId)),
    assets: a && { total: a.total, crownJewels: a.crownJewels, internetFacing: a.internetFacing, criticalVulns: a.withCriticalVulns, unbacked: a.unbackedCritical, noOwner: a.noOwner },
    identities: i && { total: i.total, privileged: i.privileged, orphaned: i.orphaned, mfaGaps: i.mfaGaps },
    incidents: inc && { open: inc.open, criticalOpen: inc.criticalOpen, breached: inc.breached, mttrHours: inc.mttrHours },
    compliance: c && { completionRate: c.completionRate, openFindings: c.openFindings, highOpen: c.highOpen, overdue: c.overdue },
    tid: t && { tidScore: t.tidScore, detectRate: t.detectRate, mitigateRate: t.mitigateRate, testRate: t.testRate, detectionFailed: t.detectionFailed, detectionRegressed: t.detectionRegressed, exposed: t.exposed, threatRelevant: t.threatRelevant },
    crisis: cr && { readinessScore: cr.readinessScore, exercises: cr.exercises, completionRate: cr.completionRate, scenarioCoverage: cr.scenarioCoverage, openActions: cr.openActions, overdueActions: cr.overdueActions, scenariosNeverExercised: cr.scenariosNeverExercised },
    risk: rr && { riskScore: rr.riskScore, open: rr.open, highCritical: rr.highCritical, untreated: rr.untreated, overdueReview: rr.overdueReview, treatedRate: rr.treatedRate, totalALE: rr.totalALE, currency: rr.currency },
    pqcmm: pq && pq.assessments ? { maturityScore: pq.maturityScore, assessments: pq.assessments, quantumVulnerable: pq.quantumVulnerable, productionReady: pq.productionReady, managed: pq.managed } : null,
    patch: pm && pm.instances ? { coverage: pm.coverage, overdue: pm.overdue, kevUnpatched: pm.kevUnpatched, unpatched: pm.unpatched, instances: pm.instances, mttr: pm.mttr } : null,
  });
});

// GET /api/dashboard/risk-history?days=90 — the EnterpriseRiskScore over time for the current
// user's organisation (XORCISM.ORGANISATIONRISKSCORE). Records today's value on load (upsert by
// org+day), then returns the daily series since (today − days); days=0 → all history.
router.get("/dashboard/risk-history", (req: Request, res: Response) => {
  const user = req.user!;
  const organisationId = resolveUserOrganisationId({ UserID: user.UserID, Email: user.Email, TenantID: user.tenantId ?? undefined });
  const days = Math.max(0, Math.min(3650, Number(req.query.days) || 90));
  if (organisationId == null) return void res.json({ organisationId: null, current: null, days, points: [] });
  const tenant = user.isSuperAdmin ? null : (user.tenantId ?? null);
  const current = recordOrganisationRiskScore(organisationId, tenant);   // record on dashboard load
  const since = days > 0 ? new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10) : null;
  res.json({ organisationId, current, days, points: organisationRiskHistory(organisationId, since) });
});

// GET /api/dashboard/risk-breakdown — the EnterpriseRiskScore + its signed contributors
// (asset hygiene / risk register / open incidents / compliance debt / assurance credits).
router.get("/dashboard/risk-breakdown", (req: Request, res: Response) => {
  const tenant = req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);
  res.json(enterpriseRiskBreakdown(tenant));
});

// GET /api/dashboard/risk-heatmap — a 5×5 probability × impact grid of open risk-register entries
// (by residual position; falls back to current/inherent, else the residual level on the diagonal).
router.get("/dashboard/risk-heatmap", (req: Request, res: Response) => {
  const tenant = req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);
  const cc = getDb("XCOMPLIANCE");
  const out = { grid: [] as { p: number; i: number; count: number; refs: string[] }[], total: 0, placed: 0 };
  try {
    if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='RISKREGISTERENTRY'").get()) return void res.json(out);
    const rc = new Set((cc.prepare(`PRAGMA table_info("RISKREGISTERENTRY")`).all() as { name: string }[]).map((c) => c.name));
    const tw = tenant != null && rc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    const rows = cc.prepare(`SELECT * FROM RISKREGISTERENTRY ${tw}`).all() as Record<string, unknown>[];
    const cell = new Map<string, { p: number; i: number; count: number; refs: string[] }>();
    const CLOSED = /closed|clos[eé]|resolv|done|accepted|fixed|termin|ferm/i;
    const to5 = (v: unknown): number | null => { const n = Number(v); if (!Number.isFinite(n) || n <= 0) return null; return n <= 5 ? Math.max(1, Math.round(n)) : Math.max(1, Math.min(5, Math.round(n / 5))); };
    for (const e of rows) {
      out.total++;
      if (CLOSED.test(String(e.Status ?? "")) || e.ClosedDate) continue;
      // probability/impact from residual → current → inherent
      let p = to5(e.ResidualProbability) ?? to5(e.CurrentProbability) ?? to5(e.InherentProbability);
      let im = to5(e.ResidualImpact) ?? to5(e.CurrentImpact) ?? to5(e.InherentImpact);
      if (p == null || im == null) {              // no numeric prob/impact → place by residual level on the diagonal
        const rk = levelInfo(e.ResidualRiskLevel ?? e.CurrentRiskLevel ?? e.InherentRiskLevel, null, null).rank;
        if (rk === 5) continue;                   // unrated → not placed
        const d = 5 - rk;                          // rank 0(crit)→5, 4(very-low)→1
        p = p ?? d; im = im ?? d;
      }
      const key = `${p}:${im}`;
      const c = cell.get(key) ?? { p, i: im, count: 0, refs: [] };
      c.count++; if (c.refs.length < 8) c.refs.push(String(e.Ref ?? `R-${e.RiskRegisterEntryID}`));
      cell.set(key, c); out.placed++;
    }
    out.grid = [...cell.values()];
  } catch { /* empty grid */ }
  res.json(out);
});

// GET /api/dashboard/tag-cloud — cloud of active ASSETTAG tags (scoped to the tenant)
router.get("/dashboard/tag-cloud", (req: Request, res: Response) => {
  res.json(getAssetTagCloud(tenantScope(req)));
});

// GET /api/dashboard/incidents-by-status — number of incidents per status
router.get("/dashboard/incidents-by-status", (_req: Request, res: Response) => {
  res.json(incidentsByStatus());
});

// GET /api/dashboard/asset-financial-value — financial value of the assets + total
router.get("/dashboard/asset-financial-value", (_req: Request, res: Response) => {
  res.json(assetFinancialValues());
});

// GET /api/dashboard/asset-risk-exposure — exposure (RiskScore × FinancialValue)
router.get("/dashboard/asset-risk-exposure", (_req: Request, res: Response) => {
  res.json(assetRiskExposure());
});

// GET /api/asset-graph?assetId=<optional> — tenant-scoped attack-surface graph
// (assets ↔ apps / CPEs / vulns / orgs / persons / threats / incidents / tags).
router.get("/asset-graph", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  const raw = Number(req.query.assetId);
  const assetId = Number.isFinite(raw) && raw > 0 ? raw : null;
  res.json(assetAttackSurface(tenantScope(req), assetId));
});

// GET /api/dashboard/asset-financial-history?asset=<AssetName> — value over time
router.get("/dashboard/asset-financial-history", (req: Request, res: Response) => {
  const name = String(req.query.asset || "").trim();
  if (!name) return void res.status(400).json({ error: "asset (AssetName) requis" });
  res.json(assetFinancialHistory(name));
});

// GET /api/dashboard/incidents-by-asset?from=YYYY-MM-DD&to=YYYY-MM-DD
router.get("/dashboard/incidents-by-asset", (req: Request, res: Response) => {
  const from = req.query.from ? String(req.query.from) : undefined;
  const to = req.query.to ? String(req.query.to) : undefined;
  res.json(incidentsByAsset(from, to));
});

// GET /api/lookup — requires read on the reference table
router.get("/lookup", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const idCol = String(req.query.idCol || "");
  const labelCol = String(req.query.labelCol || "");
  if (!db || !table || !idCol || !labelCol)
    return void res.status(400).json({ error: "db, table, idCol, labelCol required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  res.json(lookup(db, table, idCol, labelCol));
});

// GET /api/lookup-one — label of ONE row (large tables, e.g. VULNERABILITY)
router.get("/lookup-one", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const idCol = String(req.query.idCol || "");
  const labelCol = String(req.query.labelCol || "");
  const idVal = String(req.query.idVal ?? "");
  if (!db || !table || !idCol || !labelCol || idVal === "")
    return void res.status(400).json({ error: "db, table, idCol, idVal, labelCol required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  res.json({ label: lookupOne(db, table, idCol, idVal, labelCol) });
});

// GET /api/lookup-many — labels of SEVERAL rows (ids=1,2,3) in one request:
// lazy resolution of a grid bounded to the visible rows of a large table.
router.get("/lookup-many", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const idCol = String(req.query.idCol || "");
  const labelCol = String(req.query.labelCol || "");
  const ids = String(req.query.ids ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  if (!db || !table || !idCol || !labelCol)
    return void res.status(400).json({ error: "db, table, idCol, labelCol required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  res.json(lookupMany(db, table, idCol, labelCol, ids));
});

// GET /api/row-by-id — ONE full row (with rowid) by column=value:
// opens the edit form of a target table from another view.
router.get("/row-by-id", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const idCol = String(req.query.idCol || "");
  const idVal = String(req.query.idVal ?? "");
  if (!db || !table || !idCol || idVal === "")
    return void res.status(400).json({ error: "db, table, idCol, idVal required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  res.json({ row: getRowById(db, table, idCol, idVal) });
});

// POST /api/asset/check-kev-notify — on ASSET form submission: scans the
// uncorrected ASSETVULNERABILITY rows (Status=0) linked to a KEV=1 VULNERABILITY and creates
// a "New ASSETVULNERABILITY for KEV" notification (idempotent, bounded to the tenant).
router.post("/asset/check-kev-notify", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "ASSETVULNERABILITY"))
    return deny(req, res, "read", "XORCISM", "ASSETVULNERABILITY");
  const created = checkForNewKevVulnerabilityAndNotify(req.user!.UserID, tenantScope(req));
  res.json({ created });
});

// GET /api/nextid
router.get("/nextid", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  if (!db || !table)
    return void res.status(400).json({ error: "db and table required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  res.json(nextId(db, table));
});

// GET /api/name-check?db=&table=&col=&value= — does a row already exist with
// this exact value (case-insensitive)? "*Name" duplicate check.
router.get("/name-check", (req: Request, res: Response) => {
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  const col = String(req.query.col || "");
  const value = String(req.query.value ?? "");
  if (!db || !table || !col)
    return void res.status(400).json({ error: "db, table and col required" });
  if (!userCan(req.user, "read", db, table)) return deny(req, res, "read", db, table);
  if (value.trim() === "") return void res.json({ exists: false, count: 0 });
  try {
    res.json(nameExists(db, table, col, value));
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

// POST /api/cpe { name } — creates/fetches a CPE entry (validated manual input)
router.post("/cpe", (req: Request, res: Response) => {
  if (!userCan(req.user, "create", "XORCISM", "CPE")) return deny(req, res, "create", "XORCISM", "CPE");
  const name = String((req.body as { name?: string })?.name || "").trim();
  if (!isValidCpe(name))
    return void res.status(400).json({ error: "Format CPE invalide (attendu cpe:2.3:… ou cpe:/…)" });
  try {
    const r = getOrCreateCpe(name);
    xid.addAudit({ userId: req.user!.UserID, action: r.created ? "cpe_create" : "cpe_get",
      resourceType: "table", resourceKey: "XORCISM.CPE", detail: name, ip: clientIp(req) });
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// GET /api/cpe-builder-options — suggestions (vendor/product) for the CPE builder
router.get("/cpe-builder-options", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "CPE")) return deny(req, res, "read", "XORCISM", "CPE");
  try {
    res.json(getCpeBuilderOptions());
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// ── OCIL: questions of a questionnaire (QUESTIONFORQUESTIONNAIRE link) ────────
// GET /api/questionnaire-questions?questionnaireId=N → IDs of the linked questions
router.get("/questionnaire-questions", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "QUESTIONFORQUESTIONNAIRE"))
    return deny(req, res, "read", "XCOMPLIANCE", "QUESTIONFORQUESTIONNAIRE");
  const qid = Number(req.query.questionnaireId);
  if (!Number.isInteger(qid) || qid <= 0) return void res.status(400).json({ error: "questionnaireId requis" });
  try { res.json(getQuestionnaireQuestionIds(qid)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/questionnaire-export?questionnaireId=N → questions + linked answers (Excel export)
router.get("/questionnaire-export", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "QUESTIONNAIRE"))
    return deny(req, res, "read", "XCOMPLIANCE", "QUESTIONNAIRE");
  const qid = Number(req.query.questionnaireId);
  if (!Number.isInteger(qid) || qid <= 0) return void res.status(400).json({ error: "questionnaireId requis" });
  try { res.json(getQuestionnaireExport(qid)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/questionnaire-questions { questionnaireId, questionIds:[] } → replaces the links
router.post("/questionnaire-questions", (req: Request, res: Response) => {
  if (!userCan(req.user, "update", "XCOMPLIANCE", "QUESTIONFORQUESTIONNAIRE"))
    return deny(req, res, "update", "XCOMPLIANCE", "QUESTIONFORQUESTIONNAIRE");
  const b = req.body as { questionnaireId?: unknown; questionIds?: unknown };
  const qid = Number(b.questionnaireId);
  if (!Number.isInteger(qid) || qid <= 0) return void res.status(400).json({ error: "questionnaireId requis" });
  const ids = Array.isArray(b.questionIds) ? b.questionIds.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0) : [];
  try {
    setQuestionnaireQuestions(qid, ids);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "questionnaire_questions_set", resourceType: "table",
      resourceKey: "XCOMPLIANCE.QUESTIONFORQUESTIONNAIRE", detail: `questionnaire=${qid} n=${ids.length}`, ip: clientIp(req) });
    res.json({ ok: true, count: ids.length });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── OCIL: evidence linked to an answer (ANSWEREVIDENCE) ───────────────────────
// GET /api/answer-evidences?answerId=N → IDs of the linked evidence
router.get("/answer-evidences", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "ANSWEREVIDENCE"))
    return deny(req, res, "read", "XCOMPLIANCE", "ANSWEREVIDENCE");
  const aid = Number(req.query.answerId);
  if (!Number.isInteger(aid) || aid <= 0) return void res.status(400).json({ error: "answerId requis" });
  try { res.json(getAnswerEvidenceIds(aid)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/answer-evidences { answerId, evidenceIds:[] } → replaces the links
router.post("/answer-evidences", (req: Request, res: Response) => {
  if (!userCan(req.user, "update", "XCOMPLIANCE", "ANSWEREVIDENCE"))
    return deny(req, res, "update", "XCOMPLIANCE", "ANSWEREVIDENCE");
  const b = req.body as { answerId?: unknown; evidenceIds?: unknown };
  const aid = Number(b.answerId);
  if (!Number.isInteger(aid) || aid <= 0) return void res.status(400).json({ error: "answerId requis" });
  const ids = Array.isArray(b.evidenceIds) ? b.evidenceIds.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0) : [];
  try {
    setAnswerEvidences(aid, ids);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "answer_evidences_set", resourceType: "table",
      resourceKey: "XCOMPLIANCE.ANSWEREVIDENCE", detail: `answer=${aid} n=${ids.length}`, ip: clientIp(req) });
    res.json({ ok: true, count: ids.length });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/attack/technique-search?q=... — ATT&CK technique search
router.get("/attack/technique-search", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  const q = String(req.query.q || "").trim();
  if (q.length < 2) return void res.json([]);
  try { res.json(searchAttackTechniques(q, Number(req.query.limit) || 50)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/threat-ttps?threatId=N — ATT&CK techniques linked to a THREAT
router.get("/threat-ttps", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "THREAT")) return deny(req, res, "read", "XTHREAT", "THREAT");
  const id = Number(req.query.threatId);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "threatId requis" });
  try { res.json(getThreatTtps(id)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/threat-ttps { threatId, techniqueIds:[] } — replaces the links
router.post("/threat-ttps", (req: Request, res: Response) => {
  if (!userCan(req.user, "update", "XTHREAT", "THREAT")) return deny(req, res, "update", "XTHREAT", "THREAT");
  const b = req.body as { threatId?: unknown; techniqueIds?: unknown };
  const id = Number(b.threatId);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "threatId requis" });
  const ids = Array.isArray(b.techniqueIds) ? b.techniqueIds.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0) : [];
  try {
    setThreatTtps(id, ids);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "threat_ttps_set", resourceType: "table",
      resourceKey: "XTHREAT.THREATTTP", detail: `threat=${id} n=${ids.length}`, ip: clientIp(req) });
    res.json({ ok: true, count: ids.length });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/attack/matrix?domain=enterprise — ATT&CK matrix (tactics → techniques)
router.get("/attack/matrix", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  const domain = ["enterprise", "mobile", "ics", "atlas"].includes(String(req.query.domain)) ? String(req.query.domain) : "enterprise";
  try { res.json(getAttackMatrix(domain)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/attack/coverage — validation coverage (BAS) per ATT&CK technique
router.get("/attack/coverage", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  try { res.json(getAttackCoverage()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/attack/llm-layer — Anthropic "LLM ATT&CK Navigator" AI-enablement layer
router.get("/attack/llm-layer", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  try { res.json(getLlmAttackLayer()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/kill-chain/groups — ATT&CK groups available as kill-chain overlay sources
router.get("/kill-chain/groups", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE")) return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  try { res.json(killChainGroups()); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/kill-chain?group=G0016 — kill-chain phases + an adversary's TTPs per phase
router.get("/kill-chain", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE")) return deny(req, res, "read", "XTHREAT", "ATTACKTECHNIQUE");
  const g = req.query.group ? String(req.query.group) : null;
  try { res.json(killChainGraph(g)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/d3fend/matrix — MITRE D3FEND matrix (tactics → techniques → sub-techniques)
router.get("/d3fend/matrix", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "D3FENDTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "D3FENDTECHNIQUE");
  try { res.json(getD3fendMatrix()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/tprm/dashboard — TPRM dashboard (third-party assessments via questionnaire)
router.get("/tprm/dashboard", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "QUESTIONNAIREFORORGANISATION"))
    return deny(req, res, "read", "XCOMPLIANCE", "QUESTIONNAIREFORORGANISATION");
  try { res.json(getTprmDashboard()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/ebios/dashboard — EBIOS RM dashboard (cyber risk analysis studies)
router.get("/ebios/dashboard", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKASSESSMENT"))
    return deny(req, res, "read", "XCOMPLIANCE", "RISKASSESSMENT");
  try { res.json(getEbiosDashboard()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/ebios/assessment — guided creation of a RISKASSESSMENT (risk-assessment study)
router.post("/ebios/assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKASSESSMENT"))
    return deny(req, res, "create", "XCOMPLIANCE", "RISKASSESSMENT");
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createRiskAssessment({
      name,
      description: b.description ? String(b.description) : undefined,
      methodology: b.methodology ? String(b.methodology) : undefined,
      status: b.status ? String(b.status) : undefined,
      expressMode: !!b.expressMode,
      authorPersonId: b.authorPersonId != null && String(b.authorPersonId) !== "" ? Number(b.authorPersonId) : null,
      version: b.version ? String(b.version) : undefined,
      date: b.date ? String(b.date) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_assessment_create", resourceType: "RISKASSESSMENT",
      resourceKey: String(out.id), detail: `name="${name}" methodology="${String(b.methodology || "EBIOS RM")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/nist-800-30/dashboard — NIST SP 800-30 risk-assessment dashboard
router.get("/nist-800-30/dashboard", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKASSESSMENT"))
    return deny(req, res, "read", "XCOMPLIANCE", "RISKASSESSMENT");
  const tenant = req.user?.isSuperAdmin ? null : (req.user?.tenantId ?? null);
  try { res.json(getNist80030Dashboard(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/nist-800-30/assessment — guided creation of a NIST SP 800-30 risk assessment
router.post("/nist-800-30/assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKASSESSMENT"))
    return deny(req, res, "create", "XCOMPLIANCE", "RISKASSESSMENT");
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createNist80030Assessment({
      name,
      description: b.description ? String(b.description) : undefined,
      status: b.status ? String(b.status) : undefined,
      authorPersonId: b.authorPersonId != null && String(b.authorPersonId) !== "" ? Number(b.authorPersonId) : null,
      date: b.date ? String(b.date) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_assessment_create", resourceType: "RISKASSESSMENT",
      resourceKey: String(out.id), detail: `name="${name}" methodology="NIST SP 800-30"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/threat-model/dashboard — threat-modeling dashboard (models + threat/asset/control counts)
router.get("/threat-model/dashboard", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return deny(req, res, "read", "XORCISM", "THREATMODEL");
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(getThreatModelDashboard(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/threat-model — guided creation of a THREATMODEL
router.post("/threat-model", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return deny(req, res, "create", "XORCISM", "THREATMODEL");
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createThreatModel({
      name,
      description: b.description ? String(b.description) : undefined,
      methodology: b.methodology ? String(b.methodology) : undefined,
      status: b.status ? String(b.status) : undefined,
      scope: b.scope ? String(b.scope) : undefined,
      riskLevel: b.riskLevel ? String(b.riskLevel) : undefined,
      owner: b.owner ? String(b.owner) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "threat_model_create", resourceType: "THREATMODEL",
      resourceKey: String(out.id), detail: `name="${name}" methodology="${String(b.methodology || "STRIDE")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/a3m/matrix — A3M matrix (Agentic AI Attack Matrix): tactics → AAT techniques
router.get("/a3m/matrix", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "A3MTECHNIQUE"))
    return deny(req, res, "read", "XTHREAT", "A3MTECHNIQUE");
  try { res.json(getA3mMatrix()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/evidence { name } → creates (or fetches) an EVIDENCE; returns its ID
router.post("/evidence", (req: Request, res: Response) => {
  if (!userCan(req.user, "create", "XCOMPLIANCE", "EVIDENCE"))
    return deny(req, res, "create", "XCOMPLIANCE", "EVIDENCE");
  const name = String((req.body as { name?: string })?.name || "").trim();
  if (!name) return void res.status(400).json({ error: "Nom de preuve requis" });
  try {
    const r = createEvidence(name.slice(0, 200));
    xid.addAudit({ userId: req.user?.UserID ?? null, action: r.created ? "evidence_create" : "evidence_get",
      resourceType: "table", resourceKey: "XCOMPLIANCE.EVIDENCE", detail: name, ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/question { name } → creates (or fetches) a QUESTION; returns its ID
router.post("/question", (req: Request, res: Response) => {
  if (!userCan(req.user, "create", "XCOMPLIANCE", "QUESTION"))
    return deny(req, res, "create", "XCOMPLIANCE", "QUESTION");
  const name = String((req.body as { name?: string })?.name || "").trim();
  if (!name) return void res.status(400).json({ error: "Nom de question requis" });
  try {
    const r = createQuestion(name.slice(0, 200));
    xid.addAudit({ userId: req.user?.UserID ?? null, action: r.created ? "question_create" : "question_get",
      resourceType: "table", resourceKey: "XCOMPLIANCE.QUESTION", detail: name, ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/questionnaire-import { name, fileName, questions:[{QuestionName,…}] }
// → creates a complete QUESTIONNAIRE (questions + links) from a mapped Excel/CSV file.
router.post("/questionnaire-import", (req: Request, res: Response) => {
  for (const tbl of ["QUESTIONNAIRE", "QUESTION", "QUESTIONFORQUESTIONNAIRE"]) {
    if (!userCan(req.user, "create", "XCOMPLIANCE", tbl)) return deny(req, res, "create", "XCOMPLIANCE", tbl);
  }
  const b = req.body as { name?: unknown; fileName?: unknown; questions?: unknown };
  const name = String(b.name ?? "").slice(0, 300);
  const fileName = String(b.fileName ?? "").slice(0, 300);
  const questions = Array.isArray(b.questions) ? (b.questions as Record<string, unknown>[]).slice(0, 5000) : [];
  if (!questions.length) return void res.status(400).json({ error: "Aucune question à importer" });
  try {
    const r = importQuestionnaireFromExcel(name, fileName, questions, sessionTenant(req));
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "questionnaire_import", resourceType: "table",
      resourceKey: "XCOMPLIANCE.QUESTIONNAIRE", detail: `questionnaire=${r.questionnaireId} n=${r.questions}`, ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/insert — CREATE right
// On saving an ASSET with a FinancialValue, records a snapshot
// in ASSETFINANCIALVALUE ("value over time" history).
function maybeSnapshotAssetValue(
  db: string, table: string, row: Record<string, unknown>, email: string
): void {
  if (db !== "XORCISM" || table !== "ASSET") return;
  const raw = row["FinancialValue"];
  if (raw == null || String(raw).trim() === "") return;
  const value = Number(raw);
  const assetId = Number(row["AssetID"]);
  if (!Number.isFinite(value) || !Number.isFinite(assetId)) return;
  try {
    recordAssetFinancialValue(assetId, value, (row["Currency"] as string) ?? null, email);
  } catch {
    /* the history must not block the save */
  }
}

router.post("/insert", (req: Request, res: Response) => {
  const { db, table, row } = req.body as {
    db: string;
    table: string;
    row: Record<string, unknown>;
  };
  if (!db || !table || !row)
    return void res.status(400).json({ error: "db, table, row required" });
  if (!userCan(req.user, "create", db, table)) return deny(req, res, "create", db, table);

  // Removes the fields forbidden for creation (field-level)
  const deniedC = deniedFields(req.user, db, table, "create");
  const newId = insertRow(db, table, deniedC.size ? stripCols(row, deniedC) : row, sessionTenant(req));
  maybeSnapshotAssetValue(db, table, row, req.user!.Email);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "insert",
    resourceType: "table",
    resourceKey: `${db}.${table}`,
    ip: clientIp(req),
  });
  res.json({ ok: true, id: newId });
});

// POST /api/import — bulk import from a JSON/CSV file (CREATE right)
// body: { db, table, rows: [ {col: val, …}, … ] }
//
// ⚠ INVARIANT — DO NOT hard-code any list of tables or columns here.
// The import is *driven by the live schema*: `getSchema(db, table)` (PRAGMA
// table_info) provides the set of valid columns at time T, and each
// row goes through the SAME `insertRow()` as the rest of the application. Thus
// the import automatically reflects any change — new tables, new
// columns, multi-tenant isolation (TenantID), PK auto-increment, default
// dates, vault encryption, and computed values (RiskScore, RISKREGISTERENTRY
// risk levels…). No per-table maintenance is required when
// adding/modifying tables or fields. (Same for export: /api/export = SELECT *.)
//
// Each row is filtered to the valid columns (and not forbidden for creation);
// non-primitive values serialized; defaults + tenant stamping via insertRow.
router.post("/import", (req: Request, res: Response) => {
  const { db, table, rows, replace } = req.body as {
    db: string;
    table: string;
    rows: unknown[];
    replace?: boolean;
  };
  if (!db || !table || !Array.isArray(rows))
    return void res.status(400).json({ error: "db, table, rows[] required" });
  if (!userCan(req.user, "create", db, table)) return deny(req, res, "create", db, table);
  // "Replace" mode: empty the table first (DELETE right additionally required)
  let cleared = 0;
  if (replace) {
    if (!userCan(req.user, "delete", db, table)) return deny(req, res, "delete", db, table);
    cleared = clearTable(db, table, tenantScope(req));
  }

  const validCols = new Set((getSchema(db, table) as { name: string }[]).map((c) => c.name));
  const denied = deniedFields(req.user, db, table, "create");
  const scope = sessionTenant(req);

  const coerce = (v: unknown): unknown => {
    if (v === null) return null;
    if (typeof v === "boolean") return v ? 1 : 0;
    if (typeof v === "object") return JSON.stringify(v); // arrays/objects → JSON text
    return v; // string / number
  };

  let inserted = 0;
  const errors: string[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      if (errors.length < 5) errors.push("ligne ignorée (objet attendu)");
      continue;
    }
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (k === "rowid" || !validCols.has(k) || denied.has(k) || v === undefined) continue;
      row[k] = coerce(v);
    }
    try {
      insertRow(db, table, row, scope);
      inserted++;
    } catch (e) {
      if (errors.length < 5) errors.push((e as Error).message);
    }
  }

  xid.addAudit({
    userId: req.user!.UserID,
    action: replace ? "import_replace" : "import",
    resourceType: "table",
    resourceKey: `${db}.${table}`,
    detail: `rows=${rows.length} inserted=${inserted}${replace ? ` cleared=${cleared}` : ""}`,
    ip: clientIp(req),
  });
  res.json({ inserted, total: rows.length, failed: rows.length - inserted, errors, cleared });
});

// PUT /api/update — UPDATE right
router.put("/update", (req: Request, res: Response) => {
  const { db, table, rowid, row } = req.body as {
    db: string;
    table: string;
    rowid: number;
    row: Record<string, unknown>;
  };
  if (!db || !table || rowid == null || !row)
    return void res.status(400).json({ error: "db, table, rowid, row required" });
  if (!userCan(req.user, "update", db, table)) return deny(req, res, "update", db, table);

  // Removes the fields forbidden for modification (field-level)
  const deniedU = deniedFields(req.user, db, table, "update");
  updateRow(db, table, Number(rowid), deniedU.size ? stripCols(row, deniedU) : row, tenantScope(req));
  maybeSnapshotAssetValue(db, table, row, req.user!.Email);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "update",
    resourceType: "table",
    resourceKey: `${db}.${table}`,
    detail: `rowid=${rowid}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// POST /api/delete — DELETE right
router.post("/delete", (req: Request, res: Response) => {
  const { db, table, rowid } = req.body as {
    db: string;
    table: string;
    rowid: number;
  };
  if (!db || !table || rowid == null)
    return void res.status(400).json({ error: "db, table, rowid required" });
  if (!userCan(req.user, "delete", db, table)) return deny(req, res, "delete", db, table);

  deleteRow(db, table, Number(rowid), tenantScope(req));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "delete",
    resourceType: "table",
    resourceKey: `${db}.${table}`,
    detail: `rowid=${rowid}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /api/asset-cpes?assetId=N — CPEs linked to an asset (CPEFORASSET)
router.get("/asset-cpes", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET"))
    return deny(req, res, "read", "XORCISM", "ASSET");
  // Isolation: the targeted asset must belong to the caller's tenant.
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetCpes(assetId));
});

// GET /api/asset-vulnerabilities?assetId=N — linked vulnerabilities (ASSETVULNERABILITY)
router.get("/asset-vulnerabilities", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET"))
    return deny(req, res, "read", "XORCISM", "ASSET");
  // Isolation: the targeted asset must belong to the caller's tenant.
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetVulnerabilities(assetId));
});

// GET /api/vuln-search?q=...&limit=50 — vulnerability search (CVE/GUID)
router.get("/vuln-search", (req: Request, res: Response) => {
  const q = String(req.query.q || "").trim();
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  if (!userCan(req.user, "read", "XORCISM", "ASSET"))
    return deny(req, res, "read", "XORCISM", "ASSET");
  if (q.length < 2) return void res.json([]);
  res.json(searchVulnerabilities(q, limit));
});

// PUT /api/asset-vulnerabilities { assetId, vulnerabilityIds:[...] } — replaces the links
router.put("/asset-vulnerabilities", (req: Request, res: Response) => {
  const { assetId, vulnerabilityIds } = req.body as {
    assetId: number;
    vulnerabilityIds: number[];
  };
  if (!assetId || !Array.isArray(vulnerabilityIds))
    return void res.status(400).json({ error: "assetId et vulnerabilityIds[] requis" });
  if (
    !userCan(req.user, "update", "XORCISM", "ASSET") &&
    !userCan(req.user, "create", "XORCISM", "ASSET")
  ) {
    return deny(req, res, "update", "XORCISM", "ASSET");
  }
  // Isolation: the targeted asset must belong to the tenant; the junction inherits it.
  const av = parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update");
  if (!av) return;
  setAssetVulnerabilities(Number(assetId), vulnerabilityIds.map(Number), av.tenant);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_asset_vulnerabilities",
    resourceType: "table",
    resourceKey: "XORCISM.ASSETVULNERABILITY",
    detail: `asset=${assetId} vulns=${vulnerabilityIds.length}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /api/asset-tags?assetId=N — tags of an asset (ASSETTAG)
router.get("/asset-tags", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetTags(assetId));
});

// PUT /api/asset-tags { assetId, tags:[...] } — replaces the asset's tags
router.put("/asset-tags", (req: Request, res: Response) => {
  const { assetId, tags } = req.body as { assetId: number; tags: unknown[] };
  if (!assetId || !Array.isArray(tags))
    return void res.status(400).json({ error: "assetId et tags[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET") && !userCan(req.user, "create", "XORCISM", "ASSET"))
    return deny(req, res, "update", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  setAssetTags(Number(assetId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "asset_tags", resourceType: "table",
    resourceKey: "XORCISM.ASSETTAG", detail: `asset=${assetId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/tags — tag labels (XORCISM.TAG referential) for autocompletion
router.get("/tags", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "TAG")) return void res.json([]); // degraded: no suggestions
  res.json(listTags());
});

// GET /api/vuln-tags?vulnerabilityId=N — tags of a VULNERABILITY (VULNERABILITYTAG)
router.get("/vuln-tags", (req: Request, res: Response) => {
  const vid = Number(req.query.vulnerabilityId);
  if (!vid) return void res.status(400).json({ error: "vulnerabilityId requis" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY"))
    return deny(req, res, "read", "XVULNERABILITY", "VULNERABILITY");
  res.json(getVulnerabilityTags(vid));
});

// PUT /api/vuln-tags { vulnerabilityId, tags:[...] } — replaces the tags
router.put("/vuln-tags", (req: Request, res: Response) => {
  const { vulnerabilityId, tags } = req.body as { vulnerabilityId: number; tags: unknown[] };
  if (!vulnerabilityId || !Array.isArray(tags))
    return void res.status(400).json({ error: "vulnerabilityId et tags[] requis" });
  if (!userCan(req.user, "update", "XVULNERABILITY", "VULNERABILITY") && !userCan(req.user, "create", "XVULNERABILITY", "VULNERABILITY"))
    return deny(req, res, "update", "XVULNERABILITY", "VULNERABILITY");
  setVulnerabilityTags(Number(vulnerabilityId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "vuln_tags", resourceType: "table",
    resourceKey: "XVULNERABILITY.VULNERABILITYTAG", detail: `vuln=${vulnerabilityId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/ovaldef-tags?ovalDefinitionId=N — tags of an OVALDEFINITION (OVALDEFINITIONTAG)
router.get("/ovaldef-tags", (req: Request, res: Response) => {
  const oid = Number(req.query.ovalDefinitionId);
  if (!oid) return void res.status(400).json({ error: "ovalDefinitionId requis" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION"))
    return deny(req, res, "read", "XOVAL", "OVALDEFINITION");
  res.json(getOvalDefinitionTags(oid));
});

// PUT /api/ovaldef-tags { ovalDefinitionId, tags:[...] } — replaces the tags
router.put("/ovaldef-tags", (req: Request, res: Response) => {
  const { ovalDefinitionId, tags } = req.body as { ovalDefinitionId: number; tags: unknown[] };
  if (!ovalDefinitionId || !Array.isArray(tags))
    return void res.status(400).json({ error: "ovalDefinitionId et tags[] requis" });
  if (!userCan(req.user, "update", "XOVAL", "OVALDEFINITION") && !userCan(req.user, "create", "XOVAL", "OVALDEFINITION"))
    return deny(req, res, "update", "XOVAL", "OVALDEFINITION");
  setOvalDefinitionTags(Number(ovalDefinitionId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "ovaldef_tags", resourceType: "table",
    resourceKey: "XOVAL.OVALDEFINITIONTAG", detail: `oval=${ovalDefinitionId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/cpe-tags?cpeId=N — tags of a CPE (CPETAG)
router.get("/cpe-tags", (req: Request, res: Response) => {
  const cid = Number(req.query.cpeId);
  if (!cid) return void res.status(400).json({ error: "cpeId requis" });
  if (!userCan(req.user, "read", "XORCISM", "CPE")) return deny(req, res, "read", "XORCISM", "CPE");
  res.json(getCpeTags(cid));
});

// PUT /api/cpe-tags { cpeId, tags:[...] } — replaces the tags
router.put("/cpe-tags", (req: Request, res: Response) => {
  const { cpeId, tags } = req.body as { cpeId: number; tags: unknown[] };
  if (!cpeId || !Array.isArray(tags))
    return void res.status(400).json({ error: "cpeId et tags[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "CPE") && !userCan(req.user, "create", "XORCISM", "CPE"))
    return deny(req, res, "update", "XORCISM", "CPE");
  setCpeTags(Number(cpeId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "cpe_tags", resourceType: "table",
    resourceKey: "XORCISM.CPETAG", detail: `cpe=${cpeId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/cwe-tags?cweId=N — tags of a CWE (CWETAG)
router.get("/cwe-tags", (req: Request, res: Response) => {
  const cid = Number(req.query.cweId);
  if (!cid) return void res.status(400).json({ error: "cweId requis" });
  if (!userCan(req.user, "read", "XORCISM", "CWE")) return deny(req, res, "read", "XORCISM", "CWE");
  res.json(getCweTags(cid));
});

// PUT /api/cwe-tags { cweId, tags:[...] } — replaces the tags
router.put("/cwe-tags", (req: Request, res: Response) => {
  const { cweId, tags } = req.body as { cweId: number; tags: unknown[] };
  if (!cweId || !Array.isArray(tags))
    return void res.status(400).json({ error: "cweId et tags[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "CWE") && !userCan(req.user, "create", "XORCISM", "CWE"))
    return deny(req, res, "update", "XORCISM", "CWE");
  setCweTags(Number(cweId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "cwe_tags", resourceType: "table",
    resourceKey: "XORCISM.CWETAG", detail: `cwe=${cweId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/control-tags?controlId=N — tags of a CONTROL (CONTROLTAG)
router.get("/control-tags", (req: Request, res: Response) => {
  const cid = Number(req.query.controlId);
  if (!cid) return void res.status(400).json({ error: "controlId requis" });
  if (!userCan(req.user, "read", "XORCISM", "CONTROL")) return deny(req, res, "read", "XORCISM", "CONTROL");
  res.json(getControlTags(cid));
});

// PUT /api/control-tags { controlId, tags:[...] } — replaces the tags
router.put("/control-tags", (req: Request, res: Response) => {
  const { controlId, tags } = req.body as { controlId: number; tags: unknown[] };
  if (!controlId || !Array.isArray(tags))
    return void res.status(400).json({ error: "controlId et tags[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "CONTROL") && !userCan(req.user, "create", "XORCISM", "CONTROL"))
    return deny(req, res, "update", "XORCISM", "CONTROL");
  setControlTags(Number(controlId), tags.map((t) => String(t)));
  xid.addAudit({ userId: req.user!.UserID, action: "control_tags", resourceType: "table",
    resourceKey: "XORCISM.CONTROLTAG", detail: `control=${controlId} n=${tags.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// ── ASSET form combobox lookups + ASSET↔ORG / ASSET↔PERSON links ──────────────
// GET /api/lookup/organisations?q= — searchable organisation list (ASSET form combobox)
router.get("/lookup/organisations", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  res.json(searchOrganisations(String(req.query.q ?? ""), 30));
});
// GET /api/lookup/persons?q= — searchable person list (ASSET form combobox)
router.get("/lookup/persons", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  res.json(searchPersons(String(req.query.q ?? ""), 30));
});
// GET /api/default-organisation — the current user's organisation (combobox default)
router.get("/default-organisation", (req: Request, res: Response) => {
  res.json(getDefaultOrganisationForUser(req.user) ?? {});
});
// GET /api/asset-organisations?assetId= — organisations linked to an asset (ASSETFORORGANISATION)
router.get("/asset-organisations", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetOrganisations(assetId));
});
// PUT /api/asset-organisations { assetId, organisationIds:[...] } — replaces the ORG links
router.put("/asset-organisations", (req: Request, res: Response) => {
  const { assetId, organisationIds } = req.body as { assetId: number; organisationIds: number[] };
  if (!assetId || !Array.isArray(organisationIds))
    return void res.status(400).json({ error: "assetId et organisationIds[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET") && !userCan(req.user, "create", "XORCISM", "ASSET"))
    return deny(req, res, "update", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  setAssetOrganisations(Number(assetId), organisationIds.map(Number));
  xid.addAudit({ userId: req.user!.UserID, action: "link_asset_organisations", resourceType: "table",
    resourceKey: "XORCISM.ASSETFORORGANISATION", detail: `asset=${assetId} n=${organisationIds.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});
// GET /api/asset-persons?assetId= — persons linked to an asset (PERSONFORASSET) + name + role
router.get("/asset-persons", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetPersons(assetId));
});
// PUT /api/asset-persons { assetId, links:[{personId, relationshiptype}] } — replaces the PERSON links
router.put("/asset-persons", (req: Request, res: Response) => {
  const { assetId, links } = req.body as { assetId: number; links: { personId: number; relationshiptype: string }[] };
  if (!assetId || !Array.isArray(links))
    return void res.status(400).json({ error: "assetId et links[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET") && !userCan(req.user, "create", "XORCISM", "ASSET"))
    return deny(req, res, "update", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  setAssetPersons(Number(assetId), links.map((l) => ({ personId: Number(l.personId), relationshiptype: String(l.relationshiptype ?? "") })));
  xid.addAudit({ userId: req.user!.UserID, action: "link_asset_persons", resourceType: "table",
    resourceKey: "XORCISM.PERSONFORASSET", detail: `asset=${assetId} n=${links.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/setup/status — true when the first-run wizard should be offered:
// the caller is an Admin and no ORGANISATION exists yet (fresh install).
router.get("/setup/status", (req: Request, res: Response) => {
  const needed = !!req.user?.isAdmin && setupFirstRunNeeded();
  res.json({ needed });
});

// POST /api/setup/admin-asset { organisationId } — wizard step 2: create the
// "XORCISM Admin account" ASSET and the ASSETFORORGANISATION link. Admin only.
router.post("/setup/admin-asset", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return deny(req, res, "create", "XORCISM", "ASSET");
  const { organisationId } = req.body as { organisationId?: number };
  if (!organisationId) return void res.status(400).json({ error: "organisationId requis" });
  const r = setupCreateAdminAsset(Number(organisationId), req.user.tenantId ?? null);
  xid.addAudit({ userId: req.user.UserID, action: "setup_admin_asset", resourceType: "table",
    resourceKey: "XORCISM.ASSETFORORGANISATION",
    detail: `org=${organisationId} adminAsset=${r.adminAssetId} xorcismAsset=${r.xorcismAssetId} app=${r.applicationId} ` +
      `new=${r.created.adminAsset}/${r.created.xorcismAsset}/${r.created.application}`,
    ip: clientIp(req) });
  res.json({ ok: true, ...r });
});

// POST /api/asset-email-harvest { email } — when an ASSET name is an email
// address, capture it into the directory (EMAIL / EMAILADDRESS /
// EMAILFORORGANISATION for the current user's organisation), idempotently.
router.post("/asset-email-harvest", (req: Request, res: Response) => {
  const { email } = req.body as { email?: string };
  if (!email || typeof email !== "string")
    return void res.status(400).json({ error: "email requis" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET") && !userCan(req.user, "update", "XORCISM", "ASSET"))
    return deny(req, res, "create", "XORCISM", "ASSET");
  const orgId = resolveUserOrganisationId(req.user);
  const result = harvestEmailAddress(email, orgId);
  if (!result)
    return void res.status(400).json({ error: "AssetName n'est pas une adresse email valide" });
  xid.addAudit({
    userId: req.user!.UserID, action: "asset_email_harvest", resourceType: "table",
    resourceKey: "XORCISM.EMAIL",
    detail: `${result.email} org=${orgId ?? "-"} email=${result.emailInserted} addr=${result.addressInserted} orglink=${result.orgLinkInserted}`,
    ip: clientIp(req),
  });
  res.json({ ok: true, ...result });
});

// PUT /api/asset-cpes { assetId, cpeIds:[...] } — replaces the linked CPEs
router.put("/asset-cpes", (req: Request, res: Response) => {
  const { assetId, cpeIds } = req.body as { assetId: number; cpeIds: number[] };
  if (!assetId || !Array.isArray(cpeIds))
    return void res.status(400).json({ error: "assetId et cpeIds[] requis" });
  if (
    !userCan(req.user, "update", "XORCISM", "ASSET") &&
    !userCan(req.user, "create", "XORCISM", "ASSET")
  ) {
    return deny(req, res, "update", "XORCISM", "ASSET");
  }
  // Isolation: the targeted asset must belong to the tenant; the junction inherits it.
  const ac = parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update");
  if (!ac) return;
  setAssetCpes(Number(assetId), cpeIds.map(Number), ac.tenant);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_asset_cpes",
    resourceType: "table",
    resourceKey: "XORCISM.CPEFORASSET",
    detail: `asset=${assetId} cpes=${cpeIds.length}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── Threat models: scope (assets), threats, mitigations (controls) ─────────

// GET /api/threatmodel-assets?modelId=N — assets in scope
router.get("/threatmodel-assets", (req: Request, res: Response) => {
  const modelId = Number(req.query.modelId);
  if (!modelId) return void res.status(400).json({ error: "modelId requis" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL"))
    return deny(req, res, "read", "XORCISM", "THREATMODEL");
  if (!parentTenantOr403(req, res, "XORCISM", "THREATMODEL", "ThreatModelID", modelId, "read")) return;
  res.json(getThreatModelAssets(modelId));
});

// PUT /api/threatmodel-assets { modelId, assetIds:[...] } — replaces the scope
router.put("/threatmodel-assets", (req: Request, res: Response) => {
  const { modelId, assetIds } = req.body as { modelId: number; assetIds: number[] };
  if (!modelId || !Array.isArray(assetIds))
    return void res.status(400).json({ error: "modelId et assetIds[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODEL") && !userCan(req.user, "create", "XORCISM", "THREATMODEL"))
    return deny(req, res, "update", "XORCISM", "THREATMODEL");
  const tm = parentTenantOr403(req, res, "XORCISM", "THREATMODEL", "ThreatModelID", Number(modelId), "update");
  if (!tm) return;
  setThreatModelAssets(Number(modelId), assetIds.map(Number), tm.tenant);
  xid.addAudit({ userId: req.user!.UserID, action: "threatmodel_scope", resourceType: "table",
    resourceKey: "XORCISM.THREATMODELASSET", detail: `model=${modelId} assets=${assetIds.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/threatmodel-threats?modelId=N — threats of the model (summary)
router.get("/threatmodel-threats", (req: Request, res: Response) => {
  const modelId = Number(req.query.modelId);
  if (!modelId) return void res.status(400).json({ error: "modelId requis" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL"))
    return deny(req, res, "read", "XORCISM", "THREATMODEL");
  if (!parentTenantOr403(req, res, "XORCISM", "THREATMODEL", "ThreatModelID", modelId, "read")) return;
  res.json(getThreatModelThreats(modelId));
});

// POST /api/threatmodel-threats { modelId, threat:{...} } — adds a threat to the model
router.post("/threatmodel-threats", (req: Request, res: Response) => {
  const { modelId, threat } = req.body as { modelId: number; threat: Record<string, unknown> };
  if (!modelId || !threat) return void res.status(400).json({ error: "modelId et threat requis" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODELTHREAT") && !userCan(req.user, "create", "XORCISM", "THREATMODEL"))
    return deny(req, res, "create", "XORCISM", "THREATMODELTHREAT");
  const tm = parentTenantOr403(req, res, "XORCISM", "THREATMODEL", "ThreatModelID", Number(modelId), "update");
  if (!tm) return;
  const id = addThreatModelThreat(Number(modelId), threat, tm.tenant);
  xid.addAudit({ userId: req.user!.UserID, action: "threatmodel_add_threat", resourceType: "table",
    resourceKey: "XORCISM.THREATMODELTHREAT", detail: `model=${modelId} threat=${id}`, ip: clientIp(req) });
  res.json({ ok: true, id });
});

// GET /api/threat-controls?threatId=N — mitigation controls of a threat
router.get("/threat-controls", (req: Request, res: Response) => {
  const threatId = Number(req.query.threatId);
  if (!threatId) return void res.status(400).json({ error: "threatId requis" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODELTHREAT") && !userCan(req.user, "read", "XORCISM", "THREATMODEL"))
    return deny(req, res, "read", "XORCISM", "THREATMODELTHREAT");
  if (!parentTenantOr403(req, res, "XORCISM", "THREATMODELTHREAT", "ThreatModelThreatID", threatId, "read")) return;
  res.json(getThreatControls(threatId));
});

// PUT /api/threat-controls { threatId, controlIds:[...] } — replaces the mitigations
router.put("/threat-controls", (req: Request, res: Response) => {
  const { threatId, controlIds } = req.body as { threatId: number; controlIds: number[] };
  if (!threatId || !Array.isArray(controlIds))
    return void res.status(400).json({ error: "threatId et controlIds[] requis" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODELTHREAT") && !userCan(req.user, "update", "XORCISM", "THREATMODEL"))
    return deny(req, res, "update", "XORCISM", "THREATMODELTHREAT");
  const tt = parentTenantOr403(req, res, "XORCISM", "THREATMODELTHREAT", "ThreatModelThreatID", Number(threatId), "update");
  if (!tt) return;
  setThreatControls(Number(threatId), controlIds.map(Number), tt.tenant);
  xid.addAudit({ userId: req.user!.UserID, action: "threat_mitigations", resourceType: "table",
    resourceKey: "XORCISM.THREATMODELCONTROL", detail: `threat=${threatId} controls=${controlIds.length}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// ── INCIDENT ↔ ASSET links (INCIDENTFORASSET) ──────────────────────────────────

// GET /api/incident-assets?incidentId=N — linked AssetIDs
router.get("/incident-assets", (req: Request, res: Response) => {
  const incidentId = Number(req.query.incidentId);
  if (!incidentId) return void res.status(400).json({ error: "incidentId requis" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT"))
    return deny(req, res, "read", "XINCIDENT", "INCIDENT");
  // Isolation: the targeted incident must belong to the caller's tenant.
  if (!parentTenantOr403(req, res, "XINCIDENT", "INCIDENT", "IncidentID", incidentId, "read")) return;
  res.json(getIncidentAssets(incidentId));
});

// PUT /api/incident-assets { incidentId, assetIds:[...] } — replaces the links
router.put("/incident-assets", (req: Request, res: Response) => {
  const { incidentId, assetIds } = req.body as { incidentId: number; assetIds: number[] };
  if (!incidentId || !Array.isArray(assetIds))
    return void res.status(400).json({ error: "incidentId et assetIds[] requis" });
  // Linking = modifying the incident: create OR update right on INCIDENT
  if (
    !userCan(req.user, "update", "XINCIDENT", "INCIDENT") &&
    !userCan(req.user, "create", "XINCIDENT", "INCIDENT")
  ) {
    return deny(req, res, "update", "XINCIDENT", "INCIDENT");
  }
  // Isolation: the targeted incident must belong to the tenant; the junction inherits it.
  const ia = parentTenantOr403(req, res, "XINCIDENT", "INCIDENT", "IncidentID", Number(incidentId), "update");
  if (!ia) return;
  setIncidentAssets(Number(incidentId), assetIds.map(Number), ia.tenant);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_incident_assets",
    resourceType: "table",
    resourceKey: "XINCIDENT.INCIDENTFORASSET",
    detail: `incident=${incidentId} assets=[${assetIds.join(",")}]`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── ALERT ↔ ASSET impacted-assets links (ALERTFORASSET) ────────────────────────
// GET /api/alert-assets?alertId=N — linked AssetIDs
router.get("/alert-assets", (req: Request, res: Response) => {
  const alertId = Number(req.query.alertId);
  if (!alertId) return void res.status(400).json({ error: "alertId requis" });
  if (!userCan(req.user, "read", "XINCIDENT", "ALERT")) return deny(req, res, "read", "XINCIDENT", "ALERT");
  if (!parentTenantOr403(req, res, "XINCIDENT", "ALERT", "AlertID", alertId, "read")) return;
  res.json(getAlertAssets(alertId));
});

// PUT /api/alert-assets { alertId, assetIds:[...] } — replaces the impacted-asset links
router.put("/alert-assets", (req: Request, res: Response) => {
  const { alertId, assetIds } = req.body as { alertId: number; assetIds: number[] };
  if (!alertId || !Array.isArray(assetIds))
    return void res.status(400).json({ error: "alertId et assetIds[] requis" });
  if (
    !userCan(req.user, "update", "XINCIDENT", "ALERT") &&
    !userCan(req.user, "create", "XINCIDENT", "ALERT")
  ) {
    return deny(req, res, "update", "XINCIDENT", "ALERT");
  }
  const ia = parentTenantOr403(req, res, "XINCIDENT", "ALERT", "AlertID", Number(alertId), "update");
  if (!ia) return;
  setAlertAssets(Number(alertId), assetIds.map(Number), ia.tenant);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_alert_assets",
    resourceType: "table",
    resourceKey: "XINCIDENT.ALERTFORASSET",
    detail: `alert=${alertId} assets=[${assetIds.join(",")}]`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /api/threat-assets?threatId=N — assets linked to a threat (XTHREAT.THREATFORASSET)
router.get("/threat-assets", (req: Request, res: Response) => {
  const threatId = Number(req.query.threatId);
  if (!threatId) return void res.status(400).json({ error: "threatId requis" });
  if (!userCan(req.user, "read", "XTHREAT", "THREAT")) return deny(req, res, "read", "XTHREAT", "THREAT");
  res.json(getThreatAssets(threatId));
});

// PUT /api/threat-assets { threatId, assetIds:[...] } — replaces the THREAT↔ASSET links
router.put("/threat-assets", (req: Request, res: Response) => {
  const { threatId, assetIds } = req.body as { threatId: number; assetIds: number[] };
  if (!threatId || !Array.isArray(assetIds))
    return void res.status(400).json({ error: "threatId et assetIds[] requis" });
  if (!userCan(req.user, "update", "XTHREAT", "THREAT") && !userCan(req.user, "create", "XTHREAT", "THREAT"))
    return deny(req, res, "update", "XTHREAT", "THREAT");
  setThreatAssets(Number(threatId), assetIds.map(Number), req.user!.tenantId ?? null);
  xid.addAudit({
    userId: req.user!.UserID, action: "link_threat_assets", resourceType: "table",
    resourceKey: "XTHREAT.THREATFORASSET", detail: `threat=${threatId} assets=[${assetIds.join(",")}]`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /api/assets-with-tags — ASSET list (id + name + comma-joined ASSETTAG tags) for the tag-filterable picker
router.get("/assets-with-tags", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  res.json(getAssetsWithTags(req.user!.tenantId ?? null));
});

// POST /api/threat-for-asset/bulk { threatId, assetIds:[...], relationship?, validFrom?, validUntil? }
// — creates one THREATFORASSET per asset for the given threat (skips existing pairs).
router.post("/threat-for-asset/bulk", (req: Request, res: Response) => {
  const b = req.body as { threatId?: number; assetIds?: number[]; relationship?: string; validFrom?: string; validUntil?: string };
  if (!b?.threatId || !Array.isArray(b.assetIds) || !b.assetIds.length)
    return void res.status(400).json({ error: "threatId et assetIds[] requis" });
  if (!userCan(req.user, "create", "XTHREAT", "THREATFORASSET") && !userCan(req.user, "update", "XTHREAT", "THREATFORASSET"))
    return deny(req, res, "create", "XTHREAT", "THREATFORASSET");
  const r = bulkCreateThreatForAsset(Number(b.threatId), b.assetIds.map(Number), {
    relationship: b.relationship, validFrom: b.validFrom, validUntil: b.validUntil,
  }, req.user!.tenantId ?? null);
  xid.addAudit({ userId: req.user!.UserID, action: "bulk_threat_for_asset", resourceType: "table",
    resourceKey: "XTHREAT.THREATFORASSET", detail: `threat=${b.threatId} created=${r.created} skipped=${r.skipped}`, ip: clientIp(req) });
  res.json({ ok: true, ...r });
});

// GET /api/incident-threatactor?incidentId=N — name of the linked threat actor
router.get("/incident-threatactor", (req: Request, res: Response) => {
  const incidentId = Number(req.query.incidentId);
  if (!incidentId) return void res.status(400).json({ error: "incidentId requis" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT"))
    return deny(req, res, "read", "XINCIDENT", "INCIDENT");
  if (!parentTenantOr403(req, res, "XINCIDENT", "INCIDENT", "IncidentID", incidentId, "read")) return;
  res.json({ name: getIncidentThreatActor(incidentId) });
});

// PUT /api/incident-threatactor { incidentId, actorName } — replaces the link
router.put("/incident-threatactor", (req: Request, res: Response) => {
  const { incidentId, actorName } = req.body as { incidentId: number; actorName?: string };
  if (!incidentId) return void res.status(400).json({ error: "incidentId requis" });
  if (
    !userCan(req.user, "update", "XINCIDENT", "INCIDENT") &&
    !userCan(req.user, "create", "XINCIDENT", "INCIDENT")
  ) {
    return deny(req, res, "update", "XINCIDENT", "INCIDENT");
  }
  if (!parentTenantOr403(req, res, "XINCIDENT", "INCIDENT", "IncidentID", Number(incidentId), "update"))
    return;
  setIncidentThreatActor(Number(incidentId), String(actorName ?? ""));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_incident_threatactor",
    resourceType: "table",
    resourceKey: "XTHREAT.THREATACTORFORINCIDENT",
    detail: `incident=${incidentId} actor=${String(actorName ?? "").slice(0, 80)}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// GET /api/audit-assets?auditId=N — AssetIDs linked to an audit (ASSETAUDIT)
router.get("/audit-assets", (req: Request, res: Response) => {
  const auditId = Number(req.query.auditId);
  if (!auditId) return void res.status(400).json({ error: "auditId requis" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT"))
    return deny(req, res, "read", "XCOMPLIANCE", "AUDIT");
  if (!parentTenantOr403(req, res, "XCOMPLIANCE", "AUDIT", "AuditID", auditId, "read")) return;
  res.json(getAuditAssets(auditId));
});

// PUT /api/audit-assets { auditId, assetIds:[...] } — replaces the ASSET links
router.put("/audit-assets", (req: Request, res: Response) => {
  const { auditId, assetIds } = req.body as { auditId: number; assetIds: number[] };
  if (!auditId || !Array.isArray(assetIds))
    return void res.status(400).json({ error: "auditId et assetIds[] requis" });
  if (
    !userCan(req.user, "update", "XCOMPLIANCE", "AUDIT") &&
    !userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")
  ) {
    return deny(req, res, "update", "XCOMPLIANCE", "AUDIT");
  }
  if (!parentTenantOr403(req, res, "XCOMPLIANCE", "AUDIT", "AuditID", Number(auditId), "update"))
    return;
  setAuditAssets(Number(auditId), assetIds.map(Number));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_audit_assets",
    resourceType: "table",
    resourceKey: "XORCISM.ASSETAUDIT",
    detail: `audit=${auditId} assets=[${assetIds.join(",")}]`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── ASSET ↔ OVAL definitions (ASSETOVALDEFINITION) ──────────────────────────────
// GET /api/asset-ovals?assetId=N — OVAL definitions linked to an asset (+ pattern)
router.get("/asset-ovals", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetOvals(assetId));
});

// GET /api/oval-search?q=...&limit=50 — OVAL definition search
router.get("/oval-search", (req: Request, res: Response) => {
  const q = String(req.query.q || "").trim();
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (q.length < 2) return void res.json([]);
  res.json(searchOvalDefinitions(q, limit));
});

// GET /api/oval-xml?id=oval:org.cisecurity:def:1704 — source XML of the imported
// OVAL file (CIS OVALRepo repository). The file uses the identifier with ":" → "_".
const OVAL_DEF_DIR = process.env.OVAL_REPO_DIR
  ? path.join(process.env.OVAL_REPO_DIR, "repository", "definitions")
  : path.resolve(__dirname, "../../../../xorcism_python/importers/OVALRepo/repository/definitions");
let _ovalFileIndex: Map<string, string> | null = null;
function indexOvalDir(dir: string, map: Map<string, string>): void {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) indexOvalDir(full, map);
    else if (e.name.endsWith(".xml") && !map.has(e.name)) map.set(e.name, full);
  }
}
function ovalDefFilePath(pattern: string): string | null {
  if (!_ovalFileIndex) { _ovalFileIndex = new Map(); indexOvalDir(OVAL_DEF_DIR, _ovalFileIndex); }
  return _ovalFileIndex.get(pattern.replace(/:/g, "_") + ".xml") ?? null;
}

router.get("/oval-xml", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return deny(req, res, "read", "XOVAL", "OVALDEFINITION");
  const id = String(req.query.id || "").trim();
  // The OVAL identifier (without "/" or "..") strictly bounds the file name.
  if (!/^oval:[A-Za-z0-9_.\-]+:def:[0-9]+$/i.test(id))
    return void res.status(400).json({ error: "Identifiant OVAL invalide." });
  const file = ovalDefFilePath(id);
  if (!file) return void res.status(404).json({ error: "Fichier OVAL introuvable dans le dépôt importé (OVALRepo)." });
  try {
    const xml = fs.readFileSync(file, "utf-8");
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "oval_xml_view", resourceType: "table",
      resourceKey: "XOVAL.OVALDEFINITION", detail: id, ip: clientIp(req) });
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.send(xml);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// POST /api/asset-ovals { assetId, ovalDefinitionId } — links an OVAL definition
router.post("/asset-ovals", (req: Request, res: Response) => {
  const { assetId, ovalDefinitionId } = req.body as { assetId: number; ovalDefinitionId: number };
  if (!assetId || !ovalDefinitionId)
    return void res.status(400).json({ error: "assetId et ovalDefinitionId requis" });
  if (
    !userCan(req.user, "update", "XORCISM", "ASSET") &&
    !userCan(req.user, "create", "XORCISM", "ASSET")
  ) {
    return deny(req, res, "update", "XORCISM", "ASSET");
  }
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  addAssetOval(Number(assetId), Number(ovalDefinitionId));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_asset_oval",
    resourceType: "table",
    resourceKey: "XORCISM.ASSETOVALDEFINITION",
    detail: `asset=${assetId} oval=${ovalDefinitionId}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// DELETE /api/asset-ovals { assetId, assetOvalDefinitionId } — unlinks an OVAL definition
router.delete("/asset-ovals", (req: Request, res: Response) => {
  const { assetId, assetOvalDefinitionId } = req.body as {
    assetId: number;
    assetOvalDefinitionId: number;
  };
  if (!assetId || !assetOvalDefinitionId)
    return void res.status(400).json({ error: "assetId et assetOvalDefinitionId requis" });
  if (
    !userCan(req.user, "update", "XORCISM", "ASSET") &&
    !userCan(req.user, "delete", "XORCISM", "ASSET")
  ) {
    return deny(req, res, "update", "XORCISM", "ASSET");
  }
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  removeAssetOval(Number(assetId), Number(assetOvalDefinitionId));
  res.json({ ok: true });
});

// GET /api/asset-geolocations?assetId=N — geolocations of an asset (ASSETGEOLOCATION)
router.get("/asset-geolocations", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetGeolocations(assetId));
});

// GET /api/asset-audits?assetId=N — audits linked to an asset (ASSETAUDIT) + AuditName
router.get("/asset-audits", (req: Request, res: Response) => {
  const assetId = Number(req.query.assetId);
  if (!assetId) return void res.status(400).json({ error: "assetId requis" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return deny(req, res, "read", "XORCISM", "ASSET");
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", assetId, "read")) return;
  res.json(getAssetAudits(assetId));
});

// PUT /api/asset-audits { assetId, auditIds:[...] } — replaces the AUDIT links
router.put("/asset-audits", (req: Request, res: Response) => {
  const { assetId, auditIds } = req.body as { assetId: number; auditIds: number[] };
  if (!assetId || !Array.isArray(auditIds))
    return void res.status(400).json({ error: "assetId et auditIds[] requis" });
  if (
    !userCan(req.user, "update", "XORCISM", "ASSET") &&
    !userCan(req.user, "create", "XORCISM", "ASSET")
  ) {
    return deny(req, res, "update", "XORCISM", "ASSET");
  }
  if (!parentTenantOr403(req, res, "XORCISM", "ASSET", "AssetID", Number(assetId), "update")) return;
  setAssetAudits(Number(assetId), auditIds.map(Number));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_asset_audits",
    resourceType: "table",
    resourceKey: "XORCISM.ASSETAUDIT",
    detail: `asset=${assetId} audits=[${auditIds.join(",")}]`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── THREATAGENT ↔ CATEGORY (vocabulary-dependent dropdown) ──────────

// GET /api/threatagent-categories?vocabId=N — options (filtered by vocabulary)
router.get("/threatagent-categories", (req: Request, res: Response) => {
  const vocabId = Number(req.query.vocabId);
  if (!userCan(req.user, "read", "XTHREAT", "THREATAGENT"))
    return deny(req, res, "read", "XTHREAT", "THREATAGENT");
  if (!vocabId) return void res.json([]);
  res.json(threatAgentCategoryOptions(vocabId));
});

// GET /api/threatagent-category?threatAgentId=N — linked category (CategoryID or null)
router.get("/threatagent-category", (req: Request, res: Response) => {
  const taId = Number(req.query.threatAgentId);
  if (!userCan(req.user, "read", "XTHREAT", "THREATAGENT"))
    return deny(req, res, "read", "XTHREAT", "THREATAGENT");
  if (!taId) return void res.json({ categoryId: null });
  res.json({ categoryId: getThreatAgentCategory(taId) });
});

// PUT /api/threatagent-category { threatAgentId, categoryId } — replaces the link
router.put("/threatagent-category", (req: Request, res: Response) => {
  const { threatAgentId, categoryId } = req.body as {
    threatAgentId: number;
    categoryId: number | null | "";
  };
  if (!threatAgentId)
    return void res.status(400).json({ error: "threatAgentId requis" });
  if (
    !userCan(req.user, "update", "XTHREAT", "THREATAGENT") &&
    !userCan(req.user, "create", "XTHREAT", "THREATAGENT")
  ) {
    return deny(req, res, "update", "XTHREAT", "THREATAGENT");
  }
  const cat = categoryId == null || categoryId === "" ? null : Number(categoryId);
  setThreatAgentCategory(Number(threatAgentId), cat);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "link_threatagent_category",
    resourceType: "table",
    resourceKey: "XTHREAT.THREATAGENTCATEGORY",
    detail: `threatAgent=${threatAgentId} category=${cat}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── STIX examples (stix/ folder of the repository) — for the graph visualization ─────
// __dirname = dist/server/routes → ../../../.. = repository root → stix/
const STIX_DIR = path.resolve(__dirname, "../../../../stix");

// GET /api/stix/hunts — STIX 2.1 bundle of the XTHREAT hunts (x-hunt) linked to the
// ATT&CK techniques (attack-pattern) and IOCs (indicator). For the STIX Graph page.
router.get("/stix/hunts", (_req: Request, res: Response) => {
  try {
    res.json(getHuntsStixBundle());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/stix/reports — STIX 2.1 bundle of the XTHREAT threat reports (report SDO)
// linked to the ATT&CK techniques / CVEs they mention. For the STIX Graph page.
router.get("/stix/reports", (_req: Request, res: Response) => {
  try {
    res.json(getReportsStixBundle());
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/stix-examples — list of the example STIX bundles
router.get("/stix-examples", (_req: Request, res: Response) => {
  try {
    const files = fs.readdirSync(STIX_DIR).filter((f) => f.endsWith(".json")).sort();
    res.json(files);
  } catch {
    res.json([]);
  }
});

// GET /api/stix-example?name=... — content of an example bundle
router.get("/stix-example", (req: Request, res: Response) => {
  const name = String(req.query.name || "");
  if (!/^[\w.-]+\.json$/.test(name))
    return void res.status(400).json({ error: "nom invalide" });
  const p = path.join(STIX_DIR, name);
  if (!p.startsWith(STIX_DIR + path.sep) || !fs.existsSync(p))
    return void res.status(404).json({ error: "introuvable" });
  res.type("application/json").send(fs.readFileSync(p, "utf-8"));
});

// ── TAXII 2.1 proxy (server-to-server: respects CSP connect-src 'self') ─────────
// Lets the STIX Graph page fetch a bundle from a TAXII collection
// without a cross-origin call. The target is fixed by configuration (no SSRF).
const TAXII_URL = (process.env.TAXII_PROXY_URL || "http://127.0.0.1:5000").replace(/\/$/, "");
const TAXII_API_ROOT = process.env.TAXII_PROXY_API_ROOT || "api1";
const TAXII_USER = process.env.TAXII_PROXY_USER;
const TAXII_PASS = process.env.TAXII_PROXY_PASSWORD;
const TAXII_MEDIA = "application/taxii+json;version=2.1";

async function taxiiGet(p: string, params?: Record<string, unknown>): Promise<any> {
  const u = new URL(TAXII_URL + p);
  if (params)
    for (const [k, v] of Object.entries(params))
      if (v != null && v !== "") u.searchParams.set(k, String(v));
  const headers: Record<string, string> = { Accept: TAXII_MEDIA };
  if (TAXII_USER)
    headers.Authorization = "Basic " + Buffer.from(`${TAXII_USER}:${TAXII_PASS ?? ""}`).toString("base64");
  const r = await fetch(u, { headers });
  if (!r.ok) throw new Error(`TAXII ${r.status}`);
  return r.json();
}

// GET /api/taxii/status — is the TAXII target reachable?
router.get("/taxii/status", async (_req: Request, res: Response) => {
  try {
    await taxiiGet(`/${TAXII_API_ROOT}/collections/`);
    res.json({ reachable: true, url: TAXII_URL, apiRoot: TAXII_API_ROOT });
  } catch (e) {
    res.json({ reachable: false, url: TAXII_URL, apiRoot: TAXII_API_ROOT, error: (e as Error).message });
  }
});

// GET /api/taxii/collections — collections of the configured API Root
router.get("/taxii/collections", async (_req: Request, res: Response) => {
  try {
    const data = await taxiiGet(`/${TAXII_API_ROOT}/collections/`);
    res.json(data.collections || []);
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// GET /api/taxii/objects?collection=ID&limit=N&type=...&version=... — aggregated bundle
router.get("/taxii/objects", async (req: Request, res: Response) => {
  const col = String(req.query.collection || "");
  if (!/^[\w-]+$/.test(col))
    return void res.status(400).json({ error: "collection invalide" });
  const limit = Math.min(Math.max(Number(req.query.limit) || 500, 1), 10000);
  const type = req.query.type ? String(req.query.type) : undefined;
  const version = req.query.version ? String(req.query.version) : "last";

  const base: Record<string, unknown> = { limit: 200, "match[version]": version };
  if (type) base["match[type]"] = type;

  const objects: any[] = [];
  let next: string | undefined;
  try {
    for (let i = 0; i < 100 && objects.length < limit; i++) {
      const env = await taxiiGet(
        `/${TAXII_API_ROOT}/collections/${col}/objects/`,
        next ? { ...base, next } : base
      );
      for (const o of env.objects || []) objects.push(o);
      if (!env.more || !env.next) break;
      next = env.next;
    }
    res.json({ type: "bundle", id: "bundle--" + crypto.randomUUID(), objects: objects.slice(0, limit) });
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

export default router;
