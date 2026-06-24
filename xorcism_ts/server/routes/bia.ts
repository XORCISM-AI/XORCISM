/**
 * bia.ts — Business Impact Analysis API routes
 * Replaces PowerShell /api/bia/* routes
 *
 * Multi-tenant: BIAAUDIT and BIAENTRY are operational tables isolated
 * by TenantID (cf. db.ts: TENANT_SCOPED_TABLES). Reads are filtered and the
 * TenantID is enforced on write for a tenant user; the super-admin
 * (System tenant) is not filtered. As long as the TenantID column does not
 * exist yet (XORCISM import in progress), isolation stays inactive — consistent
 * with the explorer's generic CRUD.
 */

import { Router, Request, Response } from "express";
import { getDb, tableHasTenantCol, rowTenant, TENANT_COL, biaDependencyGraph, ensureBiaDependency } from "../db";
import { clientIp } from "../auth";
import * as xid from "../xid";
import { tr } from "../i18n";
import type { BiaAudit, BiaEntry } from "../types";

const router = Router();

const AUDIT_TBL = "BIAAUDIT";
const ENTRY_TBL = "BIAENTRY";

function db() {
  return getDb("XORCISM");
}

function now(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

// Isolation scope for READ/filtering: null = super-admin
// (sees everything), otherwise the user's tenant.
function biaScope(req: Request): number | null {
  const u = req.user!;
  return u.isSuperAdmin ? null : u.tenantId ?? null;
}

// Tenant to STAMP on a created root row: always the session's one
// (including super-admin → System tenant), like sessionTenant in the explorer.
// Child rows (entries) instead inherit the tenant of their parent audit.
function sessionTenant(req: Request): number | null {
  return req.user!.tenantId ?? null;
}

// Isolation predicate for a given table, or null if inactive
// (super-admin, or TenantID column absent). To be combined in the WHERE clause.
function scopeClause(req: Request, table: string): { cond: string; param: number } | null {
  const scope = biaScope(req);
  if (scope != null && tableHasTenantCol("XORCISM", table)) {
    return { cond: `"${TENANT_COL}" = ?`, param: scope };
  }
  return null;
}

// Denies access (403) and logs the attempt.
function deny(req: Request, res: Response, action: string, table: string): void {
  xid.addAudit({
    userId: req.user?.UserID ?? null,
    action: "access_denied",
    resourceType: "table",
    resourceKey: `XORCISM.${table}`,
    detail: action,
    ip: clientIp(req),
  });
  res.status(403).json({ error: tr(req, "err.accessDenied") });
}

/**
 * Checks that the targeted parent audit belongs to the caller's tenant and returns
 * the TenantID to inherit on the entry. Same model as parentTenantOr403 in
 * the explorer: super-admin not filtered (inherits the audit's real tenant);
 * tenant user denied (403 + audit) if the audit is not theirs.
 * Returns null after emitting the 403 (the route must stop).
 */
function parentAuditTenant(
  req: Request,
  res: Response,
  auditId: number
): { tenant: number | null } | null {
  const scope = biaScope(req);
  const parent = rowTenant("XORCISM", AUDIT_TBL, "BIAAuditID", auditId);
  if (scope == null) return { tenant: parent };
  if (tableHasTenantCol("XORCISM", AUDIT_TBL) && parent !== scope) {
    deny(req, res, "create", ENTRY_TBL);
    return null;
  }
  return { tenant: scope };
}

// ── Audits ───────────────────────────────────────────────────────────────────

// GET /api/bia/audits
router.get("/audits", (req: Request, res: Response) => {
  const sc = scopeClause(req, AUDIT_TBL);
  const where = sc ? `WHERE ${sc.cond}` : "";
  const params = sc ? [sc.param] : [];
  const rows = db()
    .prepare(`SELECT * FROM BIAAUDIT ${where} ORDER BY BIAAuditID DESC`)
    .all(...params);
  res.json(rows);
});

// POST /api/bia/audits
router.post("/audits", (req: Request, res: Response) => {
  const d = req.body as BiaAudit;
  if (!d.BIAAuditName)
    return void res.status(400).json({ error: "BIAAuditName required" });

  // Multi-tenant: stamps the session's tenant (super-admin → System tenant).
  const hasTenant = tableHasTenantCol("XORCISM", AUDIT_TBL);
  const cols =
    "BIAAuditName, BIAAuditDescription, BIAAuditScope, BIAAuditDate, " +
    `Auditor, BIAAuditStatus, CreatedDate${hasTenant ? `, "${TENANT_COL}"` : ""}`;
  const placeholders = `?, ?, ?, ?, ?, 'Draft', ?${hasTenant ? ", ?" : ""}`;
  const args: (string | number | null)[] = [
    d.BIAAuditName,
    d.BIAAuditDescription ?? null,
    d.BIAAuditScope ?? null,
    d.BIAAuditDate ?? null,
    d.Auditor ?? null,
    now(),
  ];
  if (hasTenant) args.push(sessionTenant(req));

  const info = db()
    .prepare(`INSERT INTO BIAAUDIT (${cols}) VALUES (${placeholders})`)
    .run(...args);
  res.json({ id: info.lastInsertRowid });
});

// PATCH /api/bia/audits/:id — update status
router.patch("/audits/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const { BIAAuditStatus } = req.body as { BIAAuditStatus: string };
  const sc = scopeClause(req, AUDIT_TBL);
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: (string | number)[] = sc
    ? [BIAAuditStatus, id, sc.param]
    : [BIAAuditStatus, id];
  db()
    .prepare(`UPDATE BIAAUDIT SET BIAAuditStatus=? WHERE BIAAuditID=?${extra}`)
    .run(...params);
  res.json({ ok: true });
});

// PUT /api/bia/audits/:id — full update
router.put("/audits/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const d = req.body as BiaAudit;
  const sc = scopeClause(req, AUDIT_TBL);
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: (string | number | null)[] = [
    d.BIAAuditName,
    d.BIAAuditDescription ?? null,
    d.BIAAuditScope ?? null,
    d.BIAAuditDate ?? null,
    d.Auditor ?? null,
    d.BIAAuditStatus ?? "Draft",
    id,
  ];
  if (sc) params.push(sc.param);
  db()
    .prepare(`
      UPDATE BIAAUDIT SET
        BIAAuditName=?, BIAAuditDescription=?, BIAAuditScope=?,
        BIAAuditDate=?, Auditor=?, BIAAuditStatus=?
      WHERE BIAAuditID=?${extra}
    `)
    .run(...params);
  res.json({ ok: true });
});

// DELETE /api/bia/audits/:id
router.delete("/audits/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const scA = scopeClause(req, AUDIT_TBL);
  const scE = scopeClause(req, ENTRY_TBL);
  const extraA = scA ? ` AND ${scA.cond}` : "";
  const extraE = scE ? ` AND ${scE.cond}` : "";
  const paramsA: number[] = scA ? [id, scA.param] : [id];
  const paramsE: number[] = scE ? [id, scE.param] : [id];
  const deleteEntries = db().prepare(
    `DELETE FROM BIAENTRY WHERE BIAAuditID=?${extraE}`
  );
  const deleteAudit = db().prepare(
    `DELETE FROM BIAAUDIT WHERE BIAAuditID=?${extraA}`
  );
  db().transaction(() => {
    deleteEntries.run(...paramsE);
    deleteAudit.run(...paramsA);
  })();
  res.json({ ok: true });
});

// ── Entries ──────────────────────────────────────────────────────────────────

// GET /api/bia/entries?auditId=N
router.get("/entries", (req: Request, res: Response) => {
  const auditId = Number(req.query.auditId);
  if (!auditId)
    return void res.status(400).json({ error: "auditId required" });
  const sc = scopeClause(req, ENTRY_TBL);
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: number[] = sc ? [auditId, sc.param] : [auditId];
  const rows = db()
    .prepare(`SELECT * FROM BIAENTRY WHERE BIAAuditID=?${extra} ORDER BY BIAEntryID`)
    .all(...params);
  res.json(rows);
});

// POST /api/bia/entries
router.post("/entries", (req: Request, res: Response) => {
  const d = req.body as BiaEntry;
  if (!d.BIAAuditID)
    return void res.status(400).json({ error: "BIAAuditID required" });

  // Isolation: the parent audit must belong to the tenant; the entry inherits it.
  const guard = parentAuditTenant(req, res, Number(d.BIAAuditID));
  if (!guard) return;

  const hasTenant = tableHasTenantCol("XORCISM", ENTRY_TBL);
  const cols =
    "BIAAuditID, AssetName, AssetDescription, AssetType, CriticalityLevel, " +
    "OwnerName, RiskDescription, RiskLevel, " +
    "ImpactFinancial, ImpactOperational, ImpactLegal, ImpactReputational, " +
    `MTD, RTO, RPO, Notes, CreatedDate, ModifiedDate${hasTenant ? `, "${TENANT_COL}"` : ""}`;
  const placeholders = `?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?${hasTenant ? ",?" : ""}`;
  const n = now();
  const args: (string | number | null)[] = [
    d.BIAAuditID,
    d.AssetName ?? null,
    d.AssetDescription ?? null,
    d.AssetType ?? null,
    d.CriticalityLevel ?? null,
    d.OwnerName ?? null,
    d.RiskDescription ?? null,
    d.RiskLevel ?? null,
    d.ImpactFinancial ?? null,
    d.ImpactOperational ?? null,
    d.ImpactLegal ?? null,
    d.ImpactReputational ?? null,
    d.MTD ?? null,
    d.RTO ?? null,
    d.RPO ?? null,
    d.Notes ?? null,
    n,
    n,
  ];
  if (hasTenant) args.push(guard.tenant);

  const info = db()
    .prepare(`INSERT INTO BIAENTRY (${cols}) VALUES (${placeholders})`)
    .run(...args);
  res.json({ id: info.lastInsertRowid });
});

// PUT /api/bia/entries/:id
router.put("/entries/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const d = req.body as BiaEntry;
  const sc = scopeClause(req, ENTRY_TBL);
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: (string | number | null)[] = [
    d.AssetName ?? null,
    d.AssetDescription ?? null,
    d.AssetType ?? null,
    d.CriticalityLevel ?? null,
    d.OwnerName ?? null,
    d.RiskDescription ?? null,
    d.RiskLevel ?? null,
    d.ImpactFinancial ?? null,
    d.ImpactOperational ?? null,
    d.ImpactLegal ?? null,
    d.ImpactReputational ?? null,
    d.MTD ?? null,
    d.RTO ?? null,
    d.RPO ?? null,
    d.Notes ?? null,
    now(),
    id,
  ];
  if (sc) params.push(sc.param);
  db()
    .prepare(`
      UPDATE BIAENTRY SET
        AssetName=?, AssetDescription=?, AssetType=?, CriticalityLevel=?,
        OwnerName=?, RiskDescription=?, RiskLevel=?,
        ImpactFinancial=?, ImpactOperational=?, ImpactLegal=?, ImpactReputational=?,
        MTD=?, RTO=?, RPO=?, Notes=?, ModifiedDate=?
      WHERE BIAEntryID=?${extra}
    `)
    .run(...params);
  res.json({ ok: true });
});

// DELETE /api/bia/entries/:id
router.delete("/entries/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const sc = scopeClause(req, ENTRY_TBL);
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: number[] = sc ? [id, sc.param] : [id];
  db().prepare(`DELETE FROM BIAENTRY WHERE BIAEntryID=?${extra}`).run(...params);
  res.json({ ok: true });
});

// ── Autocomplete helpers ──────────────────────────────────────────────────────

// GET /api/bia/assets?q=search — ASSET is isolated per tenant.
router.get("/assets", (req: Request, res: Response) => {
  const q = `%${req.query.q ?? ""}%`;
  const sc = scopeClause(req, "ASSET");
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: (string | number)[] = sc ? [q, sc.param] : [q];
  const rows = db()
    .prepare(
      `SELECT AssetID, AssetName, AssetDescription, AssetCriticalityLevel
       FROM ASSET WHERE AssetName LIKE ?${extra} LIMIT 20`
    )
    .all(...params);
  res.json(rows);
});

// GET /api/bia/asset-names — DISTINCT asset names (BIA datalist), isolated per tenant.
router.get("/asset-names", (req: Request, res: Response) => {
  const sc = scopeClause(req, "ASSET");
  const extra = sc ? ` AND ${sc.cond}` : "";
  const params: (string | number)[] = sc ? [sc.param] : [];
  const rows = db()
    .prepare(
      `SELECT DISTINCT AssetName FROM ASSET
       WHERE AssetName IS NOT NULL AND TRIM(AssetName) <> ''${extra}
       ORDER BY AssetName COLLATE NOCASE`
    )
    .all(...params) as { AssetName: string }[];
  res.json(rows.map((r) => r.AssetName));
});

// GET /api/bia/persons?q=search — PERSON is not isolated (shared referential).
router.get("/persons", (req: Request, res: Response) => {
  const q = `%${req.query.q ?? ""}%`;
  const rows = db()
    .prepare(
      `SELECT PersonID, FullName, FirstName, LastName
       FROM PERSON WHERE FullName LIKE ? OR LastName LIKE ? LIMIT 20`
    )
    .all(q, q);
  res.json(rows);
});

// GET /api/bia/person-names — DISTINCT PERSON.FullName for the auditor combobox (PERSON is shared).
router.get("/person-names", (_req: Request, res: Response) => {
  const rows = db()
    .prepare(
      `SELECT DISTINCT FullName FROM PERSON
       WHERE FullName IS NOT NULL AND TRIM(FullName) <> ''
       ORDER BY FullName COLLATE NOCASE`
    )
    .all() as { FullName: string }[];
  res.json(rows.map((r) => r.FullName));
});

// ── Dependency graph ─────────────────────────────────────────────────────────
// GET /api/bia/graph?auditId=N — BIA entries + dependency edges for one audit.
router.get("/graph", (req: Request, res: Response) => {
  const auditId = Number(req.query.auditId);
  if (!Number.isInteger(auditId) || auditId <= 0) return void res.status(400).json({ error: "auditId required" });
  try { res.json(biaDependencyGraph(biaScope(req), auditId)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/bia/dependencies { auditId, fromEntryId, toEntryId, type } — "From depends on To".
router.post("/dependencies", (req: Request, res: Response) => {
  const b = req.body as { auditId?: unknown; fromEntryId?: unknown; toEntryId?: unknown; type?: unknown };
  const auditId = Number(b.auditId), from = Number(b.fromEntryId), to = Number(b.toEntryId);
  if (![auditId, from, to].every((n) => Number.isInteger(n) && n > 0))
    return void res.status(400).json({ error: "auditId, fromEntryId, toEntryId required" });
  if (from === to) return void res.status(400).json({ error: "a node cannot depend on itself" });
  const pt = parentAuditTenant(req, res, auditId); if (!pt) return;
  ensureBiaDependency();
  const d = db();
  const inAudit = (id: number): boolean => !!d.prepare("SELECT 1 FROM BIAENTRY WHERE BIAEntryID=? AND BIAAuditID=?").get(id, auditId);
  if (!inAudit(from) || !inAudit(to)) return void res.status(400).json({ error: "both entries must belong to the audit" });
  const dup = d.prepare("SELECT BIADependencyID FROM BIADEPENDENCY WHERE BIAAuditID=? AND FromEntryID=? AND ToEntryID=?").get(auditId, from, to) as { BIADependencyID: number } | undefined;
  if (dup) return void res.json({ ok: true, id: dup.BIADependencyID });
  d.prepare(`INSERT INTO BIADEPENDENCY (BIADependencyID, BIAAuditID, FromEntryID, ToEntryID, DependencyType, CreatedDate, "${TENANT_COL}")
    VALUES ((SELECT COALESCE(MAX(BIADependencyID),0)+1 FROM BIADEPENDENCY), ?, ?, ?, ?, ?, ?)`)
    .run(auditId, from, to, String(b.type || "depends-on").slice(0, 60), now(), pt.tenant);
  const id = (d.prepare("SELECT MAX(BIADependencyID) m FROM BIADEPENDENCY WHERE BIAAuditID=? AND FromEntryID=? AND ToEntryID=?").get(auditId, from, to) as { m: number }).m;
  xid.addAudit({ userId: req.user!.UserID, action: "bia_dependency_add", resourceType: "table", resourceKey: `XORCISM.BIADEPENDENCY#${id}`, ip: clientIp(req) });
  res.json({ ok: true, id });
});

// DELETE /api/bia/dependencies/:id
router.delete("/dependencies/:id", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  ensureBiaDependency();
  const d = db();
  const row = d.prepare("SELECT BIAAuditID FROM BIADEPENDENCY WHERE BIADependencyID=?").get(id) as { BIAAuditID: number } | undefined;
  if (!row) return void res.json({ ok: true });
  const pt = parentAuditTenant(req, res, row.BIAAuditID); if (!pt) return;
  d.prepare("DELETE FROM BIADEPENDENCY WHERE BIADependencyID=?").run(id);
  res.json({ ok: true });
});

export default router;
