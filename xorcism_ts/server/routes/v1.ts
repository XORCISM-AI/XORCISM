/**
 * v1.ts (routes) — XORCISM public REST API v1. API-key (or session) authenticated,
 * tenant-scoped, per-resource scopes. Mounted at /api/v1. See openapi.ts / GET /openapi.json.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { scopeOrSession } from "../apikey";
import { getDb, insertRow, updateRow } from "../db";
import { topExposures } from "../fusion";
import { incidentSlaView } from "../sla";
import { computeEnterpriseRiskScore } from "../riskscore";
import { identityInventory } from "../identities";
import { assetInventory } from "../assets";
import { incidentInventory } from "../incidents";
import { complianceInventory } from "../compliance";
import { policyInventory } from "../policies";
import { configurationInventory } from "../configuration";
import { tidInventory, tidNavigatorLayer } from "../tid";
import { crisisInventory } from "../crisis";
import { buildOpenApi } from "../openapi";
import { dispatchWebhook } from "../webhook";

const router = Router();
const VERSION = "1.1.0-beta.1";

const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const colset = (dbName: string, table: string): Set<string> => {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
};
const page = (req: Request, def = 50, max = 500): { limit: number; offset: number } => ({
  limit: Math.min(max, Math.max(1, Number(req.query.limit) || def)),
  offset: Math.max(0, Number(req.query.offset) || 0),
});
const num = (v: unknown): number | null => (v == null || v === "" || Number.isNaN(Number(v)) ? null : Number(v));

/** Auth + (for API keys) scope gate. Session users pass the scope gate (RBAC still applies). */
function gate(req: Request, res: Response, scope: string): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!scopeOrSession(req, scope)) { res.status(403).json({ error: `API key lacks the '${scope}' scope` }); return false; }
  return true;
}
const rowidByPk = (dbName: string, table: string, pkCol: string, pkVal: number, hasTenant: boolean) =>
  getDb(dbName).prepare(`SELECT rowid AS rid${hasTenant ? ", TenantID AS tid" : ""} FROM "${table}" WHERE "${pkCol}" = ?`).get(pkVal) as { rid: number; tid?: unknown } | undefined;

// ── Meta ────────────────────────────────────────────────────────────────────
router.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", name: "XORCISM API", version: VERSION, time: new Date().toISOString() });
});
router.get("/openapi.json", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json(buildOpenApi());
});
router.get("/me", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const u = req.user;
  const r = req as Request & { apiKeyScopes?: string };
  res.json({ userId: u.UserID, email: u.Email, tenantId: u.tenantId, tenant: u.tenantName, roles: u.roles, isSuperAdmin: u.isSuperAdmin, scopes: r.apiKeyScopes ?? "session" });
});

// ── Assets ──────────────────────────────────────────────────────────────────
function assetSelect(cols: Set<string>): string {
  const f = (c: string, alias: string): string => (cols.has(c) ? `"${c}"` : "NULL") + ` AS ${alias}`;
  return [f("AssetID", "assetId"), f("AssetName", "name"), f("AssetCriticalityLevel", "criticality"),
    f("BusinessValue", "businessValue"), f("FinancialValue", "financialValue"), f("RiskScore", "riskScore"),
    f("SLAResolutionHours", "slaResolutionHours")].join(", ");
}

router.get("/assets", (req: Request, res: Response) => {
  if (!gate(req, res, "assets:read")) return;
  if (!userCan(req.user!, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const xo = getDb("XORCISM");
  const cols = colset("XORCISM", "ASSET");
  const tenant = tenantOf(req);
  const where = tenant != null && cols.has("TenantID") ? `WHERE "TenantID" = ${tenant}` : "";
  const { limit, offset } = page(req);
  const total = (xo.prepare(`SELECT COUNT(*) c FROM ASSET ${where}`).get() as { c: number }).c;
  const items = xo.prepare(`SELECT ${assetSelect(cols)} FROM ASSET ${where} ORDER BY AssetID LIMIT ? OFFSET ?`).all(limit, offset);
  res.json({ total, limit, offset, items });
});

router.get("/assets/:id", (req: Request, res: Response) => {
  if (!gate(req, res, "assets:read")) return;
  if (!userCan(req.user!, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const xo = getDb("XORCISM");
  const cols = colset("XORCISM", "ASSET");
  const tenant = tenantOf(req);
  const row = xo.prepare(`SELECT ${assetSelect(cols)} FROM ASSET WHERE AssetID = ?`).get(Number(req.params.id)) as Record<string, unknown> | undefined;
  if (!row) return void res.status(404).json({ error: "not found" });
  if (tenant != null && cols.has("TenantID")) {
    const t = num((xo.prepare(`SELECT TenantID t FROM ASSET WHERE AssetID = ?`).get(Number(req.params.id)) as { t: unknown }).t);
    if (t !== tenant) return void res.status(404).json({ error: "not found" });
  }
  res.json(row);
});

// PATCH /api/v1/assets/:id — set SLA / value fields
router.patch("/assets/:id", (req: Request, res: Response) => {
  if (!gate(req, res, "assets:write")) return;
  if (!userCan(req.user!, "update", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const cols = colset("XORCISM", "ASSET");
  const tenant = tenantOf(req);
  const loc = rowidByPk("XORCISM", "ASSET", "AssetID", Number(req.params.id), cols.has("TenantID"));
  if (!loc) return void res.status(404).json({ error: "not found" });
  if (tenant != null && num(loc.tid) !== tenant) return void res.status(404).json({ error: "not found" });
  const b = (req.body || {}) as Record<string, unknown>;
  const row: Record<string, unknown> = {};
  const put = (c: string, v: unknown): void => { if (cols.has(c) && v !== undefined) row[c] = v; };
  put("SLAResponseHours", num(b.slaResponseHours));
  put("SLAResolutionHours", num(b.slaResolutionHours));
  put("BusinessValue", num(b.businessValue));
  put("FinancialValue", num(b.financialValue));
  if (!Object.keys(row).length) return void res.status(400).json({ error: "no updatable fields (slaResponseHours, slaResolutionHours, businessValue, financialValue)" });
  updateRow("XORCISM", "ASSET", loc.rid, row, tenant);
  dispatchWebhook("asset.updated", { assetId: Number(req.params.id), changes: { slaResponseHours: row.SLAResponseHours, slaResolutionHours: row.SLAResolutionHours, businessValue: row.BusinessValue, financialValue: row.FinancialValue } }, tenant);
  res.json({ updated: true, assetId: Number(req.params.id) });
});

// ── Incidents ────────────────────────────────────────────────────────────────
router.get("/incidents", (req: Request, res: Response) => {
  if (!gate(req, res, "incidents:read")) return;
  if (!userCan(req.user!, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const xi = getDb("XINCIDENT");
  const cols = colset("XINCIDENT", "INCIDENT");
  if (!cols.size) return void res.json({ total: 0, limit: 0, offset: 0, items: [] });
  const f = (c: string, alias: string): string => (cols.has(c) ? `"${c}"` : "NULL") + ` AS ${alias}`;
  const tenant = tenantOf(req);
  const where = tenant != null && cols.has("TenantID") ? `WHERE "TenantID" = ${tenant}` : "";
  const { limit, offset } = page(req);
  const total = (xi.prepare(`SELECT COUNT(*) c FROM INCIDENT ${where}`).get() as { c: number }).c;
  const sel = [f("IncidentID", "incidentId"), f("IncidentName", "name"), f("Severity", "severity"),
    f("status", "status"), f("Duration", "durationHours")].join(", ");
  const items = xi.prepare(`SELECT ${sel} FROM INCIDENT ${where} ORDER BY IncidentID DESC LIMIT ? OFFSET ?`).all(limit, offset);
  res.json({ total, limit, offset, items });
});

// POST /api/v1/incidents — create an incident
router.post("/incidents", (req: Request, res: Response) => {
  if (!gate(req, res, "incidents:write")) return;
  if (!userCan(req.user!, "create", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const cols = colset("XINCIDENT", "INCIDENT");
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name is required" });
  const row: Record<string, unknown> = {};
  const put = (c: string, v: unknown): void => { if (cols.has(c) && v != null && v !== "") row[c] = v; };
  put("IncidentName", name);
  put("Severity", b.severity);
  put("status", b.status);
  put("synopsis", b.synopsis);
  put("Duration", num(b.durationHours));
  const id = insertRow("XINCIDENT", "INCIDENT", row, tenantOf(req));
  const out = { incidentId: id, name, severity: b.severity ?? null, status: b.status ?? null, durationHours: num(b.durationHours) };
  dispatchWebhook("incident.created", out, tenantOf(req));
  res.status(201).json(out);
});

// PATCH /api/v1/incidents/:id — update duration / status / severity
router.patch("/incidents/:id", (req: Request, res: Response) => {
  if (!gate(req, res, "incidents:write")) return;
  if (!userCan(req.user!, "update", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const cols = colset("XINCIDENT", "INCIDENT");
  const tenant = tenantOf(req);
  const loc = rowidByPk("XINCIDENT", "INCIDENT", "IncidentID", Number(req.params.id), cols.has("TenantID"));
  if (!loc) return void res.status(404).json({ error: "not found" });
  if (tenant != null && num(loc.tid) !== tenant) return void res.status(404).json({ error: "not found" });
  const b = (req.body || {}) as Record<string, unknown>;
  const row: Record<string, unknown> = {};
  const put = (c: string, v: unknown): void => { if (cols.has(c) && v !== undefined) row[c] = v; };
  put("Duration", num(b.durationHours));
  put("status", b.status);
  put("Severity", b.severity);
  if (!Object.keys(row).length) return void res.status(400).json({ error: "no updatable fields (durationHours, status, severity)" });
  updateRow("XINCIDENT", "INCIDENT", loc.rid, row, tenant);
  dispatchWebhook("incident.updated", { incidentId: Number(req.params.id), changes: { durationHours: row.Duration, status: row.status, severity: row.Severity } }, tenant);
  res.json({ updated: true, incidentId: Number(req.params.id) });
});

// GET /api/v1/incident-sla — incidents vs asset SLAs & BIA RTOs
router.get("/incident-sla", (req: Request, res: Response) => {
  if (!gate(req, res, "incidents:read")) return;
  if (!userCan(req.user!, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  res.json(incidentSlaView(tenantOf(req)));
});

// ── Exposure & risk ───────────────────────────────────────────────────────────
const CVE_RX = /CVE-\d{4}-\d{4,7}/i;
router.get("/exposures", (req: Request, res: Response) => {
  if (!gate(req, res, "exposure:read")) return;
  if (!userCan(req.user!, "read", "XVULNERABILITY", "VULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  const { results, scanned } = topExposures(tenantOf(req), limit);
  const items = results.map((v) => ({
    vulnerabilityId: v.VulnerabilityID, cve: (v.ref.match(CVE_RX) || [null])[0],
    score: v.score, priority: v.priority, kev: !!v.kev, epss: v.epss, exploits: v.exploits, affectedAssets: v.assets,
  }));
  res.json({ scanned, items });
});

router.get("/risk", (req: Request, res: Response) => {
  if (!gate(req, res, "risk:read")) return;
  const tenant = tenantOf(req);
  res.json({ tenantId: tenant, enterpriseRiskScore: computeEnterpriseRiskScore(tenant) });
});

// ── Governance (inventory + worklists) ─────────────────────────────────────────
// GET /api/v1/asset-management — asset inventory + governance findings (owner / exposure /
// backup / controls / BIA / KEV-critical vulns) with a 0-100 risk score per asset.
router.get("/asset-management", (req: Request, res: Response) => {
  if (!gate(req, res, "assets:read")) return;
  if (!userCan(req.user!, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  res.json(assetInventory(tenantOf(req)));
});

// GET /api/v1/identities — IAM inventory (human + non-human) + governance findings
// (orphaned NHI / privileged / stale / expiring credentials / missing MFA) with a risk score.
router.get("/identities", (req: Request, res: Response) => {
  if (!gate(req, res, "identities:read")) return;
  if (!userCan(req.user!, "read", "XORCISM", "IDENTITY")) return void res.status(403).json({ error: "forbidden" });
  res.json(identityInventory(tenantOf(req)));
});

// GET /api/v1/incident-management — incident inventory + response worklist (open critical /
// SLA-RTO breach / unassigned / stale / compromise) with a priority score + MTTR.
router.get("/incident-management", (req: Request, res: Response) => {
  if (!gate(req, res, "incidents:read")) return;
  if (!userCan(req.user!, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  res.json(incidentInventory(tenantOf(req)));
});

// GET /api/v1/compliance-management — audit inventory + remediation worklist (open findings
// by severity / overdue / unassigned / policies past review) with a posture score.
router.get("/compliance-management", (req: Request, res: Response) => {
  if (!gate(req, res, "compliance:read")) return;
  if (!userCan(req.user!, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  res.json(complianceInventory(tenantOf(req)));
});

// GET /api/v1/policy-management — policy lifecycle inventory + document register + governance
// worklist (overdue reviews / unpublished / unowned / missing version / expired documents).
router.get("/policy-management", (req: Request, res: Response) => {
  if (!gate(req, res, "policies:read")) return;
  if (!userCan(req.user!, "read", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  res.json(policyInventory(tenantOf(req)));
});

// GET /api/v1/configuration-management — secure-configuration content library (OVAL hardening
// baselines) + verification worklist (deprecated / unverified / interim status / no CCE).
router.get("/configuration-management", (req: Request, res: Response) => {
  if (!gate(req, res, "configuration:read")) return;
  if (!userCan(req.user!, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  res.json(configurationInventory(tenantOf(req)));
});

// GET /api/v1/crisis-management — tabletop-exercise readiness: exercises (inject progress,
// participants, improvement actions), the scenario library, the worklist + a readiness score.
router.get("/crisis-management", (req: Request, res: Response) => {
  if (!gate(req, res, "crisis:read")) return;
  if (!userCan(req.user!, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  res.json(crisisInventory(tenantOf(req)));
});

// GET /api/v1/threat-informed-defense — ATT&CK technique coverage scorecard (adversary use vs
// detect / mitigate / test) + prioritised gap worklist + a threat-weighted program score.
router.get("/threat-informed-defense", (req: Request, res: Response) => {
  if (!gate(req, res, "tid:read")) return;
  if (!userCan(req.user!, "read", "XTHREAT", "ATTACKTECHNIQUE")) return void res.status(403).json({ error: "forbidden" });
  res.json(tidInventory(tenantOf(req)));
});

// GET /api/v1/threat-informed-defense/navigator-layer — export the program as a MITRE ATT&CK
// Navigator layer (v4.5 JSON) for visualisation in the official ATT&CK Navigator.
router.get("/threat-informed-defense/navigator-layer", (req: Request, res: Response) => {
  if (!gate(req, res, "tid:read")) return;
  if (!userCan(req.user!, "read", "XTHREAT", "ATTACKTECHNIQUE")) return void res.status(403).json({ error: "forbidden" });
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(JSON.stringify(tidNavigatorLayer(tenantOf(req)), null, 2));
});

export default router;
