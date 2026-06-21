/**
 * monitoring.ts (routes) — Asset Monitoring: read inventory + add a monitor + record a status.
 * Guarded by RBAC on XORCISM.MONITORINGCHECK.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { monitoringInventory, createMonitor, updateMonitorStatus, activateMonitoring, CHECK_TYPES, MON_STATUSES } from "../monitoring";
import { runMonitorChecks } from "../monitorcheck";
import * as xid from "../xid";

const router = Router();

// GET /api/asset-monitoring — monitors + incidents + uptime/SSL worklist
router.get("/asset-monitoring", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "MONITORINGCHECK")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json({ checkTypes: CHECK_TYPES, statuses: MON_STATUSES, ...monitoringInventory(tenant) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/asset-monitoring/check — create a monitor
router.post("/asset-monitoring/check", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "MONITORINGCHECK")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createMonitor({
      name, type: b.type ? String(b.type) : undefined, target: b.target ? String(b.target) : undefined,
      assetId: b.assetId != null && String(b.assetId) !== "" ? Number(b.assetId) : null,
      intervalSeconds: b.intervalSeconds != null && String(b.intervalSeconds) !== "" ? Number(b.intervalSeconds) : null,
      cronExpression: b.cronExpression ? String(b.cronExpression) : null,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      sslExpiryDate: b.sslExpiryDate ? String(b.sslExpiryDate) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "monitor_create", resourceType: "MONITORINGCHECK",
      resourceKey: String(out.id), detail: `name="${name}" type="${String(b.type || "http")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/asset-monitoring/activate — turn on monitoring for an ASSET (derive monitors from its IP/URL)
router.post("/asset-monitoring/activate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "MONITORINGCHECK")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const assetId = Number(b.assetId);
  if (!Number.isInteger(assetId) || assetId <= 0) return void res.status(400).json({ error: "assetId required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = activateMonitoring(assetId, {
      intervalSeconds: b.intervalSeconds != null && String(b.intervalSeconds) !== "" ? Number(b.intervalSeconds) : null,
      cronExpression: b.cronExpression ? String(b.cronExpression) : null,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      types: Array.isArray(b.types) ? (b.types as unknown[]).map(String) : undefined,
      target: b.target ? String(b.target) : null,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "monitor_activate", resourceType: "MONITORINGCHECK",
      resourceKey: String(assetId), detail: `created=${out.created} skipped=${out.skipped}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/asset-monitoring/status — record a check result (status + response time)
router.post("/asset-monitoring/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "MONITORINGCHECK")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const id = Number(b.checkId);
  const status = String(b.status ?? "").trim();
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "checkId required" });
  if (!status) return void res.status(400).json({ error: "status required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = updateMonitorStatus(id, status, b.responseTimeMs != null && String(b.responseTimeMs) !== "" ? Number(b.responseTimeMs) : null, tenant);
    if (!out.ok) return void res.status(404).json({ error: "monitor not found / not in scope" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "monitor_status", resourceType: "MONITORINGCHECK",
      resourceKey: String(id), detail: `status="${status}"`, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/asset-monitoring/run-checks — probe all due monitors now (live HTTP/TCP/DNS/SSL/ping)
router.post("/asset-monitoring/run-checks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "MONITORINGCHECK")) return void res.status(403).json({ error: "forbidden" });
  runMonitorChecks()
    .then((checked) => {
      xid.addAudit({ userId: req.user!.UserID ?? null, action: "monitor_run_checks", resourceType: "MONITORINGCHECK", detail: `checked=${checked}`, ip: clientIp(req) });
      res.json({ ok: true, checked });
    })
    .catch((e) => res.status(500).json({ error: String((e as Error).message || e) }));
});

export default router;
