/**
 * uem.ts (routes) — Unified Exposure Management (/exposure-management).
 * The single prioritized exposure queue across all finding types: summary + queue + coverage,
 * a sync that (re)builds the unified queue from every source, and per-exposure lifecycle actions
 * (status / owner / risk-accept / validation). RBAC-gated on XVULNERABILITY.VULNERABILITY; audited.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { syncExposures, exposureQueue, exposureSummary, exposureCoverage, setStatus, acceptRisk, setValidation, assignOwner, exposureTrend, mobilizeExposure, exposureExport, EXPOSURE_TYPES } from "../uem";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const auth = (req: Request, res: Response, act: "read" | "create" | "update"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XVULNERABILITY", "VULNERABILITY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "exposure", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/exposures — summary + coverage + the prioritized queue (filters: type/severity/status/validation/q)
router.get("/exposures", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const t = tenantOf(req);
  const f = {
    type: req.query.type ? String(req.query.type) : undefined,
    severity: req.query.severity ? String(req.query.severity) : undefined,
    status: req.query.status ? String(req.query.status) : undefined,
    validation: req.query.validation ? String(req.query.validation) : undefined,
    q: req.query.q ? String(req.query.q) : undefined,
    openOnly: req.query.all !== "1",
  };
  res.json({ summary: exposureSummary(t), coverage: exposureCoverage(t), types: EXPOSURE_TYPES, queue: exposureQueue(t, f) });
});

// POST /api/exposures/sync — rebuild the unified queue from every source (dedup + lifecycle)
router.post("/exposures/sync", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = syncExposures(tenantOf(req));
  audit(req, "exposure_sync", "all", `scanned ${out.scanned} new ${out.created} reopened ${out.reopened} resolved ${out.resolved}`);
  res.json({ ok: true, ...out });
});

// POST /api/exposures/:id/status { status, owner? }
router.post("/exposures/:id/status", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = req.body || {};
  const out = setStatus(tenantOf(req), Number(req.params.id), String(b.status || ""), b.owner ? String(b.owner) : undefined);
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "exposure_status", String(req.params.id), String(b.status));
  res.json(out);
});

// POST /api/exposures/:id/validate { validation } — re-weights the score (AEV → priority)
router.post("/exposures/:id/validate", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = setValidation(tenantOf(req), Number(req.params.id), String((req.body || {}).validation || ""));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "exposure_validate", String(req.params.id), String((req.body || {}).validation));
  res.json(out);
});

// POST /api/exposures/:id/accept-risk { note }
router.post("/exposures/:id/accept-risk", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = acceptRisk(tenantOf(req), Number(req.params.id), String((req.body || {}).note || ""));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "exposure_accept_risk", String(req.params.id));
  res.json(out);
});

// POST /api/exposures/:id/owner { owner }
router.post("/exposures/:id/owner", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = assignOwner(tenantOf(req), Number(req.params.id), String((req.body || {}).owner || ""));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "exposure_owner", String(req.params.id));
  res.json(out);
});

// GET /api/exposures/trend?days=90 — the Exposure Score over time
router.get("/exposures/trend", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(exposureTrend(tenantOf(req), req.query.days != null ? Number(req.query.days) : 90));
});

// POST /api/exposures/:id/mobilize { assignee? } — open an internal remediation ticket (XTICKET) from the exposure
router.post("/exposures/:id/mobilize", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = mobilizeExposure(tenantOf(req), Number(req.params.id), (req.body || {}).assignee ? String((req.body || {}).assignee) : undefined);
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "exposure_mobilize", String(req.params.id), `ticket ${out.ticket}`);
  res.json(out);
});

// GET /api/exposures/:id/export — a Jira/ServiceNow-ready payload (export, not auto-push)
router.get("/exposures/:id/export", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const out = exposureExport(tenantOf(req), Number(req.params.id));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

export default router;
