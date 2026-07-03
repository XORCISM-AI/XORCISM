/**
 * auditplanning.ts (routes) — Audit planning / programme management (/audit-planning).
 * Plans + planned items (CRUD), launch a planned item into a real AUDIT, monthly calendar + KPIs.
 * RBAC on XCOMPLIANCE.AUDIT (create/update/read).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  getAuditPlanning, createPlan, updatePlan, deletePlan,
  createItem, updateItem, deleteItem, launchItem,
} from "../auditplanning";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const actorOf = (req: Request): string => req.user!.DisplayName || req.user!.Email || "user";
const canRead = (req: Request): boolean => !!req.user && userCan(req.user, "read", "XCOMPLIANCE", "AUDIT");
const canWrite = (req: Request): boolean => !!req.user && (userCan(req.user, "update", "XCOMPLIANCE", "AUDIT") || userCan(req.user, "create", "XCOMPLIANCE", "AUDIT"));

// GET /api/audit-planning — plans + items + KPIs + monthly calendar
router.get("/audit-planning", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(getAuditPlanning(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// ── Plans ────────────────────────────────────────────────────────────────────
router.post("/audit-planning/plan", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = createPlan(tenantOf(req), { ...(req.body || {}), createdBy: actorOf(req) });
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "audit_plan_create", resourceType: "AUDIT", resourceKey: `plan:${out.planId}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});
router.patch("/audit-planning/plan/:id", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try { updatePlan(tenantOf(req), Number(req.params.id), { ...(req.body || {}), approver: actorOf(req) }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});
router.delete("/audit-planning/plan/:id", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try { deletePlan(tenantOf(req), Number(req.params.id)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// ── Items (planned audits) ─────────────────────────────────────────────────────
router.post("/audit-planning/plan/:id/item", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = createItem(tenantOf(req), Number(req.params.id), req.body || {});
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "audit_plan_item_add", resourceType: "AUDIT", resourceKey: `item:${out.itemId}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});
router.patch("/audit-planning/item/:id", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(updateItem(tenantOf(req), Number(req.params.id), req.body || {})); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});
router.delete("/audit-planning/item/:id", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try { deleteItem(tenantOf(req), Number(req.params.id)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/audit-planning/item/:id/launch — materialise a planned item into a real AUDIT
router.post("/audit-planning/item/:id/launch", (req: Request, res: Response) => {
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = launchItem(tenantOf(req), Number(req.params.id), actorOf(req));
    if (!out.ok) return void res.status(404).json({ error: "planned item not found" });
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "audit_plan_item_launch", resourceType: "AUDIT", resourceKey: `item:${req.params.id}`, detail: `auditId=${out.auditId}`, ip: clientIp(req) });
    res.json(out);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
