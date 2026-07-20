/**
 * controlweight.ts (routes) — control-weight calculator (CapGRC PfC model) and its weighted
 * assurance contribution to the EnterpriseRiskScore. RBAC: XORCISM.CONTROL.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  computeWeight, controlWeightInventory, setControlWeight, clearControlWeight,
  weightedControlAssurance, searchControls, ensureControlWeightColumns,
} from "../controlweight";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request): boolean => userCan(req.user, "read", "XORCISM", "CONTROL");
const wr = (req: Request): boolean => userCan(req.user, "update", "XORCISM", "CONTROL");
const auth = (req: Request, res: Response, write = false): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!(write ? wr(req) : rd(req))) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/control-weight — the model, the weighted controls, the distribution and the risk term
router.get("/control-weight", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  try { ensureControlWeightColumns(); res.json(controlWeightInventory(ten(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/control-weight/compute { type, scope, confidentiality, integrity, availability, nonRepudiation, qty, qtyTotal }
// Pure calculator — computes PfC without persisting anything (the live calculator panel).
router.post("/control-weight/compute", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  try { res.json(computeWeight((req.body || {}) as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// GET /api/control-weight/controls?q= — control catalogue picker
router.get("/control-weight/controls", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  res.json({ items: searchControls(String(req.query.q || ""), 40) });
});

// GET /api/control-weight/assurance — just the EnterpriseRiskScore contribution (+ per-control rows)
router.get("/control-weight/assurance", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  res.json(weightedControlAssurance(ten(req), String(req.query.rows || "") === "1"));
});

// POST /api/control-weight/control/:id — assign the weight to a control for this tenant
router.post("/control-weight/control/:id", (req: Request, res: Response) => {
  if (!auth(req, res, true)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid control id" });
  const out = setControlWeight(id, ten(req), (req.body || {}) as Record<string, unknown>);
  if (!out.ok) return void res.status(404).json(out);
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "control_weight_set", resourceType: "CONTROLIMPLEMENTATION", resourceKey: String(id), detail: String(out.result?.weight ?? ""), ip: clientIp(req) });
  res.json({ ok: true, ...out.result });
});

// DELETE /api/control-weight/control/:id — clear the weight (keeps the implementation row)
router.delete("/control-weight/control/:id", (req: Request, res: Response) => {
  if (!auth(req, res, true)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid control id" });
  res.json(clearControlWeight(id, ten(req)));
});

export default router;
