/**
 * ess8.ts (routes) — ASD Essential Eight Maturity Model assessment.
 * Read the model + per-strategy maturity + ISM-control drill-in; write a self-assessment.
 * Guarded by RBAC on XCOMPLIANCE.AUDIT (a compliance/maturity assessment).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { essentialEightDashboard, essentialEightControls, saveEss8 } from "../ess8";
import * as xid from "../xid";

const router = Router();

// GET /api/essential-eight — the 4 maturity levels + 8 strategies with current/target + overall posture + worklist
router.get("/essential-eight", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(essentialEightDashboard(tenant));
});

// GET /api/essential-eight/controls/:strategy — the backing ISM controls for one strategy
router.get("/essential-eight/controls/:strategy", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const out = essentialEightControls(String(req.params.strategy));
  if (!out) return void res.status(404).json({ error: "unknown strategy" });
  res.json(out);
});

// POST /api/essential-eight/assess — set the current/target maturity for one strategy
router.post("/essential-eight/assess", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { strategy?: string; current?: number; target?: number; notes?: string; owner?: string };
  if (!b.strategy) return void res.status(400).json({ error: "strategy required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    saveEss8(tenant, b as Required<Pick<typeof b, "strategy">> & typeof b);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ess8_assess", resourceType: "essential-eight",
      resourceKey: String(b.strategy), detail: `current=ML${b.current ?? 0} target=ML${b.target ?? 1}`, ip: clientIp(req) });
    res.json(essentialEightDashboard(tenant));
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
