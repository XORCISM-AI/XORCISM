/**
 * riskregister.ts (routes) — Risk Register inventory + treatment worklist.
 * Read-only; guarded by read on XCOMPLIANCE.RISKREGISTERENTRY. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { riskRegisterInventory } from "../riskregister";

const router = Router();

// GET /api/risk-register — risk register inventory + treatment/governance worklist
router.get("/risk-register", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(riskRegisterInventory(tenant));
});

export default router;
