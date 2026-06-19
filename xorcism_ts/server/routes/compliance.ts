/**
 * compliance.ts (routes) — Compliance / GRC inventory + governance worklist.
 * Read-only; guarded by read on XCOMPLIANCE.AUDIT. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { complianceInventory } from "../compliance";

const router = Router();

// GET /api/compliance-management — audits inventory + open-findings/policy worklist
router.get("/compliance-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(complianceInventory(tenant));
});

export default router;
