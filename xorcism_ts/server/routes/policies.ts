/**
 * policies.ts (routes) — Policy & document management inventory + governance worklist.
 * Read-only; guarded by read on XORCISM.POLICY. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { policyInventory } from "../policies";

const router = Router();

// GET /api/policy-management — policies + document register + governance worklist
router.get("/policy-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(policyInventory(tenant));
});

export default router;
