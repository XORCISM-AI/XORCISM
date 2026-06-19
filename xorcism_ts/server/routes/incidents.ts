/**
 * incidents.ts (routes) — Incident Management inventory + governance worklist.
 * Read-only; guarded by read on XINCIDENT.INCIDENT. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { incidentInventory } from "../incidents";

const router = Router();

// GET /api/incident-management — incident inventory + governance findings
router.get("/incident-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(incidentInventory(tenant));
});

export default router;
