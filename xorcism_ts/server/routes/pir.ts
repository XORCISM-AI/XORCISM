/**
 * pir.ts (routes) — Priority Intelligence Requirements coverage register.
 * Read-only; guarded by read on XTHREAT.PIR. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { pirRegister } from "../pir";

const router = Router();

// GET /api/pir — PIRs with collection coverage + gaps
router.get("/pir", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "PIR")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(pirRegister(tenant));
});

export default router;
