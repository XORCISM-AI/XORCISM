/** cloudsec.ts (routes) — Cloud Security Management inventory (read-only). RBAC on XORCISM.ASSET. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { cloudInventory } from "../cloudsec";

const router = Router();

// GET /api/cloud-security — cloud asset inventory + exposure worklist + CCM posture reference
router.get("/cloud-security", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(cloudInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
