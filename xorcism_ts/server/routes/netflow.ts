/** netflow.ts (routes) — Network flow / sessions cartography (NetFlow around ASSET). RBAC XORCISM.ASSET. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { netflowInventory } from "../netflow";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/network-sessions", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(netflowInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
