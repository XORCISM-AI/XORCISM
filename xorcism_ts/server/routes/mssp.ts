/** mssp.ts (routes) — MSSP / multi-tenant rollup (/mssp). Super-admin only (cross-tenant). */
import { Router, Request, Response } from "express";
import { msspRollup } from "../mssp";

const router = Router();

router.get("/mssp", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!req.user.isSuperAdmin) return void res.status(403).json({ error: "MSSP rollup is super-admin only (cross-tenant)." });
  try { res.json(msspRollup()); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
