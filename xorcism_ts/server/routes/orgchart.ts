/** orgchart.ts (routes) — organisation chart over XORCISM.PERSON (read-only). */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { orgChart } from "../orgchart";

const router = Router();

// GET /api/org-chart — the PERSON management hierarchy (forest) + headcount summary
router.get("/org-chart", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "PERSON")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(orgChart()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
