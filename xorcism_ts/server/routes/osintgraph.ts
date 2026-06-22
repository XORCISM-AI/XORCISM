/** osintgraph.ts (routes) — OSINT link-analysis graph over XTHREAT.INTELEXCHANGE (read-only). */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { osintGraph } from "../osintgraph";

const router = Router();

// GET /api/osint-graph — entity-link graph (intel items + extracted CVE/actor/malware/IOC entities)
router.get("/osint-graph", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "INTELEXCHANGE")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(osintGraph({ limit: Number(req.query.limit) || 600 })); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
