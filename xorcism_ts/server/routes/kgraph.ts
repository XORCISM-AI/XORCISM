/** kgraph.ts (routes) — Unified security knowledge graph (/knowledge-graph).
 *  RBAC: read XORCISM.ASSET. Read-only graph + blast-radius + keyword query. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { knowledgeGraph, blastRadius, queryGraph } from "../kgraph";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "ASSET");

router.get("/knowledge-graph", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const limit = Math.max(20, Math.min(400, Number(req.query.limit) || 160));
  try { res.json(knowledgeGraph(ten(req), limit)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/knowledge-graph/blast/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const hops = Math.max(1, Math.min(4, Number(req.query.hops) || 2));
  try { res.json(blastRadius(ten(req), String(req.params.id), hops)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/knowledge-graph/query", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const q = String((req.body as { q?: unknown })?.q ?? "").slice(0, 200);
  try { res.json(queryGraph(ten(req), q)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
