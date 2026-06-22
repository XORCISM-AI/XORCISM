/** aiexchange.ts (routes) — OWASP AI Exchange agent threat advisor. RBAC on XTHREAT.THREAT (read). */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { aiThreatCatalogue, advise, Shape } from "../aiexchange";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const VALID: Shape[] = ["llm", "agent", "ml", "tools", "memory", "autonomous", "external", "sensitive"];

router.get("/ai-threats", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "THREAT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(aiThreatCatalogue(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ai-threats/advise", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "THREAT")) return void res.status(403).json({ error: "forbidden" });
  const shapes = (Array.isArray((req.body || {}).shapes) ? (req.body as any).shapes : []).map((s: unknown) => String(s)).filter((s: string) => (VALID as string[]).includes(s)) as Shape[];
  if (!shapes.length) return void res.status(400).json({ error: "select at least one AI system characteristic" });
  res.json(advise(shapes));
});

export default router;
