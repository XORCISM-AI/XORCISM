/** soccmm.ts (routes) — SOC-CMM maturity self-assessment. RBAC on XINCIDENT.INCIDENT. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { soccmmInventory, saveScore } from "../soccmm";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/soc-cmm", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(soccmmInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/soc-cmm/score/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = saveScore(Number(req.params.id), { maturity: b.maturity != null ? Number(b.maturity) : undefined, importance: b.importance != null ? Number(b.importance) : undefined, notes: b.notes != null ? String(b.notes) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
