/** awareness.ts (routes) — Security Awareness Training + Phishing Simulations. RBAC on XORCISM.TRAINING. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { awarenessInventory, createTraining, createPhishingSim } from "../awareness";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/security-awareness", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "TRAINING")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(awarenessInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/security-awareness/training", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "TRAINING")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const out = createTraining({ name: String(b.name), category: b.category ? String(b.category) : undefined, provider: b.provider ? String(b.provider) : undefined,
      duration: b.duration != null && String(b.duration) !== "" ? Number(b.duration) : undefined, required: !!b.required, description: b.description ? String(b.description) : undefined }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "training_create", resourceType: "TRAINING", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/security-awareness/phishing", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "TRAINING")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const out = createPhishingSim({ name: String(b.name), theme: b.theme ? String(b.theme) : undefined, difficulty: b.difficulty ? String(b.difficulty) : undefined, description: b.description ? String(b.description) : undefined }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "phishingsim_create", resourceType: "PHISHINGSIMULATION", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
