/** workforce.ts (routes) — NICE + ENISA ECSF workforce roles around PERSON. RBAC on XORCISM.PERSON. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { workforceInventory, assignRole, unassignRole } from "../workforce";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/workforce", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "PERSON")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(workforceInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/workforce/assign", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "PERSON")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const personId = Number(b.personId), workRoleId = Number(b.workRoleId);
  if (!Number.isFinite(personId) || !Number.isFinite(workRoleId)) return void res.status(400).json({ error: "personId and workRoleId required" });
  const out = assignRole(personId, workRoleId, { proficiency: b.proficiency ? String(b.proficiency) : undefined, primary: !!b.primary }, ten(req));
  if (!out) return void res.status(404).json({ error: "person or work role not found" });
  res.json({ ok: true, ...out });
});

router.delete("/workforce/assign/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "PERSON")) return void res.status(403).json({ error: "forbidden" });
  unassignRole(Number(req.params.id));
  res.json({ ok: true });
});

export default router;
