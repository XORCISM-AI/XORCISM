/** soccmm.ts (routes) — SOC-CMM advanced self-assessment (maturity 0–5 + capability 0–3).
 * RBAC on XINCIDENT.INCIDENT. Results entry: per-aspect scores + the assessment header. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { soccmmInventory, saveScore, saveAssessment } from "../soccmm";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const num = (v: unknown): number | undefined => (v != null && v !== "" ? Number(v) : undefined);

router.get("/soc-cmm", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(soccmmInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// Enter/update one aspect's result (maturity, capability, importance, notes).
router.post("/soc-cmm/score/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = saveScore(Number(req.params.id), {
    maturity: num(b.maturity), capability: num(b.capability), importance: num(b.importance),
    notes: b.notes != null ? String(b.notes) : undefined,
  }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json(soccmmInventory(ten(req)));
});

// Update the assessment header (SOC scope, self vs 3rd-party, assessor, targets).
router.post("/soc-cmm/assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  saveAssessment(ten(req), {
    scopeName: b.scopeName != null ? String(b.scopeName) : undefined,
    assessType: b.assessType != null ? String(b.assessType) : undefined,
    assessor: b.assessor != null ? String(b.assessor) : undefined,
    targetMaturity: num(b.targetMaturity), targetCapability: num(b.targetCapability),
    notes: b.notes != null ? String(b.notes) : undefined,
  });
  res.json(soccmmInventory(ten(req)));
});

export default router;
