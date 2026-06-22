/** governance.ts (routes) — NIST CSF 2.0 Govern (GV) register. RBAC on XCOMPLIANCE.AUDIT. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { governanceInventory, saveGovernanceStatus } from "../governance";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/governance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(governanceInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/governance/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = saveGovernanceStatus(Number(req.params.id), { status: b.status != null ? String(b.status) : undefined, maturity: b.maturity != null ? Number(b.maturity) : undefined, ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined, evidence: b.evidence != null ? String(b.evidence) : undefined, notes: b.notes != null ? String(b.notes) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
