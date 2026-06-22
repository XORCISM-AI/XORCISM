/** journeys.ts (routes) — Guided compliance-journey wizard. RBAC on XCOMPLIANCE.COMPLIANCEASSESSMENT. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { journeysDashboard, getJourney, startJourney, updateStep, deleteJourney } from "../journeys";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/compliance-journeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(journeysDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/compliance-journeys/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const out = getJourney(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/compliance-journeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.framework ?? "").trim()) return void res.status(400).json({ error: "framework required" });
  try {
    const out = startJourney({
      framework: String(b.framework), name: b.name ? String(b.name) : undefined, scope: b.scope ? String(b.scope) : undefined,
      owner: b.owner ? String(b.owner) : undefined, targetDate: b.targetDate ? String(b.targetDate) : undefined, spawnAssessment: b.spawnAssessment !== false,
    }, ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "journey_start", resourceType: "COMPLIANCEJOURNEY", resourceKey: String(out.id), detail: String(b.framework), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/compliance-journeys/step/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = updateStep(Number(req.params.id), { status: b.status != null ? String(b.status) : undefined, notes: b.notes != null ? String(b.notes) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/compliance-journeys/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteJourney(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "journey_delete", resourceType: "COMPLIANCEJOURNEY", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
