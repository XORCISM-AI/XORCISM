/**
 * crisis.ts (routes) — Crisis management & tabletop-exercise readiness.
 * Read-only inventory guarded by read on XCOMPLIANCE.AUDIT; the launch action needs create.
 * CRUD stays in the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { crisisInventory, launchExercise } from "../crisis";
import * as xid from "../xid";

const router = Router();

// GET /api/crisis-management — tabletop-exercise inventory + scenario library + worklist
router.get("/crisis-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(crisisInventory(tenant));
});

// POST /api/crisis-management/launch { scenarioId, name?, date? } — schedule a tabletop exercise
// from a scenario template: create the AUDIT (AuditType='Tabletop Exercise') + copy its injects.
router.post("/crisis-management/launch", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { scenarioId?: unknown; name?: unknown; date?: unknown };
  const scenarioId = Number(b.scenarioId) || 0;
  if (!scenarioId) return void res.status(400).json({ error: "scenarioId required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = launchExercise(scenarioId, {
      name: b.name ? String(b.name) : undefined,
      date: b.date ? String(b.date) : undefined,
      tenant,
    });
    xid.addAudit({
      userId: req.user.UserID ?? null, action: "crisis_launch_exercise", resourceType: "audit",
      resourceKey: String(out.auditId), detail: `scenario=${scenarioId} (${out.scenario}) injects=${out.injects}`, ip: clientIp(req),
    });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ error: String((e as Error).message || e) });
  }
});

export default router;
