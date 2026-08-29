/**
 * complianceactivities.ts (routes) — Compliance Activity Calendar & Reminders. List the calendar +
 * activities + KPIs, CRUD an activity, mark an occurrence complete (advances the recurring due date),
 * and run the reminder engine on demand. RBAC: XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import {
  complianceCalendar, createActivity, updateActivity, deleteActivity, completeActivity,
  runComplianceReminders, ensureComplianceActivities,
} from "../complianceactivities";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const audit = (req: Request, action: string, key: string, detail = ""): void =>
  xid.addAudit({ userId: req.user?.UserID ?? null, action, resourceType: "compliance-activity", resourceKey: key, detail, ip: clientIp(req) });

router.get("/compliance-calendar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { ensureComplianceActivities(); res.json(complianceCalendar(ten(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/compliance-calendar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  try { const a = createActivity(ten(req), req.body || {}); audit(req, "activity_create", String(a.activityId), a.name); res.json({ ok: true, activity: a }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.patch("/compliance-calendar/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try { const a = updateActivity(ten(req), Number(req.params.id), req.body || {}); if (!a) return void res.status(404).json({ error: "not found" }); audit(req, "activity_update", String(req.params.id)); res.json({ ok: true, activity: a }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.delete("/compliance-calendar/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  try { deleteActivity(ten(req), Number(req.params.id)); audit(req, "activity_delete", String(req.params.id)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/compliance-calendar/:id/complete — mark done + advance the recurring due date
router.post("/compliance-calendar/:id/complete", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  try {
    const a = completeActivity(ten(req), Number(req.params.id), {
      completedDate: b.completedDate != null ? String(b.completedDate) : undefined,
      completedBy: b.completedBy != null ? String(b.completedBy) : (req.user.DisplayName || req.user.Email || undefined),
      notes: b.notes != null ? String(b.notes) : undefined,
      evidenceId: b.evidenceId != null && String(b.evidenceId) !== "" ? Number(b.evidenceId) : undefined,
    });
    audit(req, "activity_complete", String(req.params.id), a.nextDueDate ? `next ${a.nextDueDate}` : "closed");
    res.json({ ok: true, activity: a });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/compliance-calendar/run-reminders — fire the reminder engine now (admin/manual)
router.post("/compliance-calendar/run-reminders", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try { const r = runComplianceReminders(); audit(req, "activity_run_reminders", "-", `${r.reminded}/${r.checked}`); res.json({ ok: true, ...r }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
