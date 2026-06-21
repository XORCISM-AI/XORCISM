/**
 * control53.ts (routes) — NIST SP 800-53 control management.
 * Inventory (catalogue + status + assessment + baselines + crosswalks + POA&M posture), per-control
 * detail (full text + crosswalks), set implementation/assessment, and POA&M create/update.
 * Reads gated by RBAC read on XORCISM.CONTROL; writes by update on XORCISM.CONTROLIMPLEMENTATION.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { controlManagementInventory, controlDetail, setControlImplementation, createPoam, updatePoam } from "../control53";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/control-management — full inventory + posture
router.get("/control-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "CONTROL")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(controlManagementInventory(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/control-management/control/:id — one control's text + crosswalks + implementation + POA&M
router.get("/control-management/control/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "CONTROL")) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "bad id" });
  try {
    const d = controlDetail(id, tenantOf(req));
    if (!d) return void res.status(404).json({ error: "control not found" });
    res.json(d);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/control-management/implementation — set status/responsibility/owner/narrative/target + 800-53A assessment
router.post("/control-management/implementation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "CONTROLIMPLEMENTATION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const controlId = Number(b.controlId);
  if (!Number.isInteger(controlId) || controlId <= 0) return void res.status(400).json({ error: "controlId required" });
  const num = (v: unknown): number | null | undefined => v === undefined ? undefined : (v === null || String(v) === "" ? null : Number(v));
  try {
    const out = setControlImplementation(controlId, {
      status: b.status != null ? String(b.status) : undefined,
      responsibility: b.responsibility != null ? String(b.responsibility) : undefined,
      narrative: b.narrative != null ? String(b.narrative) : undefined,
      ownerPersonId: num(b.ownerPersonId),
      targetDate: b.targetDate !== undefined ? (b.targetDate ? String(b.targetDate) : null) : undefined,
      assessmentResult: b.assessmentResult != null ? String(b.assessmentResult) : undefined,
      assessedDate: b.assessedDate !== undefined ? (b.assessedDate ? String(b.assessedDate) : null) : undefined,
      assessorPersonId: num(b.assessorPersonId),
      assessmentRemarks: b.assessmentRemarks != null ? String(b.assessmentRemarks) : undefined,
    }, tenantOf(req));
    if (!out.ok) return void res.status(404).json({ error: "control not found / implementation store unavailable" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "control_implementation", resourceType: "CONTROLIMPLEMENTATION",
      resourceKey: String(controlId), detail: `status="${String(b.status ?? "")}" assess="${String(b.assessmentResult ?? "")}"`, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/control-management/poam — create a POA&M item
router.post("/control-management/poam", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "CONTROLIMPLEMENTATION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const title = String(b.title ?? "").trim();
  if (!title) return void res.status(400).json({ error: "title required" });
  try {
    const out = createPoam({
      controlId: b.controlId != null && String(b.controlId) !== "" ? Number(b.controlId) : null,
      title, weaknessDescription: b.weaknessDescription ? String(b.weaknessDescription) : undefined,
      severity: b.severity ? String(b.severity) : undefined, status: b.status ? String(b.status) : undefined,
      remediationPlan: b.remediationPlan ? String(b.remediationPlan) : undefined,
      milestones: b.milestones ? String(b.milestones) : undefined,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      scheduledCompletionDate: b.scheduledCompletionDate ? String(b.scheduledCompletionDate) : undefined,
    }, tenantOf(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "poam_create", resourceType: "CONTROLPOAM",
      resourceKey: String(out.id), detail: `title="${title}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/control-management/poam/update — update a POA&M item (status / fields)
router.post("/control-management/poam/update", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "CONTROLIMPLEMENTATION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const poamId = Number(b.poamId);
  if (!Number.isInteger(poamId) || poamId <= 0) return void res.status(400).json({ error: "poamId required" });
  try {
    const out = updatePoam(poamId, {
      title: b.title != null ? String(b.title) : undefined,
      weaknessDescription: b.weaknessDescription != null ? String(b.weaknessDescription) : undefined,
      severity: b.severity != null ? String(b.severity) : undefined,
      status: b.status != null ? String(b.status) : undefined,
      remediationPlan: b.remediationPlan != null ? String(b.remediationPlan) : undefined,
      milestones: b.milestones != null ? String(b.milestones) : undefined,
      ownerPersonId: b.ownerPersonId !== undefined ? (b.ownerPersonId === null || String(b.ownerPersonId) === "" ? null : Number(b.ownerPersonId)) : undefined,
      scheduledCompletionDate: b.scheduledCompletionDate !== undefined ? (b.scheduledCompletionDate ? String(b.scheduledCompletionDate) : null) : undefined,
      actualCompletionDate: b.actualCompletionDate !== undefined ? (b.actualCompletionDate ? String(b.actualCompletionDate) : null) : undefined,
    }, tenantOf(req));
    if (!out.ok) return void res.status(404).json({ error: "POA&M not found / not in scope" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "poam_update", resourceType: "CONTROLPOAM",
      resourceKey: String(poamId), detail: `status="${String(b.status ?? "")}"`, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
