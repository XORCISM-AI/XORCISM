/**
 * fairmam.ts (routes) — FAIR-MAM materiality assessment. Read-only inventory + a live
 * calculator (compute without persisting) + a persist endpoint. Guarded by RBAC on
 * XCOMPLIANCE.RISKREGISTERENTRY (FAIR-MAM is the loss-magnitude breakdown of the CRQ/FAIR risk).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { fairMamInventory, computeFairMam, saveFairMamAssessment, LineInput } from "../fairmam";
import * as xid from "../xid";

const router = Router();

// GET /api/fair-mam — the taxonomy + saved assessments with computed totals + materiality
router.get("/fair-mam", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(fairMamInventory(tenant));
});

// POST /api/fair-mam/compute { lines, threshold } — live calculator (no persistence)
router.post("/fair-mam/compute", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { lines?: LineInput[]; threshold?: unknown };
  const threshold = b.threshold != null && Number.isFinite(Number(b.threshold)) ? Number(b.threshold) : null;
  res.json(computeFairMam(Array.isArray(b.lines) ? b.lines : [], threshold));
});

// POST /api/fair-mam/assess — persist an assessment + its line items, return the computed result
router.post("/fair-mam/assess", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Parameters<typeof saveFairMamAssessment>[0];
  if (!Array.isArray(b.lines) || !b.lines.length) return void res.status(400).json({ error: "at least one loss line item required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = saveFairMamAssessment(b, tenant, req.user.UserID ?? null);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "fairmam_assess", resourceType: "fairmam",
      resourceKey: String(out.assessmentId), detail: `total=${out.total} ${out.determination}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
