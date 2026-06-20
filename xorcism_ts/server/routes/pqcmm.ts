/**
 * pqcmm.ts (routes) — PQCMM (Post-Quantum Cryptography Maturity Model) assessment.
 * Read-only inventory + an assess endpoint. Guarded by RBAC on XCOMPLIANCE.AUDIT
 * (PQCMM is a compliance/maturity assessment). CRUD also via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { pqcmmInventory, savePqcmmAssessment, bootstrapPqcmmFromInventory } from "../pqcmm";
import * as xid from "../xid";

const router = Router();

// GET /api/pqcmm — the PQCMM model (6 levels) + assessments with quantum-readiness posture + worklist
router.get("/pqcmm", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(pqcmmInventory(tenant));
});

// POST /api/pqcmm/assess — create or update a PQCMM maturity assessment for a subject
router.post("/pqcmm/assess", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Parameters<typeof savePqcmmAssessment>[0];
  if (!b.subjectName || !String(b.subjectName).trim()) return void res.status(400).json({ error: "subjectName required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = savePqcmmAssessment(b, tenant, req.user.UserID ?? null);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "pqcmm_assess", resourceType: "pqcmm",
      resourceKey: String(out.assessmentId), detail: `subject="${b.subjectName}" level=${out.currentLevel}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/pqcmm/bootstrap — auto-seed PQCMM subjects from the asset crypto inventory (CPE):
// every asset running quantum-vulnerable crypto software becomes a Level-0 PQCMM subject (CBOM bootstrap).
router.post("/pqcmm/bootstrap", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const out = bootstrapPqcmmFromInventory(tenant, req.user.UserID ?? null);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "pqcmm_bootstrap", resourceType: "pqcmm",
    resourceKey: "inventory", detail: `created=${out.created} skipped=${out.skipped} scanned=${out.scanned}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

export default router;
