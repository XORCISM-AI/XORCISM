/**
 * otsecurity.ts (routes) — OT / ICS / SCADA / IoT Security (IEC 62443 / NIST SP 800-82).
 * Read-only inventory over AUDIT (OT assessments) + a guided "new OT assessment" create endpoint,
 * guarded by RBAC on XCOMPLIANCE.AUDIT. Generic CRUD stays in the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { otSecurityInventory, createOtAssessment } from "../otsecurity";
import * as xid from "../xid";

const router = Router();

// GET /api/ot-security — OT assessments inventory + OT assets + zones + catalogue coverage
router.get("/ot-security", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(otSecurityInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/ot-security/assessment — guided creation of an OT security AUDIT
router.post("/ot-security/assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createOtAssessment({
      name,
      standard: b.standard ? String(b.standard) : undefined,
      status: b.status ? String(b.status) : undefined,
      auditor: b.auditor ? String(b.auditor) : undefined,
      scope: b.scope ? String(b.scope) : undefined,
      description: b.description ? String(b.description) : undefined,
      date: b.date ? String(b.date) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ot_assessment_create", resourceType: "AUDIT",
      resourceKey: String(out.id), detail: `name="${name}" standard="${String(b.standard || "IEC 62443-3-3")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
