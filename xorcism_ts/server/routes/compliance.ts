/**
 * compliance.ts (routes) — Compliance / GRC inventory + governance worklist + guided create.
 * Read-only inventory + a guided "new audit" create endpoint; guarded by RBAC on
 * XCOMPLIANCE.AUDIT. Generic CRUD also via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { complianceInventory, createAudit } from "../compliance";
import * as xid from "../xid";

const router = Router();

// GET /api/compliance-management — audits inventory + open-findings/policy worklist
router.get("/compliance-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(complianceInventory(tenant));
});

// POST /api/compliance-management/audit — guided creation of an AUDIT
router.post("/compliance-management/audit", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createAudit({
      name,
      type: b.type ? String(b.type) : undefined,
      category: b.category ? String(b.category) : undefined,
      status: b.status ? String(b.status) : undefined,
      auditor: b.auditor ? String(b.auditor) : undefined,
      scope: b.scope ? String(b.scope) : undefined,
      description: b.description ? String(b.description) : undefined,
      date: b.date ? String(b.date) : undefined,
      closureDate: b.closureDate ? String(b.closureDate) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "audit_create", resourceType: "AUDIT",
      resourceKey: String(out.id), detail: `name="${name}" type="${String(b.type || "")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
