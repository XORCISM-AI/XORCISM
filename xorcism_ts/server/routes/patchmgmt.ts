/**
 * patchmgmt.ts (routes) — Patch Management: read inventory + two write actions (mark patch status,
 * create a remediation plan). Guarded by RBAC on XORCISM.ASSETVULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { patchInventory, updatePatchStatus, createRemediation, PATCH_STATUSES } from "../patchmgmt";
import * as xid from "../xid";

const router = Router();

// GET /api/patch-management — asset↔vuln patch inventory + SLA/MTTR/coverage worklist
router.get("/patch-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json({ statuses: PATCH_STATUSES, ...patchInventory(tenant) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/patch-management/status — set the patch status of one asset↔vuln instance
router.post("/patch-management/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const id = Number(b.assetVulnId);
  const status = String(b.status ?? "").trim();
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "assetVulnId required" });
  if (!status) return void res.status(400).json({ error: "status required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = updatePatchStatus(id, status, tenant);
    if (!out.ok) return void res.status(404).json({ error: "asset-vuln not found / not in scope" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "patch_status_update", resourceType: "ASSETVULNERABILITY",
      resourceKey: String(id), detail: `status="${status}"`, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/patch-management/remediation — create a remediation plan for an asset↔vuln instance
router.post("/patch-management/remediation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const assetVulnId = Number(b.assetVulnId);
  const name = String(b.name ?? "").trim();
  if (!Number.isInteger(assetVulnId) || assetVulnId <= 0) return void res.status(400).json({ error: "assetVulnId required" });
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createRemediation({
      assetVulnId, name,
      description: b.description ? String(b.description) : undefined,
      type: b.type ? String(b.type) : undefined,
      status: b.status ? String(b.status) : undefined,
      targetDate: b.targetDate ? String(b.targetDate) : undefined,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      priority: b.priority ? String(b.priority) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "remediation_create", resourceType: "ASSETVULNERABILITYREMEDIATION",
      resourceKey: String(out.id), detail: `assetVuln=${assetVulnId} name="${name}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
