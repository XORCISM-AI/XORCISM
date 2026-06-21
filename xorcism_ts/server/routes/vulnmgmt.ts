/**
 * vulnmgmt.ts (routes) — Vulnerability Management: read inventory + two write actions
 * (track a CVE against an asset, set a disposition across instances). Guarded by RBAC on
 * XORCISM.ASSETVULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { vulnInventory, trackVulnerability, setVulnDisposition, assetPickList } from "../vulnmgmt";
import * as xid from "../xid";

const router = Router();
const DISPOSITIONS = ["false-positive", "accept-risk", "reopen"] as const;

// GET /api/vulnerability-management — vulnerability-centric inventory + triage worklist + KPIs
router.get("/vulnerability-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json({ ...vulnInventory(tenant), assets: assetPickList(tenant) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/vulnerability-management/track — link a CVE to an asset (guided create)
router.post("/vulnerability-management/track", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const cve = String(b.cve ?? "").trim();
  const assetId = Number(b.assetId);
  if (!cve) return void res.status(400).json({ error: "cve required" });
  if (!Number.isInteger(assetId) || assetId <= 0) return void res.status(400).json({ error: "assetId required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = trackVulnerability({
      cve, assetId,
      targetDate: b.targetDate ? String(b.targetDate) : undefined,
      priority: b.priority ? String(b.priority) : undefined,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "vuln_track", resourceType: "ASSETVULNERABILITY",
      resourceKey: String(out.id), detail: `cve=${out.cve} asset=${assetId}${out.existed ? " (existed)" : ""}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/vulnerability-management/disposition — false-positive / accept-risk / reopen a vuln
router.post("/vulnerability-management/disposition", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const vulnerabilityId = Number(b.vulnerabilityId);
  const disposition = String(b.disposition ?? "") as (typeof DISPOSITIONS)[number];
  if (!Number.isInteger(vulnerabilityId) || vulnerabilityId <= 0) return void res.status(400).json({ error: "vulnerabilityId required" });
  if (!DISPOSITIONS.includes(disposition)) return void res.status(400).json({ error: "invalid disposition" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = setVulnDisposition({ vulnerabilityId, disposition }, tenant);
    if (!out.ok) return void res.status(404).json({ error: "vulnerability not found / not in scope" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "vuln_disposition", resourceType: "ASSETVULNERABILITY",
      resourceKey: String(vulnerabilityId), detail: `disposition=${disposition} affected=${out.affected}`, ip: clientIp(req) });
    res.json(out);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
