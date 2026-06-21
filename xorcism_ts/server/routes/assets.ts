/**
 * assets.ts (routes) — Asset Management inventory + governance worklist.
 * Read-only; guarded by read on XORCISM.ASSET. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { assetInventory, createAsset } from "../assets";
import { matchCves } from "../cvematch";
import * as xid from "../xid";

const router = Router();

// GET /api/asset-management — asset inventory with governance findings
router.get("/asset-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(assetInventory(tenant));
});

// POST /api/asset-management/asset — guided creation of an ASSET
router.post("/asset-management/asset", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createAsset({
      name,
      description: b.description ? String(b.description) : undefined,
      criticality: b.criticality ? String(b.criticality) : undefined,
      os: b.os ? String(b.os) : undefined,
      hostname: b.hostname ? String(b.hostname) : undefined,
      ip: b.ip ? String(b.ip) : undefined,
      environment: b.environment ? String(b.environment) : undefined,
      publicFacing: !!b.publicFacing,
      businessValue: b.businessValue ? String(b.businessValue) : undefined,
      financialValue: b.financialValue != null && String(b.financialValue) !== "" ? Number(b.financialValue) : null,
      currency: b.currency ? String(b.currency) : undefined,
      hostPii: !!b.hostPii,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      notes: b.notes ? String(b.notes) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_create", resourceType: "ASSET",
      resourceKey: String(out.id), detail: `name="${name}" criticality="${String(b.criticality || "")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cve-match/run — on-demand CVE→asset rematch over a recent window (admin).
// Links CVEs matching each asset's technologies (CPE tokens + tech tags) and notifies.
router.post("/cve-match/run", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const days = Math.min(Math.max(Number((req.body as { days?: unknown })?.days) || 30, 1), 365);
  try {
    const out = matchCves({ tenant, days });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cve_match_run", resourceType: "ASSETVULNERABILITY",
      detail: `days=${days} newLinks=${out.newLinks} assets=${out.assetsAffected}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
