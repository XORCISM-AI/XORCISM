/**
 * trustcenter.ts (routes) — Trust Center admin config + the PUBLIC read-only posture endpoint.
 *   GET  /api/trust-center            (auth)   — current tenant's config + live posture + public URL
 *   POST /api/trust-center/config     (admin)  — update the config
 *   GET  /api/public/trust/:slug      (PUBLIC) — read-only public posture for a published slug
 * The public endpoint is auth-exempt (see requireAuthGate) and only ever returns aggregate posture.
 */
import { Router, Request, Response } from "express";
import { clientIp } from "../auth";
import { getTrustCenterConfig, setTrustCenterConfig, trustCenterPosture, publicTrustCenter, TrustConfig } from "../trustcenter";
import * as xid from "../xid";

const router = Router();

router.get("/trust-center", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const config = getTrustCenterConfig(tenant);
    res.json({ config, posture: trustCenterPosture(tenant), publicUrl: config.slug ? `/trust/${config.slug}` : null, canEdit: !!req.user.isAdmin });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/trust-center/config", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!req.user.isAdmin) return void res.status(403).json({ error: "admin required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const b = (req.body || {}) as Partial<TrustConfig>;
  try {
    const out = setTrustCenterConfig(tenant, b);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "trust_center_config", resourceType: "TRUSTCENTER",
      resourceKey: out.slug, detail: `enabled=${out.enabled} slug=${out.slug}`, ip: clientIp(req) });
    res.json({ ok: true, config: out, publicUrl: out.slug ? `/trust/${out.slug}` : null });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// PUBLIC — no auth (requireAuthGate exempts /api/public/*)
router.get("/public/trust/:slug", (req: Request, res: Response) => {
  try {
    const data = publicTrustCenter(String(req.params.slug || ""));
    if (!data) return void res.status(404).json({ error: "not found" });
    res.set("Cache-Control", "public, max-age=300");
    res.json(data);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
