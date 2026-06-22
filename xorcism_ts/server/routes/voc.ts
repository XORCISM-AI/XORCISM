/** voc.ts (routes) — Vulnerability Operations Center. RBAC: read XVULNERABILITY.VULNERABILITY,
 * write actions on XORCISM.ASSETVULNERABILITY. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { vocDashboard, setSlaTier, createCampaign, createException, assignInstance, remediateInstance } from "../voc";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY");
const wrVuln = (req: Request) => userCan(req.user, "update", "XVULNERABILITY", "VULNERABILITY");
const wrAv = (req: Request) => userCan(req.user, "update", "XORCISM", "ASSETVULNERABILITY");

router.get("/voc", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(vocDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/voc/sla", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wrVuln(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.tier || b.days == null) return void res.status(400).json({ error: "tier and days required" });
  setSlaTier(String(b.tier), Number(b.days), ten(req));
  res.json({ ok: true });
});

router.post("/voc/campaign", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wrVuln(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  const out = createCampaign({ name: String(b.name), scope: b.scope ? String(b.scope) : undefined, targetDate: b.targetDate ? String(b.targetDate) : undefined, description: b.description ? String(b.description) : undefined }, ten(req));
  res.json({ ok: true, ...out });
});

router.post("/voc/exception", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wrVuln(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  const out = createException({ title: String(b.title), vulnerabilityId: b.vulnerabilityId != null ? Number(b.vulnerabilityId) : undefined, assetVulnerabilityId: b.assetVulnerabilityId != null ? Number(b.assetVulnerabilityId) : undefined, scope: b.scope ? String(b.scope) : undefined, justification: b.justification ? String(b.justification) : undefined, compensating: b.compensating ? String(b.compensating) : undefined, approvedBy: b.approvedBy ? String(b.approvedBy) : undefined, expiryDate: b.expiryDate ? String(b.expiryDate) : undefined }, ten(req));
  xid.addAudit({ userId: req.user.UserID ?? null, action: "voc_exception", resourceType: "VOCEXCEPTION", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/voc/instance/:id/assign", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wrAv(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = assignInstance(Number(req.params.id), { ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined, targetDate: b.targetDate != null ? String(b.targetDate) : undefined, priority: b.priority != null ? String(b.priority) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/voc/instance/:id/remediate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wrAv(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = remediateInstance(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "voc_remediate", resourceType: "ASSETVULNERABILITY", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
