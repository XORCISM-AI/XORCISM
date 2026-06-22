/** soc.ts (routes) — SOC Operations cockpit. RBAC on XINCIDENT.INCIDENT. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { socDashboard, createShift, acknowledgeIncident, escalateIncident, attachPlaybook, completePlaybookStep, incidentPlaybook } from "../soc";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request): string => req.user!.DisplayName || req.user!.Email || String(req.user!.UserID ?? "");
const canRead = (req: Request) => userCan(req.user, "read", "XINCIDENT", "INCIDENT");
const canWrite = (req: Request) => userCan(req.user, "update", "XINCIDENT", "INCIDENT");

router.get("/soc", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(socDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/soc/incident/:id/playbook", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(incidentPlaybook(Number(req.params.id)));
});

router.post("/soc/shift", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.start || !b.end) return void res.status(400).json({ error: "start and end required" });
  try {
    const out = createShift({ personId: b.personId != null ? Number(b.personId) : undefined, personName: b.personName ? String(b.personName) : undefined,
      tier: b.tier ? String(b.tier) : undefined, start: String(b.start), end: String(b.end), onCall: !!b.onCall }, ten(req));
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/soc/incident/:id/ack", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const ok = acknowledgeIncident(id, who(req), req.user.UserID ?? null);
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_ack", resourceType: "INCIDENT", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/soc/incident/:id/escalate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const b = (req.body || {}) as Record<string, unknown>;
  const out = escalateIncident(id, { toTier: b.toTier ? String(b.toTier) : undefined, reason: b.reason ? String(b.reason) : undefined, byPerson: who(req), toPerson: b.toPerson ? String(b.toPerson) : undefined }, ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_escalate", resourceType: "INCIDENT", resourceKey: String(id), detail: `→ ${out.tier}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/soc/incident/:id/playbook", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const playbookId = Number((req.body || {}).playbookId);
  if (!Number.isFinite(playbookId)) return void res.status(400).json({ error: "playbookId required" });
  const out = attachPlaybook(id, playbookId, ten(req));
  if (!out) return void res.status(404).json({ error: "incident or playbook not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_attach_playbook", resourceType: "INCIDENT", resourceKey: String(id), detail: `playbook ${playbookId}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/soc/playbook-step/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = completePlaybookStep(Number(req.params.id), String((req.body || {}).status || "done"), who(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
