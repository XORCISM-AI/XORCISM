/** soc.ts (routes) — SOC Operations cockpit. RBAC on XINCIDENT.INCIDENT. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { socDashboard, createShift, deleteShift, acknowledgeIncident, escalateIncident, attachPlaybook, completePlaybookStep, incidentPlaybook,
  listPlaybooks, createPlaybook, updatePlaybook, deletePlaybook, addPlaybookStep, deletePlaybookStep } from "../soc";
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

router.delete("/soc/shift/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const ok = deleteShift(Number(req.params.id), ten(req));
    if (!ok) return void res.status(404).json({ error: "shift not found" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_shift_delete", resourceType: "SOCSHIFT", resourceKey: String(req.params.id), detail: "", ip: clientIp(req) });
    res.json({ ok: true });
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

// ── IR playbook library management ───────────────────────────────────────────
router.get("/soc/playbooks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ playbooks: listPlaybooks(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/soc/playbook", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const steps = Array.isArray(b.steps) ? (b.steps as Record<string, unknown>[]).map((s) => ({ phase: s.phase ? String(s.phase) : undefined, title: String(s.title ?? ""), description: s.description ? String(s.description) : undefined, role: s.role ? String(s.role) : undefined })) : [];
  try {
    const out = createPlaybook({ name, category: b.category ? String(b.category) : undefined, severity: b.severity ? String(b.severity) : undefined, description: b.description ? String(b.description) : undefined, steps }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_create_playbook", resourceType: "PLAYBOOK", resourceKey: String(out.id), detail: name, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.put("/soc/playbook/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = updatePlaybook(Number(req.params.id), { name: b.name != null ? String(b.name) : undefined, category: b.category != null ? String(b.category) : undefined, severity: b.severity != null ? String(b.severity) : undefined, description: b.description != null ? String(b.description) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/soc/playbook/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const ok = deletePlaybook(id, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soc_delete_playbook", resourceType: "PLAYBOOK", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/soc/playbook/:id/step", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const title = String(b.title ?? "").trim();
  if (!title) return void res.status(400).json({ error: "title required" });
  const out = addPlaybookStep(Number(req.params.id), { phase: b.phase ? String(b.phase) : undefined, title, description: b.description ? String(b.description) : undefined, role: b.role ? String(b.role) : undefined }, ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true, ...out });
});

router.delete("/soc/playbook-step/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = deletePlaybookStep(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
