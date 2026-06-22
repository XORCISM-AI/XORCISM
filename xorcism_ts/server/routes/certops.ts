/** certops.ts (routes) — CERT/CSIRT operations: forensic cases + chain of custody. RBAC XINCIDENT.INCIDENT. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { certInventory, caseDetail, createCase, addEvidence, addCustody, createActivity } from "../certops";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XINCIDENT", "INCIDENT");
const wr = (req: Request) => userCan(req.user, "update", "XINCIDENT", "INCIDENT");

router.get("/cert-ops", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(certInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/cert-ops/case/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const out = caseDetail(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/cert-ops/case", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  const out = createCase({ title: String(b.title), incidentId: b.incidentId != null ? Number(b.incidentId) : undefined, severity: b.severity ? String(b.severity) : undefined, examiner: b.examiner ? String(b.examiner) : undefined, description: b.description ? String(b.description) : undefined, methodology: b.methodology ? String(b.methodology) : undefined }, ten(req));
  xid.addAudit({ userId: req.user.UserID ?? null, action: "cert_case_create", resourceType: "FORENSICCASE", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/cert-ops/case/:id/evidence", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.description ?? "").trim()) return void res.status(400).json({ error: "description required" });
  const out = addEvidence(Number(req.params.id), { description: String(b.description), type: b.type ? String(b.type) : undefined, source: b.source ? String(b.source) : undefined, tool: b.tool ? String(b.tool) : undefined, sha256: b.sha256 ? String(b.sha256) : undefined, size: b.size ? String(b.size) : undefined, collectedBy: b.collectedBy ? String(b.collectedBy) : undefined, storage: b.storage ? String(b.storage) : undefined }, ten(req));
  if (!out) return void res.status(404).json({ error: "case not found" });
  res.json({ ok: true, ...out });
});

router.post("/cert-ops/evidence/:id/custody", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.action ?? "").trim()) return void res.status(400).json({ error: "action required" });
  const out = addCustody(Number(req.params.id), { action: String(b.action), from: b.from ? String(b.from) : undefined, to: b.to ? String(b.to) : undefined, purpose: b.purpose ? String(b.purpose) : undefined, hash: b.hash ? String(b.hash) : undefined, verified: b.verified != null ? !!b.verified : undefined }, ten(req));
  if (!out) return void res.status(404).json({ error: "evidence not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "cert_custody", resourceType: "CUSTODYEVENT", resourceKey: String(out.id), detail: String(b.action), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/cert-ops/activity", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  const out = createActivity({ title: String(b.title), type: b.type ? String(b.type) : undefined, service: b.service ? String(b.service) : undefined, priority: b.priority ? String(b.priority) : undefined, assignedTo: b.assignedTo ? String(b.assignedTo) : undefined, incidentId: b.incidentId != null ? Number(b.incidentId) : undefined, description: b.description ? String(b.description) : undefined, dueDate: b.dueDate ? String(b.dueDate) : undefined }, ten(req));
  res.json({ ok: true, ...out });
});

export default router;
