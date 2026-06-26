/**
 * incidents.ts (routes) — Incident Management inventory + governance worklist + lightweight
 * per-incident evidence attachments (CAS blob store). Read gates on XINCIDENT.INCIDENT read;
 * attaching/detaching evidence gates on update. CRUD of the incident itself is the explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { incidentInventory, listIncidentEvidence, attachIncidentEvidence, detachIncidentEvidence } from "../incidents";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XINCIDENT", "INCIDENT");
const wr = (req: Request) => userCan(req.user, "update", "XINCIDENT", "INCIDENT");

// GET /api/incident-management — incident inventory + governance findings
router.get("/incident-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(incidentInventory(ten(req)));
});

// GET /api/incident-management/incident/:id/evidence — list the files attached to an incident
router.get("/incident-management/incident/:id/evidence", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const list = listIncidentEvidence(Number(req.params.id), ten(req));
  if (list === null) return void res.status(404).json({ error: "incident not found" });
  res.json({ evidence: list, canEdit: wr(req) });
});

// POST /api/incident-management/incident/:id/evidence — attach a file (base64) to an incident
router.post("/incident-management/incident/:id/evidence", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const r = attachIncidentEvidence(Number(req.params.id), ten(req), {
    fileName: b.fileName ? String(b.fileName) : undefined,
    contentType: b.contentType ? String(b.contentType) : undefined,
    dataBase64: b.dataBase64 ? String(b.dataBase64) : undefined,
    description: b.description ? String(b.description) : undefined,
    userId: req.user.UserID ?? null, userName: String((req.user as any).Email || (req.user as any).Username || ""),
  });
  if ("error" in r) return void res.status(r.error === "incident not found" ? 404 : 400).json({ error: r.error });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "incident_evidence_attach", resourceType: "INCIDENTEVIDENCE", resourceKey: String(r.id), detail: `${r.size}B sha256:${r.sha256.slice(0, 12)}`, ip: clientIp(req) });
  res.json({ ok: true, ...r, evidence: listIncidentEvidence(Number(req.params.id), ten(req)) });
});

// DELETE /api/incident-management/evidence/:eid — detach (unlink) an evidence file
router.delete("/incident-management/evidence/:eid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const r = detachIncidentEvidence(Number(req.params.eid), ten(req));
  if (!r) return void res.status(404).json({ error: "evidence not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "incident_evidence_detach", resourceType: "INCIDENTEVIDENCE", resourceKey: String(req.params.eid), ip: clientIp(req) });
  res.json({ ok: true, evidence: listIncidentEvidence(r.incidentId, ten(req)) });
});

export default router;
