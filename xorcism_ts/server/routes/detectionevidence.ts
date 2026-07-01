/**
 * detectionevidence.ts (routes) — the proof behind a detection: list/attach/remove the intel,
 * PoC, logs/PCAP, AI prompt and references that show a Sigma/YARA rule does what it claims, plus
 * a provenance-completeness summary. Files go to the CAS. RBAC on XTHREAT.SIGMARULE; writes audited.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { listEvidence, addEvidence, addFileEvidence, readEvidenceFile, removeEvidence, detectionPickList } from "../detectionevidence";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request) => ({ id: req.user!.UserID ?? null, name: String(req.user!.DisplayName || req.user!.Email || "") });
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XTHREAT", "SIGMARULE")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "detection-evidence", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/detection-evidence/detections — Sigma+YARA rules to attach proof to + coverage summary
router.get("/detection-evidence/detections", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(detectionPickList(tenantOf(req)));
});

// GET /api/detection-evidence?type=sigma&id=123 — a detection's evidence + provenance summary
router.get("/detection-evidence", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const type = String(req.query.type || ""), id = Number(req.query.id);
  if (!type || !Number.isInteger(id)) return void res.status(400).json({ error: "type + id required" });
  res.json(listEvidence(type, id, tenantOf(req)));
});

// POST /api/detection-evidence { type, id, evidenceType, title, content?, url?, source?, verdict? }
router.post("/detection-evidence", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = req.body || {};
  const out = addEvidence(String(b.type || ""), Number(b.id), tenantOf(req), b, who(req));
  if ("error" in out) return void res.status(400).json(out);
  audit(req, "detection_evidence_add", `${b.type}:${b.id}`, `${b.evidenceType}`);
  res.json({ ok: true, ...out });
});

// POST /api/detection-evidence/upload { type, id, evidenceType, fileName, contentType, dataBase64, title?, source? }
router.post("/detection-evidence/upload", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = req.body || {};
  const out = addFileEvidence(String(b.type || ""), Number(b.id), tenantOf(req), b, who(req));
  if ("error" in out) return void res.status(400).json(out);
  audit(req, "detection_evidence_upload", `${b.type}:${b.id}`, `${b.evidenceType} ${out.size}B sha256:${out.sha256.slice(0, 12)}`);
  res.json({ ok: true, ...out });
});

// GET /api/detection-evidence/:eid/download — stream a file evidence item from the CAS
router.get("/detection-evidence/:eid/download", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const f = readEvidenceFile(Number(req.params.eid), tenantOf(req));
  if (!f) return void res.status(404).json({ error: "not found" });
  res.setHeader("Content-Type", f.ct);
  res.setHeader("Content-Disposition", `attachment; filename="${f.name.replace(/[^\w.\-]/g, "_")}"`);
  res.send(f.buf);
});

// DELETE /api/detection-evidence/:eid
router.delete("/detection-evidence/:eid", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  const out = removeEvidence(Number(req.params.eid), tenantOf(req));
  if (!out.ok) return void res.status(404).json(out);
  audit(req, "detection_evidence_remove", String(req.params.eid));
  res.json(out);
});

export default router;
