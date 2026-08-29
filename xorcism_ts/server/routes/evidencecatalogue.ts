/**
 * evidencecatalogue.ts (routes) — Evidence Catalogue: a central library of audit/compliance evidence.
 * List/create/update/delete evidence items, upload a file to the content-addressed store (CAS), and
 * link/unlink an item to an AUDIT. Files download via the generic /api/blob/:sha route. RBAC: XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { putBlob, ensureBlobStore } from "../blobstore";
import {
  evidenceCatalogue, createEvidenceItem, updateEvidenceItem, deleteEvidenceItem, getEvidence,
  linkEvidenceToAudit, unlinkEvidenceFromAudit, auditsForPicker, ensureEvidenceCatalogue,
} from "../evidencecatalogue";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const audit = (req: Request, action: string, key: string, detail = ""): void =>
  xid.addAudit({ userId: req.user?.UserID ?? null, action, resourceType: "evidence", resourceKey: key, detail, ip: clientIp(req) });

// GET /api/evidence-catalogue — items + KPIs + facets (+ audits for the picker)
router.get("/evidence-catalogue", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { ensureEvidenceCatalogue(); res.json({ ...evidenceCatalogue(ten(req)), audits: auditsForPicker(ten(req)) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/evidence-catalogue — create an item (metadata; optionally referencing an already-uploaded blob)
router.post("/evidence-catalogue", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  try { const it = createEvidenceItem(ten(req), req.body || {}); audit(req, "evidence_create", String(it.id), it.name); res.json({ ok: true, item: it }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/evidence-catalogue/upload — upload a file to CAS and create an evidence item in one call
router.post("/evidence-catalogue/upload", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.fileName || !b.dataBase64) return void res.status(400).json({ error: "fileName + dataBase64 required" });
  try {
    ensureBlobStore();
    const buf = Buffer.from(String(b.dataBase64), "base64");
    if (buf.length > 25 * 1024 * 1024) return void res.status(413).json({ error: "file too large (25MB max)" });
    const put = putBlob(buf, { name: String(b.fileName), contentType: b.contentType ? String(b.contentType) : undefined, pin: true });
    const it = createEvidenceItem(ten(req), { ...b, name: b.name || b.fileName, sha256: put.sha256, size: put.size, contentType: b.contentType });
    audit(req, "evidence_upload", String(it.id), `${b.fileName} ${put.size}B sha256:${put.sha256.slice(0, 12)}`);
    res.json({ ok: true, item: it, dedup: put.dedup });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// PATCH /api/evidence-catalogue/:id — edit metadata
router.patch("/evidence-catalogue/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try { const it = updateEvidenceItem(ten(req), Number(req.params.id), req.body || {}); if (!it) return void res.status(404).json({ error: "not found" }); audit(req, "evidence_update", String(req.params.id)); res.json({ ok: true, item: it }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// DELETE /api/evidence-catalogue/:id
router.delete("/evidence-catalogue/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  try { deleteEvidenceItem(ten(req), Number(req.params.id)); audit(req, "evidence_delete", String(req.params.id)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/evidence-catalogue/:id/audit { auditId, unlink? } — link/unlink to an AUDIT
router.post("/evidence-catalogue/:id/audit", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.auditId) return void res.status(400).json({ error: "auditId required" });
  try {
    if (b.unlink) unlinkEvidenceFromAudit(ten(req), Number(req.params.id), Number(b.auditId));
    else linkEvidenceToAudit(ten(req), Number(req.params.id), Number(b.auditId));
    audit(req, b.unlink ? "evidence_unlink_audit" : "evidence_link_audit", String(req.params.id), String(b.auditId));
    res.json({ ok: true, item: getEvidence(ten(req), Number(req.params.id)) });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

export default router;
