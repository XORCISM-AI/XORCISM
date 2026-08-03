/**
 * airiskloop.ts (routes) — Operational AI Risk Management loop (IDENTIFY -> ASSESS -> MITIGATE -> MONITOR).
 * Read the loop (risks + controls + KRIs + log + analytics), CRUD risks, link/score controls (design vs
 * operating effectiveness + evidence), manage KRIs (thresholds + current value), and record monitoring
 * findings that feed back and close the loop. Markdown export. Guarded by RBAC on XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import {
  aiRiskLoop, getRisk, createRisk, updateRisk, deleteRisk, linkControl, updateControlLink, unlinkControl,
  addKri, updateKri, deleteKri, addLoopEvent, loopMarkdown, ensureAiRiskTables, seedAiRiskDemo,
  attachEvidence, deleteEvidence,
} from "../airiskloop";
import { putBlob, ensureBlobStore } from "../blobstore";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const N = (v: unknown): number | undefined => (v === undefined || v === null || v === "" ? undefined : Number(v));
const S = (v: unknown): string | undefined => (v === undefined || v === null ? undefined : String(v));
function guard(req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XCOMPLIANCE", "AUDIT")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
}
const audit = (req: Request, action: string, key: string, detail = ""): void =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "ai-risk-loop", resourceKey: key, detail, ip: clientIp(req) });

// GET /api/ai-risk-loop[?format=md] — the full loop + analytics (or markdown export)
router.get("/ai-risk-loop", (req: Request, res: Response) => {
  if (!guard(req, res, "read")) return;
  try {
    ensureAiRiskTables();
    if (String(req.query.format) === "md") {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="ai-risk-loop.md"`);
      return void res.send(loopMarkdown(ten(req)));
    }
    res.json(aiRiskLoop(ten(req)));
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/ai-risk-loop/:id — one risk's full traceability chain
router.get("/ai-risk-loop/:id", (req: Request, res: Response) => {
  if (!guard(req, res, "read")) return;
  const r = getRisk(ten(req), Number(req.params.id));
  if (!r) return void res.status(404).json({ error: "unknown risk" });
  res.json(r);
});

function riskPatch(b: Record<string, unknown>) {
  return {
    aiSystemId: b.aiSystemId !== undefined ? (b.aiSystemId === null || b.aiSystemId === "" ? null : Number(b.aiSystemId)) : undefined,
    title: S(b.title), riskArea: S(b.riskArea), description: S(b.description),
    context: b.context !== undefined ? (b.context as Record<string, unknown>) : undefined,
    lifecyclePhase: S(b.lifecyclePhase), owner: S(b.owner), stage: S(b.stage), status: S(b.status),
    inherentLikelihood: N(b.inherentLikelihood), inherentImpact: N(b.inherentImpact),
    residualLikelihood: N(b.residualLikelihood), residualImpact: N(b.residualImpact),
    factors: b.factors !== undefined ? (b.factors as Record<string, unknown>) : undefined,
    treatment: S(b.treatment), acceptanceBy: S(b.acceptanceBy), acceptanceDate: S(b.acceptanceDate), acceptanceRationale: S(b.acceptanceRationale),
  };
}

// POST /api/ai-risk-loop — create (IDENTIFY)
router.post("/ai-risk-loop", (req: Request, res: Response) => {
  if (!guard(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.title) return void res.status(400).json({ error: "title required" });
  try { const r = createRisk(ten(req), riskPatch(b)); audit(req, "ai_risk_create", String(r.riskId), r.title); res.json({ ok: true, risk: r }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// PATCH /api/ai-risk-loop/:id — update (ASSESS / MITIGATE decision / stage / owner / accept residual)
router.patch("/ai-risk-loop/:id", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  try { const r = updateRisk(ten(req), Number(req.params.id), riskPatch((req.body || {}) as Record<string, unknown>)); audit(req, "ai_risk_update", String(r.riskId)); res.json({ ok: true, risk: r }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// DELETE /api/ai-risk-loop/:id
router.delete("/ai-risk-loop/:id", (req: Request, res: Response) => {
  if (!guard(req, res, "delete")) return;
  try { deleteRisk(ten(req), Number(req.params.id)); audit(req, "ai_risk_delete", String(req.params.id)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// MITIGATE — link a control to a risk
router.post("/ai-risk-loop/:id/control", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  try { const r = linkControl(ten(req), Number(req.params.id), { controlRef: S(b.controlRef), controlName: S(b.controlName), controlOwner: S(b.controlOwner) }); audit(req, "ai_risk_link_control", String(req.params.id), S(b.controlRef) || ""); res.json({ ok: true, risk: r }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});
// set control design/operating effectiveness + evidence
router.patch("/ai-risk-loop/control/:linkId", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  try { updateControlLink(ten(req), Number(req.params.linkId), { designEffective: S(b.designEffective), operatingEffective: S(b.operatingEffective), evidenceRef: S(b.evidenceRef), notes: S(b.notes) }); audit(req, "ai_risk_control_effectiveness", String(req.params.linkId)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});
router.delete("/ai-risk-loop/control/:linkId", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  try { unlinkControl(ten(req), Number(req.params.linkId)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// MONITOR — KRIs
router.post("/ai-risk-loop/:id/kri", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  try { const r = addKri(ten(req), Number(req.params.id), { name: S(b.name), metric: S(b.metric), threshold: N(b.threshold), direction: S(b.direction), action: S(b.action) }); audit(req, "ai_risk_add_kri", String(req.params.id)); res.json({ ok: true, risk: r }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});
router.patch("/ai-risk-loop/kri/:kriId", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  try { updateKri(ten(req), Number(req.params.kriId), { currentValue: b.currentValue !== undefined ? (b.currentValue === null || b.currentValue === "" ? null : Number(b.currentValue)) : undefined, threshold: N(b.threshold), direction: S(b.direction), action: S(b.action), name: S(b.name), metric: S(b.metric) }); audit(req, "ai_risk_update_kri", String(req.params.kriId)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});
router.delete("/ai-risk-loop/kri/:kriId", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  try { deleteKri(ten(req), Number(req.params.kriId)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// MONITOR — record a finding that feeds back (closes the loop)
router.post("/ai-risk-loop/:id/event", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  try { const r = addLoopEvent(ten(req), Number(req.params.id), S(b.kind) || "", S(b.detail) || "", b.reopen === true); audit(req, "ai_risk_loop_event", String(req.params.id), S(b.kind) || ""); res.json({ ok: true, risk: r }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// EVIDENCE — attach a control/monitoring evidence file to the content-addressed store (CAS)
router.post("/ai-risk-loop/:id/evidence/upload", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.fileName || !b.dataBase64) return void res.status(400).json({ error: "fileName + dataBase64 required" });
  try {
    ensureBlobStore();
    const buf = Buffer.from(String(b.dataBase64), "base64");
    if (buf.length > 25 * 1024 * 1024) return void res.status(413).json({ error: "file too large (25MB max)" });
    const put = putBlob(buf, { name: String(b.fileName), contentType: b.contentType ? String(b.contentType) : undefined, pin: true });
    const r = attachEvidence(ten(req), Number(req.params.id), { sha256: put.sha256, filename: String(b.fileName), size: put.size, contentType: b.contentType ? String(b.contentType) : undefined, title: S(b.title), linkId: N(b.linkId) });
    audit(req, "ai_risk_evidence_upload", String(req.params.id), `${b.fileName} ${put.size}B sha256:${put.sha256.slice(0, 12)}`);
    res.json({ ok: true, risk: r, sha256: put.sha256, dedup: put.dedup });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});
router.delete("/ai-risk-loop/evidence/:evId", (req: Request, res: Response) => {
  if (!guard(req, res, "update")) return;
  try { deleteEvidence(ten(req), Number(req.params.evId)); audit(req, "ai_risk_evidence_delete", String(req.params.evId)); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/ai-risk-loop/seed — demo (idempotent)
router.post("/ai-risk-loop/seed", (req: Request, res: Response) => {
  if (!guard(req, res, "create")) return;
  const tenant = req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1);
  try { seedAiRiskDemo(tenant); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

export default router;
