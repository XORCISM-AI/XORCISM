/**
 * riskregister.ts (routes) — Risk Register inventory + treatment worklist + guided create.
 * Read-only inventory + a guided "new risk" create endpoint; guarded by RBAC on
 * XCOMPLIANCE.RISKREGISTERENTRY. Generic CRUD also via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  riskRegisterInventory, createRiskRegisterEntry,
  getRiskGovernance, saveRiskStrategy, createMeasure, updateMeasure,
  entryMeasures, linkMeasure, unlinkMeasure, setLinkStatus,
  importRiskRegisterEntries, importRiskAssessments, RISK_REGISTER_IMPORT_FIELDS, RISK_ASSESSMENT_IMPORT_FIELDS,
  getTreatmentPlan, upsertTreatmentPlan, approveTreatmentPlan, addTreatmentAction, updateTreatmentAction, deleteTreatmentAction,
} from "../riskregister";
import * as xid from "../xid";

const router = Router();

// helpers shared by the governance endpoints
function tenantOf(req: Request): number | null { return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null); }
function canRead(req: Request): boolean { return userCan(req.user!, "read", "XCOMPLIANCE", "RISKREGISTERENTRY"); }
function canWrite(req: Request): boolean { return userCan(req.user!, "update", "XCOMPLIANCE", "RISKREGISTERENTRY") || userCan(req.user!, "create", "XCOMPLIANCE", "RISKREGISTERENTRY"); }

// GET /api/risk-register — risk register inventory + treatment/governance worklist
router.get("/risk-register", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(riskRegisterInventory(tenant));
});

// POST /api/risk-register/entry — guided creation of a risk-register entry
router.post("/risk-register/entry", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const title = String(b.title ?? "").trim();
  if (!title) return void res.status(400).json({ error: "title required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const numOrNull = (v: unknown): number | null => (v != null && String(v) !== "" ? Number(v) : null);
  try {
    const out = createRiskRegisterEntry({
      title,
      description: b.description ? String(b.description) : undefined,
      category: b.category ? String(b.category) : undefined,
      ref: b.ref ? String(b.ref) : undefined,
      ownerPersonId: numOrNull(b.ownerPersonId),
      assetId: numOrNull(b.assetId),
      probability: numOrNull(b.probability),
      impact: numOrNull(b.impact),
      treatment: b.treatment ? String(b.treatment) : undefined,
      status: b.status ? String(b.status) : undefined,
      reviewDate: b.reviewDate ? String(b.reviewDate) : undefined,
      targetDate: b.targetDate ? String(b.targetDate) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_register_create", resourceType: "RISKREGISTERENTRY",
      resourceKey: String(out.id), detail: `title="${title}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// ── Excel/CSV import: Risk Register entries + Risk Assessments ────────────────────
// GET …/import-fields — the logical fields a spreadsheet column can map to (drives the client UI).
router.get("/risk-register/import-fields", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json({ fields: RISK_REGISTER_IMPORT_FIELDS.map((f) => ({ key: f.key, type: f.type })) });
});
router.get("/risk-assessment/import-fields", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  res.json({ fields: RISK_ASSESSMENT_IMPORT_FIELDS.map((f) => ({ key: f.key, type: f.type })) });
});

// POST /api/risk-register/import — bulk-create/upsert RISKREGISTERENTRY from column-mapped rows.
router.post("/risk-register/import", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { rows?: unknown; upsert?: unknown };
  if (!Array.isArray(b.rows) || b.rows.length === 0) return void res.status(400).json({ error: "rows[] required" });
  if (b.rows.length > 5000) return void res.status(400).json({ error: "too many rows (max 5000 per import)" });
  const rows = b.rows.filter((r) => r && typeof r === "object") as Record<string, unknown>[];
  try {
    const out = importRiskRegisterEntries(rows, tenantOf(req), { upsert: !!b.upsert });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_register_import", resourceType: "RISKREGISTERENTRY",
      detail: `rows=${rows.length} created=${out.created} updated=${out.updated} skipped=${out.skipped} errors=${out.errors.length} upsert=${!!b.upsert}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-assessment/import — bulk-create/upsert RISKASSESSMENT from column-mapped rows.
router.post("/risk-assessment/import", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { rows?: unknown; upsert?: unknown };
  if (!Array.isArray(b.rows) || b.rows.length === 0) return void res.status(400).json({ error: "rows[] required" });
  if (b.rows.length > 5000) return void res.status(400).json({ error: "too many rows (max 5000 per import)" });
  const rows = b.rows.filter((r) => r && typeof r === "object") as Record<string, unknown>[];
  try {
    const out = importRiskAssessments(rows, tenantOf(req), { upsert: !!b.upsert });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_assessment_import", resourceType: "RISKASSESSMENT",
      detail: `rows=${rows.length} created=${out.created} updated=${out.updated} skipped=${out.skipped} errors=${out.errors.length} upsert=${!!b.upsert}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// ── Risk-management strategy / appetite / measures library ────────────────────────
// GET /api/risk-register/governance — strategy + appetite + measures library
router.get("/risk-register/governance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(getRiskGovernance(tenantOf(req)));
});

// POST /api/risk-register/strategy — upsert the strategy + replace appetite rows
router.post("/risk-register/strategy", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    saveRiskStrategy(tenantOf(req), (req.body || {}) as Record<string, never>);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_strategy_save", resourceType: "RISKSTRATEGY", resourceKey: "1", detail: "", ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/measure — create a measure in the library
router.post("/risk-register/measure", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  try {
    const out = createMeasure(tenantOf(req), {
      name, ref: b.ref ? String(b.ref) : undefined, description: b.description ? String(b.description) : undefined,
      measureType: b.measureType ? String(b.measureType) : undefined, category: b.category ? String(b.category) : undefined,
      controlRef: b.controlRef ? String(b.controlRef) : undefined, effectiveness: b.effectiveness ? String(b.effectiveness) : undefined,
      cost: b.cost ? String(b.cost) : undefined, status: b.status ? String(b.status) : undefined,
    });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/measure/update — patch a measure (status / fields)
router.post("/risk-register/measure/update", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const id = Number(b.id);
  if (!id) return void res.status(400).json({ error: "id required" });
  try { updateMeasure(tenantOf(req), id, b); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/risk-register/entry/:id/measures — measures linked to a register entry
router.get("/risk-register/entry/:id/measures", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json({ measures: entryMeasures(tenantOf(req), Number(req.params.id)) });
});

// POST /api/risk-register/entry/:id/measure — link a measure to an entry
router.post("/risk-register/entry/:id/measure", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const measureId = Number(b.measureId);
  if (!measureId) return void res.status(400).json({ error: "measureId required" });
  try { res.json({ ok: true, ...linkMeasure(tenantOf(req), Number(req.params.id), measureId, b.status ? String(b.status) : undefined) }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/link/update — set an entry↔measure link's implementation status
router.post("/risk-register/link/update", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const linkId = Number(b.linkId);
  if (!linkId) return void res.status(400).json({ error: "linkId required" });
  try { setLinkStatus(tenantOf(req), linkId, String(b.status ?? "Planned")); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/link/delete — unlink a measure from an entry
router.post("/risk-register/link/delete", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const linkId = Number((req.body || {}).linkId);
  if (!linkId) return void res.status(400).json({ error: "linkId required" });
  try { unlinkMeasure(tenantOf(req), linkId); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// ── Advanced treatment plans ──────────────────────────────────────────────────
const actorOf = (req: Request): string => req.user!.DisplayName || req.user!.Email || "user";

// GET /api/risk-register/entry/:id/treatment-plan — plan header + actions + progress rollup
router.get("/risk-register/entry/:id/treatment-plan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id); if (!id) return void res.status(400).json({ error: "entry id required" });
  try { res.json(getTreatmentPlan(tenantOf(req), id)); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/entry/:id/treatment-plan — create/update the plan header
router.post("/risk-register/entry/:id/treatment-plan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id); if (!id) return void res.status(400).json({ error: "entry id required" });
  try {
    const out = upsertTreatmentPlan(tenantOf(req), id, { ...(req.body || {}), createdBy: actorOf(req) });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_treatment_plan", resourceType: "RISKREGISTERENTRY", resourceKey: String(id), detail: `planId=${out.planId} strategy=${(req.body || {}).strategy || ""}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/entry/:id/treatment-plan/approve — record approver + date
router.post("/risk-register/entry/:id/treatment-plan/approve", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id); if (!id) return void res.status(400).json({ error: "entry id required" });
  try {
    const out = approveTreatmentPlan(tenantOf(req), id, (req.body || {}).approver || actorOf(req));
    if (!out.ok) return void res.status(404).json({ error: "no plan to approve" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_treatment_approve", resourceType: "RISKREGISTERENTRY", resourceKey: String(id), ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/risk-register/entry/:id/treatment-plan/action — add a treatment action
router.post("/risk-register/entry/:id/treatment-plan/action", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id); if (!id) return void res.status(400).json({ error: "entry id required" });
  try {
    const out = addTreatmentAction(tenantOf(req), id, { ...(req.body || {}), createdBy: actorOf(req) });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_treatment_action_add", resourceType: "RISKREGISTERENTRY", resourceKey: String(id), detail: `actionId=${out.actionId}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// PATCH /api/risk-register/treatment-action/:aid — update an action (status/progress/owner/due…)
router.patch("/risk-register/treatment-action/:aid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const aid = Number(req.params.aid); if (!aid) return void res.status(400).json({ error: "action id required" });
  try { updateTreatmentAction(tenantOf(req), aid, req.body || {}); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// DELETE /api/risk-register/treatment-action/:aid — remove an action
router.delete("/risk-register/treatment-action/:aid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const aid = Number(req.params.aid); if (!aid) return void res.status(400).json({ error: "action id required" });
  try { deleteTreatmentAction(tenantOf(req), aid); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
