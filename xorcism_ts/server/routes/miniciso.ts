/**
 * miniciso.ts (routes) — Evidence-driven security assessment (/miniciso). Assessments, tiered
 * evidence, classified outputs (finding/observation/hypothesis/missing-evidence), the GO/RESEARCH/
 * NO-GO gate, the mandatory Security-QA gate, AI candidate suggestions and accountable synthesis.
 * RBAC: XCOMPLIANCE.AUDIT (same as cra.ts / cc.ts / smematurity.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureMcTables, mcCatalogue, mcDashboard, mcDetail, createAssessment, deleteAssessment,
  updateAssessment, addEvidence, removeEvidence, addOutput, updateOutput, removeOutput,
  setQa, synthesize, suggestOutputs, adoptSuggestions,
} from "../miniciso";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const exists = (id: number, req: Request): boolean => !!mcDetail(id, ten(req));

// GET /api/miniciso — assessments + summary
router.get("/miniciso", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureMcTables(); res.json(mcDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/miniciso/catalogue — the nine roles, stages, output classes, gates, evidence tiers
router.get("/miniciso/catalogue", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(mcCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/miniciso/:id — one assessment: evidence, outputs, delivery readiness
router.get("/miniciso/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = mcDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

// POST /api/miniciso { name, objective, scope, boundaries, operator }
router.post("/miniciso", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// PATCH /api/miniciso/:id { name?, objective?, scope?, boundaries?, operator?, stage?, status? }
router.patch("/miniciso/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(mcDetail(id, ten(req)));
});

// DELETE /api/miniciso/:id
router.delete("/miniciso/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// POST /api/miniciso/:id/evidence { title, tier, source, content }
router.post("/miniciso/:id/evidence", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  addEvidence(id, req.body as Record<string, unknown>);
  res.json(mcDetail(id, ten(req)));
});

// DELETE /api/miniciso/:id/evidence/:evId
router.delete("/miniciso/:id/evidence/:evId", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  removeEvidence(id, Number(req.params.evId));
  res.json(mcDetail(id, ten(req)));
});

// POST /api/miniciso/:id/output { role, cls, title, detail, severity, gate, confidence, residualRisk, evidenceRefs[] }
router.post("/miniciso/:id/output", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  addOutput(id, req.body as Record<string, unknown>);
  res.json(mcDetail(id, ten(req)));
});

// PATCH /api/miniciso/:id/output/:outId
router.patch("/miniciso/:id/output/:outId", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  updateOutput(id, Number(req.params.outId), req.body as Record<string, unknown>);
  res.json(mcDetail(id, ten(req)));
});

// DELETE /api/miniciso/:id/output/:outId
router.delete("/miniciso/:id/output/:outId", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  removeOutput(id, Number(req.params.outId));
  res.json(mcDetail(id, ten(req)));
});

// POST /api/miniciso/:id/output/:outId/qa { status: passed|rejected|pending, note } — the Security-QA gate
router.post("/miniciso/:id/output/:outId/qa", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { status?: unknown; note?: unknown };
  const r = setQa(id, Number(req.params.outId), String(b.status ?? ""), b.note != null ? String(b.note) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(mcDetail(id, ten(req)));
});

// POST /api/miniciso/:id/synthesize — Chief-of-Staff final synthesis (blocked if a finding is unreviewed)
router.post("/miniciso/:id/synthesize", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  const r = synthesize(id, ten(req));
  if (!r.ok && r.blocked) return void res.status(409).json({ error: "delivery blocked", ...r });
  if (!r.ok) return void res.status(400).json({ error: "synthesis failed" });
  res.json({ ...r, detail: mcDetail(id, ten(req)) });
});

// POST /api/miniciso/:id/suggest — AI candidate outputs from the evidence (Ollama or offline heuristic)
router.post("/miniciso/:id/suggest", async (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!exists(id, req)) return void res.status(404).json({ error: "assessment not found" });
  try {
    const s = await suggestOutputs(id, ten(req));
    if ((req.body as any)?.adopt) { const r = adoptSuggestions(id, s.suggestions); return void res.json({ ...s, ...r, detail: mcDetail(id, ten(req)) }); }
    res.json(s);
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

export default router;
