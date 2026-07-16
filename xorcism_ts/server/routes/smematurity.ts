/**
 * smematurity.ts (routes) — ENISA SME Cyber Resilience Maturity self-assessment (/cra-maturity).
 * Assessments, per-question scoring on the 1-5 anchored rubric, live domain/overall scores + band,
 * and the band-appropriate improvement roadmap. RBAC: XCOMPLIANCE.AUDIT (same as cra.ts / cc.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureSmeTables, smeCatalogue, smeDashboard, smeAssessmentDetail,
  createAssessment, deleteAssessment, updateAssessment, setAnswer,
} from "../smematurity";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/cra-maturity — assessments + summary + catalogue stats
router.get("/cra-maturity", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  try { ensureSmeTables(); res.json(smeDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/cra-maturity/catalogue — the full ENISA model (domains, questions, anchors, levels, bands)
router.get("/cra-maturity/catalogue", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  try { res.json(smeCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/cra-maturity/:id — one assessment: scores, RAG, answers, roadmap
router.get("/cra-maturity/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  try {
    const d = smeAssessmentDetail(id, ten(req));
    if (!d) return void res.status(404).json({ error: "assessment not found" });
    res.json(d);
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cra-maturity { name, orgName, productScope, assessor } — create an assessment
router.post("/cra-maturity", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// PATCH /api/cra-maturity/:id { name?, orgName?, productScope?, assessor?, notes?, status? }
router.patch("/cra-maturity/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!smeAssessmentDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  try {
    const r = updateAssessment(id, ten(req), req.body as Record<string, unknown>);
    res.json(smeAssessmentDetail(id, ten(req)) ?? r);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// DELETE /api/cra-maturity/:id
router.delete("/cra-maturity/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!smeAssessmentDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  try { res.json(deleteAssessment(id)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cra-maturity/:id/answer { ref, score, evidence } — score one question (score 0 clears it)
router.post("/cra-maturity/:id/answer", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!smeAssessmentDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { ref?: unknown; score?: unknown; evidence?: unknown };
  const r = setAnswer(id, String(b.ref ?? ""), Number(b.score), b.evidence != null ? String(b.evidence) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(smeAssessmentDetail(id, ten(req)));
});

export default router;
