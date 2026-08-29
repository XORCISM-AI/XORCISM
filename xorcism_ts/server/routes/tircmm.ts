/**
 * tircmm.ts (routes) — TIR-CMM (Threat-Informed Response Capability Maturity Model) assessment.
 * 8 domains → 58 sub-capabilities scored 0–5 with an evidence grade (VC0–VC3) that caps the score;
 * assessment tiers (pulse/baseline/assurance) cap the ceiling; weighted overall → band L0–L5, radar,
 * gap worklist with remediation actions, and a crosswalk to the referenced frameworks.
 * RBAC: XCOMPLIANCE.AUDIT (same as cticmm.ts / inform.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureTirCmmTables, tircmmModel, tircmmDashboard, tircmmDetail,
  createAssessment, deleteAssessment, updateAssessment, setScore,
} from "../tircmm";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/tir-cmm", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureTirCmmTables(); res.json(tircmmDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/tir-cmm/model", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(tircmmModel()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/tir-cmm/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = tircmmDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/tir-cmm", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/tir-cmm/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!tircmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(tircmmDetail(id, ten(req)));
});

router.delete("/tir-cmm/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!tircmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// Score one sub-capability: Level 0–5 (""/null clears) + Evidence grade VC0–VC3 + note.
router.post("/tir-cmm/:id/score", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!tircmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { subCapId?: unknown; level?: unknown; evidence?: unknown; notes?: unknown };
  const level = b.level === "" || b.level == null ? null : Number(b.level);
  const r = setScore(id, String(b.subCapId ?? ""), level, b.evidence != null ? String(b.evidence) : undefined, b.notes != null ? String(b.notes) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(tircmmDetail(id, ten(req)));
});

export default router;
