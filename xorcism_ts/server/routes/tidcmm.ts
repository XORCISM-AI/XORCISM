/**
 * tidcmm.ts (routes) — TID-CMM (Threat-Informed Detection Capability Maturity Model) assessment.
 * 8 domains → 58 sub-capabilities scored 0–5 (or NA), tier ceiling, weighted overall → band L0–L5,
 * radar and gap worklist. RBAC: XCOMPLIANCE.AUDIT (same as tircmm.ts / cticmm.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureTidCmmTables, tidcmmModel, tidcmmDashboard, tidcmmDetail,
  createAssessment, deleteAssessment, updateAssessment, setScore,
} from "../tidcmm";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/tid-cmm", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureTidCmmTables(); res.json(tidcmmDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/tid-cmm/model", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(tidcmmModel()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/tid-cmm/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = tidcmmDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/tid-cmm", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/tid-cmm/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!tidcmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(tidcmmDetail(id, ten(req)));
});

router.delete("/tid-cmm/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!tidcmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// Score one sub-capability: Level 0–5 (""/null clears), or na:true to scope it out.
router.post("/tid-cmm/:id/score", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!tidcmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { subCapId?: unknown; level?: unknown; na?: unknown; notes?: unknown };
  const level = b.level === "" || b.level == null ? null : Number(b.level);
  const r = setScore(id, String(b.subCapId ?? ""), level, b.na != null ? !!b.na : undefined, b.notes != null ? String(b.notes) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(tidcmmDetail(id, ten(req)));
});

export default router;
