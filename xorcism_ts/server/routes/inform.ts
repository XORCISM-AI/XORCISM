/**
 * inform.ts (routes) — MITRE CTID INFORM Threat-Informed Defense maturity assessment.
 * 3 weighted dimensions → components scored by achieved level; weighted overall + radar + worklist.
 * RBAC: XCOMPLIANCE.AUDIT (same as aisvs.ts / cticmm.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureInformTables, informCatalogue, informDashboard, informDetail,
  createAssessment, deleteAssessment, updateAssessment, setScore,
} from "../inform";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/inform", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureInformTables(); res.json(informDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/inform/catalogue", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(informCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/inform/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = informDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/inform", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/inform/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!informDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(informDetail(id, ten(req)));
});

router.delete("/inform/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!informDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// Set a component's achieved level (index, "" clears).
router.post("/inform/:id/score", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!informDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { componentId?: unknown; level?: unknown; notes?: unknown };
  const level = b.level === "" || b.level == null ? null : Number(b.level);
  const r = setScore(id, String(b.componentId ?? ""), level, b.notes != null ? String(b.notes) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(informDetail(id, ten(req)));
});

export default router;
