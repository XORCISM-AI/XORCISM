/**
 * aisvs.ts (routes) — OWASP AISVS verification assessment (/aisvs). Target-level scoping, the AISVS
 * maturity answers with evidence, weighted verification scoring per part + overall, and the gaps /
 * EU-AI-Act coverage. RBAC: XCOMPLIANCE.AUDIT (same as cra.ts / smematurity.ts / miniciso.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureAisvsTables, aisvsCatalogue, aisvsDashboard, aisvsDetail,
  createAssessment, deleteAssessment, updateAssessment, setAnswer,
} from "../aisvs";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/aisvs", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureAisvsTables(); res.json(aisvsDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/aisvs/catalogue", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(aisvsCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/aisvs/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = aisvsDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/aisvs", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/aisvs/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!aisvsDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(aisvsDetail(id, ten(req)));
});

router.delete("/aisvs/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!aisvsDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// POST /api/aisvs/:id/answer { ref, answer, evidence } — score one control (answer "" clears it)
router.post("/aisvs/:id/answer", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!aisvsDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { ref?: unknown; answer?: unknown; evidence?: unknown };
  const r = setAnswer(id, String(b.ref ?? ""), String(b.answer ?? ""), b.evidence != null ? String(b.evidence) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(aisvsDetail(id, ten(req)));
});

export default router;
