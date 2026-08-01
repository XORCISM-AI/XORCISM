/**
 * cticmm.ts (routes) — CTI-CMM (Cyber Threat Intelligence Capability Maturity Model) assessment.
 * 11 domains → CTI use cases scored CTI0–CTI3, per-domain applicability, radar + gap worklist.
 * RBAC: XCOMPLIANCE.AUDIT (same as aisvs.ts / cc.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureCtiCmmTables, cticmmCatalogue, cticmmDashboard, cticmmDetail,
  createAssessment, deleteAssessment, updateAssessment, setScore, setDomainApplicable,
} from "../cticmm";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/cti-cmm", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureCtiCmmTables(); res.json(cticmmDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/cti-cmm/catalogue", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(cticmmCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/cti-cmm/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = cticmmDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/cti-cmm", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/cti-cmm/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!cticmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(cticmmDetail(id, ten(req)));
});

router.delete("/cti-cmm/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!cticmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// Score one use case CTI0–CTI3 (level "" clears).
router.post("/cti-cmm/:id/score", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!cticmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { useCaseId?: unknown; level?: unknown; notes?: unknown };
  const level = b.level === "" || b.level == null ? null : Number(b.level);
  const r = setScore(id, String(b.useCaseId ?? ""), level, b.notes != null ? String(b.notes) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(cticmmDetail(id, ten(req)));
});

// Toggle a domain in/out of scope.
router.post("/cti-cmm/:id/domain", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!cticmmDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { domainCode?: unknown; applicable?: unknown };
  const r = setDomainApplicable(id, String(b.domainCode ?? ""), !!b.applicable);
  if (!r.ok) return void res.status(400).json(r);
  res.json(cticmmDetail(id, ten(req)));
});

export default router;
