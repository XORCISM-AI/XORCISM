/**
 * ncaEcc.ts (routes) — Saudi NCA ECC Implementation & Evidence cockpit (/nca-ecc). The 108 ECC
 * controls with the GECC 2:2024 implementation guidelines + expected deliverables; per-control
 * status, owner, evidence notes and produced-deliverable tracking; implementation % + evidence %
 * (overall + per domain). RBAC: XCOMPLIANCE.AUDIT (same as aisvs.ts / cc.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureNcaEccTables, geccCatalogue, ncaEccDashboard, ncaEccDetail,
  createAssessment, deleteAssessment, updateAssessment, setControl,
} from "../ncaEcc";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/nca-ecc", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureNcaEccTables(); res.json(ncaEccDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/nca-ecc/catalogue", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { res.json(geccCatalogue()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/nca-ecc/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = ncaEccDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "assessment not found" });
  res.json(d);
});

router.post("/nca-ecc", (req, res) => {
  if (!auth(req, res, "create")) return;
  if (!String((req.body as any)?.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createAssessment(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.patch("/nca-ecc/:id", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!ncaEccDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  updateAssessment(id, ten(req), req.body as Record<string, unknown>);
  res.json(ncaEccDetail(id, ten(req)));
});

router.delete("/nca-ecc/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!ncaEccDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  res.json(deleteAssessment(id));
});

// POST /api/nca-ecc/:id/control { ref, status, owner, evidenceNote, deliverablesDone:[] } — update one control
router.post("/nca-ecc/:id/control", (req, res) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!ncaEccDetail(id, ten(req))) return void res.status(404).json({ error: "assessment not found" });
  const b = req.body as { ref?: unknown; status?: unknown; owner?: unknown; evidenceNote?: unknown; deliverablesDone?: unknown };
  const patch: { status?: string; owner?: string; evidenceNote?: string; deliverablesDone?: number[] } = {};
  if (b.status != null) patch.status = String(b.status);
  if (b.owner != null) patch.owner = String(b.owner);
  if (b.evidenceNote != null) patch.evidenceNote = String(b.evidenceNote);
  if (Array.isArray(b.deliverablesDone)) patch.deliverablesDone = (b.deliverablesDone as unknown[]).map((x) => Number(x));
  const r = setControl(id, String(b.ref ?? ""), patch);
  if (!r.ok) return void res.status(400).json(r);
  res.json(ncaEccDetail(id, ten(req)));
});

export default router;
