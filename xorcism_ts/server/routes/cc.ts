/**
 * cc.ts (routes) — Common Criteria (ISO/IEC 15408) Security Target / TOE cockpit.
 * Targets, the EAL-driven assurance worklist, SFR selection and the EUCC / CRA Art. 27 link.
 * RBAC: XCOMPLIANCE.AUDIT (same as cra.ts).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  ensureCcTables, ccCatalogue, ccDashboard, ccTargetDetail, createTarget, deleteTarget,
  setEal, selectSfr, removeSfr, assessSar,
} from "../cc";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/common-criteria — targets + summary + catalogue stats
router.get("/common-criteria", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  try { ensureCcTables(); res.json(ccDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/common-criteria/catalogue?kind=SFR|SAR&q= — the imported CC catalogue (for the pickers)
router.get("/common-criteria/catalogue", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const kind = String(req.query.kind || "SFR").toUpperCase();
  const q = String(req.query.q || "").trim().toLowerCase();
  try {
    const cat = ccCatalogue();
    let items = kind === "SAR" ? cat.sar : cat.sfr;
    if (q) items = items.filter((i) => i.cis.toLowerCase().includes(q) || (i.name || "").toLowerCase().includes(q));
    res.json({ imported: cat.imported, classes: cat.classes.filter((c) => c.kind === kind), eals: cat.eals, items: items.slice(0, 300) });
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/common-criteria/:id — one Security Target with its SFRs, SARs and the EUCC verdict
router.get("/common-criteria/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  try {
    const d = ccTargetDetail(id, ten(req));
    if (!d) return void res.status(404).json({ error: "target not found" });
    res.json(d);
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// POST /api/common-criteria { name, toeName, ..., eal } — create a Security Target
router.post("/common-criteria", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = req.body as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try { res.json(createTarget(ten(req), b)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// DELETE /api/common-criteria/:id
router.delete("/common-criteria/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  if (!ccTargetDetail(id, ten(req))) return void res.status(404).json({ error: "target not found" });
  try { res.json(deleteTarget(id)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/common-criteria/:id/eal { eal } — set the EAL and reseed the assurance worklist
router.post("/common-criteria/:id/eal", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!ccTargetDetail(id, ten(req))) return void res.status(404).json({ error: "target not found" });
  const eal = String((req.body as { eal?: unknown }).eal ?? "").trim();
  if (!/^EAL[1-7]$/i.test(eal)) return void res.status(400).json({ error: "eal must be EAL1..EAL7" });
  try { res.json({ ...setEal(id, eal), ...ccTargetDetail(id, ten(req))! }); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/common-criteria/:id/sfr { cis, rationale }
router.post("/common-criteria/:id/sfr", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const id = Number(req.params.id);
  if (!ccTargetDetail(id, ten(req))) return void res.status(404).json({ error: "target not found" });
  const b = req.body as { cis?: unknown; rationale?: unknown };
  const r = selectSfr(id, String(b.cis ?? ""), b.rationale ? String(b.rationale) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(ccTargetDetail(id, ten(req)));
});

// DELETE /api/common-criteria/sfr/:sfrId
router.delete("/common-criteria/sfr/:sfrId", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const sid = Number(req.params.sfrId);
  if (!Number.isInteger(sid)) return void res.status(400).json({ error: "invalid id" });
  try { res.json(removeSfr(sid)); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/common-criteria/sar/:sarId { status, evidence }
router.post("/common-criteria/sar/:sarId", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const sid = Number(req.params.sarId);
  if (!Number.isInteger(sid)) return void res.status(400).json({ error: "invalid id" });
  const b = req.body as { status?: unknown; evidence?: unknown };
  const r = assessSar(sid, String(b.status ?? ""), b.evidence ? String(b.evidence) : undefined);
  if (!r.ok) return void res.status(400).json(r);
  res.json(r);
});

export default router;
