/**
 * attackflow.ts (routes) — MITRE CTID Attack Flow cockpit. List/visualise imported adversary flows
 * (STIX 2.1 Attack Flow bundles) as ATT&CK-mapped directed graphs; import a bundle by paste or URL.
 * RBAC: XTHREAT.ATTACKTECHNIQUE (same as the other ATT&CK-facing threat cockpits).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import * as xid from "../xid";
import {
  ensureAttackFlowTables, attackFlowDashboard, attackFlowDetail, importBundle, deleteFlow, navigatorLayer,
} from "../attackflow";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XTHREAT", "ATTACKTECHNIQUE");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!can(req, act)) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

router.get("/attack-flow", (req, res) => {
  if (!auth(req, res, "read")) return;
  try { ensureAttackFlowTables(); res.json(attackFlowDashboard(ten(req))); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.get("/attack-flow/:id", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid id" });
  const d = attackFlowDetail(id, ten(req));
  if (!d) return void res.status(404).json({ error: "flow not found" });
  res.json(d);
});

// GET /api/attack-flow/:id/navigator — download an ATT&CK Navigator layer for the flow
router.get("/attack-flow/:id/navigator", (req, res) => {
  if (!auth(req, res, "read")) return;
  const id = Number(req.params.id);
  const layer = navigatorLayer(id, ten(req));
  if (!layer) return void res.status(404).json({ error: "flow not found" });
  res.setHeader("Content-Disposition", `attachment; filename="attack-flow-${id}-navigator.json"`);
  res.json(layer);
});

// POST /api/attack-flow/import — body { bundle: <STIX bundle object> } OR { url: "https://…/x.json" }
router.post("/attack-flow/import", async (req, res) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as { bundle?: unknown; url?: unknown; source?: unknown };
  try {
    let bundle = b.bundle;
    let source = b.source != null ? String(b.source) : "";
    if (!bundle && b.url) {
      const url = String(b.url);
      if (!/^https:\/\//i.test(url)) return void res.status(400).json({ error: "url must be https" });
      const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) return void res.status(400).json({ error: `fetch failed: HTTP ${r.status}` });
      bundle = await r.json();
      source = source || url;
    }
    if (!bundle || typeof bundle !== "object") return void res.status(400).json({ error: "provide a STIX bundle in `bundle` or an https `url`" });
    const out = importBundle(ten(req), bundle, source);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "attackflow_import", resourceType: "attack-flow", resourceKey: String(out.id), detail: `${out.name} (${out.actions} actions, ${out.techniques} techniques)` });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.delete("/attack-flow/:id", (req, res) => {
  if (!auth(req, res, "delete")) return;
  const id = Number(req.params.id);
  const r = deleteFlow(id, ten(req));
  if (!r.ok) return void res.status(404).json({ error: "flow not found" });
  xid.addAudit({ userId: req.user?.UserID ?? null, action: "attackflow_delete", resourceType: "attack-flow", resourceKey: String(id), detail: "" });
  res.json(r);
});

export default router;
