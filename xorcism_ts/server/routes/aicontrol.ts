/**
 * aicontrol.ts (routes) — AI Control Library: a reusable, testable, auditable repository of AI controls
 * (objective / type / lifecycle / risk domain / owner / evidence / testing / monitoring / framework refs)
 * with coverage analytics and control-library failure-mode checks. RBAC: XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { ensureAiControlTables, aiControlLibrary, seedAiControlLibrary, createAiControl, updateAiControl, deleteAiControl,
  listAiSystems, applyControlToSystem, unapplyControl, systemCoverage, aiControlReport, aiControlReportMarkdown } from "../aicontrol";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");

router.get("/ai-control-library", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try {
    ensureAiControlTables();
    if (String(req.query.format) === "md") {
      const rep = await aiControlReport(ten(req));
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="ai-control-library-report.md"`);
      return void res.send(aiControlReportMarkdown(rep));
    }
    res.json({ ...aiControlLibrary(ten(req)), systems: listAiSystems(ten(req)), systemCoverage: systemCoverage(ten(req)) });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/ai-control-library/control/:id/apply { aiSystemId }
router.post("/ai-control-library/control/:id/apply", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.aiSystemId) return void res.status(400).json({ error: "aiSystemId required" });
  try { res.json(applyControlToSystem(ten(req), Number(req.params.id), Number(b.aiSystemId), b.status ? String(b.status) : undefined)); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// DELETE /api/ai-control-library/apply/:linkId
router.delete("/ai-control-library/apply/:linkId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(unapplyControl(Number(req.params.linkId))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ai-control-library/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = seedAiControlLibrary(ten(req));
    xid.addAudit({ userId: req.user.UserID, action: "aicontrol_seed", resourceType: "table", resourceKey: `XCOMPLIANCE.AICONTROL (+${r.created})`, ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ai-control-library/control", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.ref || !b.objective) return void res.status(400).json({ error: "ref and objective required" });
  try {
    const r = createAiControl(ten(req), b);
    xid.addAudit({ userId: req.user.UserID, action: "aicontrol_add", resourceType: "table", resourceKey: `XCOMPLIANCE.AICONTROL#${r.id}`, ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.post("/ai-control-library/control/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(updateAiControl(ten(req), Number(req.params.id), (req.body || {}) as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.delete("/ai-control-library/control/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(deleteAiControl(Number(req.params.id))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
