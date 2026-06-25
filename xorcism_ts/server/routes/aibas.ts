/** aibas.ts (routes) — LLM red-team / AI-BAS (/ai-redteam). RBAC mirrors the AI inventory
 *  (read XORCISM.ASSET); running an assessment / importing results gates on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { aibasDashboard, assessSystem, importResults, getRun, liveProbe } from "../aibas";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "ASSET");
const wr = (req: Request) => userCan(req.user, "update", "XORCISM", "ASSET");

router.get("/ai-redteam", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...aibasDashboard(ten(req)), canRun: wr(req) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/ai-redteam/run/:runId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const run = getRun(Number(req.params.runId), ten(req));
  if (!run) return void res.status(404).json({ error: "run not found" });
  res.json(run);
});

router.post("/ai-redteam/assess/:systemId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const r = assessSystem(Number(req.params.systemId), ten(req));
  if (!r) return void res.status(404).json({ error: "AI system not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "aibas_assess", resourceType: "AIBASRUN", resourceKey: String(r.runId), ip: clientIp(req) });
  res.json({ ok: true, ...r, run: getRun(r.runId, ten(req)), ...aibasDashboard(ten(req)), canRun: true });
});

router.post("/ai-redteam/live/:systemId", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = await liveProbe(Number(req.params.systemId), ten(req));
    if ("error" in r) return void res.status(400).json({ error: r.error });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "aibas_live", resourceType: "AIBASRUN", resourceKey: String(r.runId), detail: `${r.tested} live probes`, ip: clientIp(req) });
    res.json({ ok: true, ...r, run: getRun(r.runId, ten(req)), ...aibasDashboard(ten(req)), canRun: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ai-redteam/import/:systemId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  let results = (req.body as { results?: unknown })?.results;
  if (typeof results === "string") { try { results = JSON.parse(results); } catch { /* */ } }
  if (!Array.isArray(results) || !results.length) return void res.status(400).json({ error: "results[] required (garak/PyRIT/promptfoo outcomes)" });
  const r = importResults(Number(req.params.systemId), ten(req), results as any[], "import");
  if (!r) return void res.status(404).json({ error: "AI system not found or no parseable results" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "aibas_import", resourceType: "AIBASRUN", resourceKey: String(r.runId), detail: `${r.tested} results`, ip: clientIp(req) });
  res.json({ ok: true, ...r, run: getRun(r.runId, ten(req)), ...aibasDashboard(ten(req)), canRun: true });
});

export default router;
