/** aiskills.ts (routes) — AI Operations: Skills/Prompt Library + AI activity log + agent handover
 *  routing (/ai-skills). Read gates on XORCISM.ASSET read; editing the library / routing gates on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { aiSkillsDashboard, getSkill, upsertSkill, toggleSkill, useSkill, addHandover, deleteHandover } from "../aiskills";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "ASSET");
const wr = (req: Request) => userCan(req.user, "update", "XORCISM", "ASSET");

router.get("/ai-skills", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...aiSkillsDashboard(ten(req)), canRun: wr(req) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/ai-skills/skill/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const s = getSkill(Number(req.params.id), ten(req));
  if (!s) return void res.status(404).json({ error: "skill not found" });
  res.json(s);
});

router.post("/ai-skills/skill", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const r = upsertSkill(ten(req), req.body || {});
  if (!r.id) return void res.status(404).json({ error: "skill not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "aiskill_upsert", resourceType: "AISKILL", resourceKey: String(r.id), ip: clientIp(req) });
  res.json({ ok: true, ...r, ...aiSkillsDashboard(ten(req)), canRun: true });
});

router.post("/ai-skills/skill/:id/toggle", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = toggleSkill(Number(req.params.id), ten(req), !!(req.body || {}).enabled);
  if (!ok) return void res.status(404).json({ error: "skill not found" });
  res.json({ ok: true, ...aiSkillsDashboard(ten(req)), canRun: true });
});

router.post("/ai-skills/skill/:id/use", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const r = useSkill(Number(req.params.id), ten(req), String((req.body || {}).by || "user"));
  if (!r.ok) return void res.status(404).json({ error: "skill not found" });
  res.json({ ok: true, ...aiSkillsDashboard(ten(req)), canRun: true });
});

router.post("/ai-skills/handover", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const r = addHandover(ten(req), req.body || {});
  if (!r) return void res.status(400).json({ error: "from and to are required" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "aihandover_add", resourceType: "AIHANDOVER", resourceKey: String(r.id), ip: clientIp(req) });
  res.json({ ok: true, ...r, ...aiSkillsDashboard(ten(req)), canRun: true });
});

router.delete("/ai-skills/handover/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteHandover(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "route not found (default routes are read-only)" });
  res.json({ ok: true, ...aiSkillsDashboard(ten(req)), canRun: true });
});

export default router;
