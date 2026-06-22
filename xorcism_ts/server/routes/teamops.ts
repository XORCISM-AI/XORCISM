/** teamops.ts (routes) — Purple/Red/Blue Team Operations. RBAC on XTHREAT.THREAT. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { teamOpsDashboard, exerciseDetail, createExercise, addTestCase, setOutcome, createCapability } from "../teamops";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XTHREAT", "THREAT");
const wr = (req: Request) => userCan(req.user, "update", "XTHREAT", "THREAT");

router.get("/team-ops", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(teamOpsDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/team-ops/exercise/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const out = exerciseDetail(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/team-ops/exercise", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  const out = createExercise({ name: String(b.name), type: b.type ? String(b.type) : undefined, objective: b.objective ? String(b.objective) : undefined, actor: b.actor ? String(b.actor) : undefined, startDate: b.startDate ? String(b.startDate) : undefined }, ten(req));
  xid.addAudit({ userId: req.user.UserID ?? null, action: "teamops_exercise", resourceType: "TEAMEXERCISE", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/team-ops/exercise/:id/testcase", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.technique ?? "").trim()) return void res.status(400).json({ error: "technique required" });
  const out = addTestCase(Number(req.params.id), { attackId: b.attackId ? String(b.attackId) : undefined, technique: String(b.technique), tactic: b.tactic ? String(b.tactic) : undefined, offensiveAction: b.offensiveAction ? String(b.offensiveAction) : undefined, offensiveTool: b.offensiveTool ? String(b.offensiveTool) : undefined, expectedDefense: b.expectedDefense ? String(b.expectedDefense) : undefined }, ten(req));
  if (!out) return void res.status(404).json({ error: "exercise not found" });
  res.json({ ok: true, ...out });
});

router.post("/team-ops/testcase/:id/outcome", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setOutcome(Number(req.params.id), { outcome: b.outcome ? String(b.outcome) : undefined, detectionTimeMin: b.detectionTimeMin != null ? Number(b.detectionTimeMin) : undefined, detectionSource: b.detectionSource != null ? String(b.detectionSource) : undefined, responseAction: b.responseAction != null ? String(b.responseAction) : undefined, notes: b.notes != null ? String(b.notes) : undefined });
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/team-ops/capability", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  const out = createCapability({ team: b.team ? String(b.team) : "Purple", name: String(b.name), category: b.category ? String(b.category) : undefined, maturity: b.maturity != null ? Number(b.maturity) : undefined, capacity: b.capacity ? String(b.capacity) : undefined, tooling: b.tooling ? String(b.tooling) : undefined }, ten(req));
  res.json({ ok: true, ...out });
});

export default router;
