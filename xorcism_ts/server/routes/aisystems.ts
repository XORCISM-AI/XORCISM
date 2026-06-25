/** aisystems.ts (routes) — AI system inventory + AI-BOM + model-risk register (/ai-systems).
 *  RBAC: read XORCISM.ASSET (asset inventory sibling); create/component gates on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { aiSystemDashboard, getSystem, createSystem, addComponent, exportAiBom, seedAiSystemsDemo } from "../aisystems";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "ASSET");
const wr = (req: Request) => userCan(req.user, "update", "XORCISM", "ASSET");

router.get("/ai-systems", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...aiSystemDashboard(ten(req)), canEdit: wr(req) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/ai-systems/:id/aibom", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const bom = exportAiBom(Number(req.params.id), ten(req));
  if (!bom) return void res.status(404).json({ error: "not found" });
  res.setHeader("Content-Disposition", `attachment; filename="ai-bom-${Number(req.params.id)}.cdx.json"`);
  res.json(bom);
});

router.get("/ai-systems/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const s = getSystem(Number(req.params.id), ten(req));
  if (!s) return void res.status(404).json({ error: "not found" });
  res.json(s);
});

router.post("/ai-systems", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const id = createSystem(ten(req), b);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_system_create", resourceType: "AISYSTEM", resourceKey: String(id), ip: clientIp(req) });
    res.json({ ok: true, id, ...aiSystemDashboard(ten(req)), canEdit: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ai-systems/:id/component", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const id = addComponent(Number(req.params.id), ten(req), (req.body || {}) as Record<string, unknown>);
  if (id == null) return void res.status(404).json({ error: "system not found" });
  res.json({ ok: true, id, system: getSystem(Number(req.params.id), ten(req)) });
});

router.post("/ai-systems-seed-demo", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const t = ten(req);
  if (t == null) return void res.status(400).json({ error: "select a tenant (demo data is tenant-scoped)" });
  try { const n = seedAiSystemsDemo(t); res.json({ ok: true, created: n, ...aiSystemDashboard(t), canEdit: true }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
