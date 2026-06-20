/**
 * tools.ts (routes) — the TOOL catalogue + GitHub-style stars.
 *   GET  /api/tools                — browse/search/filter/sort the catalogue (with star state)
 *   POST /api/tools/:id/star       — toggle the current user's star on a tool
 * Read is gated by RBAC on XORCISM.TOOL; starring is a personal action (any authenticated user
 * who can read the catalogue).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { toolCatalogue, toggleStar, ToolSort } from "../tools";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/tools — the catalogue with per-tool star count + the caller's star state
router.get("/tools", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "TOOL")) return void res.status(403).json({ error: "forbidden" });
  const sort = (["stars", "name", "recent"].includes(String(req.query.sort)) ? req.query.sort : "stars") as ToolSort;
  res.json(toolCatalogue(req.user.UserID ?? 0, tenantOf(req), {
    q: req.query.q ? String(req.query.q) : undefined,
    category: req.query.category ? String(req.query.category) : undefined,
    sort,
    starred: String(req.query.starred) === "1" || String(req.query.starred) === "true",
    limit: req.query.limit ? Number(req.query.limit) : undefined,
    offset: req.query.offset ? Number(req.query.offset) : undefined,
  }));
});

// POST /api/tools/:id/star — toggle the star (star if absent, unstar if present)
router.post("/tools/:id/star", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "TOOL")) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return void res.status(400).json({ error: "bad id" });
  try {
    const out = toggleStar(req.user.UserID ?? 0, id, tenantOf(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: out.starred ? "tool_star" : "tool_unstar",
      resourceType: "tool", resourceKey: String(id), detail: `stars=${out.starCount}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(404).json({ error: String((e as Error).message || e) }); }
});

export default router;
