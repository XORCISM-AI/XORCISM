/**
 * bugbounty.ts (routes) — Bug Bounty management: programmes + submissions inventory + worklist, and a
 * guided "new program" create. Guarded by RBAC on XVULNERABILITY.BUGBOUNTYPROGRAM. CRUD stays in the explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { bugBountyInventory, createBugBountyProgram } from "../bugbounty";
import * as xid from "../xid";

const router = Router();

router.get("/bug-bounty", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "BUGBOUNTYPROGRAM")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(bugBountyInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/bug-bounty/program", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XVULNERABILITY", "BUGBOUNTYPROGRAM") && !userCan(req.user, "update", "XVULNERABILITY", "BUGBOUNTYPROGRAM"))
    return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const n = (v: unknown): number | null => v != null && String(v) !== "" ? Number(v) : null;
  try {
    const out = createBugBountyProgram({
      name, platform: b.platform ? String(b.platform) : undefined, status: b.status ? String(b.status) : undefined,
      policyUrl: b.policyUrl ? String(b.policyUrl) : undefined, scope: b.scope ? String(b.scope) : undefined,
      minReward: n(b.minReward), maxReward: n(b.maxReward), currency: b.currency ? String(b.currency) : undefined,
      startDate: b.startDate ? String(b.startDate) : undefined, endDate: b.endDate ? String(b.endDate) : undefined,
      description: b.description ? String(b.description) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "bugbounty_program_create", resourceType: "BUGBOUNTYPROGRAM",
      resourceKey: String(out.id), detail: `name="${name}" platform="${String(b.platform || "Self-hosted")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
