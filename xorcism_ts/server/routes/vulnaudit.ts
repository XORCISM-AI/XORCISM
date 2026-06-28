/** vulnaudit.ts (routes) — Vulnerability Assessment (inventory → enriched vuln report). Read-gated on VULNERABILITY. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { assessInventory } from "../vulnaudit";
import * as xid from "../xid";

const router = Router();

// POST /api/vuln-assessment { inventory } — Vulners-style software-inventory → vulnerability report
router.post("/vuln-assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { inventory?: unknown };
  const text = typeof b.inventory === "string" ? b.inventory : "";
  if (!text.trim()) return void res.status(400).json({ error: "inventory required" });
  if (text.length > 500_000) return void res.status(400).json({ error: "inventory too large (max 500 KB)" });
  try {
    const out = assessInventory(text);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "vuln_assessment", resourceType: "VULNERABILITY",
      detail: `components=${out.summary.components} vulnerable=${out.summary.vulnerable} cves=${out.summary.totalCves} kev=${out.summary.kev}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
