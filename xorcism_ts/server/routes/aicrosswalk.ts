/**
 * aicrosswalk.ts (routes) — AI Governance Crosswalk cockpit. Read the crosswalk matrix (capabilities ×
 * EU AI Act / NIST AI RMF / ISO 42001 / Singapore + evidence/owner/priority + per-tenant status + coverage
 * analytics), set a capability's status, and export as markdown. Guarded by RBAC on XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { crosswalkMatrix, setCrosswalkStatus, crosswalkMarkdown, ensureCrosswalkTables, syncCrosswalkMappings } from "../aicrosswalk";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/ai-governance-crosswalk[?format=md] — full crosswalk matrix + analytics (or markdown export)
router.get("/ai-governance-crosswalk", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try {
    ensureCrosswalkTables();
    if (String(req.query.format) === "md") {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="ai-governance-crosswalk.md"`);
      return void res.send(crosswalkMarkdown(tenantOf(req)));
    }
    res.json(crosswalkMatrix(tenantOf(req)));
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/ai-governance-crosswalk/status — set one capability's status / evidence / owner / notes
router.post("/ai-governance-crosswalk/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT") && !userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.capId) return void res.status(400).json({ error: "capId required" });
  try {
    const cap = setCrosswalkStatus(tenantOf(req), String(b.capId), {
      status: b.status != null ? String(b.status) : undefined,
      evidenceRef: b.evidenceRef != null ? String(b.evidenceRef) : undefined,
      owner: b.owner != null ? String(b.owner) : undefined,
      notes: b.notes != null ? String(b.notes) : undefined,
    });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_crosswalk_status", resourceType: "ai-crosswalk", resourceKey: String(b.capId), detail: String(b.status ?? ""), ip: clientIp(req) });
    res.json({ ok: true, capability: cap });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/ai-governance-crosswalk/sync-mappings — persist the crosswalk as CONTROLMAPPING rows (Singapore-anchored)
router.post("/ai-governance-crosswalk/sync-mappings", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT") && !userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = syncCrosswalkMappings();
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_crosswalk_sync", resourceType: "ai-crosswalk", resourceKey: "mappings", detail: `${r.mapped} rows`, ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
