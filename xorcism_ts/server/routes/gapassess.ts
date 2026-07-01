/**
 * gapassess.ts (routes) — Automated gap assessment of the governance estate (POLICYs + DOCUMENTs)
 * against a selected Framework / Regulation, using local AI (with a deterministic offline fallback).
 * RBAC on XORCISM.POLICY (the assessed corpus is policies & documents).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { gapOverview, latestForFramework, getAssessment, runGapAssessment } from "../gapassess";
import { dispatchEvent } from "../notifrules";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/gap-assessment/overview — assessable frameworks + corpus size (for the picker / dashboard)
router.get("/gap-assessment/overview", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  res.json(gapOverview(tenantOf(req)));
});

// GET /api/gap-assessment?framework=<id>  — latest assessment for a framework
// GET /api/gap-assessment?assessment=<id> — a specific past run
router.get("/gap-assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const aid = Number(req.query.assessment), fid = Number(req.query.framework);
  try {
    if (aid) return void res.json({ report: getAssessment(aid, tenantOf(req)) });
    if (fid) return void res.json({ report: latestForFramework(fid, tenantOf(req)) });
    res.status(400).json({ error: "framework or assessment id required" });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/gap-assessment/run { frameworkId, limit? } — run a new assessment (local AI + fallback)
router.post("/gap-assessment/run", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body || {};
  const fid = Number(b.frameworkId);
  if (!fid) return void res.status(400).json({ error: "frameworkId required" });
  const limit = b.limit != null ? Number(b.limit) : 60;
  try {
    const rep = await runGapAssessment(fid, tenantOf(req), limit);
    try {
      dispatchEvent("gap.assessment", {
        userId: (req.user as { UserID?: number }).UserID ?? undefined, tenant: tenantOf(req),
        level: rep.counts.gap > 0 ? "warning" : "info",
        title: `Gap assessment: ${rep.frameworkName} — ${rep.coveragePct}% covered`,
        message: `${rep.counts.covered} covered · ${rep.counts.partial} partial · ${rep.counts.gap} gaps across ${rep.assessed} controls (${rep.ai ? "AI" : "heuristic"}).`,
        link: "/gap-assessment",
      });
    } catch { /* alerting is best-effort */ }
    res.json(rep);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
