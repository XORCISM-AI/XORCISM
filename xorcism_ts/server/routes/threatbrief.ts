/**
 * threatbrief.ts (routes) — the "Morning Threat Intelligence" briefing (/threat-brief).
 * Read-only aggregation: newest CISA KEV + EPSS-ranked CVEs (local XVULNERABILITY), recent
 * ransomware victims (ransomware.live), active botnet C2 (abuse.ch Feodo Tracker) and security
 * headlines (THREATFEED). All external URLs are server constants → no SSRF. Gated on read of
 * XTHREAT.THREATFEED. Panels degrade to empty independently (see server/threatbrief.ts).
 *
 *   GET /api/threat-brief → the consolidated briefing
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { threatBrief } from "../threatbrief";

const router = Router();

router.get("/threat-brief", async (req: Request, res: Response) => {
  if (!userCan(req.user, "read", "XTHREAT", "THREATFEED")) return void res.status(403).json({ error: "Accès refusé" });
  try {
    res.json(await threatBrief());
  } catch (e) {
    res.status(500).json({ error: (e as Error)?.message || "briefing error" });
  }
});

export default router;
