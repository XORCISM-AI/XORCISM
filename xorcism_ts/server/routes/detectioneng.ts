/**
 * detectioneng.ts (routes) — Detection Engineering studio. Mounted under /api (authenticated).
 * Generate multi-platform detection logic from an ATT&CK technique, save it into the detection
 * stores, and surface Cyber Insights over the knowledge graph.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { getDb } from "../db";
import { PLATFORMS, generateDetections, saveDetection, cyberInsights, DetectContext } from "../detectioneng";

const router = Router();
const TECH_RE = /^T\d{4}(\.\d{3})?$/i;

// GET /api/detection-eng/platforms — the 12 supported detection platforms
router.get("/detection-eng/platforms", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json({ platforms: PLATFORMS.map((p) => ({ key: p.key, label: p.label, language: p.language, kind: p.kind })) });
});

// GET /api/detection-eng/techniques?q= — ATT&CK technique search for the picker (id + name)
router.get("/detection-eng/techniques", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const q = String(req.query.q ?? "").trim().slice(0, 60);
  try {
    const xt = getDb("XTHREAT"); // ATT&CK techniques are stored in XTHREAT.ATTACKTECHNIQUE
    if (!xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").get())
      return void res.json({ techniques: [] });
    const like = `%${q}%`;
    const rows = xt.prepare(
      `SELECT AttackID AS id, Name AS name FROM ATTACKTECHNIQUE
       WHERE AttackID LIKE 'T%' AND COALESCE(Deprecated,0)=0 AND (AttackID LIKE ? OR Name LIKE ?)
       ORDER BY (AttackID = ?) DESC, length(AttackID), AttackID LIMIT 40`,
    ).all(like, like, q.toUpperCase()) as { id: string; name: string }[];
    res.json({ techniques: rows });
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// POST /api/detection-eng/generate { techId, techName?, platforms?, context?, useAi? }
router.post("/detection-eng/generate", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "SIGMARULE")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as { techId?: unknown; techName?: unknown; platforms?: unknown; context?: DetectContext; useAi?: unknown };
  const techId = String(b.techId ?? "").trim().toUpperCase();
  if (!TECH_RE.test(techId)) return void res.status(400).json({ error: "valid ATT&CK technique id required (e.g. T1059.001)" });
  let techName = String(b.techName ?? "").trim().slice(0, 160);
  if (!techName) {
    try {
      const r = getDb("XTHREAT").prepare("SELECT Name AS name FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1").get(techId) as { name?: string } | undefined;
      techName = r?.name || techId;
    } catch { techName = techId; }
  }
  const platforms = Array.isArray(b.platforms) ? b.platforms.map(String).filter(Boolean) : [];
  const ctx = (b.context && typeof b.context === "object") ? b.context : undefined;
  const useAi = b.useAi !== false;
  try {
    res.json(await generateDetections(techId, techName, platforms, ctx, useAi));
  } catch (e) { res.status(502).json({ error: String((e as Error).message || e) }); }
});

// POST /api/detection-eng/save { platform, techId, techName, rule, description?, level? }
router.post("/detection-eng/save", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTHREAT", "DETECTIONRULE")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as { platform?: unknown; techId?: unknown; techName?: unknown; rule?: unknown; description?: unknown; level?: unknown };
  const platform = String(b.platform ?? "").trim();
  const techId = String(b.techId ?? "").trim().toUpperCase();
  const rule = String(b.rule ?? "");
  if (!platform || !TECH_RE.test(techId) || rule.trim().length < 5)
    return void res.status(400).json({ error: "platform, valid techId and a rule body are required" });
  try {
    const saved = saveDetection({
      platform, techId, techName: String(b.techName ?? techId).slice(0, 160), rule,
      description: b.description ? String(b.description) : undefined,
      level: b.level ? String(b.level) : undefined,
      author: req.user.Email || req.user.DisplayName || undefined,
    });
    res.json({ ok: true, ...saved });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/detection-eng/insights — Cyber Insights (coverage, gaps, surface, mitigations)
router.get("/detection-eng/insights", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "SIGMARULE")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(cyberInsights()); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

export default router;
