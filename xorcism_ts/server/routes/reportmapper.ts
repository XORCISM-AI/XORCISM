/**
 * reportmapper.ts (routes) — Report ATT&CK Mapper (native MITRE TRAM). Mounted under /api (authenticated).
 * Map report text → ATT&CK techniques (keyword + AI), save to THREATREPORT + REPORTMAPPING, list
 * mapped reports, and export an ATT&CK Navigator layer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { mapReport, saveReportMapping, getMappedReports, navigatorLayer, SaveInput } from "../reportmapper";

const router = Router();

// POST /api/report-mapper/map { text, useAi? } — map report text to ATT&CK techniques
router.post("/report-mapper/map", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "REPORTMAPPING")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as { text?: unknown; useAi?: unknown };
  const text = String(b.text ?? "").trim();
  if (text.length < 30) return void res.status(400).json({ error: "provide at least ~30 characters of report text" });
  if (text.length > 100000) return void res.status(400).json({ error: "report too large (max 100k chars)" });
  try {
    res.json(await mapReport(text, b.useAi !== false));
  } catch (e) { res.status(502).json({ error: String((e as Error).message || e) }); }
});

// POST /api/report-mapper/save { name, reference?, text?, source?, mlModel?, sentences[] }
router.post("/report-mapper/save", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTHREAT", "REPORTMAPPING")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as Partial<SaveInput>;
  if (!b.name || !Array.isArray(b.sentences) || !b.sentences.length)
    return void res.status(400).json({ error: "name and non-empty sentences[] required" });
  const total = b.sentences.reduce((n, s) => n + ((s.mappings || []).length), 0);
  if (!total) return void res.status(400).json({ error: "no accepted mappings to save" });
  try {
    const saved = saveReportMapping({ name: b.name, reference: b.reference, text: b.text, source: b.source || "Report Mapper", mlModel: b.mlModel, sentences: b.sentences });
    res.json({ ok: true, ...saved });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/report-mapper/reports — saved reports that have mappings
router.get("/report-mapper/reports", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "REPORTMAPPING")) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ reports: getMappedReports() }); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/report-mapper/navigator/:id — ATT&CK Navigator layer for a saved report
router.get("/report-mapper/navigator/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "REPORTMAPPING")) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "invalid report id" });
  try {
    const layer = navigatorLayer(id);
    if (!layer) return void res.status(404).json({ error: "report not found" });
    res.setHeader("Content-Disposition", `attachment; filename="tram-report-${id}-navigator.json"`);
    res.json(layer);
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

export default router;
