/**
 * hunting.ts (routes) — Threat Hunting domain. Mounted under /api after the
 * auth gate. RBAC: read on XTHREAT.HUNT for the overview / AI assistant,
 * create on XTHREAT.HUNT to persist a generated hunt.
 *
 *   GET  /api/hunting/overview         → stats + recent hunts/IOCs/hypotheses
 *   POST /api/hunting/generate {focus} → AI hunt package (local Ollama agent)
 *   POST /api/hunting/save {...}        → INSERT into HUNT (+ HUNTATTACK links)
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { huntingOverview, generateHunt, saveHunt } from "../hunting";

const router = Router();
const DB = "XTHREAT", TBL = "HUNT";

function aiError(e: unknown): string {
  const m = String((e as Error)?.message || e);
  if (/ECONNREFUSED|fetch failed|ENOTFOUND|ETIMEDOUT|Ollama HTTP/i.test(m)) {
    return `Local AI unreachable. Start Ollama (\`ollama serve\`) at ${process.env.OLLAMA_URL || "http://localhost:11434"} and pull a model.`;
  }
  return m;
}

// GET /api/hunting/overview
router.get("/hunting/overview", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  try {
    res.json(huntingOverview());
  } catch (e) {
    res.status(500).json({ error: String((e as Error)?.message || e) });
  }
});

// POST /api/hunting/generate { focus }
router.post("/hunting/generate", async (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const focus = String((req.body as { focus?: unknown })?.focus ?? "").trim();
  if (!focus) return void res.status(400).json({ error: "focus requis" });
  if (focus.length > 2000) return void res.status(400).json({ error: "focus trop long" });
  try {
    res.json(await generateHunt(focus));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/hunting/save { name, description?, status?, tool?, findings?, source?, techniques?[] }
router.post("/hunting/save", (req: Request, res: Response) => {
  if (!userCan(req.user, "create", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const b = req.body as { name?: unknown; description?: unknown; status?: unknown; tool?: unknown;
    findings?: unknown; source?: unknown; techniques?: unknown };
  const name = String(b?.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name requis" });
  try {
    const r = saveHunt({
      name,
      description: b.description != null ? String(b.description) : undefined,
      status: b.status != null ? String(b.status) : undefined,
      tool: b.tool != null ? String(b.tool) : undefined,
      findings: b.findings != null ? String(b.findings) : undefined,
      source: b.source != null ? String(b.source) : undefined,
      techniques: Array.isArray(b.techniques) ? b.techniques.map((t) => String(t)) : undefined,
    });
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "hunt_create", resourceType: "table",
      resourceKey: `${DB}.${TBL}`, detail: `HuntID=${r.huntId} links=${r.links} name=${name}`, ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(500).json({ error: String((e as Error)?.message || e) });
  }
});

export default router;
