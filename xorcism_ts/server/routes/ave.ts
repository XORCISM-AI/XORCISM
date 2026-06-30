/**
 * ave.ts (routes) — AVE (Agentic Vulnerability Enumeration) reference catalogue.
 * Read the catalogue + rollup, import a records export, and seed the bundled sample.
 * Read-gated on XVULNERABILITY.VULNERABILITY; writes audited.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { aveCatalogue, importAve, seedAve, importScanFindings, scanFindings, seedScanFindings } from "../ave";
import { assessAgents, aveExposure } from "../aveassess";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const auth = (req: Request, res: Response, act: "read" | "create"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XVULNERABILITY", "VULNERABILITY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/ave?severity=&componentType=&q=
router.get("/ave", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(aveCatalogue({
    severity: req.query.severity ? String(req.query.severity) : undefined,
    componentType: req.query.componentType ? String(req.query.componentType) : undefined,
    q: req.query.q ? String(req.query.q) : undefined,
  }));
});

// POST /api/ave/import { records:[...] } — import an AVE records export
router.post("/ave/import", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = req.body || {};
  const recs = Array.isArray(b) ? b : (b.records || b.ave_records || []);
  if (!Array.isArray(recs) || !recs.length) return void res.status(400).json({ error: "expected records[]" });
  const out = importAve(recs, String(b.source || "AVE import"));
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "ave_import", resourceType: "ave", resourceKey: "catalogue", detail: `imported ${out.imported} updated ${out.updated}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// POST /api/ave/seed — load the bundled AVE sample (idempotent)
router.post("/ave/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  res.json({ ok: true, ...seedAve() });
});

// POST /api/ave/assess — map the AVE catalogue onto the discovered AI agents (behavioral scan)
router.post("/ave/assess", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = assessAgents(tenantOf(req));
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "ave_assess", resourceType: "ave", resourceKey: "agents", detail: `assessed ${out.assessed} agents, ${out.exposed} exposed`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// GET /api/ave/exposure — the AVE agent-exposure posture (run /assess first)
router.get("/ave/exposure", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(aveExposure(tenantOf(req)));
});

// POST /api/ave/scan/import — import bawbel-scanner output (AVE-in-SARIF or flat findings)
router.post("/ave/scan/import", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = req.body || {};
  const input = b.sarif || b.findings || b.results || (Array.isArray(b) ? b : b);
  const out = importScanFindings(input, String(b.source || "bawbel-scanner"), String(b.scanRef || ""));
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "ave_scan_import", resourceType: "ave", resourceKey: "scan", detail: `imported ${out.imported} scan findings`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// GET /api/ave/scan?severity= — the imported bawbel-scanner per-artifact findings
router.get("/ave/scan", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(scanFindings({ severity: req.query.severity ? String(req.query.severity) : undefined }));
});

// POST /api/ave/scan/seed — load the bundled bawbel-scanner sample SARIF (idempotent)
router.post("/ave/scan/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  res.json({ ok: true, ...seedScanFindings() });
});

export default router;
