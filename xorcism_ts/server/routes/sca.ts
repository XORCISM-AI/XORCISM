/**
 * sca.ts (routes) — Software Composition Analysis (SCA) + SBOM import/export.
 * Read-only inventory + composition graph + import (CycloneDX/SPDX) + export + delete.
 * Guarded by RBAC on XORCISM.ASSET (SCA is part of the asset/CPE inventory domain);
 * generic CRUD over SBOM/COMPONENT also available via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { parseSbom, importSbom, scaInventory, scaGraph, scaPriority, exportCycloneDX, exportSPDX, deleteSbom } from "../sca";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/sca — full SCA inventory: SBOM documents, components, breakdowns, worklist
router.get("/sca", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  res.json(scaInventory(tenantOf(req)));
});

// GET /api/sca/priority — reachability-based prioritization of vulnerable dependencies (Endor/Snyk-style)
router.get("/sca/priority", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  res.json(scaPriority(tenantOf(req)));
});

// GET /api/sca/graph?sbom=<id> — composition graph (SBOM → components + dependency edges)
router.get("/sca/graph", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const sbomId = req.query.sbom != null && String(req.query.sbom).trim() !== "" ? Number(req.query.sbom) : null;
  res.json(scaGraph(sbomId, tenantOf(req)));
});

// POST /api/sca/import — import a CycloneDX or SPDX SBOM (auto-detected) and persist its components
router.post("/sca/import", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { content?: string | object; name?: string; assetId?: number; applicationId?: number; source?: string };
  if (b.content == null || (typeof b.content === "string" && !b.content.trim()))
    return void res.status(400).json({ error: "content (SBOM JSON) required" });
  try {
    const sbom = parseSbom(b.content);
    const assetId = b.assetId != null && String(b.assetId).trim() !== "" ? Number(b.assetId) : null;
    const out = importSbom({ sbom, name: b.name, assetId, applicationId: b.applicationId ?? null, source: b.source || "upload" },
      tenantOf(req), req.user.UserID ?? null);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "sca_import", resourceType: "sbom",
      resourceKey: String(out.sbomId), detail: `${out.format} components=${out.components} cpeLinks=${out.cpeLinks}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/sca/export?sbom=<id>&format=cyclonedx|spdx — download an SBOM in a standard format
router.get("/sca/export", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const sbomId = Number(req.query.sbom);
  if (!Number.isFinite(sbomId)) return void res.status(400).json({ error: "sbom id required" });
  const fmt = String(req.query.format || "cyclonedx").toLowerCase();
  const doc = fmt === "spdx" ? exportSPDX(sbomId, tenantOf(req)) : exportCycloneDX(sbomId, tenantOf(req));
  if (!doc) return void res.status(404).json({ error: "not found" });
  const fname = `sbom-${sbomId}.${fmt === "spdx" ? "spdx" : "cdx"}.json`;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
  res.send(JSON.stringify(doc, null, 2));
});

// DELETE /api/sca/:id — delete an SBOM and its components/edges
router.delete("/sca/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteSbom(Number(req.params.id), tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "sca_delete", resourceType: "sbom",
    resourceKey: String(req.params.id), detail: "deleted", ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
