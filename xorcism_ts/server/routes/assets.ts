/**
 * assets.ts (routes) — Asset Management inventory + governance worklist.
 * Read-only; guarded by read on XORCISM.ASSET. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { assetInventory, createAsset, importAssets, ASSET_IMPORT_FIELDS, bulkUpdateAssets, BULK_FIELDS } from "../assets";
import { exportAssetsArf, importAssetsArf } from "../arf";
import { matchCves, rescoreLegacyMatches } from "../cvematch";
import * as xid from "../xid";

const router = Router();

// GET /api/asset-management — asset inventory with governance findings
router.get("/asset-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(assetInventory(tenant));
});

// POST /api/asset-management/asset — guided creation of an ASSET
router.post("/asset-management/asset", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createAsset({
      name,
      description: b.description ? String(b.description) : undefined,
      criticality: b.criticality ? String(b.criticality) : undefined,
      os: b.os ? String(b.os) : undefined,
      hostname: b.hostname ? String(b.hostname) : undefined,
      ip: b.ip ? String(b.ip) : undefined,
      environment: b.environment ? String(b.environment) : undefined,
      publicFacing: !!b.publicFacing,
      businessValue: b.businessValue ? String(b.businessValue) : undefined,
      financialValue: b.financialValue != null && String(b.financialValue) !== "" ? Number(b.financialValue) : null,
      currency: b.currency ? String(b.currency) : undefined,
      hostPii: !!b.hostPii,
      ownerPersonId: b.ownerPersonId != null && String(b.ownerPersonId) !== "" ? Number(b.ownerPersonId) : null,
      notes: b.notes ? String(b.notes) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_create", resourceType: "ASSET",
      resourceKey: String(out.id), detail: `name="${name}" criticality="${String(b.criticality || "")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/asset-management/bulk-fields — the settable fields for the bulk-update UI.
router.get("/asset-management/bulk-fields", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  res.json({ fields: BULK_FIELDS });
});

// POST /api/asset-management/bulk-update — apply a set of field changes to many assets at once,
// targeted by explicit assetIds (what the UI selects) or a filter (e.g. every asset tagged
// "endpoint"). Body: { assetIds?: number[], filter?: {tag,criticality,environment,exposure,ownerless,publicFacing}, set: {<field>: value} }.
router.post("/asset-management/bulk-update", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { assetIds?: unknown; filter?: unknown; set?: unknown };
  const set = (b.set && typeof b.set === "object") ? b.set as Record<string, unknown> : {};
  if (!Object.keys(set).length) return void res.status(400).json({ error: "set: at least one field to update is required" });
  const assetIds = Array.isArray(b.assetIds) ? b.assetIds.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n > 0) : undefined;
  const filter = (b.filter && typeof b.filter === "object") ? b.filter as Record<string, unknown> : undefined;
  if ((!assetIds || !assetIds.length) && !filter) return void res.status(400).json({ error: "provide assetIds[] or a filter" });
  if (assetIds && assetIds.length > 20000) return void res.status(400).json({ error: "too many assetIds (max 20000)" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = bulkUpdateAssets(tenant, { assetIds, filter: filter as never, set });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_bulk_update", resourceType: "ASSET",
      detail: `matched=${out.matched} updated=${out.updated} fields=[${out.fields.join(",")}] via=${out.targeting}${filter ? ` filter=${JSON.stringify(filter)}` : ""}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/asset-management/import-fields — the logical ASSET fields a spreadsheet column
// can be mapped to (drives the client's Excel column-mapping UI). Read access is enough.
router.get("/asset-management/import-fields", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  res.json({ fields: ASSET_IMPORT_FIELDS.map((f) => ({ key: f.key, type: f.type })) });
});

// POST /api/asset-management/import — bulk-create/upsert assets from column-mapped spreadsheet
// rows. Body: { rows: [{ <field>: value, ... }], upsert?: boolean }. The Excel parsing + column
// mapping happen client-side; here we normalise and create via the same path as the guided form.
router.post("/asset-management/import", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { rows?: unknown; upsert?: unknown };
  if (!Array.isArray(b.rows)) return void res.status(400).json({ error: "rows[] required" });
  if (b.rows.length === 0) return void res.status(400).json({ error: "no rows to import" });
  if (b.rows.length > 5000) return void res.status(400).json({ error: "too many rows (max 5000 per import)" });
  const rows = b.rows.filter((r) => r && typeof r === "object") as Record<string, unknown>[];
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = importAssets(rows, tenant, { upsert: !!b.upsert });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_import", resourceType: "ASSET",
      detail: `rows=${rows.length} created=${out.created} updated=${out.updated} skipped=${out.skipped} errors=${out.errors.length} upsert=${!!b.upsert}`,
      ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// GET /api/asset-management/export/arf — export the asset estate as a NIST ARF 1.1 (NISTIR 7694)
// document (Asset Identification 1.1 computing-devices + a XORCISM inventory-extension report).
router.get("/asset-management/export/arf", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const xml = exportAssetsArf(tenant);
    const stamp = new Date().toISOString().slice(0, 10);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_export_arf", resourceType: "ASSET",
      detail: `bytes=${xml.length}`, ip: clientIp(req) });
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="xorcism-assets-arf-${stamp}.xml"`);
    res.send(xml);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/asset-management/import/arf — import assets from an ARF/AI XML document.
// Body: { xml: string, upsert?: boolean }. The file is read client-side and posted as text.
router.post("/asset-management/import/arf", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { xml?: unknown; upsert?: unknown };
  const xml = typeof b.xml === "string" ? b.xml : "";
  if (!xml.trim()) return void res.status(400).json({ error: "xml required" });
  if (xml.length > 24 * 1024 * 1024) return void res.status(400).json({ error: "ARF document too large (max 24 MB)" });
  if (!/asset-report-collection|<(?:[\w.\-]+:)?(?:asset|computing-device)\b/i.test(xml)) {
    return void res.status(400).json({ error: "not a recognisable ARF / Asset Identification document" });
  }
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = importAssetsArf(xml, tenant, { upsert: !!b.upsert });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "asset_import_arf", resourceType: "ASSET",
      detail: `parsed=${out.parsed} created=${out.created} updated=${out.updated} skipped=${out.skipped} errors=${out.errors.length} upsert=${!!b.upsert}`,
      ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cve-match/run — on-demand CVE→asset rematch over a recent window (admin).
// Links CVEs matching each asset's technologies (CPE tokens + tech tags) and notifies.
router.post("/cve-match/run", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const b = (req.body || {}) as { days?: unknown; minConfidence?: unknown; rescore?: unknown; onlyRescore?: unknown };
  const days = Math.min(Math.max(Number(b.days) || 30, 1), 365);
  // Precision knob: "high" = CPE/pair only, "medium" (default) = + specific product tokens, "low" = + weak tags.
  const minConfidence = ["high", "medium", "low"].includes(String(b.minConfidence)) ? String(b.minConfidence) : "medium";
  const truthy = (v: unknown): boolean => v === true || v === 1 || v === "1" || v === "true";
  const onlyRescore = truthy(b.onlyRescore);   // "Clean false positives": skip matching, just re-score the backlog
  const doRescore = onlyRescore || truthy(b.rescore);
  try {
    // onlyRescore = clean-up only (no new links created); otherwise run the matcher first.
    const out = onlyRescore ? undefined : matchCves({ tenant, days, minConfidence });
    let rescore: { scanned: number; flagged: number; kept: number } | undefined;
    if (doRescore) rescore = rescoreLegacyMatches(tenant, minConfidence);
    xid.addAudit({ userId: req.user.UserID ?? null, action: onlyRescore ? "cve_match_rescore" : "cve_match_run", resourceType: "ASSETVULNERABILITY",
      detail: `${onlyRescore ? "rescore-only" : `days=${days} newLinks=${out!.newLinks} assets=${out!.assetsAffected}`} minConf=${minConfidence}${rescore ? ` rescored=${rescore.scanned} flaggedFP=${rescore.flagged}` : ""}`, ip: clientIp(req) });
    res.json({ ok: true, ...(out || {}), rescore, onlyRescore });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
