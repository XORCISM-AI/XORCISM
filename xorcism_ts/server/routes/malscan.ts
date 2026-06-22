/** malscan.ts (routes) — Multi-engine malware / IOC scan (XMALWARE backend), surfaced in CTI and on
 * DOCUMENTs. RBAC on XMALWARE.MALWARESCAN. Engine API keys come from the worker environment only. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { runScan, storeScan, getScan, scanInventory, scanDocument, detectType, TargetType } from "../malscan";
import { dispatchEvent } from "../notifrules";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const VALID_TYPES = new Set(["hash", "url", "domain", "ip", "file"]);

router.get("/malware-scan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XMALWARE", "MALWARESCAN")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(scanInventory(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/malware-scan/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XMALWARE", "MALWARESCAN")) return void res.status(403).json({ error: "forbidden" });
  const out = getScan(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/malware-scan/run", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XMALWARE", "MALWARESCAN")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const target = String(b.target ?? "").trim();
  if (!target) return void res.status(400).json({ error: "target required (hash / URL / domain / IP)" });
  if (target.length > 2048) return void res.status(400).json({ error: "target too long" });
  const type = b.type && VALID_TYPES.has(String(b.type)) ? (String(b.type) as TargetType) : detectType(target);
  try {
    const result = await runScan(target, type);
    const scanId = storeScan(result, { tenant: ten(req), createdBy: req.user.Email ?? String(req.user.UserID ?? ""), source: "Manual", trackObservable: !!b.trackObservable });
    if (result.verdict === "malicious") dispatchEvent("malware.malicious", { userId: req.user.UserID, tenant: req.user.tenantId ?? null, title: `Malicious: ${target.slice(0, 80)}`, message: result.summary, link: "/malware-scan", dedupeByLink: false });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "malware_scan", resourceType: "MALWARESCAN", resourceKey: String(scanId), detail: `${type}:${target} → ${result.verdict}`, ip: clientIp(req) });
    res.json({ ok: true, scanId, ...result });
  } catch (e) { res.status(502).json({ error: String((e as Error).message || e) }); }
});

router.post("/malware-scan/document/:id", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XMALWARE", "MALWARESCAN")) return void res.status(403).json({ error: "forbidden" });
  const docId = Number(req.params.id);
  if (!Number.isFinite(docId)) return void res.status(400).json({ error: "bad document id" });
  try {
    const { scanId, result } = await scanDocument(docId, { tenant: ten(req), createdBy: req.user.Email ?? String(req.user.UserID ?? "") });
    if (result.verdict === "malicious") dispatchEvent("malware.malicious", { userId: req.user.UserID, tenant: req.user.tenantId ?? null, title: `Malicious document #${docId}`, message: result.summary, link: "/malware-scan" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "malware_scan_document", resourceType: "DOCUMENT", resourceKey: String(docId), detail: `→ ${result.verdict}`, ip: clientIp(req) });
    res.json({ ok: true, scanId, ...result });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
