/** siem.ts (routes) — SIEM-lite: log ingest → Sigma → ALERT (/siem).
 *  Read dashboard = read XINCIDENT.ALERT; ingesting logs (raises alerts) = update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { siemDashboard, ingestEvents, SAMPLE_LOGS } from "../siem";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XINCIDENT", "ALERT");
const wr = (req: Request) => userCan(req.user, "update", "XINCIDENT", "ALERT");

router.get("/siem", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...siemDashboard(ten(req)), canIngest: wr(req) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

function doIngest(req: Request, res: Response, events: any[]): void {
  if (!Array.isArray(events) || !events.length) return void res.status(400).json({ error: "events[] required (an array of log records)" });
  try {
    const r = ingestEvents(events.slice(0, 5000), ten(req));
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "siem_ingest", resourceType: "SIEMEVENT", detail: `${r.ingested} events, ${r.matched} matches`, ip: clientIp(req) });
    res.json({ ok: true, ...r, ...siemDashboard(ten(req)), canIngest: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
}

router.post("/siem/ingest", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "Ingest requires update on alerts." });
  let events = (req.body as { events?: unknown })?.events;
  if (typeof events === "string") { try { events = JSON.parse(events); } catch { /* */ } }
  doIngest(req, res, events as any[]);
});

router.post("/siem/sample", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "Ingest requires update on alerts." });
  doIngest(req, res, SAMPLE_LOGS as any[]);
});

export default router;
