/** regobligations.ts (routes) — Regulatory obligations & compliance calendar (/reg-calendar).
 *  RBAC: read XCOMPLIANCE.AUDIT (compliance:read); creating/updating obligations gates on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { regCalendar, createObligation, updateObligation } from "../regobligations";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XCOMPLIANCE", "AUDIT");
const wr = (req: Request) => userCan(req.user, "update", "XCOMPLIANCE", "AUDIT");

router.get("/reg-calendar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...regCalendar(ten(req)), canEdit: wr(req) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/reg-calendar/obligation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  try {
    const id = createObligation(ten(req), b);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "reg_obligation_create", resourceType: "REGOBLIGATION", resourceKey: String(id), ip: clientIp(req) });
    res.json({ ok: true, id, ...regCalendar(ten(req)), canEdit: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/reg-calendar/obligation/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return void res.status(400).json({ error: "bad id" });
  try {
    const ok = updateObligation(ten(req), id, (req.body || {}) as Record<string, unknown>);
    if (!ok) return void res.status(404).json({ error: "obligation not found or not editable" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "reg_obligation_update", resourceType: "REGOBLIGATION", resourceKey: String(id), ip: clientIp(req) });
    res.json({ ok: true, ...regCalendar(ten(req)), canEdit: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
