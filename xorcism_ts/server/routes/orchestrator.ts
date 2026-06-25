/** orchestrator.ts (routes) — Agentic CROC orchestrator (/croc-orchestrator).
 *  Read (queue/dashboard): any authenticated user, tenant-scoped. Running the orchestrator and
 *  approving/dismissing proposed actions gate on update of XINCIDENT.INCIDENT (the response right). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { orchestratorDashboard, runOrchestrator, decideAction } from "../orchestrator";
import { emitLoopEvent } from "../croc";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const wr = (req: Request) => userCan(req.user, "update", "XINCIDENT", "INCIDENT");

router.get("/croc-orchestrator", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  try { res.json({ ...orchestratorDashboard(ten(req)), canAct: wr(req) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc-orchestrator/run", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "Response capability required (update on incidents)." });
  try {
    const r = runOrchestrator();
    xid.addAudit({ userId: req.user.UserID ?? null, action: "orchestrator_run", resourceType: "CROCACTION", detail: `${r.proposed} proposed / ${r.scanned} scanned`, ip: clientIp(req) });
    res.json({ ok: true, ...r, ...orchestratorDashboard(ten(req)), canAct: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc-orchestrator/:id/decision", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "Response capability required." });
  const id = Number(req.params.id);
  const decision = String((req.body as { decision?: unknown })?.decision ?? "");
  if (decision !== "approved" && decision !== "dismissed") return void res.status(400).json({ error: "decision must be 'approved' or 'dismissed'" });
  const ok = decideAction(id, ten(req), decision, req.user.UserID ?? null);
  if (!ok) return void res.status(404).json({ error: "action not found or already decided" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: `orchestrator_${decision}`, resourceType: "CROCACTION", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true, ...orchestratorDashboard(ten(req)), canAct: true });
});

// Demo: emit a few high/critical loop events, then run the orchestrator (tenant-scoped).
router.post("/croc-orchestrator/seed-demo", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "Response capability required." });
  const t = ten(req);
  if (t == null) return void res.status(400).json({ error: "select a tenant (demo data is tenant-scoped)" });
  try {
    emitLoopEvent({ type: "identity.threat_detected", source: "demo", summary: "Impossible-travel sign-in for svc-backup from 2 countries in 5 min", severity: "critical", tenant: t });
    emitLoopEvent({ type: "exposure.kev_on_asset", source: "demo", summary: "KEV CVE-2021-44228 now reachable on web-01 (internet-facing)", severity: "high", tenant: t });
    emitLoopEvent({ type: "compliance.control_failed", source: "demo", summary: "FileVault disabled on 4 production Macs (mSCP os_filevault_enable)", severity: "high", tenant: t });
    const r = runOrchestrator();
    res.json({ ok: true, emitted: 3, ...r, ...orchestratorDashboard(t), canAct: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
