/**
 * configuration.ts (routes) — Configuration Management inventory + governance worklist.
 * Read-only inventory; guarded by read on XOVAL.OVALDEFINITION. OVAL scans are launched
 * on enrolled XOR agents (localhost or remote) via the existing /api/agent-scan queue.
 */
import os from "os";
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { configurationInventory, cisBenchmarkInventory } from "../configuration";
import { listAgents } from "../agents";
import { createSchedule, listSchedules } from "../jobs";
import * as xid from "../xid";

const router = Router();

const OVAL_CLASSES = new Set(["all", "compliance", "vulnerability", "inventory", "patch"]);
const CRON_PRESETS: Record<string, string> = {
  hourly: "0 * * * *", daily: "0 2 * * *", weekly: "0 3 * * 1", monthly: "0 4 1 * *",
};

// GET /api/configuration-management — secure-configuration content library + verification worklist
router.get("/configuration-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(configurationInventory(tenant));
});

// GET /api/configuration/scan-targets — enrolled XOR agents an OVAL scan can be launched on
// (the local host is flagged so the UI can offer "localhost"). The launch itself reuses
// POST /api/agent-scan { agent, kind } — the agent runs it at its next check-in.
router.get("/configuration/scan-targets", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const localName = os.hostname();
  const ln = localName.toLowerCase();
  const now = Date.now();
  const agents = listAgents().map((a) => {
    const seen = a.last_seen ? Date.parse(String(a.last_seen).replace(" ", "T")) : NaN;
    const online = !Number.isNaN(seen) && now - seen < 15 * 60 * 1000;
    const cands = [a.name, a.asset_name, a.fqdn].filter(Boolean).map((v) => String(v).toLowerCase());
    const isLocal = cands.some((v) => v === ln || v.startsWith(ln + "."));
    return { name: a.name, asset: a.asset_name, os: a.os, platform: a.platform, lastSeen: a.last_seen, online, isLocal };
  });
  // local host first, then online, then by name
  agents.sort((x, y) => Number(y.isLocal) - Number(x.isLocal) || Number(y.online) - Number(x.online) || x.name.localeCompare(y.name));
  // existing recurring OVAL schedules (so the UI can show what's already scheduled)
  let scheduled: { id: number; agent: string; ovalClass: string; cron: string; lastRun: string | null }[] = [];
  try {
    for (const s of listSchedules()) {
      if (s.connector !== "agent-oval") continue;
      let p: { agent?: string; ovalClass?: string } = {};
      try { p = JSON.parse(s.params || "{}"); } catch { /* ignore */ }
      scheduled.push({ id: s.ScheduleID, agent: String(p.agent ?? ""), ovalClass: String(p.ovalClass ?? "all"), cron: s.cron, lastRun: s.last_run_at ?? null });
    }
  } catch { /* schedules unavailable */ }
  res.json({ localhost: localName, agents, scheduled, cronPresets: CRON_PRESETS });
});

// POST /api/configuration/schedule-scan { agent, ovalClass?, cron|preset } — schedule a RECURRING
// OVAL scan on an enrolled agent via XSCHEDULE. The scheduler queues an agent OVAL job each tick
// (connector 'agent-oval'); the agent runs it at its next check-in and posts results.
router.post("/configuration/schedule-scan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XOVAL", "OVALRESULTS")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { agent?: unknown; ovalClass?: unknown; cron?: unknown; preset?: unknown };
  const agent = String(b.agent ?? "").trim();
  if (!agent) return void res.status(400).json({ error: "agent required" });
  const ovalClass = OVAL_CLASSES.has(String(b.ovalClass ?? "all")) ? String(b.ovalClass ?? "all") : "all";
  let cron = "";
  if (typeof b.preset === "string" && CRON_PRESETS[b.preset]) cron = CRON_PRESETS[b.preset];
  else if (typeof b.cron === "string" && b.cron.trim().split(/\s+/).length === 5) cron = b.cron.trim();
  else cron = CRON_PRESETS.daily;
  const scheduleId = createSchedule({ connector: "agent-oval", params: { agent, ovalClass }, target: null, engagementId: null, worker: null, cron, userId: req.user.UserID ?? 0 });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "configuration_schedule_scan", resourceType: "schedule",
    resourceKey: String(scheduleId), detail: `agent=${agent} ovalClass=${ovalClass} cron=${cron}`, ip: clientIp(req) });
  res.json({ ok: true, scheduleId, agent, ovalClass, cron });
});

// GET /api/configuration/cis-benchmarks — CIS Benchmark catalogue + CIS-CAT pass/fail posture
router.get("/configuration/cis-benchmarks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(cisBenchmarkInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
