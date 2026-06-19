/**
 * agent.ts (routes) — XOR endpoint agent API.
 *
 *  Token (Bearer, no session) — mounted BEFORE the auth gate:
 *    POST /api/agent/enroll          enrollment (enrollment key) → token
 *    POST /api/agent/checkin         heartbeat → pending scan jobs + intel state
 *    POST /api/agent/inventory       software inventory → CPE/CPEFORASSET (via import)
 *    POST /api/agent/vulnerabilities detected CVEs → ASSETVULNERABILITY (via import)
 *    POST /api/agent/oval            OpenSCAP OVAL verdicts → XOVAL.OVALRESULTS + fan-out
 *    POST /api/agent/events          AV detections / hunting hits / EDR / compliance
 *    GET  /api/agent/intel           IOCs (threat intel) to hunt locally
 *    POST /api/agent/job/:id/result  end of a scan job
 *
 *  Session (admin/UI) — mounted AFTER the gate:
 *    GET  /api/agents, /api/agent-events, /api/agent-jobs
 *    POST /api/agent-scan { agent, kind }   "launch a scan" from the ASSET window
 */
import { Router, Request, Response, NextFunction } from "express";
import {
  enrollAgent, agentByToken, touchAgent, listAgents, addAgentEvent, listAgentEvents,
  createAgentJob, claimAgentJobs, finishAgentJob, listAgentJobs, listIocs, iocCount, Agent,
} from "../agents";
import { createCollectedJob } from "../jobs";
import { ingestOvalResults, ovalResultsView, findOvalContent, listOvalContent, ovalContentDir, OvalPayload } from "../oval";
import { getDb, createNotification } from "../db";
import * as xid from "../xid";
import { clientIp } from "../auth";

// ── TOKEN router (agents) ────────────────────────────────────────────────────────
export const agentTokenRouter = Router();
interface AReq extends Request { agent?: Agent }

function tokenAuth(req: AReq, res: Response, next: NextFunction): void {
  const m = /^Bearer\s+(.+)$/.exec(req.headers.authorization || "");
  const a = m ? agentByToken(m[1].trim()) : undefined;
  if (!a) return void res.status(401).json({ error: "jeton agent invalide" });
  req.agent = a;
  next();
}

// Enrollment: protected by a shared key (XOR_ENROLL_KEY). If not set → dev (open).
agentTokenRouter.post("/agent/enroll", (req: Request, res: Response) => {
  const need = process.env.XOR_ENROLL_KEY;
  if (need && (req.headers["x-enroll-key"] !== need)) {
    return void res.status(403).json({ error: "clé d'enrôlement invalide" });
  }
  const b = req.body as Record<string, string>;
  const name = String(b.name || "").trim();
  if (!/^[A-Za-z0-9_.\-]{1,120}$/.test(name)) return void res.status(400).json({ error: "nom d'agent invalide" });
  const { token, agentId } = enrollAgent(name, {
    os: b.os, platform: b.platform, version: b.version,
    ip: b.ip || clientIp(req), fqdn: b.fqdn,
  });
  addAgentEvent(name, { type: "enroll", severity: "info", title: "Agent enrolled", detail: { os: b.os, platform: b.platform } });
  res.json({ ok: true, token, agentId, asset: name });
});

agentTokenRouter.post("/agent/checkin", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  res.json({ jobs: claimAgentJobs(req.agent!.name), intel: { count: iocCount() } });
});

agentTokenRouter.post("/agent/inventory", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  // The normalized result { assets, services(cpe), cpes, vulns } is imported by the runner.
  const result = (req.body as { result?: unknown }).result ?? req.body;
  const jobId = createCollectedJob("xor-inventory", result, req.agent!.name);
  res.json({ ok: true, jobId });
});

agentTokenRouter.post("/agent/vulnerabilities", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  const vulns = (req.body as { vulns?: unknown[] }).vulns ?? [];
  const result = { assets: [{ hostname: req.agent!.name, key: req.agent!.name }], vulns };
  const jobId = createCollectedJob("xor-vuln", result, req.agent!.name);
  addAgentEvent(req.agent!.name, { type: "vuln_scan", severity: "info", title: `${Array.isArray(vulns) ? vulns.length : 0} CVE`, detail: { count: Array.isArray(vulns) ? vulns.length : 0 } });
  res.json({ ok: true, jobId });
});

agentTokenRouter.post("/agent/events", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  const events = (req.body as { events?: { type: string; severity?: string; title?: string; detail?: unknown }[] }).events ?? [];
  for (const ev of events) if (ev && ev.type) addAgentEvent(req.agent!.name, ev);
  res.json({ ok: true, stored: events.length });
});

// OVAL scan results (OpenSCAP `oscap oval eval`): stored in XOVAL.OVALRESULTS and
// fanned out — vulnerability-class → ASSETVULNERABILITY, inventory-class → CPEFORASSET.
agentTokenRouter.post("/agent/oval", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  const asset = req.agent!.asset_name || req.agent!.name;
  const summary = ingestOvalResults(asset, (req.body as OvalPayload) || {}, null);
  addAgentEvent(req.agent!.name, {
    type: "oval_scan",
    severity: summary.compliance.fail > 0 ? "warning" : "info",
    title: `OVAL: ${summary.stored} verdicts (${summary.vulnerabilities} CVE, compliance ${summary.compliance.fail} fail/${summary.compliance.pass} pass)`,
    detail: { engine: summary.engine, content: summary.content, byClass: summary.byClass },
  });
  res.json({ ok: true, ...summary });
});

// CPE→CVE correlation (heuristic bounded by product name) against the CVE database (NVD).
// ⚠️ Demonstration heuristic: to be replaced by a real NVD "CPE applicability match".
agentTokenRouter.post("/agent/match", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  const host = req.agent!.name;
  const products = ((req.body as { products?: { name: string; version?: string }[] }).products ?? [])
    .map((p) => (p?.name || "").trim())
    .filter((n) => n.length >= 5)
    .filter((n, i, a) => a.indexOf(n) === i)
    .slice(0, 15); // perf bound: LIKE over ~CVE
  const vulns: { asset: string; ref: string; name: string; severity: string }[] = [];
  try {
    const db = getDb("XVULNERABILITY");
    const stmt = db.prepare(
      "SELECT VULGUID FROM VULNERABILITY WHERE VULGUID LIKE 'CVE-%' AND VULDescription LIKE ? LIMIT 1"
    );
    const seen = new Set<string>();
    for (const p of products) {
      const row = stmt.get(`% ${p} %`) as { VULGUID: string } | undefined;
      if (row?.VULGUID && !seen.has(row.VULGUID)) {
        seen.add(row.VULGUID);
        vulns.push({ asset: host, ref: row.VULGUID, name: `${p} (heuristic match)`, severity: "unknown" });
      }
    }
  } catch { /* CVE database unavailable */ }
  res.json({ vulns });
});

// OVAL/SCAP content served to agents (offline / centralized content). The admin drops
// OVAL/SCAP files in the content dir; the agent fetches the one matching its platform.
agentTokenRouter.get("/agent/oval-content", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  const hit = findOvalContent(String(req.query.platform || ""));
  if (!hit) return void res.status(404).json({ error: "no OVAL content available", available: listOvalContent().map((f) => f.name) });
  res.setHeader("X-OVAL-Content-Name", hit.name);
  res.sendFile(hit.path);
});

agentTokenRouter.get("/agent/intel", tokenAuth, (req: AReq, res: Response) => {
  touchAgent(req.agent!.name);
  res.json({ iocs: listIocs() });
});

agentTokenRouter.post("/agent/job/:id/result", tokenAuth, (req: AReq, res: Response) => {
  finishAgentJob(Number(req.params.id), String((req.body as { summary?: string }).summary || ""));
  res.json({ ok: true });
});

// ── ADMIN/UI router (session) ──────────────────────────────────────────────────
export const agentAdminRouter = Router();

agentAdminRouter.get("/agents", (_req: Request, res: Response) => res.json(listAgents()));
// OVAL scan results (per-asset verdicts + compliance/vuln worklist) for the /oval-scan page.
agentAdminRouter.get("/oval-results", (req: Request, res: Response) => {
  const tenant = req.user?.isSuperAdmin ? null : (req.user?.tenantId ?? null);
  res.json(ovalResultsView(tenant));
});
// OVAL content the server makes available to agents (admin visibility).
agentAdminRouter.get("/oval-content", (_req: Request, res: Response) =>
  res.json({ dir: ovalContentDir(), files: listOvalContent() }));
agentAdminRouter.get("/agent-events", (req: Request, res: Response) =>
  res.json(listAgentEvents(Math.min(Number(req.query.limit) || 100, 500), req.query.agent ? String(req.query.agent) : undefined)));
agentAdminRouter.get("/agent-jobs", (req: Request, res: Response) =>
  res.json(listAgentJobs(req.query.agent ? String(req.query.agent) : undefined)));

// XOR agent bulk scan: for each selected ASSET, queues a job on
// the corresponding agent (match by asset_name or name). Results auto-populated
// via the agent's inventory/vuln callbacks.
agentAdminRouter.post("/agent-bulk-scan", (req: Request, res: Response) => {
  const { assetIds, kind } = req.body as { assetIds?: unknown; kind?: string };
  const ids = Array.isArray(assetIds)
    ? assetIds.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0).slice(0, 1000)
    : [];
  if (!ids.length) return void res.status(400).json({ error: "Aucun actif sélectionné" });
  const k = ["inventory", "vuln", "oval", "av", "hunt", "full"].includes(String(kind)) ? String(kind) : "full";

  const db = getDb("XORCISM");
  const ph = ids.map(() => "?").join(",");
  const assets = db
    .prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${ph})`)
    .all(...ids) as { AssetID: number; AssetName: string | null }[];

  const byName = new Map<string, string>(); // asset_name/name (lowercase) → agent name
  for (const a of listAgents()) {
    if (a.asset_name) byName.set(a.asset_name.toLowerCase(), a.name);
    byName.set(a.name.toLowerCase(), a.name);
  }

  let queued = 0;
  const noAgent: string[] = [];
  for (const a of assets) {
    const agentName = byName.get((a.AssetName || "").toLowerCase());
    if (!agentName) { noAgent.push(a.AssetName || `#${a.AssetID}`); continue; }
    createAgentJob(agentName, k, {}, req.user?.UserID ?? null);
    queued++;
  }
  xid.addAudit({ userId: req.user?.UserID ?? null, action: "agent_bulk_scan", resourceType: "asset",
    detail: `${queued} agents, kind=${k}, sans-agent=${noAgent.length}`, ip: clientIp(req) });
  if (req.user) {
    createNotification({
      userId: req.user.UserID,
      title: `Scan XOR agent lancé (${queued})`,
      message: `${queued} agent(s) en file (type ${k})` + (noAgent.length ? ` · ${noAgent.length} actif(s) sans agent` : ""),
      level: queued ? "info" : "warning",
      source: "agent",
      tenantId: req.user.tenantId,
    });
  }
  res.json({ queued, noAgent: noAgent.slice(0, 50), kind: k });
});

// "Launch a scan" from the ASSET window (the agent picks up the job at the next checkin).
agentAdminRouter.post("/agent-scan", (req: Request, res: Response) => {
  const { agent, kind } = req.body as { agent?: string; kind?: string };
  const valid = ["inventory", "vuln", "oval", "av", "hunt", "full"];
  if (!agent) return void res.status(400).json({ error: "agent requis" });
  if (!valid.includes(String(kind))) return void res.status(400).json({ error: "type de scan invalide" });
  // Checks that the agent exists
  if (!listAgents().some((a) => a.name === agent)) return void res.status(404).json({ error: "agent not found for this asset" });
  const id = createAgentJob(String(agent), String(kind), {}, req.user?.UserID ?? null);
  xid.addAudit({ userId: req.user?.UserID ?? null, action: "agent_scan", resourceType: "agent",
    resourceKey: String(agent), detail: `kind=${kind} job=${id}`, ip: clientIp(req) });
  res.json({ ok: true, jobId: id });
});
