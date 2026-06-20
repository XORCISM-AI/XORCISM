/**
 * tid.ts (routes) — Threat-Informed Defense cockpit (ATT&CK technique coverage:
 * adversary use vs detect / mitigate / test). Read-only; guarded by read on
 * XTHREAT.ATTACKTECHNIQUE.
 */
import { randomUUID } from "crypto";
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { tidInventory, planTidValidation, tidNavigatorLayer } from "../tid";
import { suggestSigma, SigmaContext } from "../purpleteam";
import { getDb } from "../db";
import { createSchedule } from "../jobs";
import * as xid from "../xid";

const router = Router();

// GET /api/threat-informed-defense — TID scorecard + prioritised gap worklist
router.get("/threat-informed-defense", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(tidInventory(tenant));
});

// GET /api/threat-informed-defense/navigator-layer — export the program as a MITRE ATT&CK
// Navigator layer (v4.5 JSON). ?download=1 sends it as a file attachment. Opens directly in
// the official ATT&CK Navigator (score=adversary prevalence, colour=defence status).
router.get("/threat-informed-defense/navigator-layer", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "ATTACKTECHNIQUE")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const layer = tidNavigatorLayer(tenant);
  if (req.query.download) res.setHeader("Content-Disposition", 'attachment; filename="xorcism-tid-navigator-layer.json"');
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.send(JSON.stringify(layer, null, 2));
});

// POST /api/threat-informed-defense/plan-validation — close the validation gap: build a BAS
// emulation scenario scheduling the top-N untested high-threat techniques (Atomic Red Team).
router.post("/threat-informed-defense/plan-validation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTHREAT", "ATOMICTEST")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { limit?: unknown; tactic?: unknown };
  const limit = Number(b.limit) || 20;
  const tactic = b.tactic ? String(b.tactic) : undefined;
  const result = planTidValidation(limit, tactic);
  xid.addAudit({
    userId: req.user.UserID ?? null, action: "tid_plan_validation", resourceType: "emulation",
    resourceKey: String(result.scenarioId), detail: `created=${result.created} reused=${result.reused} techniques=${result.techniques.length}`, ip: clientIp(req),
  });
  res.json({ ok: true, ...result });
});

// POST /api/threat-informed-defense/generate-detection { techId } — remediate a detection gap
// (no-detection or proven false-coverage): draft a Sigma rule (local AI, deterministic skeleton
// fallback) and persist it to the SIGMARULE library, marked experimental + auto-draft. This adds
// detection *capability*; the false-coverage flag clears only once a re-run emulation proves it fires.
router.post("/threat-informed-defense/generate-detection", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTHREAT", "SIGMARULE")) return void res.status(403).json({ error: "forbidden" });
  const techId = String((req.body as { techId?: unknown })?.techId ?? "").trim().toUpperCase();
  if (!/^T\d{4}(\.\d{3})?$/.test(techId)) return void res.status(400).json({ error: "valid ATT&CK technique id required" });

  const xt = getDb("XTHREAT");
  const t = xt.prepare("SELECT Name FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1").get(techId) as { Name: string } | undefined;
  const name = t?.Name || techId;

  // Procedure-tuned context: the technique's atomic-test command + its latest emulation telemetry,
  // so the drafted rule detects what the test actually did (not a generic technique guess).
  let ctx: SigmaContext | undefined;
  try {
    const fam = techId.includes(".") ? techId.split(".")[0] : techId;
    const at = xt.prepare(
      `SELECT Command AS c, Executor AS e, Platform AS p FROM ATOMICTEST
       WHERE (AttackID = ? OR AttackID LIKE ?) AND Command IS NOT NULL AND Command != '' AND Command NOT LIKE '#%'
       ORDER BY (AttackID = ?) DESC, AtomicTestID LIMIT 1`
    ).get(techId, `${fam}.%`, techId) as { c: string; e: string; p: string } | undefined;
    let er: { o: string; d: string; n: string } | undefined;
    if (xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='EMULATIONRESULT'").get())
      er = xt.prepare(
        `SELECT Outcome AS o, DetectedBy AS d, Notes AS n FROM EMULATIONRESULT
         WHERE AttackID = ? OR AttackID LIKE ? ORDER BY EmulationResultID DESC LIMIT 1`
      ).get(techId, `${fam}.%`) as { o: string; d: string; n: string } | undefined;
    if (at?.c || er) ctx = { command: at?.c, executor: at?.e, platform: at?.p, outcome: er?.o, detectedBy: er?.d || undefined, telemetry: (er?.n || "").slice(0, 300) || undefined };
  } catch { /* context optional */ }

  let gen: { yaml: string; model: string; offline: boolean; tuned: boolean };
  try { gen = await suggestSigma(techId, name, ctx); }
  catch (e) { return void res.status(502).json({ error: String((e as Error).message || e) }); }

  const yaml = gen.yaml || "";
  const grab = (re: RegExp): string => (yaml.match(re)?.[1] || "").trim();
  const title = grab(/^title:\s*(.+)$/m) || `Detect ${techId} — ${name}`;
  const desc = grab(/^description:\s*(.+)$/m) || `Auto-drafted detection for ${techId} (${name}).`;
  const level = (grab(/^level:\s*(\w+)/m) || "medium").toLowerCase();
  const logsource = (yaml.match(/logsource:\s*\n([\s\S]*?)\n(?=\w)/)?.[1] || "").replace(/\s+/g, " ").trim().slice(0, 200);
  const ruleId = grab(/^id:\s*([0-9a-fA-F-]{8,})/m) || randomUUID();
  const now = new Date().toISOString();
  const r = xt.prepare(
    `INSERT INTO SIGMARULE (SigmaRuleGUID, SigmaRuleName, SigmaRuleDescription, SigmaYaml, LogSource, Level, Status, Author, SigmaReference, AttackTags, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).run(ruleId, title.slice(0, 300), desc.slice(0, 2000), yaml, logsource, level, "experimental", "XORCISM Threat-Informed Defense (auto-draft)", "tid-generated", techId, now);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "tid_generate_detection", resourceType: "sigma",
    resourceKey: techId, detail: `rule=${Number(r.lastInsertRowid)} model=${gen.model}${gen.offline ? " (skeleton)" : ""}${gen.tuned ? " tuned-to-procedure" : ""}`, ip: clientIp(req) });
  res.json({ ok: true, techId, name, ruleName: title, level, model: gen.model, offline: gen.offline, tuned: gen.tuned, sigmaRuleId: Number(r.lastInsertRowid) });
});

// POST /api/threat-informed-defense/schedule-revalidation { scenarioId, agent, cron? } — auto
// re-run a validation scenario on a cadence (XSCHEDULE) so drafts get proven without a manual
// re-run. The scheduler queues an agent emulation job each tick; the agent executes at check-in.
router.post("/threat-informed-defense/schedule-revalidation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTHREAT", "ATOMICTEST")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { scenarioId?: unknown; agent?: unknown; cron?: unknown };
  const scenarioId = Number(b.scenarioId) || 0;
  const agent = String(b.agent ?? "").trim();
  if (!scenarioId || !agent) return void res.status(400).json({ error: "scenarioId and agent required" });
  // default cadence: weekly, Monday 07:00 (server time). Accept a valid 5-field cron.
  const cron = (typeof b.cron === "string" && b.cron.trim().split(/\s+/).length === 5) ? b.cron.trim() : "0 7 * * 1";
  const scheduleId = createSchedule({ connector: "agent-emulate", params: { scenarioId, agent }, target: null, engagementId: null, worker: null, cron, userId: req.user.UserID ?? 0 });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "tid_schedule_revalidation", resourceType: "schedule",
    resourceKey: String(scheduleId), detail: `scenario=${scenarioId} agent=${agent} cron=${cron}`, ip: clientIp(req) });
  res.json({ ok: true, scheduleId, scenarioId, agent, cron });
});

export default router;
