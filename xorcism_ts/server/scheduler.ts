/**
 * scheduler.ts — Loop that fires scheduled tasks (XSCHEDULE).
 * Every ~30 s: for each enabled schedule whose cron matches the current
 * minute (and which has not already run this minute), a job is queued
 * (XJOB), after re-validating the engagement scope. The runner remains the
 * authoritative guard (re-checks the scope before executing).
 */
import {
  listEnabledSchedules, markScheduleRun, createJob, getEngagement, minuteOf, sqlNow,
  Schedule,
} from "./jobs";
import { createAgentJob } from "./agents";
import { cronMatches } from "./cron";
import { targetInScope } from "./scope";
import * as xid from "./xid";

function scopeHost(target: string): string {
  try {
    const u = new URL(target);
    return u.hostname || target;
  } catch {
    return target;
  }
}

function fireSchedule(s: Schedule, nowMin: string): void {
  // Anti-duplicate: already fired during this minute?
  if (minuteOf(s.last_run_at) === nowMin) return;

  // Threat-Informed Defense auto-re-validation: queue an AGENT emulation job (not a connector
  // job) so a validation scenario's injects are re-run on a cadence — the agent (opt-in
  // XOR_ALLOW_EMULATION=1) re-attributes detection and the cockpit's validated/false-coverage
  // signals refresh without a manual re-run.
  if (s.connector === "agent-emulate") {
    let p: { scenarioId?: number; agent?: string } = {};
    try { p = JSON.parse(s.params || "{}"); } catch { p = {}; }
    if (!p.scenarioId || !p.agent) {
      console.warn(`[scheduler] agent-emulate schedule ${s.ScheduleID} ignoré : scenarioId/agent manquant`);
      return;
    }
    const jobId = createAgentJob(String(p.agent), "emulate", { scenarioId: Number(p.scenarioId) }, s.created_by ?? null);
    markScheduleRun(s.ScheduleID, jobId, sqlNow());
    xid.addAudit({ userId: s.created_by, action: "schedule_fire", resourceType: "agent",
      resourceKey: String(p.agent), detail: `re-validate scenario=${p.scenarioId} job=${jobId} cron=${s.cron}` });
    console.log(`[scheduler] schedule ${s.ScheduleID} (agent-emulate) → agent job ${jobId} (scenario ${p.scenarioId} on ${p.agent})`);
    return;
  }

  // Recurring OVAL scan: queue an AGENT OVAL job on a cadence (Configuration Management →
  // "Schedule recurring scan"). The agent runs OpenSCAP/native OVAL of the chosen class at its
  // next check-in and posts results to XOVAL — no manual re-trigger needed.
  if (s.connector === "agent-oval") {
    let p: { agent?: string; ovalClass?: string } = {};
    try { p = JSON.parse(s.params || "{}"); } catch { p = {}; }
    if (!p.agent) {
      console.warn(`[scheduler] agent-oval schedule ${s.ScheduleID} ignoré : agent manquant`);
      return;
    }
    const oc = p.ovalClass && p.ovalClass !== "all" ? { ovalClass: String(p.ovalClass) } : {};
    const jobId = createAgentJob(String(p.agent), "oval", oc, s.created_by ?? null);
    markScheduleRun(s.ScheduleID, jobId, sqlNow());
    xid.addAudit({ userId: s.created_by, action: "schedule_fire", resourceType: "agent",
      resourceKey: String(p.agent), detail: `oval class=${p.ovalClass ?? "all"} job=${jobId} cron=${s.cron}` });
    console.log(`[scheduler] schedule ${s.ScheduleID} (agent-oval) → agent job ${jobId} (oval ${p.ovalClass ?? "all"} on ${p.agent})`);
    return;
  }

  // Re-validate the scope if the schedule targets something with an engagement.
  if (s.target) {
    if (!s.engagement_id) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : cible sans engagement`);
      return;
    }
    const eng = getEngagement(s.engagement_id);
    if (!eng || !eng.active) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : engagement inactif/introuvable`);
      return;
    }
    let scope: string[] = [];
    try { scope = JSON.parse(eng.scope || "[]"); } catch { scope = []; }
    if (!targetInScope(scopeHost(s.target), scope)) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : cible hors périmètre`);
      xid.addAudit({ userId: s.created_by, action: "schedule_out_of_scope", resourceType: "connector",
        resourceKey: s.connector, detail: `schedule=${s.ScheduleID} target=${s.target}` });
      return;
    }
  }

  let params: unknown = {};
  try { params = JSON.parse(s.params || "{}"); } catch { params = {}; }
  const jobId = createJob(s.connector, params, s.target, s.created_by ?? 0, s.engagement_id, s.worker);
  markScheduleRun(s.ScheduleID, jobId, sqlNow());
  xid.addAudit({ userId: s.created_by, action: "schedule_fire", resourceType: "connector",
    resourceKey: s.connector, detail: `schedule=${s.ScheduleID} job=${jobId} cron=${s.cron}` });
  console.log(`[scheduler] schedule ${s.ScheduleID} (${s.connector}) → job ${jobId}`);
}

export function tickSchedules(now = new Date()): void {
  const nowMin = sqlNow().slice(0, 16);
  for (const s of listEnabledSchedules()) {
    try {
      if (cronMatches(s.cron, now)) fireSchedule(s, nowMin);
    } catch (e) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} erreur : ${(e as Error).message}`);
    }
  }
}

let timer: NodeJS.Timeout | null = null;

export function startScheduler(): void {
  if (timer) return;
  // Every 30 s (cron has a one-minute granularity; the anti-duplicate check avoids
  // double firing between two ticks within the same minute).
  timer = setInterval(() => {
    try { tickSchedules(); } catch (e) { console.warn(`[scheduler] tick: ${(e as Error).message}`); }
  }, 30_000);
  if (typeof timer.unref === "function") timer.unref();
  console.log("[scheduler] démarré (tick 30s)");
}
