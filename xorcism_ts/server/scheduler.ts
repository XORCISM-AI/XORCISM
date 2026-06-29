/**
 * scheduler.ts — Loop that fires scheduled tasks (XSCHEDULE).
 * Every ~30 s: for each enabled schedule whose cron matches the current
 * minute (and which has not already run this minute), a job is queued
 * (XJOB), after re-validating the engagement scope. The runner remains the
 * authoritative guard (re-checks the scope before executing).
 */
import { spawn } from "child_process";
import * as path from "path";
import {
  listEnabledSchedules, markScheduleRun, createJob, getEngagement, minuteOf, sqlNow,
  Schedule,
} from "./jobs";
import { createAgentJob } from "./agents";
import { matchCves } from "./cvematch";
import { controlAssurance, ensureAssuranceTables } from "./assurance";
import { recordAuditSnapshot } from "./auditpack";
import { listRegressionPdps, runAuthzTestSuite, recordSuiteRun, buildRequest, normalizeDecision, type DecisionRequest, type Decision } from "./authzgov";
import { dispatchEvent } from "./notifrules";
import { runScheduledBoardReports } from "./boardreport";
import { cronMatches } from "./cron";
import { targetInScope } from "./scope";
import * as xid from "./xid";

// Single-flight guard: never run two NVD imports at once (an hourly run that overruns is skipped).
let cveImportRunning = false;

// Spawn the Python NVD CVE importer (incremental --recent-only by default). Fire-and-forget,
// non-blocking; graceful if Python isn't on PATH (logs once, set XOR_PYTHON to override).
function runCveImport(s: Schedule): void {
  markScheduleRun(s.ScheduleID, 0, sqlNow()); // mark fired now → anti-duplicate within the minute
  if (cveImportRunning) { console.warn("[scheduler] NVD CVE import still running — skipping this hour"); return; }
  let p: { recentOnly?: boolean } = {};
  try { p = JSON.parse(s.params || "{}"); } catch { p = {}; }
  const py = process.env.XOR_PYTHON || "python";
  const repoRoot = path.resolve(__dirname, "../../..");
  const script = path.join(repoRoot, "xorcism_python", "importers", "import_nvd_cve.py");
  const args = [script];
  if (p.recentOnly !== false) args.push("--recent-only");
  if (process.env.NVD_API_KEY) args.push("--api-key", process.env.NVD_API_KEY);
  const env = { ...process.env, XORCISM_DB_DIR: process.env.DB_DIR || "C:/Users/jerom/XORCISM_databases" };
  cveImportRunning = true;
  const t0 = Date.now();
  console.log(`[scheduler] NVD CVE import starting (${py} import_nvd_cve.py ${args.slice(1).join(" ")})`);
  let child;
  try {
    child = spawn(py, args, { cwd: repoRoot, env, windowsHide: true });
  } catch (e) {
    cveImportRunning = false;
    console.warn(`[scheduler] NVD CVE import could not start: ${(e as Error).message} — set XOR_PYTHON to your python executable`);
    return;
  }
  let tail = "";
  const cap = (b: Buffer): void => { tail = (tail + b.toString()).slice(-2000); };
  child.stdout?.on("data", cap);
  child.stderr?.on("data", cap);
  const killTimer = setTimeout(() => { try { child!.kill(); } catch { /* already gone */ } }, 50 * 60 * 1000);
  if (typeof killTimer.unref === "function") killTimer.unref();
  child.on("error", (e) => {
    cveImportRunning = false; clearTimeout(killTimer);
    console.warn(`[scheduler] NVD CVE import failed: ${e.message} — is '${py}' on PATH? (set XOR_PYTHON)`);
  });
  child.on("close", (code) => {
    cveImportRunning = false; clearTimeout(killTimer);
    const secs = Math.round((Date.now() - t0) / 1000);
    const last = (tail.trim().split(/\r?\n/).pop() || "").slice(0, 200);
    console.log(`[scheduler] NVD CVE import finished (exit ${code}, ${secs}s)${last ? " · " + last : ""}`);
    xid.addAudit({ userId: s.created_by, action: "schedule_fire", resourceType: "importer",
      resourceKey: "import-nvd-cve", detail: `recent-only exit=${code} ${secs}s` });
    // Link the freshly-imported CVEs to assets by technology + raise "New CVEs for ASSET" alerts.
    if (code === 0) {
      try {
        const r = matchCves({ tenant: null });
        if (r.newLinks) console.log(`[cvematch] post-import: ${r.newLinks} new link(s) → ${r.assetsNotified} asset(s) notified (scanned ${r.cvesScanned})`);
      } catch (e) { console.warn(`[cvematch] post-import: ${(e as Error).message}`); }
    }
  });
}

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

  // Recurring NVD CVE import: spawn the Python importer (incremental --recent-only) every hour.
  if (s.connector === "import-nvd-cve") { runCveImport(s); return; }

  // Scheduled board report: generate per tenant + notify users (in-process, no job spawned).
  if (s.connector === "board-report") {
    markScheduleRun(s.ScheduleID, 0, sqlNow());
    try {
      let p: any = {}; try { p = JSON.parse(s.params || "{}"); } catch { p = {}; }
      const r = runScheduledBoardReports(p && p.tenant != null ? Number(p.tenant) : undefined);
      xid.addAudit({ userId: s.created_by, action: "board_report_scheduled", resourceType: "report", resourceKey: "board-report", detail: `${r.tenants} tenant(s), ${r.notified} user(s) notified` });
    } catch (e) { console.warn(`[scheduler] board-report failed: ${(e as Error).message}`); }
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

  // Continuous control monitoring: persist a global control-assurance snapshot so the page has a
  // trend + drift baseline even when nobody opens it (recordSnapshot throttles to one per 12 h).
  try { ensureAssuranceTables(); } catch { /* */ }
  const assureTick = (): void => { try { controlAssurance(null); } catch (e) { console.warn(`[assurance] snapshot: ${(e as Error).message}`); } };
  const bootT = setTimeout(assureTick, 60_000); if (typeof bootT.unref === "function") bootT.unref();
  const assureTimer = setInterval(assureTick, 6 * 3600_000); if (typeof assureTimer.unref === "function") assureTimer.unref();

  // Audit & accreditation package: persist a daily posture rollup so the package shows a trend over time.
  const auditTick = (): void => { try { recordAuditSnapshot(null); } catch (e) { console.warn(`[auditpack] snapshot: ${(e as Error).message}`); } };
  const auditBoot = setTimeout(auditTick, 90_000); if (typeof auditBoot.unref === "function") auditBoot.unref();
  const auditTimer = setInterval(auditTick, 24 * 3600_000); if (typeof auditTimer.unref === "function") auditTimer.unref();

  // API authorization: re-run the BOLA/BFLA battery against opted-in PDPs (RegressionEnabled + http endpoint),
  // persist a pass-rate trend and alert on regression. No-op when no PDP opts in.
  const authzRegressionTick = async (): Promise<void> => {
    try {
      const pdps = listRegressionPdps();
      for (const p of pdps) {
        const evaluate = async (engine: string, dr: DecisionRequest): Promise<{ decision: Decision; raw?: unknown }> => {
          try {
            const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 5000);
            const resp = await fetch(p.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(buildRequest(engine, dr)), signal: ctrl.signal });
            clearTimeout(to); const raw = await resp.json().catch(() => ({}));
            return { decision: normalizeDecision(engine, raw), raw };
          } catch { return { decision: "error" }; }
        };
        const report = await runAuthzTestSuite(p.tenant, { engine: p.engine, pdpId: p.pdpId, evaluate });
        const run = recordSuiteRun(p.tenant, { engine: p.engine, endpoint: p.endpoint, pdpId: p.pdpId, total: report.total, passed: report.passed, failed: report.failed, errors: report.errors, findings: report.findings.length }, "scheduled");
        if (run.regressed && report.findings.length) {
          try { dispatchEvent("authz.regression", { tenant: p.tenant, level: "warning", title: `Authorization regression: ${p.name}`, message: `${report.findings.length} BOLA/BFLA test(s) now allowed by the PDP (was ${run.prevFailed} fail, now ${report.failed}).`, link: "/authz-governance" }); } catch { /* best-effort */ }
        }
      }
    } catch (e) { console.warn(`[authz] regression: ${(e as Error).message}`); }
  };
  const authzBoot = setTimeout(() => void authzRegressionTick(), 120_000); if (typeof authzBoot.unref === "function") authzBoot.unref();
  const authzTimer = setInterval(() => void authzRegressionTick(), 24 * 3600_000); if (typeof authzTimer.unref === "function") authzTimer.unref();

  console.log("[scheduler] démarré (tick 30s)");
}
