/**
 * emulation.ts — BAS emulation run ingest (the XOR agent executes a scenario's atomic-test
 * injects and reports outcomes → EMULATIONRUN + EMULATIONRESULT). Closes the Threat-Informed
 * Defense loop: techniques move from "test defined" to "test executed / validated".
 *
 * Outcome vocabulary (EMULATIONRESULT.Outcome): Prevented / Blocked / Detected / Alerted /
 * Logged / Executed (ran, no defensive action observed) / Skipped (manual / unsafe — not run) /
 * Error. The agent determines Prevented vs Executed; "Detected" needs SIEM correlation
 * (recorded manually in DetectedBy), so the agent leaves it open.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface ScenarioTest {
  atomicTestId: number; name: string; attackId: string | null; attackTechniqueId: number | null;
  platform: string | null; executor: string | null; command: string | null; cleanup: string | null;
}
export interface EmulationResultItem {
  atomicTestId?: number; attackId?: string; outcome?: string; detectedBy?: string; notes?: string;
}
export interface EmulationRunSummary {
  runId: number; scenario: number; asset: string; assetId: number | null;
  stored: number; executed: number; prevented: number; skipped: number;
  score: number | null; byOutcome: Record<string, number>;
  drift: string[];        // techniques whose detection regressed this run (alerts raised)
}

function has(db: ReturnType<typeof getDb>, table: string): boolean {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); }
  catch { return false; }
}

/** The ordered atomic-test injects of an emulation scenario (for the agent to execute). */
export function scenarioTests(scenarioId: number): ScenarioTest[] {
  const xt = getDb("XTHREAT");
  if (!has(xt, "SCENARIOTEST") || !has(xt, "ATOMICTEST")) return [];
  return xt.prepare(
    `SELECT a.AtomicTestID AS atomicTestId, a.Name AS name, a.AttackID AS attackId,
            a.AttackTechniqueID AS attackTechniqueId, a.Platform AS platform, a.Executor AS executor,
            a.Command AS command, a.Cleanup AS cleanup
     FROM SCENARIOTEST s JOIN ATOMICTEST a ON a.AtomicTestID = s.AtomicTestID
     WHERE s.ScenarioID = ? ORDER BY COALESCE(s.StepOrder, s.ScenarioTestID)`
  ).all(scenarioId) as ScenarioTest[];
}

const DEFENSIVE = new Set(["prevented", "blocked", "detected", "alerted", "logged"]);

/** Detection drift = a technique that fired a detection on an EARLIER run but ran UNDETECTED on
 *  this one. Raise a Defender-aligned alert (XINCIDENT.ALERT), de-duplicated against any still-open
 *  drift alert for the same technique (so the weekly re-validation cron doesn't spam). Best-effort. */
function emitDriftAlerts(regressed: string[], scenarioId: number, asset: string, tenant: number | null, now: string): string[] {
  if (!regressed.length) return [];
  const raised: string[] = [];
  try {
    const xt = getDb("XTHREAT");
    const xi = getDb("XINCIDENT");
    if (!has(xi, "ALERT")) return [];
    const nameOf = xt.prepare("SELECT Name FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1");
    const lastDef = xt.prepare(
      `SELECT DetectedBy AS by, CreatedDate AS d FROM EMULATIONRESULT
       WHERE AttackID=? AND lower(COALESCE(Outcome,'')) IN ('detected','logged','prevented','blocked','alerted')
       ORDER BY EmulationResultID DESC LIMIT 1`);
    const open = xi.prepare(
      `SELECT 1 FROM ALERT WHERE AttackTechniques=? AND Category='Detection drift'
       AND COALESCE(Status,'') NOT IN ('Resolved','Closed','Dismissed','FalsePositive') LIMIT 1`);
    const ins = xi.prepare(
      `INSERT INTO ALERT (AlertGUID, AlertName, AlertDescription, CreatedDate, TenantID, Severity, Status,
        Category, AttackTechniques, RecommendedActions, ServiceSource, DetectionSource, Classification, Tags)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    for (const id of regressed) {
      if (open.get(id)) continue; // already an open drift alert for this technique
      const nm = (nameOf.get(id) as { Name?: string } | undefined)?.Name || id;
      const prev = lastDef.get(id) as { by?: string; d?: string } | undefined;
      const prevTxt = prev ? ` It last fired${prev.by ? ` via ${prev.by}` : ""}${prev.d ? ` on ${String(prev.d).slice(0, 16).replace("T", " ")}` : ""}.` : "";
      ins.run(
        randomUUID(),
        `Detection drift — ${id} ${nm} no longer detected`,
        `The detection for ${id} (${nm}) fired on an earlier emulation but the latest re-validation on "${asset}" (scenario #${scenarioId}) ran UNDETECTED.${prevTxt} A previously-proven detection has regressed — likely a rule edit, a broken/disabled log source, or an agent/sensor change.`,
        now, tenant, "High", "New", "Detection drift", id,
        `Review the Sigma rule and its log source for ${id}; confirm the sensor/agent is healthy, then re-run the validation to re-prove the detection.`,
        "XORCISM", "Threat-Informed Defense — BAS re-validation", "TruePositive",
        "detection-drift,threat-informed-defense",
      );
      raised.push(id);
    }
  } catch { /* alerting is best-effort; never break the ingest */ }
  return raised;
}

/** Persist an agent emulation run + per-inject outcomes; Score = % executed injects with a
 *  defensive action observed (prevented/detected/…). */
export function ingestEmulationRun(scenarioId: number, assetName: string, results: EmulationResultItem[], hintTenant: number | null): EmulationRunSummary {
  const xt = getDb("XTHREAT");
  const empty: EmulationRunSummary = { runId: 0, scenario: scenarioId, asset: assetName, assetId: null, stored: 0, executed: 0, prevented: 0, skipped: 0, score: null, byOutcome: {}, drift: [] };
  if (!has(xt, "EMULATIONRUN") || !has(xt, "EMULATIONRESULT")) return empty;
  const now = new Date().toISOString();

  // Baseline for drift detection: techniques that have EVER fired a detection PRIOR to this run.
  const priorDefensive = new Set<string>();
  try {
    for (const r of xt.prepare(`SELECT DISTINCT AttackID AS t FROM EMULATIONRESULT WHERE AttackID LIKE 'T%' AND lower(COALESCE(Outcome,'')) IN ('detected','logged','prevented','blocked','alerted')`).all() as { t: string }[])
      if (r.t) priorDefensive.add(String(r.t).toUpperCase());
  } catch { /* none */ }
  const ranDefensive = new Set<string>();   // techniques that fired defensively in THIS run
  const ranExecuted = new Set<string>();     // techniques that ran undetected in THIS run

  // resolve target asset (cross-DB, best-effort) for the run's TargetAssetID
  let assetId: number | null = null;
  try {
    const xo = getDb("XORCISM");
    const cols = new Set((xo.prepare(`PRAGMA table_info("ASSET")`).all() as { name: string }[]).map((c) => c.name));
    const tw = hintTenant != null && cols.has("TenantID") ? `AND TenantID = ${hintTenant}` : "";
    const r = xo.prepare(`SELECT AssetID FROM ASSET WHERE AssetName = ? ${tw} ORDER BY AssetID LIMIT 1`).get(assetName) as { AssetID: number } | undefined;
    assetId = r ? Number(r.AssetID) : null;
  } catch { /* no ASSET */ }

  const norm = (o: string): string => {
    const v = (o || "").trim().toLowerCase();
    if (DEFENSIVE.has(v)) return v.replace(/^\w/, (c) => c.toUpperCase());
    if (v === "executed" || v === "no result" || v === "ran") return "Executed";
    if (v === "skipped" || v === "manual" || v === "not executed") return "Skipped";
    if (v === "error" || v === "failed") return "Error";
    return o.trim() || "Executed";
  };

  const byOutcome: Record<string, number> = {};
  let executed = 0, prevented = 0, skipped = 0, defensive = 0, real = 0, stored = 0, runId = 0;

  const insRun = xt.prepare("INSERT INTO EMULATIONRUN (RunGUID, ScenarioID, Name, TargetAssetID, Status, RunDate, Score, CreatedDate) VALUES (?,?,?,?,?,?,?,?)");
  const insRes = xt.prepare("INSERT INTO EMULATIONRESULT (RunID, AtomicTestID, AttackID, Outcome, DetectedBy, Notes, CreatedDate) VALUES (?,?,?,?,?,?,?)");

  const tx = xt.transaction(() => {
    runId = Number(insRun.run(randomUUID(), scenarioId, `Agent run — ${assetName} — ${now.slice(0, 16).replace("T", " ")}`, assetId, "Completed", now, null, now).lastInsertRowid);
    for (const it of (results || []).slice(0, 2000)) {
      const outcome = norm(String(it.outcome ?? ""));
      const ov = outcome.toLowerCase();
      const techId = (it.attackId ?? "").toUpperCase() || null;
      byOutcome[outcome] = (byOutcome[outcome] || 0) + 1;
      if (ov === "skipped") skipped++;
      else {
        real++;
        if (DEFENSIVE.has(ov)) { defensive++; if (techId) ranDefensive.add(techId); }
        if (ov === "prevented" || ov === "blocked") prevented++;
        else if (ov === "executed") { executed++; if (techId) ranExecuted.add(techId); }
      }
      insRes.run(runId, it.atomicTestId ?? null, (it.attackId ?? "").toUpperCase() || null, outcome, (it.detectedBy ?? "") || null, (it.notes ?? "").slice(0, 2000) || null, now);
      stored++;
    }
    const score = real ? Math.round((defensive / real) * 100) : null;
    xt.prepare("UPDATE EMULATIONRUN SET Score = ? WHERE RunID = ?").run(score, runId);
  });
  tx();

  // Drift = ran undetected this run, had fired before, and did NOT fire (anywhere) this run → regression.
  const regressed = [...ranExecuted].filter((t) => priorDefensive.has(t) && !ranDefensive.has(t));
  const drift = emitDriftAlerts(regressed, scenarioId, assetName, hintTenant, now);

  return { runId, scenario: scenarioId, asset: assetName, assetId, stored, executed, prevented, skipped, score: real ? Math.round((defensive / real) * 100) : null, byOutcome, drift };
}
