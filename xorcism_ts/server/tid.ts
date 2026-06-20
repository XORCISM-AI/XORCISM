/**
 * tid.ts — Threat-Informed Defense cockpit.
 *
 * Operationalises MITRE's Threat-Informed Defense loop on top of XORCISM's ATT&CK data:
 * for every (top-level) ATT&CK technique it scores how much *adversaries* use it
 * (ecosystem prevalence from ATTACKRELATIONSHIP 'uses', boosted by local CTI/hunts) against
 * whether we **detect** it (Sigma rules), **mitigate** it (ATT&CK mitigations + D3FEND
 * countermeasures) and **test** it (Atomic Red Team). The result is a prioritised gap
 * worklist (high-threat techniques with the weakest defence) and a single program score —
 * "do we detect / mitigate / test what our adversaries actually do?".
 *
 * Pillars, all keyed on ATT&CK technique id (Txxxx), rolled sub-technique → parent:
 *   threat   : distinct adversary groups (G####) + software using the technique  ('uses')
 *   local    : local CTI references (INTELEXCHANGEATTACK) + hunts (HUNTATTACK)    (×3 weight)
 *   detect   : Sigma rules tagged with the technique (SIGMARULE.AttackTags)
 *   mitigate : ATT&CK 'mitigates' relationships + D3FEND countermeasures (D3FENDATTACKMAP)
 *   test     : Atomic Red Team tests (ATOMICTEST)
 * Read-only over XTHREAT.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface TidRow {
  id: string;            // AttackID (Txxxx, top-level)
  name: string;
  tactic: string;
  threat: number;        // # adversary groups using it (ecosystem prevalence)
  local: number;         // local CTI/hunt references
  procedures: number;    // total 'uses' relationships
  detect: number;        // Sigma rule count
  mitigate: number;      // ATT&CK mitigation + D3FEND count
  test: number;          // atomic test count (defined)
  validated: number;     // emulation results (executed/validated)
  emuDetected: boolean;  // the most recent emulation fired a detection/prevention (currently proven)
  detectionFailed: boolean; // has a detection rule, but the emulation ran UNDETECTED (rule never fired)
  detectionRegressed: boolean; // detection fired on an EARLIER run but the LATEST re-validation ran undetected (drift)
  pillars: number;       // 0-3 defensive pillars present
  priority: number;      // threat + local*3
  gapScore: number;      // priority * (3 - pillars)  (higher = worse)
  status: "covered" | "partial" | "exposed" | "untargeted";
  gaps: string[];        // which pillars are missing
}
export interface TidFinding {
  id: string;
  name: string;
  tactic: string;
  severity: "High" | "Medium" | "Low";
  reason: string;
  label: string;
}
export interface TidInventory {
  rows: TidRow[];
  findings: TidFinding[];
  summary: {
    techniques: number; threatRelevant: number;
    detected: number; mitigated: number; tested: number; validated: number;
    detectionProven: number; detectionFailed: number; detectionRegressed: number;
    fullyCovered: number; exposed: number;
    detectRate: number; mitigateRate: number; testRate: number; validatedRate: number;
    tidScore: number;                 // 0-100 threat-weighted defence coverage
    sigmaRules: number; atomicTests: number; d3fendCountermeasures: number; adversaryGroups: number;
    byTactic: { tactic: string; techniques: number; detect: number; mitigate: number; test: number; threat: number }[];
  };
}

const EMPTY: TidInventory = {
  rows: [], findings: [],
  summary: {
    techniques: 0, threatRelevant: 0, detected: 0, mitigated: 0, tested: 0, validated: 0,
    detectionProven: 0, detectionFailed: 0, detectionRegressed: 0, fullyCovered: 0, exposed: 0,
    detectRate: 0, mitigateRate: 0, testRate: 0, validatedRate: 0, tidScore: 0,
    sigmaRules: 0, atomicTests: 0, d3fendCountermeasures: 0, adversaryGroups: 0, byTactic: [],
  },
};

const ROW_CAP = 160;
const TXX = /T\d{4}(?:\.\d{3})?/g;

function has(db: ReturnType<typeof getDb>, table: string): boolean {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); }
  catch { return false; }
}
function colset(db: ReturnType<typeof getDb>, table: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
const parentOf = (id: string): string => (id.includes(".") ? id.split(".")[0] : id);

/** Full Threat-Informed Defense scorecard (technique-level, sub → parent rollup). */
export function tidInventory(_tenant: number | null): TidInventory {
  let xt;
  try { xt = getDb("XTHREAT"); } catch { return { ...EMPTY }; }
  if (!has(xt, "ATTACKTECHNIQUE") || !has(xt, "ATTACKRELATIONSHIP")) return { ...EMPTY };

  // ── techniques (top-level enterprise, non-deprecated) + tactic ──────────────
  const techs = xt.prepare(
    `SELECT AttackTechniqueID AS tid, AttackID AS id, Name AS name, IsSubtechnique AS sub, ParentAttackID AS parent
     FROM ATTACKTECHNIQUE WHERE Domain='enterprise' AND COALESCE(Deprecated,0)=0 AND COALESCE(Revoked,0)=0 AND AttackID LIKE 'T%'`
  ).all() as { tid: number; id: string; name: string; sub: number; parent: string | null }[];
  if (!techs.length) return { ...EMPTY };

  const tacticOf = new Map<number, string>();      // AttackTechniqueID → primary tactic short name
  if (has(xt, "ATTACKTECHNIQUETACTIC")) {
    for (const r of xt.prepare("SELECT AttackTechniqueID AS tid, TacticShortName AS t FROM ATTACKTECHNIQUETACTIC").all() as { tid: number; t: string }[])
      if (!tacticOf.has(Number(r.tid)) && r.t) tacticOf.set(Number(r.tid), String(r.t));
  }
  const niceTactic = (s: string): string => (s || "—").replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  // family head per AttackID (sub → parent); only top-level heads become rows
  const headName = new Map<string, string>();      // headId → name
  const headTactic = new Map<string, string>();
  const allTechIds = new Set<string>();
  for (const t of techs) {
    allTechIds.add(t.id);
    if (!t.sub) { headName.set(t.id, t.name); headTactic.set(t.id, niceTactic(tacticOf.get(Number(t.tid)) || "")); }
  }
  // a sub whose parent row is missing still needs a head — fall back to itself
  const head = (id: string): string => {
    const p = parentOf(id);
    return headName.has(p) ? p : (headName.has(id) ? id : p);
  };

  // accumulator per head
  type Acc = { groups: Set<string>; uses: number; local: number; detect: number; mitigate: number; test: number; validated: number; emuDef: number; emuExec: number; lastDef: number; lastExec: number };
  const acc = new Map<string, Acc>();
  const newAcc = (): Acc => ({ groups: new Set(), uses: 0, local: 0, detect: 0, mitigate: 0, test: 0, validated: 0, emuDef: 0, emuExec: 0, lastDef: 0, lastExec: 0 });
  const get = (id: string): Acc => {
    const h = head(id);
    let a = acc.get(h);
    if (!a) { a = newAcc(); acc.set(h, a); }
    return a;
  };

  // ── threat usage (ATTACKRELATIONSHIP 'uses' → technique) ────────────────────
  let adversaryGroups = new Set<string>();
  for (const r of xt.prepare("SELECT SourceAttackID AS s, TargetAttackID AS t FROM ATTACKRELATIONSHIP WHERE RelationshipType='uses' AND TargetAttackID LIKE 'T%'").all() as { s: string; t: string }[]) {
    if (!allTechIds.has(r.t) && !allTechIds.has(parentOf(r.t))) continue;
    const a = get(r.t); a.uses++;
    if (typeof r.s === "string" && r.s.startsWith("G")) { a.groups.add(r.s); adversaryGroups.add(r.s); }
  }
  // ── mitigation (ATT&CK 'mitigates' + D3FEND) ────────────────────────────────
  for (const r of xt.prepare("SELECT TargetAttackID AS t FROM ATTACKRELATIONSHIP WHERE RelationshipType='mitigates' AND TargetAttackID LIKE 'T%'").all() as { t: string }[])
    get(r.t).mitigate++;
  if (has(xt, "D3FENDATTACKMAP"))
    for (const r of xt.prepare("SELECT AttackID AS t FROM D3FENDATTACKMAP WHERE AttackID LIKE 'T%'").all() as { t: string }[])
      get(r.t).mitigate++;
  // ── detection (Sigma rules tagged with the technique) ───────────────────────
  let sigmaRules = 0;
  if (has(xt, "SIGMARULE")) {
    for (const r of xt.prepare("SELECT AttackTags AS tags FROM SIGMARULE WHERE AttackTags IS NOT NULL AND AttackTags != ''").all() as { tags: string }[]) {
      sigmaRules++;
      const seen = new Set<string>();
      for (const m of String(r.tags).toUpperCase().match(TXX) || []) { const h = head(m); if (!seen.has(h)) { seen.add(h); get(m).detect++; } }
    }
  }
  // ── test (Atomic Red Team) ──────────────────────────────────────────────────
  let atomicTests = 0;
  if (has(xt, "ATOMICTEST"))
    for (const r of xt.prepare("SELECT AttackID AS t FROM ATOMICTEST WHERE AttackID LIKE 'T%'").all() as { t: string }[]) { atomicTests++; get(r.t).test++; }
  // ── validated (BAS emulation executed) + detection outcome (did detection actually fire?) ──
  // EmulationResultID is monotonic (rowid) → its max per technique tells us the *latest* outcome,
  // which separates "currently proven" (latest fired) from "drift" (fired before, latest missed).
  const EMU_DEFENSIVE = new Set(["detected", "logged", "prevented", "blocked", "alerted"]);
  if (has(xt, "EMULATIONRESULT")) {
    for (const r of xt.prepare("SELECT EmulationResultID AS rid, AttackID AS t, COALESCE(Outcome,'') AS o FROM EMULATIONRESULT WHERE AttackID LIKE 'T%'").all() as { rid: number; t: string; o: string }[]) {
      const o = String(r.o).toLowerCase().trim();
      if (o === "" || o === "skipped" || o === "manual" || o === "error") continue;
      const a = get(r.t); const rid = Number(r.rid) || 0;
      a.validated++;
      if (EMU_DEFENSIVE.has(o)) { a.emuDef++; if (rid > a.lastDef) a.lastDef = rid; }
      else if (o === "executed") { a.emuExec++; if (rid > a.lastExec) a.lastExec = rid; }
    }
  }
  // ── local CTI / hunts (your environment → heavier weight) ───────────────────
  if (has(xt, "INTELEXCHANGEATTACK"))
    for (const r of xt.prepare("SELECT AttackID AS t FROM INTELEXCHANGEATTACK WHERE AttackID LIKE 'T%'").all() as { t: string }[]) get(r.t).local++;
  if (has(xt, "HUNTATTACK")) {
    const hc = colset(xt, "HUNTATTACK");
    const col = hc.has("AttackID") ? "AttackID" : null;
    if (col) for (const r of xt.prepare(`SELECT ${col} AS t FROM HUNTATTACK WHERE ${col} LIKE 'T%'`).all() as { t: string }[]) get(r.t).local++;
  }
  const d3fendCountermeasures = has(xt, "D3FENDTECHNIQUE") ? (xt.prepare("SELECT COUNT(*) AS n FROM D3FENDTECHNIQUE").get() as { n: number }).n : 0;

  // ── build rows (top-level techniques) ───────────────────────────────────────
  const rows: TidRow[] = [];
  for (const [id, name] of headName) {
    const a = acc.get(id) ?? newAcc();
    const threat = a.groups.size, local = a.local;
    const priority = threat + local * 3;
    const pillars = (a.detect > 0 ? 1 : 0) + (a.mitigate > 0 ? 1 : 0) + (a.test > 0 ? 1 : 0);
    // "drift": the rule fired on an earlier run but the most recent re-validation ran undetected.
    const detectionRegressed = a.lastDef > 0 && a.lastExec > a.lastDef;
    // "currently proven": the most recent decisive emulation result was a defensive action.
    const emuDetected = a.lastDef > 0 && a.lastDef >= a.lastExec;
    // "false coverage": a detection rule exists, the technique was emulated, but it NEVER fired.
    const detectionFailed = a.detect > 0 && a.emuExec > 0 && a.emuDef === 0;
    const gaps = [a.detect ? "" : "no detection", a.test ? "" : "not tested", a.mitigate ? "" : "no mitigation",
      (a.test && !a.validated) ? "test not executed" : "", detectionFailed ? "detection didn't fire" : "",
      detectionRegressed ? "detection regressed" : ""].filter(Boolean);
    const status: TidRow["status"] = priority === 0 ? "untargeted" : pillars === 3 ? "covered" : pillars === 0 ? "exposed" : "partial";
    rows.push({
      id, name, tactic: headTactic.get(id) || "—",
      threat, local, procedures: a.uses, detect: a.detect, mitigate: a.mitigate, test: a.test, validated: a.validated,
      emuDetected, detectionFailed, detectionRegressed,
      pillars, priority, gapScore: priority * (3 - pillars), status, gaps,
    });
  }

  // ── summary over threat-relevant (priority ≥ 1) techniques ──────────────────
  const tr = rows.filter((r) => r.priority > 0);
  const detected = tr.filter((r) => r.detect > 0).length;
  const mitigated = tr.filter((r) => r.mitigate > 0).length;
  const tested = tr.filter((r) => r.test > 0).length;
  const validated = tr.filter((r) => r.validated > 0).length;
  const pct = (n: number) => (tr.length ? Math.round((n / tr.length) * 100) : 0);
  const wSum = tr.reduce((s, r) => s + r.priority, 0);
  const tidScore = wSum ? Math.round((tr.reduce((s, r) => s + r.priority * (r.pillars / 3), 0) / wSum) * 100) : 0;

  // by-tactic coverage (threat-relevant)
  const tac = new Map<string, { techniques: number; detect: number; mitigate: number; test: number; threat: number }>();
  for (const r of tr) {
    const k = r.tactic || "—";
    const v = tac.get(k) ?? { techniques: 0, detect: 0, mitigate: 0, test: 0, threat: 0 };
    v.techniques++; v.detect += r.detect > 0 ? 1 : 0; v.mitigate += r.mitigate > 0 ? 1 : 0; v.test += r.test > 0 ? 1 : 0; v.threat += r.threat;
    tac.set(k, v);
  }
  const byTactic = [...tac.entries()].map(([tactic, v]) => ({ tactic, ...v })).sort((a, b) => b.threat - a.threat);

  // ── findings: prioritised gaps (high threat × weak defence) ─────────────────
  const findings: TidFinding[] = [];
  for (const r of tr) {
    if (r.gapScore <= 0) continue;
    let sev: TidFinding["severity"], reason: string, label: string;
    if (r.pillars === 0) { sev = "High"; reason = "exposed"; label = `${r.id} ${r.name} — used by ${r.threat} adversary group(s), NO detection / mitigation / test`; }
    else if (r.detect === 0) { sev = r.threat >= 20 ? "High" : "Medium"; reason = "no-detection"; label = `${r.id} ${r.name} — ${r.threat} adversary group(s), no Sigma detection`; }
    else if (r.test === 0) { sev = "Medium"; reason = "not-tested"; label = `${r.id} ${r.name} — ${r.threat} adversary group(s), detected but never validated by a test`; }
    else { sev = "Low"; reason = "no-mitigation"; label = `${r.id} ${r.name} — ${r.threat} adversary group(s), no mitigation mapped`; }
    findings.push({ id: r.id, name: r.name, tactic: r.tactic, severity: sev, reason, label });
  }
  // "false coverage": detection rule exists but the emulation proved it didn't fire (any gapScore).
  for (const r of tr) {
    if (r.detectionFailed)
      findings.push({ id: r.id, name: r.name, tactic: r.tactic, severity: "High", reason: "detection-failed", label: `${r.id} ${r.name} — ${r.threat} group(s): has a detection rule but the emulation ran UNDETECTED — the rule did not fire (false coverage)` });
  }
  // "drift": detection that USED to fire stopped firing on the latest re-validation — the regression
  // the scheduled re-validation exists to catch (rule edit, broken log source, agent/config change).
  for (const r of tr) {
    if (r.detectionRegressed)
      findings.push({ id: r.id, name: r.name, tactic: r.tactic, severity: "High", reason: "detection-regressed", label: `${r.id} ${r.name} — ${r.threat} group(s): detection DRIFT — the rule fired on an earlier emulation but the latest re-validation ran UNDETECTED (regression)` });
  }
  const SEV: Record<string, number> = { High: 0, Medium: 1, Low: 2 };
  findings.sort((a, b) => SEV[a.severity] - SEV[b.severity] || (rows.find((r) => r.id === b.id)?.gapScore ?? 0) - (rows.find((r) => r.id === a.id)?.gapScore ?? 0));

  rows.sort((a, b) => b.gapScore - a.gapScore || b.priority - a.priority || a.id.localeCompare(b.id));

  return {
    rows: rows.slice(0, ROW_CAP),
    findings: findings.slice(0, 120),
    summary: {
      techniques: rows.length, threatRelevant: tr.length,
      detected, mitigated, tested, validated,
      detectionProven: tr.filter((r) => r.emuDetected).length,
      detectionFailed: tr.filter((r) => r.detectionFailed).length,
      detectionRegressed: tr.filter((r) => r.detectionRegressed).length,
      fullyCovered: tr.filter((r) => r.pillars === 3).length,
      exposed: tr.filter((r) => r.pillars === 0).length,
      detectRate: pct(detected), mitigateRate: pct(mitigated), testRate: pct(tested), validatedRate: pct(validated),
      tidScore,
      sigmaRules, atomicTests, d3fendCountermeasures, adversaryGroups: adversaryGroups.size,
      byTactic,
    },
  };
}

/** Export the Threat-Informed Defense program as a MITRE ATT&CK Navigator layer (v4.5):
 *  score = adversary prevalence, colour = defence status (red=false-coverage/exposed,
 *  amber=partial, green=covered), with per-technique comment + metadata. */
export function tidNavigatorLayer(tenant: number | null): Record<string, unknown> {
  const inv = tidInventory(tenant);
  const C = { failed: "#b91c1c", exposed: "#7f1d1d", partial: "#a16207", covered: "#15803d", none: "" };
  const techniques = inv.rows.map((r) => {
    const color = r.detectionFailed ? C.failed : r.status === "exposed" ? C.exposed : r.status === "covered" ? C.covered : r.status === "partial" ? C.partial : C.none;
    const testTxt = r.validated ? "✓ executed" : r.test ? "~ defined" : "✗";
    const comment = `Threat: ${r.threat} group(s)${r.local ? ` +${r.local} local` : ""} · Detect ${r.detect ? "✓" : "✗"} · Mitigate ${r.mitigate ? "✓" : "✗"} · Test ${testTxt}`
      + (r.detectionFailed ? " · ⚠ FALSE COVERAGE: detection rule did not fire when tested" : "");
    return {
      techniqueID: r.id, score: r.priority, color, comment, enabled: true,
      metadata: [
        { name: "Adversary groups", value: String(r.threat) },
        { name: "Local CTI / hunts", value: String(r.local) },
        { name: "Detection (Sigma rules)", value: String(r.detect) },
        { name: "Mitigation (D3FEND + ATT&CK)", value: String(r.mitigate) },
        { name: "Test (atomic, defined)", value: String(r.test) },
        { name: "Validated (executed)", value: String(r.validated) },
        { name: "Detection proven", value: r.emuDetected ? "yes" : r.detectionFailed ? "NO — false coverage" : "untested" },
      ],
      showSubtechniques: false,
    };
  });
  const s = inv.summary;
  const maxScore = Math.max(10, ...inv.rows.map((r) => r.priority));
  return {
    name: "XORCISM — Threat-Informed Defense",
    versions: { attack: "16", navigator: "4.9.1", layer: "4.5" },
    domain: "enterprise-attack",
    description: `Threat-Informed Defense coverage. Score = adversary prevalence; colour = defence status. `
      + `TID program score ${s.tidScore}; detect ${s.detectRate}% / mitigate ${s.mitigateRate}% / test ${s.testRate}% (executed ${s.validatedRate}%); `
      + `${s.detectionFailed} false-coverage technique(s). Generated ${new Date().toISOString().slice(0, 10)} by XORCISM.`,
    techniques,
    gradient: { colors: ["#ffffff", "#fde68a", "#fca5a5", "#dc2626"], minValue: 0, maxValue: maxScore },
    legendItems: [
      { label: "False coverage (rule didn't fire)", color: C.failed },
      { label: "Exposed (no defence)", color: C.exposed },
      { label: "Partial coverage", color: C.partial },
      { label: "Covered (detect+mitigate+test)", color: C.covered },
    ],
    metadata: [
      { name: "TID program score", value: String(s.tidScore) },
      { name: "Threat-relevant techniques", value: String(s.threatRelevant) },
      { name: "Detect / Mitigate / Test", value: `${s.detectRate}% / ${s.mitigateRate}% / ${s.testRate}%` },
      { name: "Validated (executed)", value: `${s.validatedRate}%` },
      { name: "False coverage", value: String(s.detectionFailed) },
    ],
    showTacticRowBackground: true,
    tacticRowBackground: "#1f2937",
    selectTechniquesAcrossTactics: true,
    sorting: 3,
    hideDisabled: false,
  };
}

export interface TidPlanResult {
  scenarioId: number; name: string; created: number; reused: number;
  techniques: { id: string; name: string; threat: number; reused: boolean }[];
}

/**
 * Close the validation gap: turn the highest-threat *untested* ATT&CK techniques into a
 * scheduled BAS plan. Creates one EMULATIONSCENARIO and, per technique, links an existing
 * ATOMICTEST when one exists or creates a manual-validation inject (Source='tid-validation-plan')
 * — so the technique counts as "tested" (a test now exists) and the team has an executable backlog.
 */
export function planTidValidation(limit = 20, tacticFilter?: string): TidPlanResult {
  const inv = tidInventory(null);
  let cands = inv.rows.filter((r) => r.priority > 0 && r.test === 0);
  if (tacticFilter) cands = cands.filter((r) => r.tactic.toLowerCase() === tacticFilter.toLowerCase());
  cands.sort((a, b) => b.priority - a.priority || b.gapScore - a.gapScore);
  cands = cands.slice(0, Math.max(1, Math.min(100, limit || 20)));
  if (!cands.length) return { scenarioId: 0, name: "", created: 0, reused: 0, techniques: [] };

  const xt = getDb("XTHREAT");
  if (!has(xt, "EMULATIONSCENARIO") || !has(xt, "ATOMICTEST") || !has(xt, "SCENARIOTEST"))
    return { scenarioId: 0, name: "", created: 0, reused: 0, techniques: [] };

  const now = new Date().toISOString();
  const date = now.slice(0, 10);
  const tac: Record<string, number> = {};
  for (const r of cands) tac[r.tactic] = (tac[r.tactic] || 0) + 1;
  const phase = Object.entries(tac).sort((a, b) => b[1] - a[1])[0]?.[0] || "Multiple";
  const name = `Threat-Informed validation plan — ${date}`;
  const desc = `Auto-generated from the Threat-Informed Defense cockpit: validation injects for the ${cands.length} highest-threat ATT&CK technique(s) you detect or are exposed to but have never tested. Execute via your BAS / red team and record each outcome (Prevented / Detected / …) in EMULATIONRESULT.`;

  const techIdByAttack = new Map<string, number>();
  for (const r of xt.prepare("SELECT AttackID, AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID LIKE 'T%'").all() as { AttackID: string; AttackTechniqueID: number }[])
    techIdByAttack.set(r.AttackID, Number(r.AttackTechniqueID));
  const existing = new Map<string, number>();
  for (const r of xt.prepare("SELECT AttackID, MIN(AtomicTestID) AS id FROM ATOMICTEST WHERE AttackID LIKE 'T%' GROUP BY AttackID").all() as { AttackID: string; id: number }[])
    existing.set(r.AttackID, Number(r.id));
  const detectOf = new Map<string, number>();
  for (const r of inv.rows) detectOf.set(r.id, r.detect);

  const insScenario = xt.prepare("INSERT INTO EMULATIONSCENARIO (ScenarioGUID, Name, Description, AdversaryRef, KillChainPhase, Status, CreatedDate) VALUES (?,?,?,?,?,?,?)");
  const insTest = xt.prepare("INSERT INTO ATOMICTEST (AtomicGUID, Name, Description, AttackID, AttackTechniqueID, Platform, Executor, Command, Cleanup, Source, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
  const insLink = xt.prepare("INSERT INTO SCENARIOTEST (ScenarioID, AtomicTestID, StepOrder, CreatedDate) VALUES (?,?,?,?)");

  let scenarioId = 0, created = 0, reused = 0, order = 0;
  const techniques: TidPlanResult["techniques"] = [];
  const tx = xt.transaction(() => {
    scenarioId = Number(insScenario.run(randomUUID(), name, desc, "threat-informed-defense", phase, "Planned", now).lastInsertRowid);
    for (const r of cands) {
      let testId = existing.get(r.id);
      const wasReused = testId != null;
      if (wasReused) { reused++; }
      else {
        const sc = detectOf.get(r.id) ?? 0;
        const tName = `Validate ${r.id} — ${r.name}`;
        const tDesc = `Threat-Informed Defense validation inject. ${r.id} (${r.name}) is used by ${r.threat} adversary group(s)${r.detect ? ` and you have ${sc} Sigma rule(s) tagged ${r.id}` : ", with no detection yet"}, but it has never been tested. Execute a known procedure (e.g. an Atomic Red Team test) for this technique and confirm your detection/prevention fires; record the outcome in EMULATIONRESULT.`;
        const cmd = `# Manual validation of ${r.id} (${r.name}). Run an Atomic Red Team test — https://attack.mitre.org/techniques/${r.id.replace(".", "/")}/ — and verify your SIEM / EDR alerts on it.`;
        testId = Number(insTest.run(randomUUID(), tName, tDesc, r.id, techIdByAttack.get(r.id) ?? null, "multi", "manual", cmd, "", "tid-validation-plan", now).lastInsertRowid);
        created++;
      }
      insLink.run(scenarioId, testId, ++order, now);
      techniques.push({ id: r.id, name: r.name, threat: r.threat, reused: wasReused });
    }
  });
  tx();
  return { scenarioId, name, created, reused, techniques };
}
