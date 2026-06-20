/**
 * threat-informed-defense.ts — Threat-Informed Defense cockpit (/threat-informed-defense).
 * ATT&CK technique coverage (adversary use vs detect/mitigate/test) from
 * /api/threat-informed-defense. Read-only.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { id: string; name: string; tactic: string; threat: number; local: number; procedures: number; detect: number; mitigate: number; test: number; validated: number; emuDetected: boolean; detectionFailed: boolean; detectionRegressed: boolean; pillars: number; priority: number; gapScore: number; status: string; gaps: string[]; }
interface Finding { id: string; name: string; tactic: string; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Tactic { tactic: string; techniques: number; detect: number; mitigate: number; test: number; threat: number; }
interface Inventory {
  rows: Row[]; findings: Finding[];
  summary: { techniques: number; threatRelevant: number; detected: number; mitigated: number; tested: number; validated: number; detectionProven: number; detectionFailed: number; detectionRegressed: number; fullyCovered: number; exposed: number; detectRate: number; mitigateRate: number; testRate: number; validatedRate: number; tidScore: number; sigmaRules: number; atomicTests: number; d3fendCountermeasures: number; adversaryGroups: number; byTactic: Tactic[]; };
}

const rateColor = (n: number): string => (n >= 70 ? "#34d399" : n >= 40 ? "#fbbf24" : "#f87171");
const gapClass = (n: number): string => (n >= 30 ? "g-hi" : n >= 10 ? "g-md" : "g-lo");

function card(lbl: string, val: string, foot: string, color?: string, cls = "ti-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

const pill = (on: number, label: string): string => `<span class="pill ${on ? "p-on" : "p-off"}" title="${on ? on + " " + label : "no " + label}">${label[0]}</span>`;
// Detect pillar: drift — fired before, latest re-validation missed (orange D↓, most urgent) >
// fired in emulation (green D✓) > rule exists but emulation ran undetected = false coverage (red D⚠) >
// rule exists, untested (green D) > no rule (red D)
const detectPill = (r: Row): string => r.detectionRegressed
  ? `<span class="pill p-drift" title="detection DRIFT — the rule fired on an earlier run but the latest re-validation ran UNDETECTED (regression)">D↓</span>`
  : r.emuDetected ? `<span class="pill p-on" title="detection fired when emulated">D✓</span>`
  : r.detectionFailed ? `<span class="pill p-fail" title="detection rule exists but the emulation ran UNDETECTED — the rule did not fire">D⚠</span>`
  : pill(r.detect, "Detect");
// Test pillar is tri-state: executed/validated (green) > defined-only (amber) > none (red)
const testPill = (r: Row): string => r.validated
  ? `<span class="pill p-on" title="${r.validated} executed test result(s)">T✓</span>`
  : r.test ? `<span class="pill p-mid" title="${r.test} test(s) defined, not yet executed">T</span>`
  : `<span class="pill p-off" title="no test">T</span>`;

function rowHtml(r: Row): string {
  return `<tr>
    <td><div class="tname">${esc(r.id)} <span style="font-weight:400">${esc(r.name)}</span></div>
      <div class="muted" style="font-size:11px">${esc(r.tactic)}</div></td>
    <td>${r.threat}${r.local ? ` <span class="tid" title="local CTI/hunt references">+${r.local}★</span>` : ""}</td>
    <td>${detectPill(r)} ${pill(r.mitigate, "Mitigate")} ${testPill(r)}</td>
    <td><span class="st st-${r.status}">${esc(r.status)}</span></td>
    <td class="gap ${gapClass(r.gapScore)}">${r.gapScore || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const detectionGap = f.reason === "no-detection" || f.reason === "exposed" || f.reason === "detection-failed" || f.reason === "detection-regressed";
  const href = detectionGap ? "/purple-team" : f.reason === "not-tested" ? "/?db=XTHREAT&table=ATOMICTEST" : "/d3fend";
  const draft = detectionGap ? ` <button class="ti-gen" data-tech="${esc(f.id)}" title="Draft a Sigma detection rule for ${esc(f.id)} (local AI, skeleton fallback) and add it to the library">✨ draft Sigma</button>` : "";
  return `<li><span class="dot" style="background:${f.severity === "High" ? "#f87171" : f.severity === "Medium" ? "#fbbf24" : "#64748b"}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> · <span class="muted">${esc(f.tactic)}</span> —
    ${esc(f.label)} <a href="${href}">▸ fix</a>${draft}</li>`;
}

async function genDetection(btn: HTMLButtonElement): Promise<void> {
  const tech = btn.dataset.tech;
  if (!tech) return;
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = "drafting…";
  try {
    const r = await fetch("/api/threat-informed-defense/generate-detection", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ techId: tech }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    btn.outerHTML = `<span class="ti-gen-done">✅ drafted Sigma <a href="/?db=XTHREAT&table=SIGMARULE">#${esc(d.sigmaRuleId)}</a> (${esc(d.offline ? "skeleton" : d.model)}${d.tuned ? ", tuned to the emulated procedure" : ""}, <i>experimental</i>) — re-run the validation plan to prove it fires</span>`;
  } catch (e) {
    btn.disabled = false; btn.textContent = orig;
    const s = document.createElement("span"); s.className = "ti-gen-done"; s.style.color = "#f87171"; s.textContent = ` ⚠️ ${e}`; btn.after(s);
  }
}

function tacticBar(t: Tactic): string {
  const n = t.techniques || 1;
  const seg = (count: number, color: string, label: string) => {
    const pc = Math.round((count / n) * 100);
    return pc > 0 ? `<div class="bar-seg" style="width:${pc}%;background:${color}" title="${label}: ${count}/${n} (${pc}%)"></div>` : "";
  };
  // stacked: show detect/mitigate/test as overlapping rates side by side (averaged width)
  const avg = Math.round(((t.detect + t.mitigate + t.test) / (3 * n)) * 100);
  return `<div class="bar-row"><span class="tac">${esc(t.tactic)} <span class="muted">(${t.techniques})</span></span>
    <div class="bar-track" title="avg coverage ${avg}%">
      ${seg(t.detect, "#38bdf8", "Detect")}${seg(t.mitigate, "#a78bfa", "Mitigate")}${seg(t.test, "#34d399", "Test")}
      <div class="bar-seg" style="flex:1;background:transparent"></div>
    </div></div>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/threat-informed-defense"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ti-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!s.threatRelevant) {
    $("ti-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No ATT&CK threat data yet. Import MITRE ATT&CK (groups, techniques, relationships) and detections (Sigma),
      then the Threat-Informed Defense scorecard appears here.</div>`;
    return;
  }

  const cards = [
    card("TID program score", `${s.tidScore}`, "threat-weighted detect+mitigate+test", rateColor(s.tidScore), "ti-card ti-score"),
    card("Threat-relevant", String(s.threatRelevant), `of ${s.techniques} techniques · ${s.adversaryGroups} groups`),
    card("Detection", `${s.detectRate}%`,
      s.detectionRegressed ? `${s.detected} w/ Sigma · ⚠ ${s.detectionRegressed} drifted (regressed)`
        : s.detectionFailed ? `${s.detected} w/ Sigma · ${s.detectionFailed} didn't fire`
        : `${s.detected} w/ Sigma · ${s.sigmaRules} rules`,
      (s.detectionRegressed || s.detectionFailed) ? "#f87171" : rateColor(s.detectRate)),
    card("Mitigation", `${s.mitigateRate}%`, `${s.mitigated} mapped · ${s.d3fendCountermeasures} D3FEND`, rateColor(s.mitigateRate)),
    card("Validation", `${s.testRate}%`, `${s.tested} defined · ${s.validatedRate}% executed`, rateColor(s.validatedRate || s.testRate)),
    card("Exposed", String(s.exposed), "high-threat · 0 defence", s.exposed ? "#f87171" : "#34d399"),
  ].join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 50).map(findingHtml).join("")}</ul>${d.findings.length > 50 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 50} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ Every threat-relevant technique is detected, mitigated and tested.</div>`;

  const tactics = `<div class="bars">${s.byTactic.map(tacticBar).join("")}</div>
    <div class="leg"><span style="color:#38bdf8">■</span> <b>Detect</b> (Sigma) &nbsp; <span style="color:#a78bfa">■</span> <b>Mitigate</b> (D3FEND/ATT&CK) &nbsp; <span style="color:#34d399">■</span> <b>Test</b> (Atomic) — share of threat-relevant techniques per tactic</div>`;

  const table = `<table class="ti"><thead><tr>
      <th>Technique</th><th title="adversary groups using it (+ local CTI ★)">Threat</th><th>Defence (Detect · Mitigate · Test)</th><th>Status</th><th title="priority × missing pillars">Gap</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("ti-body").innerHTML = `<div class="ti-cards">${cards}</div>
    <div class="ti-section" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Prioritised gap worklist (${d.findings.length})
      <button id="ti-plan-btn" class="ti-plan" title="Schedule the top untested high-threat techniques as a BAS emulation scenario">⚡ Build validation plan</button>
      <span id="ti-plan-stat" style="font-size:12px;font-weight:400;text-transform:none;letter-spacing:0;color:#94a3b8"></span>
    </div>${findings}
    <div class="ti-section" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Coverage by ATT&CK tactic (kill chain)
      <a class="ti-nav-dl" href="/api/threat-informed-defense/navigator-layer?download=1" download="xorcism-tid-navigator-layer.json"
        title="Download a MITRE ATT&CK Navigator layer (v4.5) of this program — score = adversary prevalence, colour = defence status. Open it in the official ATT&CK Navigator.">⬇ ATT&CK Navigator layer</a>
    </div>${tactics}
    <div class="ti-section">Top techniques by gap (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Threat</b> = distinct adversary groups using the technique (★ = local CTI/hunt references, weighted ×3).
      <b>Gap</b> = priority × missing pillars. <b>TID score</b> = threat-weighted mean of detect+mitigate+test coverage.
      As you import your own CTI (connectors → INTELEXCHANGE→ATT&CK) the priority sharpens to <i>your</i> threat model.</div>`;

  const btn = document.getElementById("ti-plan-btn");
  if (btn) btn.addEventListener("click", () => void planValidation());
  // delegated: "✨ draft Sigma" buttons on detection-gap findings
  $("ti-body").addEventListener("click", (ev) => {
    const t = ev.target as HTMLElement;
    if (t && t.classList.contains("ti-gen")) void genDetection(t as HTMLButtonElement);
  });
}

/** Close the validation gap → build a BAS emulation scenario for the top untested techniques. */
async function planValidation(): Promise<void> {
  const btn = document.getElementById("ti-plan-btn") as HTMLButtonElement | null;
  const stat = document.getElementById("ti-plan-stat");
  if (!btn || !stat) return;
  btn.disabled = true; stat.textContent = "Building validation plan…";
  try {
    const r = await fetch("/api/threat-informed-defense/plan-validation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ limit: 20 }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    if (!d.scenarioId) { stat.textContent = "✓ Nothing untested to schedule — every threat-relevant technique already has a test."; return; }
    stat.innerHTML = `✅ Created BAS scenario <a href="/?db=XTHREAT&table=EMULATIONSCENARIO" style="color:#e879f9">#${esc(d.scenarioId)}</a> — ${esc(d.created)} new validation inject(s) + ${esc(d.reused)} reused for the top ${esc(d.techniques.length)} untested techniques.
      <button id="ti-run-btn" class="ti-plan" style="background:#7c3aed" data-scenario="${esc(d.scenarioId)}">▶ Run on agent</button>
      <button id="ti-sched-btn" class="ti-plan" style="background:#0e7490" data-scenario="${esc(d.scenarioId)}">🔁 Schedule weekly</button>
      <a href="/threat-informed-defense" style="color:#e879f9">↻ Refresh</a>`;
    const rb = document.getElementById("ti-run-btn");
    if (rb) rb.addEventListener("click", () => void runOnAgent(Number(d.scenarioId)));
    const sb = document.getElementById("ti-sched-btn");
    if (sb) sb.addEventListener("click", () => void scheduleRevalidation(Number(d.scenarioId)));
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

/** Pick the best enrolled agent (localhost + online preferred) for an emulation. */
async function pickAgent(): Promise<{ name: string } | null> {
  try {
    const tr = await fetch("/api/configuration/scan-targets");
    const td = await tr.json();
    const a: { name: string; online: boolean; isLocal: boolean }[] = td.agents || [];
    return a.find((x) => x.isLocal && x.online) || a.find((x) => x.online) || a.find((x) => x.isLocal) || a[0] || null;
  } catch { return null; }
}

/** Execute a validation scenario on an enrolled XOR agent (localhost or remote). */
async function runOnAgent(scenarioId: number): Promise<void> {
  const rb = document.getElementById("ti-run-btn") as HTMLButtonElement | null;
  const stat = document.getElementById("ti-plan-stat");
  if (!rb || !stat || !scenarioId) return;
  rb.disabled = true;
  try {
    const target = await pickAgent();
    if (!target) { stat.innerHTML += ` — ⚠️ no enrolled agent to run on.`; return; }
    const r = await fetch("/api/agent-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent: target.name, kind: "emulate", scenarioId }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML += ` <br>▶ Queued emulation of scenario #${esc(scenarioId)} on <b>${esc(target.name)}</b> (job #${esc(d.jobId)}). The agent runs the injects at its next check-in (execution is opt-in: <code>XOR_ALLOW_EMULATION=1</code>) and posts outcomes — re-run the cockpit to see <b>validated</b> tests.`;
  } catch (e) { stat.innerHTML += ` — ⚠️ ${esc(e)}`; }
  finally { rb.disabled = false; }
}

/** Schedule periodic auto-re-validation of a scenario (weekly) so drafts get proven on a cadence. */
async function scheduleRevalidation(scenarioId: number): Promise<void> {
  const sb = document.getElementById("ti-sched-btn") as HTMLButtonElement | null;
  const stat = document.getElementById("ti-plan-stat");
  if (!sb || !stat || !scenarioId) return;
  sb.disabled = true;
  try {
    const target = await pickAgent();
    if (!target) { stat.innerHTML += ` — ⚠️ no enrolled agent to schedule on.`; return; }
    const r = await fetch("/api/threat-informed-defense/schedule-revalidation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenarioId, agent: target.name }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML += ` <br>🔁 Scheduled re-validation (schedule <a href="/?db=XJOB&table=XSCHEDULE" style="color:#22d3ee">#${esc(d.scheduleId)}</a>, cron <code>${esc(d.cron)}</code>) of scenario #${esc(scenarioId)} on <b>${esc(target.name)}</b> — the agent re-runs it on cadence and the cockpit's <b>validated / false-coverage</b> signals refresh automatically.`;
    sb.outerHTML = "";
  } catch (e) { sb.disabled = false; stat.innerHTML += ` — ⚠️ ${esc(e)}`; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
