/**
 * crisis-management.ts — Crisis management & tabletop-exercise readiness (/crisis-management).
 * Exercises + scenario library + improvement worklist, from /api/crisis-management.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface ExerciseRow { id: number; name: string; scenario: string; type: string; status: string; date: string | null; completed: boolean; injects: number; injectsDone: number; participants: number; actions: number; highActions: number; overdue: number; hasAAR: boolean; score: number; }
interface ScenarioRow { id: number; name: string; type: string; severity: string; injects: number; exercised: boolean; }
interface Finding { id: number; exercise: string; name: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; overdue: boolean; unassigned: boolean; kind: "action" | "scenario" | "exercise"; label: string; }
interface Inventory {
  rows: ExerciseRow[]; findings: Finding[]; scenarios: ScenarioRow[];
  summary: { exercises: number; planned: number; inProgress: number; completed: number; completionRate: number | null; scenarios: number; scenariosNeverExercised: number; scenarioCoverage: number; openActions: number; highActions: number; overdueActions: number; participants: number; withoutAAR: number; readinessScore: number; byType: Record<string, number>; byStatus: Record<string, number>; };
}

const sevClass = (s: string): string => `s-${(s || "low").toLowerCase()}`;
const stClass = (s: string): string => (/complet|clos|done|conduct/i.test(s) ? "st-completed" : /progress|cours|ongoing/i.test(s) ? "st-progress" : "st-planned");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");
const readyColor = (n: number): string => (n >= 70 ? "#34d399" : n >= 40 ? "#fbbf24" : "#f87171");

function card(lbl: string, val: string, foot: string, color?: string, cls = "cr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: ExerciseRow): string {
  const pct = r.injects ? Math.round((r.injectsDone / r.injects) * 100) : 0;
  const injCell = r.injects
    ? `${r.injectsDone}/${r.injects}<div class="prog"><span style="width:${pct}%"></span></div>`
    : `<span class="muted">—</span>`;
  const posture = r.actions
    ? `<span class="pill p-open">${r.actions} open</span>${r.highActions ? `<span class="pill p-high">${r.highActions} high</span>` : ""}${r.overdue ? `<span class="tag">${r.overdue} overdue</span>` : ""}`
    : `<span class="pill p-clean">clean</span>`;
  const aar = r.completed ? (r.hasAAR ? `<span class="pill p-aar">AAR</span>` : `<span class="pill p-noaar">no AAR</span>`) : `<span class="muted">—</span>`;
  return `<tr>
    <td><div class="aname">${esc(r.name)}</div><div class="muted" style="font-size:11px">${esc(r.scenario)}${r.date ? ` · ${esc(r.date)}` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${injCell}</td>
    <td>${r.participants || `<span class="muted">0</span>`}</td>
    <td>${posture}</td>
    <td>${aar}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "scenario" ? "#e11d48" : f.kind === "exercise" ? "#38bdf8" : "#fb923c";
  const href = f.kind === "scenario" ? "/?db=XCOMPLIANCE&table=CRISISSCENARIO" : f.kind === "exercise" ? "/?db=XCOMPLIANCE&table=AUDIT" : "/?db=XCOMPLIANCE&table=AUDITFINDING";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="${href}">${esc(f.exercise)}</a> — ${esc(f.label)}</li>`;
}

function scenarioHtml(s: ScenarioRow): string {
  const run = s.exercised
    ? `<span class="scn-done">✓ exercised</span>`
    : `<button class="scn-run" data-scn="${s.id}" data-name="${esc(s.name)}" title="Schedule a tabletop exercise from this scenario (creates an exercise audit + copies its injects)">▶ Run exercise</button>`;
  return `<div class="scn-card">
    <div class="t">${esc(s.name)}</div>
    <div class="m"><span class="sev ${sevClass(s.severity)}">${esc(s.severity)}</span> · ${esc(s.type)} · ${s.injects} inject(s)</div>
    ${run}
  </div>`;
}

async function launch(btn: HTMLButtonElement): Promise<void> {
  const id = Number(btn.dataset.scn);
  if (!id) return;
  btn.disabled = true; const orig = btn.textContent; btn.textContent = "scheduling…";
  try {
    const r = await fetch("/api/crisis-management/launch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenarioId: id }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    btn.outerHTML = `<span class="scn-done">✅ exercise <a href="/?db=XCOMPLIANCE&table=AUDIT&filterCol=AuditID&filterVal=${esc(d.auditId)}" style="color:#fb7185">#${esc(d.auditId)}</a> created (${esc(d.injects)} injects) — <a href="/crisis-management" style="color:#fb7185">↻ refresh</a></span>`;
  } catch (e) { btn.disabled = false; btn.textContent = orig; const sp = document.createElement("span"); sp.className = "scn-done"; sp.style.color = "#f87171"; sp.textContent = ` ⚠ ${e}`; btn.after(sp); }
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/crisis-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length && !d.scenarios.length) {
    $("cr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No crisis scenarios or tabletop exercises yet. Seed the scenario library
      (<code>seed_crisis_scenarios.py</code>) or <a href="/?db=XCOMPLIANCE&table=CRISISSCENARIO">create a scenario</a>,
      then launch an exercise — the readiness picture appears here.</div>`;
    return;
  }

  const cards = [
    card("Crisis readiness", `${s.readinessScore}`, "exercise completion × scenario coverage", readyColor(s.readinessScore), "cr-card cr-ready"),
    card("Exercises", String(s.exercises), `${s.planned} planned · ${s.completed} conducted`),
    card("Scenario coverage", `${s.scenarioCoverage}%`, `${s.scenarios - s.scenariosNeverExercised}/${s.scenarios} scenarios exercised`, s.scenarioCoverage >= 60 ? "#34d399" : s.scenarioCoverage >= 30 ? "#fbbf24" : "#f87171"),
    card("Open actions", String(s.openActions), `${s.highActions} high · improvement actions`, s.openActions ? "#fb923c" : "#34d399"),
    card("Overdue", String(s.overdueActions), "actions past due", s.overdueActions ? "#f87171" : "#34d399"),
    card("No after-action", String(s.withoutAAR), "conducted · no AAR", s.withoutAAR ? "#fbbf24" : "#34d399"),
  ].join("");

  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No overdue actions, every scenario exercised, all exercises have an after-action report.</div>`;

  const scenarios = d.scenarios.length
    ? `<div class="scn">${d.scenarios.map(scenarioHtml).join("")}</div>`
    : `<div class="muted" style="padding:12px 0">No scenario templates. Seed them with <code>seed_crisis_scenarios.py</code>.</div>`;

  const table = d.rows.length ? `<table class="cr"><thead><tr>
      <th>Exercise</th><th>Status</th><th title="injects played / total">Injects</th><th>People</th><th>Improvement actions</th><th title="after-action report">AAR</th><th title="outstanding-gaps score">Score</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">No exercises conducted yet — launch one from a scenario above.</div>`;

  $("cr-body").innerHTML = `<div class="cr-cards">${cards}</div>
    <div class="cr-section">Improvement worklist (${d.findings.length})</div>${findings}
    <div class="cr-section">Crisis scenario library (${d.scenarios.length}) — launch a tabletop exercise</div>${scenarios}
    ${byType ? `<div class="cr-section">Exercises by type</div><div class="breakdown">${byType}</div>` : ""}
    <div class="cr-section">Tabletop exercises (${d.rows.length})</div>${table}
    <div class="legend">↳ A tabletop exercise is an <b>audit</b> of type <i>Tabletop Exercise</i>; its observations are
      <b>improvement actions</b> (findings) and its <b>after-action report</b> a linked document.
      <b>Readiness</b> = 50% exercise completion + 50% scenario coverage − overdue penalties.
      <b>Score</b> per exercise = outstanding gaps (open actions weighted by severity + overdue + no-AAR).</div>`;

  $("cr-body").addEventListener("click", (ev) => {
    const t = ev.target as HTMLElement;
    if (t && t.classList.contains("scn-run")) void launch(t as HTMLButtonElement);
  });
}

document.addEventListener("DOMContentLoaded", () => void load());
