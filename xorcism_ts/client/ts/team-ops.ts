/** team-ops.ts — Purple/Red/Blue Team Operations cockpit (/team-ops). Reads /api/team-ops. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2400); }

let TACTICS: string[] = [];
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const rateColor = (p: number): string => (p >= 75 ? "#4ade80" : p >= 50 ? "#fbbf24" : "#f87171");
const ocls = (o: string): string => `o-${["prevented", "detected", "logged", "missed"].includes(o) ? o : "missed"}`;
const tcls = (t: string): string => `t-${["Red", "Blue", "Purple", "AppSec"].includes(t) ? t : "Purple"}`;

function load(): void {
  fetch("/api/team-ops").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    TACTICS = d.tactics;
    const s = d.summary;
    const cards = [
      card("Prevention rate", `${s.preventionRate}%`, "blocked outright", rateColor(s.preventionRate)),
      card("Detection rate", `${s.detectionRate}%`, "prevented or alerted", rateColor(s.detectionRate)),
      card("Visibility", `${s.visibility}%`, "incl. logged-only", rateColor(s.visibility)),
      card("MTTD", s.mttdMinutes == null ? "—" : `${s.mttdMinutes}m`, "mean time to detect", s.mttdMinutes != null && s.mttdMinutes <= 30 ? "#4ade80" : "#fbbf24"),
      card("Missed", String(s.missed), "no visibility — gaps", s.missed ? "#f87171" : "#4ade80"),
      card("Exercises", String(s.exercises), `${s.testCases} test cases`),
    ].join("");
    const exs = d.exercises.length
      ? `<table class="t"><thead><tr><th>Exercise</th><th>Type</th><th>Adversary</th><th>Cases</th><th>Prevent</th><th>Detect</th><th>Visibility</th><th></th></tr></thead><tbody>${d.exercises.map((e: any) => `<tr>
          <td><span class="nm">${esc(e.name)}</span></td><td><span class="tm ${tcls(e.type)}">${esc(e.type)}</span></td><td class="muted" style="font-size:11px">${esc(e.actor)}</td>
          <td>${e.total}</td><td style="color:${rateColor(e.preventionRate)}">${e.preventionRate}%</td><td style="color:${rateColor(e.detectionRate)}">${e.detectionRate}%</td>
          <td>${bar(e.visibility)} <span class="muted">${e.visibility}%</span></td><td><button class="btn-sm2 open" data-id="${e.id}">Open</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No exercises yet.</div>`;
    const tactics = d.byTactic.length ? d.byTactic.map((t: any) => `<div class="tac"><span class="nm2">${esc(t.tactic)}</span>${bar(t.rate)}<span style="min-width:80px;text-align:right;color:${rateColor(t.rate)};font-weight:700">${t.rate}% <span class="muted" style="font-weight:400">(${t.detected}/${t.tested})</span></span></div>`).join("") : `<div class="muted">No test cases yet.</div>`;
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.map((w: any) => `<li><span class="oc ${ocls(w.outcome === "logged-only" ? "logged" : "missed")}">${esc(w.outcome)}</span> <span class="mono">${esc(w.attackId)}</span> <b style="color:#e2e8f0">${esc(w.technique)}</b> <span class="muted">${esc(w.tactic)}</span> <a class="btn-sm2" style="margin-left:auto" href="/purple-team">build detection ↗</a></li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ No detection gaps — every tested technique is prevented or detected.</div>`;
    const caps = d.capByTeam.map((c: any) => `<div class="panel"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span class="tm ${tcls(c.team)}">${esc(c.team)} Team</span><span class="muted">${c.count} capabilities · maturity ${c.maturity == null ? "—" : c.maturity + "/5"}</span></div>${d.capabilities.filter((x: any) => x.team === c.team).map((x: any) => `<div style="font-size:12px;padding:4px 0;border-top:1px solid #1e2133"><b style="color:#e2e8f0">${esc(x.name)}</b> <span class="muted">${esc(x.category)} · maturity ${x.maturity ?? "—"}/5 · ${esc(x.capacity)}</span><div class="muted" style="font-size:11px">${esc(x.tooling)}</div></div>`).join("")}</div>`).join("");
    const autos = d.automations.map((a: any) => `<div class="auto"><span class="tm ${tcls(a.team)}">${esc(a.team)}</span> <b>${esc(a.name)}</b> — ${esc(a.desc)} <span class="muted" style="font-size:11px">[${esc(a.tools)}]</span></div>`).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">Exercises (${d.exercises.length})<span class="spacer"></span><button class="btn-sm2" id="new-ex">+ New exercise</button></div>${exs}
      <div class="grid2" style="margin-top:8px">
        <div class="panel"><div class="sec" style="margin-top:0">ATT&CK tactic coverage</div>${tactics}</div>
        <div class="panel"><div class="sec" style="margin-top:0">Detection-engineering worklist (${d.worklist.length})</div>${work}</div>
      </div>
      <div class="sec">Capabilities & capacities</div><div class="grid2">${caps}</div>
      <div class="sec">Automation playbooks (n8n — offensive & defensive)</div><div class="panel">${autos}</div>`;
    Array.prototype.forEach.call(document.querySelectorAll(".open"), (b: HTMLElement) => { b.onclick = () => openExercise(Number(b.getAttribute("data-id"))); });
    $("new-ex").onclick = newExercise;
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
function bar(pct: number): string { return `<div class="bar"><i style="width:${Math.max(0, Math.min(100, pct))}%;background:${rateColor(pct)}"></i></div>`; }

const OUTCOMES = [["prevented", "Prevented"], ["detected", "Detected"], ["logged", "Logged"], ["missed", "Missed"]];
function openExercise(id: number): void {
  fetch(`/api/team-ops/exercise/${id}`).then((r) => r.json()).then((d) => {
    const e = d.exercise;
    const rows = d.cases.map((c: any) => `<tr>
      <td class="mono">${esc(c.attackId)}</td><td><span class="nm">${esc(c.technique)}</span><div class="muted" style="font-size:11px">${esc(c.tactic)}</div></td>
      <td style="font-size:12px;color:#cbd5e1">${esc(c.offensive)}${c.tool ? ` <span class="muted">[${esc(c.tool)}]</span>` : ""}</td>
      <td><select class="oc-sel" data-id="${c.id}">${OUTCOMES.map(([v, l]) => `<option value="${v}"${c.outcome === v ? " selected" : ""}>${l}</option>`).join("")}</select></td>
      <td class="muted" style="font-size:11px">${c.detectionTimeMin != null ? c.detectionTimeMin + "m" : ""}${c.detectionSource ? " · " + esc(c.detectionSource) : ""}</td></tr>`).join("");
    $("dlg").innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><b style="font-size:16px;color:#e7ebf3">${esc(e.name)}</b><span class="tm ${tcls(e.type)}">${esc(e.type)}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2" id="add-tc">+ test case</button><button class="btn-sm2" id="close">Close</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:10px">${esc(e.objective)}${e.actor ? ` · adversary: ${esc(e.actor)}` : ""}</div>
      <table class="t"><thead><tr><th>ATT&CK</th><th>Technique</th><th>Red offensive action</th><th>Blue outcome</th><th>Detection</th></tr></thead><tbody>${rows}</tbody></table>`;
    $("modal").classList.add("show");
    $("close").onclick = () => $("modal").classList.remove("show");
    $("add-tc").onclick = () => {
      const attackId = prompt("ATT&CK technique id (e.g. T1059.001):") || "";
      const technique = prompt("Technique name:"); if (!technique) return;
      const tactic = prompt("Tactic (e.g. Execution):") || "";
      const offensiveAction = prompt("Red offensive action:") || "";
      post(`/api/team-ops/exercise/${id}/testcase`, { attackId, technique, tactic, offensiveAction }, () => openExercise(id));
    };
    Array.prototype.forEach.call(document.querySelectorAll(".oc-sel"), (sel: HTMLSelectElement) => {
      sel.onchange = () => {
        const body: any = { outcome: sel.value };
        if (sel.value === "detected") { const m = prompt("Detection time (minutes)?", "10"); if (m) body.detectionTimeMin = Number(m); body.detectionSource = "EDR/SIEM"; }
        post(`/api/team-ops/testcase/${sel.getAttribute("data-id")}/outcome`, body, () => { openExercise(id); load(); });
      };
    });
  }).catch((e) => toast("⚠️ " + e));
}
function post(url: string, body: unknown, cb: () => void): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast("Saved"); cb(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function newExercise(): void {
  const name = prompt("Exercise name:"); if (!name) return;
  const type = prompt("Type (Purple / Red / Blue):", "Purple") || "Purple";
  const actor = prompt("Emulated adversary (optional):") || "";
  post("/api/team-ops/exercise", { name, type, actor }, () => load());
}
document.addEventListener("DOMContentLoaded", () => { $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").classList.remove("show"); }); load(); });
