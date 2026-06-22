/** security-awareness.ts — Security Awareness cockpit (/security-awareness). Training catalogue +
 * enrollment, phishing simulation campaigns, Phish-Prone %, repeat clickers, per-user human-risk
 * worklist, from /api/security-awareness. KnowBe4-style. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

interface Training { id: number; name: string; category: string; provider: string; duration: number | null; required: boolean; status: string; enrolled: number; completed: number; completionRate: number | null; }
interface Phish { id: number; name: string; theme: string; difficulty: string; status: string; sentDate: string | null; sent: number; clicked: number; reported: number; submitted: number; clickRate: number; reportRate: number; }
interface UserRow { id: number; name: string; clicks: number; submitted: number; reported: number; campaigns: number; trainingsDone: number; trainingsAssigned: number; incomplete: number; risk: number; phishProne: boolean; repeatClicker: boolean; }
interface Data { trainings: Training[]; phishing: Phish[]; users: UserRow[]; worklist: { kind: string; id: number; name: string; severity: string; reason: string }[]; summary: any; }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="sa-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const riskColor = (r: number): string => (r >= 70 ? "#f87171" : r >= 40 ? "#fbbf24" : r >= 15 ? "#a3e635" : "#34d399");
const rateColor = (r: number): string => (r >= 30 ? "#f87171" : r >= 15 ? "#fbbf24" : "#34d399");

function bar(pct: number, color: string): string {
  return `<span class="bar" title="${pct}%"><i style="width:${Math.max(0, Math.min(100, pct))}%;background:${color}"></i></span>`;
}

function trainingRow(t: Training): string {
  const cr = t.completionRate;
  return `<tr>
    <td><span class="nm">${esc(t.name)}</span>${t.required ? ` <span class="tag t-req">REQUIRED</span>` : ""}</td>
    <td>${t.category ? `<span class="tag t-cat">${esc(t.category)}</span>` : "<span class='muted'>—</span>"}</td>
    <td>${t.provider ? `<span class="tag t-prov">${esc(t.provider)}</span>` : "<span class='muted'>—</span>"}</td>
    <td>${t.duration ? `${t.duration} min` : "<span class='muted'>—</span>"}</td>
    <td>${t.enrolled}</td>
    <td>${cr == null ? "<span class='muted'>no enrollees</span>" : `${bar(cr, cr >= 80 ? "#34d399" : cr >= 50 ? "#fbbf24" : "#f87171")} <span class="muted">${t.completed}/${t.enrolled} · ${cr}%</span>`}</td>
  </tr>`;
}

function phishRow(p: Phish): string {
  return `<tr>
    <td><span class="nm">${esc(p.name)}</span>${p.theme ? `<div class="muted" style="font-size:11px">${esc(p.theme)}</div>` : ""}</td>
    <td>${esc(p.difficulty || "—")}</td>
    <td>${esc(p.status || "—")}</td>
    <td>${p.sentDate || "<span class='muted'>—</span>"}</td>
    <td>${p.sent}</td>
    <td><span class="tag t-phish">${p.clicked}</span> ${bar(p.clickRate, rateColor(p.clickRate))} <span class="muted ppp">${p.clickRate}%</span></td>
    <td>${p.submitted ? `<span class="tag t-sub">${p.submitted}</span>` : "<span class='muted'>0</span>"}</td>
    <td><span class="tag t-report">${p.reported}</span> <span class="muted ppp">${p.reportRate}%</span></td>
  </tr>`;
}

function userRow(u: UserRow): string {
  return `<tr>
    <td><span class="nm">${esc(u.name)}</span></td>
    <td>${bar(u.risk, riskColor(u.risk))} <span class="riskpill" style="background:${riskColor(u.risk)}22;color:${riskColor(u.risk)}">${u.risk}</span></td>
    <td>${u.clicks ? `<span class="tag t-phish">${u.clicks}×</span>` : "<span class='muted'>0</span>"}${u.repeatClicker ? " <span class='muted' style='font-size:10px'>repeat</span>" : ""}</td>
    <td>${u.submitted ? `<span class="tag t-sub">${u.submitted}</span>` : "<span class='muted'>0</span>"}</td>
    <td>${u.reported ? `<span class="tag t-report">${u.reported}</span>` : "<span class='muted'>0</span>"}</td>
    <td>${u.trainingsAssigned ? `${u.trainingsDone}/${u.trainingsAssigned}${u.incomplete ? ` <span class="muted" style="font-size:11px">(${u.incomplete} due)</span>` : ""}` : "<span class='tag t-phish'>never</span>"}</td>
  </tr>`;
}

function load(): void {
  fetch("/api/security-awareness").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    const s = d.summary;
    if (!d.trainings.length && !d.phishing.length) {
      $("sa-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No awareness program yet.<br>
        Create a training course or launch a phishing simulation to start tracking human risk.
        <div style="margin-top:14px"><button class="btn-sm2" id="sa-new-t">+ New training</button> <button class="btn-sm2" id="sa-new-p">+ New phishing test</button></div></div>`;
      wireCreate();
      return;
    }
    const ppp = s.phishPronePct;
    const cards = [
      card("Phish-Prone %", ppp == null ? "—" : `${ppp}%`, "of recipients clicked", ppp == null ? undefined : rateColor(ppp)),
      card("Completion", s.completionRate == null ? "—" : `${s.completionRate}%`, `${s.completed}/${s.enrolled} enrollments`, s.completionRate == null ? undefined : (s.completionRate >= 80 ? "#34d399" : "#fbbf24")),
      card("Repeat clickers", String(s.repeatClickers), "clicked ≥2 phishing tests", s.repeatClickers ? "#f87171" : "#34d399"),
      card("Never trained", String(s.neverTrained), "staff with no enrollment", s.neverTrained ? "#fbbf24" : "#34d399"),
      card("Avg human-risk", String(s.avgRisk), `${s.highRisk} high-risk users`, riskColor(s.avgRisk)),
      card("Campaigns", String(s.campaigns), `${s.recipients} recipients · ${s.reported} reported`, "#60a5fa"),
    ].join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.slice(0, 50).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> — ${esc(w.reason)}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ No human-risk findings — everyone is trained and nobody clicked.</div>`;
    const tTable = d.trainings.length
      ? `<table class="sa"><thead><tr><th>Course</th><th>Category</th><th>Provider</th><th>Duration</th><th>Enrolled</th><th>Completion</th></tr></thead><tbody>${d.trainings.map(trainingRow).join("")}</tbody></table>`
      : "<div class='muted' style='padding:8px 0'>No training courses yet.</div>";
    const pTable = d.phishing.length
      ? `<table class="sa"><thead><tr><th>Campaign</th><th>Difficulty</th><th>Status</th><th>Sent date</th><th>Recipients</th><th>Clicked</th><th>Submitted</th><th>Reported</th></tr></thead><tbody>${d.phishing.map(phishRow).join("")}</tbody></table>`
      : "<div class='muted' style='padding:8px 0'>No phishing campaigns yet.</div>";
    const uTable = d.users.length
      ? `<table class="sa"><thead><tr><th>User</th><th>Human-risk</th><th>Clicked</th><th>Submitted</th><th>Reported</th><th>Training</th></tr></thead><tbody>${d.users.slice(0, 100).map(userRow).join("")}</tbody></table>`
      : "<div class='muted' style='padding:8px 0'>No user activity yet.</div>";
    $("sa-body").innerHTML = `<div class="sa-cards">${cards}</div>
      <div class="sa-section">Human-risk worklist (${d.worklist.length})</div>${work}
      <div class="sa-section">Training catalogue (${d.trainings.length})<span class="spacer"></span><button class="btn-sm2" id="sa-new-t">+ New training</button></div>${tTable}
      <div class="sa-section">Phishing simulations (${d.phishing.length})<span class="spacer"></span><button class="btn-sm2" id="sa-new-p">+ New phishing test</button></div>${pTable}
      <div class="sa-section">Per-user human-risk (${d.users.length})</div>${uTable}`;
    wireCreate();
  }).catch((e) => { $("sa-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function wireCreate(): void {
  const t = document.getElementById("sa-new-t");
  if (t) t.onclick = () => {
    const name = prompt("Training course name:");
    if (!name) return;
    const category = prompt("Category (e.g. Phishing, Passwords, Data Protection):") || "";
    fetch("/api/security-awareness/training", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, category, required: true }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Training created"); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
  const p = document.getElementById("sa-new-p");
  if (p) p.onclick = () => {
    const name = prompt("Phishing campaign name:");
    if (!name) return;
    const theme = prompt("Theme (e.g. Password reset, Invoice, HR policy):") || "";
    fetch("/api/security-awareness/phishing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, theme, difficulty: "Medium" }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Phishing campaign created"); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}
document.addEventListener("DOMContentLoaded", load);
