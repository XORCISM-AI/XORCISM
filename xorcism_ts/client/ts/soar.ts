/** soar.ts — SOAR cockpit (/soar). Orchestration playbooks (trigger→actions) + action catalogue +
 *  simulate/live run engine + run history. Reads /api/soar. */
// NB: import as T — `t` is used as a local/param in this file (toast()'s `const t`, .find/.map((t)=>…)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2800); }

interface Action { id: number; order: number; type: string; name: string; params: string; onFailure: string }
interface Playbook { id: number; name: string; description: string; trigger: string; category: string; enabled: boolean; runCount: number; lastRunAt: string | null; actions: Action[] }
interface Run { id: number; playbookId: number; playbookName: string; mode: string; status: string; steps: number; startedAt: string; summary: string }
interface Data {
  summary: { playbooks: number; enabled: number; actions: number; triggersCovered: number; triggersTotal: number; runs: number; successRuns: number; successRate: number | null; webhookTargets: number; externalConfigured: boolean };
  playbooks: Playbook[]; runs: Run[]; worklist: { label: string; severity: string }[];
  triggers: { id: string; label: string; severity: string }[]; actionCatalogue: { id: string; label: string }[]; webhooks: any[];
}
let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const statusPill = (s: string): string => `<span class="pill ${s === "success" ? "p-ok" : s === "partial" ? "p-warn" : s === "failed" ? "p-bad" : "p-off"}">${esc(s)}</span>`;

function pbHtml(p: Playbook): string {
  const trig = DATA!.triggers.find((tr) => tr.id === p.trigger)?.label || p.trigger;
  const steps = p.actions.length
    ? p.actions.map((a) => `<div class="step"><span class="stepn">${a.order}</span><span class="atype">${esc(a.type)}</span> <span>${esc(a.name)}</span>${a.params ? ` <span class="muted">— ${esc(a.params)}</span>` : ""}</div>`).join("")
    : `<div class="muted" style="font-size:12px;padding:3px 0">${T("soar.noActions")}</div>`;
  return `<div class="pb">
    <div class="pbh">
      <span class="nm">${esc(p.name)}</span>
      <span class="chiptrig">▶ ${esc(trig)}</span>${p.category ? `<span class="chipcat">${esc(p.category)}</span>` : ""}
      <span class="pill ${p.enabled ? "p-ok" : "p-off"}">${p.enabled ? T("soar.enabled") : T("soar.disabled")}</span>
      <span style="flex:1"></span>
      <span class="muted" style="font-size:11px">${fmt("soar.runN", { n: p.runCount })}</span>
      <button class="btn-sm2" data-run="${p.id}">${T("soar.runSim")}</button>
      <button class="btn-sm2" data-toggle="${p.id}" data-on="${p.enabled ? 1 : 0}">${p.enabled ? T("soar.disable") : T("soar.enable")}</button>
      <button class="btn-sm2" data-del="${p.id}">✕</button>
    </div>
    ${p.description ? `<div class="muted" style="font-size:12px;margin:4px 0 6px">${esc(p.description)}</div>` : '<div style="height:4px"></div>'}
    ${steps}
  </div>`;
}

function render(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card(T("soar.cPlaybooks"), String(s.playbooks), fmt("soar.cPlaybooksF", { e: s.enabled, a: s.actions })),
    card(T("soar.cCoverage"), `${s.triggersCovered}/${s.triggersTotal}`, T("soar.cCoverageF"), s.triggersCovered >= s.triggersTotal ? "#34d399" : "#fbbf24"),
    card(T("soar.cRuns"), String(s.runs), s.successRate != null ? fmt("soar.cRunsF", { n: s.successRate }) : T("soar.noneYet"), "#60a5fa"),
    card(T("soar.cTargets"), String(s.webhookTargets), s.externalConfigured ? T("soar.cTargetsConfigured") : T("soar.cTargetsSim"), s.externalConfigured ? "#34d399" : "#94a3b8"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev sv-${["High", "Medium", "Low"].includes(w.severity) ? w.severity : "Low"}">${esc(w.severity)}</span> <span>${esc(w.label)}</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">${T("soar.allCovered")}</div>`;

  const pbs = d.playbooks.length ? d.playbooks.map(pbHtml).join("") : `<div class="muted" style="padding:8px 0">${T("soar.noPlaybooks")}</div>`;

  const cat = `<div class="grid2">
    <div class="panel"><h3 style="margin:0 0 6px;font-size:12px;color:#cbd5e1;text-transform:uppercase">${T("soar.actionCatalogue")}</h3>${d.actionCatalogue.map((a) => `<div class="step"><span class="atype">${esc(a.id)}</span> <span>${esc(a.label)}</span></div>`).join("")}</div>
    <div class="panel"><h3 style="margin:0 0 6px;font-size:12px;color:#cbd5e1;text-transform:uppercase">${T("soar.outboundTargets")}</h3>${d.webhooks.length ? d.webhooks.map((w) => `<div class="step"><span class="pill ${w.enabled ? "p-ok" : "p-off"}">${w.enabled ? T("soar.on") : T("soar.off")}</span> <span>${esc(w.name)}</span> <span class="muted">${esc(w.host)} · ≥${esc(w.minSeverity)}</span></div>`).join("") : `<div class="muted" style="font-size:12px">${T("soar.noWebhook")}</div>`}</div>
  </div>`;

  const runs = d.runs.length
    ? `<table class="rt"><thead><tr><th>#</th><th>${T("soar.thPlaybook")}</th><th>${T("soar.thMode")}</th><th>${T("soar.thStatus")}</th><th>${T("soar.thSteps")}</th><th>${T("soar.thSummary")}</th><th></th></tr></thead><tbody>${d.runs.map((r) => `<tr>
        <td class="muted">${r.id}</td><td class="nm">${esc(r.playbookName)}</td><td><span class="pill ${r.mode === "live" ? "p-warn" : "p-off"}">${esc(r.mode)}</span></td>
        <td>${statusPill(r.status)}</td><td>${r.steps}</td><td class="muted">${esc(r.summary)}</td>
        <td><button class="btn-sm2" data-rundetail="${r.id}">${T("soar.view")}</button></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${T("soar.noRuns")}</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">🧩 ${fmt("soar.secGaps", { n: d.worklist.length })}</div><div class="panel">${work}</div>
    <div class="sec">⚙️ ${fmt("soar.secPlaybooks", { n: d.playbooks.length })}</div>${pbs}
    <div class="sec">📚 ${T("soar.secCatalogue")}</div>${cat}
    <div class="sec">🏃 ${fmt("soar.secRuns", { n: d.runs.length })}</div><div class="panel">${runs}</div>`;
  wire();
}

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("run", (id) => runPlaybook(id));
  on("toggle", (id, el) => act(`/api/soar/playbook/${id}/enabled`, "POST", { enabled: el.getAttribute("data-on") !== "1" }, T("soar.updated")));
  on("del", (id) => { if (confirm(T("soar.confirmDelete"))) act(`/api/soar/playbook/${id}`, "DELETE", null, T("soar.deleted")); });
  on("rundetail", (id) => runDetail(id));
}

function act(url: string, method: string, body: unknown, okMsg: string): void {
  fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body == null ? undefined : JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function closeModal(): void { $("modal").classList.remove("show"); }

function runPlaybook(id: number): void {
  fetch(`/api/soar/playbook/${id}/run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "simulate" }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j: { runId: number; status: string }) => { toast(fmt("soar.simulated", { s: j.status })); runDetail(j.runId); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function runDetail(runId: number): void {
  fetch(`/api/soar/run/${runId}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { id: number; mode: string; status: string; summary: string; steps: any[] }) => {
      const steps = d.steps.map((s) => `<div class="step" style="align-items:flex-start"><span class="stepn">${s.order}</span>
        <div><span class="atype">${esc(s.type)}</span> <span>${esc(s.name)}</span> <span class="pill ${s.status === "success" ? "p-ok" : "p-off"}">${esc(s.status)}</span>
        <div class="muted" style="font-size:12px;margin-top:2px">${esc(s.output)}</div></div></div>`).join("");
      $("dlg").innerHTML = `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${fmt("soar.runHash", { id: d.id })}</b><span class="pill ${d.mode === "live" ? "p-warn" : "p-off"}">${esc(d.mode)}</span><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${T("soar.close")}</button></div>
        <div class="muted" style="font-size:12px;margin-bottom:8px">${esc(d.summary)}</div>${steps}`;
      $("modal").classList.add("show");
      ($("dlg-close") as HTMLButtonElement).onclick = closeModal;
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

let actionRows = 1;
function addActionRow(): void {
  const wrap = $("act-rows"); const i = actionRows++;
  const div = document.createElement("div"); div.className = "arow";
  div.innerHTML = `<select id="a-type-${i}">${DATA!.actionCatalogue.map((a) => `<option value="${esc(a.id)}">${esc(a.label)}</option>`).join("")}</select><input id="a-params-${i}" placeholder="${esc(T("soar.paramsPh"))}">`;
  wrap.appendChild(div);
}

function newDialog(): void {
  const d = DATA!;
  $("dlg").innerHTML = `<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${T("soar.newTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${T("soar.close")}</button></div>
    <label>${T("soar.fName")}<input id="p-name" placeholder="${esc(T("soar.fNamePh"))}"></label>
    <label>${T("soar.fDesc")}<input id="p-desc" placeholder="${esc(T("soar.fDescPh"))}"></label>
    <div style="display:flex;gap:8px"><label style="flex:1">${T("soar.fTrigger")}<select id="p-trigger">${d.triggers.map((tr) => `<option value="${esc(tr.id)}">${esc(tr.label)}</option>`).join("")}</select></label>
      <label style="flex:1">${T("soar.fCategory")}<input id="p-cat" placeholder="${esc(T("soar.fCategoryPh"))}"></label></div>
    <label>${T("soar.fActions")}</label><div id="act-rows"></div>
    <button class="btn-sm2" id="add-act" style="margin-top:6px">${T("soar.addAction")}</button>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="p-save" style="border-color:#fb923c;color:#fdba74">${T("soar.createBtn")}</button></div>`;
  $("modal").classList.add("show");
  ($("dlg-close") as HTMLButtonElement).onclick = closeModal;
  actionRows = 1; $("act-rows").innerHTML = ""; addActionRow(); addActionRow();
  ($("add-act") as HTMLButtonElement).onclick = addActionRow;
  ($("p-save") as HTMLButtonElement).onclick = () => {
    const name = ($("p-name") as HTMLInputElement).value.trim();
    if (!name) { toast(T("soar.nameRequired")); return; }
    const actions: any[] = [];
    for (let i = 0; i < actionRows; i++) {
      const sel = document.getElementById(`a-type-${i}`) as HTMLSelectElement | null;
      if (sel) actions.push({ actionType: sel.value, params: (document.getElementById(`a-params-${i}`) as HTMLInputElement)?.value || "" });
    }
    fetch("/api/soar/playbook", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, description: ($("p-desc") as HTMLInputElement).value, triggerType: ($("p-trigger") as HTMLSelectElement).value, category: ($("p-cat") as HTMLInputElement).value, actions }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(T("soar.created")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function reload(): Promise<void> {
  return fetch("/api/soar").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
  ($("btn-new") as HTMLButtonElement).onclick = newDialog;
  reload().then(render).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
