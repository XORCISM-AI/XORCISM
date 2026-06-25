/** soc.ts — SOC Operations cockpit (/soc). MTTD/MTTA/MTTR KPIs, on-call roster + shifts, open-incident
 * queue with escalation procedure + IR playbooks (attach + step tracking). Reads /api/soc. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2800); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

const PHASE_KEY: Record<string, string> = {
  "Detection & Analysis": "soc.phaseDetection", "Containment": "soc.phaseContainment",
  "Eradication": "soc.phaseEradication", "Recovery": "soc.phaseRecovery", "Post-Incident": "soc.phasePost",
};
const phaseLabel = (p: string): string => (PHASE_KEY[p] ? t(PHASE_KEY[p]) : p);

interface Q { id: number; name: string; severity: string; status: string; tier: string; owner: string; detectedAt: string | null; ageMinutes: number | null; acknowledged: boolean; ackBreached: boolean; ackSlaMin: number; playbookId: number | null; playbookName: string | null; playbookDone: number; playbookTotal: number; escalations: number; }
interface Data { metrics: any; onCall: any[]; shifts: any[]; coverageNow: string[]; coverageGaps: string[]; queue: Q[]; worklist: any[]; escalation: { tiers: any[] }; playbooks: any[]; summary: any }

let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="so-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const bar = (pct: number): string => `<span class="bar"><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></span>`;
function age(m: number | null): string { if (m == null) return "—"; if (m < 60) return `${m}m`; const h = Math.floor(m / 60); return h < 24 ? `${h}h${m % 60 ? ` ${m % 60}m` : ""}` : `${Math.floor(h / 24)}d ${h % 24}h`; }
function mttd(v: number | null): string { if (v == null) return "—"; return v < 90 ? `${Math.round(v)} min` : `${(v / 60).toFixed(1)} h`; }

function queueRow(q: Q): string {
  const ackPill = q.acknowledged ? `<span class="pill p-ok">${t("soc.ack")}</span>` : q.ackBreached ? `<span class="pill p-bad">${t("soc.ackOverdue")}</span>` : `<span class="pill p-warn">${t("soc.unack")}</span>`;
  const pb = q.playbookId ? `${bar(q.playbookTotal ? Math.round((q.playbookDone / q.playbookTotal) * 100) : 0)} <span class="muted" style="font-size:11px">${q.playbookDone}/${q.playbookTotal}</span>` : `<span class="muted">${t("soc.none")}</span>`;
  return `<tr>
    <td><span class="nm">${esc(q.name)}</span>${q.escalations ? ` <span class="muted" style="font-size:10px">↑${q.escalations}</span>` : ""}</td>
    <td><span class="sev ${scls(q.severity)}">${esc(q.severity || "—")}</span></td>
    <td><span class="tier">${esc(q.tier)}</span></td>
    <td>${esc(q.owner || "—")}</td>
    <td>${age(q.ageMinutes)}</td>
    <td>${ackPill}</td>
    <td>${q.playbookId ? `<a class="muted" style="cursor:pointer;color:#a5b4fc" data-pb="${q.id}">${esc(q.playbookName || t("soc.playbook"))}</a><br>${pb}` : pb}</td>
    <td style="white-space:nowrap">
      ${q.acknowledged ? "" : `<button class="btn-sm2" data-ack="${q.id}">${t("soc.btnAck")}</button> `}
      <button class="btn-sm2" data-esc="${q.id}">${t("soc.btnEscalate")}</button>
      <button class="btn-sm2" data-attach="${q.id}">${t("soc.btnPlaybook")}</button>
    </td>
  </tr>`;
}

function render(): void {
  const d = DATA!; const m = d.metrics; const s = d.summary;
  const cards = [
    card(t("soc.cMttd"), mttd(m.mttdMinutes), fmt("soc.cMttd.foot", { n: m.detectedCount }), m.mttdMinutes != null && m.mttdMinutes <= 60 ? "#4ade80" : "#fbbf24"),
    card(t("soc.cMtta"), mttd(m.mttaMinutes), fmt("soc.cMtta.foot", { n: m.ackCount }), m.mttaMinutes != null && m.mttaMinutes <= 30 ? "#4ade80" : "#fbbf24"),
    card(t("soc.cMttr"), m.mttrHours == null ? "—" : `${m.mttrHours} h`, fmt("soc.cMttr.foot", { n: m.resolvedCount }), m.mttrHours != null && m.mttrHours <= 24 ? "#4ade80" : "#fbbf24"),
    card(t("soc.cOpen"), String(s.openIncidents), fmt("soc.cOpen.foot", { c: s.criticalOpen, b: s.ackBreached }), s.ackBreached ? "#f87171" : undefined),
    card(t("soc.cOnCall"), String(s.onCallNow), s.coverageGaps ? fmt("soc.cOnCall.gaps", { n: s.coverageGaps }) : t("soc.cOnCall.full"), s.coverageGaps ? "#fbbf24" : "#4ade80"),
    card(t("soc.cEscalations"), String(s.escalationsToday), t("soc.cEscalations.foot"), "#60a5fa"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.slice(0, 30).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> — ${esc(w.reason)} <a class="muted" style="cursor:pointer;color:#a5b4fc;margin-left:auto" data-open="${w.id}">${t("soc.openLink")}</a></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">${t("soc.noWork")}</div>`;

  const queue = d.queue.length
    ? `<table class="so"><thead><tr><th>${t("soc.thIncident")}</th><th>${t("soc.thSev")}</th><th>${t("soc.thTier")}</th><th>${t("soc.thOwner")}</th><th>${t("soc.thAge")}</th><th>${t("soc.thAck")}</th><th>${t("soc.thPlaybook")}</th><th></th></tr></thead><tbody>${d.queue.map(queueRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("soc.noQueue")}</div>`;

  const onCall = d.onCall.length
    ? d.onCall.map((o) => `<div class="oncall"><span class="tier">${esc(o.tier)}</span> <b style="color:#e2e8f0">${esc(o.person)}</b>${o.onCall ? ` <span class="pill p-ok">${t("soc.onCallPill")}</span>` : ""}<span style="flex:1"></span><span class="muted" style="font-size:11px">→ ${esc(o.end)}</span></div>`).join("")
    : `<div class="muted" style="padding:6px 0">${t("soc.noOnCall")}</div>`;
  const cov = `<div style="margin-top:8px;font-size:12px;color:#94a3b8">${t("soc.coverage")}: ${d.coverageNow.length ? d.coverageNow.map((tn) => `<span class="tier">${esc(tn)}</span>`).join(" ") : `<span class='pill p-bad'>${t("soc.none")}</span>`}${d.coverageGaps.length ? ` · ${t("soc.gaps")}: ${d.coverageGaps.map((tn) => `<span class="pill p-warn">${esc(tn)}</span>`).join(" ")}` : ""}</div>`;

  const tiers = d.escalation.tiers.map((ti) => `<div class="tierrow"><span class="tier">${esc(ti.name)}</span> <b style="color:#e2e8f0">${esc(ti.role)}</b><span style="flex:1"></span><span class="muted" style="font-size:11px">${fmt("soc.tierMeta", { a: ti.ack, r: Math.round(ti.resolve / 60) })}</span></div>`).join("");

  const shifts = d.shifts.length
    ? `<table class="so"><thead><tr><th>${t("soc.thAnalyst")}</th><th>${t("soc.thTier")}</th><th>${t("soc.thStart")}</th><th>${t("soc.thEnd")}</th><th>${t("soc.thOnCall")}</th><th></th></tr></thead><tbody>${d.shifts.map((sh) => `<tr><td><span class="nm">${esc(sh.person)}</span>${sh.active ? ` <span class="pill p-ok">${t("soc.now")}</span>` : ""}</td><td><span class="tier">${esc(sh.tier)}</span></td><td class="muted" style="font-size:12px">${esc(sh.start)}</td><td class="muted" style="font-size:12px">${esc(sh.end)}</td><td>${sh.onCall ? "✓" : ""}</td><td style="text-align:right"><button class="btn-sm2" data-delshift="${sh.id}" title="${t("soc.delShiftTitle")}">✕</button></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("soc.noShifts")}</div>`;

  const pbs = d.playbooks.length
    ? `<div class="grid2">${d.playbooks.map((p) => `<div class="panel"><div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span class="pbcat">${esc(p.category)}</span><span class="sev ${scls(p.severity)}">${esc(p.severity)}</span><span style="flex:1"></span><button class="btn-sm2" data-managepb="${p.id}">${t("soc.manage")}</button></div><div class="nm">${esc(p.name)}</div><div class="muted" style="font-size:12px;margin-top:2px">${fmt("soc.pbSteps", { n: p.steps })}</div></div>`).join("")}</div>`
    : `<div class="muted" style="padding:8px 0">${t("soc.noPlaybooks")}</div>`;

  $("so-body").innerHTML = `<div class="so-cards">${cards}</div>
    <div class="so-section">${fmt("soc.secWorklist", { n: d.worklist.length })}</div>${work}
    <div class="so-section">${fmt("soc.secQueue", { n: d.queue.length })}</div>${queue}
    <div class="grid2" style="margin-top:8px">
      <div class="panel"><div class="so-section" style="margin-top:0">${fmt("soc.secOnCall", { n: d.onCall.length })}</div>${onCall}${cov}</div>
      <div class="panel"><div class="so-section" style="margin-top:0">${t("soc.secEscalation")}</div>${tiers}</div>
    </div>
    <div class="so-section" style="display:flex;align-items:center">${fmt("soc.secShifts", { n: d.shifts.length })}<span style="flex:1"></span><button class="btn-sm2" data-newshift="1">${t("soc.addShift")}</button></div>${shifts}
    <div class="so-section" style="display:flex;align-items:center">${fmt("soc.secPlaybooks", { n: d.playbooks.length })}<span style="flex:1"></span><button class="btn-sm2" data-newpb="1">${t("soc.newPlaybook")}</button></div>${pbs}`;
  wire();
}

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("ack", (id) => act(`/api/soc/incident/${id}/ack`, {}, t("soc.toastAck")));
  on("esc", (id) => { const reason = prompt(t("soc.escPrompt"), t("soc.escDefault")); if (reason == null) return; act(`/api/soc/incident/${id}/escalate`, { reason }, t("soc.toastEsc")); });
  on("attach", (id) => attachPlaybook(id));
  on("pb", (id) => openPlaybook(id));
  on("open", (id) => openPlaybook(id));
  on("newpb", () => newPlaybookDialog());
  on("managepb", (id) => managePlaybook(id));
  on("newshift", () => newShiftDialog());
  on("delshift", (id) => {
    if (!confirm(t("soc.confirmDelShift"))) return;
    fetch(`/api/soc/shift/${id}`, { method: "DELETE" })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("soc.shiftDeleted")); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  });
}

function newShiftDialog(): void {
  const tiers = (DATA?.escalation.tiers || []).map((ti: any) => ti.name);
  $("so-dlg").innerHTML = `${PBFORM_CSS}
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="font-size:16px;color:#e7ebf3">${t("soc.newShiftTitle")}</span><span style="flex:1"></span><button class="btn-sm2" id="so-close">${t("soc.close")}</button></div>
    <div class="pbform">
      <label>${t("soc.thAnalyst")}<input id="ns-person" placeholder="${t("soc.fPersonPh")}"></label>
      <div style="display:flex;gap:8px">
        <label style="flex:1">${t("soc.thTier")}<select id="ns-tier">${tiers.map((nm: string) => `<option>${esc(nm)}</option>`).join("")}</select></label>
        <label class="ns-chk" style="flex:1;display:flex;align-items:center;gap:6px;margin-top:24px"><input type="checkbox" id="ns-oncall" style="width:auto;margin-top:0"> ${t("soc.thOnCall")}</label>
      </div>
      <div style="display:flex;gap:8px">
        <label style="flex:1">${t("soc.thStart")}<input id="ns-start" type="datetime-local"></label>
        <label style="flex:1">${t("soc.thEnd")}<input id="ns-end" type="datetime-local"></label>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px"><button class="btn-sm2" id="ns-save" style="border-color:#fb923c;color:#fdba74">${t("soc.createShift")}</button></div>
    </div>`;
  $("so-modal").classList.add("show");
  $("so-close").onclick = closeModal;
  ($("ns-save") as HTMLButtonElement).onclick = () => {
    const person = ($("ns-person") as HTMLInputElement).value.trim();
    if (!person) { toast(t("soc.personRequired")); return; }
    const start = ($("ns-start") as HTMLInputElement).value, end = ($("ns-end") as HTMLInputElement).value;
    if (!start || !end) { toast(t("soc.datesRequired")); return; }
    fetch("/api/soc/shift", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ personName: person, tier: ($("ns-tier") as HTMLSelectElement).value, start, end, onCall: ($("ns-oncall") as HTMLInputElement).checked }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("soc.shiftCreated")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

const PB_PHASES = ["Detection & Analysis", "Containment", "Eradication", "Recovery", "Post-Incident"];
const PBFORM_CSS = `<style>.pbform label{display:block;font-size:12px;color:#94a3b8;margin-top:8px}
  .pbform input,.pbform select,.pbform textarea,.pbaddstep input,.pbaddstep select{box-sizing:border-box;background:#0f1117;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit}
  .pbform input,.pbform select,.pbform textarea{width:100%;margin-top:3px}.pbform textarea{font-family:ui-monospace,monospace}</style>`;
function closeModal(): void { $("so-modal").classList.remove("show"); }

function newPlaybookDialog(): void {
  $("so-dlg").innerHTML = `${PBFORM_CSS}
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="font-size:16px;color:#e7ebf3">${t("soc.newPbTitle")}</span><span style="flex:1"></span><button class="btn-sm2" id="so-close">${t("soc.close")}</button></div>
    <div class="pbform">
      <label>${t("soc.fName")}<input id="npb-name" placeholder="${t("soc.fNamePh")}"></label>
      <div style="display:flex;gap:8px">
        <label style="flex:1">${t("soc.fCategory")}<input id="npb-cat" placeholder="${t("soc.fCategoryPh")}"></label>
        <label style="flex:1">${t("soc.fSeverity")}<select id="npb-sev">${["Critical", "High", "Medium", "Low"].map((sv) => `<option value="${sv}"${sv === "Medium" ? " selected" : ""}>${esc(sevLabel(sv))}</option>`).join("")}</select></label>
      </div>
      <label>${t("soc.fDescription")}<input id="npb-desc" placeholder="${t("soc.optional")}"></label>
      <label>${t("soc.fSteps")} <span class="muted" style="font-size:11px">${t("soc.stepsHelp")}</span>
        <textarea id="npb-steps" rows="7" placeholder="${esc(t("soc.stepsPh"))}"></textarea></label>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px"><button class="btn-sm2" id="npb-save" style="border-color:#fb923c;color:#fdba74">${t("soc.createPb")}</button></div>
    </div>`;
  $("so-modal").classList.add("show");
  $("so-close").onclick = closeModal;
  ($("npb-save") as HTMLButtonElement).onclick = () => {
    const name = ($("npb-name") as HTMLInputElement).value.trim();
    if (!name) { toast(t("soc.nameRequired")); return; }
    const steps = ($("npb-steps") as HTMLTextAreaElement).value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
      const p = l.split("|").map((x) => x.trim());
      if (p.length >= 3) return { phase: p[0], title: p[1], description: p.slice(2).join(" | ") };
      if (p.length === 2) return { phase: p[0], title: p[1] };
      return { title: p[0] };
    });
    fetch("/api/soc/playbook", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, category: ($("npb-cat") as HTMLInputElement).value.trim(), severity: ($("npb-sev") as HTMLSelectElement).value, description: ($("npb-desc") as HTMLInputElement).value.trim(), steps }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("soc.pbCreated")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

const sevLabel = (s: string): string => ({ Critical: "soc.sevCritical", High: "soc.sevHigh", Medium: "soc.sevMedium", Low: "soc.sevLow" }[s] ? t(({ Critical: "soc.sevCritical", High: "soc.sevHigh", Medium: "soc.sevMedium", Low: "soc.sevLow" } as Record<string, string>)[s]) : s);

function managePlaybook(id: number): void {
  fetch("/api/soc/playbooks").then((r) => r.json()).then((d: { playbooks: any[] }) => {
    const pb = d.playbooks.find((p) => p.id === id);
    if (!pb) { toast(t("soc.pbNotFound")); return; }
    const steps = pb.steps.length ? pb.steps.map((st: any) => `
      <div class="pstep" style="align-items:flex-start">
        <div class="pt"><div class="tt">${st.order}. ${esc(st.title)} <span class="muted" style="font-size:11px">· ${esc(phaseLabel(st.phase))}</span></div><div class="dd">${esc(st.description)}</div></div>
        <button class="btn-sm2" data-delstep="${st.id}" title="${t("soc.delStepTitle")}">✕</button>
      </div>`).join("") : `<div class="muted" style="padding:6px 0">${t("soc.noSteps")}</div>`;
    $("so-dlg").innerHTML = `${PBFORM_CSS}
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="font-size:16px;color:#e7ebf3">${esc(pb.name)}</span><span class="pbcat">${esc(pb.category)}</span><span class="sev ${scls(pb.severity)}">${esc(pb.severity)}</span><span style="flex:1"></span><button class="btn-sm2" id="so-close">${t("soc.close")}</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:8px">${fmt("soc.pbStepCount", { n: pb.steps.length })} · ${esc(pb.description || t("soc.nistPb"))}</div>
      ${steps}
      <div class="pbaddstep" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:10px;border-top:1px solid #1e2133;padding-top:10px">
        <select id="as-phase">${PB_PHASES.map((p) => `<option value="${p}">${esc(phaseLabel(p))}</option>`).join("")}</select>
        <input id="as-title" placeholder="${t("soc.stepTitlePh")}" style="flex:1;min-width:150px">
        <input id="as-desc" placeholder="${t("soc.stepDescPh")}" style="flex:2;min-width:150px">
        <button class="btn-sm2" id="as-add">${t("soc.addStep")}</button>
      </div>
      <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="pb-del" style="border-color:#7f1d1d;color:#fca5a5">${t("soc.delPlaybook")}</button></div>`;
    $("so-modal").classList.add("show");
    $("so-close").onclick = closeModal;
    Array.prototype.forEach.call(document.querySelectorAll("[data-delstep]"), (b: HTMLElement) => {
      b.onclick = () => fetch(`/api/soc/playbook-step/${b.getAttribute("data-delstep")}`, { method: "DELETE" })
        .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(() => { toast(t("soc.stepDeleted")); managePlaybook(id); reload().then(render); }).catch((e) => toast("⚠️ " + e));
    });
    ($("as-add") as HTMLButtonElement).onclick = () => {
      const title = ($("as-title") as HTMLInputElement).value.trim();
      if (!title) { toast(t("soc.titleRequired")); return; }
      fetch(`/api/soc/playbook/${id}/step`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phase: ($("as-phase") as HTMLSelectElement).value, title, description: ($("as-desc") as HTMLInputElement).value.trim() }) })
        .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
        .then(() => { toast(t("soc.stepAdded")); managePlaybook(id); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
    };
    ($("pb-del") as HTMLButtonElement).onclick = () => {
      if (!confirm(fmt("soc.confirmDelPb", { name: pb.name }))) return;
      fetch(`/api/soc/playbook/${id}`, { method: "DELETE" })
        .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
        .then(() => { toast(t("soc.pbDeleted")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
    };
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function act(url: string, body: unknown, okMsg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function attachPlaybook(incidentId: number): void {
  const d = DATA!;
  if (!d.playbooks.length) { toast(t("soc.noPbAvail")); return; }
  const list = d.playbooks.map((p, i) => `${i + 1}. ${p.name} (${p.category})`).join("\n");
  const pick = prompt(t("soc.attachPrompt") + "\n\n" + list);
  if (!pick) return;
  const idx = Number(pick) - 1;
  if (!d.playbooks[idx]) { toast(t("soc.invalidChoice")); return; }
  act(`/api/soc/incident/${incidentId}/playbook`, { playbookId: d.playbooks[idx].id }, t("soc.pbAttached"));
}

function openPlaybook(incidentId: number): void {
  const q = DATA!.queue.find((x) => x.id === incidentId);
  fetch(`/api/soc/incident/${incidentId}/playbook`).then((r) => r.json()).then((d: { phases: any[]; progress: any }) => {
    if (!d.phases.length) { toast(t("soc.noPbAttached")); return; }
    const statusOpts: [string, string][] = [["todo", "soc.stTodo"], ["in_progress", "soc.stInProgress"], ["done", "soc.stDone"], ["na", "soc.stNa"]];
    const phases = d.phases.map((ph) => `<div class="phase"><div class="ph-head">${esc(phaseLabel(ph.name))}</div>${ph.steps.map((st: any) => `
      <div class="pstep ${st.status === "done" ? "st-done" : ""}" data-step="${st.id}">
        <div class="pt"><div class="tt">${esc(st.title)}</div><div class="dd">${esc(st.description)}</div></div>
        <select class="pstep-status" data-step="${st.id}">
          ${statusOpts.map(([v, k]) => `<option value="${v}"${st.status === v ? " selected" : ""}>${esc(t(k))}</option>`).join("")}
        </select>
      </div>`).join("")}</div>`).join("");
    $("so-dlg").innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px"><span style="font-size:16px;color:#e7ebf3">${esc(q?.name || fmt("soc.incidentN", { id: incidentId }))}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2" id="so-close">${t("soc.close")}</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:8px">${fmt("soc.irProgress", { bar: bar(d.progress.pct), done: d.progress.done, total: d.progress.total, pct: d.progress.pct })}</div>${phases}`;
    $("so-modal").classList.add("show");
    $("so-close").onclick = () => $("so-modal").classList.remove("show");
    Array.prototype.forEach.call(document.querySelectorAll(".pstep-status"), (sel: HTMLSelectElement) => {
      sel.onchange = () => {
        fetch(`/api/soc/playbook-step/${sel.getAttribute("data-step")}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: sel.value }) })
          .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
          .then(() => openPlaybook(incidentId)).then(() => reload().then(render)).catch((e) => toast("⚠️ " + e));
      };
    });
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/soc").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("so-modal").addEventListener("click", (e) => { if (e.target === $("so-modal")) $("so-modal").classList.remove("show"); });
  reload().then(render).catch((e) => { $("so-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
