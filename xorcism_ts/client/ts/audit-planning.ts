/**
 * audit-planning.ts — Audit planning cockpit (/audit-planning).
 * KPIs + a yearly calendar of the audit programme + planned-item CRUD (type / framework / lead
 * auditor / planned window / recurrence / status) + "launch" a planned item into a real AUDIT.
 * All from /api/audit-planning*. i18n via the window.t global (FR-only, English fallback).
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
function translateChrome(): void { document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim()); }); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function send(method: string, u: string, b?: any): Promise<any> { const r = await fetch(u, { method, credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: b ? JSON.stringify(b) : undefined }); const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d; }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => (el.className = ""), 2200); }

let DATA: any = { plans: [], items: [], kpis: {}, byMonth: {}, byType: {}, options: {} };
let PLAN = 0; // selected plan
let PERSONS: { id: number; label: string }[] = [];
const opts = (arr: string[], sel: unknown, key?: string): string => arr.map((o) => `<option value="${esc(o)}"${String(sel ?? "") === o ? " selected" : ""}>${key ? esc(t(key + "." + o, o)) : esc(o)}</option>`).join("");
const personOpts = (sel: unknown): string => `<option value="">—</option>` + PERSONS.map((p) => `<option value="${p.id}"${String(sel ?? "") === String(p.id) ? " selected" : ""}>${esc(p.label || ("#" + p.id))}</option>`).join("");
const card = (lbl: string, val: string, color?: string): string => `<div class="ap-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div></div>`;

async function load(): Promise<void> {
  try { DATA = await getJSON("/api/audit-planning"); } catch (e) { $("ap-body").innerHTML = `<div class="muted" style="padding:20px">${t("aup.failLoad", "Failed to load")}: ${esc(String(e))}</div>`; return; }
  if (!PERSONS.length) { try { PERSONS = await getJSON("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName"); } catch { PERSONS = []; } }
  if (!PLAN || !DATA.plans.some((p: any) => p.PlanID === PLAN)) PLAN = DATA.plans[0]?.PlanID || 0;
  render();
}

function render(): void {
  const k = DATA.kpis;
  if (!DATA.plans.length) {
    $("ap-body").innerHTML = `<div class="ap-sec">${t("aup.noPlan", "No audit plan yet")}</div>
      <div class="muted" style="margin-bottom:8px">${t("aup.noPlanMsg", "Create an audit programme (typically annual) to start scheduling audits.")}</div>${newPlanForm()}`;
    wireNewPlan(); return;
  }
  const cards = [
    card(t("aup.k.plans", "Plans"), String(k.plans ?? 0)),
    card(t("aup.k.planned", "Planned audits"), String(k.planned ?? 0)),
    card(t("aup.k.upcoming", "Upcoming (30d)"), String(k.upcoming ?? 0), k.upcoming ? "#fbbf24" : undefined),
    card(t("aup.k.overdue", "Overdue"), String(k.overdue ?? 0), k.overdue ? "#f87171" : "#34d399"),
    card(t("aup.k.inProgress", "In progress"), String(k.inProgress ?? 0), k.inProgress ? "#fbbf24" : undefined),
    card(t("aup.k.completed", "Completed"), String(k.completed ?? 0), "#34d399"),
    card(t("aup.k.completion", "Completion"), k.completionPct == null ? "—" : `${k.completionPct}%`, (k.completionPct ?? 0) >= 70 ? "#34d399" : "#fbbf24"),
  ].join("");

  const plan = DATA.plans.find((p: any) => p.PlanID === PLAN) || DATA.plans[0];
  const planSel = `<select class="in" id="ap-plan-sel">${DATA.plans.map((p: any) => `<option value="${p.PlanID}"${p.PlanID === PLAN ? " selected" : ""}>${esc(p.Name)}${p.Year ? ` (${p.Year})` : ""}</option>`).join("")}</select>`;
  const planMeta = `<span class="muted" style="font-size:12px">${esc(plan.Framework || "")}${plan.Owner ? ` · ${esc(plan.Owner)}` : ""} · <span class="st st-${esc(String(plan.Status))}">${esc(plan.Status)}</span>${plan.ApprovedBy ? ` · ✓ ${esc(plan.ApprovedBy)}` : ""}</span>`;

  const items = DATA.items.filter((i: any) => i.PlanID === PLAN);
  $("ap-body").innerHTML = `
    <div class="ap-cards">${cards}</div>
    <div class="ap-sec">${t("aup.programme", "Audit programme")}
      <span style="flex:1"></span>${planSel} ${planMeta}
      <button class="btn sm" id="ap-approve">${t("aup.approve", "Approve")}</button>
      <button class="btn sm" id="ap-newplan">＋ ${t("aup.newPlan", "New plan")}</button>
      <button class="btn sm" id="ap-delplan" title="${t("aup.deletePlan", "Delete plan")}">✕</button></div>
    <div class="ap-sec">${t("aup.calendar", "Calendar")} ${plan.Year || ""}</div>
    <div class="cal">${calendarHtml(plan.Year)}</div>
    <div class="ap-sec">${t("aup.plannedAudits", "Planned audits")} (${items.length})</div>
    <div style="overflow-x:auto">${itemsTable(items)}</div>
    <div class="ap-sec">${t("aup.addAudit", "Add a planned audit")}</div>${addItemForm()}`;

  wireRender();
}

function calendarHtml(year: number): string {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return months.map((mn, i) => {
    const key = `${year}-${String(i + 1).padStart(2, "0")}`;
    const b = DATA.byMonth[key];
    return `<div class="mo${b ? " has" : ""}"><div class="m">${t("aup.mon." + (i + 1), mn)}</div><div class="n">${b ? b.total : ""}</div>
      ${b && b.completed ? `<span class="b b-done">✓${b.completed}</span>` : ""}${b && b.overdue ? ` <span class="b b-over">!${b.overdue}</span>` : ""}</div>`;
  }).join("");
}

function itemsTable(items: any[]): string {
  const o = DATA.options;
  const rows = items.map((i: any) => {
    const win = [i.PlannedStartDate ? String(i.PlannedStartDate).slice(0, 10) : "", i.PlannedEndDate ? "→ " + String(i.PlannedEndDate).slice(0, 10) : ""].filter(Boolean).join(" ");
    const launched = i.AuditID != null;
    return `<tr data-item="${i.ItemID}">
      <td><b>${esc(i.Title)}</b>${i.Priority ? ` <span class="tag">${esc(i.Priority)}</span>` : ""}${i.Frequency && i.Frequency !== "one-off" ? ` <span class="muted" style="font-size:10px">↻ ${esc(t("aup.freq." + i.Frequency, i.Frequency))}</span>` : ""}</td>
      <td><span class="tag t-${esc(String(i.AuditType || ""))}">${esc(i.AuditType || "—")}</span></td>
      <td class="muted">${esc(i.Framework || "—")}</td>
      <td${i.overdue ? ' class="ov"' : ""}>${esc(win || "—")}</td>
      <td>${esc(i.LeadAuditorName || i.AuditorName || "—")}</td>
      <td><select class="in ap-status st-${esc(String(i.Status))}" data-item="${i.ItemID}">${opts(o.itemStatuses, i.Status, "aup.is")}</select></td>
      <td>${launched ? `<a href="/?db=XCOMPLIANCE&table=AUDIT&editCol=AuditID&editVal=${i.AuditID}" title="${esc(i.LinkedAuditName || "")}" style="color:#6ee7b7;text-decoration:none">🔗 AUDIT #${i.AuditID}</a>` : `<button class="btn sm ap-launch" data-item="${i.ItemID}">${t("aup.launch", "▶ Launch")}</button>`}</td>
      <td><button class="btn sm ap-edit" data-item="${i.ItemID}">✎</button> <button class="btn sm ap-del" data-item="${i.ItemID}" style="color:#f87171">✕</button></td>
    </tr>`;
  }).join("") || `<tr><td colspan="8" class="muted" style="padding:12px;text-align:center">${t("aup.noItems", "No planned audits in this plan yet.")}</td></tr>`;
  return `<table class="ap"><thead><tr>
    <th>${t("aup.h.audit", "Audit")}</th><th>${t("aup.h.type", "Type")}</th><th>${t("aup.h.framework", "Framework")}</th><th>${t("aup.h.window", "Planned window")}</th><th>${t("aup.h.lead", "Lead auditor")}</th><th>${t("aup.h.status", "Status")}</th><th>${t("aup.h.execution", "Execution")}</th><th></th>
  </tr></thead><tbody>${rows}</tbody></table>`;
}

function addItemForm(): string {
  const o = DATA.options; const inl = "class=\"in\"";
  return `<div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr auto;gap:6px;align-items:center">
    <input ${inl} id="ai-title" placeholder="${t("aup.f.title", "Audit title")}">
    <select ${inl} id="ai-type"><option value="">${t("aup.f.type", "Type")}</option>${opts(o.auditTypes, "")}</select>
    <input ${inl} id="ai-fw" placeholder="${t("aup.f.framework", "Framework")}">
    <input ${inl} id="ai-start" type="date" title="${t("aup.f.start", "Planned start")}">
    <select ${inl} id="ai-freq">${opts(o.frequencies, "one-off", "aup.freq")}</select>
    <select ${inl} id="ai-lead">${personOpts("")}</select>
    <button class="btn pri" id="ai-add">＋ ${t("aup.add", "Add")}</button></div>`;
}
function newPlanForm(): string {
  return `<div style="display:grid;grid-template-columns:1.6fr .6fr 1fr 1fr auto;gap:6px;align-items:center;max-width:820px">
    <input class="in" id="np-name" placeholder="${t("aup.f.planName", "Plan name (e.g. Annual audit programme 2026)")}">
    <input class="in" id="np-year" type="number" placeholder="${t("aup.f.year", "Year")}" value="${new Date().getFullYear()}">
    <input class="in" id="np-fw" placeholder="${t("aup.f.framework", "Framework")}">
    <input class="in" id="np-owner" placeholder="${t("aup.f.owner", "Owner")}">
    <button class="btn pri" id="np-add">＋ ${t("aup.createPlan", "Create plan")}</button></div>`;
}

function wireRender(): void {
  ($("ap-plan-sel") as HTMLSelectElement).onchange = (e) => { PLAN = Number((e.target as HTMLSelectElement).value); render(); };
  $("ap-newplan").onclick = () => { const b = $("ap-body"); b.insertAdjacentHTML("afterbegin", `<div id="ap-np">${newPlanForm()}</div>`); wireNewPlan(); };
  $("ap-approve").onclick = async () => { try { await send("PATCH", `/api/audit-planning/plan/${PLAN}`, { approve: true }); toast(t("aup.approved", "Plan approved")); await load(); } catch (e) { toast(`⚠️ ${esc(e)}`); } };
  $("ap-delplan").onclick = async () => { if (!confirm(t("aup.delPlanConfirm", "Delete this plan and all its planned audits?"))) return; try { await send("DELETE", `/api/audit-planning/plan/${PLAN}`); PLAN = 0; await load(); } catch (e) { toast(`⚠️ ${esc(e)}`); } };
  $("ai-add").onclick = async () => {
    const v = (id: string) => ($(id) as HTMLInputElement | HTMLSelectElement).value;
    const title = v("ai-title").trim(); if (!title) { toast(t("aup.titleReq", "Audit title required")); return; }
    try { await send("POST", `/api/audit-planning/plan/${PLAN}/item`, { title, auditType: v("ai-type"), framework: v("ai-fw"), plannedStartDate: v("ai-start"), frequency: v("ai-freq"), leadAuditorPersonId: v("ai-lead") }); await load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  };
  document.querySelectorAll<HTMLSelectElement>(".ap-status").forEach((sel) => sel.onchange = async () => {
    try { const r = await send("PATCH", `/api/audit-planning/item/${sel.dataset.item}`, { status: sel.value }); if (r.scheduledNext) toast(t("aup.nextScheduled", "Next occurrence scheduled")); await load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  });
  document.querySelectorAll<HTMLElement>(".ap-launch").forEach((b) => b.onclick = async () => {
    if (!confirm(t("aup.launchConfirm", "Launch this planned audit into a real AUDIT?"))) return;
    try { const r = await send("POST", `/api/audit-planning/item/${b.dataset.item}/launch`); toast(`${t("aup.launched", "Audit launched")} (#${r.auditId})`); await load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  });
  document.querySelectorAll<HTMLElement>(".ap-del").forEach((b) => b.onclick = async () => { if (!confirm(t("aup.delItemConfirm", "Delete this planned audit?"))) return; try { await send("DELETE", `/api/audit-planning/item/${b.dataset.item}`); await load(); } catch (e) { toast(`⚠️ ${esc(e)}`); } });
  document.querySelectorAll<HTMLElement>(".ap-edit").forEach((b) => b.onclick = () => editItem(Number(b.dataset.item)));
}

function wireNewPlan(): void {
  const add = document.getElementById("np-add"); if (!add) return;
  add.onclick = async () => {
    const v = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
    const name = v("np-name").trim(); if (!name) { toast(t("aup.planNameReq", "Plan name required")); return; }
    try { const r = await send("POST", "/api/audit-planning/plan", { name, year: v("np-year"), framework: v("np-fw"), owner: v("np-owner") }); PLAN = r.planId; await load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  };
}

// Inline edit of a planned item (scope / dates / auditor / priority) via a small modal.
function editItem(itemId: number): void {
  const i = DATA.items.find((x: any) => x.ItemID === itemId); if (!i) return;
  const o = DATA.options;
  document.getElementById("ap-edit-modal")?.remove();
  const wrap = document.createElement("div"); wrap.id = "ap-edit-modal";
  wrap.style.cssText = "position:fixed;inset:0;background:rgba(4,6,15,.72);display:flex;align-items:flex-start;justify-content:center;z-index:1200;overflow:auto";
  wrap.innerHTML = `<div style="background:#0f1322;border:1px solid #2d3250;border-radius:12px;padding:18px 20px;margin:44px 16px;max-width:560px;width:100%">
    <b style="font-size:15px;color:#e7ebf3">${t("aup.editAudit", "Edit planned audit")}</b>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px">
      <label class="apf" style="grid-column:span 2">${t("aup.f.title", "Title")}<input class="in" id="e-title" value="${esc(i.Title)}" style="width:100%;box-sizing:border-box"></label>
      <label class="apf">${t("aup.f.type", "Type")}<select class="in" id="e-type"><option value="">—</option>${opts(o.auditTypes, i.AuditType)}</select></label>
      <label class="apf">${t("aup.f.framework", "Framework")}<input class="in" id="e-fw" value="${esc(i.Framework || "")}"></label>
      <label class="apf">${t("aup.f.start", "Planned start")}<input class="in" id="e-start" type="date" value="${esc((i.PlannedStartDate || "").slice(0, 10))}"></label>
      <label class="apf">${t("aup.f.end", "Planned end")}<input class="in" id="e-end" type="date" value="${esc((i.PlannedEndDate || "").slice(0, 10))}"></label>
      <label class="apf">${t("aup.f.freq", "Frequency")}<select class="in" id="e-freq">${opts(o.frequencies, i.Frequency, "aup.freq")}</select></label>
      <label class="apf">${t("aup.f.priority", "Priority")}<input class="in" id="e-prio" value="${esc(i.Priority || "")}" placeholder="Low/Medium/High/Critical"></label>
      <label class="apf">${t("aup.f.lead", "Lead auditor")}<select class="in" id="e-lead">${personOpts(i.LeadAuditorPersonID)}</select></label>
      <label class="apf">${t("aup.f.auditor", "Auditor (name)")}<input class="in" id="e-auditor" value="${esc(i.AuditorName || "")}"></label>
      <label class="apf" style="grid-column:span 2">${t("aup.f.scope", "Scope")}<textarea class="in" id="e-scope" rows="2" style="width:100%;box-sizing:border-box">${esc(i.Scope || "")}</textarea></label>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px"><button class="btn" id="e-cancel">${t("aup.cancel", "Cancel")}</button><button class="btn pri" id="e-save">${t("aup.save", "Save")}</button></div>
  </div>`;
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  $("e-cancel").onclick = close;
  $("e-save").onclick = async () => {
    const v = (id: string) => ($(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
    try { await send("PATCH", `/api/audit-planning/item/${itemId}`, { title: v("e-title"), auditType: v("e-type"), framework: v("e-fw"), plannedStartDate: v("e-start"), plannedEndDate: v("e-end"), frequency: v("e-freq"), priority: v("e-prio"), leadAuditorPersonId: v("e-lead"), auditorName: v("e-auditor"), scope: v("e-scope") }); close(); await load(); }
    catch (e) { toast(`⚠️ ${esc(e)}`); }
  };
}

document.addEventListener("DOMContentLoaded", () => { translateChrome(); void load(); });
