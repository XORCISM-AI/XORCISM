/**
 * compliance-management.ts — Compliance / GRC inventory + governance worklist
 * (/compliance-management). Audits + open-findings/policy worklist, from /api/compliance-management.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface AuditRow { id: number; name: string; type: string; status: string; date: string | null; completed: boolean; findings: number; open: number; high: number; overdue: number; unassigned: number; score: number; }
interface Finding { id: number; audit: string; name: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; overdue: boolean; unassigned: boolean; noPlan: boolean; kind: "finding" | "policy"; label: string; plans?: number; openPlans?: number; }
const FLD = "background:#0f1117;border:1px solid #2d3250;color:#e2e8f0;border-radius:7px;padding:7px 9px;font-size:12.5px;box-sizing:border-box;width:100%";
interface Inventory {
  rows: AuditRow[]; findings: Finding[];
  summary: { audits: number; inProgress: number; planned: number; completed: number; completionRate: number | null; findings: number; openFindings: number; highOpen: number; overdue: number; unassigned: number; policiesReview: number; bySeverity: Record<string, number>; byStatus: Record<string, number>; byType: Record<string, number>; };
}

const sevClass = (s: string): string => `s-${(s || "low").toLowerCase()}`;
const stClass = (s: string): string => (/complet|clos|done/i.test(s) ? "st-completed" : /progress|cours/i.test(s) ? "st-progress" : "st-planned");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="cp-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: AuditRow): string {
  const posture = r.open
    ? `<span class="pill p-open">${fmt("cm.open", { n: r.open })}</span>${r.high ? `<span class="pill p-high">${fmt("cm.high", { n: r.high })}</span>` : ""}${r.overdue ? `<span class="tag">${fmt("cm.overdueN", { n: r.overdue })}</span>` : ""}`
    : `<span class="pill p-clean">${t("cm.clean")}</span>`;
  return `<tr>
    <td><div class="aname">${esc(r.name)}</div><div class="muted" style="font-size:11px">${esc(r.type)}${r.assessmentType && r.assessmentType !== "Operating Effectiveness" ? ` · <span style="color:#c4b5fd">${esc(r.assessmentType)}</span>` : ""}${r.date ? ` · ${esc(r.date)}` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${r.findings}</td>
    <td>${posture}</td>
    <td>${r.unassigned ? `<span class="tag">${r.unassigned}</span>` : `<span class="muted">0</span>`}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const plansBtn = f.kind === "finding"
    ? ` <button class="plan-btn" data-fid="${f.id}" title="${t("cm.plansTitle")}" style="margin-left:6px;background:#1e2440;border:1px solid #2d3250;color:#cbd5e1;border-radius:6px;font-size:11px;padding:1px 8px;cursor:pointer">${t("cm.plans")}${f.plans ? ` (${f.openPlans ?? f.plans})` : ""}</button>`
    : "";
  return `<li><span class="dot" style="background:${f.kind === "policy" ? "#c084fc" : "#fb923c"}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">${esc(f.audit)}</a> — ${esc(f.label)}${plansBtn}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/compliance-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("cp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("cm.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("cm.cAudits"), String(s.audits), fmt("cm.cAudits.foot", { p: s.inProgress, d: s.completed })),
    card(t("cm.cCompletion"), s.completionRate != null ? `${s.completionRate}%` : "—", t("cm.cCompletion.foot"), s.completionRate != null ? (s.completionRate >= 70 ? "#34d399" : s.completionRate >= 40 ? "#fbbf24" : "#f87171") : undefined),
    card(t("cm.cOpenFindings"), String(s.openFindings), fmt("cm.cOpenFindings.foot", { n: s.findings }), s.openFindings ? "#fb923c" : "#34d399"),
    card(t("cm.cHighCrit"), String(s.highOpen), t("cm.cHighCrit.foot"), s.highOpen ? "#f87171" : "#34d399"),
    card(t("cm.cOverdue"), String(s.overdue), t("cm.cOverdue.foot"), s.overdue ? "#f87171" : "#34d399"),
    card(t("cm.cUnassigned"), String(s.unassigned), t("cm.cUnassigned.foot"), s.unassigned ? "#fbbf24" : "#34d399"),
    card(t("cm.cPolicies"), String(s.policiesReview), t("cm.cPolicies.foot"), s.policiesReview ? "#fbbf24" : undefined),
  ].join("");

  const bySev = Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("cm.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("cm.noFindings")}</div>`;

  const table = `<table class="cp"><thead><tr>
      <th>${t("cm.thAudit")}</th><th>${t("cm.thStatus")}</th><th>${t("cm.thFindings")}</th><th>${t("cm.thPosture")}</th><th>${t("cm.thUnassigned")}</th><th title="${t("cm.thScore.title")}">${t("cm.thScore")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("cp-body").innerHTML = `<div class="cp-cards">${cards}</div>
    <div class="cp-section">${fmt("cm.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="cp-section">${t("cm.secBySeverity")}</div><div class="breakdown">${bySev || `<span class="muted">${t("cm.none")}</span>`}</div>
    <div class="cp-section">${t("cm.secByType")}</div><div class="breakdown">${byType}</div>
    <div class="cp-section">${fmt("cm.secAudits", { n: d.rows.length })}</div>${table}
    <div class="legend">${t("cm.legend")}</div>`;

  document.querySelectorAll<HTMLButtonElement>(".plan-btn").forEach((b) => b.addEventListener("click", () => void openPlansModal(Number(b.dataset.fid))));
}

// ── Remediation-plans modal (per finding) ──────────────────────────────────────
let OWNERS: { id: number; label: string }[] | null = null;
let CUR_FINDING = 0;
async function loadOwners(): Promise<{ id: number; label: string }[]> {
  if (OWNERS) return OWNERS;
  try { const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName"); OWNERS = r.ok ? await r.json() : []; }
  catch { OWNERS = []; }
  return OWNERS!;
}
const stPill = (s: string): string =>
  /implement|verif|clos|done|complet/i.test(s) ? "#14532d;color:#bbf7d0" : /cancel/i.test(s) ? "#3f3f46;color:#d4d4d8" : /progress/i.test(s) ? "#3b2d12;color:#fcd34d" : "#1e2440;color:#cbd5e1";

function ensurePlansModal(): HTMLElement {
  let m = document.getElementById("cp-plans-modal");
  if (m) return m;
  m = document.createElement("div");
  m.id = "cp-plans-modal";
  m.style.cssText = "position:fixed;inset:0;background:rgba(5,7,15,.72);display:none;align-items:flex-start;justify-content:center;z-index:1200;overflow:auto;padding:30px 12px";
  m.innerHTML = `<div id="cp-plans-dlg" style="background:#0f1322;border:1px solid #2d3250;border-radius:14px;padding:18px 20px;width:min(760px,96vw)"></div>`;
  m.addEventListener("click", (e) => { if (e.target === m) (m as HTMLElement).style.display = "none"; });
  document.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Escape" && m) (m as HTMLElement).style.display = "none"; });
  document.body.appendChild(m);
  return m;
}

async function openPlansModal(findingId: number): Promise<void> {
  CUR_FINDING = findingId;
  const m = ensurePlansModal();
  document.getElementById("cp-plans-dlg")!.innerHTML = `<div class="muted" style="padding:10px">${t("cm.loadingPlans")}</div>`;
  m.style.display = "flex";
  await renderPlans();
}

async function renderPlans(): Promise<void> {
  const dlg = document.getElementById("cp-plans-dlg")!;
  let d: any;
  try { const r = await fetch(`/api/compliance-management/finding/${CUR_FINDING}/remediations`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { dlg.innerHTML = `<div class="muted" style="padding:10px">⚠️ ${esc(e)}</div>`; return; }
  const owners = await loadOwners();
  const f = d.finding;
  const sopt = (sel: string): string => (d.statuses as string[]).map((s) => `<option${s === sel ? " selected" : ""}>${esc(s)}</option>`).join("");
  const planRow = (p: any): string => `<div style="border:1px solid #2d3250;border-radius:9px;padding:9px 11px;margin-bottom:8px">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <b style="color:#e7ebf3">${esc(p.name)}</b>
      <span style="font-size:10px;font-weight:700;border-radius:5px;padding:1px 7px;background:${stPill(p.status)}">${esc(p.status)}</span>
      ${p.type ? `<span class="muted" style="font-size:11px">${esc(p.type)}</span>` : ""}${p.priority ? `<span class="muted" style="font-size:11px">· ${esc(p.priority)}</span>` : ""}
      <span style="flex:1"></span>
      <select class="pl-st" data-id="${p.id}" style="background:#0f1117;border:1px solid #2d3250;color:#cbd5e1;border-radius:6px;font-size:11px;padding:3px 6px">${sopt(p.status)}</select>
      <button class="pl-del" data-id="${p.id}" title="${t("cm.deletePlan")}" style="background:#1e2440;border:1px solid #7f1d1d;color:#fca5a5;border-radius:6px;font-size:11px;padding:3px 8px;cursor:pointer">✕</button>
    </div>
    <div class="muted" style="font-size:11.5px;margin-top:4px">${p.owner ? `👤 ${esc(p.owner)} · ` : ""}${p.targetDate ? `🎯 ${esc(p.targetDate)} · ` : ""}${p.progress != null ? `${p.progress}% · ` : ""}${p.createdDate ? fmt("cm.createdAt", { d: esc(p.createdDate) }) : ""}${p.completedDate ? ` · ✓ ${esc(p.completedDate)}` : ""}</div>
    ${p.description ? `<div style="font-size:12px;color:#cbd5e1;margin-top:4px;white-space:pre-wrap">${esc(p.description)}</div>` : ""}
  </div>`;
  const ownerOpts = `<option value="">${t("cm.optOwner")}</option>` + owners.map((o) => `<option value="${o.id}">${esc(o.label)}</option>`).join("");
  dlg.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
      <h3 style="margin:0;font-size:16px;color:#e7ebf3">${t("cm.plansHeader")}</h3><span style="flex:1"></span>
      <button id="cp-plans-close" style="background:#1e2440;border:1px solid #2d3250;color:#cbd5e1;border-radius:7px;font-size:12px;padding:5px 12px;cursor:pointer">${t("cm.close")}</button>
    </div>
    <div class="muted" style="font-size:12.5px;margin-bottom:12px"><b style="color:#cbd5e1">${esc(f.name)}</b> · <a href="/?db=XCOMPLIANCE&table=AUDITFINDING&editCol=AuditFindingID&editVal=${f.id}" style="color:#7dd3fc">${t("cm.editFinding")}</a>${f.audit ? ` · ${fmt("cm.auditLbl", { a: esc(f.audit) })}` : ""}${f.severity ? ` · ${esc(f.severity)}` : ""}</div>
    <div>${d.plans.length ? d.plans.map(planRow).join("") : `<div class="muted" style="padding:6px 0 12px">${t("cm.noPlans")}</div>`}</div>
    <div style="border-top:1px solid #2d3250;margin-top:6px;padding-top:12px">
      <div style="font-weight:700;color:#cbd5e1;font-size:12px;margin-bottom:7px">${t("cm.newPlan")}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px">
        <input id="pl-name" placeholder="${t("cm.planNamePh")}" style="grid-column:1/-1;${FLD}">
        <select id="pl-type" style="${FLD}">${(d.types as string[]).map((x) => `<option>${esc(x)}</option>`).join("")}</select>
        <select id="pl-prio" style="${FLD}"><option value="">${t("cm.optPriority")}</option>${(d.priorities as string[]).map((x) => `<option>${esc(x)}</option>`).join("")}</select>
        <select id="pl-status" style="${FLD}">${(d.statuses as string[]).map((x) => `<option>${esc(x)}</option>`).join("")}</select>
        <select id="pl-owner" style="${FLD}">${ownerOpts}</select>
        <input id="pl-target" type="date" style="${FLD}">
        <textarea id="pl-desc" placeholder="${t("cm.planDescPh")}" style="grid-column:1/-1;min-height:54px;resize:vertical;${FLD}"></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:7px;margin-top:8px"><button id="pl-add" style="background:#22c55e;border:none;color:#04130a;border-radius:7px;font-weight:700;font-size:12.5px;padding:7px 14px;cursor:pointer">${t("cm.addPlan")}</button></div>
      <div id="pl-err" style="color:#fca5a5;font-size:12px;margin-top:5px"></div>
    </div>`;
  document.getElementById("cp-plans-close")!.onclick = () => { document.getElementById("cp-plans-modal")!.style.display = "none"; };
  dlg.querySelectorAll<HTMLSelectElement>(".pl-st").forEach((sel) => { sel.onchange = () => void planAction("POST", `/api/compliance-management/remediation/${sel.dataset.id}`, { status: sel.value }); });
  dlg.querySelectorAll<HTMLButtonElement>(".pl-del").forEach((b) => { b.onclick = () => { if (confirm(t("cm.confirmDelete"))) void planAction("DELETE", `/api/compliance-management/remediation/${b.dataset.id}`); }; });
  document.getElementById("pl-add")!.onclick = () => void addPlan();
}

async function planAction(method: string, url: string, body?: unknown): Promise<void> {
  try {
    const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body != null ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    await renderPlans(); await load();
  } catch (e) { toast(`⚠️ ${e}`); }
}

async function addPlan(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("pl-name").trim();
  const err = document.getElementById("pl-err")!;
  if (!name) { err.textContent = t("cm.errPlanName"); return; }
  try {
    const body = { name, type: v("pl-type"), priority: v("pl-prio") || undefined, status: v("pl-status"), ownerPersonId: v("pl-owner") || undefined, targetDate: v("pl-target") || undefined, description: v("pl-desc").trim() || undefined };
    const r = await fetch(`/api/compliance-management/finding/${CUR_FINDING}/remediation`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    toast(t("cm.planAdded"));
    await renderPlans(); await load();
  } catch (e) { err.textContent = `⚠️ ${e}`; }
}

// ── Guided "new audit" modal ──────────────────────────────────────────────────
function openAuditModal(): void {
  for (const id of ["cm-f-name", "cm-f-category", "cm-f-auditor", "cm-f-scope", "cm-f-desc", "cm-f-closure"]) (document.getElementById(id) as HTMLInputElement).value = "";
  (document.getElementById("cm-f-type") as HTMLSelectElement).value = "Compliance";
  (document.getElementById("cm-f-status") as HTMLSelectElement).value = "Planned";
  (document.getElementById("cm-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("cm-f-err").textContent = "";
  $("cm-modal").classList.add("open");
  ($("cm-f-name") as HTMLInputElement).focus();
}
function closeAuditModal(): void { $("cm-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAudit(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("cm-f-name").trim();
  const err = $("cm-f-err");
  if (!name) { err.textContent = t("cm.errName"); ($("cm-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("cm-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("cm.creating");
  try {
    const body = {
      name, type: v("cm-f-type"), assessmentType: v("cm-f-assess"), category: v("cm-f-category").trim() || undefined, status: v("cm-f-status"),
      auditor: v("cm-f-auditor").trim() || undefined, scope: v("cm-f-scope").trim() || undefined,
      description: v("cm-f-desc").trim() || undefined, date: v("cm-f-date") || undefined,
      closureDate: v("cm-f-closure") || undefined,
    };
    const r = await fetch("/api/compliance-management/audit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeAuditModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=AUDIT&editCol=AuditID&editVal=${d.id}`;
    toast(fmt("cm.auditCreated", { link }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("cm-new").addEventListener("click", openAuditModal);
  $("cm-cancel").addEventListener("click", closeAuditModal);
  $("cm-create").addEventListener("click", () => void createAudit());
  $("cm-modal").addEventListener("click", (e) => { if (e.target === $("cm-modal")) closeAuditModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAuditModal(); });
  ($("cm-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAudit(); });
  void load();
});
