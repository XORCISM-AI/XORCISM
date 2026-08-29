/**
 * compliance-calendar.ts — Compliance Activity Calendar & Reminders cockpit (/compliance-calendar).
 * KPIs (overdue / due-soon / due-30d), new-activity form, a table with status, next-due, cadence, an
 * inline due-date edit, complete (advances the recurring occurrence), delete, and a "run reminders" button.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function val(id: string): string { return (document.getElementById(id) as HTMLInputElement).value.trim(); }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const el = $("toast"); el.textContent = msg; el.className = ok ? "toast-ok" : "toast-err"; el.style.opacity = "1"; setTimeout(() => (el.style.opacity = "0"), 2400); }

interface Act { activityId: number; name: string; category: string | null; description: string | null; ownerName: string | null; assigneeUserId: number | null; framework: string | null; controlRef: string | null; cadence: string; intervalDays: number | null; nextDueDate: string | null; leadTimeDays: number | null; lastCompletedDate: string | null; status: string; display: string; }
interface Data { activities: Act[]; summary: { total: number; overdue: number; dueSoon: number; scheduled: number; completed: number; paused: number; due30: number }; cadences: string[]; categories: string[]; }

let DATA: Data | null = null;

async function api(url: string, method = "GET", body?: unknown): Promise<any> {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

async function load(): Promise<void> {
  try { DATA = await api("/api/compliance-calendar"); } catch (e) { $("cc-table").innerHTML = `<div style="color:#64748b">${t("cc.loadFail")}: ${esc(e)}</div>`; return; }
  const d = DATA!; const s = d.summary;
  const cat = $("a-cat") as HTMLSelectElement; if (!cat.options.length) cat.innerHTML = d.categories.map((x) => `<option>${esc(x)}</option>`).join("");
  const cad = $("a-cadence") as HTMLSelectElement; if (!cad.options.length) cad.innerHTML = d.cadences.map((x) => `<option value="${x}">${t("cc.cad." + x)}</option>`).join("");
  $("cc-kpis").innerHTML = [
    ["overdue", s.overdue, s.overdue ? "#fca5a5" : "#6ee7b7"], ["dueSoon", s.dueSoon, s.dueSoon ? "#fcd34d" : "#94a3b8"], ["due30", s.due30, "#93c5fd"],
    ["scheduled", s.scheduled, "#cbd5e1"], ["completed", s.completed, "#6ee7b7"], ["total", s.total, "#e2e8f0"],
  ].map(([k, v, c]) => `<div class="kpi"><div class="v" style="color:${c}">${v}</div><div class="l">${t("cc.kpi." + k)}</div></div>`).join("");
  render();
}

function render(): void {
  if (!DATA) return;
  const rows = DATA.activities.map((a) => `<tr>
    <td><b>${esc(a.name)}</b>${a.description ? `<div style="font-size:10.5px;color:#64748b">${esc(a.description)}</div>` : ""}${a.ownerName ? `<div style="font-size:10px;color:#64748b">${t("cc.owner")}: ${esc(a.ownerName)}${a.assigneeUserId ? " · uid " + a.assigneeUserId : ""}</div>` : ""}</td>
    <td>${esc(a.category || "")}</td>
    <td style="font-size:10.5px;color:#a5b4fc">${esc(a.framework || "")}${a.controlRef ? " · " + esc(a.controlRef) : ""}</td>
    <td>${t("cc.cad." + a.cadence)}</td>
    <td><input type="date" value="${esc(a.nextDueDate || "")}" data-due="${a.activityId}" style="width:122px"></td>
    <td><span class="st ${esc(a.display)}">${t("cc.st." + a.display)}</span></td>
    <td style="white-space:nowrap">
      <button class="btn-ai btn-sm" data-done="${a.activityId}" title="${t("cc.completeHint")}">✓ ${t("cc.complete")}</button>
      <span class="x" data-del="${a.activityId}" title="${t("cc.delete")}" style="margin-left:6px">✕</span>
    </td></tr>`).join("");
  $("cc-table").innerHTML = `<table class="cc"><thead><tr>
    <th>${t("cc.col.name")}</th><th>${t("cc.col.category")}</th><th>${t("cc.col.control")}</th><th>${t("cc.col.cadence")}</th>
    <th>${t("cc.col.nextDue")}</th><th>${t("cc.col.status")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  $("cc-table").querySelectorAll<HTMLInputElement>("[data-due]").forEach((el) => el.onchange = async () => { try { await api(`/api/compliance-calendar/${el.dataset.due}`, "PATCH", { nextDueDate: el.value }); toast(t("cc.saved")); await load(); } catch (e) { toast(String(e), false); } });
  $("cc-table").querySelectorAll<HTMLElement>("[data-done]").forEach((b) => b.onclick = async () => { const notes = prompt(t("cc.completeNotes")) ?? undefined; try { await api(`/api/compliance-calendar/${b.dataset.done}/complete`, "POST", { notes }); toast(t("cc.completed")); await load(); } catch (e) { toast(String(e), false); } });
  $("cc-table").querySelectorAll<HTMLElement>("[data-del]").forEach((x) => x.onclick = async () => { if (!confirm(t("cc.confirmDel"))) return; try { await api(`/api/compliance-calendar/${x.dataset.del}`, "DELETE"); await load(); } catch (e) { toast(String(e), false); } });
}

async function add(): Promise<void> {
  if (!val("a-name")) { toast(t("cc.needName"), false); return; }
  const body = { name: val("a-name"), category: val("a-cat"), cadence: (document.getElementById("a-cadence") as HTMLSelectElement).value, nextDueDate: val("a-due"), leadTimeDays: val("a-lead"), intervalDays: val("a-interval"), ownerName: val("a-owner"), assigneeUserId: val("a-assignee"), framework: val("a-framework"), controlRef: val("a-control"), description: val("a-desc") };
  try {
    await api("/api/compliance-calendar", "POST", body);
    ["a-name", "a-due", "a-interval", "a-owner", "a-assignee", "a-framework", "a-control", "a-desc"].forEach((id) => (document.getElementById(id) as HTMLInputElement).value = "");
    toast(t("cc.added")); await load();
  } catch (e) { toast(String(e), false); }
}

async function runReminders(): Promise<void> {
  try { const r = await api("/api/compliance-calendar/run-reminders", "POST"); toast(`${t("cc.reminded")}: ${r.reminded}/${r.checked}`); } catch (e) { toast(String(e), false); }
}

initI18n().then(() => {
  $("a-add").onclick = add;
  $("cc-remind").onclick = runReminders;
  return load();
});
