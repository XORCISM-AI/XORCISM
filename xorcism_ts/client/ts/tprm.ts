/**
 * tprm.ts — TPRM (Third-Party Risk Management) dashboard. Lists the resolved
 * third-party assessments (XCOMPLIANCE.QUESTIONNAIREFORORGANISATION) + stats, via /api/tprm/dashboard.
 */
import { initI18n, t } from "./i18n";

interface Assessment {
  id: number; organisation: string; questionnaire: string; questions: number;
  relationship: string; status: string; type: string; riskRating: string;
  score: number | null; criticality: string; dueDate: string; completedDate: string;
  owner: string; overdue: boolean;
}
interface Dashboard { assessments: Assessment[]; stats: { total: number; byStatus?: Record<string, number>; byRisk?: Record<string, number>; overdue?: number; avgScore?: number | null } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string)); }

const RISK_COLOR: Record<string, string> = { Critical: "#f87171", High: "#f59e0b", Medium: "#eab308", Low: "#22c55e" };
const STATUS_COLOR: Record<string, string> = {
  Requested: "#64748b", Sent: "#3b82f6", "In progress": "#f59e0b", Submitted: "#2dd4bf",
  "Under review": "#a78bfa", Completed: "#22c55e", Expired: "#f87171",
};
function pill(val: string, colors: Record<string, string>): string {
  if (!val) return "";
  const c = colors[val] || "#94a3b8";
  return `<span class="pill" style="color:${c}">${esc(val)}</span>`;
}

let all: Assessment[] = [];

function renderStats(s: Dashboard["stats"]): void {
  const stat = (n: unknown, l: string): string => `<div class="tprm-stat"><div class="n">${esc(n)}</div><div class="l">${l}</div></div>`;
  const parts = [stat(s.total, t("tprm.assessments")), stat(s.overdue ?? 0, t("tprm.overdue")), stat(s.avgScore ?? "—", t("tprm.avgScore"))];
  const risk = s.byRisk || {};
  for (const r of ["Critical", "High"]) if (risk[r]) parts.push(stat(risk[r], `${t("tprm.risk")} ${r}`));
  $("tprm-stats").innerHTML = parts.join("");
}

function renderTable(rows: Assessment[]): void {
  if (!rows.length) { $("tprm-table").innerHTML = `<div style="padding:20px;color:#64748b">${esc(t("tprm.empty"))}</div>`; return; }
  const head = [
    t("tprm.col.org"), t("tprm.col.questionnaire"), t("tprm.col.relationship"), t("tprm.col.status"),
    t("tprm.col.risk"), t("tprm.col.score"), t("tprm.col.criticality"), t("tprm.col.due"),
    t("tprm.col.completed"), t("tprm.col.owner"), t("tprm.col.questions"),
  ].map((h) => `<th>${esc(h)}</th>`).join("");
  const body = rows.map((a) => `<tr class="tprm-row" data-id="${esc(a.id)}" style="cursor:pointer" title="${esc(t("tprm.editHint"))}">
    <td>${esc(a.organisation)}</td>
    <td>${esc(a.questionnaire)}</td>
    <td>${esc(a.relationship)}</td>
    <td>${pill(a.status, STATUS_COLOR)}</td>
    <td>${pill(a.riskRating, RISK_COLOR)}</td>
    <td>${a.score == null ? "" : esc(a.score)}</td>
    <td>${pill(a.criticality, RISK_COLOR)}</td>
    <td class="${a.overdue ? "ov" : ""}">${esc(a.dueDate)}${a.overdue ? " ⚠" : ""}</td>
    <td>${esc(a.completedDate)}</td>
    <td>${esc(a.owner)}</td>
    <td>${esc(a.questions)}</td>
  </tr>`).join("");
  $("tprm-table").innerHTML = `<table class="tprm"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function applyFilter(): void {
  const q = ($("tprm-search") as HTMLInputElement).value.trim().toLowerCase();
  renderTable(!q ? all : all.filter((a) =>
    `${a.organisation} ${a.questionnaire} ${a.status} ${a.riskRating} ${a.criticality} ${a.relationship} ${a.owner}`.toLowerCase().includes(q)));
}

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/tprm/dashboard");
    if (!r.ok) { $("tprm-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(t("tprm.error"))} ${r.status}</div>`; return; }
    const d = (await r.json()) as Dashboard;
    all = d.assessments || [];
    renderStats(d.stats || { total: all.length });
    renderTable(all);
    $("tprm-hint").textContent = t("tprm.hint");
  } catch (e) {
    $("tprm-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(e)}</div>`;
  }
}

// Click a row → edit the underlying assessment (XCOMPLIANCE.QUESTIONNAIREFORORGANISATION)
// in the main explorer's generic edit form, via its deep-link (editCol/editVal).
function editAssessment(id: string): void {
  const p = new URLSearchParams({
    db: "XCOMPLIANCE", table: "QUESTIONNAIREFORORGANISATION",
    editCol: "QuestionnaireOrganisationID", editVal: id,
  });
  location.href = `/?${p.toString()}`;
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("tprm-search") as HTMLInputElement).oninput = applyFilter;
  $("tprm-table").addEventListener("click", (e) => {
    const tr = (e.target as Element | null)?.closest("tr[data-id]") as HTMLElement | null;
    if (tr?.dataset.id) editAssessment(tr.dataset.id);
  });
  void load();
});
