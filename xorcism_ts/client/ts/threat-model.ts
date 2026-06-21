/**
 * threat-model.ts — Threat Modeling dashboard (/threat-model). Lists XORCISM.THREATMODEL
 * with per-model asset / threat / mitigation counts, and a guided "new threat model" modal
 * (POST /api/threat-model) replacing the raw explorer insert. Data from /api/threat-model/dashboard.
 */
import { initI18n, t } from "./i18n";

interface Counts { assets: number; threats: number; openThreats: number; mitigations: number }
interface Model {
  id: number; name: string; description: string | null; methodology: string | null;
  status: string | null; scope: string | null; riskLevel: string | null; owner: string | null;
  createdDate: string | null; counts: Counts;
}
interface Dashboard { models: Model[]; stats: { total: number; threats?: number; openThreats?: number; mitigations?: number } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string)); }

const STATUS_COLOR: Record<string, string> = {
  draft: "#64748b", "in progress": "#f59e0b", inprogress: "#f59e0b", "in review": "#a78bfa",
  review: "#a78bfa", approved: "#22c55e", done: "#22c55e", deprecated: "#f87171",
};
const RISK_COLOR: Record<string, string> = { critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#86efac" };

function pill(val: string | null, colors: Record<string, string>): string {
  if (!val) return "";
  const c = colors[val.toLowerCase()] || "#94a3b8";
  return `<span class="pill" style="color:${c}">${esc(val)}</span>`;
}

let all: Model[] = [];

function renderStats(s: Dashboard["stats"]): void {
  const stat = (n: unknown, l: string): string => `<div class="tm-stat"><div class="n">${esc(n)}</div><div class="l">${l}</div></div>`;
  $("tm-stats").innerHTML = [
    stat(s.total, t("tm.stat.models")),
    stat(s.threats ?? 0, t("tm.stat.threats")),
    stat(s.openThreats ?? 0, t("tm.stat.open")),
    stat(s.mitigations ?? 0, t("tm.stat.mitigations")),
  ].join("");
}

function modelLink(id: number, label: string): string {
  return `<a href="/?db=XORCISM&table=THREATMODEL&editCol=ThreatModelID&editVal=${id}">${esc(label || `#${id}`)}</a>`;
}

function renderTable(rows: Model[]): void {
  if (!rows.length) { $("tm-table").innerHTML = `<div style="padding:20px;color:#64748b">${esc(t("tm.empty"))}</div>`; return; }
  const head = [t("tm.col.model"), t("tm.col.status"), t("tm.col.risk"), t("tm.col.assets"),
    t("tm.col.threats"), t("tm.col.mitigations")].map((h, i) => `<th${i >= 3 ? ' class="num"' : ""}>${esc(h)}</th>`).join("");
  const body = rows.map((m) => {
    const c = m.counts;
    return `<tr>
      <td>${modelLink(m.id, m.name)}${m.methodology ? ` <span class="tm-meth">${esc(m.methodology)}</span>` : ""}${m.owner ? `<div class="muted" style="font-size:11px">${esc(m.owner)}</div>` : ""}</td>
      <td>${pill(m.status, STATUS_COLOR)}</td>
      <td>${pill(m.riskLevel, RISK_COLOR)}</td>
      <td class="num">${c.assets || ""}</td>
      <td class="num">${c.threats ? `${c.threats}` : ""}${c.openThreats ? `<span class="tm-meth" title="${esc(t("tm.col.open"))}"> ${c.openThreats} open</span>` : ""}</td>
      <td class="num">${c.mitigations || ""}</td>
    </tr>`;
  }).join("");
  $("tm-table").innerHTML = `<table class="tm"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function applyFilter(): void {
  const q = ($("tm-search") as HTMLInputElement).value.trim().toLowerCase();
  renderTable(!q ? all : all.filter((m) =>
    `${m.name} ${m.description ?? ""} ${m.status ?? ""} ${m.methodology ?? ""} ${m.owner ?? ""}`.toLowerCase().includes(q)));
}

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/threat-model/dashboard");
    if (!r.ok) { $("tm-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(t("tm.error"))} ${r.status}</div>`; return; }
    const d = (await r.json()) as Dashboard;
    all = d.models || [];
    renderStats(d.stats || { total: all.length });
    renderTable(all);
    $("tm-hint").textContent = t("tm.hint");
  } catch (e) { $("tm-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(e)}</div>`; }
}

// ── Guided "new threat model" modal ───────────────────────────────────────────
function openModal(): void {
  for (const id of ["tm-f-name", "tm-f-owner", "tm-f-scope", "tm-f-desc"]) (document.getElementById(id) as HTMLInputElement).value = "";
  ($("tm-f-method") as HTMLSelectElement).value = "STRIDE";
  ($("tm-f-status") as HTMLSelectElement).value = "Draft";
  ($("tm-f-risk") as HTMLSelectElement).value = "";
  $("tm-f-err").textContent = "";
  $("tm-modal").classList.add("open");
  ($("tm-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("tm-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createModel(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("tm-f-name").trim();
  const err = $("tm-f-err");
  if (!name) { err.textContent = t("tm.modal.err.name"); ($("tm-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("tm-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("tm.modal.creating");
  try {
    const body = {
      name, description: v("tm-f-desc").trim() || undefined, methodology: v("tm-f-method"),
      status: v("tm-f-status"), riskLevel: v("tm-f-risk") || undefined,
      owner: v("tm-f-owner").trim() || undefined, scope: v("tm-f-scope").trim() || undefined,
    };
    const r = await fetch("/api/threat-model", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XORCISM&table=THREATMODEL&editCol=ThreatModelID&editVal=${d.id}`;
    toast(`✅ ${esc(t("tm.modal.created"))} — <a href="${link}" style="color:#7dd3fc">${esc(t("tm.modal.open"))} ↗</a>`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("tm-search") as HTMLInputElement).oninput = applyFilter;
  $("tm-new").addEventListener("click", openModal);
  $("tm-cancel").addEventListener("click", closeModal);
  $("tm-create").addEventListener("click", () => void createModel());
  $("tm-modal").addEventListener("click", (e) => { if (e.target === $("tm-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("tm-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createModel(); });
  void load();
});
