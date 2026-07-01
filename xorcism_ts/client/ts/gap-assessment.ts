/**
 * gap-assessment.ts — Automated gap assessment (/gap-assessment): pick a framework/regulation, run a
 * local-AI (with deterministic fallback) coverage assessment of the POLICY + DOCUMENT estate, and read
 * the per-control covered / partial / gap verdict with rationale, cited evidence and remediation.
 * From /api/gap-assessment.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("ga-toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 3200); }
const pctColor = (n: number): string => (n >= 80 ? "#34d399" : n >= 50 ? "#fbbf24" : "#f87171");

type Status = "covered" | "partial" | "gap" | "unknown";
interface Item { controlId: number; ref: string; name: string; status: Status; rationale: string; evidence: string; recommendation: string; source: "ai" | "heuristic"; }
interface Report {
  assessmentId: number | null; frameworkId: number; frameworkName: string; vocabularyName: string | null;
  runAt: string | null; ai: boolean; model: string; totalControls: number; assessed: number; coveragePct: number;
  counts: { covered: number; partial: number; gap: number; unknown: number };
  corpus: { policies: number; documents: number }; items: Item[]; gaps: Item[];
  history: { assessmentId: number; runAt: string; coveragePct: number }[];
}
interface Overview { frameworks: { id: number; name: string; vocabularyName: string | null; controls: number; lastRunAt: string | null; lastCoveragePct: number | null }[]; corpus: { policies: number; documents: number }; }

let current: Report | null = null;
let filter: Status | "all" = "all";

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ga-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url); const j = await r.json();
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j as T;
}
async function postJson<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j as T;
}

async function loadOverview(): Promise<void> {
  let o: Overview;
  try { o = await getJson<Overview>("/api/gap-assessment/overview"); }
  catch (e) { $("ga-status").textContent = "⚠️ " + (e as Error).message; return; }
  const sel = $("ga-fw") as HTMLSelectElement;
  if (!o.frameworks.length) {
    sel.innerHTML = `<option value="">No mapped frameworks — map one under Frameworks</option>`;
    $("ga-status").innerHTML = `Corpus: <b>${o.corpus.policies}</b> policies · <b>${o.corpus.documents}</b> documents. ` +
      `No framework is mapped to a controls vocabulary yet — <a href="/frameworks">map one</a> to enable assessment.`;
    return;
  }
  sel.innerHTML = o.frameworks.map((f) => {
    const last = f.lastCoveragePct != null ? ` · last ${f.lastCoveragePct}%` : "";
    return `<option value="${f.id}">${esc(f.name)} (${f.controls} controls${f.vocabularyName ? " · " + esc(f.vocabularyName) : ""}${last})</option>`;
  }).join("");
  $("ga-status").innerHTML = `Corpus: <b>${o.corpus.policies}</b> policies · <b>${o.corpus.documents}</b> documents assessed against the selected framework.`;
  sel.onchange = () => void loadLatest();
  await loadLatest();
}

async function loadLatest(): Promise<void> {
  const fid = Number(($("ga-fw") as HTMLSelectElement).value);
  if (!fid) return;
  try {
    const { report } = await getJson<{ report: Report | null }>(`/api/gap-assessment?framework=${fid}`);
    current = report;
    if (report) render(report);
    else $("ga-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No assessment yet for this framework. Click <b>Run assessment</b> to generate one.</div>`;
  } catch (e) { $("ga-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}

async function run(): Promise<void> {
  const fid = Number(($("ga-fw") as HTMLSelectElement).value);
  if (!fid) { toast("Pick a framework first"); return; }
  const limit = Math.max(1, Math.min(200, Number(($("ga-limit") as HTMLInputElement).value) || 60));
  const btn = $("ga-run") as HTMLButtonElement;
  btn.disabled = true; const label = btn.textContent; btn.textContent = "⏳ Running…";
  $("ga-status").textContent = `Assessing up to ${limit} controls against your policies & documents — this can take a minute with local AI…`;
  try {
    const report = await postJson<Report>("/api/gap-assessment/run", { frameworkId: fid, limit });
    current = report; render(report);
    toast(`Assessment complete — ${report.coveragePct}% covered (${report.ai ? "AI" : "heuristic"})`);
  } catch (e) {
    $("ga-status").textContent = "⚠️ " + (e as Error).message; toast("⚠️ " + (e as Error).message);
  } finally { btn.disabled = false; btn.textContent = label; }
}

function statusChip(s: Status): string { return `<span class="st st-${s}">${s}</span>`; }

function itemRow(it: Item): string {
  return `<tr>
    <td><span class="ref">${esc(it.ref)}</span></td>
    <td><span class="cname">${esc(it.name)}</span>${it.rationale ? `<div class="small">${esc(it.rationale)}</div>` : ""}</td>
    <td>${statusChip(it.status)}<span class="pill ${it.source === "ai" ? "pill-ai" : "pill-heur"}">${it.source === "ai" ? "AI" : "heur"}</span></td>
    <td>${it.evidence ? `<span class="ev">${esc(it.evidence)}</span>` : `<span class="muted">—</span>`}</td>
    <td>${it.recommendation ? `<span class="rec">${esc(it.recommendation)}</span>` : `<span class="muted">—</span>`}</td>
  </tr>`;
}

function render(r: Report): void {
  const cvW = r.assessed ? (r.counts.covered / r.assessed) * 100 : 0;
  const paW = r.assessed ? (r.counts.partial / r.assessed) * 100 : 0;
  const gaW = r.assessed ? (r.counts.gap / r.assessed) * 100 : 0;
  const when = r.runAt ? new Date(r.runAt).toLocaleString() : "—";
  const cards =
    card("Coverage", `${r.coveragePct}%`, `covered + ½·partial over ${r.assessed} assessed`, pctColor(r.coveragePct)) +
    card("Covered", String(r.counts.covered), "fully addressed", "#34d399") +
    card("Partial", String(r.counts.partial), "mentioned, incomplete", "#fbbf24") +
    card("Gaps", String(r.counts.gap), "not addressed", r.counts.gap ? "#f87171" : "#34d399") +
    card("Corpus", `${r.corpus.policies}+${r.corpus.documents}`, "policies + documents") +
    card("Engine", r.ai ? "Local AI" : "Heuristic", r.ai ? (r.model || "ollama") : "keyword overlap — enable Ollama for precise verdicts", r.ai ? "#a5b4fc" : "#fcd34d");

  const bar = `<div class="cbar">
    <i class="c-cov" style="width:${cvW}%"></i><i class="c-par" style="width:${paW}%"></i><i class="c-gap" style="width:${gaW}%"></i></div>`;

  const chips = (["all", "gap", "partial", "covered"] as const).map((f) => {
    const n = f === "all" ? r.assessed : r.counts[f];
    return `<span class="fb${filter === f ? " active" : ""}" data-filter="${f}">${f}${f !== "all" ? ` (${n})` : ` (${n})`}</span>`;
  }).join("");

  const shown = r.items.filter((it) => filter === "all" ? true : it.status === filter);
  const table = shown.length ? `<table class="ga"><thead><tr>
      <th>Ref</th><th>Control</th><th>Status</th><th>Evidence (cited doc)</th><th>Recommendation</th>
    </tr></thead><tbody>${shown.map(itemRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:18px;text-align:center">No controls with status “${filter}”.</div>`;

  const trend = r.history.length > 1 ? `<span class="small"> · trend: ${r.history.map((h) => `${h.coveragePct}%`).join(" → ")}</span>` : "";
  const capNote = r.assessed < r.totalControls
    ? `<div class="small" style="margin-bottom:8px">Assessed the first <b>${r.assessed}</b> of <b>${r.totalControls}</b> controls — raise the “Controls” limit to cover more.</div>` : "";

  $("ga-body").innerHTML = `
    <div class="ga-cards">${cards}</div>
    <div class="ga-section">Coverage — ${esc(r.frameworkName)}${r.vocabularyName ? ` <span class="small">(${esc(r.vocabularyName)})</span>` : ""}</div>
    ${bar}
    <div class="small" style="margin-bottom:8px">Run ${esc(when)}${trend}</div>
    ${capNote}
    <div class="ga-section">Control-by-control (${r.assessed})</div>
    <div class="filterbar">${chips}</div>
    ${table}
    <div class="legend">↳ <b>Covered</b>: a document specifically addresses the control. <b>Partial</b>: the topic is mentioned but incomplete.
      <b>Gap</b>: nothing in your governance estate addresses it — start there. Coverage% = (covered + ½·partial) ÷ assessed.
      The <span class="pill pill-ai">AI</span> tag means a local model judged it; <span class="pill pill-heur">heur</span> is the
      offline keyword fallback (which never claims “covered” on its own). Evidence cites the policy/document the verdict relied on.</div>`;

  $("ga-body").querySelectorAll<HTMLElement>(".fb").forEach((el) => {
    el.onclick = () => { filter = (el.getAttribute("data-filter") as Status | "all"); if (current) render(current); };
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("ga-run") as HTMLButtonElement).onclick = () => void run();
  void loadOverview();
});
