/**
 * ai-redteam.ts — client for LLM red-team / AI-BAS (/ai-redteam). KPI cards, OWASP-LLM coverage
 * matrix, per-AI-system assessment table (run assessment / open latest run) from /api/ai-redteam.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Run { id: number; mode: string; exposure: number; grade: string; tested: number; passed: number; failed: number; createdDate: string }
interface SysRow { id: number; name: string; riskTier: string; lifecycle: string; guardrails: string[]; endpoint?: string; latestRun: Run | null }
interface Data {
  summary: { systems: number; assessed: number; notAssessed: number; avgExposure: number; failing: number; probes: number };
  systems: SysRow[]; coverage: Record<string, { exposed: number; tested: number }>; categories: string[]; canRun: boolean;
  atlas?: { score: number; total: number; mappable: number; covered: number; exposed: number; gaps: { atlasId: string; name: string; status: string }[] };
}
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
let DATA: Data | null = null;

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card(t("art.cSystems"), s.systems, fmt("art.cSystemsF", { n: s.assessed })),
    card(t("art.cNotAssessed"), s.notAssessed, t("art.cNotAssessedF"), s.notAssessed ? "#fbbf24" : "#34d399"),
    card(t("art.cAvgExp"), `${s.avgExposure}/100`, t("art.cAvgExpF"), s.avgExposure >= 40 ? "#f87171" : s.avgExposure >= 20 ? "#fbbf24" : "#34d399"),
    card(t("art.cFailing"), s.failing, t("art.cFailingF"), s.failing ? "#f87171" : "#34d399"),
    card(t("art.cProbes"), s.probes, "OWASP LLM Top 10"),
  ].join("");

  const cov = d.categories.map((c) => {
    const x = d.coverage[c] || { exposed: 0, tested: 0 };
    const pct = x.tested ? Math.round(100 * x.exposed / x.tested) : 0;
    const col = pct >= 50 ? "#f87171" : pct >= 20 ? "#fbbf24" : "#34d399";
    return `<div class="covc"><div class="cn">${esc(c)}</div><div class="muted" style="font-size:11px">${fmt("art.exposedN", { e: x.exposed, t: x.tested })}</div><div class="cb"><i style="width:${pct}%;background:${col}"></i></div></div>`;
  }).join("");

  const rows = d.systems.map((sy) => {
    const r = sy.latestRun;
    const run = r
      ? `<span class="g g-${esc(r.grade)}">${esc(r.grade)}</span> <b>${r.exposure}</b><span class="muted">/100</span> · <span style="color:${r.failed ? "#f87171" : "#34d399"}">${fmt("art.failN", { n: r.failed })}</span> / ${fmt("art.passN", { n: r.passed })} <span class="muted">(${esc(r.mode)})</span>`
      : `<span class="muted">${t("art.notAssessed")}</span>`;
    const live = DATA?.canRun && sy.endpoint ? ` <button class="btn-sm2" data-live="${sy.id}" title="${esc(fmt("art.liveTitle", { ep: sy.endpoint }))}">⚡ ${t("art.liveProbe")}</button>` : "";
    const act = DATA?.canRun ? `<button class="btn" data-assess="${sy.id}">${t("art.runAssess")}</button>${live}${r ? ` <button class="btn-sm2" data-open="${r.id}">${t("art.details")}</button>` : ""}` : (r ? `<button class="btn-sm2" data-open="${r.id}">${t("art.details")}</button>` : "");
    return `<tr><td><span class="nm">${esc(sy.name)}</span><div class="muted" style="font-size:11px">${esc(sy.riskTier)} · ${esc(sy.lifecycle)} · ${fmt("art.guardrailN", { n: sy.guardrails.length })}</div></td><td>${run}</td><td style="white-space:nowrap">${act}</td></tr>`;
  }).join("");

  const a = d.atlas;
  const atlasHtml = a && a.total ? `<div class="sec">${t("art.secAtlas")} <span class="muted" style="font-weight:400">${t("art.secAtlasSub")}</span></div>
    <div class="muted" style="font-size:12.5px;margin-bottom:8px"><b style="color:${a.score >= 70 ? "#34d399" : a.score >= 40 ? "#fbbf24" : "#f87171"};font-size:15px">${a.score}%</b> ${fmt("art.atlasLine", { covered: a.covered, mappable: a.mappable })} · <span style="color:${a.exposed ? "#f87171" : "#34d399"}">${fmt("art.exposedCount", { n: a.exposed })}</span> · ${fmt("art.atlasImported", { n: a.total })}</div>
    <div>${(a.gaps || []).map((g) => `<span class="owasp" style="background:${g.status === "exposed" ? "#7f1d1d" : "#1e2440"};color:${g.status === "exposed" ? "#fecaca" : "#cbd5e1"};border:1px solid #2d3250;border-radius:6px;padding:2px 7px;margin:2px;display:inline-block;font-size:11px" title="${esc(g.name)}">${esc(g.atlasId)} ${g.status === "exposed" ? "⚠" : "○"}</span>`).join("") || `<span class='muted' style='font-size:12px'>${t("art.noAtlasGaps")}</span>`}</div>` : "";

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">${t("art.secCoverage")}</div><div class="cov">${cov}</div>
    ${atlasHtml}
    <div class="sec">${fmt("art.secSystems", { n: d.systems.length })}</div>
    <table class="t"><thead><tr><th>${t("art.thSystem")}</th><th>${t("art.thLatest")}</th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="3" class="muted" style="padding:14px;text-align:center">${t("art.noSystems")} <a href="/ai-systems">${t("art.aiInventory")}</a>.</td></tr>`}</tbody></table>`;

  body.querySelectorAll<HTMLElement>("[data-assess]").forEach((b) => b.addEventListener("click", () => void assess(Number(b.dataset.assess))));
  body.querySelectorAll<HTMLElement>("[data-live]").forEach((b) => b.addEventListener("click", () => void live(Number(b.dataset.live))));
  body.querySelectorAll<HTMLElement>("[data-open]").forEach((b) => b.addEventListener("click", () => void openRun(Number(b.dataset.open))));
}

async function live(systemId: number): Promise<void> {
  toast(t("art.runningLive"));
  try { const d = await getJson(`/api/ai-redteam/live/${systemId}`, { method: "POST" }); render(d); if (d.run) renderRun(d.run); toast(fmt("art.liveDone", { n: d.tested })); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

function renderRun(run: any): void {
  const host = $("rundetail"); if (!host) return;
  const rows = run.results.map((r: any) => `<tr><td><span class="out out-${esc(r.outcome)}">${esc(r.outcome)}</span></td><td><span class="owasp">${esc(r.owasp)}</span> ${esc(r.category)}</td><td><span class="nm">${esc(r.name)}</span><div class="muted" style="font-size:11px">${esc(r.detail)}</div></td><td>${esc(r.severity)}</td></tr>`).join("");
  host.innerHTML = `<div class="detail"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span class="nm" style="font-size:15px">${esc(run.systemName)}</span><span class="g g-${esc(run.grade)}">${esc(run.grade)}</span><span class="muted">${fmt("art.runMeta", { e: run.exposure, f: run.failed, p: run.passed, mode: esc(run.mode) })}</span><span style="flex:1"></span><button class="btn-sm2" id="rd-close">${t("art.close")}</button></div>
    <table class="t"><thead><tr><th>${t("art.thOutcome")}</th><th>OWASP</th><th>${t("art.thProbe")}</th><th>${t("art.thSev")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  host.scrollIntoView({ behavior: "smooth" });
  $("rd-close")?.addEventListener("click", () => { host.innerHTML = ""; });
}

async function load(): Promise<void> {
  try { render(await getJson("/api/ai-redteam")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
async function assess(systemId: number): Promise<void> {
  try { const d = await getJson(`/api/ai-redteam/assess/${systemId}`, { method: "POST" }); render(d); if (d.run) renderRun(d.run); toast(t("art.assessDone")); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function openRun(runId: number): Promise<void> {
  try { renderRun(await getJson(`/api/ai-redteam/run/${runId}`)); } catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
