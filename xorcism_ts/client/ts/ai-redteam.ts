/**
 * ai-redteam.ts — client for LLM red-team / AI-BAS (/ai-redteam). KPI cards, OWASP-LLM coverage
 * matrix, per-AI-system assessment table (run assessment / open latest run) from /api/ai-redteam.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Run { id: number; mode: string; exposure: number; grade: string; tested: number; passed: number; failed: number; createdDate: string }
interface SysRow { id: number; name: string; riskTier: string; lifecycle: string; guardrails: string[]; endpoint?: string; latestRun: Run | null }
interface Data {
  summary: { systems: number; assessed: number; notAssessed: number; avgExposure: number; failing: number; probes: number };
  systems: SysRow[]; coverage: Record<string, { exposed: number; tested: number }>; categories: string[]; canRun: boolean;
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
    card("AI systems", s.systems, `${s.assessed} assessed`),
    card("Not assessed", s.notAssessed, "run a probe", s.notAssessed ? "#fbbf24" : "#34d399"),
    card("Avg exposure", `${s.avgExposure}/100`, "lower is better", s.avgExposure >= 40 ? "#f87171" : s.avgExposure >= 20 ? "#fbbf24" : "#34d399"),
    card("Failing systems", s.failing, "open vulns", s.failing ? "#f87171" : "#34d399"),
    card("Probes", s.probes, "OWASP LLM Top 10"),
  ].join("");

  const cov = d.categories.map((c) => {
    const x = d.coverage[c] || { exposed: 0, tested: 0 };
    const pct = x.tested ? Math.round(100 * x.exposed / x.tested) : 0;
    const col = pct >= 50 ? "#f87171" : pct >= 20 ? "#fbbf24" : "#34d399";
    return `<div class="covc"><div class="cn">${esc(c)}</div><div class="muted" style="font-size:11px">${x.exposed}/${x.tested} exposed</div><div class="cb"><i style="width:${pct}%;background:${col}"></i></div></div>`;
  }).join("");

  const rows = d.systems.map((sy) => {
    const r = sy.latestRun;
    const run = r
      ? `<span class="g g-${esc(r.grade)}">${esc(r.grade)}</span> <b>${r.exposure}</b><span class="muted">/100</span> · <span style="color:${r.failed ? "#f87171" : "#34d399"}">${r.failed} fail</span> / ${r.passed} pass <span class="muted">(${esc(r.mode)})</span>`
      : `<span class="muted">not assessed</span>`;
    const live = DATA?.canRun && sy.endpoint ? ` <button class="btn-sm2" data-live="${sy.id}" title="Send the probes to ${esc(sy.endpoint)}">⚡ Live probe</button>` : "";
    const act = DATA?.canRun ? `<button class="btn" data-assess="${sy.id}">Run assessment</button>${live}${r ? ` <button class="btn-sm2" data-open="${r.id}">Details</button>` : ""}` : (r ? `<button class="btn-sm2" data-open="${r.id}">Details</button>` : "");
    return `<tr><td><span class="nm">${esc(sy.name)}</span><div class="muted" style="font-size:11px">${esc(sy.riskTier)} · ${esc(sy.lifecycle)} · ${sy.guardrails.length} guardrail(s)</div></td><td>${run}</td><td style="white-space:nowrap">${act}</td></tr>`;
  }).join("");

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">OWASP LLM coverage (exposed categories across latest runs)</div><div class="cov">${cov}</div>
    <div class="sec">AI systems (${d.systems.length})</div>
    <table class="t"><thead><tr><th>AI system</th><th>Latest assessment</th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="3" class="muted" style="padding:14px;text-align:center">No AI systems registered. Add them in the <a href="/ai-systems">AI inventory</a>.</td></tr>`}</tbody></table>`;

  body.querySelectorAll<HTMLElement>("[data-assess]").forEach((b) => b.addEventListener("click", () => void assess(Number(b.dataset.assess))));
  body.querySelectorAll<HTMLElement>("[data-live]").forEach((b) => b.addEventListener("click", () => void live(Number(b.dataset.live))));
  body.querySelectorAll<HTMLElement>("[data-open]").forEach((b) => b.addEventListener("click", () => void openRun(Number(b.dataset.open))));
}

async function live(systemId: number): Promise<void> {
  toast("Running live probes…");
  try { const d = await getJson(`/api/ai-redteam/live/${systemId}`, { method: "POST" }); render(d); if (d.run) renderRun(d.run); toast(`Live probe complete (${d.tested} probes)`); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

function renderRun(run: any): void {
  const host = $("rundetail"); if (!host) return;
  const rows = run.results.map((r: any) => `<tr><td><span class="out out-${esc(r.outcome)}">${esc(r.outcome)}</span></td><td><span class="owasp">${esc(r.owasp)}</span> ${esc(r.category)}</td><td><span class="nm">${esc(r.name)}</span><div class="muted" style="font-size:11px">${esc(r.detail)}</div></td><td>${esc(r.severity)}</td></tr>`).join("");
  host.innerHTML = `<div class="detail"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span class="nm" style="font-size:15px">${esc(run.systemName)}</span><span class="g g-${esc(run.grade)}">${esc(run.grade)}</span><span class="muted">exposure ${run.exposure}/100 · ${run.failed} fail / ${run.passed} pass · ${esc(run.mode)}</span><span style="flex:1"></span><button class="btn-sm2" id="rd-close">✕ close</button></div>
    <table class="t"><thead><tr><th>Outcome</th><th>OWASP</th><th>Probe</th><th>Sev</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  host.scrollIntoView({ behavior: "smooth" });
  $("rd-close")?.addEventListener("click", () => { host.innerHTML = ""; });
}

async function load(): Promise<void> {
  try { render(await getJson("/api/ai-redteam")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
async function assess(systemId: number): Promise<void> {
  try { const d = await getJson(`/api/ai-redteam/assess/${systemId}`, { method: "POST" }); render(d); if (d.run) renderRun(d.run); toast("Assessment complete"); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function openRun(runId: number): Promise<void> {
  try { renderRun(await getJson(`/api/ai-redteam/run/${runId}`)); } catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
