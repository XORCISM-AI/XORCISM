/**
 * ai-systems.ts — client for the AI system inventory + AI-BOM cockpit (/ai-systems).
 * KPI cards, EU-AI-Act risk-tier breakdown, governance-gap worklist and the full register from
 * /api/ai-systems, with a register-system modal, expandable detail (components + gaps + AI-BOM export).
 */
// NB: import as T — `t` is used as a map param in this file (riskTiers.map((t) => …)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Sys {
  id: number; name: string; purpose: string; provider: string; modelName: string; modelType: string;
  hosting: string; dataClassification: string; usesPersonalData: boolean; riskTier: string; lifecycle: string;
  guardrails: string[]; frameworks: string[]; score: number; severity: string; gaps: string[];
}
interface Data {
  summary: { systems: number; highRisk: number; production: number; personalData: number; ungoverned: number; noGuardrails: number; avgRisk: number };
  byTier: Record<string, number>; worklist: Sys[]; systems: Sys[]; riskTiers: string[]; canEdit: boolean;
}
let DATA: Data | null = null;

function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function sysRow(s: Sys): string {
  return `<tr class="row-c" data-sys="${s.id}">
    <td><span class="nm">${esc(s.name)}</span>${s.usesPersonalData ? ` <span class="sev sv-Medium" title="${esc(T("ais.piiTitle"))}">PII</span>` : ""}<div class="muted" style="font-size:11.5px;max-width:340px">${esc(s.purpose)}</div></td>
    <td><span class="tier tier-${esc(s.riskTier)}">${esc(s.riskTier)}</span></td>
    <td>${esc(s.lifecycle)}</td>
    <td>${esc(s.modelName || "—")}<div class="muted" style="font-size:11px">${esc([s.provider, s.hosting].filter(Boolean).join(" · "))}</div></td>
    <td><span class="sev sv-${esc(s.severity)}">${esc(s.severity)}</span> <b>${s.score}</b></td>
    <td>${s.gaps.length ? `<span style="color:#fbbf24">${fmt("ais.gapN", { n: s.gaps.length })}</span>` : `<span style="color:#34d399">✓</span>`}</td>
  </tr>
  <tr id="d-${s.id}" style="display:none"><td colspan="6" style="background:#0f1117">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;padding:6px 2px 10px">
      <div class="panel">
        <div class="muted" style="font-size:11px;text-transform:uppercase;margin-bottom:5px">${T("ais.governance")}</div>
        <div style="font-size:12.5px;line-height:1.7">${T("ais.frameworks")} ${s.frameworks.length ? s.frameworks.map((f) => `<span class="chip">${esc(f)}</span>`).join("") : `<span style='color:#fbbf24'>${T("ais.none")}</span>`}<br>
        ${T("ais.guardrails")} ${s.guardrails.length ? s.guardrails.map((g) => `<span class="chip">${esc(g)}</span>`).join("") : `<span style='color:#fbbf24'>${T("ais.none")}</span>`}<br>
        ${T("ais.data")} ${esc(s.dataClassification || "—")}</div>
      </div>
      <div class="panel">
        <div class="muted" style="font-size:11px;text-transform:uppercase;margin-bottom:5px">${T("ais.riskGaps")}</div>
        <ul style="font-size:12.5px;line-height:1.6;padding-left:18px;margin:0">${s.gaps.map((g) => `<li>${esc(g)}</li>`).join("") || `<li class='muted'>${T("ais.noGaps")}</li>`}</ul>
        <div id="comp-${s.id}" style="margin-top:8px"></div>
        <a class="btn-sm2" style="display:inline-block;margin-top:8px;text-decoration:none" href="/api/ai-systems/${s.id}/aibom" download>${T("ais.exportBom")}</a>
      </div>
    </div>
  </td></tr>`;
}

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card(T("ais.cSystems"), s.systems, fmt("ais.cSystemsF", { n: s.avgRisk })),
    card(T("ais.cHighRisk"), s.highRisk, T("ais.cHighRiskF"), s.highRisk ? "#f87171" : "#34d399"),
    card(T("ais.cProduction"), s.production, T("ais.cProductionF")),
    card(T("ais.cPersonal"), s.personalData, T("ais.cPersonalF"), s.personalData ? "#fbbf24" : undefined),
    card(T("ais.cUngoverned"), s.ungoverned, T("ais.cUngovernedF"), s.ungoverned ? "#f87171" : "#34d399"),
    card(T("ais.cNoGuard"), s.noGuardrails, T("ais.cNoGuardF"), s.noGuardrails ? "#fbbf24" : "#34d399"),
  ].join("");
  const tiers = d.riskTiers.map((tr) => `<span class="chip"><span class="tier tier-${esc(tr)}">${esc(tr)}</span> ${d.byTier[tr] || 0}</span>`).join("");
  const thead = `<thead><tr><th>${T("ais.thSystem")}</th><th>${T("ais.thTier")}</th><th>${T("ais.thLifecycle")}</th><th>${T("ais.thModel")}</th><th>${T("ais.thRisk")}</th><th>${T("ais.thGaps")}</th></tr></thead>`;
  const worklist = d.worklist.length
    ? `<table class="t">${thead}<tbody>${d.worklist.map(sysRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${T("ais.allGoverned")}</div>`;
  const all = `<table class="t">${thead}<tbody>${d.systems.map(sysRow).join("")}</tbody></table>`;

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">${T("ais.secTiers")}</div><div>${tiers}</div>
    <div class="sec">${fmt("ais.secWorklist", { n: d.worklist.length })}</div>${worklist}
    <div class="sec">${fmt("ais.secRegister", { n: d.systems.length })}</div>${all}`;

  body.querySelectorAll<HTMLElement>("tr.row-c").forEach((tr) => {
    tr.addEventListener("click", () => { const det = $(`d-${tr.dataset.sys}`); if (det) { det.style.display = det.style.display === "none" ? "" : "none"; if (det.style.display === "") void loadComponents(Number(tr.dataset.sys)); } });
  });
  const nb = $("ai-new") as HTMLButtonElement | null, db = $("ai-demo") as HTMLButtonElement | null;
  if (!d.canEdit) { for (const b of [nb, db]) if (b) { b.disabled = true; b.style.opacity = "0.5"; } }
}

async function loadComponents(id: number): Promise<void> {
  const host = $(`comp-${id}`); if (!host || host.dataset.loaded) return;
  try {
    const sys = await getJson(`/api/ai-systems/${id}`);
    const comps = sys.components || [];
    host.dataset.loaded = "1";
    host.innerHTML = `<div class="muted" style="font-size:11px;text-transform:uppercase;margin-bottom:4px">${fmt("ais.bomComps", { n: comps.length })}</div>` +
      (comps.length ? comps.map((c: any) => `<span class="chip">${esc(c.type)}: ${esc(c.name)}${c.version ? "@" + esc(c.version) : ""}</span>`).join("") : `<span class='muted' style='font-size:12px'>${T("ais.noneRecorded")}</span>`);
  } catch { /* ignore */ }
}

function openModal(): void { $("m-modal")?.classList.add("open"); ($("f-name") as HTMLInputElement)?.focus(); }
function closeModal(): void { $("m-modal")?.classList.remove("open"); const e = $("f-err"); if (e) e.textContent = ""; }
async function save(): Promise<void> {
  const v = (id: string): string => ($(id) as HTMLInputElement | HTMLSelectElement)?.value || "";
  const name = v("f-name").trim(); const err = $("f-err");
  if (!name) { if (err) err.textContent = T("ais.nameRequired"); return; }
  const body = { name, purpose: v("f-purpose"), provider: v("f-provider"), modelName: v("f-model"), modelType: v("f-mtype"), hosting: v("f-hosting"), riskTier: v("f-tier"), lifecycle: v("f-life"), dataClassification: v("f-data"), usesPersonalData: v("f-pii") === "1", guardrails: v("f-guard"), frameworks: v("f-fw"), endpoint: v("f-endpoint") };
  try { render(await getJson("/api/ai-systems", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })); closeModal(); toast(T("ais.registered")); }
  catch (e) { if (err) err.textContent = `⚠️ ${(e as Error).message}`; }
}
async function demo(): Promise<void> {
  try { render(await getJson("/api/ai-systems-seed-demo", { method: "POST" })); toast(T("ais.demoLoaded")); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("ai-new")?.addEventListener("click", openModal);
  $("ai-demo")?.addEventListener("click", () => void demo());
  $("m-cancel")?.addEventListener("click", closeModal);
  $("m-save")?.addEventListener("click", () => void save());
  $("m-modal")?.addEventListener("click", (e) => { if (e.target === $("m-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Escape") closeModal(); });
  void load();
});
async function load(): Promise<void> {
  try { render(await getJson("/api/ai-systems")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
