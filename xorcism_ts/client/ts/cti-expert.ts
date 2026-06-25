/**
 * cti-expert.ts — client for the CTI-Expert AI OSINT investigation cockpit (/cti-expert).
 * Dashboard (KPIs, 4-phase flow, technique catalogue, recent investigations) + an "Investigate"
 * form that POSTs a target to the local-AI analyst and renders the graded INTSUM.
 */
import { initI18n, t } from "./i18n";
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const PHASE_KEY: Record<string, string> = { Acquire: "cte.phaseAcquire", Enrich: "cte.phaseEnrich", Assess: "cte.phaseAssess", Deliver: "cte.phaseDeliver" };
const phaseLabel = (p: string): string => (PHASE_KEY[p] ? t(PHASE_KEY[p]) : p);

/** Minimal, safe Markdown → HTML (escape first, then a few inline/block rules). */
function md(src: string): string {
  const lines = esc(src).split(/\r?\n/);
  let html = "", inList = false;
  for (let ln of lines) {
    ln = ln.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    const h = ln.match(/^(#{2,3})\s+(.*)/);
    const li = ln.match(/^\s*[-*]\s+(.*)/);
    if (li) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${li[1]}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (h) html += `<h3>${h[2]}</h3>`;
    else if (ln.trim()) html += `<p>${ln}</p>`;
  }
  if (inList) html += "</ul>";
  return html;
}

const gaugeColor = (n: number): string => n >= 80 ? "#7f1d1d" : n >= 55 ? "#78350f" : n >= 30 ? "#1e3a5f" : "#1e2133";

async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }

function toast(msg: string): void {
  const el = $("toast"); if (!el) return;
  el.textContent = msg; el.className = "show";
  setTimeout(() => { el.className = ""; }, 3200);
}

function renderInvestigation(inv: any): string {
  const findings = (inv.findings || []) as { technique: string; phase: string; finding: string; reliability: string; severity: string }[];
  const obs = (inv.observables || []) as { type: string; value: string }[];
  const recs = (inv.recommendations || []) as string[];
  const tags = (inv.attackTags || []) as string[];
  const aiBadge = inv.offline ? `<span class="ai-badge" title="${esc(inv.model)}">${t("cte.offlineBadge")}</span>` : `<span class="ai-badge">🤖 ${esc(inv.model)}</span>`;
  return `
  <div class="sec">${t("cte.invResult")} <span class="spacer"></span>${aiBadge}</div>
  <div class="grid2" style="margin-bottom:14px">
    <div class="panel" style="display:flex;gap:14px;align-items:center">
      <div class="gauge" style="background:${gaugeColor(inv.exposureScore)}">${inv.exposureScore}</div>
      <div>
        <div class="nm" style="font-size:15px">${esc(inv.target)} <span class="muted">(${esc(inv.kind)})</span></div>
        <div style="margin-top:4px"><span class="sev sv-${esc(inv.severity)}">${esc(inv.severity)}</span> · ${fmt("cte.exposureN", { n: inv.exposureScore })}</div>
        <div class="muted" style="font-size:11px;margin-top:4px">${fmt("cte.intelMeta", { intel: inv.intelId, n: obs.length, case: inv.id ? fmt("cte.caseN", { id: inv.id }) : "" })}</div>
      </div>
    </div>
    <div class="panel"><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">${t("cte.execBrief")}</div><div class="md" style="margin-top:5px">${md(inv.brief || "")}</div></div>
  </div>
  ${tags.length ? `<div style="margin-bottom:10px">${tags.map((tg) => `<span class="chip">${esc(tg)}</span>`).join("")}</div>` : ""}
  <div class="grid2">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">INTSUM</div>
      <div class="md">${md(inv.summary || "")}</div>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">${fmt("cte.findings", { n: findings.length })}</div>
      <table class="t"><thead><tr><th>${t("cte.thRel")}</th><th>${t("cte.thSev")}</th><th>${t("cte.thPhase")}</th><th>${t("cte.thFinding")}</th></tr></thead><tbody>
      ${findings.map((f) => `<tr><td><span class="rel rel-${esc((f.reliability || "F")[0])}">${esc(f.reliability)}</span></td><td><span class="sev sv-${esc(f.severity)}">${esc(f.severity)}</span></td><td><span class="ph ph-${esc(f.phase)}">${esc(phaseLabel(f.phase))}</span></td><td><span class="nm">${esc(f.technique)}</span><div class="muted" style="font-size:11.5px">${esc(f.finding)}</div></td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("cte.noFindings")}</td></tr>`}
      </tbody></table>
    </div>
  </div>
  <div class="grid2" style="margin-top:14px">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">${fmt("cte.observables", { n: obs.length })}</div>
      <table class="t"><tbody>${obs.map((o) => `<tr><td style="width:120px"><span class="ph ph-Acquire">${esc(o.type)}</span></td><td class="mono">${esc(o.value)}</td></tr>`).join("") || `<tr><td class="muted">${t("cte.none")}</td></tr>`}</tbody></table>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">${t("cte.recommendations")}</div>
      <ul class="md" style="padding-left:18px">${recs.map((r) => `<li>${esc(r)}</li>`).join("") || `<li class='muted'>${t("cte.none")}</li>`}</ul>
    </div>
  </div>`;
}

function renderDashboard(d: any): string {
  const s = d.summary || {};
  const recent = (d.recent || []) as any[];
  const phaseDesc: Record<string, string> = { Acquire: t("cte.descAcquire"), Enrich: t("cte.descEnrich"), Assess: t("cte.descAssess"), Deliver: t("cte.descDeliver") };
  return `
  <div class="cards">
    <div class="card"><div class="lbl">${t("cte.cInvestigations")}</div><div class="val">${s.investigations || 0}</div><div class="foot">${fmt("cte.cInvestigations.foot", { n: s.avgExposure || 0 })}</div></div>
    <div class="card"><div class="lbl">${t("cte.cCritical")}</div><div class="val" style="color:#fca5a5">${s.critical || 0}</div><div class="foot">${fmt("cte.cCritical.foot", { n: s.high || 0 })}</div></div>
    <div class="card"><div class="lbl">${t("cte.cObservables")}</div><div class="val">${s.observables || 0}</div><div class="foot">→ XTHREAT.OBSERVABLE</div></div>
    <div class="card"><div class="lbl">${t("cte.cTechniques")}</div><div class="val">${s.techniques || 0}</div><div class="foot">${fmt("cte.cTechniques.foot", { n: s.kinds || 0 })}</div></div>
  </div>
  <div class="sec">${t("cte.sec4Phase")}</div>
  <div class="flow">
    ${(d.phases || []).map((p: any) => `<div class="stage s-${esc(p.phase)}"><div class="n" style="font-size:18px">${esc(phaseLabel(p.phase))}</div><div class="d">${esc(phaseDesc[p.phase] || "")}</div><div class="t" style="margin-top:6px">${fmt("cte.nTechniques", { n: p.techniques })}</div></div>`).join('<div class="arrow">→</div>')}
  </div>
  <div class="sec">${t("cte.secRecent")}</div>
  <table class="t"><thead><tr><th>${t("cte.thTarget")}</th><th>${t("cte.thType")}</th><th>${t("cte.thExposure")}</th><th>${t("cte.thSeverity")}</th><th>${t("cte.thFindings")}</th><th>${t("cte.thWhen")}</th></tr></thead><tbody>
    ${recent.map((i) => `<tr style="cursor:pointer" data-inv="${i.id}"><td class="nm">${esc(i.target)}</td><td><span class="ph ph-Acquire">${esc(i.kind)}</span></td><td>${i.exposureScore}/100</td><td><span class="sev sv-${esc(i.severity)}">${esc(i.severity)}</span></td><td>${(i.findings || []).length}</td><td class="muted" style="font-size:11px">${esc((i.createdDate || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${t("cte.noInvestigations")}</td></tr>`}
  </tbody></table>
  <div class="sec">${fmt("cte.secCatalogue", { n: (d.techniqueCatalogue || []).length })}</div>
  <div class="tcat">
    ${(d.techniqueCatalogue || []).map((tc: any) => `<div class="tc"><div class="tn">${esc(tc.name)}</div><div class="tm"><span class="ph ph-${esc(tc.phase)}">${esc(phaseLabel(tc.phase))}</span> ${tc.connector ? `· <span class="mono">${esc(tc.connector)}</span>` : ""}</div></div>`).join("")}
  </div>`;
}

async function loadDashboard(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { body.innerHTML = renderDashboard(await getJson("/api/cti-expert")); wireRows(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("cte.loadFailed", { e: esc((e as Error).message) })}</div>`; }
}

function wireRows(): void {
  document.querySelectorAll<HTMLElement>("tr[data-inv]").forEach((tr) => {
    tr.addEventListener("click", async () => {
      try {
        const inv = await getJson(`/api/cti-expert/${tr.dataset.inv}`);
        const r = $("result"); if (r) { r.innerHTML = renderInvestigation(inv); r.scrollIntoView({ behavior: "smooth" }); }
      } catch { toast(t("cte.loadInvFailed")); }
    });
  });
}

async function investigate(): Promise<void> {
  const target = ($("t-target") as HTMLInputElement)?.value.trim();
  const kind = ($("t-kind") as HTMLSelectElement)?.value;
  const btn = $("t-go") as HTMLButtonElement;
  if (!target) { toast(t("cte.enterTarget")); return; }
  btn.disabled = true; btn.textContent = t("cte.investigating");
  try {
    const r = await fetch("/api/cti-expert/investigate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, kind: kind || undefined }),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || String(r.status));
    const out = $("result"); if (out) { out.innerHTML = renderInvestigation(d); out.scrollIntoView({ behavior: "smooth" }); }
    toast(d.offline ? t("cte.planReady") : t("cte.invComplete"));
    void loadDashboard();
  } catch (e) { toast(fmt("cte.failed", { e: (e as Error).message })); }
  finally { btn.disabled = false; btn.innerHTML = t("cte.investigateBtn"); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("t-go")?.addEventListener("click", () => void investigate());
  $("t-target")?.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void investigate(); });
  void loadDashboard();
});
