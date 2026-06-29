/**
 * ai-control-library.ts — AI Control Library cockpit (/ai-control-library).
 * Renders the reusable AI-control repository, the lifecycle × risk-domain coverage matrix, the
 * control-library maturity / failure-mode checks, and per-control status assessment.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function val(id: string): string { return (document.getElementById(id) as HTMLInputElement).value.trim(); }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const t = $("toast"); t.textContent = msg; t.className = ok ? "toast-ok" : "toast-err"; (t as HTMLElement).style.opacity = "1"; setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2600); }
const pctColor = (p: number): string => p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444";
const heat = (n: number): string => n === 0 ? "#1e2133" : n === 1 ? "#1e3a5f" : n <= 3 ? "#14532d" : "#065f46";

interface Ctl { id: number; ref: string; objective: string; statement: string; riskDomains: string[]; type: string; lifecycle: string; owner: string; evidence: string; testing: string; frequency: string; frameworks: string[]; status: string; }
interface Lib {
  controls: Ctl[];
  coverage: { byLifecycle: Record<string, number>; byDomain: Record<string, number>; byType: Record<string, number>; byStatus: Record<string, number> };
  matrix: { lifecycle: string; domains: Record<string, number> }[];
  gaps: { noObjective: number; noOwner: number; noEvidence: number; noTesting: number; noFramework: number; noFrequency: number; lifecycleUncovered: string[]; domainUncovered: string[] };
  summary: { total: number; implemented: number; partial: number; planned: number; ownershipPct: number; evidencePct: number; testablePct: number; mappedPct: number; maturityPct: number };
  vocab: { lifecycle: string[]; domains: string[]; types: string[]; frequency: string[]; owners: string[]; status: string[] };
}

interface SysCov { aiSystemId: number; name: string; riskTier: string; applied: number; implemented: number; coveragePct: number; }
let VOCAB: Lib["vocab"] | null = null;
let SYSTEMS: { id: number; name: string; riskTier: string }[] = [];

async function load(): Promise<void> {
  let d: Lib & { systems?: { id: number; name: string; riskTier: string }[]; systemCoverage?: { systems: SysCov[]; summary: { systems: number; governed: number; avgCoverage: number } } };
  try { const r = await fetch("/api/ai-control-library"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ai-controls").innerHTML = `<div class="muted">Failed to load: ${esc(e)}</div>`; return; }
  VOCAB = d.vocab; SYSTEMS = d.systems || [];
  fillSelects(d.vocab);
  const s = d.summary;
  $("ai-kpis").innerHTML = [
    `<div class="kpi"><div class="v">${s.total}</div><div class="l">AI controls</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.maturityPct)}">${s.maturityPct}%</div><div class="l">Library maturity</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.total ? Math.round(s.implemented / s.total * 100) : 0)}">${s.implemented}/${s.total}</div><div class="l">Implemented</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.ownershipPct)}">${s.ownershipPct}%</div><div class="l">With owner</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.evidencePct)}">${s.evidencePct}%</div><div class="l">With evidence</div></div>`,
    `<div class="kpi"><div class="v" style="color:${pctColor(s.mappedPct)}">${s.mappedPct}%</div><div class="l">Framework-mapped</div></div>`,
  ].join("");

  // common control-library failure modes
  const g = d.gaps; const flag = (n: number, label: string): string => `<span class="chip ${n ? "bad" : "ok"}">${n ? "✗ " + n : "✓"} ${esc(label)}</span>`;
  $("ai-gaps").innerHTML = d.summary.total ? [
    flag(g.noObjective, "no measurable objective"), flag(g.noOwner, "no owner"), flag(g.noEvidence, "no evidence"),
    flag(g.noTesting, "no testing method"), flag(g.noFrequency, "no monitoring frequency"), flag(g.noFramework, "no framework mapping"),
    g.lifecycleUncovered.length ? `<span class="chip bad">✗ lifecycle gaps: ${g.lifecycleUncovered.map(esc).join(", ")}</span>` : `<span class="chip ok">✓ all lifecycle phases covered</span>`,
    g.domainUncovered.length ? `<span class="chip bad">✗ risk domains uncovered: ${g.domainUncovered.map(esc).join(", ")}</span>` : `<span class="chip ok">✓ all risk domains covered</span>`,
  ].join("") : `<span class="muted">Library is empty — seed the starter library to begin.</span>`;
  ($("ai-seed") as HTMLButtonElement).style.display = d.summary.total ? "none" : "";

  renderMatrix(d);
  renderSysCoverage(d.systemCoverage);
  renderControls(d.controls);
}

function renderSysCoverage(sc?: { systems: SysCov[]; summary: { systems: number; governed: number; avgCoverage: number } }): void {
  const host = document.getElementById("ai-syscov"); if (!host) return;
  if (!sc || !sc.systems.length) { host.innerHTML = `<div class="muted" style="font-size:12px">No AI systems inventoried — apply controls to systems (from the controls table) to track per-system coverage.</div>`; return; }
  host.innerHTML = `<div class="muted" style="font-size:11px;margin-bottom:4px">${sc.summary.governed}/${sc.summary.systems} systems governed · avg ${sc.summary.avgCoverage}% implemented</div>
    <table class="ai"><thead><tr><th>AI system</th><th>Risk tier</th><th>Applied</th><th>Implemented</th><th>Coverage</th></tr></thead><tbody>${sc.systems.map((s) => `<tr><td>${esc(s.name)}</td><td>${esc(s.riskTier || "—")}</td><td>${s.applied}</td><td>${s.implemented}</td><td><span class="bar"><i style="width:${s.coveragePct}%;background:${pctColor(s.coveragePct)}"></i></span> ${s.coveragePct}%</td></tr>`).join("")}</tbody></table>`;
}

function renderMatrix(d: Lib): void {
  const domains = d.vocab.domains;
  const head = `<tr><th class="lc"></th>${domains.map((x) => `<th title="${esc(x)}">${esc(x.split(" ").map((w) => w[0]).join(""))}</th>`).join("")}</tr>`;
  const body = d.matrix.map((r) => `<tr><td class="lc">${esc(r.lifecycle)}</td>${domains.map((dm) => { const n = r.domains[dm] || 0; return `<td><span class="cell" style="background:${heat(n)};color:${n ? "#e2e8f0" : "#3b4663"}">${n || "·"}</span></td>`; }).join("")}</tr>`).join("");
  $("ai-matrix").innerHTML = `<table class="ai mtx">${head}${body}</table><div class="muted" style="font-size:11px;margin-top:4px">Count of controls per AI lifecycle phase (rows) × risk domain (columns). Empty cells are coverage gaps.</div>`;
}

function renderControls(ctls: Ctl[]): void {
  if (!ctls.length) { $("ai-controls").innerHTML = `<div class="muted">No controls yet.</div>`; return; }
  const opt = (sel: string): string => (VOCAB?.status || ["implemented", "partial", "planned", "na"]).map((o) => `<option ${o === sel ? "selected" : ""}>${o}</option>`).join("");
  const applyCell = (id: number): string => SYSTEMS.length ? `<select data-apply="${id}" class="c-apply" style="background:#0f1117;border:1px solid #2d3250;color:#94a3b8;border-radius:6px;padding:3px 6px;font-size:11px"><option value="">apply ▾</option>${SYSTEMS.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select>` : "";
  $("ai-controls").innerHTML = `<table class="ai"><thead><tr><th>ID</th><th>Objective / statement</th><th>Type</th><th>Lifecycle</th><th>Domains</th><th>Owner</th><th>Evidence</th><th>Frameworks</th><th>Status</th><th>Apply</th><th></th></tr></thead><tbody>${ctls.map((c) => `<tr>
    <td><b>${esc(c.ref)}</b></td>
    <td>${esc(c.objective)}<div class="muted" style="font-size:11px">${esc(c.statement)}</div></td>
    <td class="t-${esc(c.type)}">${esc(c.type)}</td>
    <td>${esc(c.lifecycle)}</td>
    <td>${c.riskDomains.map((x) => `<span class="tag">${esc(x)}</span>`).join(" ")}</td>
    <td>${c.owner ? esc(c.owner) : "<span class='tag' style='background:#7f1d1d;color:#fecaca'>none</span>"}</td>
    <td style="max-width:180px">${c.evidence ? esc(c.evidence) : "<span class='tag' style='background:#7f1d1d;color:#fecaca'>none</span>"}<div class="muted" style="font-size:10px">${esc(c.testing || "")}${c.frequency ? " · " + esc(c.frequency) : ""}</div></td>
    <td style="max-width:160px"><span class="muted" style="font-size:11px">${c.frameworks.map(esc).join(" · ") || "<span class='tag' style='background:#7f1d1d;color:#fecaca'>unmapped</span>"}</span></td>
    <td><select data-id="${c.id}" class="c-st" style="background:#0f1117;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:3px 6px;font-size:11px">${opt(c.status)}</select></td>
    <td>${applyCell(c.id)}</td>
    <td><a href="#" data-del="${c.id}" style="color:#f87171">✕</a></td></tr>`).join("")}</tbody></table>`;
  $("ai-controls").querySelectorAll<HTMLSelectElement>("select.c-apply").forEach((sel) => sel.onchange = async () => {
    if (!sel.value) return;
    await fetch(`/api/ai-control-library/control/${sel.dataset.apply}/apply`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ aiSystemId: Number(sel.value) }) });
    toast("Applied to AI system"); void load();
  });
  $("ai-controls").querySelectorAll<HTMLSelectElement>("select.c-st").forEach((sel) => sel.onchange = async () => {
    await fetch(`/api/ai-control-library/control/${sel.dataset.id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: sel.value }) });
    toast("Status updated"); void load();
  });
  $("ai-controls").querySelectorAll<HTMLAnchorElement>("a[data-del]").forEach((a) => a.onclick = async (e) => {
    e.preventDefault(); if (!confirm("Delete this control?")) return;
    await fetch(`/api/ai-control-library/control/${a.dataset.del}`, { method: "DELETE" }); toast("Deleted"); void load();
  });
}

function fillSelects(v: Lib["vocab"]): void {
  const set = (id: string, opts: string[], blank = false): void => { const el = document.getElementById(id) as HTMLSelectElement; if (el && !el.dataset.filled) { el.innerHTML = (blank ? `<option value="">—</option>` : "") + opts.map((o) => `<option>${o}</option>`).join(""); el.dataset.filled = "1"; } };
  set("c-type", v.types); set("c-lc", v.lifecycle); set("c-dom", v.domains); set("c-owner", v.owners, true); set("c-freq", v.frequency, true);
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); void load();
  ($("ai-seed") as HTMLButtonElement).onclick = async () => {
    const r = await fetch("/api/ai-control-library/seed", { method: "POST" });
    if (r.ok) { const j = await r.json(); toast(`Seeded ${j.created} controls`); void load(); } else toast("Failed", false);
  };
  ($("c-add") as HTMLButtonElement).onclick = async () => {
    if (!val("c-ref") || !val("c-obj")) return toast("Identifier and objective required", false);
    const r = await fetch("/api/ai-control-library/control", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      ref: val("c-ref"), objective: val("c-obj"), statement: val("c-stmt"), type: val("c-type"), lifecycle: val("c-lc"),
      riskDomains: val("c-dom"), owner: val("c-owner"), frequency: val("c-freq"), testing: val("c-test"), evidence: val("c-ev"),
      frameworks: val("c-fw"), status: "planned" }) });
    if (r.ok) { toast("Control added"); (document.getElementById("c-ref") as HTMLInputElement).value = ""; (document.getElementById("c-obj") as HTMLInputElement).value = ""; void load(); } else toast("Failed (duplicate id?)", false);
  };
});
