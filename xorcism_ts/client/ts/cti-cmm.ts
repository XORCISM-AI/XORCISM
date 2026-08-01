/**
 * cti-cmm.ts — CTI-CMM assessment cockpit (/cti-cmm).
 * List/create assessments; per assessment, score each domain's CTI use cases on CTI0–CTI3, toggle
 * domain applicability, and read per-domain + overall maturity (radar) plus the gap worklist.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2300); }
const col = (v: number | null): string => (v == null ? "#334155" : v >= 2.5 ? "#4ade80" : v >= 1.5 ? "#fbbf24" : v >= 0.5 ? "#fb923c" : "#f87171");

let SEL: number | null = null;
const OPEN = new Set<string>();

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}
const post = (u: string, b?: unknown): Promise<any> => api(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
const patch = (u: string, b: unknown): Promise<any> => api(u, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });

function radar(points: any[], stroke: string): string {
  const n = points.length; if (n < 3) return "";
  const cx = 150, cy = 140, R = 110, max = 3;
  const pt = (i: number, r: number): [number, number] => { const a = -Math.PI / 2 + (i / n) * 2 * Math.PI; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  const rings = [1, 2, 3].map((f) => `<polygon points="${points.map((_, i) => pt(i, R * f / max).join(",")).join(" ")}" fill="none" stroke="#23273f" stroke-width="1"/>`).join("");
  const spokes = points.map((_, i) => { const [x, y] = pt(i, R); return `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#23273f" stroke-width="1"/>`; }).join("");
  const val = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.value) || 0) / max)).join(",")).join(" ");
  const tgt = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.target) || 0) / max)).join(",")).join(" ");
  const dots = points.map((p, i) => { const [x, y] = pt(i, R * Math.min(1, (Number(p.value) || 0) / max)); return p.value == null ? "" : `<circle cx="${x}" cy="${y}" r="2.5" fill="${stroke}"/>`; }).join("");
  const labels = points.map((p, i) => { const [x, y] = pt(i, R + 15); return `<text x="${x}" y="${y}" fill="#94a3b8" font-size="9" text-anchor="middle" dominant-baseline="middle">${esc(p.domain)}</text>`; }).join("");
  return `<svg viewBox="0 0 300 290" width="100%" style="max-width:320px;display:block;margin:0 auto">${rings}${spokes}
    <polygon points="${tgt}" fill="none" stroke="#64748b" stroke-width="1.2" stroke-dasharray="4 3"/>
    <polygon points="${val}" fill="${stroke}33" stroke="${stroke}" stroke-width="1.8"/>${dots}${labels}</svg>`;
}

const lvOpts = (v: number | null): string => ["", "0", "1", "2", "3"]
  .map((o) => `<option value="${o}" ${String(v ?? "") === o ? "selected" : ""}>${o === "" ? "— CTI? —" : "CTI" + o}</option>`).join("");

function renderDash(d: any): void {
  const s = d.summary, c = d.catalogue;
  $("ver").textContent = `— v${c.version} · ${c.domains} domains · ${c.useCases} use cases`;
  $("kpis").innerHTML = [
    ["Assessments", s.assessments], ["Completed", s.completed],
    ["Avg maturity", s.avgMaturity != null ? `${s.avgMaturity}/3` : "—"], ["Open gaps", s.openGaps],
  ].map(([l, v]) => `<div class="card"><div class="lbl">${esc(l)}</div><div class="val">${esc(v)}</div></div>`).join("");
  $("body").innerHTML = d.assessments.length ? d.assessments.map((a: any) => `
    <tr class="row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.programName)}${a.assessor ? " · " + esc(a.assessor) : ""} · target CTI${a.targetLevel}</div></td>
      <td><b style="color:${col(a.overall)}">${a.overall != null ? a.overall + "/3" : "—"}</b> <span class="bar"><span style="width:${((a.overall || 0) / 3) * 100}%;background:${col(a.overall)}"></span></span></td>
      <td class="muted">${a.scored}/${a.total}</td>
      <td>${a.belowTarget ? `<span class="gap">${a.belowTarget}</span>` : "—"}</td>
      <td><button class="btn ghost danger del" data-id="${a.id}">Del</button></td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">No CTI-CMM assessment yet — create one to measure your CTI program.</td></tr>`;
}

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  const a = d.assessment, sc = d.score;
  $("detail").style.display = "";
  const domains = d.domains.map((dm: any) => {
    const open = OPEN.has(dm.code);
    const ucs = open ? dm.useCases.map((u: any) => `
      <div class="uc"><span class="ucn">${esc(u.name)} <span class="tgt">↑CTI${u.targetLevel}</span></span>
        ${u.level != null ? `<span class="lv lv${u.level}">CTI${u.level}</span>` : ""}
        <select class="uc-lv" data-uc="${esc(u.id)}" ${dm.applicable ? "" : "disabled"}>${lvOpts(u.level)}</select>
        <input class="uc-note" data-uc="${esc(u.id)}" value="${esc(u.notes)}" placeholder="evidence / note…" style="flex:1;min-width:150px" ${dm.applicable ? "" : "disabled"}></div>`).join("") : "";
    const body = open ? `<div class="domb">
        <div class="meta"><b>Purpose:</b> ${esc(dm.purpose)}</div>
        <div class="meta"><b>CTI mission:</b> ${esc(dm.mission)}</div>
        <div class="meta"><b>Data sources:</b> ${dm.dataSources.map((x: string) => `<span class="src">${esc(x)}</span>`).join("")}</div>
        <label style="font-size:11px;color:#94a3b8;display:inline-flex;gap:5px;align-items:center;margin:4px 0">
          <input type="checkbox" class="dom-na" data-dom="${esc(dm.code)}" ${dm.applicable ? "checked" : ""}> in scope</label>
        ${ucs}</div>` : "";
    return `<div class="dom ${dm.applicable ? "" : "na"}"><div class="dom-h" data-dom="${esc(dm.code)}">
        <span class="dn">${open ? "▾" : "▸"} ${esc(dm.name)}</span> <span class="code">${esc(dm.code)}</span>
        <span class="dm">${dm.applicable ? `maturity <b style="color:${col(dm.maturity)}">${dm.maturity != null ? dm.maturity + "/3" : "—"}</b> · ${dm.scored}/${dm.total}` : "out of scope"}</span>
      </div>${body}</div>`;
  }).join("");

  $("detail").innerHTML = `
    <div class="dh"><span>🧗</span><b style="font-size:15px">${esc(a.name)}</b><span class="muted">${esc(a.programName)}</span>
      <span style="margin-left:auto"></span><span class="big" style="color:${col(sc.overall)}">${sc.overall != null ? sc.overall + "/3" : "—"}</span><span class="muted">overall</span></div>
    <div class="hdr">
      <label>CTI program<input id="h-prog" value="${esc(a.programName)}" style="min-width:170px"></label>
      <label>Assessor<input id="h-assessor" value="${esc(a.assessor)}"></label>
      <label>Target level<select id="h-target">${[1, 2, 3].map((o) => `<option value="${o}" ${a.targetLevel === o ? "selected" : ""}>CTI${o}</option>`).join("")}</select></label>
      <span class="muted" style="font-size:11px;align-self:flex-end">${sc.domainsInScope}/${d.domains.length} domains in scope · coverage ${sc.coverage}%</span></div>
    <div class="grid">
      <div class="panel"><h3>Domain maturity radar (CTI0–3)</h3>${radar(sc.radar, "#22d3ee")}</div>
      <div>${domains}</div></div>
    <div class="sec">Improvement worklist (below target CTI${sc.target})</div>
    ${sc.worklist.length ? `<ul class="worklist">${sc.worklist.map((w: any) => `<li><span class="code" style="font-family:ui-monospace,monospace;color:#a5b4fc">${esc(w.domain)}</span> <b>${esc(w.useCase)}</b> <span class="muted">CTI${w.level} → target CTI${w.target}</span> <span class="gap">+${w.gap}</span></li>`).join("")}</ul>` : `<div class="muted" style="padding:10px">No gaps below target.</div>`}`;
}

async function load(): Promise<void> { try { renderDash(await api("/api/cti-cmm")); } catch (e) { toast((e as Error).message); } }
async function open(id: number): Promise<void> { try { renderDetail(await api(`/api/cti-cmm/${id}`)); renderDash(await api("/api/cti-cmm")); } catch (e) { toast((e as Error).message); } }

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("c-add").addEventListener("click", async () => {
    const body = {
      name: ($("c-name") as HTMLInputElement).value.trim(), programName: ($("c-prog") as HTMLInputElement).value.trim(),
      assessor: ($("c-assessor") as HTMLInputElement).value.trim(), targetLevel: Number(($("c-target") as HTMLSelectElement).value),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/cti-cmm", body);
      (["c-name", "c-prog", "c-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      OPEN.clear(); OPEN.add("ASSET"); await load(); await open(r.id); $("detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".del") as HTMLElement | null;
    if (del) { ev.stopPropagation(); if (!confirm("Delete this CTI-CMM assessment?")) return;
      try { await api(`/api/cti-cmm/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("detail").style.display = "none"; await load(); } catch (e) { toast((e as Error).message); } return; }
    const row = t.closest(".row") as HTMLElement | null;
    if (row) { if (!OPEN.size) OPEN.add("ASSET"); void open(Number(row.dataset.id)); }
  });

  $("detail").addEventListener("click", (ev) => {
    const h = (ev.target as HTMLElement).closest(".dom-h") as HTMLElement | null;
    if (!h || SEL == null) return;
    const c = h.dataset.dom!; if (OPEN.has(c)) OPEN.delete(c); else OPEN.add(c);
    void open(SEL);
  });

  $("detail").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("uc-lv")) renderDetail(await post(`/api/cti-cmm/${SEL}/score`, { useCaseId: (t as HTMLElement).dataset.uc, level: (t as HTMLSelectElement).value }));
      else if (t.classList.contains("dom-na")) renderDetail(await post(`/api/cti-cmm/${SEL}/domain`, { domainCode: (t as HTMLElement).dataset.dom, applicable: (t as HTMLInputElement).checked }));
      else if (t.id === "h-target") renderDetail(await patch(`/api/cti-cmm/${SEL}`, { targetLevel: (t as HTMLSelectElement).value }));
      await load();
    } catch (e) { toast((e as Error).message); }
  });
  $("detail").addEventListener("focusout", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("uc-note")) renderDetail(await post(`/api/cti-cmm/${SEL}/score`, { useCaseId: (t as HTMLElement).dataset.uc, notes: (t as HTMLInputElement).value }));
      else if (t.id === "h-prog") { await patch(`/api/cti-cmm/${SEL}`, { programName: (t as HTMLInputElement).value }); toast("saved"); }
      else if (t.id === "h-assessor") { await patch(`/api/cti-cmm/${SEL}`, { assessor: (t as HTMLInputElement).value }); toast("saved"); }
    } catch (e) { toast((e as Error).message); }
  });
});
