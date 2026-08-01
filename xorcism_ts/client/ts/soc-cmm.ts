/**
 * soc-cmm.ts — SOC-CMM advanced capability & maturity assessment (/soc-cmm).
 * Renders the dual-axis assessment: maturity (0–5) for all 26 aspects + capability (0–3) for the
 * Technology & Services domains, with importance weighting, two radars, and per-aspect results entry.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2200); }
const col = (v: number | null, max: number): string => { if (v == null) return "#334155"; const p = v / max; return p >= 0.8 ? "#4ade80" : p >= 0.5 ? "#fbbf24" : p >= 0.25 ? "#fb923c" : "#f87171"; };

let DATA: any = null;
const OPEN = new Set<string>();

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}
const post = (u: string, b: unknown): Promise<any> => api(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });

/** SVG radar chart from [{domain,value,target}] on a 0..max axis. */
function radar(points: any[], max: number, stroke: string): string {
  const n = points.length;
  if (n < 3) return `<div class="muted" style="font-size:12px;padding:20px;text-align:center">${points.map((p) => `${esc(p.domain)}: <b>${p.value ?? "—"}</b>`).join(" · ") || "—"}</div>`;
  const cx = 130, cy = 120, R = 92;
  const pt = (i: number, r: number): [number, number] => { const a = -Math.PI / 2 + (i / n) * 2 * Math.PI; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  const rings = [0.25, 0.5, 0.75, 1].map((f) => `<polygon points="${points.map((_, i) => pt(i, R * f).join(",")).join(" ")}" fill="none" stroke="#23273f" stroke-width="1"/>`).join("");
  const spokes = points.map((_, i) => { const [x, y] = pt(i, R); return `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#23273f" stroke-width="1"/>`; }).join("");
  const valPoly = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.value) || 0) / max)).join(",")).join(" ");
  const tgtPoly = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.target) || 0) / max)).join(",")).join(" ");
  const dots = points.map((p, i) => { const [x, y] = pt(i, R * Math.min(1, (Number(p.value) || 0) / max)); return `<circle cx="${x}" cy="${y}" r="2.5" fill="${stroke}"/>`; }).join("");
  const labels = points.map((p, i) => { const [x, y] = pt(i, R + 16); return `<text x="${x}" y="${y}" fill="#94a3b8" font-size="9.5" text-anchor="middle" dominant-baseline="middle">${esc(p.domain)} ${p.value ?? "—"}</text>`; }).join("");
  return `<svg viewBox="0 0 260 240" width="100%" style="max-width:320px;display:block;margin:0 auto">
    ${rings}${spokes}
    <polygon points="${tgtPoly}" fill="none" stroke="#64748b" stroke-width="1.2" stroke-dasharray="4 3"/>
    <polygon points="${valPoly}" fill="${stroke}33" stroke="${stroke}" stroke-width="1.8"/>${dots}${labels}</svg>`;
}

const matOpts = (v: number | null): string => ["", "0", "0.5", "1", "1.5", "2", "2.5", "3", "3.5", "4", "4.5", "5"]
  .map((o) => `<option value="${o}" ${String(v ?? "") === o ? "selected" : ""}>${o === "" ? "—" : o}</option>`).join("");
const capOpts = (v: number | null): string => ["", "0", "0.5", "1", "1.5", "2", "2.5", "3"]
  .map((o) => `<option value="${o}" ${String(v ?? "") === o ? "selected" : ""}>${o === "" ? "—" : o}</option>`).join("");
const impOpts = (v: number): string => [1, 2, 3, 4, 5].map((o) => `<option value="${o}" ${o === v ? "selected" : ""}>${o}</option>`).join("");

function render(): void {
  const d = DATA, s = d.summary, a = d.assessment;
  const cards = [
    ["Overall maturity", `<span style="color:${col(s.overallMaturity, 5)}">${s.overallMaturity ?? "—"}</span> <span class="muted" style="font-size:13px">/5</span>`, `target ${s.target}`],
    ["Overall capability", `<span style="color:${col(s.overallCapability, 3)}">${s.overallCapability ?? "—"}</span> <span class="muted" style="font-size:13px">/3</span>`, `target ${s.targetCapability} · Tech+Services`],
    ["Coverage", `${s.coverage}%`, `${s.scored}/${s.aspects} aspects`],
    ["Below target", `${s.belowTarget}`, `+ ${s.capBelowTarget} capability`],
  ].map(([l, v, f]) => `<div class="card"><div class="lbl">${esc(l)}</div><div class="val">${v}</div><div class="foot">${esc(f)}</div></div>`).join("");

  const header = `<div class="hdr">
    <label>SOC scope<input id="h-scope" value="${esc(a.scopeName)}" placeholder="e.g. Enterprise SOC" style="min-width:180px"></label>
    <label>Assessment type<select id="h-type"><option value="self" ${a.assessType === "self" ? "selected" : ""}>Self-assessment</option><option value="3rd-party" ${a.assessType === "3rd-party" ? "selected" : ""}>3rd-party</option></select></label>
    <label>Assessor<input id="h-assessor" value="${esc(a.assessor)}" placeholder="assessor"></label>
    <label>Target maturity<select id="h-tmat">${["1", "1.5", "2", "2.5", "3", "3.5", "4", "4.5", "5"].map((o) => `<option ${String(a.targetMaturity) === o ? "selected" : ""}>${o}</option>`).join("")}</select></label>
    <label>Target capability<select id="h-tcap">${["1", "1.5", "2", "2.5", "3"].map((o) => `<option ${String(a.targetCapability) === o ? "selected" : ""}>${o}</option>`).join("")}</select></label>
  </div>`;

  const radars = `<div class="grid2">
    <div class="panel"><h3>Maturity radar (0–5)</h3>${radar(d.maturityRadar, 5, "#4ade80")}</div>
    <div class="panel"><h3>Capability radar (0–3) — Technology &amp; Services</h3>${radar(d.capabilityRadar, 3, "#818cf8")}</div>
  </div>`;

  const domBars = `<div class="panel" style="margin-bottom:10px"><h3>Domain scores</h3>${d.domains.map((dm: any) => `
    <div class="dom"><span class="nm">${esc(dm.domain)}</span>
      <span class="bar mat"><i style="width:${((dm.maturity || 0) / 5) * 100}%"></i></span>
      <b style="min-width:30px;color:${col(dm.maturity, 5)}">${dm.maturity ?? "—"}</b>
      ${dm.capable ? `<span class="bar cap"><i style="width:${((dm.capability || 0) / 3) * 100}%"></i></span><b style="min-width:30px;color:${col(dm.capability, 3)}">${dm.capability ?? "—"}</b>` : `<span style="flex:1"></span><span class="muted" style="min-width:30px">—</span>`}
    </div>`).join("")}<div class="dom" style="border:0"><span class="nm muted" style="font-size:11px">maturity /5 · capability /3</span></div></div>`;

  const rowsByDom = (dom: string): string => d.rows.filter((r: any) => r.domain === dom).map((r: any) => `
    <tr><td>${esc(r.aspect)}<div class="muted" style="font-size:11px">${esc(r.description)}</div></td>
      <td><select class="sc sc-m" data-id="${r.id}">${matOpts(r.maturity)}</select></td>
      <td>${r.capable ? `<select class="sc sc-c" data-id="${r.id}">${capOpts(r.capability)}</select>` : `<span class="muted">n/a</span>`}</td>
      <td><select class="sc sc-i" data-id="${r.id}">${impOpts(r.importance)}</select></td>
      <td><input class="note" data-id="${r.id}" value="${esc(r.notes)}" placeholder="evidence / notes…"></td></tr>`).join("");

  const domains = d.domains.map((dm: any) => {
    const open = OPEN.has(dm.domain);
    const body = open ? `<table class="t"><thead><tr><th>Aspect</th><th>Maturity 0–5</th><th>Capability 0–3</th><th>Importance</th><th>Notes</th></tr></thead>
      <tbody>${rowsByDom(dm.domain)}</tbody></table>` : "";
    return `<div class="domgrp"><div class="h" data-dom="${esc(dm.domain)}">
        <span class="dn">${open ? "▾" : "▸"} ${esc(dm.domain)}</span>
        <span class="dm">maturity <b style="color:${col(dm.maturity, 5)}">${dm.maturity ?? "—"}</b>${dm.capable ? ` · capability <b style="color:${col(dm.capability, 3)}">${dm.capability ?? "—"}</b>` : ""} · ${dm.scored}/${dm.aspects}</span>
      </div>${body}</div>`;
  }).join("");

  const worklist = d.worklist.length ? `<ul class="worklist">${d.worklist.map((w: any) => `<li>
      <span class="dchip">${esc(w.domain)}</span> <b>${esc(w.aspect)}</b>
      <span class="muted">maturity ${w.maturity ?? "—"}${w.capability != null ? ` · capability ${w.capability}` : ""}</span>
      ${w.gap ? `<span class="gap">+${w.gap} maturity</span>` : ""}${w.capGap ? `<span class="capchip">+${w.capGap} capability</span>` : ""}
      <span class="muted" style="margin-left:auto">importance ${w.importance}</span></li>`).join("")}</ul>` : `<div class="muted" style="padding:12px">No gaps below target — nice.</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>${header}${radars}${domBars}
    <div class="sec">Results entry — 26 aspects</div>${domains}
    <div class="sec">Improvement worklist (below target × importance)</div>${worklist}`;
}

async function load(): Promise<void> {
  try { DATA = await api("/api/soc-cmm"); if (!OPEN.size) OPEN.add("Business"); render(); }
  catch (e) { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${esc((e as Error).message)}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("body").addEventListener("click", (ev) => {
    const h = (ev.target as HTMLElement).closest(".domgrp > .h") as HTMLElement | null;
    if (!h) return;
    const dom = h.dataset.dom!; if (OPEN.has(dom)) OPEN.delete(dom); else OPEN.add(dom);
    render();
  });

  const saveScore = async (id: string, patch: Record<string, unknown>): Promise<void> => {
    try { DATA = await post(`/api/soc-cmm/score/${id}`, patch); render(); } catch (e) { toast((e as Error).message); }
  };
  const saveHeader = async (patch: Record<string, unknown>): Promise<void> => {
    try { DATA = await post("/api/soc-cmm/assessment", patch); render(); toast("saved"); } catch (e) { toast((e as Error).message); }
  };

  $("body").addEventListener("change", (ev) => {
    const t = ev.target as HTMLElement;
    const id = t.dataset.id;
    if (id && t.classList.contains("sc-m")) void saveScore(id, { maturity: (t as HTMLSelectElement).value });
    else if (id && t.classList.contains("sc-c")) void saveScore(id, { capability: (t as HTMLSelectElement).value });
    else if (id && t.classList.contains("sc-i")) void saveScore(id, { importance: (t as HTMLSelectElement).value });
    else if (t.id === "h-type") void saveHeader({ assessType: (t as HTMLSelectElement).value });
    else if (t.id === "h-tmat") void saveHeader({ targetMaturity: (t as HTMLSelectElement).value });
    else if (t.id === "h-tcap") void saveHeader({ targetCapability: (t as HTMLSelectElement).value });
  });
  $("body").addEventListener("focusout", (ev) => {
    const t = ev.target as HTMLElement;
    const id = t.dataset.id;
    if (id && t.classList.contains("note")) void saveScore(id, { notes: (t as HTMLInputElement).value });
    else if (t.id === "h-scope") void saveHeader({ scopeName: (t as HTMLInputElement).value });
    else if (t.id === "h-assessor") void saveHeader({ assessor: (t as HTMLInputElement).value });
  });
});
