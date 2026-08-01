/**
 * inform.ts — MITRE CTID INFORM Threat-Informed Defense maturity cockpit (/inform).
 * List/create assessments; per assessment, score each component of the 3 weighted dimensions by its
 * achieved level, and read the weighted overall TID score, the per-dimension radar and the worklist.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2300); }
const col = (v: number | null): string => (v == null ? "#334155" : v >= 75 ? "#4ade80" : v >= 50 ? "#fbbf24" : v >= 25 ? "#fb923c" : "#f87171");

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
  const n = points.length, cx = 150, cy = 140, R = 108, max = 100;
  const pt = (i: number, r: number): [number, number] => { const a = -Math.PI / 2 + (i / n) * 2 * Math.PI; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  const poly = (r: (p: any) => number) => points.map((p, i) => pt(i, R * Math.min(1, r(p) / max)).join(",")).join(" ");
  const rings = [25, 50, 75, 100].map((f) => `<polygon points="${points.map((_, i) => pt(i, R * f / max).join(",")).join(" ")}" fill="none" stroke="#23273f" stroke-width="1"/>`).join("");
  const spokes = points.map((_, i) => { const [x, y] = pt(i, R); return `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#23273f" stroke-width="1"/>`; }).join("");
  const dots = points.map((p, i) => { const [x, y] = pt(i, R * Math.min(1, (Number(p.value) || 0) / max)); return p.value == null ? "" : `<circle cx="${x}" cy="${y}" r="3" fill="${stroke}"/>`; }).join("");
  const labels = points.map((p, i) => { const [x, y] = pt(i, R + 16); return `<text x="${x}" y="${y}" fill="#94a3b8" font-size="10" text-anchor="middle" dominant-baseline="middle">${esc(p.domain)}${p.value != null ? " " + p.value + "%" : ""}</text>`; }).join("");
  return `<svg viewBox="0 0 300 290" width="100%" style="max-width:320px;display:block;margin:0 auto">${rings}${spokes}
    <polygon points="${poly((p) => Number(p.target) || 0)}" fill="none" stroke="#64748b" stroke-width="1.2" stroke-dasharray="4 3"/>
    <polygon points="${poly((p) => Number(p.value) || 0)}" fill="${stroke}33" stroke="${stroke}" stroke-width="1.8"/>${dots}${labels}</svg>`;
}

const lvOpts = (levels: string[], v: number | null): string =>
  `<option value="" ${v == null ? "selected" : ""}>— not assessed —</option>` +
  levels.map((lv, i) => `<option value="${i}" ${v === i ? "selected" : ""}>L${i} · ${esc(lv)}</option>`).join("");

function renderDash(d: any): void {
  const s = d.summary, c = d.catalogue;
  $("ver").textContent = `— v${c.version} · ${c.dimensions} dimensions · ${c.components} components`;
  $("kpis").innerHTML = [
    ["Assessments", s.assessments], ["Completed", s.completed],
    ["Avg TID score", s.avgScore != null ? `${s.avgScore}%` : "—"], ["Open gaps", s.openGaps],
  ].map(([l, v]) => `<div class="card"><div class="lbl">${esc(l)}</div><div class="val">${esc(v)}</div></div>`).join("");
  $("body").innerHTML = d.assessments.length ? d.assessments.map((a: any) => `
    <tr class="row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.orgName)}${a.assessor ? " · " + esc(a.assessor) : ""}</div></td>
      <td><b style="color:${col(a.overall)}">${a.overall != null ? a.overall + "%" : "—"}</b> <span class="bar"><span style="width:${a.overall || 0}%;background:${col(a.overall)}"></span></span></td>
      <td class="muted">${a.scored}/${a.total}</td>
      <td>${a.belowMax ? `<span class="gap">${a.belowMax}</span>` : "—"}</td>
      <td><button class="btn ghost danger del" data-id="${a.id}">Del</button></td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">No INFORM assessment yet — create one to measure your threat-informed defense.</td></tr>`;
}

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  const a = d.assessment, sc = d.score;
  $("detail").style.display = "";
  const dims = d.dimensions.map((dm: any) => {
    const open = OPEN.has(dm.code);
    const comps = open ? dm.components.map((c: any) => `
      <div class="comp"><div class="cn">${esc(c.name)} ${c.level != null ? `<span class="pct" style="color:${col((c.level / c.max) * 100)}">L${c.level}/${c.max}</span>` : ""}</div>
        ${c.description ? `<div class="cq">${esc(c.description)}</div>` : ""}
        <div class="cq">❝ ${esc(c.question)} ❞</div>
        <div class="crow"><select class="comp-lv" data-c="${esc(c.id)}">${lvOpts(c.levels, c.level)}</select>
          <input class="note" data-c="${esc(c.id)}" value="${esc(c.notes)}" placeholder="evidence / note…"></div></div>`).join("") : "";
    return `<div class="dim"><div class="dim-h" data-dim="${esc(dm.code)}">
        <span class="dn">${open ? "▾" : "▸"} ${esc(dm.name)}</span> <span class="wt">${Math.round(dm.weight * 100)}%</span>
        <span class="dm">score <b style="color:${col(dm.score)}">${dm.score != null ? dm.score + "%" : "—"}</b> · ${dm.scored}/${dm.total}</span>
      </div>${open ? `<div class="dimb">${comps}</div>` : ""}</div>`;
  }).join("");

  $("detail").innerHTML = `
    <div class="dh"><span>🛡️</span><b style="font-size:15px">${esc(a.name)}</b><span class="muted">${esc(a.orgName)}</span>
      <span style="margin-left:auto"></span><span class="big" style="color:${col(sc.overall)}">${sc.overall != null ? sc.overall + "%" : "—"}</span><span class="muted">weighted TID</span></div>
    <div class="hdr">
      <label>Organization<input id="h-org" value="${esc(a.orgName)}" style="min-width:170px"></label>
      <label>Assessor<input id="h-assessor" value="${esc(a.assessor)}"></label>
      <span class="muted" style="font-size:11px;align-self:flex-end">coverage ${sc.coverage}% · weights CTI 35 / DM 40 / T&E 25</span></div>
    <div class="grid">
      <div class="panel"><h3>Dimension scores (0–100%)</h3>${radar(sc.radar, "#38bdf8")}
        <div style="margin-top:6px">${sc.dimensions.map((x: any) => `<div style="display:flex;gap:8px;align-items:center;font-size:12px;padding:2px 0"><span style="min-width:44px;font-family:ui-monospace,monospace;color:#a5b4fc">${esc(x.code)}</span><span class="bar" style="flex:1"><span style="width:${x.score || 0}%;background:${col(x.score)}"></span></span><b style="min-width:38px;color:${col(x.score)}">${x.score != null ? x.score + "%" : "—"}</b></div>`).join("")}</div></div>
      <div>${dims}</div></div>
    <div class="sec">Improvement worklist (below top level · weighted gap)</div>
    ${sc.worklist.length ? `<ul class="worklist">${sc.worklist.map((w: any) => `<li><span class="dchip">${esc(w.dimension)}</span> <b>${esc(w.component)}</b> <span class="muted">L${w.level}/${w.max}</span> <span class="gap">+${w.gap}</span></li>`).join("")}</ul>` : `<div class="muted" style="padding:10px">No components below the top level.</div>`}`;
}

async function load(): Promise<void> { try { renderDash(await api("/api/inform")); } catch (e) { toast((e as Error).message); } }
async function open(id: number): Promise<void> { try { renderDetail(await api(`/api/inform/${id}`)); renderDash(await api("/api/inform")); } catch (e) { toast((e as Error).message); } }

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("c-add").addEventListener("click", async () => {
    const body = { name: ($("c-name") as HTMLInputElement).value.trim(), orgName: ($("c-org") as HTMLInputElement).value.trim(), assessor: ($("c-assessor") as HTMLInputElement).value.trim() };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/inform", body);
      (["c-name", "c-org", "c-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      OPEN.clear(); OPEN.add("CTI"); await load(); await open(r.id); $("detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".del") as HTMLElement | null;
    if (del) { ev.stopPropagation(); if (!confirm("Delete this INFORM assessment?")) return;
      try { await api(`/api/inform/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("detail").style.display = "none"; await load(); } catch (e) { toast((e as Error).message); } return; }
    const row = t.closest(".row") as HTMLElement | null;
    if (row) { if (!OPEN.size) OPEN.add("CTI"); void open(Number(row.dataset.id)); }
  });

  $("detail").addEventListener("click", (ev) => {
    const h = (ev.target as HTMLElement).closest(".dim-h") as HTMLElement | null;
    if (!h || SEL == null) return;
    const c = h.dataset.dim!; if (OPEN.has(c)) OPEN.delete(c); else OPEN.add(c);
    void open(SEL);
  });

  $("detail").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    if (t.classList.contains("comp-lv")) {
      try { renderDetail(await post(`/api/inform/${SEL}/score`, { componentId: (t as HTMLElement).dataset.c, level: (t as HTMLSelectElement).value })); await load(); }
      catch (e) { toast((e as Error).message); }
    }
  });
  $("detail").addEventListener("focusout", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("note")) renderDetail(await post(`/api/inform/${SEL}/score`, { componentId: (t as HTMLElement).dataset.c, notes: (t as HTMLInputElement).value }));
      else if (t.id === "h-org") { await patch(`/api/inform/${SEL}`, { orgName: (t as HTMLInputElement).value }); toast("saved"); }
      else if (t.id === "h-assessor") { await patch(`/api/inform/${SEL}`, { assessor: (t as HTMLInputElement).value }); toast("saved"); }
    } catch (e) { toast((e as Error).message); }
  });
});
