/**
 * tid-cmm.ts — TID-CMM (Threat-Informed Detection CMM) assessment cockpit (/tid-cmm).
 * List/create assessments; per assessment, score each domain's sub-capabilities 0–5 against per-level
 * descriptors (or NA = scoped out), pick an assessment tier (ceiling), and read the weighted overall +
 * band, a per-domain radar, a weighted gap worklist (each with the target-level descriptor as guidance)
 * and the constraints + crosswalks. Companion response model: TIR-CMM.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2500); }
const col = (v: number | null): string => (v == null ? "#334155" : v >= 4 ? "#4ade80" : v >= 3 ? "#22d3ee" : v >= 2 ? "#fbbf24" : v >= 1 ? "#fb923c" : "#f87171");
const bandColor = (id: string): string => ({ L0: "#f87171", L1: "#fb923c", L2: "#fbbf24", L3: "#22d3ee", L4: "#4ade80", L5: "#a78bfa" }[id] || "#94a3b8");

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
  const cx = 155, cy = 145, R = 112, max = 5;
  const pt = (i: number, r: number): [number, number] => { const a = -Math.PI / 2 + (i / n) * 2 * Math.PI; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  const rings = [1, 2, 3, 4, 5].map((f) => `<polygon points="${points.map((_, i) => pt(i, R * f / max).join(",")).join(" ")}" fill="none" stroke="#23273f" stroke-width="1"/>`).join("");
  const spokes = points.map((_, i) => { const [x, y] = pt(i, R); return `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#23273f" stroke-width="1"/>`; }).join("");
  const val = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.value) || 0) / max)).join(",")).join(" ");
  const tgt = points.map((p, i) => pt(i, R * Math.min(1, (Number(p.target) || 0) / max)).join(",")).join(" ");
  const dots = points.map((p, i) => { const [x, y] = pt(i, R * Math.min(1, (Number(p.value) || 0) / max)); return p.value == null ? "" : `<circle cx="${x}" cy="${y}" r="2.5" fill="${stroke}"/>`; }).join("");
  const labels = points.map((p, i) => { const [x, y] = pt(i, R + 14); return `<text x="${x}" y="${y}" fill="#94a3b8" font-size="9.5" text-anchor="middle" dominant-baseline="middle">${esc(p.domain)}</text>`; }).join("");
  return `<svg viewBox="0 0 310 300" width="100%" style="max-width:330px;display:block;margin:0 auto">${rings}${spokes}
    <polygon points="${tgt}" fill="none" stroke="#64748b" stroke-width="1.2" stroke-dasharray="4 3"/>
    <polygon points="${val}" fill="${stroke}33" stroke="${stroke}" stroke-width="1.8"/>${dots}${labels}</svg>`;
}

const lvOpts = (v: number | null, na: boolean): string => ["", "0", "1", "2", "3", "4", "5", "NA"]
  .map((o) => { const sel = na ? o === "NA" : String(v ?? "") === o; return `<option value="${o}" ${sel ? "selected" : ""}>${o === "" ? "— L? —" : o === "NA" ? "NA" : "L" + o}</option>`; }).join("");

function renderDash(d: any): void {
  const s = d.summary, m = d.model;
  $("td-ver").textContent = `— v${m.version} · ${m.domains} domains · ${m.subCapabilities} sub-capabilities · ATT&CK v${m.attack.version} · ${m.licence}`;
  const tierSel = $("c-tier") as HTMLSelectElement;
  if (!tierSel.options.length) tierSel.innerHTML = m.tiers.map((t: any) => `<option value="${t.id}" ${t.id === "structured" ? "selected" : ""}>${esc(t.name)}${t.ceiling ? " (ceiling " + t.ceiling + ")" : ""}</option>`).join("");
  $("td-kpis").innerHTML = [
    ["Assessments", s.assessments], ["Completed", s.completed],
    ["Avg maturity", s.avgScore != null ? `${s.avgScore}/5` : "—"], ["Open gaps", s.openGaps],
  ].map(([l, v]) => `<div class="td-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("td-body").innerHTML = d.assessments.length ? d.assessments.map((a: any) => `
    <tr class="td-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted" style="font-size:11px">${esc(a.orgName)}${a.assessor ? " · " + esc(a.assessor) : ""}</div></td>
      <td><span class="td-tier">${esc(a.tier)}</span></td>
      <td>${a.band ? `<span class="td-band" style="background:${bandColor(a.band.id)}22;color:${bandColor(a.band.id)};border:1px solid ${bandColor(a.band.id)}">${esc(a.band.name)}</span> <b style="color:${col(a.overall)}">${a.overall != null ? a.overall : "—"}</b>` : "—"}</td>
      <td class="muted">${a.scored}/${a.total}${a.na ? ` <span class="td-chip">${a.na} NA</span>` : ""}</td>
      <td>${a.belowTarget ? `<span class="td-gap">${a.belowTarget}</span>` : "—"}</td>
      <td><button class="td-btn ghost danger td-del" data-id="${a.id}">Del</button></td></tr>`).join("")
    : `<tr><td colspan="6" class="td-empty">No TID-CMM assessment yet — create one to measure your detection readiness.</td></tr>`;
}

function subRow(u: any): string {
  const desc = u.level != null && u.levels ? (u.levels[String(u.level)] || "") : "";
  return `<div class="td-sub">
    <span class="td-sid">${esc(u.id)}</span>
    <span class="td-sn"><div class="nm">${esc(u.name)}${u.na ? ` <span class="td-chip">NA — scoped out</span>` : ""}</div>
      <div class="qn">${esc(u.question)}</div>
      ${desc ? `<div class="lvd"><b>L${u.level}:</b> ${esc(desc)}</div>` : ""}</span>
    <span class="td-sc">
      <select class="td-lv" data-sub="${esc(u.id)}" title="maturity level 0–5, or NA to scope out">${lvOpts(u.level, u.na)}</select>
      <input class="td-note" data-sub="${esc(u.id)}" value="${esc(u.notes)}" placeholder="evidence / note…">
    </span></div>`;
}

function domainBlock(dm: any): string {
  const open = OPEN.has(dm.code);
  const body = open ? `<div class="td-domb">
      <div class="td-q"><b>${esc(dm.intent)}</b>${dm.antiPattern ? ` — <i>anti-pattern: ${esc(dm.antiPattern)}</i>` : ""}</div>
      ${dm.ceilingRule ? `<div class="td-q" style="color:#a78bfa">⛒ ${esc(dm.ceilingRule)}</div>` : ""}
      ${dm.subCapabilities.map(subRow).join("")}
    </div>` : "";
  return `<div class="td-dom"><div class="td-domh" data-dom="${esc(dm.code)}">
      <span>${open ? "▾" : "▸"}</span><span class="td-code">${esc(dm.code)}</span><span class="td-dn">${esc(dm.name)}</span>
      <span class="td-dm">weight ${dm.weight}% · <b style="color:${col(dm.score)}">${dm.score != null ? dm.score + "/5" : "—"}</b> · ${dm.scored}/${dm.total}${dm.na ? " · " + dm.na + " NA" : ""}</span>
    </div>${body}</div>`;
}

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  const a = d.assessment, sc = d.score, band = sc.band;
  $("td-detail").style.display = "";
  $("td-detail").innerHTML = `
    <div class="td-dh"><span style="font-size:18px">🔎</span><b>${esc(a.name)}</b><span class="muted">${esc(a.orgName)}</span>
      <span style="margin-left:auto"></span>
      ${band ? `<span class="td-band" style="background:${bandColor(band.id)}22;color:${bandColor(band.id)};border:1px solid ${bandColor(band.id)};font-size:12px;padding:3px 10px">${esc(band.name)}</span>` : ""}
      <span class="td-big" style="color:${col(sc.overall)}">${sc.overall != null ? sc.overall : "—"}</span><span class="muted">/5</span>
      <button class="td-btn ghost" id="td-close">Close</button></div>
    <div class="td-hdr">
      <label>Assessment tier<select id="h-tier">${d.tiers.map((t: any) => `<option value="${t.id}" ${a.tier === t.id ? "selected" : ""}>${esc(t.name)}${t.ceiling ? " · ceiling " + t.ceiling : ""}</option>`).join("")}</select></label>
      <label>Target level<select id="h-target">${[3, 4, 5].map((o) => `<option value="${o}" ${a.targetLevel === o ? "selected" : ""}>L${o}</option>`).join("")}</select></label>
      <label>Organisation<input id="h-org" value="${esc(a.orgName)}" style="min-width:150px"></label>
      <label>Assessor<input id="h-assessor" value="${esc(a.assessor)}"></label>
      <span class="muted" style="font-size:11px;align-self:flex-end">coverage ${sc.coverage}% · ${sc.na} scoped-out · ceiling ${sc.ceiling >= 6 ? "none" : "L" + sc.ceiling}</span></div>
    <div class="td-grid">
      <div class="td-panel" style="margin:0"><h3>Detection readiness radar (0–5)</h3>${radar(sc.radar, "#8b5cf6")}
        <div class="muted" style="font-size:10.5px;text-align:center;margin-top:4px">dashed = target L${sc.target}</div></div>
      <div>${d.domains.map(domainBlock).join("")}</div>
    </div>
    <div class="td-sec">Improvement worklist — below target L${sc.target} (weighted, with the target-level descriptor)</div>
    ${sc.worklist.length ? `<ul class="td-worklist">${sc.worklist.map((w: any) => `<li><span class="td-code">${esc(w.domain)}</span> <b>${esc(w.name)}</b> <span class="muted">L${w.level} → target L${w.target}</span> <span class="td-gap">+${w.gap}</span>${w.guidance ? `<div class="td-guid">↳ L${w.target}: ${esc(w.guidance)}</div>` : ""}</li>`).join("")}</ul>` : `<div class="muted" style="padding:8px">No sub-capabilities below target.</div>`}
    <div class="td-sec">Structural constraints (inter-domain ceilings — the model is deliberately hard to game)</div>
    <div class="td-con">${d.constraints.map((c: any) => `<div class="c"><b>${esc(c.id)} · ${esc(c.name)}</b><div class="r">${esc(c.rule)}</div></div>`).join("")}</div>
    <div class="muted" style="font-size:11px;margin-top:10px">Companion response model: <b>${esc(d.companion || "TIR-CMM")}</b>. Aligned to <b>MITRE ATT&CK v${esc(d.attack.version)}</b> (${d.attack.techniques} techniques). Crosswalks: ${d.crosswalks.map((c: any) => `<span class="td-chip">${esc(c.name)}</span>`).join(" ")}</div>`;
}

async function load(): Promise<void> { try { renderDash(await api("/api/tid-cmm")); } catch (e) { toast((e as Error).message); } }
async function open(id: number): Promise<void> { try { renderDetail(await api(`/api/tid-cmm/${id}`)); renderDash(await api("/api/tid-cmm")); } catch (e) { toast((e as Error).message); } }

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("c-add").addEventListener("click", async () => {
    const body = {
      name: ($("c-name") as HTMLInputElement).value.trim(), orgName: ($("c-org") as HTMLInputElement).value.trim(),
      assessor: ($("c-assessor") as HTMLInputElement).value.trim(), tier: ($("c-tier") as HTMLSelectElement).value,
      targetLevel: Number(($("c-target") as HTMLSelectElement).value),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/tid-cmm", body);
      (["c-name", "c-org", "c-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      OPEN.clear(); OPEN.add("TI"); await load(); await open(r.id); $("td-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("td-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".td-del") as HTMLElement | null;
    if (del) { ev.stopPropagation(); if (!confirm("Delete this TID-CMM assessment?")) return;
      try { await api(`/api/tid-cmm/${del.dataset.id}`, { method: "DELETE" }); if (SEL === Number(del.dataset.id)) { SEL = null; $("td-detail").style.display = "none"; } await load(); } catch (e) { toast((e as Error).message); } return; }
    const row = t.closest(".td-row") as HTMLElement | null;
    if (row) { if (!OPEN.size) OPEN.add("TI"); void open(Number(row.dataset.id)); }
  });

  $("td-detail").addEventListener("click", (ev) => {
    const t = ev.target as HTMLElement;
    if (t.id === "td-close") { SEL = null; $("td-detail").style.display = "none"; void load(); return; }
    const h = t.closest(".td-domh") as HTMLElement | null;
    if (h && SEL != null) { const c = h.dataset.dom!; if (OPEN.has(c)) OPEN.delete(c); else OPEN.add(c); void open(SEL); }
  });

  $("td-detail").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("td-lv")) {
        const val = (t as HTMLSelectElement).value;
        const payload: any = { subCapId: (t as HTMLElement).dataset.sub };
        if (val === "NA") { payload.na = true; } else { payload.na = false; payload.level = val; }
        renderDetail(await post(`/api/tid-cmm/${SEL}/score`, payload));
      } else if (t.id === "h-tier") renderDetail(await patch(`/api/tid-cmm/${SEL}`, { tier: (t as HTMLSelectElement).value }));
      else if (t.id === "h-target") renderDetail(await patch(`/api/tid-cmm/${SEL}`, { targetLevel: (t as HTMLSelectElement).value }));
      await load();
    } catch (e) { toast((e as Error).message); }
  });
  $("td-detail").addEventListener("focusout", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("td-note")) renderDetail(await post(`/api/tid-cmm/${SEL}/score`, { subCapId: (t as HTMLElement).dataset.sub, notes: (t as HTMLInputElement).value }));
      else if (t.id === "h-org") { await patch(`/api/tid-cmm/${SEL}`, { orgName: (t as HTMLInputElement).value }); toast("saved"); }
      else if (t.id === "h-assessor") { await patch(`/api/tid-cmm/${SEL}`, { assessor: (t as HTMLInputElement).value }); toast("saved"); }
    } catch (e) { toast((e as Error).message); }
  });
});
