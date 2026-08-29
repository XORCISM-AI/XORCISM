/**
 * tir-cmm.ts — TIR-CMM (Threat-Informed Response CMM) assessment cockpit (/tir-cmm).
 * List/create assessments; per assessment, score each domain's sub-capabilities 0–5 with an evidence
 * grade (VC0–VC3) that CAPS the score, pick an assessment tier that sets the ceiling, and read the
 * evidence-capped weighted overall + band, a per-domain radar, a weighted gap worklist (each with its
 * remediation action) and the crosswalk to the referenced frameworks.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2500); }
const col = (v: number | null): string => (v == null ? "#334155" : v >= 4 ? "#4ade80" : v >= 3 ? "#22d3ee" : v >= 2 ? "#fbbf24" : v >= 1 ? "#fb923c" : "#f87171");
const bandColor = (id: string): string => ({ L0: "#f87171", L1: "#fb923c", L2: "#fbbf24", L3: "#22d3ee", L4: "#4ade80", L5: "#a78bfa" }[id] || "#94a3b8");

let SEL: number | null = null;
const OPEN = new Set<string>();
let MODEL: any = null;

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

const lvOpts = (v: number | null): string => ["", "0", "1", "2", "3", "4", "5"]
  .map((o) => `<option value="${o}" ${String(v ?? "") === o ? "selected" : ""}>${o === "" ? "— L? —" : "L" + o}</option>`).join("");
const evOpts = (v: string): string => ["", "VC0", "VC1", "VC2", "VC3"]
  .map((o) => `<option value="${o}" ${v === o ? "selected" : ""}>${o === "" ? "— ev —" : o}</option>`).join("");

function renderDash(d: any): void {
  MODEL = d.model;
  const s = d.summary, m = d.model;
  $("tc-ver").textContent = `— v${m.version} · ${m.domains} domains · ${m.subCapabilities} sub-capabilities · model ${m.licence.model}`;
  // populate tier select once
  const tierSel = $("c-tier") as HTMLSelectElement;
  if (!tierSel.options.length) tierSel.innerHTML = m.tiers.map((t: any) => `<option value="${t.id}" ${t.id === "baseline" ? "selected" : ""}>${esc(t.name)} (ceiling ${t.ceiling || "none"})</option>`).join("");
  $("tc-kpis").innerHTML = [
    ["Assessments", s.assessments], ["Completed", s.completed],
    ["Avg maturity", s.avgScore != null ? `${s.avgScore}/5` : "—"], ["Open gaps", s.openGaps],
  ].map(([l, v]) => `<div class="tc-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("tc-body").innerHTML = d.assessments.length ? d.assessments.map((a: any) => `
    <tr class="tc-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted" style="font-size:11px">${esc(a.orgName)}${a.assessor ? " · " + esc(a.assessor) : ""}</div></td>
      <td><span class="tc-tier">${esc(a.tier)}</span></td>
      <td>${a.band ? `<span class="tc-band" style="background:${bandColor(a.band.id)}22;color:${bandColor(a.band.id)};border:1px solid ${bandColor(a.band.id)}">${a.band.id} ${esc(a.band.name)}</span> <b style="color:${col(a.overall)}">${a.overall != null ? a.overall : "—"}</b>` : "—"}</td>
      <td class="muted">${a.scored}/${a.total}</td>
      <td>${a.belowTarget ? `<span class="tc-gap">${a.belowTarget}</span>` : "—"}${a.evidenceCapped ? ` <span class="tc-chip" title="scores capped by evidence grade (R3)">${a.evidenceCapped}⚠</span>` : ""}</td>
      <td><button class="tc-btn ghost danger tc-del" data-id="${a.id}">Del</button></td></tr>`).join("")
    : `<tr><td colspan="6" class="tc-empty">No TIR-CMM assessment yet — create one to measure your response readiness.</td></tr>`;
}

function subRow(u: any): string {
  const capped = u.effective != null && u.level != null && u.effective < u.level;
  const effBadge = u.level != null ? `<span class="tc-eff ${capped ? "cap" : "ok"}" title="${capped ? "capped by evidence grade " + esc(u.evidence || "VC0") : "effective score"}">→ ${u.effective}${capped ? " ⚠" : ""}</span>` : "";
  return `<div class="tc-sub">
    <span class="tc-sid">${esc(u.id)}</span>
    <span class="tc-sn"><div class="nm">${esc(u.name)}</div><div class="anchor"><b>L3:</b> ${esc(u.anchor)}</div></span>
    <span class="tc-sc">
      <select class="tc-lv" data-sub="${esc(u.id)}" title="maturity level 0–5">${lvOpts(u.level)}</select>
      <select class="tc-ev" data-sub="${esc(u.id)}" title="evidence grade — caps the score (${esc(u.evidenceExpect)})">${evOpts(u.evidence)}</select>
      ${effBadge}
      <input class="tc-note" data-sub="${esc(u.id)}" value="${esc(u.notes)}" placeholder="evidence / note…">
    </span></div>`;
}

function domainBlock(dm: any): string {
  const open = OPEN.has(dm.code);
  const cw = dm.crosswalk;
  const body = open ? `<div class="tc-domb">
      <div class="tc-q"><b>${esc(dm.question)}</b>${dm.note ? ` — <i>${esc(dm.note)}</i>` : ""}</div>
      ${dm.subCapabilities.map(subRow).join("")}
      ${cw ? `<div class="tc-q" style="margin-top:8px"><b>Crosswalk:</b> <span class="tc-chip">CSF ${esc(cw.csf || "—")}</span> <span class="tc-chip">800-61 ${esc(cw.nist || "—")}</span> <span class="tc-chip">ISO ${esc(cw.iso || "—")}</span> <span class="tc-chip">RE&CT ${esc(cw.react || "—")}</span> <span class="tc-chip">D3FEND ${esc(cw.d3fend || "—")}</span> <span class="tc-chip">SOC-CMM ${esc(cw.soccmm || "—")}</span></div>` : ""}
    </div>` : "";
  return `<div class="tc-dom"><div class="tc-domh" data-dom="${esc(dm.code)}">
      <span>${open ? "▾" : "▸"}</span><span class="tc-code">${esc(dm.code)}</span><span class="tc-dn">${esc(dm.name)}</span>
      <span class="tc-dm">weight ${dm.weight}% · <b style="color:${col(dm.score)}">${dm.score != null ? dm.score + "/5" : "—"}</b> · ${dm.scored}/${dm.total}</span>
    </div>${body}</div>`;
}

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  const a = d.assessment, sc = d.score;
  $("tc-detail").style.display = "";
  const band = sc.band;
  $("tc-detail").innerHTML = `
    <div class="tc-dh"><span style="font-size:18px">🎯</span><b>${esc(a.name)}</b><span class="muted">${esc(a.orgName)}</span>
      <span style="margin-left:auto"></span>
      ${band ? `<span class="tc-band" style="background:${bandColor(band.id)}22;color:${bandColor(band.id)};border:1px solid ${bandColor(band.id)};font-size:12px;padding:3px 10px">${band.id} · ${esc(band.name)}</span>` : ""}
      <span class="tc-big" style="color:${col(sc.overall)}">${sc.overall != null ? sc.overall : "—"}</span><span class="muted">/5</span>
      <button class="tc-btn ghost" id="tc-close">Close</button></div>
    <div class="tc-hdr">
      <label>Assessment tier<select id="h-tier">${d.tiers.map((t: any) => `<option value="${t.id}" ${a.tier === t.id ? "selected" : ""}>${esc(t.name)} · ceiling ${t.ceiling || "none"}</option>`).join("")}</select></label>
      <label>Target level<select id="h-target">${[3, 4, 5].map((o) => `<option value="${o}" ${a.targetLevel === o ? "selected" : ""}>L${o}</option>`).join("")}</select></label>
      <label>Organisation<input id="h-org" value="${esc(a.orgName)}" style="min-width:150px"></label>
      <label>Assessor<input id="h-assessor" value="${esc(a.assessor)}"></label>
      <span class="muted" style="font-size:11px;align-self:flex-end">coverage ${sc.coverage}% · ${sc.evidenceCapped} evidence-capped · ceiling L${sc.ceiling >= 6 ? "∞" : sc.ceiling}</span></div>
    <div class="tc-grid">
      <div class="tc-panel" style="margin:0"><h3>Domain readiness radar (0–5)</h3>${radar(sc.radar, "#f97316")}
        <div class="muted" style="font-size:10.5px;text-align:center;margin-top:4px">dashed = target L${sc.target}</div></div>
      <div>${d.domains.map(domainBlock).join("")}</div>
    </div>
    <div class="tc-sec">Improvement worklist — below target L${sc.target} (weighted, with remediation)</div>
    ${sc.worklist.length ? `<ul class="tc-worklist">${sc.worklist.map((w: any) => `<li><span class="tc-code">${esc(w.domain)}</span> <b>${esc(w.name)}</b> <span class="muted">L${w.level}→ eff ${w.effective} (${esc(w.evidence)})</span> <span class="tc-gap">+${w.gap}</span>${w.action ? `<div class="tc-act">↳ ${esc(w.action.act)}${w.action.owner ? ` · <b>${esc(w.action.owner)}</b>` : ""}${w.action.effort ? ` · effort ${w.action.effort}` : ""}</div>` : ""}</li>`).join("")}</ul>` : `<div class="muted" style="padding:8px">No sub-capabilities below target.</div>`}`;

  // constraints + companion/parent
  $("tc-detail").innerHTML += `
    <div class="tc-sec">Mechanical constraints (they lower scores; the model is deliberately hard to game)</div>
    <div class="tc-con">${d.constraints.map((c: any) => `<div class="c"><b>${esc(c.id)} · ${esc(c.name)}</b> <span class="muted" style="font-size:10px">[${esc(c.level)}]</span><div class="r">${esc(c.rule)}</div></div>`).join("")}</div>
    <div class="muted" style="font-size:11px;margin-top:10px">Companion detection model: <b>${esc(d.companion ? d.companion.model : "TID-CMM")}</b> · parent operating model: <b>${esc(d.parent ? d.parent.model : "UTIOM")}</b>. The per-domain crosswalk maps each domain to NIST CSF 2.0, NIST 800-61, ISO, RE&CT, MITRE D3FEND and SOC-CMM.</div>`;
}

async function load(): Promise<void> { try { renderDash(await api("/api/tir-cmm")); } catch (e) { toast((e as Error).message); } }
async function open(id: number): Promise<void> { try { renderDetail(await api(`/api/tir-cmm/${id}`)); renderDash(await api("/api/tir-cmm")); } catch (e) { toast((e as Error).message); } }

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
      const r = await post("/api/tir-cmm", body);
      (["c-name", "c-org", "c-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      OPEN.clear(); OPEN.add("RP"); await load(); await open(r.id); $("tc-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("tc-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".tc-del") as HTMLElement | null;
    if (del) { ev.stopPropagation(); if (!confirm("Delete this TIR-CMM assessment?")) return;
      try { await api(`/api/tir-cmm/${del.dataset.id}`, { method: "DELETE" }); if (SEL === Number(del.dataset.id)) { SEL = null; $("tc-detail").style.display = "none"; } await load(); } catch (e) { toast((e as Error).message); } return; }
    const row = t.closest(".tc-row") as HTMLElement | null;
    if (row) { if (!OPEN.size) OPEN.add("RP"); void open(Number(row.dataset.id)); }
  });

  $("tc-detail").addEventListener("click", (ev) => {
    const t = ev.target as HTMLElement;
    if (t.id === "tc-close") { SEL = null; $("tc-detail").style.display = "none"; void load(); return; }
    const h = t.closest(".tc-domh") as HTMLElement | null;
    if (h && SEL != null) { const c = h.dataset.dom!; if (OPEN.has(c)) OPEN.delete(c); else OPEN.add(c); void open(SEL); }
  });

  $("tc-detail").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("tc-lv")) renderDetail(await post(`/api/tir-cmm/${SEL}/score`, { subCapId: (t as HTMLElement).dataset.sub, level: (t as HTMLSelectElement).value }));
      else if (t.classList.contains("tc-ev")) renderDetail(await post(`/api/tir-cmm/${SEL}/score`, { subCapId: (t as HTMLElement).dataset.sub, evidence: (t as HTMLSelectElement).value }));
      else if (t.id === "h-tier") renderDetail(await patch(`/api/tir-cmm/${SEL}`, { tier: (t as HTMLSelectElement).value }));
      else if (t.id === "h-target") renderDetail(await patch(`/api/tir-cmm/${SEL}`, { targetLevel: (t as HTMLSelectElement).value }));
      await load();
    } catch (e) { toast((e as Error).message); }
  });
  $("tc-detail").addEventListener("focusout", async (ev) => {
    const t = ev.target as HTMLElement; if (SEL == null) return;
    try {
      if (t.classList.contains("tc-note")) renderDetail(await post(`/api/tir-cmm/${SEL}/score`, { subCapId: (t as HTMLElement).dataset.sub, notes: (t as HTMLInputElement).value }));
      else if (t.id === "h-org") { await patch(`/api/tir-cmm/${SEL}`, { orgName: (t as HTMLInputElement).value }); toast("saved"); }
      else if (t.id === "h-assessor") { await patch(`/api/tir-cmm/${SEL}`, { assessor: (t as HTMLInputElement).value }); toast("saved"); }
    } catch (e) { toast((e as Error).message); }
  });
});
