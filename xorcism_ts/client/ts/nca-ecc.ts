/**
 * nca-ecc.ts — Saudi NCA ECC Implementation & Evidence cockpit (/nca-ecc).
 * Create an assessment, then per ECC control set status/owner/evidence and check off the expected
 * deliverables (GECC 2:2024). Reads implementation % + evidence readiness % per domain + overall.
 */
import { initI18n } from "./i18n";

interface Status { key: string; label: string; weight: number }
interface Cat { version: string; source: string; authority: string; url: string; domains: any[]; subdomains: any[]; controls: any[] }
interface Row { id: number; name: string; entityName: string; assessor: string; status: string; implementation: number; evidence: number; assessed: number; total: number }

const STATUSES: Status[] = [
  { key: "", label: "— set status —", weight: 0 },
  { key: "implemented", label: "Implemented", weight: 1 },
  { key: "in-progress", label: "In progress", weight: 0.5 },
  { key: "not-started", label: "Not started", weight: 0 },
  { key: "not-applicable", label: "Not applicable", weight: -1 },
];

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("ec-toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }
const color = (v: number): string => (v >= 80 ? "#4ade80" : v >= 50 ? "#fbbf24" : v >= 25 ? "#fb923c" : "#f87171");

let CAT: Cat | null = null;
let SEL: number | null = null;
const OPEN = new Set<string>();

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}
const post = (u: string, b?: unknown): Promise<any> => api(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });

function renderDash(d: any): void {
  const s = d.summary, c = d.catalogue;
  $("ec-ver").textContent = `— ${c.version} · ${c.domains} domains · ${c.controls} controls · ${c.deliverables} deliverables`;
  $("ec-kpis").innerHTML = [
    ["Assessments", s.assessments], ["Completed", s.completed],
    ["Avg implementation", `${s.avgImplementation}%`], ["Avg evidence", `${s.avgEvidence}%`],
  ].map(([l, v]) => `<div class="ec-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  $("ec-body").innerHTML = d.assessments.length ? d.assessments.map((a: Row) => `
    <tr class="ec-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.entityName)}${a.assessor ? " · " + esc(a.assessor) : ""}</div></td>
      <td><b style="color:${color(a.implementation)}">${a.implementation}%</b> <span class="bar"><span style="width:${a.implementation}%;background:${color(a.implementation)}"></span></span></td>
      <td><b style="color:${color(a.evidence)}">${a.evidence}%</b> <span class="bar"><span style="width:${a.evidence}%;background:${color(a.evidence)}"></span></span></td>
      <td class="muted">${a.assessed}/${a.total}</td>
      <td><button class="ec-btn ghost danger ec-del" data-id="${a.id}">Del</button></td>
    </tr>`).join("") : `<tr><td colspan="5" class="ec-empty">No ECC assessment yet — create one to start implementing.</td></tr>`;
}

function controlHtml(c: any): string {
  const stCls = c.status ? `st-${c.status}` : "";
  const stLabel = STATUSES.find((s) => s.key === c.status)?.label || "";
  const tools = (c.tools || []).map((t: string) => `<span class="tool">${esc(t)}</span>`).join("");
  const guides = (c.guidelines || []).slice(0, 12).map((g: string) => `<li class="gl">${esc(g)}</li>`).join("");
  const delivs = (c.deliverables || []).map((dv: string, i: number) => `<label class="deliv">
    <input type="checkbox" class="ec-dv" data-ref="${esc(c.ref)}" data-i="${i}" ${(c.deliverablesDone || []).includes(i) ? "checked" : ""}>
    <span>${esc(dv)}</span></label>`).join("");
  const subs = (c.subcontrols || []).map((s: any) => `<div class="subctl"><span class="r">${esc(s.ref)}</span> ${esc(s.text)}</div>`).join("");
  return `<div class="ctl" data-ref="${esc(c.ref)}">
    <div class="ctl-h"><span class="cref">${esc(c.ref)}</span>
      ${c.status ? `<span class="chip st ${stCls}">${esc(stLabel)}</span>` : ""}
      <span class="muted" style="font-size:10.5px">${(c.deliverablesDone || []).length}/${(c.deliverables || []).length} evidence</span></div>
    <div class="ctl-txt">${esc(c.text)}</div>
    ${subs ? `<div class="sec-t">Applies in cases</div>${subs}` : ""}
    ${tools ? `<div class="sec-t">Relevant tools</div>${tools}` : ""}
    ${guides ? `<div class="sec-t">Implementation guidelines</div><ul style="margin:0;padding-left:4px">${guides}</ul>` : ""}
    ${delivs ? `<div class="sec-t">Expected deliverables (check what you have)</div>${delivs}` : ""}
    <div class="ctl-row">
      <select class="ec-st" data-ref="${esc(c.ref)}">${STATUSES.map((s) => `<option value="${s.key}" ${c.status === s.key ? "selected" : ""}>${esc(s.label)}</option>`).join("")}</select>
      <input class="ec-owner" data-ref="${esc(c.ref)}" value="${esc(c.owner)}" placeholder="owner…" style="width:130px">
      <input class="ec-note" data-ref="${esc(c.ref)}" value="${esc(c.evidenceNote)}" placeholder="evidence note / reference…" style="flex:1;min-width:180px">
    </div></div>`;
}

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  const a = d.assessment, sc = d.score;
  const el = $("ec-detail"); el.style.display = "";
  el.innerHTML = `
    <div class="ec-dh">
      <span>&#127481;&#127462;</span><b style="font-size:15px">${esc(a.name)}</b>
      <span class="muted">${esc(a.entityName)}${a.assessor ? " · " + esc(a.assessor) : ""}</span>
      <span style="margin-left:auto"></span>
      <span class="big" style="color:${color(sc.implementation)}">${sc.implementation}%</span>
      <span class="muted">implementation</span>
    </div>
    <div class="ec-metrics">
      <div class="ec-metric"><div class="l">Evidence readiness</div><div class="n" style="color:${color(sc.evidence)}">${sc.evidence}% <span class="muted" style="font-size:11px">(${sc.deliverablesProduced}/${sc.deliverablesExpected})</span></div></div>
      <div class="ec-metric"><div class="l">Implemented</div><div class="n" style="color:#6ee7b7">${sc.implemented}</div></div>
      <div class="ec-metric"><div class="l">In progress</div><div class="n" style="color:#fde68a">${sc.inProgress}</div></div>
      <div class="ec-metric"><div class="l">Not started</div><div class="n">${sc.notStarted}</div></div>
      <div class="ec-metric"><div class="l">N/A</div><div class="n" style="color:#cbd5e1">${sc.na}</div></div>
      <div class="ec-metric"><div class="l">Assessed</div><div class="n">${sc.assessed}/${sc.total}</div></div>
    </div>
    ${d.domains.map((dm: any) => {
      const open = OPEN.has(dm.num);
      const body = open ? dm.subdomains.map((s: any) => `
        <div class="sub"><div class="sub-h">${esc(s.code)} — ${esc(s.name)}</div>
          ${s.objective ? `<div class="sub-obj">${esc(s.objective)}</div>` : ""}
          ${s.controls.map((c: any) => controlHtml(c)).join("")}</div>`).join("") : "";
      return `<div class="dom"><div class="dom-h" data-dom="${esc(dm.num)}">
          <span class="dn">${open ? "▾" : "▸"} Domain ${esc(dm.num)} — ${esc(dm.name)}</span>
          <span class="dm">impl <b style="color:${color(dm.implementation)}">${dm.implementation}%</b> · evidence <b style="color:${color(dm.evidence)}">${dm.evidence}%</b></span>
        </div>${body}</div>`;
    }).join("")}`;
}

async function load(): Promise<void> {
  try {
    if (!CAT) CAT = await api("/api/nca-ecc/catalogue");
    renderDash(await api("/api/nca-ecc"));
  } catch (e) { toast((e as Error).message); }
}
async function open(id: number): Promise<void> {
  try { renderDetail(await api(`/api/nca-ecc/${id}`)); renderDash(await api("/api/nca-ecc")); }
  catch (e) { toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("ec-add").addEventListener("click", async () => {
    const body = {
      name: ($("ec-name") as HTMLInputElement).value.trim(),
      entityName: ($("ec-entity") as HTMLInputElement).value.trim(),
      assessor: ($("ec-assessor") as HTMLInputElement).value.trim(),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/nca-ecc", body);
      (["ec-name", "ec-entity", "ec-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      OPEN.clear(); OPEN.add("1"); await load(); await open(r.id);
      $("ec-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("ec-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".ec-del") as HTMLElement | null;
    if (del) {
      ev.stopPropagation();
      if (!confirm("Delete this ECC assessment?")) return;
      try { await api(`/api/nca-ecc/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("ec-detail").style.display = "none"; await load(); }
      catch (e) { toast((e as Error).message); }
      return;
    }
    const row = t.closest(".ec-row") as HTMLElement | null;
    if (row) { if (!OPEN.size) OPEN.add("1"); void open(Number(row.dataset.id)); }
  });

  // expand/collapse domains
  $("ec-detail").addEventListener("click", (ev) => {
    const h = (ev.target as HTMLElement).closest(".dom-h") as HTMLElement | null;
    if (!h || SEL == null) return;
    const n = h.dataset.dom!;
    if (OPEN.has(n)) OPEN.delete(n); else OPEN.add(n);
    void open(SEL);
  });

  // status / owner / note changes + deliverable checkboxes
  const send = async (ref: string, patch: Record<string, unknown>): Promise<void> => {
    if (SEL == null) return;
    try { renderDetail(await post(`/api/nca-ecc/${SEL}/control`, { ref, ...patch })); }
    catch (e) { toast((e as Error).message); }
  };
  $("ec-detail").addEventListener("change", (ev) => {
    const t = ev.target as HTMLElement;
    const ref = t.dataset.ref;
    if (!ref) return;
    if (t.classList.contains("ec-st")) void send(ref, { status: (t as HTMLSelectElement).value });
    else if (t.classList.contains("ec-dv")) {
      const boxes = [...document.querySelectorAll(`.ec-dv[data-ref="${CSS.escape(ref)}"]`)] as HTMLInputElement[];
      const done = boxes.filter((b) => b.checked).map((b) => Number(b.dataset.i));
      void send(ref, { deliverablesDone: done });
    }
  });
  // owner/note commit on blur (Enter)
  $("ec-detail").addEventListener("focusout", (ev) => {
    const t = ev.target as HTMLElement;
    const ref = t.dataset.ref;
    if (!ref) return;
    if (t.classList.contains("ec-owner")) void send(ref, { owner: (t as HTMLInputElement).value });
    else if (t.classList.contains("ec-note")) void send(ref, { evidenceNote: (t as HTMLInputElement).value });
  });
});
