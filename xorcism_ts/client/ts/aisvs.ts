/**
 * aisvs.ts — OWASP AISVS verification-assessment cockpit (/aisvs).
 * Pick a target level, answer the 203 controls on the AISVS maturity scale with evidence, and read
 * back the weighted verification score per part + overall, gaps and EU AI Act coverage.
 */
import { initI18n } from "./i18n";

interface Answer { key: string; label: string; eff: number }
interface Cat { version: string; source: string; levels: string[]; answers: Answer[]; parts: { num: number; name: string; total: number }[] }
interface Assessment { id: number; name: string; systemName: string; targetLevel: string; assessor: string; status: string; verification: number; scope: number; answered: number; gaps: number }
interface Dash { assessments: Assessment[]; summary: Record<string, number>; catalogue: { version: string; parts: number; controls: number; questions: number } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

let DASH: Dash | null = null;
let CAT: Cat | null = null;
let SEL: number | null = null;
const OPEN = new Set<number>();

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}
const post = (url: string, b?: unknown): Promise<any> => api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
const patch = (url: string, b: unknown): Promise<any> => api(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });

const vColor = (v: number): string => (v >= 80 ? "#4ade80" : v >= 50 ? "#fbbf24" : "#f87171");

function renderDash(): void {
  if (!DASH) return;
  const s = DASH.summary, c = DASH.catalogue;
  $("av-ver").textContent = `— ${c.version}`;
  $("av-cat").textContent = `${c.parts} parts · ${c.controls} controls · ${c.questions} questions`;
  $("av-kpis").innerHTML = [
    ["Assessments", String(s.assessments)], ["Completed", String(s.completed)],
    ["Avg verification", `${s.avgVerification}%`], ["L3 targets", String(s.l3)], ["Open gaps", String(s.openGaps)],
  ].map(([l, v]) => `<div class="av-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  $("av-body").innerHTML = DASH.assessments.length ? DASH.assessments.map((a) => `
    <tr class="av-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.systemName)}${a.assessor ? " · " + esc(a.assessor) : ""}</div></td>
      <td><span class="av-chip lv-${esc(a.targetLevel)}">${esc(a.targetLevel)}</span></td>
      <td><b style="color:${vColor(a.verification)}">${a.verification}%</b> <span class="av-bar"><span style="width:${a.verification}%"></span></span></td>
      <td><span class="muted">${a.answered}/${a.scope}</span></td>
      <td>${a.gaps ? `<span class="av-chip av-ans-not">${a.gaps}</span>` : "—"}</td>
      <td><button class="av-btn ghost danger av-del" data-id="${a.id}">Del</button></td>
    </tr>`).join("") : `<tr><td colspan="6" class="muted">No AISVS assessment yet — create one to start the AI security verification.</td></tr>`;
}

const ansLabel = (k: string): string => CAT?.answers.find((a) => a.key === k)?.label ?? k;

function renderDetail(d: any): void {
  SEL = d.assessment.id;
  $("av-detail").style.display = "";
  const a = d.assessment, sc = d.score;
  $("av-d-title").innerHTML = `&#129302; ${esc(a.name)} <span class="muted">— ${esc(a.systemName)} · target ${esc(a.targetLevel)}</span>`;
  $("av-d-score").textContent = `${sc.verification}%`;
  ($("av-d-score") as HTMLElement).style.color = vColor(sc.verification);
  ($("av-d-level") as HTMLSelectElement).value = a.targetLevel;
  $("av-d-scope").textContent = `${sc.answered}/${sc.scope} controls answered · ${sc.gaps} gaps · ${sc.naCount} n/a`;
  $("av-d-aiact").innerHTML = `<span class="av-map av-ai">EU AI Act</span> ${sc.aiActInScope} of ${sc.scope} in-scope controls carry an EU AI Act mapping`;

  const order = ["fully", "largely", "partial", "planned", "not", "na"];
  const maxd = Math.max(1, ...order.map((k) => sc.distribution[k] || 0));
  $("av-d-dist").innerHTML = order.map((k) => `<div class="bar" style="height:${Math.round(((sc.distribution[k] || 0) / maxd) * 100)}%" title="${esc(ansLabel(k))}: ${sc.distribution[k] || 0}"><b>${sc.distribution[k] || ""}</b><i>${k === "partial" ? "part" : k === "largely" ? "larg" : k}</i></div>`).join("");

  $("av-partscores").innerHTML = sc.parts.map((p: any) => `
    <tr><td style="width:56%"><b>Part ${p.num}</b> ${esc(p.name)}<div class="muted">${p.fully}/${p.scope} fully · ${p.gaps} gaps</div></td>
      <td><span class="av-bar"><span style="width:${p.verification}%"></span></span></td>
      <td style="width:48px;text-align:right"><b style="color:${vColor(p.verification)}">${p.verification}%</b></td></tr>`).join("");

  $("av-parts").innerHTML = d.parts.map((p: any) => {
    const open = OPEN.has(p.num);
    const ctrls = open ? p.controls.map((c: any) => `
      <div class="av-ctrl">
        <div><span class="cref">${esc(c.ref)}</span>${c.levels.map((l: string) => `<span class="av-chip lv-${esc(l)}">${esc(l)}</span>`).join(" ")}
          <span class="av-w">w${c.weight}</span> <b style="color:#e2e8f0;font-size:12.5px">${esc(c.title)}</b></div>
        <div class="creq">${esc(c.requirement)}</div>
        <div class="cq">❝ ${esc(c.question)} ❞</div>
        ${c.evidence.length ? `<div class="cev"><b>Evidence:</b> ${c.evidence.map((e: string) => esc(e)).join(" · ")}</div>` : ""}
        <div style="margin-top:3px">${[c.iso27001 && `ISO 27001: ${c.iso27001}`, c.nistCsf && `NIST CSF: ${c.nistCsf}`, c.nis2 && `NIS2: ${c.nis2}`].filter(Boolean).map((m) => `<span class="av-map">${esc(m as string)}</span>`).join("")}${c.aiAct ? `<span class="av-map av-ai">EU AI Act ${esc(c.aiAct)}</span>` : ""}</div>
        <div class="crow">
          <select class="av-ans" data-ref="${esc(c.ref)}">
            <option value="">— answer —</option>
            ${(CAT?.answers || []).map((x) => `<option value="${x.key}" ${c.answer === x.key ? "selected" : ""}>${esc(x.label)}</option>`).join("")}
          </select>
          <input class="av-ev" data-ref="${esc(c.ref)}" value="${esc(c.evidenceNote)}" placeholder="evidence reference / note…" style="flex:1;min-width:200px">
          ${c.answer ? `<span class="av-chip av-ans-${esc(c.answer)}">${esc(ansLabel(c.answer))}</span>` : ""}
        </div>
      </div>`).join("") : "";
    return `<div class="av-part"><div class="av-part-h" data-part="${p.num}">
        <span class="pn">${open ? "▾" : "▸"} Part ${p.num} — ${esc(p.name)}</span>
        <span class="pv">${p.verification}% <span class="muted" style="font-weight:400">(${p.controls.length})</span></span></div>${ctrls}</div>`;
  }).join("");
}

async function load(): Promise<void> {
  try {
    if (!CAT) CAT = await api("/api/aisvs/catalogue");
    DASH = await api("/api/aisvs"); renderDash();
  } catch (e) { toast((e as Error).message); }
}
async function open(id: number): Promise<void> {
  try { renderDetail(await api(`/api/aisvs/${id}`)); renderDash(); }
  catch (e) { toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("av-add").addEventListener("click", async () => {
    const body = {
      name: ($("av-name") as HTMLInputElement).value.trim(),
      systemName: ($("av-sys") as HTMLInputElement).value.trim(),
      targetLevel: ($("av-level") as HTMLSelectElement).value,
      assessor: ($("av-assessor") as HTMLInputElement).value.trim(),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/aisvs", body);
      (["av-name", "av-sys", "av-assessor"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      $("av-msg").textContent = `created #${r.id}`;
      OPEN.clear(); await load(); await open(r.id);
      $("av-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("av-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".av-del") as HTMLElement | null;
    if (del) {
      ev.stopPropagation();
      if (!confirm("Delete this AISVS assessment and its answers?")) return;
      try { await api(`/api/aisvs/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("av-detail").style.display = "none"; await load(); }
      catch (e) { toast((e as Error).message); }
      return;
    }
    const row = t.closest(".av-row") as HTMLElement | null;
    if (row) { OPEN.clear(); void open(Number(row.dataset.id)); }
  });

  // target level change
  $("av-d-level").addEventListener("change", async (ev) => {
    if (SEL == null) return;
    try { renderDetail(await patch(`/api/aisvs/${SEL}`, { targetLevel: (ev.target as HTMLSelectElement).value })); await load(); }
    catch (e) { toast((e as Error).message); }
  });

  // expand/collapse parts
  $("av-parts").addEventListener("click", (ev) => {
    const h = (ev.target as HTMLElement).closest(".av-part-h") as HTMLElement | null;
    if (!h || SEL == null) return;
    const n = Number(h.dataset.part);
    if (OPEN.has(n)) OPEN.delete(n); else OPEN.add(n);
    void open(SEL);
  });

  // answer / evidence
  $("av-parts").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement;
    if (SEL == null) return;
    const ref = (t as HTMLElement).dataset.ref;
    if (!ref) return;
    const row = t.closest(".av-ctrl")!;
    const ans = (row.querySelector(".av-ans") as HTMLSelectElement).value;
    const evd = (row.querySelector(".av-ev") as HTMLInputElement).value;
    try { renderDetail(await post(`/api/aisvs/${SEL}/answer`, { ref, answer: ans, evidence: evd })); }
    catch (e) { toast((e as Error).message); }
  });
});
