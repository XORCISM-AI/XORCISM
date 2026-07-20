/**
 * miniciso.ts — Evidence-driven security assessment cockpit (/miniciso).
 * Collect tiered evidence, classify outputs (finding/observation/hypothesis/missing-evidence),
 * run the Security-QA gate, get AI candidate suggestions, and synthesize an accountable report
 * (blocked while any finding is unreviewed).
 */
import { initI18n } from "./i18n";

interface Role { id: string; name: string; mission: string; kind: string }
interface Stage { key: string; name: string; detail: string }
interface Catalogue { roles: Role[]; stages: Stage[]; classes: string[]; gates: string[]; tiers: { key: string; name: string }[]; severities: string[] }
interface Evidence { id: number; title: string; tier: string; source: string; content: string }
interface Output {
  id: number; role: string; roleName: string; cls: string; title: string; detail: string; severity: string;
  confidence: number; residualRisk: string; gate: string; evidenceRefs: number[]; qaStatus: string; qaNote: string; source: string;
}
interface Assessment {
  id: number; name: string; objective: string; scope: string; boundaries: string; operator: string;
  stage: string; stageName: string; status: string; synthesis: string; evidence: number; outputs: number;
  findings: number; hypotheses: number; observations: number; missingEvidence: number; qaPassed: number; ready: boolean;
}
interface Readiness { ready: boolean; findings: number; qaPassed: number; blockers: { id: number; title: string; reason: string }[] }
interface Detail { assessment: Assessment; evidence: Evidence[]; outputs: Output[]; readiness: Readiness; stages: Stage[] }
interface Dash { assessments: Assessment[]; summary: Record<string, number> }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

let DASH: Dash | null = null;
let CAT: Catalogue | null = null;
let SEL: number | null = null;
let CUR: Detail | null = null;

const clsChip = (c: string): string => `<span class="mc-chip cl-${esc(c)}">${esc(c.replace("-", " "))}</span>`;

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(d.error || `Error ${r.status}`); (e as any).body = d; throw e; }
  return d;
}
const post = (url: string, body?: unknown): Promise<any> =>
  api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
const patch = (url: string, body: unknown): Promise<any> =>
  api(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function fillSelect(el: HTMLSelectElement, items: string[], label?: (s: string) => string): void {
  el.innerHTML = items.map((i) => `<option value="${esc(i)}">${esc(label ? label(i) : i)}</option>`).join("");
}

function renderDash(): void {
  if (!DASH) return;
  const s = DASH.summary;
  $("mc-cat").textContent = `${CAT?.roles.length ?? 9} roles · ${CAT?.stages.length ?? 9} stages`;
  $("mc-kpis").innerHTML = [
    ["Assessments", String(s.assessments)], ["Delivered", String(s.delivered)],
    ["Open findings", String(s.openFindings)], ["Ready to deliver", String(s.readyToDeliver)],
    ["Open hypotheses", String(s.hypotheses)],
  ].map(([l, v]) => `<div class="mc-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  $("mc-body").innerHTML = DASH.assessments.length ? DASH.assessments.map((a) => `
    <tr class="mc-row ${a.id === SEL ? "sel" : ""}" data-id="${a.id}">
      <td><b>${esc(a.name)}</b><div class="muted">${esc(a.scope || a.objective || "")}</div></td>
      <td>${esc(a.stageName)}</td>
      <td><span class="mc-chip cl-finding">${a.findings} F</span> <span class="mc-chip cl-observation">${a.observations} O</span>
          <span class="mc-chip cl-hypothesis">${a.hypotheses} H</span> <span class="mc-chip cl-missing-evidence">${a.missingEvidence} ME</span></td>
      <td>${a.status === "delivered" ? '<span class="mc-chip qa-passed">delivered</span>' : a.ready ? '<span class="mc-chip qa-passed">ready</span>' : '<span class="mc-chip qa-pending">blocked</span>'}</td>
      <td><button class="mc-btn ghost danger mc-del" data-id="${a.id}">Del</button></td>
    </tr>`).join("") : `<tr><td colspan="5" class="muted">No assessment yet — create one above to start an evidence-driven review.</td></tr>`;
}

function renderRoles(): void {
  if (!CAT) return;
  $("mc-roles").innerHTML = CAT.roles.map((r) => `<div class="mc-role"><div class="rn">${r.kind === "coordinator" ? "&#9733; " : ""}${esc(r.name)}</div><div class="rm">${esc(r.mission)}</div></div>`).join("");
}

function renderStages(a: Assessment): void {
  if (!CAT) return;
  const curIdx = CAT.stages.findIndex((s) => s.key === a.stage);
  $("mc-d-stages").innerHTML = CAT.stages.map((s, i) =>
    `<span class="mc-stage ${i < curIdx ? "done" : i === curIdx ? "cur" : ""}" data-stage="${esc(s.key)}" title="${esc(s.detail)}">${i + 1}. ${esc(s.name)}</span>`).join("");
}

function evidenceLabel(refs: number[], evidence: Evidence[]): string {
  if (!refs.length) return '<span class="muted">no evidence</span>';
  return refs.map((id) => { const e = evidence.find((x) => x.id === id); return e ? `<span class="mc-chip tier-${esc(e.tier)}" title="${esc(e.tier)}">&#128206; ${esc(e.title)}</span>` : ""; }).join(" ");
}

function renderDetail(d: Detail): void {
  CUR = d; SEL = d.assessment.id;
  $("mc-detail").style.display = "";
  const a = d.assessment;
  $("mc-d-title").innerHTML = `&#129302; ${esc(a.name)} <span class="muted">— ${esc(a.stageName)}</span>`;
  $("mc-d-meta").innerHTML = `Objective: ${esc(a.objective || "—")} · Scope: ${esc(a.scope || "—")}${a.operator ? " · Operator: " + esc(a.operator) : ""}`;
  renderStages(a);
  $("mc-d-nev").textContent = `(${d.evidence.length})`;
  $("mc-d-nout").textContent = `(${d.outputs.length})`;

  $("mc-evidence").innerHTML = d.evidence.length ? d.evidence.map((e) => `
    <div class="mc-ev"><span class="et">${esc(e.title)}</span> <span class="mc-chip tier-${esc(e.tier)}">${esc(e.tier)}</span>
      <button class="mc-btn ghost danger mc-ev-del" data-id="${e.id}" style="float:right">×</button>
      ${e.source ? `<div class="muted">${esc(e.source)}</div>` : ""}
      ${e.content ? `<div style="color:#94a3b8;margin-top:3px">${esc(e.content)}</div>` : ""}</div>`).join("")
    : '<div class="muted">No evidence yet. Evidence comes first — outputs reference it.</div>';

  $("mc-outputs").innerHTML = d.outputs.length ? d.outputs.map((o) => `
    <div class="mc-out">
      <div class="oh">${clsChip(o.cls)} <span class="ot">${esc(o.title)}</span>
        <span class="mc-chip sev-${esc(o.severity)}" style="margin-left:auto">${esc(o.severity)}</span></div>
      <div class="muted">${esc(o.roleName)} · confidence ${o.confidence}% · gate <span class="gate-${esc(o.gate)}">${esc(o.gate.toUpperCase())}</span>
        · QA <span class="mc-chip qa-${esc(o.qaStatus)}">${esc(o.qaStatus)}</span>${o.source ? " · " + esc(o.source) : ""}</div>
      ${o.detail ? `<div class="om">${esc(o.detail)}</div>` : ""}
      ${o.residualRisk ? `<div class="om"><b style="color:#fca5a5">Residual risk:</b> ${esc(o.residualRisk)}</div>` : ""}
      <div>${evidenceLabel(o.evidenceRefs, d.evidence)}</div>
      <div class="orow">
        <select class="mc-o-cls" data-id="${o.id}">${(CAT?.classes || []).map((c) => `<option value="${c}" ${c === o.cls ? "selected" : ""}>${c.replace("-", " ")}</option>`).join("")}</select>
        <select class="mc-o-link" data-id="${o.id}" multiple size="1" title="link evidence" style="min-width:130px">${d.evidence.map((e) => `<option value="${e.id}" ${o.evidenceRefs.includes(e.id) ? "selected" : ""}>${esc(e.title)}</option>`).join("")}</select>
        <button class="mc-btn ghost mc-qa" data-id="${o.id}" data-s="passed" title="Security QA pass">QA pass</button>
        <button class="mc-btn ghost mc-qa" data-id="${o.id}" data-s="rejected" title="Security QA reject">reject</button>
        <button class="mc-btn ghost danger mc-o-del" data-id="${o.id}">del</button>
      </div>
    </div>`).join("") : '<div class="muted">No outputs yet. Add a hypothesis, or use “AI: suggest candidates”.</div>';

  // readiness gate
  const rd = d.readiness;
  $("mc-readiness").innerHTML = rd.ready
    ? `<div class="mc-gate-box mc-ready">&#9989; <b>Ready to deliver.</b> ${rd.findings} finding(s), all QA-passed and evidence-backed.</div>`
    : `<div class="mc-gate-box">${rd.findings === 0 ? "No findings yet — a report needs at least one QA-passed, evidence-backed finding." : `<b>Delivery blocked.</b> ${rd.qaPassed}/${rd.findings} findings cleared QA.`}
        ${rd.blockers.length ? rd.blockers.map((b) => `<div class="mc-block">&#9888; <b>${esc(b.title)}</b> — ${esc(b.reason)}</div>`).join("") : ""}</div>`;
  $("mc-synthesis").innerHTML = a.synthesis ? `<pre class="mc-syn">${esc(a.synthesis)}</pre>` : "";
}

async function load(): Promise<void> {
  try {
    if (!CAT) {
      CAT = await api("/api/miniciso/catalogue");
      renderRoles();
      fillSelect($("mc-out-role") as HTMLSelectElement, CAT.roles.filter((r) => r.kind === "specialist").map((r) => r.id), (id) => CAT!.roles.find((r) => r.id === id)!.name);
      fillSelect($("mc-out-cls") as HTMLSelectElement, CAT.classes, (c) => c.replace("-", " "));
      fillSelect($("mc-out-sev") as HTMLSelectElement, CAT.severities);
      fillSelect($("mc-out-gate") as HTMLSelectElement, CAT.gates, (g) => g.toUpperCase());
    }
    DASH = await api("/api/miniciso"); renderDash();
  } catch (e) { toast((e as Error).message); }
}
async function open(id: number): Promise<void> {
  try { renderDetail(await api(`/api/miniciso/${id}`)); renderDash(); }
  catch (e) { toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("mc-add").addEventListener("click", async () => {
    const body = {
      name: ($("mc-name") as HTMLInputElement).value.trim(),
      objective: ($("mc-obj") as HTMLInputElement).value.trim(),
      scope: ($("mc-scope") as HTMLInputElement).value.trim(),
      operator: ($("mc-operator") as HTMLInputElement).value.trim(),
    };
    if (!body.name) { toast("assessment name required"); return; }
    try {
      const r = await post("/api/miniciso", body);
      (["mc-name", "mc-obj", "mc-scope", "mc-operator"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
      $("mc-msg").textContent = `created #${r.id}`;
      await load(); await open(r.id);
      $("mc-detail").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast((e as Error).message); }
  });

  $("mc-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".mc-del") as HTMLElement | null;
    if (del) {
      ev.stopPropagation();
      if (!confirm("Delete this assessment, its evidence and outputs?")) return;
      try { await api(`/api/miniciso/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("mc-detail").style.display = "none"; await load(); }
      catch (e) { toast((e as Error).message); }
      return;
    }
    const row = t.closest(".mc-row") as HTMLElement | null;
    if (row) void open(Number(row.dataset.id));
  });

  // stage advance
  $("mc-d-stages").addEventListener("click", async (ev) => {
    const s = (ev.target as HTMLElement).closest(".mc-stage") as HTMLElement | null;
    if (!s || SEL == null) return;
    try { renderDetail(await patch(`/api/miniciso/${SEL}`, { stage: s.dataset.stage, status: "in-progress" })); }
    catch (e) { toast((e as Error).message); }
  });

  $("mc-ev-add").addEventListener("click", async () => {
    if (SEL == null) return;
    const body = {
      title: ($("mc-ev-title") as HTMLInputElement).value.trim(),
      tier: ($("mc-ev-tier") as HTMLSelectElement).value,
      source: ($("mc-ev-source") as HTMLInputElement).value.trim(),
      content: ($("mc-ev-content") as HTMLInputElement).value.trim(),
    };
    if (!body.title) { toast("evidence title required"); return; }
    try {
      renderDetail(await post(`/api/miniciso/${SEL}/evidence`, body));
      (["mc-ev-title", "mc-ev-source", "mc-ev-content"]).forEach((i) => (($(i) as HTMLInputElement).value = ""));
    } catch (e) { toast((e as Error).message); }
  });

  $("mc-evidence").addEventListener("click", async (ev) => {
    const b = (ev.target as HTMLElement).closest(".mc-ev-del") as HTMLElement | null;
    if (!b || SEL == null) return;
    try { renderDetail(await api(`/api/miniciso/${SEL}/evidence/${b.dataset.id}`, { method: "DELETE" })); }
    catch (e) { toast((e as Error).message); }
  });

  $("mc-out-add").addEventListener("click", async () => {
    if (SEL == null) return;
    const body = {
      role: ($("mc-out-role") as HTMLSelectElement).value,
      cls: ($("mc-out-cls") as HTMLSelectElement).value,
      title: ($("mc-out-title") as HTMLInputElement).value.trim(),
      detail: ($("mc-out-detail") as HTMLTextAreaElement).value.trim(),
      severity: ($("mc-out-sev") as HTMLSelectElement).value,
      gate: ($("mc-out-gate") as HTMLSelectElement).value,
    };
    if (!body.title) { toast("output title required"); return; }
    try {
      renderDetail(await post(`/api/miniciso/${SEL}/output`, body));
      ($("mc-out-title") as HTMLInputElement).value = ""; ($("mc-out-detail") as HTMLTextAreaElement).value = "";
    } catch (e) { toast((e as Error).message); }
  });

  // output row actions (reclassify, link evidence, QA, delete)
  $("mc-outputs").addEventListener("change", async (ev) => {
    const t = ev.target as HTMLElement;
    if (SEL == null) return;
    if (t.classList.contains("mc-o-cls")) {
      try { renderDetail(await patch(`/api/miniciso/${SEL}/output/${(t as HTMLElement).dataset.id}`, { cls: (t as HTMLSelectElement).value })); }
      catch (e) { toast((e as Error).message); }
    } else if (t.classList.contains("mc-o-link")) {
      const refs = [...(t as HTMLSelectElement).selectedOptions].map((o) => Number(o.value));
      try { renderDetail(await patch(`/api/miniciso/${SEL}/output/${(t as HTMLElement).dataset.id}`, { evidenceRefs: refs })); }
      catch (e) { toast((e as Error).message); }
    }
  });
  $("mc-outputs").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    if (SEL == null) return;
    const qa = t.closest(".mc-qa") as HTMLElement | null;
    if (qa) { try { renderDetail(await post(`/api/miniciso/${SEL}/output/${qa.dataset.id}/qa`, { status: qa.dataset.s })); } catch (e) { toast((e as Error).message); } return; }
    const del = t.closest(".mc-o-del") as HTMLElement | null;
    if (del) { try { renderDetail(await api(`/api/miniciso/${SEL}/output/${del.dataset.id}`, { method: "DELETE" })); } catch (e) { toast((e as Error).message); } }
  });

  $("mc-suggest").addEventListener("click", async () => {
    if (SEL == null) return;
    $("mc-suggest-msg").textContent = "analysing evidence…";
    try {
      const r = await post(`/api/miniciso/${SEL}/suggest`, { adopt: true });
      $("mc-suggest-msg").textContent = `${r.added || 0} candidate hypothesis/hypotheses added (via ${r.via})`;
      if (r.detail) renderDetail(r.detail as Detail);
    } catch (e) { $("mc-suggest-msg").textContent = ""; toast((e as Error).message); }
  });

  $("mc-synth").addEventListener("click", async () => {
    if (SEL == null) return;
    try {
      const r = await post(`/api/miniciso/${SEL}/synthesize`);
      if (r.detail) renderDetail(r.detail as Detail);
      toast("Synthesis delivered.");
      await load();
    } catch (e) {
      const body = (e as any).body;
      if (body && body.blocked) { toast("Delivery blocked — clear the QA gate on all findings first."); if (CUR) renderDetail(CUR); }
      else toast((e as Error).message);
    }
  });
});
