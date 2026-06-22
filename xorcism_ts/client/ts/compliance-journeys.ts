/** compliance-journeys.ts — Guided compliance-journey wizard (/compliance-journeys). Framework
 * catalogue → start wizard → phased checklist with deep-links into the modules that do the work,
 * progress tracking to certification. Reads /api/compliance-journeys. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Fw { key: string; name: string; provider: string; kind: string; jurisdiction: string; summary: string; effort: string; phases: number; steps: number; }
interface Jr { id: number; framework: string; frameworkName: string; kind: string; name: string; scope: string; owner: string; status: string; startedDate: string; targetDate: string; total: number; done: number; na: number; inProgress: number; pct: number; assessmentId: number | null; }
interface Step { id: number; title: string; description: string; link: string | null; status: string; notes: string; }
interface Phase { order: number; name: string; steps: Step[]; done: number; total: number; pct: number; }
interface Detail { journey: any; phases: Phase[]; progress: { pct: number; done: number; total: number; na: number } }
interface Data { frameworks: Fw[]; journeys: Jr[]; summary: any }

let DATA: Data | null = null;
let pendingFw: Fw | null = null;

const kcls = (k: string): string => `k-${["Certification", "Attestation", "Regulation", "Framework", "Authorization"].includes(k) ? k : "Framework"}`;
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="cj-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pbar = (pct: number): string => `<div class="pbar"><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></div>`;

function fwCard(f: Fw): string {
  return `<div class="fw" data-fw="${esc(f.key)}">
    <div class="top"><span class="nm">${esc(f.name)}</span><span class="kind ${kcls(f.kind)}">${esc(f.kind)}</span></div>
    <div class="desc">${esc(f.summary)}</div>
    <div class="meta"><span>📍 ${esc(f.jurisdiction)}</span><span>🗂 ${f.phases} phases · ${f.steps} steps</span><span>⏱ ${esc(f.effort)}</span></div>
    <button class="start" data-fw="${esc(f.key)}">Start journey →</button>
  </div>`;
}

function journeyRow(j: Jr): string {
  return `<div class="jr" data-id="${j.id}">
    <div class="row1">
      <span class="jn">${esc(j.name)}</span>
      <span class="kind ${kcls(j.kind)}">${esc(j.frameworkName)}</span>
      <span class="spacer" style="flex:1"></span>
      ${pbar(j.pct)}<span class="pct">${j.pct}%</span>
    </div>
    <div class="meta">
      <span>${j.done}/${j.total - j.na} steps done${j.na ? ` · ${j.na} N/A` : ""}</span>
      ${j.owner ? `<span>👤 ${esc(j.owner)}</span>` : ""}
      ${j.scope ? `<span>🎯 ${esc(j.scope.length > 50 ? j.scope.slice(0, 50) + "…" : j.scope)}</span>` : ""}
      ${j.targetDate ? `<span>🎓 target ${esc(j.targetDate)}</span>` : ""}
      ${j.startedDate ? `<span>started ${esc(j.startedDate)}</span>` : ""}
    </div>
  </div>`;
}

function renderOverview(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card("Journeys", String(s.journeys), `${s.inFlight} in flight`),
    card("Avg progress", `${s.avgProgress}%`, "across active journeys", s.avgProgress >= 80 ? "#4ade80" : s.avgProgress >= 40 ? "#fbbf24" : undefined),
    card("Completed", String(s.completed), "reached 100%", s.completed ? "#4ade80" : undefined),
    card("Frameworks", String(s.frameworksAvailable), "ready-to-start journeys", "#60a5fa"),
  ].join("");
  const myJourneys = d.journeys.length
    ? d.journeys.map(journeyRow).join("")
    : `<div class="muted" style="padding:10px 0">No journeys yet — pick a framework below to start your first guided journey.</div>`;
  const cat = d.frameworks.map(fwCard).join("");
  $("cj-body").innerHTML = `<div class="cj-cards">${cards}</div>
    <div class="cj-section">My journeys (${d.journeys.length})</div>${myJourneys}
    <div class="cj-section">Start a new journey — pick a framework</div><div class="fw-grid">${cat}</div>`;
  Array.prototype.forEach.call(document.querySelectorAll(".fw"), (el: HTMLElement) => {
    el.onclick = () => { const k = el.getAttribute("data-fw")!; openWizard(d.frameworks.find((f) => f.key === k)!); };
  });
  Array.prototype.forEach.call(document.querySelectorAll(".jr"), (el: HTMLElement) => {
    el.onclick = () => openJourney(Number(el.getAttribute("data-id")));
  });
}

function openWizard(f: Fw): void {
  pendingFw = f;
  $("cj-dlg-title").textContent = `Start: ${f.name}`;
  $("cj-dlg-fw").innerHTML = `<span class="kind ${kcls(f.kind)}">${esc(f.kind)}</span> · ${esc(f.provider)} · ${f.phases} phases · ${f.steps} steps · ⏱ ${esc(f.effort)}`;
  ($("cj-name") as HTMLInputElement).value = `${f.name} compliance journey`;
  ($("cj-scope") as HTMLInputElement).value = "";
  ($("cj-owner") as HTMLInputElement).value = "";
  ($("cj-target") as HTMLInputElement).value = "";
  ($("cj-spawn") as HTMLInputElement).checked = true;
  $("cj-modal").classList.add("show");
}
function closeWizard(): void { $("cj-modal").classList.remove("show"); pendingFw = null; }

function createJourney(): void {
  if (!pendingFw) return;
  const body = {
    framework: pendingFw.key,
    name: ($("cj-name") as HTMLInputElement).value.trim() || undefined,
    scope: ($("cj-scope") as HTMLInputElement).value.trim() || undefined,
    owner: ($("cj-owner") as HTMLInputElement).value.trim() || undefined,
    targetDate: ($("cj-target") as HTMLInputElement).value || undefined,
    spawnAssessment: ($("cj-spawn") as HTMLInputElement).checked,
  };
  const btn = $("cj-create") as HTMLButtonElement; btn.disabled = true;
  fetch("/api/compliance-journeys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j) => { closeWizard(); toast("Journey started"); openJourney(j.id); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

const STATUS_OPTS = [["todo", "To do"], ["in_progress", "In progress"], ["done", "Done"], ["na", "N/A"]];

function stepHtml(s: Step): string {
  const opts = STATUS_OPTS.map(([v, l]) => `<option value="${v}"${s.status === v ? " selected" : ""}>${l}</option>`).join("");
  return `<div class="step st-${esc(s.status)}" data-step="${s.id}">
    <div class="st-main">
      <div class="st-title ${s.status === "done" ? "done" : ""}">${esc(s.title)}</div>
      <div class="st-desc">${esc(s.description)}</div>
    </div>
    <div class="st-actions">
      ${s.link ? `<a class="go" href="${esc(s.link)}" target="_blank" rel="noopener noreferrer">Open ↗</a>` : ""}
      <select class="st-status" data-step="${s.id}">${opts}</select>
    </div>
  </div>`;
}

function phaseHtml(p: Phase): string {
  return `<div class="phase">
    <div class="ph-head"><span class="ph-num">${p.order}</span><span class="ph-name">${esc(p.name)}</span>
      <span class="spacer" style="flex:1"></span>${pbar(p.pct)}<span class="pct">${p.pct}%</span></div>
    ${p.steps.map(stepHtml).join("")}
  </div>`;
}

function openJourney(id: number): void {
  $("cj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Loading journey…</div>`;
  fetch("/api/compliance-journeys/item/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Detail) => {
    const j = d.journey; const pr = d.progress;
    const cards = [
      card("Progress", `${pr.pct}%`, `${pr.done}/${pr.total - pr.na} steps`, pr.pct >= 80 ? "#4ade80" : pr.pct >= 40 ? "#fbbf24" : undefined),
      card("Phases", String(d.phases.length), "guided stages"),
      card("Owner", j.owner || "—", "accountable"),
      card("Target", j.targetDate || "—", "certification date"),
    ].join("");
    $("cj-body").innerHTML = `
      <div class="cj-section"><button class="btn-sm2" id="cj-back">← All journeys</button><span class="spacer" style="flex:1"></span>
        <button class="btn-sm2" id="cj-del" style="border-color:#7f1d1d;color:#fca5a5">Delete</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(j.name)} <span class="kind ${kcls(j.kind)}">${esc(j.frameworkName)}</span></h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:14px;max-width:900px">${esc(j.summary)}${j.scope ? ` &nbsp;·&nbsp; <b style="color:#94a3b8">Scope:</b> ${esc(j.scope)}` : ""}${j.assessmentId ? ` &nbsp;·&nbsp; <a href="/?db=XCOMPLIANCE&table=COMPLIANCEASSESSMENT" style="color:#7c83fd">linked assessment #${j.assessmentId} ↗</a>` : ""}</div>
      <div class="cj-cards">${cards}</div>
      <div style="margin-top:6px">${d.phases.map(phaseHtml).join("")}</div>`;
    $("cj-back").onclick = () => renderOverview();
    $("cj-del").onclick = () => {
      if (!confirm("Delete this journey and all its steps?")) return;
      fetch("/api/compliance-journeys/item/" + id, { method: "DELETE" }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(() => reload().then(renderOverview)).then(() => toast("Journey deleted")).catch((e) => toast("⚠️ " + (e.message || e)));
    };
    Array.prototype.forEach.call(document.querySelectorAll(".st-status"), (sel: HTMLSelectElement) => {
      sel.onchange = () => setStatus(id, Number(sel.getAttribute("data-step")), sel.value);
    });
  }).catch((e) => { $("cj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function setStatus(journeyId: number, stepId: number, status: string): void {
  fetch("/api/compliance-journeys/step/" + stepId, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => openJourney(journeyId))
    .catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/compliance-journeys").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  $("cj-cancel").onclick = closeWizard;
  $("cj-create").onclick = createJourney;
  $("cj-modal").addEventListener("click", (e) => { if (e.target === $("cj-modal")) closeWizard(); });
  reload().then(renderOverview).catch((e) => { $("cj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
