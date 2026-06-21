/**
 * nist-800-30.ts — NIST SP 800-30 risk-assessment cockpit (/nist-800-30). Dashboard of 800-30
 * assessments (threat sources / events / vulnerabilities / risks + risk distribution) and a
 * guided "New assessment" modal, from /api/nist-800-30. The 800-30 counterpart of /ebios.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Assessment {
  id: number; name: string; description: string | null; status: string; date: string | null;
  counts: { threatSources: number; threatEvents: number; vulnerabilities: number; risks: number };
  byLevel: Record<string, number>; maxRisk: number;
}
interface Dashboard {
  assessments: Assessment[];
  stats: { total: number; threatSources: number; threatEvents: number; vulnerabilities: number; risks: number; highRisks: number };
}

// 800-30 semi-quantitative scale 1..5.
const LVL = ["", "Very Low", "Low", "Moderate", "High", "Very High"];
const stClass = (s: string): string => (/complet|done|clos/i.test(s) ? "st-done" : /progress|review|scoping/i.test(s) ? "st-prog" : "st-draft");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="n3-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function riskBadge(level: number): string {
  return level ? `<span class="rl rl${level}">${esc(LVL[level])}</span>` : `<span class="muted">—</span>`;
}

function rowHtml(a: Assessment): string {
  const c = a.counts;
  return `<tr>
    <td><div class="aname">${esc(a.name)}</div><div class="muted" style="font-size:11px">${a.date ? esc(a.date) : ""}</div></td>
    <td><span class="st ${stClass(a.status)}">${esc(a.status || "Draft")}</span></td>
    <td><span class="chip">${c.threatSources} sources</span><span class="chip">${c.threatEvents} events</span><span class="chip">${c.vulnerabilities} vulns</span></td>
    <td>${c.risks}</td>
    <td>${riskBadge(a.maxRisk)}</td>
    <td><a class="chip" href="/?db=XCOMPLIANCE&table=NIST80030RISK&filterCol=RiskAssessmentID&filterVal=${a.id}">risks ↗</a>
        <a class="chip" href="/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${a.id}">edit ↗</a></td>
  </tr>`;
}

// The NIST SP 800-30 Rev.1 Table I-2 risk matrix (overall likelihood rows × impact cols).
const MATRIX: Record<number, number[]> = {
  5: [1, 2, 3, 4, 5], 4: [1, 2, 3, 4, 5], 3: [1, 2, 3, 3, 4], 2: [1, 2, 2, 2, 3], 1: [1, 1, 1, 2, 2],
};
function matrixHtml(): string {
  const ab = ["", "VL", "L", "M", "H", "VH"];
  let rows = "";
  for (let l = 5; l >= 1; l--) {
    let tds = `<th>${ab[l]}</th>`;
    for (let i = 1; i <= 5; i++) { const r = MATRIX[l][i - 1]; tds += `<td class="rl rl${r}" style="border-radius:0">${ab[r]}</td>`; }
    rows += `<tr>${tds}</tr>`;
  }
  return `<table class="mx"><caption>Level of risk = overall likelihood (rows) × level of impact (columns) — Table&nbsp;I-2</caption>
    <tr><th>L \\ I</th><th>VL</th><th>L</th><th>M</th><th>H</th><th>VH</th></tr>${rows}</table>`;
}

function referenceHtml(): string {
  return `<div class="ref">
    <div class="col"><h4>Process (800-30 §3)</h4><ul>
      <li><b>1. Prepare</b> — purpose, scope, assumptions, threat sources of concern.</li>
      <li><b>2. Conduct</b> — identify threat sources &amp; events, vulnerabilities/predisposing conditions, determine likelihood &amp; impact, determine risk.</li>
      <li><b>3. Communicate</b> — share results &amp; the risk register.</li>
      <li><b>4. Maintain</b> — monitor risk factors over time.</li></ul></div>
    <div class="col"><h4>Threat sources (App.&nbsp;D)</h4><ul>
      <li><b>Adversarial</b> — individual / group / organization / nation-state, rated by <b>capability</b>, <b>intent</b>, <b>targeting</b>.</li>
      <li><b>Non-adversarial</b> — accidental, structural, environmental, rated by <b>range of effects</b>.</li></ul></div>
    <div class="col"><h4>Scales (App.&nbsp;I) &amp; risk matrix</h4>
      <ul><li>All factors use <b>Very Low → Very High</b> (1–5): likelihood of <i>initiation</i> &amp; of <i>impact</i> → <b>overall likelihood</b>; <b>impact</b> magnitude.</li></ul>
      ${matrixHtml()}</div>
  </div>`;
}

async function load(): Promise<void> {
  let d: Dashboard;
  try { const r = await fetch("/api/nist-800-30/dashboard"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("n3-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.stats;

  const cards = [
    card("Assessments", String(s.total), "NIST SP 800-30"),
    card("Threat sources", String(s.threatSources), "adversarial + non-adversarial"),
    card("Threat events", String(s.threatEvents), "initiated by sources"),
    card("Vulnerabilities", String(s.vulnerabilities), "+ predisposing conditions"),
    card("Risks", String(s.risks), "likelihood × impact"),
    card("High / Very High", String(s.highRisks), "risks at level ≥ High", s.highRisks ? "#f87171" : "#34d399"),
  ].join("");

  const table = d.assessments.length
    ? `<table class="n3"><thead><tr><th>Assessment</th><th>Status</th><th>Inventory</th><th>Risks</th><th>Max risk</th><th></th></tr></thead>
        <tbody>${d.assessments.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:18px 0">No 800-30 assessment yet. Click <b>+ New assessment</b> to create one, then add its
        <a href="/?db=XCOMPLIANCE&table=NIST80030THREATSOURCE">threat sources</a>,
        <a href="/?db=XCOMPLIANCE&table=NIST80030THREATEVENT">threat events</a>,
        <a href="/?db=XCOMPLIANCE&table=NIST80030VULNERABILITY">vulnerabilities</a> and
        <a href="/?db=XCOMPLIANCE&table=NIST80030RISK">risks</a>.</div>`;

  $("n3-body").innerHTML = `<div class="n3-cards">${cards}</div>
    <div class="n3-section">Assessments (${d.assessments.length})</div>${table}
    <div class="n3-section">NIST SP 800-30 reference</div>${referenceHtml()}
    <div class="legend">↳ Risk levels: <span class="rl rl1">Very Low</span> <span class="rl rl2">Low</span>
      <span class="rl rl3">Moderate</span> <span class="rl rl4">High</span> <span class="rl rl5">Very High</span>.
      Entities are managed in the explorer (NIST80030THREATSOURCE / THREATEVENT / VULNERABILITY / RISK).</div>`;
}

// ── Guided "new assessment" modal ──────────────────────────────────────────────
async function loadAuthors(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const sel = $("n3-f-author") as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; sel.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

function openModal(): void {
  for (const id of ["n3-f-name", "n3-f-desc"]) (document.getElementById(id) as HTMLInputElement).value = "";
  (document.getElementById("n3-f-status") as HTMLSelectElement).value = "Draft";
  (document.getElementById("n3-f-author") as HTMLSelectElement).value = "";
  (document.getElementById("n3-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("n3-f-err").textContent = "";
  $("n3-modal").classList.add("open");
  ($("n3-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("n3-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAssessment(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("n3-f-name").trim();
  const err = $("n3-f-err");
  if (!name) { err.textContent = "⚠️ Enter a name."; ($("n3-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("n3-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = "Creating…";
  try {
    const body = {
      name, status: v("n3-f-status"), date: v("n3-f-date") || undefined,
      authorPersonId: v("n3-f-author") || undefined, description: v("n3-f-desc").trim() || undefined,
    };
    const r = await fetch("/api/nist-800-30/assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${d.id}`;
    toast(`✅ Assessment created — <a href="${link}" style="color:#7dd3fc">open it ↗</a>`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("n3-new").addEventListener("click", openModal);
  $("n3-cancel").addEventListener("click", closeModal);
  $("n3-create").addEventListener("click", () => void createAssessment());
  $("n3-modal").addEventListener("click", (e) => { if (e.target === $("n3-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("n3-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAssessment(); });
  void loadAuthors();
  void load();
});
