/**
 * croc-orchestrator.ts — client for the agentic CROC orchestrator (/croc-orchestrator).
 * Renders KPI cards, the approval queue (proposed actions with verdict + recommended action +
 * approve/dismiss) and recently decided actions from /api/croc-orchestrator.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Action {
  id: number; loopEventId: number; eventType: string; severity: string; title: string; copilot: string;
  verdict: string; recommendedAction: string; rationale: string; confidence: number; status: string; createdDate: string;
  decidedDate?: string; executedOutcome?: string | null;
}
interface Data {
  summary: { proposed: number; approved: number; dismissed: number; critical: number; total: number };
  queue: Action[]; recent: Action[]; all: Action[]; canAct: boolean;
}
let DATA: Data | null = null;
const sevc = (s: string): string => `sv-${(s || "").toLowerCase()}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function queueItem(a: Action): string {
  const cls = (a.severity || "").toLowerCase() === "critical" ? "crit" : "high";
  const actions = DATA?.canAct
    ? `<div style="display:flex;gap:8px;margin-top:10px"><button class="btn btn-approve" data-approve="${a.id}">✓ Approve</button><button class="btn btn-dismiss" data-dismiss="${a.id}">✕ Dismiss</button></div>`
    : `<div class="muted" style="font-size:11px;margin-top:8px">Read-only — response capability required to act.</div>`;
  return `<div class="item ${cls}">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span>
      <span class="nm" style="font-size:14px">${esc(a.title)}</span>
      <span class="spacer" style="flex:1"></span>
      <span class="pill">🤖 ${esc(a.copilot)}</span>
      <span class="muted" style="font-size:11px">conf <span class="conf" style="width:${Math.max(8, a.confidence * 0.5)}px"></span> ${a.confidence}%</span>
    </div>
    <div style="margin-top:6px;font-size:12.5px"><b style="color:#67e8f9">Verdict:</b> ${esc(a.verdict)}</div>
    <div class="rec"><b>Recommended:</b> ${esc(a.recommendedAction)}</div>
    <div class="rationale">${esc(a.rationale)} <span class="muted">· event #${a.loopEventId} · ${esc(a.eventType)}</span></div>
    ${actions}
  </div>`;
}

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("In queue", s.proposed, "awaiting approval", s.proposed ? "#fbbf24" : "#34d399"),
    card("Critical", s.critical, "proposed, critical", s.critical ? "#f87171" : "#34d399"),
    card("Approved", s.approved, "decided"),
    card("Dismissed", s.dismissed, "closed"),
    card("Total", s.total, "all proposals"),
  ].join("");
  const queue = d.queue.length ? d.queue.map(queueItem).join("") : `<div class="muted" style="padding:10px 0">✓ Queue clear — no high/critical signals awaiting a decision. Click <b>Run now</b> to scan the loop, or <b>Seed demo</b> to preview.</div>`;
  const recent = d.recent.length
    ? `<table class="t"><thead><tr><th>Severity</th><th>Action</th><th>Copilot</th><th>Decision &amp; actuation</th><th>When</th></tr></thead><tbody>${d.recent.map((a) => `<tr><td><span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.title)}</td><td>${esc(a.copilot)}</td><td>${a.status === "approved" ? `<span style='color:#34d399'>✓ approved</span>${a.executedOutcome ? `<div class="muted" style="font-size:11px">↳ ${esc(a.executedOutcome)}</div>` : ""}` : "<span class='muted'>✕ dismissed</span>"}</td><td class="muted" style="font-size:11px">${esc((a.decidedDate || a.createdDate || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("")}</tbody></table>`
    : "";

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">Approval queue (${d.queue.length})</div>${queue}
    ${recent ? `<div class="sec">Recently decided</div>${recent}` : ""}`;

  body.querySelectorAll<HTMLElement>("[data-approve]").forEach((b) => b.addEventListener("click", () => void decide(Number(b.dataset.approve), "approved")));
  body.querySelectorAll<HTMLElement>("[data-dismiss]").forEach((b) => b.addEventListener("click", () => void decide(Number(b.dataset.dismiss), "dismissed")));
  for (const id of ["o-run", "o-demo"]) { const btn = $(id) as HTMLButtonElement | null; if (btn && !d.canAct) { btn.disabled = true; btn.style.opacity = "0.5"; } }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/croc-orchestrator")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
async function decide(id: number, decision: string): Promise<void> {
  try { render(await getJson(`/api/croc-orchestrator/${id}/decision`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision }) })); toast(decision === "approved" ? "Action approved" : "Action dismissed"); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function run(): Promise<void> {
  try { const d = await getJson("/api/croc-orchestrator/run", { method: "POST" }); render(d); toast(`Scanned ${d.scanned} event(s), proposed ${d.proposed}`); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function demo(): Promise<void> {
  try { const d = await getJson("/api/croc-orchestrator/seed-demo", { method: "POST" }); render(d); toast(`Emitted ${d.emitted} events, proposed ${d.proposed}`); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  $("o-run")?.addEventListener("click", () => void run());
  $("o-demo")?.addEventListener("click", () => void demo());
  void load();
});
