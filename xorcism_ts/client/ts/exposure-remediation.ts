/**
 * exposure-remediation.ts — Autonomous Exposure Remediation cockpit (/exposure-remediation).
 * KPIs + the CTEM Mobilization closed-loop pipeline (Plan→Gate→Execute→Verify→Close), mobilize controls
 * (auto-plan top exposures / verification sweep), the open-plan worklist with per-status lifecycle actions
 * (execute → gate, approve, verify, risk-accept) and an inline AI runbook + lifecycle timeline.
 * All from /api/remediation*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

const prioColor = (n: number): string => (n >= 80 ? "#ef4444" : n >= 60 ? "#fb923c" : n >= 40 ? "#fbbf24" : "#22c55e");
let REF: any = { actionTypes: [], autonomy: [], statuses: [] };
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ar-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const fmtMttr = (h: number | null): string => (h == null ? "—" : h >= 48 ? `${Math.round(h / 24)}d` : `${h}h`);
const opts = (arr: string[], sel?: string): string => arr.map((o) => `<option${sel === o ? " selected" : ""}>${esc(o)}</option>`).join("");
const dueLabel = (p: any): string => {
  if (!p.dueDate) return "—";
  const d = new Date(p.dueDate); const days = Math.round((d.getTime() - Date.now()) / 86400000);
  const txt = days < 0 ? `${Math.abs(days)}d ago` : days === 0 ? "today" : `${days}d`;
  return p.overdue ? `${txt}<span class="ovd">OVERDUE</span>` : txt;
};

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/remediation"); } catch (e) { $("ar-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  REF = d; const s = d.summary || {}; const rc = d.receipts || { ok: true, total: 0, verified: 0 }; const pl = d.pipeline || {}; const pol = d.policy || {};

  if (!s.total) {
    $("ar-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">No remediation plans yet. <b>Mobilize</b> the top prioritized exposures into remediation plans, or seed a demo.</div>
      <div class="row"><div><label>Autonomy</label><select class="in" id="e-auto">${opts(REF.autonomy, pol.autonomy || "supervised")}</select></div>
      <div><label>Top N exposures</label><input class="in" id="e-lim" type="number" min="1" max="100" value="15" style="width:90px"></div>
      <button class="btn" id="e-auto-btn">&#129302; Auto-plan top exposures</button>
      <button class="btn sec" id="e-seed">Seed demo</button></div></div>`;
    $("e-auto-btn").onclick = async () => { await postJSON("/api/remediation/auto-plan", { autonomy: ($("e-auto") as HTMLSelectElement).value, limit: Number(($("e-lim") as HTMLInputElement).value) }); load(); };
    $("e-seed").onclick = async () => { await postJSON("/api/remediation/seed"); load(); };
    return;
  }

  const slaTxt = Object.entries(pol.sla || {}).map(([k, v]) => `${k} ${Math.round(Number(v) / 24) || Number(v)}${Number(v) >= 24 ? "d" : "h"}`).join(" · ");
  const cards = [
    card("Open plans", String(s.open ?? 0), "in the loop"),
    card("Awaiting approval", String(s.awaitingApproval ?? 0), "human-in-the-loop", (s.awaitingApproval ? "#fbbf24" : "#94a3b8")),
    card("Awaiting verification", String(s.awaitingVerification ?? 0), "executed, re-checking", (s.awaitingVerification ? "#22d3ee" : "#94a3b8")),
    card("Verified / closed", String(s.verified ?? 0), "exposure cleared", "#22c55e"),
    card("Overdue", String(s.overdue ?? 0), "past SLA", (s.overdue ? "#f87171" : "#94a3b8")),
    card("SLA compliance", s.slaCompliance == null ? "—" : `${s.slaCompliance}%`, "closed on time", s.slaCompliance == null ? "#94a3b8" : prioColor(100 - s.slaCompliance)),
    card("MTTR", fmtMttr(s.mttrHours ?? null), "mean time to remediate"),
    card("Autonomous", s.autonomousPct == null ? "—" : `${s.autonomousPct}%`, `${s.autoExecuted ?? 0}/${s.executed ?? 0} executed`, "#86efac"),
    card("Receipt chain", rc.ok ? "✓ intact" : "✗ broken", `${rc.verified}/${rc.total} signed`, rc.ok ? "#22c55e" : "#f87171"),
  ].join("");

  const loop = [
    { t: "Plan", n: pl.plan ?? 0, c: "#60a5fa" }, { t: "Gate", n: pl.gate ?? 0, c: "#fbbf24" },
    { t: "Execute", n: pl.execute ?? 0, c: "#22d3ee" }, { t: "Verify (reopened)", n: pl.verify ?? 0, c: "#f87171" },
    { t: "Close", n: pl.close ?? 0, c: "#22c55e" },
  ].map((x, i, a) => `<div class="stp"><div class="n" style="color:${x.c}">${x.n}</div><div class="t">${esc(x.t)}</div>${i < a.length - 1 ? '<span class="arr">&#10142;</span>' : ""}</div>`).join("");

  $("ar-body").innerHTML = `
    <div class="ar-cards">${cards}</div>
    <div class="ar-sec">Mobilization loop &mdash; Plan &rarr; Gate &rarr; Execute &rarr; Verify &rarr; Close</div>
    <div class="loop">${loop}</div>
    <div class="frm"><div class="row">
      <div><label>Autonomy</label><select class="in" id="e-auto">${opts(REF.autonomy, pol.autonomy || "supervised")}</select></div>
      <div><label>Top N exposures</label><input class="in" id="e-lim" type="number" min="1" max="100" value="15" style="width:90px"></div>
      <button class="btn" id="e-auto-btn">&#129302; Auto-plan top exposures</button>
      <button class="btn sec" id="e-sweep">&#128260; Run verification sweep</button>
      <span class="muted" style="font-size:11px;margin-left:auto">Default autonomy <b>${esc(pol.autonomy || "supervised")}</b> · SLA: ${esc(slaTxt)}</span>
    </div></div>
    <div class="ar-sec">Remediation worklist <span class="muted" style="font-weight:400;text-transform:none">&mdash; open plans, highest priority &amp; overdue first</span></div>
    <div id="ar-list" style="overflow-x:auto"></div>`;

  renderList(d.worklist || []);
  $("e-auto-btn").onclick = async () => { ($("e-auto-btn") as HTMLButtonElement).disabled = true; await postJSON("/api/remediation/auto-plan", { autonomy: ($("e-auto") as HTMLSelectElement).value, limit: Number(($("e-lim") as HTMLInputElement).value) }); load(); };
  $("e-sweep").onclick = async () => { await postJSON("/api/remediation/verify-sweep"); load(); };
}

function actionsFor(p: any): string {
  const b: string[] = [];
  if (["proposed", "queued", "reopened"].includes(p.status)) b.push(`<button class="btn sm" data-exec="${p.id}">&#9889; Execute</button>`);
  if (p.status === "awaiting-approval") b.push(`<button class="btn sm" data-appr="${p.id}">&#9989; Approve</button>`);
  if (["awaiting-verification", "reopened", "in-progress"].includes(p.status)) b.push(`<button class="btn sm sec" data-verify="${p.id}">&#128270; Verify</button>`);
  b.push(`<button class="btn sm sec" data-rb="${p.id}">Runbook</button>`);
  if (p.status !== "risk-accepted") b.push(`<button class="btn sm warn" data-risk="${p.id}">Risk-accept</button>`);
  return b.join(" ");
}

function renderList(plans: any[]): void {
  const rows = plans.map((p) => `<tr data-row="${p.id}">
    <td><b>${esc(p.exposureRef)}</b>${p.publicFacing ? ` <span class="tag crit">internet-facing</span>` : ""}<div class="muted" style="font-size:10px">${esc(p.title)}${p.assetCount ? ` · ${p.assetCount} asset(s)` : ""}${p.window ? ` · window ${esc(p.window)}` : ""}</div></td>
    <td><span class="tag act">${esc(p.actionType)}</span></td>
    <td class="sev-${esc(p.severity)}">${esc(p.severity)}</td>
    <td><span class="prio" style="color:${prioColor(p.priority)}">${p.priority}<span class="priobar"><i style="width:${p.priority}%;background:${prioColor(p.priority)}"></i></span></span></td>
    <td><span class="tag auto">${esc(p.autonomy)}</span></td>
    <td class="st st-${esc(p.status)}">${esc(p.status)}${p.reopenCount ? ` <span class="muted">(${p.reopenCount}×)</span>` : ""}</td>
    <td>${p.ownerPersonId ? `#${p.ownerPersonId}` : '<span class="muted">unassigned</span>'}</td>
    <td>${dueLabel(p)}</td>
    <td style="white-space:nowrap">${actionsFor(p)}</td></tr>
    <tr data-detail="${p.id}" style="display:none"><td colspan="9"><div id="rb-${p.id}"></div></td></tr>`).join("") ||
    `<tr><td colspan="9" class="muted">No open plans — the loop is clear. Auto-plan exposures to mobilize.</td></tr>`;
  $("ar-list").innerHTML = `<table class="tt"><thead><tr><th>Exposure</th><th>Action</th><th>Severity</th><th>Priority</th><th>Autonomy</th><th>Status</th><th>Owner</th><th>SLA due</th><th>Lifecycle</th></tr></thead><tbody>${rows}</tbody></table>`;

  document.querySelectorAll("[data-exec]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.exec}/execute`); flash(el as HTMLElement, r); load(); });
  document.querySelectorAll("[data-appr]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.appr}/approve`); if (r && r.error) alert(r.error); load(); });
  document.querySelectorAll("[data-verify]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.verify}/verify`); if (r && r.result) alert(r.result === "verified" ? "✓ Verified — exposure cleared, plan closed." : r.result === "reopened" ? "⚠ Still present past SLA — reopened." : `Still present on ${r.openAssets} asset(s), within SLA window.`); load(); });
  document.querySelectorAll("[data-risk]").forEach((el) => (el as HTMLElement).onclick = async () => { if (!confirm("Accept the risk for this exposure and close the plan?")) return; await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.risk}/status`, { status: "risk-accepted", note: "risk accepted via cockpit" }); load(); });
  document.querySelectorAll("[data-rb]").forEach((el) => (el as HTMLElement).onclick = () => toggleRunbook((el as HTMLElement).dataset.rb!));
}

function flash(el: HTMLElement, r: any): void { if (r && r.status === "blocked") alert("⛔ Blocked by the Agent Policy Firewall (blast radius too high)."); else if (r && r.status === "awaiting-approval") alert("⏸ Gated — requires human approval (autonomy / firewall)."); }

async function toggleRunbook(id: string): Promise<void> {
  const row = document.querySelector(`tr[data-detail="${id}"]`) as HTMLElement; if (!row) return;
  if (row.style.display !== "none") { row.style.display = "none"; return; }
  row.style.display = "";
  const box = $("rb-" + id); box.innerHTML = `<div class="muted" style="padding:6px">Loading runbook + timeline…</div>`;
  const [rb, detail] = await Promise.all([getJSON(`/api/remediation/plan/${id}/runbook`).catch(() => null), getJSON(`/api/remediation/plan/${id}`).catch(() => null)]);
  const tl = (detail?.events || []).map((e: any) => `<div class="tl">• <b>${esc(e.event)}</b> — ${esc(e.detail)} <span class="muted">(${esc(String(e.at).slice(0, 16).replace("T", " "))} · ${esc(e.actor)})</span></div>`).join("");
  box.innerHTML = `${rb ? `<div class="rb">${esc(rb.runbook)}<div class="muted" style="margin-top:6px;font-size:10px">${rb.offline ? "offline runbook" : "AI: " + esc(rb.model)}</div></div>` : ""}
    ${detail?.executionRef ? `<div class="tl" style="margin-top:6px">Execution: <b>${esc(detail.executionRef)}</b>${detail.receipt ? ` · receipt <span style="font-family:ui-monospace,monospace">${esc(detail.receipt)}…</span>` : ""}</div>` : ""}
    ${tl ? `<div style="margin-top:6px"><b style="font-size:11px;color:#cbd5e1">Lifecycle timeline</b>${tl}</div>` : ""}`;
}

document.addEventListener("DOMContentLoaded", load);
