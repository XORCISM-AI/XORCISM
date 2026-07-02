/**
 * exposure-remediation.ts — Autonomous Exposure Remediation cockpit (/exposure-remediation).
 * KPIs + the CTEM Mobilization closed-loop pipeline (Plan→Gate→Execute→Verify→Close), mobilize controls
 * (auto-plan top exposures / verification sweep), the open-plan worklist with per-status lifecycle actions
 * (execute → gate, approve, verify, risk-accept) and an inline AI runbook + lifecycle timeline.
 * All from /api/remediation*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
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
  const txt = days < 0 ? `${Math.abs(days)}${t("ar.ago", "d ago")}` : days === 0 ? t("ar.today", "today") : `${days}d`;
  return p.overdue ? `${txt}<span class="ovd">${t("ar.overdueTag", "OVERDUE")}</span>` : txt;
};

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/remediation"); } catch (e) { $("ar-body").innerHTML = `<div class="muted" style="padding:20px">${t("ar.failLoad", "Failed to load")}: ${esc(String(e))}</div>`; return; }
  REF = d; const s = d.summary || {}; const rc = d.receipts || { ok: true, total: 0, verified: 0 }; const pl = d.pipeline || {}; const pol = d.policy || {};

  if (!s.total) {
    $("ar-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">${t("ar.emptyMsg", "No remediation plans yet. <b>Mobilize</b> the top prioritized exposures into remediation plans, or seed a demo.")}</div>
      <div class="row"><div><label>${t("ar.autonomy", "Autonomy")}</label><select class="in" id="e-auto">${opts(REF.autonomy, pol.autonomy || "supervised")}</select></div>
      <div><label>${t("ar.topN", "Top N exposures")}</label><input class="in" id="e-lim" type="number" min="1" max="100" value="15" style="width:90px"></div>
      <button class="btn" id="e-auto-btn">&#129302; ${t("ar.autoPlan", "Auto-plan top exposures")}</button>
      <button class="btn sec" id="e-seed">${t("ar.seedDemo", "Seed demo")}</button></div></div>`;
    $("e-auto-btn").onclick = async () => { await postJSON("/api/remediation/auto-plan", { autonomy: ($("e-auto") as HTMLSelectElement).value, limit: Number(($("e-lim") as HTMLInputElement).value) }); load(); };
    $("e-seed").onclick = async () => { await postJSON("/api/remediation/seed"); load(); };
    return;
  }

  const slaTxt = Object.entries(pol.sla || {}).map(([k, v]) => `${k} ${Math.round(Number(v) / 24) || Number(v)}${Number(v) >= 24 ? "d" : "h"}`).join(" · ");
  const cards = [
    card(t("ar.k.open", "Open plans"), String(s.open ?? 0), t("ar.k.openFoot", "in the loop")),
    card(t("ar.k.appr", "Awaiting approval"), String(s.awaitingApproval ?? 0), t("ar.k.apprFoot", "human-in-the-loop"), (s.awaitingApproval ? "#fbbf24" : "#94a3b8")),
    card(t("ar.k.verif", "Awaiting verification"), String(s.awaitingVerification ?? 0), t("ar.k.verifFoot", "executed, re-checking"), (s.awaitingVerification ? "#22d3ee" : "#94a3b8")),
    card(t("ar.k.verified", "Verified / closed"), String(s.verified ?? 0), t("ar.k.verifiedFoot", "exposure cleared"), "#22c55e"),
    card(t("ar.k.overdue", "Overdue"), String(s.overdue ?? 0), t("ar.k.overdueFoot", "past SLA"), (s.overdue ? "#f87171" : "#94a3b8")),
    card(t("ar.k.sla", "SLA compliance"), s.slaCompliance == null ? "—" : `${s.slaCompliance}%`, t("ar.k.slaFoot", "closed on time"), s.slaCompliance == null ? "#94a3b8" : prioColor(100 - s.slaCompliance)),
    card(t("ar.k.mttr", "MTTR"), fmtMttr(s.mttrHours ?? null), t("ar.k.mttrFoot", "mean time to remediate")),
    card(t("ar.k.auto", "Autonomous"), s.autonomousPct == null ? "—" : `${s.autonomousPct}%`, `${s.autoExecuted ?? 0}/${s.executed ?? 0} ${t("ar.executed", "executed")}`, "#86efac"),
    card(t("ar.k.receipt", "Receipt chain"), rc.ok ? `✓ ${t("ar.intact", "intact")}` : `✗ ${t("ar.broken", "broken")}`, `${rc.verified}/${rc.total} ${t("ar.signed", "signed")}`, rc.ok ? "#22c55e" : "#f87171"),
  ].join("");

  const loop = [
    { t: t("ar.step.plan", "Plan"), n: pl.plan ?? 0, c: "#60a5fa" }, { t: t("ar.step.gate", "Gate"), n: pl.gate ?? 0, c: "#fbbf24" },
    { t: t("ar.step.execute", "Execute"), n: pl.execute ?? 0, c: "#22d3ee" }, { t: t("ar.step.verifyReopen", "Verify (reopened)"), n: pl.verify ?? 0, c: "#f87171" },
    { t: t("ar.step.close", "Close"), n: pl.close ?? 0, c: "#22c55e" },
  ].map((x, i, a) => `<div class="stp"><div class="n" style="color:${x.c}">${x.n}</div><div class="t">${esc(x.t)}</div>${i < a.length - 1 ? '<span class="arr">&#10142;</span>' : ""}</div>`).join("");

  $("ar-body").innerHTML = `
    <div class="ar-cards">${cards}</div>
    <div class="ar-sec">${t("ar.secLoop", "Mobilization loop")} &mdash; Plan &rarr; Gate &rarr; Execute &rarr; Verify &rarr; Close</div>
    <div class="loop">${loop}</div>
    <div class="frm"><div class="row">
      <div><label>${t("ar.autonomy", "Autonomy")}</label><select class="in" id="e-auto">${opts(REF.autonomy, pol.autonomy || "supervised")}</select></div>
      <div><label>${t("ar.topN", "Top N exposures")}</label><input class="in" id="e-lim" type="number" min="1" max="100" value="15" style="width:90px"></div>
      <button class="btn" id="e-auto-btn">&#129302; ${t("ar.autoPlan", "Auto-plan top exposures")}</button>
      <button class="btn sec" id="e-sweep">&#128260; ${t("ar.sweep", "Run verification sweep")}</button>
      <span class="muted" style="font-size:11px;margin-left:auto">${t("ar.defAutonomy", "Default autonomy")} <b>${esc(pol.autonomy || "supervised")}</b> · SLA: ${esc(slaTxt)}</span>
    </div></div>
    <div class="ar-sec">${t("ar.secWorklist", "Remediation worklist")} <span class="muted" style="font-weight:400;text-transform:none">&mdash; ${t("ar.worklistSub", "open plans, highest priority &amp; overdue first")}</span></div>
    <div id="ar-list" style="overflow-x:auto"></div>`;

  renderList(d.worklist || []);
  $("e-auto-btn").onclick = async () => { ($("e-auto-btn") as HTMLButtonElement).disabled = true; await postJSON("/api/remediation/auto-plan", { autonomy: ($("e-auto") as HTMLSelectElement).value, limit: Number(($("e-lim") as HTMLInputElement).value) }); load(); };
  $("e-sweep").onclick = async () => { await postJSON("/api/remediation/verify-sweep"); load(); };
}

function actionsFor(p: any): string {
  const b: string[] = [];
  if (["proposed", "queued", "reopened"].includes(p.status)) b.push(`<button class="btn sm" data-exec="${p.id}">&#9889; ${t("ar.execute", "Execute")}</button>`);
  if (p.status === "awaiting-approval") b.push(`<button class="btn sm" data-appr="${p.id}">&#9989; ${t("ar.approve", "Approve")}</button>`);
  if (["awaiting-verification", "reopened", "in-progress"].includes(p.status)) b.push(`<button class="btn sm sec" data-verify="${p.id}">&#128270; ${t("ar.verify", "Verify")}</button>`);
  b.push(`<button class="btn sm sec" data-rb="${p.id}">${t("ar.runbook", "Runbook")}</button>`);
  if (p.status !== "risk-accepted") b.push(`<button class="btn sm warn" data-risk="${p.id}">${t("ar.riskAccept", "Risk-accept")}</button>`);
  return b.join(" ");
}

// The exposure ref is (usually) a CVE: link it to the matching ASSETVULNERABILITY rows so the
// analyst can edit them, and expose an affected-assets expander (same fusion endpoint the
// vulnerability-management cockpit uses).
function exposureCell(p: any): string {
  const ref = esc(p.exposureRef);
  const head = p.vulnerabilityId
    ? `<a href="/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=VulnerabilityID&filterVal=${p.vulnerabilityId}" title="${t("ar.editAvTitle", "Edit matching ASSETVULNERABILITYs")}" style="text-decoration:none"><b>${ref}</b></a>`
    : `<b>${ref}</b>`;
  const assetBtn = p.assetCount
    ? (p.vulnerabilityId
      ? ` · <button class="btn sm sec ar-aff" data-aff="${p.vulnerabilityId}" title="${t("ar.viewAssets", "View affected assets")}" style="padding:1px 6px;font-size:10px">${p.assetCount} ${t("ar.assets", "asset(s)")} ▾</button>`
      : ` · ${p.assetCount} ${t("ar.assets", "asset(s)")}`)
    : "";
  return `${head}${p.publicFacing ? ` <span class="tag crit">${t("ar.internetFacing", "internet-facing")}</span>` : ""}<div class="muted" style="font-size:10px">${esc(p.title)}${assetBtn}${p.window ? ` · ${t("ar.window", "window")} ${esc(p.window)}` : ""}</div>`;
}

function renderList(plans: any[]): void {
  const rows = plans.map((p) => `<tr data-row="${p.id}">
    <td>${exposureCell(p)}</td>
    <td><span class="tag act">${esc(p.actionType)}</span></td>
    <td class="sev-${esc(p.severity)}">${esc(p.severity)}</td>
    <td><span class="prio" style="color:${prioColor(p.priority)}">${p.priority}<span class="priobar"><i style="width:${p.priority}%;background:${prioColor(p.priority)}"></i></span></span></td>
    <td><span class="tag auto">${esc(p.autonomy)}</span></td>
    <td class="st st-${esc(p.status)}">${esc(p.status)}${p.reopenCount ? ` <span class="muted">(${p.reopenCount}×)</span>` : ""}</td>
    <td>${p.ownerPersonId ? `#${p.ownerPersonId}` : `<span class="muted">${t("ar.unassigned", "unassigned")}</span>`}</td>
    <td>${dueLabel(p)}</td>
    <td style="white-space:nowrap">${actionsFor(p)}</td></tr>
    <tr data-detail="${p.id}" style="display:none"><td colspan="9"><div id="rb-${p.id}"></div></td></tr>`).join("") ||
    `<tr><td colspan="9" class="muted">${t("ar.noPlans", "No open plans — the loop is clear. Auto-plan exposures to mobilize.")}</td></tr>`;
  $("ar-list").innerHTML = `<table class="tt"><thead><tr><th>${t("ar.th.exposure", "Exposure")}</th><th>${t("ar.th.action", "Action")}</th><th>${t("ar.th.severity", "Severity")}</th><th>${t("ar.th.priority", "Priority")}</th><th>${t("ar.th.autonomy", "Autonomy")}</th><th>${t("ar.th.status", "Status")}</th><th>${t("ar.th.owner", "Owner")}</th><th>${t("ar.th.due", "SLA due")}</th><th>${t("ar.th.lifecycle", "Lifecycle")}</th></tr></thead><tbody>${rows}</tbody></table>`;

  document.querySelectorAll("[data-exec]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.exec}/execute`); flash(el as HTMLElement, r); load(); });
  document.querySelectorAll("[data-appr]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.appr}/approve`); if (r && r.error) alert(r.error); load(); });
  document.querySelectorAll("[data-verify]").forEach((el) => (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.verify}/verify`); if (r && r.result) alert(r.result === "verified" ? t("ar.vVerified", "✓ Verified — exposure cleared, plan closed.") : r.result === "reopened" ? t("ar.vReopened", "⚠ Still present past SLA — reopened.") : `${t("ar.vStillA", "Still present on")} ${r.openAssets} ${t("ar.vStillB", "asset(s), within SLA window.")}`); load(); });
  document.querySelectorAll("[data-risk]").forEach((el) => (el as HTMLElement).onclick = async () => { if (!confirm(t("ar.riskConfirm", "Accept the risk for this exposure and close the plan?"))) return; await postJSON(`/api/remediation/plan/${(el as HTMLElement).dataset.risk}/status`, { status: "risk-accepted", note: "risk accepted via cockpit" }); load(); });
  document.querySelectorAll("[data-rb]").forEach((el) => (el as HTMLElement).onclick = () => toggleRunbook((el as HTMLElement).dataset.rb!));
  document.querySelectorAll(".ar-aff").forEach((el) => (el as HTMLElement).onclick = () => toggleAssets(el as HTMLButtonElement));
}

// ── Affected-assets expander (reuses the fusion endpoint) ────────────────────────
interface ImpactedAsset { id: number; name: string; criticality: string | null; businessValue: number | null; address: string | null; publicFacing: boolean; }
function assetItemHtml(a: ImpactedAsset): string {
  const link = `/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}`;
  const meta = [a.criticality ? esc(a.criticality) : "", a.publicFacing ? t("ar.internetFacing", "internet-facing") : "", a.address ? esc(a.address) : ""].filter(Boolean).join(" · ");
  return `<a href="${link}" style="display:inline-block;background:#13162a;border:1px solid #2d3250;border-radius:6px;padding:4px 9px;font-size:12px;color:#e2e8f0;text-decoration:none;margin:2px 4px 2px 0"><b>${esc(a.name)}</b>${meta ? ` <span class="muted" style="font-size:11px">${meta}</span>` : ""}</a>`;
}
async function toggleAssets(btn: HTMLButtonElement): Promise<void> {
  const vid = Number(btn.dataset.aff);
  const tr = btn.closest("tr") as HTMLTableRowElement | null; if (!tr) return;
  const next = tr.nextElementSibling as HTMLElement | null;
  if (next && next.classList.contains("ar-asset-detail")) { next.remove(); btn.innerHTML = btn.innerHTML.replace("▴", "▾"); return; }
  btn.innerHTML = btn.innerHTML.replace("▾", "▴");
  const detail = document.createElement("tr"); detail.className = "ar-asset-detail";
  detail.innerHTML = `<td colspan="9" style="background:#0c0e1a"><div class="ar-asset-box" style="padding:8px 6px">${esc(t("ar.loadingAssets", "Loading assets…"))}</div></td>`;
  tr.parentElement!.insertBefore(detail, tr.nextSibling);
  try {
    const r = await fetch(`/api/fusion/vuln/${vid}/assets`);
    const dd = await r.json(); if (!r.ok) throw new Error(dd.error || `HTTP ${r.status}`);
    const list = (dd.assets || []) as ImpactedAsset[];
    detail.querySelector(".ar-asset-box")!.innerHTML = list.length
      ? `<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">${esc(t("ar.impactedAssets", "Impacted assets"))} (${list.length})</div>${list.map(assetItemHtml).join("")}`
      : `<span class="muted">${esc(t("ar.noAssets", "No affected assets found."))}</span>`;
  } catch (e) { detail.querySelector(".ar-asset-box")!.innerHTML = `<span class="muted">⚠️ ${esc(e)}</span>`; }
}

function flash(el: HTMLElement, r: any): void { if (r && r.status === "blocked") alert(t("ar.blocked", "⛔ Blocked by the Agent Policy Firewall (blast radius too high).")); else if (r && r.status === "awaiting-approval") alert(t("ar.gated", "⏸ Gated — requires human approval (autonomy / firewall).")); }

async function toggleRunbook(id: string): Promise<void> {
  const row = document.querySelector(`tr[data-detail="${id}"]`) as HTMLElement; if (!row) return;
  if (row.style.display !== "none") { row.style.display = "none"; return; }
  row.style.display = "";
  const box = $("rb-" + id); box.innerHTML = `<div class="muted" style="padding:6px">${t("ar.loadingRb", "Loading runbook + timeline…")}</div>`;
  const [rb, detail] = await Promise.all([getJSON(`/api/remediation/plan/${id}/runbook`).catch(() => null), getJSON(`/api/remediation/plan/${id}`).catch(() => null)]);
  const tl = (detail?.events || []).map((e: any) => `<div class="tl">• <b>${esc(e.event)}</b> — ${esc(e.detail)} <span class="muted">(${esc(String(e.at).slice(0, 16).replace("T", " "))} · ${esc(e.actor)})</span></div>`).join("");
  box.innerHTML = `${rb ? `<div class="rb">${esc(rb.runbook)}<div class="muted" style="margin-top:6px;font-size:10px">${rb.offline ? t("ar.offlineRb", "offline runbook") : "AI: " + esc(rb.model)}</div></div>` : ""}
    ${detail?.executionRef ? `<div class="tl" style="margin-top:6px">${t("ar.execution", "Execution")}: <b>${esc(detail.executionRef)}</b>${detail.receipt ? ` · ${t("ar.receipt2", "receipt")} <span style="font-family:ui-monospace,monospace">${esc(detail.receipt)}…</span>` : ""}</div>` : ""}
    ${tl ? `<div style="margin-top:6px"><b style="font-size:11px;color:#cbd5e1">${t("ar.lifecycleTimeline", "Lifecycle timeline")}</b>${tl}</div>` : ""}`;
}

document.addEventListener("DOMContentLoaded", load);
