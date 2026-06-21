/**
 * patch-management.ts — Patch Management cockpit (/patch-management). Per asset↔vulnerability patch
 * lifecycle: KPIs (coverage, MTTR, KEV-unpatched, overdue SLA), a prioritized worklist with inline
 * patch-status changes and a remediation-plan modal, from /api/patch-management.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row {
  id: number; assetId: number; asset: string; criticality: string; cve: string; vulnerabilityId: number; name: string;
  severity: string; cvss: number | null; kev: boolean; epss: number | null; patchAvailable: boolean;
  patchStatus: string; resolved: boolean; patchedDate: string | null; due: string | null; dueIn: number | null;
  overdue: boolean; hasPlan: boolean; planStatus: string; planType: string; score: number;
}
interface Data {
  statuses: string[]; rows: Row[]; worklist: Row[];
  summary: { instances: number; patched: number; unpatched: number; noPatch: number; accepted: number; coverage: number | null; mttr: number | null; kevUnpatched: number; overdue: number; withPlan: number; bySeverity: Record<string, number>; byStatus: Record<string, number> };
}

let DATA: Data | null = null;
let STATUSES: string[] = [];
let modalRow: Row | null = null;
const sevClass = (s: string): string => `s-${(s || "info").toLowerCase()}`;

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="pm-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function dueCell(r: Row): string {
  if (r.resolved) return `<span class="muted">—</span>`;
  if (r.due == null) return `<span class="muted">—</span>`;
  const cls = r.overdue ? "due-over" : (r.dueIn != null && r.dueIn <= 14 ? "due-soon" : "due-ok");
  const txt = r.dueIn != null ? (r.dueIn < 0 ? `${-r.dueIn}d overdue` : `${r.dueIn}d`) : r.due;
  return `<span class="${cls}" title="${esc(r.due)}">${esc(txt)}</span>`;
}

function rowHtml(r: Row): string {
  const opts = STATUSES.map((s) => `<option${s === r.patchStatus ? " selected" : ""}>${esc(s)}</option>`).join("");
  return `<tr data-id="${r.id}">
    <td><span class="mono">${esc(r.cve)}</span>${r.kev ? ' <span class="kev">KEV</span>' : ""}<div class="muted" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.name)}</div></td>
    <td><a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${r.assetId}">${esc(r.asset)}</a>${r.criticality ? `<div class="muted" style="font-size:11px">${esc(r.criticality)}</div>` : ""}</td>
    <td><span class="sev ${sevClass(r.severity)}">${esc(r.severity)}</span>${r.cvss != null ? `<div class="muted" style="font-size:11px">CVSS ${esc(r.cvss)}</div>` : ""}</td>
    <td>${r.epss != null ? (r.epss * 100).toFixed(0) + "%" : "<span class='muted'>—</span>"}</td>
    <td><span class="pa ${r.patchAvailable ? "pa-y" : "pa-n"}">${r.patchAvailable ? "available" : "none"}</span></td>
    <td>${dueCell(r)}</td>
    <td><select class="pst" data-id="${r.id}">${opts}</select></td>
    <td>${r.hasPlan ? `<span class="plan" title="${esc(r.planStatus)}">✓ ${esc(r.planType || "plan")}</span>` : `<button class="btn btn-ghost btn-sm pm-plan" data-id="${r.id}" style="padding:2px 8px;font-size:11px">+ plan</button>`}</td>
  </tr>`;
}

function applyFilters(): Row[] {
  if (!DATA) return [];
  const q = (($("pm-search") as HTMLInputElement)?.value || "").trim().toLowerCase();
  const sev = ($("pm-sev") as HTMLSelectElement)?.value || "";
  const st = ($("pm-status") as HTMLSelectElement)?.value || "";
  const kevOnly = !!($("pm-kev") as HTMLInputElement)?.checked;
  const overdueOnly = !!($("pm-over") as HTMLInputElement)?.checked;
  return DATA.rows.filter((r) =>
    (!q || `${r.cve} ${r.asset} ${r.name}`.toLowerCase().includes(q)) &&
    (!sev || r.severity === sev) && (!st || r.patchStatus === st) &&
    (!kevOnly || r.kev) && (!overdueOnly || r.overdue));
}

function renderTable(): void {
  const rows = applyFilters();
  const host = $("pm-table-host");
  host.innerHTML = rows.length
    ? `<table class="pm"><thead><tr><th>CVE</th><th>Asset</th><th>Severity</th><th>EPSS</th><th>Patch</th><th title="Patch SLA due">Due</th><th>Patch status</th><th>Plan</th></tr></thead>
        <tbody>${rows.slice(0, 400).map(rowHtml).join("")}</tbody></table>${rows.length > 400 ? `<div class="muted" style="font-size:11px;margin-top:6px">Showing first 400 of ${rows.length}.</div>` : ""}`
    : `<div class="muted" style="padding:14px 0">No matching asset-vulnerabilities.</div>`;
  host.querySelectorAll<HTMLSelectElement>("select.pst").forEach((sel) => sel.addEventListener("change", () => void setStatus(Number(sel.dataset.id), sel.value)));
  host.querySelectorAll<HTMLButtonElement>("button.pm-plan").forEach((b) => b.addEventListener("click", () => openPlan(Number(b.dataset.id))));
  const cnt = $("pm-count"); if (cnt) cnt.textContent = `(${rows.length}/${DATA?.rows.length ?? 0})`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/patch-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("pm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  STATUSES = DATA!.statuses || [];
  const s = DATA!.summary;
  if (!DATA!.rows.length) {
    $("pm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No asset-vulnerability links yet. Import scan findings or run the
      <a href="/asset-management">CVE→asset matcher</a>, then patch status &amp; remediation plans appear here.</div>`;
    return;
  }
  const cards = [
    card("Asset-vulns", String(s.instances), `${s.unpatched} unpatched · ${s.patched} patched`),
    card("Patch coverage", s.coverage != null ? `${s.coverage}%` : "—", "of remediable instances", s.coverage != null ? (s.coverage >= 80 ? "#34d399" : s.coverage >= 50 ? "#fbbf24" : "#f87171") : undefined),
    card("KEV unpatched", String(s.kevUnpatched), "actively exploited", s.kevUnpatched ? "#f87171" : "#34d399"),
    card("Overdue SLA", String(s.overdue), "past patch deadline", s.overdue ? "#f87171" : "#34d399"),
    card("MTTR", s.mttr != null ? `${s.mttr}d` : "—", "mean time to remediate"),
    card("With plan", String(s.withPlan), `${s.noPatch} no-patch`),
  ].join("");
  const covBar = s.coverage != null ? `<div class="bar"><span style="width:${Math.max(2, s.coverage)}%"></span></div>` : "";
  const bySev = Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
  const byStatus = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const filters = `<div class="filters">
    <input id="pm-search" type="search" placeholder="Search CVE / asset…" style="flex:1;min-width:200px">
    <select id="pm-sev"><option value="">All severities</option>${["Critical", "High", "Medium", "Low", "Info"].map((x) => `<option>${x}</option>`).join("")}</select>
    <select id="pm-status"><option value="">All statuses</option>${STATUSES.map((x) => `<option>${esc(x)}</option>`).join("")}</select>
    <label class="ck"><input type="checkbox" id="pm-kev"> KEV only</label>
    <label class="ck"><input type="checkbox" id="pm-over"> Overdue only</label>
    <span id="pm-count" class="muted" style="font-size:12px"></span></div>`;

  $("pm-body").innerHTML = `<div class="pm-cards">${cards}</div>${covBar}
    <div class="pm-section">Open by severity</div><div class="breakdown">${bySev || '<span class="muted">none</span>'}</div>
    <div class="pm-section">By patch status</div><div class="breakdown">${byStatus}</div>
    <div class="pm-section">Patch worklist</div>${filters}<div id="pm-table-host"></div>
    <div class="legend">↳ Patch SLA (days from discovery): <b>KEV 14</b> (or CISA due) · Critical 15 · High 30 · Medium 90 · Low 180.
      Mark a row <i>Patched</i> to stamp the date &amp; lift coverage; <b>+ plan</b> attaches a remediation plan
      (ASSETVULNERABILITYREMEDIATION). Manage raw rows in the <a href="/?db=XORCISM&table=ASSETVULNERABILITY">explorer</a>.</div>`;

  for (const id of ["pm-search", "pm-sev", "pm-status", "pm-kev", "pm-over"]) $(id).addEventListener("input", renderTable);
  renderTable();
}

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 6000);
}

async function setStatus(id: number, status: string): Promise<void> {
  try {
    const r = await fetch("/api/patch-management/status", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ assetVulnId: id, status }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    toast(`✅ Patch status → <b>${esc(status)}</b>`);
    await load();
  } catch (e) { toast(`⚠️ ${e}`); }
}

// ── remediation-plan modal ──────────────────────────────────────────────────────
async function loadOwners(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const sel = $("pm-f-owner") as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; sel.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

function openPlan(id: number): void {
  modalRow = DATA?.rows.find((r) => r.id === id) ?? null;
  if (!modalRow) return;
  ($("pm-f-name") as HTMLInputElement).value = `Patch ${modalRow.cve} on ${modalRow.asset}`;
  ($("pm-f-desc") as HTMLTextAreaElement).value = "";
  ($("pm-f-type") as HTMLSelectElement).value = "Patch";
  ($("pm-f-status") as HTMLSelectElement).value = "Planned";
  ($("pm-f-priority") as HTMLSelectElement).value = modalRow.severity === "Critical" ? "Critical" : modalRow.severity === "High" ? "High" : "";
  ($("pm-f-owner") as HTMLSelectElement).value = "";
  ($("pm-f-target") as HTMLInputElement).value = modalRow.due || "";
  $("pm-modal-ctx").innerHTML = `Remediation for <b>${esc(modalRow.cve)}</b> on <b>${esc(modalRow.asset)}</b> · <span class="sev ${sevClass(modalRow.severity)}">${esc(modalRow.severity)}</span>${modalRow.kev ? ' <span class="kev">KEV</span>' : ""}`;
  $("pm-f-err").textContent = "";
  $("pm-modal").classList.add("open");
  ($("pm-f-name") as HTMLInputElement).focus();
}
function closePlan(): void { $("pm-modal").classList.remove("open"); modalRow = null; }

async function createPlan(): Promise<void> {
  if (!modalRow) return;
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("pm-f-name").trim();
  const err = $("pm-f-err");
  if (!name) { err.textContent = "⚠️ Enter a plan name."; return; }
  const btn = $("pm-create") as HTMLButtonElement; btn.disabled = true; err.textContent = "Creating…";
  try {
    const body = {
      assetVulnId: modalRow.id, name, type: v("pm-f-type"), status: v("pm-f-status"),
      targetDate: v("pm-f-target") || undefined, priority: v("pm-f-priority") || undefined,
      ownerPersonId: v("pm-f-owner") || undefined, description: v("pm-f-desc").trim() || undefined,
    };
    const r = await fetch("/api/patch-management/remediation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closePlan();
    await load();
    toast(`✅ Remediation plan created`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("pm-cancel").addEventListener("click", closePlan);
  $("pm-create").addEventListener("click", () => void createPlan());
  $("pm-modal").addEventListener("click", (e) => { if (e.target === $("pm-modal")) closePlan(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePlan(); });
  void loadOwners();
  void load();
});
