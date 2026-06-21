/**
 * asset-monitoring.ts — Asset Monitoring cockpit (/asset-monitoring). Uptime/health/SSL monitors
 * over assets with status, uptime %, response time, SSL expiry and incidents, from /api/asset-monitoring.
 * Create monitors (guided modal) and change a monitor's status inline.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Check { id: number; assetId: number | null; asset: string; name: string; type: string; target: string; enabled: boolean; status: string; uptime: number | null; responseTime: number | null; lastChecked: string | null; sslExpiry: string | null; sslDays: number | null; source: string; }
interface Incident { id: number; monitor: string; asset: string; title: string; status: string; severity: string; startedAt: string | null; resolvedAt: string | null; open: boolean; }
interface Data {
  checkTypes: string[]; statuses: string[]; checks: Check[]; incidents: Incident[]; worklist: { kind: string; id: number; monitor: string; asset: string; label: string; severity: string }[];
  summary: { total: number; up: number; down: number; warning: number; paused: number; avgUptime: number | null; sslExpiringSoon: number; openIncidents: number; byType: Record<string, number>; byStatus: Record<string, number> };
}

let DATA: Data | null = null;
let STATUSES: string[] = [];

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="mn-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
function sslCell(c: Check): string {
  if (c.sslExpiry == null) return `<span class="muted">—</span>`;
  const cls = c.sslDays == null ? "ssl-ok" : c.sslDays < 0 ? "ssl-over" : c.sslDays <= 30 ? "ssl-soon" : "ssl-ok";
  const txt = c.sslDays != null ? (c.sslDays < 0 ? `expired ${-c.sslDays}d` : `${c.sslDays}d left`) : c.sslExpiry;
  return `<span class="${cls}" title="${esc(c.sslExpiry)}">${esc(txt)}</span>`;
}
function rowHtml(c: Check): string {
  const opts = STATUSES.map((s) => `<option${s === c.status ? " selected" : ""}>${esc(s)}</option>`).join("");
  return `<tr data-id="${c.id}">
    <td><span class="dot d-${c.status}"></span><span class="aname">${esc(c.name)}</span>${!c.enabled ? ' <span class="muted" style="font-size:10px">(disabled)</span>' : ""}<div class="mono muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.target)}</div></td>
    <td>${c.asset ? `<a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${c.assetId}">${esc(c.asset)}</a>` : "<span class='muted'>—</span>"}</td>
    <td><span class="ty">${esc(c.type)}</span></td>
    <td>${c.uptime != null ? `${c.uptime}%` : "<span class='muted'>—</span>"}</td>
    <td>${c.responseTime != null ? `${c.responseTime} ms` : "<span class='muted'>—</span>"}</td>
    <td>${sslCell(c)}</td>
    <td><select class="pst" data-id="${c.id}">${opts}</select></td>
  </tr>`;
}
function applyFilters(): Check[] {
  if (!DATA) return [];
  const q = (($("mn-search") as HTMLInputElement)?.value || "").trim().toLowerCase();
  const ty = ($("mn-type") as HTMLSelectElement)?.value || "";
  const st = ($("mn-status") as HTMLSelectElement)?.value || "";
  return DATA.checks.filter((c) => (!q || `${c.name} ${c.asset} ${c.target}`.toLowerCase().includes(q)) && (!ty || c.type === ty) && (!st || c.status === st));
}
function renderTable(): void {
  const rows = applyFilters();
  const host = $("mn-table-host");
  host.innerHTML = rows.length
    ? `<table class="mn"><thead><tr><th>Monitor</th><th>Asset</th><th>Type</th><th>Uptime</th><th>Response</th><th>SSL</th><th>Status</th></tr></thead><tbody>${rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:14px 0">No matching monitors.</div>`;
  host.querySelectorAll<HTMLSelectElement>("select.pst").forEach((sel) => sel.addEventListener("change", () => void setStatus(Number(sel.dataset.id), sel.value)));
  const cnt = $("mn-count"); if (cnt) cnt.textContent = `(${rows.length}/${DATA?.checks.length ?? 0})`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/asset-monitoring"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("mn-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  STATUSES = DATA!.statuses || [];
  const s = DATA!.summary;
  if (!DATA!.checks.length) {
    $("mn-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No monitors yet. Click <b>+ Add monitor</b> to create one,
      or import from <b>CheckCle</b> via the <a href="/connectors">checkcle connector</a>.</div>`;
    return;
  }
  const cards = [
    card("Monitors", String(s.total), `${s.up} up · ${s.down} down`),
    card("Up / Down", `${s.up} / ${s.down}`, "current status", s.down ? "#f87171" : "#34d399"),
    card("Avg uptime", s.avgUptime != null ? `${s.avgUptime}%` : "—", "across monitors", s.avgUptime != null ? (s.avgUptime >= 99.9 ? "#34d399" : s.avgUptime >= 99 ? "#fbbf24" : "#f87171") : undefined),
    card("SSL expiring", String(s.sslExpiringSoon), "≤ 30 days", s.sslExpiringSoon ? "#fbbf24" : "#34d399"),
    card("Open incidents", String(s.openIncidents), "unresolved", s.openIncidents ? "#f87171" : "#34d399"),
    card("Warning / paused", `${s.warning} / ${s.paused}`, "degraded / disabled"),
  ].join("");
  const byStatus = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="dot d-${esc(k)}"></span>${esc(k)} <b>${n}</b></span>`).join("");
  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="ty">${esc(k)}</span> <b>${n}</b></span>`).join("");

  const work = DATA!.worklist.length
    ? `<ul style="list-style:none;margin:0;padding:0">${DATA!.worklist.slice(0, 40).map((w) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="stt st-${w.kind === "down" ? "down" : w.kind === "ssl" ? "warning" : "warning"}">${esc(w.kind)}</span> ${esc(w.label)}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">✓ All monitors healthy — no down monitors, SSL expiries or low uptime.</div>`;
  const inc = DATA!.incidents.length
    ? `<ul style="list-style:none;margin:0;padding:0">${DATA!.incidents.slice(0, 30).map((i) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="stt st-${i.open ? "down" : "up"}">${i.open ? "open" : "resolved"}</span> ${esc(i.title)}${i.asset ? ` <span class="muted">· ${esc(i.asset)}</span>` : ""}${i.startedAt ? ` <span class="muted" style="font-size:11px">${esc(String(i.startedAt).slice(0, 16))}</span>` : ""}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">No incidents recorded.</div>`;

  const filters = `<div class="filters">
    <input id="mn-search" type="search" placeholder="Search monitor / asset / target…" style="flex:1;min-width:200px">
    <select id="mn-type"><option value="">All types</option>${(DATA!.checkTypes || []).map((x) => `<option>${esc(x)}</option>`).join("")}</select>
    <select id="mn-status"><option value="">All statuses</option>${STATUSES.map((x) => `<option>${esc(x)}</option>`).join("")}</select>
    <span id="mn-count" class="muted" style="font-size:12px"></span></div>`;

  $("mn-body").innerHTML = `<div class="mn-cards">${cards}</div>
    <div class="mn-section">By status</div><div class="breakdown">${byStatus}</div>
    <div class="mn-section">By type</div><div class="breakdown">${byType}</div>
    <div class="mn-section">Attention worklist (${DATA!.worklist.length})</div>${work}
    <div class="mn-section">Monitors</div>${filters}<div id="mn-table-host"></div>
    <div class="mn-section">Incidents (${DATA!.incidents.length})</div>${inc}
    <div class="legend">↳ Change a monitor's <b>status</b> in the table (opens/resolves an incident on up↔down).
      Import live data with the <a href="/connectors">checkcle</a> connector. Raw rows:
      <a href="/?db=XORCISM&table=MONITORINGCHECK">MONITORINGCHECK</a> / <a href="/?db=XORCISM&table=MONITORINGINCIDENT">MONITORINGINCIDENT</a>.</div>`;
  for (const id of ["mn-search", "mn-type", "mn-status"]) $(id).addEventListener("input", renderTable);
  renderTable();
}

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 6000);
}

async function setStatus(id: number, status: string): Promise<void> {
  try {
    const r = await fetch("/api/asset-monitoring/status", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ checkId: id, status }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    toast(`✅ Status → <b>${esc(status)}</b>`); await load();
  } catch (e) { toast(`⚠️ ${e}`); }
}

// ── add-monitor modal ───────────────────────────────────────────────────────────
async function loadLookup(table: string, sel: string): Promise<void> {
  try {
    const idCol = table === "ASSET" ? "AssetID" : "PersonID"; const labelCol = table === "ASSET" ? "AssetName" : "FullName";
    const r = await fetch(`/api/lookup?db=XORCISM&table=${table}&idCol=${idCol}&labelCol=${labelCol}`);
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const el = $(sel) as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; el.appendChild(o); }
  } catch { /* lookup unavailable */ }
}
function openModal(): void {
  ($("mn-f-name") as HTMLInputElement).value = "";
  ($("mn-f-type") as HTMLSelectElement).value = "http";
  ($("mn-f-target") as HTMLInputElement).value = "";
  ($("mn-f-interval") as HTMLInputElement).value = "300";
  ($("mn-f-asset") as HTMLSelectElement).value = "";
  ($("mn-f-owner") as HTMLSelectElement).value = "";
  ($("mn-f-ssl") as HTMLInputElement).value = "";
  ($("mn-f-cron") as HTMLInputElement).value = "";
  $("mn-ssl-wrap").style.display = "none";
  $("mn-f-err").textContent = "";
  $("mn-modal").classList.add("open");
  ($("mn-f-name") as HTMLInputElement).focus();
}

// ── activate-from-asset modal ────────────────────────────────────────────────────
function openActivate(): void {
  ($("mn-act-asset") as HTMLSelectElement).value = "";
  ($("mn-act-interval") as HTMLInputElement).value = "300";
  ($("mn-act-cron") as HTMLInputElement).value = "";
  ($("mn-act-owner") as HTMLSelectElement).value = "";
  document.querySelectorAll<HTMLInputElement>(".mn-act-type").forEach((c) => { c.checked = true; });
  $("mn-act-err").textContent = "";
  $("mn-act-modal").classList.add("open");
}
function closeActivate(): void { $("mn-act-modal").classList.remove("open"); }
async function runActivate(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const assetId = v("mn-act-asset");
  const err = $("mn-act-err");
  if (!assetId) { err.textContent = "⚠️ Pick an asset."; return; }
  const types = Array.from(document.querySelectorAll<HTMLInputElement>(".mn-act-type:checked")).map((c) => c.value);
  const btn = $("mn-act-go") as HTMLButtonElement; btn.disabled = true; err.textContent = "Activating…";
  try {
    const body = { assetId, intervalSeconds: v("mn-act-interval") || undefined,
      cronExpression: v("mn-act-cron").trim() || undefined, ownerPersonId: v("mn-act-owner") || undefined, types };
    const r = await fetch("/api/asset-monitoring/activate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeActivate(); await load();
    toast(d.created ? `✅ Activated ${d.created} monitor(s)${d.skipped ? ` · ${d.skipped} already existed` : ""}`
      : `✓ No new monitors — ${d.skipped} already existed, or the asset has no IP/URL`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}
function closeModal(): void { $("mn-modal").classList.remove("open"); }

async function createMonitor(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const name = v("mn-f-name").trim();
  const err = $("mn-f-err");
  if (!name) { err.textContent = "⚠️ Enter a name."; return; }
  const btn = $("mn-create") as HTMLButtonElement; btn.disabled = true; err.textContent = "Adding…";
  try {
    const body = {
      name, type: v("mn-f-type"), target: v("mn-f-target").trim() || undefined,
      intervalSeconds: v("mn-f-interval") || undefined, cronExpression: v("mn-f-cron").trim() || undefined,
      assetId: v("mn-f-asset") || undefined,
      ownerPersonId: v("mn-f-owner") || undefined, sslExpiryDate: v("mn-f-ssl") || undefined,
    };
    const r = await fetch("/api/asset-monitoring/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal(); await load(); toast(`✅ Monitor added`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function runChecks(): Promise<void> {
  const btn = $("mn-run") as HTMLButtonElement; btn.disabled = true; const label = btn.textContent; btn.textContent = "Checking…";
  try {
    const r = await fetch("/api/asset-monitoring/run-checks", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load();
    toast(d.checked ? `✅ Probed ${d.checked} due monitor(s)` : `✓ No monitors due for a check right now`);
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("mn-run").addEventListener("click", () => void runChecks());
  $("mn-new").addEventListener("click", openModal);
  $("mn-cancel").addEventListener("click", closeModal);
  $("mn-create").addEventListener("click", () => void createMonitor());
  $("mn-modal").addEventListener("click", (e) => { if (e.target === $("mn-modal")) closeModal(); });
  $("mn-activate").addEventListener("click", openActivate);
  $("mn-act-cancel").addEventListener("click", closeActivate);
  $("mn-act-go").addEventListener("click", () => void runActivate());
  $("mn-act-modal").addEventListener("click", (e) => { if (e.target === $("mn-act-modal")) closeActivate(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); closeActivate(); } });
  ($("mn-f-type") as HTMLSelectElement).addEventListener("change", (e) => { $("mn-ssl-wrap").style.display = (e.target as HTMLSelectElement).value === "ssl" ? "" : "none"; });
  void loadLookup("ASSET", "mn-f-asset");
  void loadLookup("PERSON", "mn-f-owner");
  void loadLookup("ASSET", "mn-act-asset");
  void loadLookup("PERSON", "mn-act-owner");
  void load();
});
