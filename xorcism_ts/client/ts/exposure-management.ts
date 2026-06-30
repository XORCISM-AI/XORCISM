/**
 * exposure-management.ts — Unified Exposure Management cockpit (/exposure-management).
 * The single exposure queue across all finding types: north-star Exposure Score + KPIs, a
 * coverage/confidence strip, filters, a Sync action, and per-exposure lifecycle (status /
 * validation / risk-accept / owner). All from /api/exposures*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

const STATE = { type: "", severity: "", status: "", validation: "", q: "", all: false };
const TYPE_LABEL: Record<string, string> = { cve: "CVE", cloud: "Cloud", crypto: "Crypto", "ai-scan": "AI scan", "ai-agent": "AI agent", identity: "Identity", data: "Data", misconfig: "Misconfig" };
function sparkline(series: any[], delta: number): string {
  if (!series || series.length < 2) return "";
  const vals = series.map((p) => Number(p.Score) || 0); const max = Math.max(...vals, 1), min = Math.min(...vals, 0);
  const w = 90, h = 22, span = max - min || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1)) * w},${h - ((v - min) / span) * h}`).join(" ");
  const col = delta > 0 ? "#fca5a5" : delta < 0 ? "#86efac" : "#94a3b8";
  return `<svg width="${w}" height="${h}" style="vertical-align:middle"><polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.5"/></svg> <span style="color:${col};font-size:10px">${delta > 0 ? "▲" : delta < 0 ? "▼" : ""}${Math.abs(delta)}</span>`;
}
const scoreColor = (n: number): string => (n >= 75 ? "#fca5a5" : n >= 50 ? "#fcd34d" : n >= 25 ? "#86efac" : "#94a3b8");
function card(lbl: string, val: string, foot: string, color?: string, cls = ""): string {
  return `<div class="ue-card ${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  const qs = new URLSearchParams();
  for (const k of ["type", "severity", "status", "validation", "q"] as const) if ((STATE as any)[k]) qs.set(k, (STATE as any)[k]);
  if (STATE.all) qs.set("all", "1");
  let d: any;
  try { d = await getJSON("/api/exposures?" + qs.toString()); } catch (e) { $("ue-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {}, cov = d.coverage || {};
  const queue: any[] = d.queue || [];

  if (!s.allTime) {
    $("ue-body").innerHTML = `<div class="ue-card" style="max-width:680px"><div class="muted" style="margin-bottom:10px">${esc(t("uem.empty", "No unified exposures yet. Click Sync to build the queue from every source — CVEs (fusion), cloud findings, crypto/PQC, AI scan & AI-agent exposure, identity SoD and audit findings. Run the underlying scanners/connectors first to populate those sources."))}</div>
      <button class="btn" id="sync">⟳ ${esc(t("uem.sync", "Sync exposures"))}</button></div>`;
    $("sync").onclick = doSync;
    return;
  }
  let trend: any = { series: [], delta: 0 };
  try { trend = await getJSON("/api/exposures/trend?days=90"); } catch { /* no trend yet */ }
  const spark = sparkline(trend.series, trend.delta || 0);
  const scoreCard = `<div class="ue-card score"><div class="lbl">${esc(t("uem.score", "Exposure Score"))}</div><div class="val" style="color:${scoreColor(s.exposureScore ?? 0)}">${s.exposureScore ?? 0}</div><div class="foot">${spark || esc(t("uem.scoreFoot", "lower is better"))}</div></div>`;
  const cards = [
    scoreCard,
    card(t("uem.open", "Open exposures"), String(s.total ?? 0), `${s.resolved ?? 0} ${esc(t("uem.resolved", "resolved"))} · ${s.riskAccepted ?? 0} ${esc(t("uem.accepted", "accepted"))}`),
    card(t("uem.critical", "Critical"), String(s.critical ?? 0), `${s.high ?? 0} ${esc(t("uem.high", "high"))}`, (s.critical ? "#fca5a5" : "#94a3b8")),
    card(t("uem.validated", "Proven-exploitable"), String(s.validatedExploitable ?? 0), t("uem.validatedFoot", "validation-confirmed"), (s.validatedExploitable ? "#fca5a5" : "#94a3b8")),
    card(t("uem.overdue", "Past SLA"), String(s.overdue ?? 0), t("uem.overdueFoot", "overdue"), (s.overdue ? "#fcd34d" : "#94a3b8")),
    card(t("uem.mttr", "MTTR"), s.mttrDays != null ? `${s.mttrDays}d` : "—", t("uem.mttrFoot", "mean time to resolve"), "#60a5fa"),
  ].join("");
  // coverage strip
  const covchips = (cov.sources || []).map((x: any) => `<span class="covchip ${x.feeding ? "on" : "off"}" title="${x.feeding ? x.count + " exposures" : "no source feeding"}">${x.feeding ? "● " : "○ "}${esc(x.label)}${x.feeding ? ` <b>${x.count}</b>` : ""}</span>`).join("");
  const cov2 = `<span class="muted" style="font-size:11px">${esc(t("uem.coverage", "Coverage"))}: <b style="color:${scoreColor(100 - (cov.confidence || 0))}">${cov.confidence ?? 0}%</b> (${cov.feeding ?? 0}/${cov.total ?? 7} ${esc(t("uem.sources", "sources"))})${cov.assets ? ` · ${cov.blindAssets} ${esc(t("uem.blind", "assets with no exposure data"))}` : ""}</span>`;

  const sevSel = (v: string) => `<option value="${v}"${STATE.severity === v ? " selected" : ""}>${v || t("uem.allSev", "All severities")}</option>`;
  const typeSel = (v: string) => `<option value="${v}"${STATE.type === v ? " selected" : ""}>${v ? TYPE_LABEL[v] || v : t("uem.allTypes", "All types")}</option>`;
  const valSel = (v: string, lbl: string) => `<option value="${v}"${STATE.validation === v ? " selected" : ""}>${esc(lbl)}</option>`;

  const rows = queue.map((e) => {
    const resolved = ["resolved", "risk-accepted"].includes(e.Status);
    const valCls = e.Validation === "validated-exploitable" ? "exploit" : e.Validation === "validated-safe" ? "safe" : "un";
    const valTxt = e.Validation === "validated-exploitable" ? "exploitable" : e.Validation === "validated-safe" ? "safe" : "unvalidated";
    return `<tr style="${resolved ? "opacity:.5" : ""}">
      <td><span class="scoredot" style="color:${scoreColor(e.Score)}">${e.Score}</span></td>
      <td><span class="tchip ${esc(e.Type)}">${esc(TYPE_LABEL[e.Type] || e.Type)}</span></td>
      <td><span class="sev ${esc(e.Severity)}">${esc(e.Severity)}</span></td>
      <td><b>${esc(e.Title)}</b><div class="muted" style="font-size:10px">${esc(e.Exploitability)} · ${esc(e.Reachability || "")}${e.SourceModule ? " · " + esc(e.SourceModule) : ""}</div></td>
      <td>${esc(e.AssetRef)}</td>
      <td><select class="status-sel" data-val="${e.ExposureID}"><option value="unvalidated"${e.Validation === "unvalidated" ? " selected" : ""}>unvalidated</option><option value="validated-exploitable"${e.Validation === "validated-exploitable" ? " selected" : ""}>exploitable</option><option value="validated-safe"${e.Validation === "validated-safe" ? " selected" : ""}>safe</option></select></td>
      <td><select class="status-sel" data-st="${e.ExposureID}">${["open", "triaged", "mobilizing", "resolved", "reopened", "risk-accepted"].map((st) => `<option${e.Status === st ? " selected" : ""}>${st}</option>`).join("")}</select></td>
      <td>${esc(e.DueDate || "")}${e.Owner ? `<div class="muted" style="font-size:10px">${esc(e.Owner)}</div>` : ""}${e.TicketRef ? `<div style="font-size:10px;color:#7dd3fc">🎫 ${esc(e.TicketRef)}</div>` : (resolved ? "" : `<button class="btn sec sm" data-mob="${e.ExposureID}" style="margin-top:2px">🎫 ${esc(t("uem.mobilize", "Mobilize"))}</button>`)}</td>
    </tr>`;
  }).join("");

  $("ue-body").innerHTML = `
    <div class="ue-cards">${cards}</div>
    <div class="cov">${covchips} ${cov2}</div>
    <div class="bar">
      <button class="btn" id="sync">⟳ ${esc(t("uem.sync", "Sync"))}</button>
      <select class="in" id="f-type">${["", ...(d.types || [])].map(typeSel).join("")}</select>
      <select class="in" id="f-sev">${["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sevSel).join("")}</select>
      <select class="in" id="f-val">${valSel("", t("uem.allVal", "Any validation"))}${valSel("validated-exploitable", "Proven-exploitable")}${valSel("unvalidated", "Unvalidated")}${valSel("validated-safe", "Proven-safe")}</select>
      <input class="in" id="f-q" placeholder="${esc(t("uem.search", "Search title / asset…"))}" value="${esc(STATE.q)}" style="flex:1;min-width:160px">
      <label class="muted" style="font-size:11px"><input type="checkbox" id="f-all"${STATE.all ? " checked" : ""}> ${esc(t("uem.showResolved", "show resolved"))}</label>
    </div>
    <table class="tt"><thead><tr>
      <th>${esc(t("uem.col.score", "Score"))}</th><th>${esc(t("uem.col.type", "Type"))}</th><th>${esc(t("uem.col.sev", "Sev"))}</th>
      <th>${esc(t("uem.col.exposure", "Exposure"))}</th><th>${esc(t("uem.col.asset", "Asset"))}</th>
      <th>${esc(t("uem.col.validation", "Validation"))}</th><th>${esc(t("uem.col.status", "Status"))}</th><th>${esc(t("uem.col.due", "Due / owner"))}</th>
    </tr></thead><tbody>${rows || `<tr><td colspan="8" class="muted">${esc(t("uem.noMatch", "No exposures match the filters."))}</td></tr>`}</tbody></table>
    <div class="muted" style="font-size:11px;margin-top:8px">${queue.length} ${esc(t("uem.shown", "shown"))} · ${esc(t("uem.byType", "by type"))}: ${Object.entries(s.byType || {}).map(([k, v]) => `${TYPE_LABEL[k] || k} ${v}`).join(" · ")}</div>`;

  $("sync").onclick = doSync;
  (document.getElementById("f-type") as HTMLSelectElement).onchange = (e) => { STATE.type = (e.target as HTMLSelectElement).value; load(); };
  (document.getElementById("f-sev") as HTMLSelectElement).onchange = (e) => { STATE.severity = (e.target as HTMLSelectElement).value; load(); };
  (document.getElementById("f-val") as HTMLSelectElement).onchange = (e) => { STATE.validation = (e.target as HTMLSelectElement).value; load(); };
  (document.getElementById("f-all") as HTMLInputElement).onchange = (e) => { STATE.all = (e.target as HTMLInputElement).checked; load(); };
  const qi = document.getElementById("f-q") as HTMLInputElement;
  let timer: any; qi.oninput = () => { clearTimeout(timer); timer = setTimeout(() => { STATE.q = qi.value.trim(); load(); }, 300); };
  document.querySelectorAll<HTMLSelectElement>("[data-val]").forEach((sel) => { sel.onchange = async () => { await postJSON(`/api/exposures/${sel.dataset.val}/validate`, { validation: sel.value }); load(); }; });
  document.querySelectorAll<HTMLSelectElement>("[data-st]").forEach((sel) => { sel.onchange = async () => {
    if (sel.value === "risk-accepted") { const note = prompt(t("uem.acceptPrompt", "Risk-acceptance note:") || "Risk-acceptance note:") || ""; await postJSON(`/api/exposures/${sel.dataset.st}/accept-risk`, { note }); }
    else await postJSON(`/api/exposures/${sel.dataset.st}/status`, { status: sel.value }); load(); }; });
  document.querySelectorAll<HTMLElement>("[data-mob]").forEach((b) => { b.onclick = async () => { const r = await postJSON(`/api/exposures/${b.dataset.mob}/mobilize`, {}); if (r.ticket) alert(t("uem.mobilized", "Remediation ticket opened:") + " " + r.ticket); load(); }; });
}

async function doSync(): Promise<void> {
  const btn = document.getElementById("sync") as HTMLButtonElement; if (btn) { btn.disabled = true; btn.textContent = "⟳ " + t("uem.syncing", "Syncing…"); }
  const r = await postJSON("/api/exposures/sync");
  if (btn) { (window as any).__lastSync = r; }
  load();
}

load();
