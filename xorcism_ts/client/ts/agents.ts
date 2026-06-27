/**
 * agents.ts — client for /agents. XOR agent fleet management: inventory (status / last-seen /
 * platform), recent jobs and events, and per-agent tasking (launch a scan → POST /api/agent-scan).
 * Consumes the existing agent admin API (/api/agents-overview, /api/agent-scan).
 */
// NB: import as T — `t` is used as a local/param in this file (toast()'s `const t`, .map((t)=>…)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }
function fmtBytes(n: number): string { if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(i ? 1 : 0)} ${u[i]}`; }

let kinds: string[] = ["inventory", "vuln", "oval", "av", "hunt", "full", "emulate", "forensics", "rustinel", "yara"];

/** "5m ago" / "3h ago" from a minutes-ago integer. */
function ago(mins: number | null): string {
  if (mins == null) return T("agt.never");
  if (mins < 1) return T("agt.justNow");
  if (mins < 60) return fmt("agt.minsAgo", { n: mins });
  if (mins < 1440) return fmt("agt.hoursAgo", { n: Math.round(mins / 60) });
  return fmt("agt.daysAgo", { n: Math.round(mins / 1440) });
}

function render(d: any): string {
  const s = d.summary || {};
  const agents = (d.agents || []) as any[];
  const jobs = (d.jobs || []) as any[];
  const events = (d.events || []) as any[];
  const honeypot = (d.honeypot || []) as any[];
  const topPorts = (d.honeypotTopPorts || []) as any[];
  const memDumps = (d.memDumps || []) as any[];
  const logHunts = (d.logHunts || []) as any[];
  kinds = d.kinds && d.kinds.length ? d.kinds : kinds;
  const kindOpts = kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
  const healthColor = s.health == null ? "#94a3b8" : s.health >= 80 ? "#22c55e" : s.health >= 50 ? "#fbbf24" : "#f87171";
  const srColor = s.successRate == null ? "#94a3b8" : s.successRate >= 90 ? "#22c55e" : s.successRate >= 70 ? "#fbbf24" : "#f87171";
  return `
  <div class="cards">
    <div class="card"><div class="lbl">${T("agt.cAgents")}</div><div class="val">${s.total || 0}</div><div class="foot">${fmt("agt.cAgentsF", { on: s.online || 0, idle: s.idle || 0, off: s.offline || 0 })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cHealth")}</div><div class="val" style="color:${healthColor}">${s.health == null ? "—" : s.health + "%"}</div><div class="foot">${T("agt.cHealthF")}</div></div>
    <div class="card"><div class="lbl">${T("agt.cPending")}</div><div class="val" style="color:#60a5fa">${s.jobsPending || 0}</div><div class="foot">${fmt("agt.cPendingF", { n: s.jobsTotal || 0 })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cSuccess")}</div><div class="val" style="color:${srColor}">${s.successRate == null ? "—" : s.successRate + "%"}</div><div class="foot">${fmt("agt.cSuccessF", { done: s.jobsDone || 0, failed: s.jobsFailed || 0 })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cScans")}</div><div class="val">${s.scans24h || 0}</div><div class="foot">${T("agt.cScansF")}</div></div>
    <div class="card"><div class="lbl">${T("agt.cAlerts")}</div><div class="val" style="color:${s.alerts ? "#f87171" : "#22c55e"}">${s.alerts || 0}</div><div class="foot">${T("agt.cAlertsF")}</div></div>
    <div class="card"><div class="lbl">${T("agt.cHoneypot")}</div><div class="val" style="color:${s.honeypotHits ? "#fb923c" : "#94a3b8"}">${s.honeypotHits || 0}</div><div class="foot">${fmt("agt.cHoneypotF", { n: s.honeypotIps || 0 })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cRam")}</div><div class="val" style="color:${s.memDumps ? "#a78bfa" : "#94a3b8"}">${s.memDumps || 0}</div><div class="foot">${fmt("agt.cRamF", { n: s.memDumpsCompleted || 0, b: fmtBytes(s.memDumpBytes || 0) })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cLogHunts")}</div><div class="val" style="color:${s.logHuntsSuspicious ? "#f87171" : s.logHunts ? "#22c55e" : "#94a3b8"}">${s.logHunts || 0}</div><div class="foot">${fmt("agt.cLogHuntsF", { n: s.logHuntsSuspicious || 0, e: s.logHuntEvents || 0 })}</div></div>
    <div class="card"><div class="lbl">${T("agt.cIocs")}</div><div class="val">${s.iocs || 0}</div><div class="foot">${T("agt.cIocsF")}</div></div>
  </div>

  <div class="sec">${T("agt.secFleet")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${T("agt.fleetNote")}</span></div>
  <table class="t"><thead><tr><th>${T("agt.thStatus")}</th><th>${T("agt.thAgent")}</th><th>${T("agt.thPlatform")}</th><th>${T("agt.thAddress")}</th><th>${T("agt.thLastSeen")}</th><th>${T("agt.thLaunch")}</th></tr></thead><tbody>
    ${agents.map((a) => `<tr>
      <td><span class="st st-${esc(a.freshness)}"><span class="dot"></span>${esc(a.freshness)}</span></td>
      <td><span class="nm lnk" data-detail="${esc(a.name)}">${esc(a.name)}</span>${a.asset_name && a.asset_name !== a.name ? `<div class="muted" style="font-size:11px">${T("agt.assetLabel")} ${esc(a.asset_name)}</div>` : ""}${a.version ? `<div class="muted" style="font-size:11px">v${esc(a.version)}</div>` : ""}</td>
      <td>${esc(a.os || "")}${a.platform ? ` <span class="muted">/ ${esc(a.platform)}</span>` : ""}</td>
      <td class="mono">${esc(a.ip || a.fqdn || "—")}</td>
      <td class="muted" style="font-size:12px">${ago(a.minsAgo)}</td>
      <td style="white-space:nowrap"><select class="kind" data-agent="${esc(a.name)}">${kindOpts}</select> <button class="run" data-agent="${esc(a.name)}">${T("agt.run")}</button></td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">${T("agt.noAgents")} <span class="mono">xor_agent.py --enroll</span>.</td></tr>`}
  </tbody></table>

  <div class="sec">${T("agt.secJobs")}</div>
  <table class="t"><thead><tr><th>#</th><th>${T("agt.thAgent")}</th><th>${T("agt.thScan")}</th><th>${T("agt.thStatus")}</th><th>${T("agt.thResult")}</th><th>${T("agt.thWhen")}</th></tr></thead><tbody>
    ${jobs.map((j) => `<tr><td class="muted">${j.AgentJobID}</td><td>${esc(j.agent)}</td><td><span class="mono">${esc(j.kind)}</span></td><td><span class="jb jb-${esc(j.status)}">${esc(j.status)}</span></td><td class="muted" style="font-size:12px">${esc((j.result_summary || "").slice(0, 120))}</td><td class="muted" style="font-size:11px">${esc((j.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${T("agt.noJobs")}</td></tr>`}
  </tbody></table>

  <div class="sec">${T("agt.secEvents")}</div>
  <table class="t"><thead><tr><th>${T("agt.thAgent")}</th><th>${T("agt.thType")}</th><th>${T("agt.thSeverity")}</th><th>${T("agt.thTitle")}</th><th>${T("agt.thWhen")}</th></tr></thead><tbody>
    ${events.map((e) => `<tr><td>${esc(e.agent)}</td><td><span class="mono">${esc(e.type)}</span></td><td><span class="sev sev-${esc(e.severity || "info")}">${esc(e.severity || "info")}</span></td><td>${esc(e.title || "")}</td><td class="muted" style="font-size:11px">${esc((e.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${T("agt.noEvents")}</td></tr>`}
  </tbody></table>

  <div class="sec">🍯 ${T("agt.secHoneypot")} <span class="spacer"></span>${topPorts.length ? `<span class="muted" style="font-size:11px;text-transform:none">${T("agt.topPorts")} ${topPorts.map((p: any) => `${esc(p.port)} (${esc(p.hits)})`).join(" · ")}</span>` : ""}</div>
  <table class="t"><thead><tr><th>${T("agt.thWhen")}</th><th>${T("agt.thAgent")}</th><th>${T("agt.thSrcIp")}</th><th>${T("agt.thPort")}</th><th>${T("agt.thService")}</th><th>${T("agt.thBanner")}</th></tr></thead><tbody>
    ${honeypot.map((h) => `<tr><td class="muted" style="font-size:11px">${esc((h.hit_at || h.created_at || "").slice(0, 19))}</td><td>${esc(h.agent)}</td><td class="mono">${esc(h.src_ip || "—")}${h.src_port ? `<span class="muted">:${esc(h.src_port)}</span>` : ""}</td><td class="mono">${esc(h.dst_port ?? "—")}</td><td>${esc(h.service || "")}</td><td class="muted mono" style="font-size:11px">${esc((h.banner || "").slice(0, 80))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${T("agt.noHoneypot")}</td></tr>`}
  </tbody></table>

  <div class="sec">&#129516; ${T("agt.secMemdumps")}</div>
  <table class="t"><thead><tr><th>${T("agt.thWhen")}</th><th>${T("agt.thAgent")}</th><th>${T("agt.thStatus")}</th><th>${T("agt.thTool")}</th><th>${T("agt.thSize")}</th><th>${T("agt.thImagePath")}</th></tr></thead><tbody>
    ${memDumps.map((m) => `<tr><td class="muted" style="font-size:11px">${esc((m.finished_at || m.created_at || "").slice(0, 19))}</td><td>${esc(m.agent)}</td><td><span class="sev sev-${m.status === "completed" ? "info" : m.status === "error" || m.status === "no-tool" ? "medium" : "low"}">${esc(m.status || "?")}</span></td><td class="mono">${esc(m.tool || "—")}</td><td>${m.size_bytes ? fmtBytes(m.size_bytes) : "—"}</td><td class="muted mono" style="font-size:11px;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(m.sha256 || "")}">${esc(m.path || m.error || "—")}${m.sha256 ? `<br>${esc(String(m.sha256).slice(0, 32))}…` : ""}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${T("agt.noMemdumps")}</td></tr>`}
  </tbody></table>

  <div class="sec">&#129302; ${T("agt.secLogHunts")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${T("agt.logHuntsNote")}</span></div>
  <table class="t"><thead><tr><th>${T("agt.thWhen")}</th><th>${T("agt.thAgent")}</th><th>${T("agt.thSource")}</th><th>${T("agt.thSeverity")}</th><th>${T("agt.thEvents")}</th><th>ATT&amp;CK</th><th>${T("agt.thAiVerdict")}</th></tr></thead><tbody>
    ${logHunts.map((l) => `<tr><td class="muted" style="font-size:11px">${esc((l.created_at || "").slice(0, 19))}</td><td>${esc(l.agent)}</td><td class="mono" style="font-size:11px">${esc(l.source || "")}</td><td><span class="sev sev-${["critical", "high"].includes(String(l.severity || "").toLowerCase()) ? "high" : String(l.severity || "").toLowerCase() === "medium" ? "medium" : "info"}">${esc(l.severity || "info")}</span></td><td>${esc(l.event_count ?? 0)}</td><td class="mono" style="font-size:10px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(l.techniques || "")}">${esc(l.techniques || "—")}</td><td class="muted" style="font-size:11px;max-width:420px">${esc(String(l.summary || "").slice(0, 200))}${l.hunt_id ? ` <a href="/?db=XTHREAT&table=HUNT&filterCol=HuntID&filterVal=${esc(l.hunt_id)}">${fmt("agt.huntLink", { n: esc(l.hunt_id) })}</a>` : ""}${l.ai_used ? "" : ` <span class="muted">${T("agt.heuristic")}</span>`}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">${T("agt.noLogHunts")}</td></tr>`}
  </tbody></table>`;
}

// ── per-agent detail drawer ──────────────────────────────────────────────────────────────
const jbBadge = (s: string): string => `<span class="jb jb-${esc(s)}">${esc(s)}</span>`;
function flagSev(s: string): string { const v = (s || "info").toLowerCase(); return `fl-${["critical", "high", "medium", "low"].includes(v) ? v : "info"}`; }

function drawerHtml(d: any): string {
  const a = d.agent || {}; const jobs = (d.jobs || []) as any[]; const events = (d.events || []) as any[];
  const forensics = (d.forensics || []) as any[]; const oval = d.oval || {}; const orow = oval.row; const ofind = (oval.findings || []) as any[];
  return `<div class="drawer" onclick="event.stopPropagation()">
    <h2><span class="st st-${esc(a.freshness)}"><span class="dot"></span></span> ${esc(a.name)} <span class="x" id="dw-close">&times;</span></h2>
    <div class="kv"><span><b>${T("agt.thStatus")}</b> ${esc(a.freshness)}</span><span><b>${T("agt.dwLastSeen")}</b> ${ago(a.minsAgo)}</span><span><b>OS</b> ${esc(a.os || "—")}${a.platform ? " / " + esc(a.platform) : ""}</span><span><b>${T("agt.dwVersion")}</b> ${esc(a.version || "—")}</span><span><b>${T("agt.thAddress")}</b> ${esc(a.ip || a.fqdn || "—")}</span></div>

    <div class="sec" style="margin-top:14px">${T("agt.dwOval")}</div>
    ${orow ? `<div class="kv"><span><b>${T("agt.dwLastScan")}</b> ${esc((orow.lastScan || "").slice(0, 19) || "—")}</span><span><b>${T("agt.dwVuln")}</b> ${orow.vuln || 0}</span><span><b>${T("agt.dwCompliance")}</b> ${fmt("agt.dwPassFail", { p: orow.compliancePass || 0, f: orow.complianceFail || 0 })}</span><span><b>${T("agt.dwTotalVerdicts")}</b> ${orow.total || 0}</span></div>
      <table class="t"><thead><tr><th>${T("agt.dwClass")}</th><th>${T("agt.dwFinding")}</th><th>${T("agt.thSeverity")}</th></tr></thead><tbody>${ofind.map((f) => `<tr><td class="mono">${esc(f.cls)}</td><td>${esc(f.title || "")}</td><td><span class="fl ${flagSev(f.severity)}">${esc(f.severity || "—")}</span></td></tr>`).join("") || `<tr><td colspan="3" class="muted">${T("agt.dwNoFindings")}</td></tr>`}</tbody></table>`
      : `<div class="muted" style="font-size:12px">${T("agt.dwNoOval")}</div>`}

    <div class="sec" style="margin-top:14px">${T("agt.dwTriage")} <span class="muted" style="font-size:11px;text-transform:none">${T("agt.dwTriageNote")}</span></div>
    <table class="t"><thead><tr><th>#</th><th>OS</th><th>${T("agt.dwCollected")}</th><th>${T("agt.dwFlags")}</th></tr></thead><tbody>
      ${forensics.map((tr) => `<tr class="triage" data-triage="${tr.TriageID}"><td class="muted">${tr.TriageID}</td><td>${esc(tr.host_os || "")}</td><td class="muted" style="font-size:12px">${esc((tr.collected_at || "").slice(0, 19))}</td><td>${tr.flag_count || 0}</td></tr><tr><td colspan="4" style="padding:0;border:0"><div id="tri-${tr.TriageID}"></div></td></tr>`).join("") || `<tr><td colspan="4" class="muted">${T("agt.dwNoTriage")}</td></tr>`}
    </tbody></table>

    <div class="sec" style="margin-top:14px">${fmt("agt.dwJobHistory", { n: jobs.length })}</div>
    <table class="t"><thead><tr><th>#</th><th>${T("agt.thScan")}</th><th>${T("agt.thStatus")}</th><th>${T("agt.thResult")}</th><th>${T("agt.thWhen")}</th></tr></thead><tbody>
      ${jobs.map((j) => `<tr><td class="muted">${j.AgentJobID}</td><td class="mono">${esc(j.kind)}</td><td>${jbBadge(j.status)}</td><td class="muted" style="font-size:12px">${esc((j.result_summary || "").slice(0, 140))}</td><td class="muted" style="font-size:11px">${esc((j.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${T("agt.dwNoJobs")}</td></tr>`}
    </tbody></table>

    <div class="sec" style="margin-top:14px">${fmt("agt.dwEvents", { n: events.length })}</div>
    <table class="t"><thead><tr><th>${T("agt.thType")}</th><th>${T("agt.thSeverity")}</th><th>${T("agt.thTitle")}</th><th>${T("agt.thWhen")}</th></tr></thead><tbody>
      ${events.map((e) => `<tr><td class="mono">${esc(e.type)}</td><td><span class="sev sev-${esc(e.severity || "info")}">${esc(e.severity || "info")}</span></td><td>${esc(e.title || "")}</td><td class="muted" style="font-size:11px">${esc((e.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">${T("agt.dwNoEvents")}</td></tr>`}
    </tbody></table>
  </div>`;
}

async function openDetail(name: string): Promise<void> {
  let ov = document.getElementById("agent-drawer");
  if (!ov) { ov = document.createElement("div"); ov.id = "agent-drawer"; ov.className = "ovl"; document.body.appendChild(ov); }
  ov.innerHTML = `<div class="drawer"><div class="muted" style="padding:20px">${fmt("agt.loadingName", { name: esc(name) })}</div></div>`;
  const close = (): void => { ov!.remove(); };
  ov.onclick = close;
  try {
    const d = await getJson(`/api/agents/${encodeURIComponent(name)}/detail`);
    ov.innerHTML = drawerHtml(d);
    document.getElementById("dw-close")?.addEventListener("click", close);
    ov.querySelectorAll<HTMLElement>(".triage").forEach((row) => {
      row.addEventListener("click", async () => {
        const id = row.dataset.triage; const tgt = document.getElementById(`tri-${id}`); if (!tgt) return;
        if (tgt.innerHTML) { tgt.innerHTML = ""; return; } // toggle
        tgt.innerHTML = `<div class="muted" style="padding:6px 9px;font-size:12px">${T("agt.loadingDots")}</div>`;
        try {
          const b = await getJson(`/api/forensic-triage?id=${encodeURIComponent(id || "")}`);
          const flags = (() => { try { const fb = typeof b.artifacts === "string" ? JSON.parse(b.artifacts) : b.artifacts; return Array.isArray(b.flags) ? b.flags : (fb && Array.isArray(fb.flags) ? fb.flags : []); } catch { return []; } })();
          tgt.innerHTML = `<div style="padding:6px 9px 10px">${flags.length ? flags.map((f: any) => `<div style="font-size:12px;margin:3px 0"><span class="fl ${flagSev(f.severity)}">${esc(f.severity || "info")}</span> <b>${esc(f.category || "")}</b> — ${esc(f.detail || "")}</div>`).join("") : `<span class="muted" style="font-size:12px">${T("agt.dwNoFlags")}</span>`}</div>`;
        } catch { tgt.innerHTML = `<div class="muted" style="padding:6px 9px;font-size:12px">${T("agt.dwBundleFail")}</div>`; }
      });
    });
  } catch (e) { ov.innerHTML = `<div class="drawer"><span class="x" id="dw-close">&times;</span><div class="muted" style="padding:20px">${fmt("agt.loadNameFail", { name: esc(name), e: esc((e as Error).message) })}</div></div>`; document.getElementById("dw-close")?.addEventListener("click", close); }
}

function wire(): void {
  document.querySelectorAll<HTMLElement>("[data-detail]").forEach((el) => {
    el.addEventListener("click", () => { void openDetail(el.dataset.detail || ""); });
  });
  document.querySelectorAll<HTMLButtonElement>("button.run").forEach((b) => {
    b.addEventListener("click", async () => {
      const agent = b.dataset.agent || "";
      const sel = b.parentElement?.querySelector<HTMLSelectElement>("select.kind");
      const kind = sel?.value || "full";
      b.disabled = true;
      try {
        const r = await fetch("/api/agent-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, kind }) });
        const d = await r.json().catch(() => ({}));
        toast(r.ok ? fmt("agt.queued", { kind, agent, id: d.id ?? "?" }) : fmt("agt.failed", { e: d.error || r.status }));
        if (r.ok) setTimeout(() => void load(), 700);
      } catch { toast(T("agt.queueFail")); }
      finally { b.disabled = false; }
    });
  });
}

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { body.innerHTML = render(await getJson("/api/agents-overview")); wire(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("agt.loadFail", { e: esc((e as Error).message) })}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); setInterval(() => void load(), 30000); });
