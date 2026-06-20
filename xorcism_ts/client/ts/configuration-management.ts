/**
 * configuration-management.ts — Configuration Management inventory + governance worklist
 * (/configuration-management). Secure-configuration content library (OVAL hardening
 * baselines) + verification worklist, from /api/configuration-management. Read-only.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface ConfigRow { id: number; pattern: string; title: string; version: string; status: string; deprecated: boolean; hasCce: boolean; platforms: number; score: number; issues: string[]; }
interface Finding { id: number; name: string; kind: "definition" | "library" | "coverage"; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Inventory {
  rows: ConfigRow[]; findings: Finding[];
  summary: { definitions: number; compliance: number; patch: number; vulnerability: number; inventory: number; miscellaneous: number; deprecated: number; accepted: number; interim: number; withCce: number; cceTotal: number; scannedAssets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; lastScan: string | null; byClass: Record<string, number>; byStatus: Record<string, number>; };
}

const stClass = (s: string): string => {
  const v = (s || "").toLowerCase();
  return /accepted/.test(v) ? "st-accepted" : /deprecat/.test(v) ? "st-deprecated" : /interim|draft|incomplete/.test(v) ? "st-interim" : "";
};
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");
const dotColor = (k: string): string => (k === "coverage" ? "#38bdf8" : k === "library" ? "#c084fc" : "#fb923c");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="cf-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: ConfigRow): string {
  const issues = r.issues.length
    ? r.issues.map((i) => `<span class="tag${/no cce|status/.test(i.toLowerCase()) ? " tag-w" : ""}">${esc(i)}</span>`).join("")
    : `<span class="ok">✓ ok</span>`;
  return `<tr>
    <td><div class="cname">${esc(r.title)}</div>${r.pattern ? `<div class="muted" style="font-size:11px"><span class="ref">${esc(r.pattern)}</span></div>` : ""}</td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${esc(r.version)}</td>
    <td>${r.hasCce ? '<span class="ok">CCE ✓</span>' : '<span class="muted">—</span>'}</td>
    <td>${r.platforms || '<span class="muted">0</span>'}</td>
    <td>${issues}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const href = f.kind === "coverage" ? "/oval-scan" : "/?db=XOVAL&table=OVALDEFINITION";
  return `<li><span class="dot" style="background:${dotColor(f.kind)}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="${href}">${esc(f.kind)}</a> — ${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/configuration-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!s.definitions) {
    $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No OVAL/SCAP configuration content imported yet. Import OVAL definitions, then the
      configuration baselines and verification worklist appear here.</div>`;
    return;
  }

  const cards = [
    card("Hardening baselines", String(s.compliance), "compliance-class checks", s.compliance ? undefined : "#64748b"),
    card("Verified", s.verdicts ? `${s.scannedAssets}` : "0", s.verdicts ? `${s.scannedAssets} asset(s) scanned` : "no scans yet", s.verdicts ? "#34d399" : "#fbbf24"),
    card("Compliance pass", s.passRate != null ? `${s.passRate}%` : "—", s.verdicts ? `${s.complianceFail} failing` : "run an OVAL scan", s.passRate != null ? (s.passRate >= 80 ? "#34d399" : s.passRate >= 50 ? "#fbbf24" : "#f87171") : undefined),
    card("Deprecated", String(s.deprecated), "in content library", s.deprecated ? "#fb923c" : "#34d399"),
    card("CCE-mapped", String(s.withCce), `of ${s.definitions} definitions`, s.withCce ? "#34d399" : undefined),
    card("Library", String(s.definitions), "OVAL definitions total"),
    card("Patch / Vuln", `${s.patch} / ${s.vulnerability}`, "patch · vulnerability checks"),
    card("Inventory", String(s.inventory), "platform/product checks"),
  ].join("");

  const byClass = Object.entries(s.byClass).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const byStatus = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="st ${stClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No deprecated, unverified or unmapped configuration baselines — clean posture.</div>`;

  const table = d.rows.length ? `<div class="cf-section">Hardening baselines (${d.rows.length})</div>
    <table class="cf"><thead><tr>
      <th>Configuration baseline</th><th>Status</th><th>Ver.</th><th>CCE</th><th>Platforms</th><th>Gaps</th><th title="Health score">Score</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>` : "";

  $("cf-body").innerHTML = `<div class="cf-cards">${cards}</div>
    <div class="cf-section">Governance worklist (${d.findings.length})</div>${findings}
    <div class="cf-section">By class</div><div class="breakdown">${byClass}</div>
    <div class="cf-section">By status</div><div class="breakdown">${byStatus}</div>
    ${table}
    <div class="legend">↳ <b>Score</b> is a baseline's health gap (higher = worse): deprecated +40, non-accepted status +15, no CCE reference +5.
      Configuration items are the compliance-class OVAL definitions; verification comes from
      <a href="/oval-scan">OVAL scans</a> (OVALRESULTS). Manage content under
      <a href="/?db=XOVAL&table=OVALDEFINITION">OVAL definitions</a>.</div>`;
}

// ── Launch an OVAL scan on an enrolled agent (localhost or remote) ───────────────
interface Target { name: string; asset: string | null; os: string | null; platform: string | null; lastSeen: string | null; online: boolean; isLocal: boolean; }

async function initLaunch(): Promise<void> {
  const sel = document.getElementById("cf-target") as HTMLSelectElement | null;
  const kindSel = document.getElementById("cf-kind") as HTMLSelectElement | null;
  const btn = document.getElementById("cf-launch-btn") as HTMLButtonElement | null;
  const stat = document.getElementById("cf-launch-stat");
  if (!sel || !kindSel || !btn || !stat) return;

  interface Sched { id: number; agent: string; ovalClass: string; cron: string; lastRun: string | null }
  let data: { localhost: string; agents: Target[]; scheduled?: Sched[] };
  try { const r = await fetch("/api/configuration/scan-targets"); if (!r.ok) throw new Error(`HTTP ${r.status}`); data = await r.json(); }
  catch (e) { sel.innerHTML = `<option value="">—</option>`; btn.disabled = true; stat.innerHTML = `⚠️ ${esc(e)}`; return; }

  const recurSel = document.getElementById("cf-recur") as HTMLSelectElement | null;
  const schedList = document.getElementById("cf-sched-list");
  const renderSchedules = (list: Sched[]) => {
    if (!schedList) return;
    schedList.innerHTML = list.length
      ? `🔁 <b>Recurring scans:</b> ${list.map((s) => `${esc(s.agent)} · ${esc(s.ovalClass)} · <code>${esc(s.cron)}</code>${s.lastRun ? ` (last ${esc(String(s.lastRun).slice(0, 16))})` : ""} <a href="/?db=XJOB&table=XSCHEDULE&filterCol=ScheduleID&filterVal=${esc(s.id)}" title="manage">#${esc(s.id)}</a>`).join(" &nbsp;·&nbsp; ")}`
      : "";
  };
  renderSchedules(data.scheduled || []);

  if (!data.agents.length) {
    sel.innerHTML = `<option value="">no enrolled agent</option>`;
    btn.disabled = true;
    stat.innerHTML = `No XOR agent enrolled yet. Deploy the agent (<code>agent/xor_agent.py</code>) on a host — <b>localhost or remote</b> — enroll it, then launch OVAL scans here. See <a href="/oval-scan">OVAL scan results</a>.`;
    return;
  }

  sel.innerHTML = data.agents.map((a) => {
    const tag = a.isLocal ? " — localhost" : "";
    const status = a.online ? "🟢 online" : "⚪ offline";
    return `<option value="${esc(a.name)}">${esc(a.name)}${tag} · ${esc(a.os || "?")} · ${status}</option>`;
  }).join("");
  const local = data.agents.find((a) => a.isLocal);
  if (local) sel.value = local.name;

  // OVAL-class sub-select only applies to OVAL scans
  const classFld = document.getElementById("cf-class-fld");
  const classSel = document.getElementById("cf-class") as HTMLSelectElement | null;
  const syncClass = () => { if (classFld) classFld.style.display = kindSel.value === "oval" ? "" : "none"; };
  kindSel.onchange = syncClass;
  syncClass();

  // button label tracks the recurrence (Launch now vs Schedule)
  const syncBtn = () => { btn.textContent = recurSel && recurSel.value !== "once" ? "Schedule scan" : "Launch scan"; };
  if (recurSel) { recurSel.onchange = syncBtn; syncBtn(); }

  btn.onclick = async () => {
    const agent = sel.value, kind = kindSel.value;
    if (!agent) return;
    const ovalClass = kind === "oval" && classSel ? classSel.value : "all";
    const recur = recurSel ? recurSel.value : "once";
    btn.disabled = true;
    try {
      if (recur !== "once") {
        // recurring → schedule it (XSCHEDULE). OVAL class only meaningful for OVAL scans.
        stat.textContent = "Scheduling…";
        const r = await fetch("/api/configuration/schedule-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, ovalClass, preset: recur }) });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
        const isLocal = data.agents.find((a) => a.name === agent)?.isLocal;
        stat.innerHTML = `✅ Scheduled <b>${esc(recur)}</b> OVAL <b>${esc(ovalClass)}</b> scan on <b>${esc(agent)}${isLocal ? " (localhost)" : ""}</b> (schedule <a href="/?db=XJOB&table=XSCHEDULE&filterCol=ScheduleID&filterVal=${esc(d.scheduleId)}">#${esc(d.scheduleId)}</a>, cron <code>${esc(d.cron)}</code>). The scheduler queues an agent job each cycle — the XOR agent runs it at check-in.`;
        renderSchedules([...(data.scheduled || []), { id: d.scheduleId, agent, ovalClass, cron: d.cron, lastRun: null }]);
        return;
      }
      stat.textContent = "Launching…";
      const r = await fetch("/api/agent-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, kind, ovalClass }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      const isLocal = data.agents.find((a) => a.name === agent)?.isLocal;
      const clsTxt = d.ovalClass ? ` (${esc(d.ovalClass)})` : "";
      stat.innerHTML = `✅ Queued <b>${esc(kind)}</b>${clsTxt} scan on <b>${esc(agent)}${isLocal ? " (localhost)" : ""}</b> (job #${esc(d.jobId)}). The XOR agent runs it at its next check-in — results then appear in the verification cards. <a href="/configuration-management">↻ Refresh</a>`;
    } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
    finally { btn.disabled = false; }
  };
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); void initLaunch(); });
