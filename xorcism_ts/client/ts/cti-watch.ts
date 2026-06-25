/**
 * cti-watch.ts — "CTI that acts" view (/cti-watch).
 * Lists threat intel (KEV + reports) that affects the asset inventory; one click → ticket.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("ct-toast"); el.textContent = m; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Match { cve: string; kev: boolean; epss: number | null; severity: string; assets: { id: number; name: string }[]; reports: { id: number; name: string }[]; reasons: string[]; }
interface Impact { matches: Match[]; stats: { kev: number; reported: number; assets: number }; }

function card(m: Match): string {
  const assets = m.assets.map((a) => `<a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}" target="_blank" rel="noopener">${esc(a.name)}</a>`).join(", ");
  const reasons = m.reasons.map((r, i) => `<span class="reason${i === 0 && m.kev ? " kev" : ""}">${esc(r)}</span>`).join("");
  const reps = m.reports.length ? `<div class="rep">↳ ${m.reports.map((r) => `<a href="/?db=XTHREAT&table=THREATREPORT&editCol=ThreatReportID&editVal=${r.id}" target="_blank" rel="noopener">${esc(r.name)}</a>`).join(" · ")}</div>` : "";
  return `<div class="m" data-cve="${esc(m.cve)}">
    <div class="top">
      <span class="cve"><a href="/?db=XVULNERABILITY&table=VULNERABILITY&searchCol=VULReferential&searchVal=${encodeURIComponent(m.cve)}" target="_blank" rel="noopener">${esc(m.cve)}</a></span>
      <span class="sev sev-${esc(m.severity)}">${esc(m.severity)}</span>
      <button class="btn btn-primary btn-sm act" data-cve="${esc(m.cve)}">${t("ctw.createTicket")}</button>
    </div>
    <div>${reasons}</div>
    <div class="assets">${fmt("ctw.affects", { n: m.assets.length })} ${assets}</div>
    ${reps}
  </div>`;
}

async function ticket(btn: HTMLButtonElement): Promise<void> {
  const cve = btn.dataset.cve!; btn.disabled = true;
  try {
    const r = await fetch("/api/cti/ticket", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cve }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    btn.textContent = d.created ? fmt("ctw.ticketNew", { id: d.ticketId }) : fmt("ctw.ticketExisting", { id: d.ticketId });
    toast(d.created ? fmt("ctw.toastOpened", { id: d.ticketId, cve }) : fmt("ctw.toastExists", { cve }));
  } catch (e) { btn.disabled = false; toast(String(e)); }
}

async function load(): Promise<void> {
  let d: Impact;
  try { const r = await fetch("/api/cti/impact"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ct-body").innerHTML = `<div class="ct-empty">⚠️ ${esc(e)}</div>`; return; }
  $("ct-stats").innerHTML = `<span class="pill p-kev">${fmt("ctw.pillKev", { n: d.stats.kev })}</span><span class="pill p-rep">${fmt("ctw.pillReported", { n: d.stats.reported })}</span><span class="pill p-ast">${fmt("ctw.pillAssets", { n: d.stats.assets })}</span>`;
  if (!d.matches.length) { $("ct-body").innerHTML = `<div class="ct-empty">${t("ctw.noMatches")}</div>`; return; }
  $("ct-body").innerHTML = d.matches.map(card).join("");
  $("ct-body").querySelectorAll("button.act").forEach((b) => b.addEventListener("click", () => void ticket(b as HTMLButtonElement)));
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
