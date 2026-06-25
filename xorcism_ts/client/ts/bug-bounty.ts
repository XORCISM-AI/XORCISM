/** bug-bounty.ts — Bug Bounty management cockpit (/bug-bounty). Programmes + submissions inventory,
 * triage worklist and KPIs from /api/bug-bounty, with a guided "new program" modal. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Prog { id: number; name: string; platform: string; status: string; policyUrl: string; minReward: number | null; maxReward: number | null; currency: string; submissions: number; open: number; triaged: number; resolved: number; critical: number; high: number; scopes: number; paid: number; }
interface Sub { id: number; program: string; title: string; severity: string; status: string; open: boolean; triaged: boolean; cvss: number | null; target: string; researcher: string; reward: number | null; currency: string; vulnerabilityId: number | null; submitted: string | null; ageTriage: number | null; }
interface Data { programs: Prog[]; submissions: Sub[]; findings: { kind: string; id: number; label: string; severity: string; program: string }[]; summary: any; }

let DATA: Data | null = null;

function money(n: number | null, cur: string): string { if (n == null) return "—"; try { return new Intl.NumberFormat(undefined, { style: "currency", currency: cur || "USD", maximumFractionDigits: 0, notation: "compact" }).format(n); } catch { return String(n); } }
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="bb-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const sevCls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low", "Info"].includes(s) ? s : "Low"}`;

function progRow(p: Prog): string {
  return `<tr>
    <td><span class="pname">${esc(p.name)}</span>${p.policyUrl ? ` <a href="${esc(p.policyUrl)}" target="_blank" rel="noopener" class="muted" style="font-size:11px">${t("bb.policyLink")}</a>` : ""}</td>
    <td><span class="plat">${esc(p.platform)}</span></td>
    <td>${esc(p.status)}</td>
    <td>${p.submissions}</td>
    <td>${p.open}${p.critical || p.high ? ` <span class="muted" style="font-size:11px">(${p.critical}C/${p.high}H)</span>` : ""}</td>
    <td>${p.scopes || "<span class='muted'>0</span>"}</td>
    <td>${p.minReward != null || p.maxReward != null ? `${money(p.minReward, p.currency)}–${money(p.maxReward, p.currency)}` : "<span class='muted'>—</span>"}</td>
    <td>${p.paid ? money(p.paid, p.currency) : "<span class='muted'>—</span>"}</td>
  </tr>`;
}
function subRow(s: Sub): string {
  return `<tr>
    <td><span class="sev ${sevCls(s.severity)}">${esc(s.severity || "—")}</span></td>
    <td>${esc(s.title)}${s.vulnerabilityId ? ` <a href="/?db=XVULNERABILITY&table=VULNERABILITY&editCol=VulnerabilityID&editVal=${s.vulnerabilityId}" class="muted" style="font-size:11px">${t("bb.toVuln")}</a>` : ""}</td>
    <td class="muted" style="font-size:12px">${esc(s.program)}</td>
    <td><span class="st ${s.open ? "st-open" : "st-closed"}">${esc(s.status)}</span>${s.open && !s.triaged ? ` <span class="sev sv-Medium">${t("bb.triagePill")}</span>` : ""}</td>
    <td>${s.researcher ? esc(s.researcher) : "<span class='muted'>—</span>"}</td>
    <td>${s.reward ? money(s.reward, s.currency) : "<span class='muted'>—</span>"}</td>
  </tr>`;
}

function load(): Promise<void> {
  return fetch("/api/bug-bounty").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    DATA = d; const s = d.summary;
    if (!d.programs.length) {
      $("bb-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("bb.empty")}</div>`;
      return;
    }
    const cards = [
      card(t("bb.cProgrammes"), String(s.programs), fmt("bb.cProgrammes.foot", { n: s.active })),
      card(t("bb.cSubmissions"), String(s.submissions), fmt("bb.cSubmissions.foot", { n: s.open }), s.open ? "#fbbf24" : "#34d399"),
      card(t("bb.cTriage"), String(s.awaitingTriage), t("bb.cTriage.foot"), s.awaitingTriage ? "#f87171" : "#34d399"),
      card(t("bb.cHighCrit"), String(s.highOpen), t("bb.cHighCrit.foot"), s.highOpen ? "#f87171" : "#34d399"),
      card(t("bb.cPaid"), money(s.paid, s.currency), t("bb.cPaid.foot")),
      card(t("bb.cResearchers"), String(s.researchers), t("bb.cResearchers.foot")),
    ].join("");
    const bySev = Object.entries(s.bySeverity || {}).sort((a: any, b: any) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="sev ${sevCls(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
    const byPlat = Object.entries(s.byPlatform || {}).sort((a: any, b: any) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
    const work = d.findings.length
      ? `<ul class="worklist">${d.findings.slice(0, 40).map((f) => `<li><span class="sev ${sevCls(f.severity)}">${esc(f.severity)}</span> ${esc(f.label)}${f.program ? ` <span class="muted" style="font-size:11px;margin-left:auto">${esc(f.program)}</span>` : ""}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${t("bb.noWork")}</div>`;
    const progTable = `<table class="bb"><thead><tr><th>${t("bb.thProgram")}</th><th>${t("bb.thPlatform")}</th><th>${t("bb.thStatus")}</th><th>${t("bb.thSubs")}</th><th>${t("bb.thOpen")}</th><th>${t("bb.thScope")}</th><th>${t("bb.thReward")}</th><th>${t("bb.thPaid")}</th></tr></thead><tbody>${d.programs.map(progRow).join("")}</tbody></table>`;
    const subTable = d.submissions.length
      ? `<table class="bb"><thead><tr><th>${t("bb.thSev")}</th><th>${t("bb.thTitle")}</th><th>${t("bb.thProgram")}</th><th>${t("bb.thStatus")}</th><th>${t("bb.thResearcher")}</th><th>${t("bb.thReward2")}</th></tr></thead><tbody>${d.submissions.slice(0, 100).map(subRow).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">${t("bb.noSubs")}</div>`;
    $("bb-body").innerHTML = `<div class="bb-cards">${cards}</div>
      <div class="bb-section">${t("bb.secBySeverity")}</div><div class="breakdown">${bySev || "<span class='muted'>—</span>"}</div>
      <div class="bb-section">${t("bb.secByPlatform")}</div><div class="breakdown">${byPlat}</div>
      <div class="bb-section">${fmt("bb.secWorklist", { n: d.findings.length })}</div>${work}
      <div class="bb-section">${fmt("bb.secProgrammes", { n: d.programs.length })}</div>${progTable}
      <div class="bb-section">${fmt("bb.secSubmissions", { n: s.submissions })}</div>${subTable}`;
  }).catch((e) => { $("bb-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #fb7185;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 5000);
}
function openModal(): void { for (const id of ["bb-f-name", "bb-f-min", "bb-f-max", "bb-f-policy", "bb-f-scope"]) ($(id) as HTMLInputElement).value = ""; $("bb-f-err").textContent = ""; $("bb-modal").classList.add("open"); ($("bb-f-name") as HTMLInputElement).focus(); }
function closeModal(): void { $("bb-modal").classList.remove("open"); }
async function create(): Promise<void> {
  const v = (id: string): string => ($(id) as HTMLInputElement | HTMLSelectElement).value;
  const name = v("bb-f-name").trim(); const err = $("bb-f-err");
  if (!name) { err.textContent = t("bb.errName"); return; }
  const btn = $("bb-create") as HTMLButtonElement; btn.disabled = true; err.textContent = t("bb.creating");
  try {
    const body = { name, platform: v("bb-f-platform"), status: v("bb-f-status"), currency: v("bb-f-currency"),
      minReward: v("bb-f-min") || null, maxReward: v("bb-f-max") || null, policyUrl: v("bb-f-policy").trim() || undefined, scope: v("bb-f-scope").trim() || undefined };
    const r = await fetch("/api/bug-bounty/program", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal(); await load(); toast(t("bb.created"));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("bb-new").addEventListener("click", openModal);
  $("bb-cancel").addEventListener("click", closeModal);
  $("bb-create").addEventListener("click", () => void create());
  $("bb-modal").addEventListener("click", (e) => { if (e.target === $("bb-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  void load();
});
