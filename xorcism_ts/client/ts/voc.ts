/** voc.ts — Vulnerability Operations Center cockpit (/voc). Reads /api/voc. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const slaCls = (s: string): string => `sla-${["breached", "approaching", "within"].includes(s) ? s : "within"}`;
const pctColor = (p: number | null): string => (p == null ? "#64748b" : p >= 80 ? "#4ade80" : p >= 50 ? "#fbbf24" : "#f87171");

function load(): void {
  fetch("/api/voc").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card(t("voc.cBacklog"), String(s.backlog), fmt("voc.cBacklog.foot", { c: s.criticalOpen, k: s.kevOpen }), s.backlog ? undefined : "#4ade80"),
      card(t("voc.cSla"), s.slaCompliance == null ? "—" : `${s.slaCompliance}%`, fmt("voc.cSla.foot", { n: s.breached }), pctColor(s.slaCompliance)),
      card(t("voc.cMttr"), s.mttrDays == null ? "—" : fmt("voc.dD", { n: s.mttrDays }), t("voc.cMttr.foot"), s.mttrDays != null && s.mttrDays <= 30 ? "#4ade80" : "#fbbf24"),
      card(t("voc.cCoverage"), s.coverage == null ? "—" : `${s.coverage}%`, fmt("voc.cCoverage.foot", { r: s.remediated, t: s.total }), pctColor(s.coverage)),
      card(t("voc.cVelocity"), String(s.velocity30), t("voc.cVelocity.foot"), "#60a5fa"),
      card(t("voc.cAvgAge"), fmt("voc.dD", { n: s.avgAgeDays }), fmt("voc.cAvgAge.foot", { n: s.unassigned }), s.avgAgeDays > 60 ? "#fbbf24" : undefined),
    ].join("");

    const work = d.worklist.length
      ? `<table class="t"><thead><tr><th>${t("voc.thCve")}</th><th>${t("voc.thAsset")}</th><th>${t("voc.thSev")}</th><th>${t("voc.thEpss")}</th><th>${t("voc.thSla")}</th><th>${t("voc.thAge")}</th><th>${t("voc.thOwner")}</th><th></th></tr></thead><tbody>${d.worklist.map((w: any) => `<tr>
          <td>${w.vulnId ? `<a href="/?db=XVULNERABILITY&table=VULNERABILITY&editCol=VulnerabilityID&editVal=${w.vulnId}" title="${t("voc.editVulnTitle")}" style="text-decoration:none"><span class="mono">${esc(w.cve)}</span></a>` : `<span class="mono">${esc(w.cve)}</span>`}${w.kev ? ` <span class="kev">KEV</span>` : ""}</td><td>${esc(w.asset)}</td>
          <td><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span></td><td>${w.epss != null ? Math.round(w.epss * 100) + "%" : "—"}</td>
          <td><span class="sla ${slaCls(w.slaStatus)}">${esc(w.slaStatus)}${w.overdueDays ? fmt("voc.overdueD", { n: w.overdueDays }) : ""}</span></td>
          <td>${w.ageDays != null ? fmt("voc.dD", { n: w.ageDays }) : "—"}</td><td>${w.owner ? esc(w.owner) : `<span class='muted'>${t("voc.unassigned")}</span>`}</td>
          <td style="white-space:nowrap"><button class="btn-sm2 assign" data-id="${w.id}">${t("voc.btnAssign")}</button> <button class="btn-sm2 remed" data-id="${w.id}">${t("voc.btnRemediate")}</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">${t("voc.emptyBacklog")}</div>`;

    const sla = d.slaPolicy.map((p: any) => `<div class="slarow"><span class="sev ${scls(p.tier === "KEV" ? "Critical" : p.tier)}">${esc(p.tier)}</span><span class="muted">${esc(p.label)}</span><span class="spacer" style="flex:1"></span><input class="dn sla-d" data-tier="${esc(p.tier)}" type="number" value="${p.days}" min="1"> <span class="muted">${t("voc.days")}</span></div>`).join("");
    const ageMax = Math.max(1, ...Object.values(d.aging).map((x) => Number(x)));
    const aging = Object.entries(d.aging).map(([k, v]: any) => `<div class="agerow"><span class="nm2">${fmt("voc.ageDays", { k: esc(k) })}</span><div class="bar"><i style="width:${(Number(v) / ageMax) * 100}%;background:${k === "90+" ? "#f87171" : k === "61-90" ? "#fbbf24" : "#4ade80"}"></i></div><span style="min-width:30px;text-align:right">${v}</span></div>`).join("");
    const camps = d.campaigns.length ? d.campaigns.map((c: any) => `<div class="camprow"><span class="nm2">${esc(c.name)}</span><span class="muted" style="font-size:11px">${fmt("voc.campMeta", { scope: esc(c.scope), target: esc(c.target) })}</span><span class="spacer" style="flex:1"></span><div class="bar"><i style="width:${c.pct}%"></i></div><span style="min-width:60px;text-align:right">${c.done}/${c.total} (${c.pct}%)</span></div>`).join("") : `<div class="muted">${t("voc.noCampaigns")}</div>`;
    const excs = d.exceptions.length ? d.exceptions.map((e: any) => `<div class="camprow"><span class="nm2" style="min-width:auto"><b style="color:#e2e8f0">${esc(e.title)}</b></span><span class="muted" style="font-size:11px">${fmt("voc.excMeta", { by: esc(e.approvedBy), expiry: esc(e.expiry) })}${e.expired ? t("voc.expired") : ""}</span></div>`).join("") : `<div class="muted">${t("voc.noExceptions")}</div>`;

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${fmt("voc.secWorklist", { n: d.worklist.length })}<span class="spacer"></span><button class="btn-sm2" id="new-camp">${t("voc.newCampaign")}</button> <button class="btn-sm2" id="new-exc">${t("voc.newException")}</button></div>${work}
      <div class="grid2" style="margin-top:8px">
        <div class="panel"><div class="sec" style="margin-top:0">${t("voc.secSla")}</div>${sla}</div>
        <div class="panel"><div class="sec" style="margin-top:0">${t("voc.secAging")}</div>${aging}</div>
      </div>
      <div class="sec">${fmt("voc.secCampaigns", { n: d.campaigns.length })}</div><div class="panel">${camps}</div>
      <div class="sec">${fmt("voc.secExceptions", { n: d.exceptions.length })}</div><div class="panel">${excs}</div>`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function post(url: string, body: unknown, msg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast(msg); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll(".remed"), (b: HTMLElement) => { b.onclick = () => post(`/api/voc/instance/${b.getAttribute("data-id")}/remediate`, {}, t("voc.toastRemediated")); });
  Array.prototype.forEach.call(document.querySelectorAll(".assign"), (b: HTMLElement) => { b.onclick = () => { const td = prompt(t("voc.promptTargetDate")); if (td == null) return; post(`/api/voc/instance/${b.getAttribute("data-id")}/assign`, { targetDate: td, priority: "High" }, t("voc.toastAssigned")); }; });
  Array.prototype.forEach.call(document.querySelectorAll(".sla-d"), (inp: HTMLInputElement) => { inp.onchange = () => post("/api/voc/sla", { tier: inp.getAttribute("data-tier"), days: Number(inp.value) }, t("voc.toastSlaUpdated")); });
  $("new-camp").onclick = () => { const name = prompt(t("voc.promptCampName")); if (!name) return; const scope = prompt(t("voc.promptScope"), "kev") || "all"; const targetDate = prompt(t("voc.promptCampTarget")) || ""; post("/api/voc/campaign", { name, scope, targetDate }, t("voc.toastCampCreated")); };
  $("new-exc").onclick = () => { const title = prompt(t("voc.promptExcTitle")); if (!title) return; const justification = prompt(t("voc.promptJustification")) || ""; const approvedBy = prompt(t("voc.promptApprovedBy")) || ""; const expiryDate = prompt(t("voc.promptExpiry")) || ""; post("/api/voc/exception", { title, justification, approvedBy, expiryDate, scope: "cve" }, t("voc.toastExcRecorded")); };
}
document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
