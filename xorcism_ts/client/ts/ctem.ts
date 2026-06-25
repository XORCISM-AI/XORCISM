/** ctem.ts — CTEM exposure cockpit (/ctem). Reads /api/ctem; ctem.org standardized taxonomy. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string): void { const el = $("toast"); el.textContent = msg; el.className = "show"; setTimeout(() => { el.className = ""; }, 2200); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const STAGE_KEY: Record<string, string> = { Discover: "ctem.stageDiscover", Prioritize: "ctem.stagePrioritize", Remediate: "ctem.stageRemediate" };
const STAGE_DESC_KEY: Record<string, string> = { Discover: "ctem.descDiscover", Prioritize: "ctem.descPrioritize", Remediate: "ctem.descRemediate" };
const stageLabel = (s: string): string => (STAGE_KEY[s] ? t(STAGE_KEY[s]) : s);
const stageDesc = (s: string): string => (STAGE_DESC_KEY[s] ? t(STAGE_DESC_KEY[s]) : "");

function post(url: string): Promise<any> { return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).then((r) => r.json()); }

function load(): void {
  fetch("/api/ctem").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card(t("ctem.cTracked"), String(s.tracked), fmt("ctem.cTracked.foot", { o: s.open, r: s.remediated })),
      card(t("ctem.cCritHigh"), `${s.criticalOpen} / ${s.highOpen}`, t("ctem.cCritHigh.foot"), s.criticalOpen ? "#f87171" : "#fbbf24"),
      card(t("ctem.cInPrioritize"), String(s.inPrioritize), fmt("ctem.cInPrioritize.foot", { d: s.inDiscover, r: s.inRemediate }), "#fbbf24"),
      card(t("ctem.cCoverage"), `${s.categoriesCovered}/${s.categoriesTotal}`, t("ctem.cCoverage.foot"), "#60a5fa"),
      card(t("ctem.cUnowned"), String(s.unassigned), t("ctem.cUnowned.foot"), s.unassigned ? "#fbbf24" : "#4ade80"),
      card(t("ctem.cCatalogue"), String(s.catalogueSize), t("ctem.cCatalogue.foot"), "#a78bfa"),
    ].join("");

    // 3-stage flow
    const flow = d.stages.map((st: any, i: number) =>
      `${i ? '<div class="arrow">&#10142;</div>' : ""}<div class="stage s-${esc(st.stage)}"><div class="n">${st.open}</div><div class="t">${esc(stageLabel(st.stage))}</div><div class="d">${esc(stageDesc(st.stage))}</div></div>`).join("");

    // category coverage
    const cats = d.categories.map((c: any) =>
      `<div class="catcard"><div class="cn">${esc(c.name)}</div><div class="cc"><span class="mono">${esc(c.code)}</span> · ${fmt("ctem.nIdentifiers", { n: c.catalogue })}</div>
        <span class="badge ${c.open ? "b-open" : "b-clear"}">${c.open ? fmt("ctem.nOpen", { n: c.open }) : (c.tracked ? fmt("ctem.nTracked", { n: c.tracked }) : t("ctem.none"))}</span></div>`).join("");

    // worklist
    const wl = d.worklist.length
      ? `<table class="t"><thead><tr><th>${t("ctem.thIdentifier")}</th><th>${t("ctem.thExposure")}</th><th>${t("ctem.thCategory")}</th><th>${t("ctem.thAsset")}</th><th>${t("ctem.thSeverity")}</th><th>${t("ctem.thStage")}</th><th>${t("ctem.thOwner")}</th><th></th></tr></thead><tbody>${d.worklist.map((e: any) => `<tr>
          <td><a class="mono" href="https://ctem.org/docs/${esc(String(e.ctemId).toLowerCase())}" target="_blank" rel="noopener">${esc(e.ctemId)}</a></td>
          <td class="nm">${esc(e.title)}</td><td>${esc(e.category)}</td>
          <td>${e.asset ? `<span>${esc(e.asset)}</span>` : ""}${e.evidence ? `<div class="muted" style="font-size:11px">${esc(e.evidence)}</div>` : (!e.asset ? '<span class="muted">—</span>' : "")}</td>
          <td><span class="sev sv-${esc(e.severity)}">${esc(e.severity)}</span></td>
          <td><span class="stg stg-${esc(e.stage)}">${esc(stageLabel(e.stage))}</span></td>
          <td>${e.owner ? esc(e.owner) : `<span class="muted">${t("ctem.unassigned")}</span>`}</td>
          <td style="white-space:nowrap">${e.stage !== "Remediate" ? `<button class="btn-sm2" data-adv="${e.id}" title="${t("ctem.advTitle")}">${t("ctem.advStageBtn")}</button> ` : ""}<button class="btn-sm2" data-rem="${e.id}" title="${t("ctem.remTitle")}">&#10003;</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:10px 0">${t("ctem.emptyWl")}</div>`;

    // catalogue browser
    const cat = d.catalogue;
    const browser = cat.groups.map((g: any) => `<details class="cat"><summary><span class="mono">${esc(g.code)}</span> ${esc(g.name)} <span class="muted" style="font-weight:400">· ${g.items.length}</span></summary>
      ${g.items.map((it: any) => `<div class="ident"><span class="iid">${esc(it.ctemId)}</span> &nbsp;<span class="it">${esc(it.title)}</span><div class="muted" style="margin-top:2px">${esc(it.description)} <a href="${esc(it.link)}" target="_blank" rel="noopener" style="color:#64748b">↗</a></div></div>`).join("")}</details>`).join("");

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${t("ctem.secProgram")}</div>
      <div class="flow">${flow}</div>
      <div class="sec">${t("ctem.secCoverage")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${fmt("ctem.coverageNote", { n: cat.total })}</span></div>
      <div class="catgrid">${cats}</div>
      <div class="sec">${fmt("ctem.secWorklist", { n: d.worklist.length })}</div>${wl}
      <div class="sec">${t("ctem.secCatalogue")}</div>${browser}
      <div class="lic">${fmt("ctem.lic", { src: esc(cat.source), n: esc(cat.total), v: esc(cat.version), lic: esc(cat.license) })}</div>`;

    document.querySelectorAll<HTMLButtonElement>("[data-adv]").forEach((b) => b.addEventListener("click", () => {
      post(`/api/ctem/exposure/${b.dataset.adv}/stage`).then((r) => { toast(r.stage ? fmt("ctem.toastAdvanced", { s: stageLabel(r.stage) }) : t("ctem.toastAdvanced2")); load(); }).catch(() => toast(t("ctem.toastFailed")));
    }));
    document.querySelectorAll<HTMLButtonElement>("[data-rem]").forEach((b) => b.addEventListener("click", () => {
      fetch(`/api/ctem/exposure/${b.dataset.rem}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "Remediated" }) })
        .then((r) => r.json()).then(() => { toast(t("ctem.toastRemediated")); load(); }).catch(() => toast(t("ctem.toastFailed")));
    }));
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  load();
  $("btn-discover").addEventListener("click", () => {
    const btn = $("btn-discover") as HTMLButtonElement; btn.disabled = true;
    post("/api/ctem/discover").then((r) => { toast(r.created != null ? fmt("ctem.toastDiscovered", { n: r.created, s: r.scanned }) : t("ctem.toastDone")); load(); })
      .catch(() => toast(t("ctem.toastDiscFailed"))).finally(() => { btn.disabled = false; });
  });
});
