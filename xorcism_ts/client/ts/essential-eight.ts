/** essential-eight.ts — ASD Essential Eight Maturity Model cockpit (/essential-eight).
 *  8 mitigation strategies × maturity levels ML0–ML3, backed by the imported ACSC ISM controls.
 *  Reads /api/essential-eight; per-strategy self-assessment + ISM-control drill-in. */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2800); }

interface Strat { id: string; name: string; group: string; description: string; current: number; target: number; gap: number; notes: string; owner: string; controls: number; controlsByLevel: Record<string, number>; }
interface Data {
  levels: { level: number; name: string; summary: string }[];
  strategies: Strat[];
  summary: { overall: number; overallName: string; target: number; atTarget: number; belowTarget: number; assessed: number; avg: number; ismControls: number };
  worklist: { strategy: string; current: number; target: number; reason: string }[];
}
let DATA: Data | null = null;
const ML_COLOR = ["#f87171", "#fbbf24", "#60a5fa", "#34d399"];

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const mlBadge = (n: number): string => `<span class="ml" style="background:${ML_COLOR[n]}22;color:${ML_COLOR[n]};border:1px solid ${ML_COLOR[n]}">ML${n}</span>`;
const mlSelect = (cls: string, sid: string, val: number): string =>
  `<select class="dn ${cls}" data-s="${sid}">${[0, 1, 2, 3].map((l) => `<option value="${l}"${l === val ? " selected" : ""}>ML${l}</option>`).join("")}</select>`;

function strategyCard(s: Strat): string {
  const bars = [1, 2, 3].map((l) => `<span class="lvchip" title="${fmt("ess8.ctrlsAtMl", { n: s.controlsByLevel["ML" + l] || 0, l })}">ML${l}: ${s.controlsByLevel["ML" + l] || 0}</span>`).join("");
  return `<div class="st" data-strat="${s.id}">
    <div class="sth">
      <span class="snm">${esc(s.name)}</span> ${mlBadge(s.current)}
      <span class="spacer" style="flex:1"></span>
      <span class="muted" style="font-size:11px">${fmt("ess8.controlsN", { n: s.controls })}</span>
      <button class="btn-sm2 ess-controls" data-s="${s.id}">${t("ess8.viewControls")}</button>
    </div>
    <div class="muted" style="font-size:12px;margin:3px 0 8px">${esc(s.description)}</div>
    <div class="strow">
      <label>${t("ess8.current")} ${mlSelect("cur", s.id, s.current)}</label>
      <label>${t("ess8.target")} ${mlSelect("tgt", s.id, s.target)}</label>
      <input class="inp owner" data-s="${s.id}" value="${esc(s.owner)}" placeholder="${esc(t("ess8.ownerPh"))}" style="max-width:160px">
      <button class="btn ess-save" data-s="${s.id}">${t("ess8.save")}</button>
      <span class="lvchips">${bars}</span>
    </div>
    <div class="ctrlbox" id="cb-${s.id}"></div>
  </div>`;
}

function render(d: Data): void {
  DATA = d; const s = d.summary;
  const cards = [
    card(t("ess8.cOverall"), "ML" + s.overall, s.overallName, ML_COLOR[s.overall]),
    card(t("ess8.cTarget"), "ML" + s.target, t("ess8.cTargetF")),
    card(t("ess8.cAtTarget"), `${s.atTarget}/8`, t("ess8.cAtTargetF"), s.atTarget >= 8 ? "#34d399" : "#fbbf24"),
    card(t("ess8.cBelow"), String(s.belowTarget), t("ess8.cBelowF"), s.belowTarget ? "#f87171" : "#34d399"),
    card(t("ess8.cIsm"), String(s.ismControls), t("ess8.cIsmF"), "#a78bfa"),
  ].join("");

  const groups: Record<string, Strat[]> = {};
  for (const st of d.strategies) (groups[st.group] ||= []).push(st);
  const groupHtml = Object.entries(groups).map(([g, list]) =>
    `<div class="sec">${esc(g)}</div>${list.map(strategyCard).join("")}`).join("");

  const work = d.worklist.length
    ? `<table class="t"><thead><tr><th>${t("ess8.thStrategy")}</th><th>${t("ess8.thCurrent")}</th><th>${t("ess8.thTarget")}</th><th>${t("ess8.thGap")}</th></tr></thead><tbody>${
        d.worklist.map((w) => `<tr><td class="nm">${esc(w.strategy)}</td><td>${mlBadge(w.current)}</td><td>ML${w.target}</td><td class="muted">${esc(w.reason)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ess8.allAtTarget")}</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>
    <div class="note">${fmt("ess8.scoringNote", { ml: s.overall })}</div>
    <div class="sec">${fmt("ess8.secGaps", { n: d.worklist.length })}</div>${work}
    ${groupHtml}`;
  wire();
}

function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll(".ess-save"), (b: HTMLElement) => { b.onclick = () => save(b.getAttribute("data-s")!); });
  Array.prototype.forEach.call(document.querySelectorAll(".ess-controls"), (b: HTMLElement) => { b.onclick = () => toggleControls(b.getAttribute("data-s")!); });
}

function save(sid: string): void {
  const cur = Number((document.querySelector(`.cur[data-s="${sid}"]`) as HTMLSelectElement).value);
  const tgt = Number((document.querySelector(`.tgt[data-s="${sid}"]`) as HTMLSelectElement).value);
  const owner = (document.querySelector(`.owner[data-s="${sid}"]`) as HTMLInputElement).value;
  fetch("/api/essential-eight/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ strategy: sid, current: cur, target: tgt, owner }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j: Data) => { render(j); toast(t("ess8.saved")); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function toggleControls(sid: string): void {
  const box = $(`cb-${sid}`);
  if (box.innerHTML) { box.innerHTML = ""; return; }
  box.innerHTML = `<div class="muted" style="font-size:12px;padding:6px 0">${t("ess8.loading")}</div>`;
  fetch(`/api/essential-eight/controls/${sid}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { strategy: string; controls: { id: string; text: string; levels: string[]; chapter: string }[] }) => {
      box.innerHTML = d.controls.length
        ? `<table class="t" style="margin-top:6px"><thead><tr><th>${t("ess8.thControl")}</th><th>${t("ess8.thLevels")}</th><th>${t("ess8.thControlText")}</th></tr></thead><tbody>${
            d.controls.map((c) => `<tr><td><a class="mono" href="/?db=XORCISM&table=CONTROL&filterCol=CIS&filterVal=${esc(c.id)}">${esc(c.id)}</a></td><td>${c.levels.map((l) => mlBadge(Number(l.replace("ML", "")))).join(" ")}</td><td class="muted" style="font-size:11.5px">${esc(c.text)}</td></tr>`).join("")}</tbody></table>`
        : `<div class="muted" style="font-size:12px;padding:6px 0">${t("ess8.noControls")}</div>`;
    }).catch((e) => { box.innerHTML = `<div class="muted">⚠️ ${esc(e.message || e)}</div>`; });
}

function load(): void {
  fetch("/api/essential-eight").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then(render).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
