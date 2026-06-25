/**
 * drift.ts — Attack-surface drift view (/drift). Take a snapshot, see the diff vs the
 * previous one: assets appeared/vanished and newly/no-longer internet-exposed.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Drift {
  current: { date: string | null; assets: number; exposed: number } | null;
  previous: { date: string | null; assets: number; exposed: number } | null;
  added: string[]; removed: string[]; newlyExposed: string[]; noLongerExposed: string[]; snapshots: number;
}

function delta(cur: number, prev: number | undefined): string {
  if (prev == null) return "";
  const d = cur - prev; if (d === 0) return ` <span class="delta muted">=</span>`;
  return ` <span class="delta ${d > 0 ? "up" : "down"}">${d > 0 ? "+" : ""}${d}</span>`;
}
function grp(cls: string, title: string, items: string[]): string {
  if (!items.length) return "";
  return `<div class="grp"><div class="t ${cls}">${esc(title)} (${items.length})</div>${items.slice(0, 100).map((n) => `<span class="chip">${esc(n)}</span>`).join("")}</div>`;
}

function render(d: Drift): void {
  if (!d.current) { $("df-body").innerHTML = `<div class="df-empty">${t("drift.noSnaps")}</div>`; return; }
  const c = d.current, p = d.previous || undefined;
  const anyChange = d.added.length || d.removed.length || d.newlyExposed.length || d.noLongerExposed.length;
  $("df-body").innerHTML = `
    <div class="snap">
      <div class="scard"><div class="lbl">${t("drift.cAssets")}</div><div class="big">${c.assets}${delta(c.assets, p?.assets)}</div></div>
      <div class="scard"><div class="lbl">${t("drift.cExposed")}</div><div class="big">${c.exposed}${delta(c.exposed, p?.exposed)}</div></div>
      <div class="scard"><div class="lbl">${t("drift.cSnapshots")}</div><div class="big">${d.snapshots}</div></div>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:6px">${fmt("drift.latest", { d: esc(c.date || "") })}${p ? fmt("drift.vsPrev", { p: esc(p.date || "") }) : ""}</div>
    ${!p ? `<div class="df-empty">${t("drift.takeSecond")}</div>` :
      anyChange ? `<h3>${t("drift.changesSince")}</h3>
        ${grp("t-exp", t("drift.grpNewExposed"), d.newlyExposed)}
        ${grp("t-add", t("drift.grpAdded"), d.added)}
        ${grp("t-rem", t("drift.grpRemoved"), d.removed)}
        ${grp("t-une", t("drift.grpUnexposed"), d.noLongerExposed)}`
      : `<div class="df-empty">${t("drift.noDrift")}</div>`}`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/drift"); if (!r.ok) throw new Error(`HTTP ${r.status}`); render(await r.json()); }
  catch (e) { $("df-body").innerHTML = `<div class="df-empty">⚠️ ${esc(e)}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("df-snap").addEventListener("click", async () => {
    const btn = $("df-snap") as HTMLButtonElement; btn.disabled = true; const lbl = btn.textContent; btn.textContent = t("drift.capturing");
    try { await fetch("/api/drift/snapshot", { method: "POST" }); await load(); }
    catch { /* */ } finally { btn.disabled = false; btn.textContent = lbl; }
  });
  void load();
});
