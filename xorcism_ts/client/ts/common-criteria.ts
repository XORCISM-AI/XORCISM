/**
 * common-criteria.ts — Common Criteria (ISO/IEC 15408) Security Target cockpit (/common-criteria).
 * Targets → pick an EAL (seeds the assurance worklist from the CC Part 5 package) → claim SFRs →
 * assess each SAR. Shows the EUCC assurance level (AVA_VAN-driven) and the CRA Art. 27 verdict.
 */
import { initI18n } from "./i18n";

interface Target {
  id: number; name: string; toeName: string; toeVersion: string; developer: string; scheme: string;
  certId: string; eal: string; status: string; sfrs: number; sars: number; met: number;
  conformance: number; eucc: string; van: string | null; craEligible: boolean;
}
interface Eal { id: string; name: string; components: string[] }
interface Dash { targets: Target[]; summary: Record<string, number>; catalogue: { imported: boolean; sfr: number; sar: number; eals: Eal[] } }
interface Detail { target: Target; sfrs: any[]; sars: any[]; eucc: { level: string; van: string | null; note: string } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let DASH: Dash | null = null;
let SEL: number | null = null;

const euccChip = (l: string): string =>
  l === "high" ? '<span class="cc-chip c-high">EUCC high</span>'
    : l === "substantial" ? '<span class="cc-chip c-sub">EUCC substantial</span>'
      : '<span class="cc-chip c-none">not classified</span>';

async function api(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
  return d;
}

function renderDash(): void {
  if (!DASH) return;
  const s = DASH.summary, c = DASH.catalogue;
  $("cc-cat").textContent = c.imported ? `catalogue: ${c.sfr} SFR · ${c.sar} SAR · ${c.eals.length} EAL` : "catalogue not imported";
  $("cc-kpis").innerHTML = [
    ["Security Targets", String(s.targets)], ["Certified", String(s.certified)],
    ["Avg assurance", `${s.avgConformance}%`], ["EUCC high", String(s.euccHigh)],
    ["EUCC substantial", String(s.euccSubstantial)], ["CRA Art. 27 eligible", String(s.craEligible)],
  ].map(([l, v]) => `<div class="cc-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  const opts = `<option value="">Target EAL…</option>` + c.eals.map((e) => `<option value="${esc(e.id)}">${esc(e.id)} — ${esc(e.name)}</option>`).join("");
  ($("cc-eal") as HTMLSelectElement).innerHTML = opts;
  // Keep the open target's EAL selected — renderDash() runs after renderDetail(), and rebuilding
  // the options would otherwise reset the picker back to the placeholder.
  const dsel = $("cc-d-eal") as HTMLSelectElement;
  const keep = dsel.value || (SEL != null ? (DASH.targets.find((t) => t.id === SEL)?.eal ?? "") : "");
  dsel.innerHTML = opts;
  dsel.value = keep;

  $("cc-body").innerHTML = DASH.targets.length ? DASH.targets.map((t) => `
    <tr class="cc-row ${t.id === SEL ? "sel" : ""}" data-id="${t.id}">
      <td><b>${esc(t.name)}</b><div class="muted">${esc(t.toeName)}${t.toeVersion ? " v" + esc(t.toeVersion) : ""}${t.scheme ? " · " + esc(t.scheme) : ""}</div></td>
      <td>${esc(t.eal || "—")}</td>
      <td>${euccChip(t.eucc)}${t.van ? `<div class="muted">${esc(t.van)}</div>` : ""}</td>
      <td>${t.sfrs}</td>
      <td><span class="cc-bar"><span style="width:${t.conformance}%"></span></span> ${t.conformance}% <span class="muted">(${t.met}/${t.sars})</span></td>
      <td>${esc(t.status)}</td>
      <td><button class="cc-btn ghost danger cc-del" data-id="${t.id}">Del</button></td>
    </tr>`).join("") : `<tr><td colspan="7" class="muted">No Security Target yet — create one above.</td></tr>`;
}

function renderDetail(d: Detail): void {
  SEL = d.target.id;
  $("cc-detail").style.display = "";
  $("cc-d-title").innerHTML = `&#127942; ${esc(d.target.name)} <span class="muted">— ${esc(d.target.toeName)} ${esc(d.target.toeVersion)}</span>`;
  ($("cc-d-eal") as HTMLSelectElement).value = d.target.eal || "";
  const p = d.eucc;
  $("cc-d-eucc").innerHTML = `${euccChip(p.level)} ${p.van ? `<b>${esc(p.van)}</b> claimed &mdash; ` : ""}${esc(p.note)}`;
  $("cc-d-nsfr").textContent = `(${d.sfrs.length})`;
  $("cc-d-nsar").textContent = `(${d.sars.length})`;
  $("cc-sfr-body").innerHTML = d.sfrs.length ? d.sfrs.map((s: any) => `
    <tr><td style="width:110px"><b>${esc(s.cis)}</b></td><td>${esc(s.name)}</td>
    <td style="width:44px"><button class="cc-btn ghost cc-sfr-del" data-id="${s.id}">×</button></td></tr>`).join("")
    : `<tr><td class="muted">No SFR claimed yet.</td></tr>`;
  const st = ["met", "partial", "gap", "na"];
  $("cc-sar-body").innerHTML = d.sars.length ? d.sars.map((s: any) => `
    <tr><td><b>${esc(s.cis)}</b><div class="muted">${esc(s.name)}</div></td>
      <td><select class="cc-sar-st" data-id="${s.id}">${st.map((x) => `<option value="${x}" ${s.status === x ? "selected" : ""}>${x}</option>`).join("")}</select></td>
      <td><input class="cc-sar-ev" data-id="${s.id}" value="${esc(s.evidence || "")}" placeholder="evidence…" style="width:100%"></td></tr>`).join("")
    : `<tr><td colspan="3" class="muted">Pick a target EAL to seed the assurance worklist.</td></tr>`;
}

async function load(): Promise<void> {
  try { DASH = await api("/api/common-criteria"); renderDash(); }
  catch (e) { toast((e as Error).message); }
}
async function open(id: number): Promise<void> {
  try { renderDetail(await api(`/api/common-criteria/${id}`)); renderDash(); }
  catch (e) { toast((e as Error).message); }
}

async function loadSfrList(q: string): Promise<void> {
  try {
    const d = await api(`/api/common-criteria/catalogue?kind=SFR&q=${encodeURIComponent(q)}`);
    $("cc-sfr-list").innerHTML = (d.items || []).slice(0, 60).map((i: any) => `<option value="${esc(i.cis)}">${esc(i.cis)} — ${esc(i.name)}</option>`).join("");
  } catch { /* ignore */ }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();

  $("cc-add").addEventListener("click", async () => {
    const body = {
      name: ($("cc-name") as HTMLInputElement).value.trim(),
      toeName: ($("cc-toe") as HTMLInputElement).value.trim(),
      toeVersion: ($("cc-ver") as HTMLInputElement).value.trim(),
      developer: ($("cc-dev") as HTMLInputElement).value.trim(),
      scheme: ($("cc-scheme") as HTMLSelectElement).value,
      eal: ($("cc-eal") as HTMLSelectElement).value,
    };
    if (!body.name) { toast("ST title required"); return; }
    try {
      const r = await api("/api/common-criteria", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      ($("cc-name") as HTMLInputElement).value = ""; ($("cc-toe") as HTMLInputElement).value = "";
      $("cc-msg").textContent = `created #${r.id}`;
      await load(); await open(r.id);
    } catch (e) { toast((e as Error).message); }
  });

  $("cc-body").addEventListener("click", async (ev) => {
    const t = ev.target as HTMLElement;
    const del = t.closest(".cc-del") as HTMLElement | null;
    if (del) {
      ev.stopPropagation();
      if (!confirm("Delete this Security Target and its SFR/SAR rows?")) return;
      try { await api(`/api/common-criteria/${del.dataset.id}`, { method: "DELETE" }); SEL = null; $("cc-detail").style.display = "none"; await load(); }
      catch (e) { toast((e as Error).message); }
      return;
    }
    const row = t.closest(".cc-row") as HTMLElement | null;
    if (row) void open(Number(row.dataset.id));
  });

  $("cc-d-eal").addEventListener("change", async (ev) => {
    if (SEL == null) return;
    const eal = (ev.target as HTMLSelectElement).value;
    if (!eal) return;
    try {
      const d = await api(`/api/common-criteria/${SEL}/eal`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ eal }) });
      toast(`${eal}: ${d.seeded} assurance components seeded`);
      renderDetail(d as Detail); await load();
    } catch (e) { toast((e as Error).message); }
  });

  ($("cc-sfr-q") as HTMLInputElement).addEventListener("input", (e) => void loadSfrList((e.target as HTMLInputElement).value));
  $("cc-sfr-add").addEventListener("click", async () => {
    if (SEL == null) return;
    const raw = ($("cc-sfr-q") as HTMLInputElement).value.trim();
    const cis = (raw.match(/[A-Z]{3}_[A-Z]{3}\.\d+/i) || [raw])[0];
    try { renderDetail(await api(`/api/common-criteria/${SEL}/sfr`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cis }) })); ($("cc-sfr-q") as HTMLInputElement).value = ""; await load(); }
    catch (e) { toast((e as Error).message); }
  });

  $("cc-sfr-body").addEventListener("click", async (ev) => {
    const b = (ev.target as HTMLElement).closest(".cc-sfr-del") as HTMLElement | null;
    if (!b || SEL == null) return;
    try { await api(`/api/common-criteria/sfr/${b.dataset.id}`, { method: "DELETE" }); await open(SEL); }
    catch (e) { toast((e as Error).message); }
  });

  const saveSar = async (id: string, status: string, evidence: string): Promise<void> => {
    try { await api(`/api/common-criteria/sar/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, evidence }) }); if (SEL != null) await open(SEL); }
    catch (e) { toast((e as Error).message); }
  };
  $("cc-sar-body").addEventListener("change", (ev) => {
    const t = ev.target as HTMLElement;
    const row = t.closest("tr")!;
    const st = row.querySelector(".cc-sar-st") as HTMLSelectElement;
    const ev2 = row.querySelector(".cc-sar-ev") as HTMLInputElement;
    if (t.classList.contains("cc-sar-st") || t.classList.contains("cc-sar-ev")) void saveSar(st.dataset.id!, st.value, ev2.value);
  });
});
