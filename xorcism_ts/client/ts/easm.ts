/**
 * easm.ts — External Attack Surface Management cockpit (/easm).
 * Renders the internet-facing subset of the estate (exposure reasons, services/ports, TLS
 * posture, external KEV/critical vulns), the exposures worklist and surface drift, from
 * /api/easm. A "Snapshot surface" button records a baseline so drift can be measured.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Service { proto: string; port: number; service: string; source: string }
interface Row {
  id: number; name: string; address: string; reasons: string[]; criticality: string;
  owner: string | null; services: Service[]; openPorts: number;
  ssl: { days: number | null; expiry: string | null; status: string } | null;
  vulns: { open: number; kev: number; critical: number }; shadow: boolean; flags: string[]; score: number;
}
interface Finding { kind: string; label: string; severity: string; assetId: number; asset: string }
interface Data {
  rows: Row[]; worklist: Finding[];
  drift: { added: string[]; removed: string[]; snapshots: number } | null;
  summary: { internetFacing: number; exposedServices: number; openPorts: number; expiringCerts: number; expiredCerts: number; externalKev: number; shadow: number; noOwner: number; byReason: Record<string, number> };
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="em-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
function sevClass(s: string): string { return `s-${(s || "low").toLowerCase()}`; }

function certHtml(ssl: Row["ssl"]): string {
  if (!ssl || ssl.days == null) return `<span class="muted">—</span>`;
  if (ssl.days < 0) return `<span class="cert-expired">${t("em.expired")}</span> <span class="muted">${esc(ssl.expiry)}</span>`;
  if (ssl.days <= 30) return `<span class="cert-expiring">${ssl.days}d</span> <span class="muted">${esc(ssl.expiry)}</span>`;
  return `<span class="cert-valid">${ssl.days}d</span> <span class="muted">${esc(ssl.expiry)}</span>`;
}

function rowHtml(r: Row): string {
  const ports = r.services.length
    ? r.services.slice(0, 10).map((s) => `<span class="port" title="${esc(s.service || s.source)}">${esc(s.proto)}/${esc(String(s.port))}</span>`).join("") + (r.services.length > 10 ? ` <span class="muted">+${r.services.length - 10}</span>` : "")
    : `<span class="muted">—</span>`;
  const reasons = r.reasons.map((x) => `<span class="reason">${esc(x)}</span>`).join("");
  const vulns = r.vulns.open
    ? `${r.vulns.kev ? `<span class="kev" title="${t("em.kevTitle")}">KEV ${r.vulns.kev}</span> ` : ""}${r.vulns.critical ? `<span class="sev s-high">${fmt("em.nCrit", { n: r.vulns.critical })}</span> ` : ""}<span class="muted">${fmt("em.nOpen", { n: r.vulns.open })}</span>`
    : `<span class="muted">0</span>`;
  return `<tr>
    <td><span class="scorebar"><span style="width:${Math.max(4, r.score)}%"></span></span><b>${r.score}</b></td>
    <td><span class="aname">${esc(r.name)}</span>${r.shadow ? ` <span class="shadow" title="${t("em.shadowTitle")}">${t("em.shadow")}</span>` : ""}<br><span class="muted mono">${esc(r.address)}</span><div style="margin-top:3px">${reasons}</div></td>
    <td>${esc(r.criticality)}${r.owner ? `<br><span class="muted">${esc(r.owner)}</span>` : `<br><span class="muted">${t("em.noOwnerRow")}</span>`}</td>
    <td>${ports}</td>
    <td>${certHtml(r.ssl)}</td>
    <td>${vulns}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  return `<tr><td><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></td><td><a href="/?db=XORCISM&table=ASSET&filterCol=AssetID&filterVal=${esc(f.assetId)}" class="aname">${esc(f.asset)}</a></td><td>${esc(f.label.replace(`${f.asset}: `, ""))}</td></tr>`;
}

async function load(): Promise<void> {
  let d: Data;
  try { const r = await fetch("/api/easm"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("em-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }

  if (!d.rows.length) {
    $("em-body").innerHTML = `<div class="muted" style="padding:32px;text-align:center;line-height:1.7">${t("em.empty")}</div>`;
    return;
  }

  const s = d.summary;
  const cards = [
    card(t("em.cInternetFacing"), String(s.internetFacing), t("em.cInternetFacing.foot"), s.internetFacing ? "#22d3ee" : undefined),
    card(t("em.cServices"), String(s.exposedServices), fmt("em.cServices.foot", { n: s.openPorts }), s.exposedServices ? "#60a5fa" : undefined),
    card(t("em.cExtKev"), String(s.externalKev), t("em.cExtKev.foot"), s.externalKev ? "#f87171" : "#34d399"),
    card(t("em.cCerts"), String(s.expiredCerts + s.expiringCerts), fmt("em.cCerts.foot", { e: s.expiredCerts, x: s.expiringCerts }), (s.expiredCerts + s.expiringCerts) ? "#fbbf24" : "#34d399"),
    card(t("em.cShadow"), String(s.shadow), t("em.cShadow.foot"), s.shadow ? "#fbbf24" : "#34d399"),
    card(t("em.cNoOwner"), String(s.noOwner), t("em.cNoOwner.foot"), s.noOwner ? "#fbbf24" : undefined),
  ].join("");

  const reasonChips = Object.entries(s.byReason).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<span class="bd"><b>${esc(String(v))}</b> ${esc(k)}</span>`).join("");

  const driftHtml = d.drift && (d.drift.added.length || d.drift.removed.length)
    ? `<div class="em-section">${fmt("em.driftSec", { n: d.drift.snapshots })}</div>
       <div class="breakdown">
         ${d.drift.added.length ? `<span class="bd drift-add">${fmt("em.driftAdded", { n: d.drift.added.length, list: d.drift.added.slice(0, 8).map(esc).join(", ") + (d.drift.added.length > 8 ? "…" : "") })}</span>` : ""}
         ${d.drift.removed.length ? `<span class="bd drift-rem">${fmt("em.driftRemoved", { n: d.drift.removed.length, list: d.drift.removed.slice(0, 8).map(esc).join(", ") + (d.drift.removed.length > 8 ? "…" : "") })}</span>` : ""}
       </div>`
    : d.drift && d.drift.snapshots
      ? `<div class="em-section">${t("em.driftSecSimple")}</div><div class="breakdown"><span class="bd">${fmt("em.driftNoChange", { n: d.drift.snapshots })}</span></div>`
      : "";

  const surfaceTable = `<div class="em-section">${fmt("em.secAssets", { n: d.rows.length })}</div>
    <table class="em"><thead><tr><th>${t("em.thScore")}</th><th>${t("em.thAsset")}</th><th>${t("em.thCrit")}</th><th>${t("em.thPorts")}</th><th>${t("em.thCert")}</th><th>${t("em.thVulns")}</th></tr></thead>
    <tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  const worklist = d.worklist.length
    ? `<div class="em-section">${fmt("em.secWorklist", { n: d.worklist.length })}</div>
       <table class="em"><thead><tr><th>${t("em.thSeverity")}</th><th>${t("em.thAssetW")}</th><th>${t("em.thExposure")}</th></tr></thead>
       <tbody>${d.worklist.map(findingHtml).join("")}</tbody></table>`
    : `<div class="em-section">${t("em.secWorklistEmpty")}</div><div class="breakdown"><span class="bd">${t("em.noExposures")}</span></div>`;

  $("em-body").innerHTML = `<div class="em-cards">${cards}</div>
    <div class="em-section">${t("em.secWhy")}</div><div class="breakdown">${reasonChips || `<span class="bd">—</span>`}</div>
    ${driftHtml}
    ${worklist}
    ${surfaceTable}
    <div class="legend">${t("em.legend")}</div>`;
}

async function snapshot(): Promise<void> {
  const btn = $("em-snap") as HTMLButtonElement; const stat = $("em-snap-stat");
  btn.disabled = true; stat.textContent = t("em.capturing");
  try {
    const r = await fetch("/api/easm/snapshot", { method: "POST" });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    stat.innerHTML = fmt("em.snapDone", { id: esc(j.snapshotId), a: esc(j.assets), x: esc(j.exposed) });
    toast(t("em.toastSnap"));
    void load();
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();
  const btn = document.getElementById("em-snap");
  if (btn) btn.addEventListener("click", () => void snapshot());
});
