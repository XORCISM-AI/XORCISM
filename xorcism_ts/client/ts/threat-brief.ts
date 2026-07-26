/**
 * threat-brief.ts — "Morning Threat Intelligence" cockpit (/threat-brief).
 * Renders the consolidated briefing from GET /api/threat-brief into ThreatWake-style panels:
 * Top Vulnerabilities (KEV + EPSS), Ransomware victims, Botnet C2, Security News, Cloud Security.
 */
import { initI18n } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}
function toast(m: string): void { const el = $("tb-toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

/** "3d ago" / "5h ago" from an ISO date; "" if unparseable. */
function ago(iso: string): string {
  const t = Date.parse(iso);
  if (isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
/** ISO 2-letter country code → flag emoji. */
function flag(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return cc || "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
const cveLink = (cve: string): string => `<a href="/exposure?cve=${encodeURIComponent(cve)}" class="cve">${esc(cve)}</a>`;

function panel(title: string, meta: string, bodyHtml: string, span2 = false): string {
  return `<div class="panel${span2 ? " span2" : ""}">
    <div class="panel-h"><span class="t">${esc(title)}</span><span class="meta">${esc(meta)}</span></div>
    <div class="panel-b">${bodyHtml || `<div class="tb-empty">no data right now</div>`}</div></div>`;
}

function kevRows(items: any[]): string {
  if (!items.length) return "";
  return items.map((v) => `<div class="row">
    <span class="ago">added ${esc(String(v.added).slice(0, 10))}</span>
    ${cveLink(v.cve)}
    <span class="badge b-kev">KEV</span>
    ${v.exploited ? `<span class="badge b-exploit">&#9876; EXPLOIT</span>` : ""}
    ${v.ransomware ? `<span class="badge b-ransom">RANSOMWARE</span>` : ""}
    ${v.epss != null ? `<span class="badge b-epss">EPSS ${v.epss}%</span>` : ""}
    <div class="vp">${esc(v.vendor)}${v.product ? " &middot; " + esc(v.product) : ""}${v.cvss != null ? ` <span class="metric">CVSS ${v.cvss}</span>` : ""}</div>
    <div class="vn">${esc(v.name)}</div></div>`).join("");
}

function epssRows(items: any[]): string {
  if (!items.length) return "";
  return items.map((v) => `<div class="row">
    <span class="ago">${esc(v.published)}</span>
    ${cveLink(v.cve)}
    ${v.severity ? `<span class="sev sev-${esc(v.severity)}">${esc(v.severity)}</span>` : ""}
    ${v.kev ? `<span class="badge b-kev">KEV</span>` : ""}
    ${v.exploited ? `<span class="badge b-exploit">&#9876;</span>` : ""}
    <span class="badge b-epss">EPSS ${v.epss}%</span>
    ${v.cvss != null ? `<span class="metric"> CVSS ${v.cvss}</span>` : ""}
  </div>`).join("");
}

function ransomRows(items: any[]): string {
  if (!items.length) return "";
  return items.map((r) => `<div class="row">
    <span class="ago">${esc(ago(r.date))}</span>
    <b style="color:#f1f5f9">${esc(r.victim)}</b> ${r.country ? `<span class="flag">${flag(r.country)}</span>` : ""}
    <div class="vn"><span class="badge b-ransom">${esc(r.group)}</span> ${r.activity ? esc(r.activity) : ""}${r.domain ? ` &middot; <span class="src">${esc(r.domain)}</span>` : ""}</div>
  </div>`).join("");
}

function botnetBody(b: any): string {
  const fams = (b.families || []).map((f: any) => `<span class="chip"><b>${esc(f.name)}</b> ${f.count}</span>`).join("");
  const ccs = (b.countries || []).map((c: any) => `<span class="chip">${flag(c.cc)} ${esc(c.cc)} <b>${c.count}</b></span>`).join("");
  const nodes = (b.items || []).map((n: any) => `<div class="row">
    <span class="ago">${esc(n.lastOnline)}</span>
    <span class="cve">${esc(n.ip)}${n.port ? ":" + n.port : ""}</span>
    <span class="badge b-exploit">${esc(n.malware)}</span> ${n.country ? `<span class="flag">${flag(n.country)}</span>` : ""}
    <div class="vn src">${esc(n.asn)}</div></div>`).join("");
  const secLabel = (window as any).t?.("tbf.malwareFamilies", "Malware families") || "Malware families";
  const ctyLabel = (window as any).t?.("tbf.topCountries", "Top source countries") || "Top source countries";
  return `<div style="font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px;padding:8px 10px 0">${esc(secLabel)}</div>
    <div class="tally">${fams || `<span class="tb-empty">—</span>`}</div>
    <div style="font-size:10.5px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px;padding:2px 10px 0">${esc(ctyLabel)}</div>
    <div class="tally">${ccs || `<span class="tb-empty">—</span>`}</div>${nodes}`;
}

function newsRows(items: any[]): string {
  if (!items.length) return "";
  return items.map((n) => `<div class="row">
    <span class="ago">${esc(ago(n.date))}</span>
    <a href="${esc(n.link)}" target="_blank" rel="noopener noreferrer">${esc(n.title)}</a>
    <div class="src">${esc(n.source)}</div></div>`).join("");
}

function render(d: any): void {
  $("tb-when").textContent = `generated ${new Date(d.generatedAt).toLocaleString()}`;
  const k = d.kpis || {};
  $("tb-kpis").innerHTML = [
    ["#fecaca", k.kevNew, "New KEV"], ["#6ee7b7", k.epssHigh, "High-EPSS CVEs"],
    ["#e9d5ff", k.ransom24h, "Ransomware / 24h"], ["#fed7aa", k.c2Active, "Active C2"],
  ].map(([c, v, l]) => `<div class="tb-kpi"><div class="v" style="color:${c}">${esc(v ?? 0)}</div><div class="l">${esc(l)}</div></div>`).join("");

  const kevMeta = d.kev?.updated ? `catalog ${String(d.kev.updated).slice(0, 10)} · ${d.kev.total} total` : `${d.kev?.items?.length || 0}`;
  const ranMeta = d.ransomware?.total ? `${d.ransomware.count24h} in 24h · top: ${d.ransomware.topGroup || "—"}` : "";
  const c2Meta = d.botnet?.total ? `${d.botnet.total} active` : "";

  $("tb-body").innerHTML = `<div class="tb-grid">
    ${panel("Top Vulnerabilities · KEV", kevMeta, kevRows(d.kev?.items || []))}
    ${panel("Top Vulnerabilities · EPSS", `${d.epss?.items?.length || 0} recent high-sev`, epssRows(d.epss?.items || []))}
    ${panel("Ransomware · Recent Victims", ranMeta, ransomRows(d.ransomware?.items || []))}
    ${panel("Botnet C2", c2Meta, botnetBody(d.botnet || {}))}
    ${panel("Security News", `${d.news?.length || 0}`, newsRows(d.news || []))}
    ${panel("Cloud Security", `${d.cloud?.length || 0}`, newsRows(d.cloud || []))}
  </div>`;
}

async function load(): Promise<void> {
  $("tb-body").innerHTML = `<div class="tb-loading">Assembling this morning's threat briefing…</div>`;
  try {
    const r = await fetch("/api/threat-brief");
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `Error ${r.status}`);
    render(d);
  } catch (e) { $("tb-body").innerHTML = `<div class="tb-empty">${esc((e as Error).message)}</div>`; toast((e as Error).message); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();
  $("tb-refresh").addEventListener("click", () => { void load(); toast("refreshing…"); });
});
