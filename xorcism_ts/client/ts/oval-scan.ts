/**
 * oval-scan.ts — OVAL scan results (/oval-scan). Per-asset verdicts + compliance/vuln
 * worklist from the XOR agent's OpenSCAP evaluations, via /api/oval-results.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { asset: string; assetId: number | null; lastScan: string | null; vuln: number; compliancePass: number; complianceFail: number; inventory: number; total: number; }
interface Finding { asset: string; assetId: number | null; cls: string; title: string; severity: string; result: string; }
interface View {
  rows: Row[]; findings: Finding[];
  summary: { assets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; cves: number; lastScan: string | null };
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ov-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const cell = (n: number, cls: string): string => (n ? `<span class="pill ${cls}">${n}</span>` : `<span class="muted">0</span>`);
  return `<tr>
    <td><span class="aname">${esc(r.asset)}</span></td>
    <td>${esc(r.lastScan ? r.lastScan.replace("T", " ") : "—")}</td>
    <td>${cell(r.vuln, "p-vuln")}</td>
    <td>${cell(r.complianceFail, "p-fail")} ${cell(r.compliancePass, "p-pass")}</td>
    <td>${cell(r.inventory, "p-inv")}</td>
    <td class="muted">${r.total}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const vuln = f.cls === "vulnerability";
  return `<li><span class="dot ${vuln ? "d-vuln" : "d-fail"}"></span>
    <span class="cls-${f.cls}">${vuln ? "VULN" : "FAIL"}</span> ·
    <a href="/asset-management">${esc(f.asset)}</a> — ${esc(f.title || (vuln ? "CVE detected" : "compliance check"))}${f.severity ? ` <span class="muted">(${esc(f.severity)})</span>` : ""}</li>`;
}

async function load(): Promise<void> {
  let d: View;
  try { const r = await fetch("/api/oval-results"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ov-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("ov-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No OVAL scans yet. Deploy the XOR agent on a host (with <code>oscap</code>), then launch an
      <b>OVAL</b> scan from the agent or the ASSET window — results land here and in
      <a href="/?db=XOVAL&table=OVALRESULTS"><code>OVALRESULTS</code></a>.</div>`;
    return;
  }

  const cards = [
    card("Assets scanned", String(s.assets), `${s.verdicts} verdicts`),
    card("Compliance pass", s.passRate != null ? `${s.passRate}%` : "—", `${s.compliancePass} pass · ${s.complianceFail} fail`, s.passRate != null ? (s.passRate >= 80 ? "#34d399" : s.passRate >= 50 ? "#fbbf24" : "#f87171") : undefined),
    card("Compliance failures", String(s.complianceFail), "config checks failed", s.complianceFail ? "#fb923c" : "#34d399"),
    card("OVAL-detected CVEs", String(s.cves), "vulnerability verdicts", s.cves ? "#f87171" : "#34d399"),
    card("Last scan", s.lastScan ? esc(s.lastScan.slice(0, 10)) : "—", s.lastScan ? esc(s.lastScan.slice(11, 19)) : "never"),
  ].join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No vulnerability detections or compliance failures.</div>`;

  const table = `<table class="ov"><thead><tr>
      <th>Asset</th><th>Last scan</th><th>Vulns</th><th>Compliance (fail/pass)</th><th>Inventory</th><th>Verdicts</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("ov-body").innerHTML = `<div class="ov-cards">${cards}</div>
    <div class="ov-section">Worklist (${d.findings.length})</div>${findings}
    <div class="ov-section">By asset (${d.rows.length})</div>${table}
    <div class="legend">↳ Verdicts come from the agent's <code>oscap oval eval</code> against distro/SSG content.
      Vulnerability hits also create <code>ASSETVULNERABILITY</code> links; inventory hits create
      <code>CPEFORASSET</code>. Launch a scan with kind <b>oval</b> from the agent / ASSET window.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
