/** cloud-security.ts — Cloud Security Management cockpit (/cloud-security). Cloud asset inventory,
 * exposure/misconfig worklist, provider breakdown + CSA CCM reference, from /api/cloud-security. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { id: number; name: string; provider: string; criticality: string; publicFacing: boolean; encrypted: boolean; pii: boolean; thirdParty: boolean; owner: boolean; vulns: number; criticalVulns: number; kev: number; tags: string[]; flags: string[]; score: number; hostname: string; ip: string; }
interface Data { rows: Row[]; worklist: { id: number; name: string; provider: string; severity: string; reason: string }[]; summary: any; }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="cs-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pcls = (p: string): string => `p-${["AWS", "Azure", "GCP", "OCI", "SaaS", "Cloud"].includes(p) ? p : "Cloud"}`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;

function rowHtml(r: Row): string {
  return `<tr>
    <td><span class="nm">${esc(r.name)}</span>${r.hostname || r.ip ? `<div class="muted" style="font-size:11px">${esc(r.hostname || r.ip)}</div>` : ""}</td>
    <td><span class="prov ${pcls(r.provider)}">${esc(r.provider)}</span></td>
    <td>${esc(r.criticality || "—")}</td>
    <td>${r.publicFacing ? `<span class="tag t-pub">PUBLIC</span>` : "<span class='muted'>internal</span>"}</td>
    <td>${r.encrypted ? `<span class="tag t-enc">ENC</span>` : `<span class="tag t-unenc">NO ENC</span>`}${r.pii ? ` <span class="tag t-pii">PII</span>` : ""}</td>
    <td>${r.vulns ? `${r.vulns}${r.criticalVulns ? ` <span class="muted" style="font-size:11px">(${r.criticalVulns}C)</span>` : ""}${r.kev ? ` <span class="tag t-kev">${r.kev} KEV</span>` : ""}` : "<span class='muted'>0</span>"}</td>
    <td>${r.owner ? "✓" : "<span class='tag t-unenc'>none</span>"}</td>
  </tr>`;
}

function load(): void {
  fetch("/api/cloud-security").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    const s = d.summary;
    if (!d.rows.length) {
      $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No cloud assets detected yet (${s.ccmControls} CSA CCM controls / ${s.ccmDomains} domains available as reference).<br>
        Tag assets as <code>cloud/aws/azure/gcp</code> or set the cloud flag, or run a cloud connector (Entra ID, Wiz, Lacework, Upwind, Chainguard).</div>`;
      return;
    }
    const cards = [
      card("Cloud assets", String(s.cloudAssets), `${s.thirdParty} third-party hosted`),
      card("Internet-facing", String(s.publicFacing), "publicly exposed", s.publicFacing ? "#fbbf24" : "#34d399"),
      card("Unencrypted", String(s.unencrypted), "no encryption-at-rest", s.unencrypted ? "#f87171" : "#34d399"),
      card("KEV exposed", String(s.kev), "known-exploited vulns", s.kev ? "#f87171" : "#34d399"),
      card("Critical assets", String(s.criticalAssets), `${s.withCriticalVulns} with critical vulns`),
      card("CSA CCM", String(s.ccmControls), `${s.ccmDomains} domains (reference)`, "#60a5fa"),
    ].join("");
    const byProv = Object.entries(s.byProvider || {}).sort((a: any, b: any) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="prov ${pcls(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.slice(0, 40).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> <span class="prov ${pcls(w.provider)}">${esc(w.provider)}</span> — ${esc(w.reason)}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ No cloud exposure findings — every cloud asset is owned, encrypted and not publicly exposed with critical vulns.</div>`;
    const table = `<table class="cs"><thead><tr><th>Asset</th><th>Provider</th><th>Criticality</th><th>Exposure</th><th>Encryption</th><th>Vulns</th><th>Owner</th></tr></thead><tbody>${d.rows.slice(0, 200).map(rowHtml).join("")}</tbody></table>`;
    $("cs-body").innerHTML = `<div class="cs-cards">${cards}</div>
      <div class="cs-section">By provider</div><div class="breakdown">${byProv || "<span class='muted'>—</span>"}</div>
      <div class="cs-section">Cloud exposure worklist (${d.worklist.length})</div>${work}
      <div class="cs-section">Cloud assets (${d.rows.length})</div>${table}`;
  }).catch((e) => { $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
document.addEventListener("DOMContentLoaded", load);
