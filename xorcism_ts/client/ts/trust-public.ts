/** trust-public.ts — the PUBLIC, read-only Trust Center page rendered at /trust/<slug>. Fetches
 * /api/public/trust/<slug> (auth-exempt) and shows aggregate posture only. No session / no auth. */
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

async function render(): Promise<void> {
  const host = document.getElementById("tp")!;
  const slug = location.pathname.split("/").filter(Boolean).pop() || "";
  let d: any;
  try { const r = await fetch(`/api/public/trust/${encodeURIComponent(slug)}`); if (!r.ok) throw new Error(String(r.status)); d = await r.json(); }
  catch { host.innerHTML = `<div class="err">This Trust Center is not available.</div>`; return; }

  document.title = `${d.companyName || "Trust Center"} — Trust Center`;
  const p = d.posture || {};
  const stats: string[] = [];
  if (d.showControls && p.controls) stats.push(`<div class="stat"><div class="v" style="color:${p.controls.coveragePct >= 80 ? "#34d399" : p.controls.coveragePct >= 40 ? "#fbbf24" : "#f87171"}">${p.controls.coveragePct}%</div><div class="l">NIST 800-53 coverage</div></div>`);
  if (d.showUptime && p.uptime) stats.push(`<div class="stat"><div class="v" style="color:#34d399">${p.uptime.avgUptime}%</div><div class="l">Service uptime</div></div>`);
  if (d.showPolicies) stats.push(`<div class="stat"><div class="v">${p.policies ?? 0}</div><div class="l">Security policies</div></div>`);
  stats.push(`<div class="stat"><div class="v">${p.audits ?? 0}</div><div class="l">Audits & assessments</div></div>`);

  const fws = (d.frameworks && d.frameworks.length ? d.frameworks : (p.frameworksLive || []));
  const fwChips = fws.map((f: any) => `<span class="chip">${esc(f.name)} ${/(compliant|certif|pass|complete)/i.test(f.status || "") ? `<b>✓ ${esc(f.status)}</b>` : `<span class="ip">${esc(f.status || "In progress")}</span>`}</span>`).join("");
  const sp = (d.subprocessors || []).filter((x: any) => x.name);

  host.innerHTML = `
    <div class="badge">🛡 Trust Center</div>
    <h1>${esc(d.companyName || d.title || "Security & Compliance")}</h1>
    ${d.intro ? `<p class="intro">${esc(d.intro)}</p>` : ""}
    <div class="stats">${stats.join("")}</div>
    ${fwChips ? `<h2>Compliance & frameworks</h2><div class="chips">${fwChips}</div>` : ""}
    ${sp.length ? `<h2>Sub-processors</h2><table><thead><tr><th>Name</th><th>Purpose</th><th>Location</th></tr></thead><tbody>${sp.map((s: any) => `<tr><td>${esc(s.name)}</td><td>${esc(s.purpose || "—")}</td><td>${esc(s.location || "—")}</td></tr>`).join("")}</tbody></table>` : ""}
    <div class="foot">
      ${d.contactEmail ? `Security questions? <a href="mailto:${esc(d.contactEmail)}">${esc(d.contactEmail)}</a>. ` : ""}
      ${d.updatedAt ? `Last updated ${esc(String(d.updatedAt).slice(0, 10))}.` : ""}
      <div class="powered">Posture published live from XORCISM.</div>
    </div>`;
}

document.addEventListener("DOMContentLoaded", () => void render());
