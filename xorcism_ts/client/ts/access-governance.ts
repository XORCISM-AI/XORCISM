/**
 * access-governance.ts — Access Governance cockpit (/access-governance).
 * KPIs + SoD violations worklist (mitigate/accept), pending access requests (approve/deny with SoD
 * override), JIT active grants, entitlement catalogue, SoD rules (+ add), and peer outliers.
 * All from /api/access-governance*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return { status: r.status, body: await r.json().catch(() => ({})) }; }

const rk = (r: string): string => `r-${esc(r)}`;
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ag-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/access-governance"); } catch (e) { $("ag-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  if (!s.entitlements) {
    $("ag-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">No entitlements yet. Seed a demo estate (entitlements, assignments, SoD rules, an access request &amp; a JIT grant) to explore the cockpit, or import via the Saviynt connector.</div><button class="btn" id="seed">Seed demo</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/access-governance/seed"); load(); };
    return;
  }
  const cards = [
    card("Entitlements", String(s.entitlements ?? 0), `${s.privilegedEnt ?? 0} privileged · ${s.highRiskEnt ?? 0} high-risk`),
    card("SoD violations", String(s.sodViolations ?? 0), `${s.sodCritical ?? 0} critical/high`, (s.sodViolations ? "#f87171" : "#22c55e")),
    card("SoD rules", String(s.sodRules ?? 0), `${s.sodMitigated ?? 0} mitigated/accepted`),
    card("Pending requests", String(s.pendingRequests ?? 0), `${s.sodBlockedPending ?? 0} SoD-blocked`, (s.sodBlockedPending ? "#fbbf24" : s.pendingRequests ? "#60a5fa" : "#94a3b8")),
    card("JIT active", String(s.jitActive ?? 0), "time-bound grants", (s.jitActive ? "#c4b5fd" : "#94a3b8")),
    card("Assignments", String(s.assignments ?? 0), `${s.identitiesWithAccess ?? 0} identities`),
    card("Peer outliers", String(s.outliers ?? 0), "rare privileged access", (s.outliers ? "#fb923c" : "#22c55e")),
  ].join("");

  $("ag-body").innerHTML = `
    <div class="ag-cards">${cards}</div>
    <div class="row">
      <button class="btn" id="ag-detect">&#128270; Run SoD detection</button>
      <button class="btn sec" id="ag-jit">&#9203; JIT expiry sweep</button>
      <span class="muted" style="font-size:11px;margin-left:auto">Saviynt-style IGA: entitlements · SoD · access requests · JIT</span>
    </div>
    <div class="ag-sec">Segregation-of-Duties violations</div>
    <div id="ag-viol" style="overflow-x:auto"></div>
    <div class="ag-sec">Pending access requests</div>
    <div id="ag-req" style="overflow-x:auto"></div>
    <div class="ag-sec">Active JIT grants</div>
    <div id="ag-jitgrants" style="overflow-x:auto"></div>
    <div class="ag-sec">SoD ruleset</div>
    <div id="ag-rules"></div>
    <div class="ag-sec">Entitlement catalogue</div>
    <div id="ag-ents" style="overflow-x:auto"></div>
    <div class="ag-sec">Peer-group outliers <span class="muted" style="font-weight:400;text-transform:none">— rare privileged access vs. same-type peers</span></div>
    <div id="ag-outliers"></div>`;

  renderViolations(d.sodViolations || []);
  renderRequests(d.pendingRequests || []);
  renderJit(d.jitActive || []);
  renderRules(d.sodRules || []);
  renderEntitlements(d.topEntitlements || []);
  renderOutliers(d.outliers || []);
  $("ag-detect").onclick = async () => { const r = await postJSON("/api/access-governance/detect"); if (r.body) alert(`SoD detection: ${r.body.violations} open violation(s) (+${r.body.created} new / -${r.body.resolved} cleared) across ${r.body.rules} rules.`); load(); };
  $("ag-jit").onclick = async () => { const r = await postJSON("/api/access-governance/jit-sweep"); if (r.body) alert(`JIT sweep: revoked ${r.body.revoked} expired grant(s), expired ${r.body.expired} request(s).`); load(); };
}

function renderViolations(v: any[]): void {
  const rows = v.map((x) => `<tr>
    <td><b>${esc(x.ruleName)}</b><div class="muted" style="font-size:10px">${esc(x.detectedDate).slice(0, 10)}</div></td>
    <td>${esc(x.identityName)}</td>
    <td><span class="pair"><b>${esc(x.left)}</b> + <b>${esc(x.right)}</b></span></td>
    <td class="${rk(x.risk)}">${esc(x.risk)}</td>
    <td class="st-${esc(x.status)}">${esc(x.status)}${x.notes ? `<div class="muted" style="font-size:10px">${esc(x.notes)}</div>` : ""}</td>
    <td style="white-space:nowrap">${x.status === "open" ? `<button class="btn sm warn" data-mit="${x.id}">Mitigate</button> <button class="btn sm sec" data-acc="${x.id}">Accept</button>` : `<button class="btn sm sec" data-reopen="${x.id}">Reopen</button>`}</td>
  </tr>`).join("") || `<tr><td colspan="6" class="muted">No SoD violations — run detection after assigning access.</td></tr>`;
  $("ag-viol").innerHTML = `<table class="tt"><thead><tr><th>Rule</th><th>Identity</th><th>Conflicting entitlements</th><th>Risk</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  const setStatus = (id: string, status: string, prompt0: boolean) => async () => { let note = ""; if (prompt0) { note = window.prompt(`${status} — note (mitigating control / justification):`, "") || ""; } await postJSON(`/api/access-governance/violation/${id}/status`, { status, note }); load(); };
  document.querySelectorAll("[data-mit]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.mit!, "mitigated", true));
  document.querySelectorAll("[data-acc]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.acc!, "accepted", true));
  document.querySelectorAll("[data-reopen]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.reopen!, "open", false));
}

function renderRequests(reqs: any[]): void {
  const rows = reqs.map((r) => `<tr>
    <td>${esc(r.identityName)}</td>
    <td><b>${esc(r.entitlementName)}</b>${r.jitHours ? ` <span class="tag jit">JIT ${r.jitHours}h</span>` : ""}</td>
    <td class="muted" style="font-size:11px">${esc(r.justification || "—")}</td>
    <td>${r.sodConflict ? `<span class="conf" title="${esc(r.sodDetail)}">⚠ SoD conflict</span>` : `<span class="r-low">clean</span>`}</td>
    <td style="white-space:nowrap"><button class="btn sm" data-appr="${r.id}" data-sod="${r.sodConflict ? 1 : 0}">Approve</button> <button class="btn sm danger" data-deny="${r.id}">Deny</button></td>
  </tr>`).join("") || `<tr><td colspan="5" class="muted">No pending access requests.</td></tr>`;
  $("ag-req").innerHTML = `<table class="tt"><thead><tr><th>Identity</th><th>Entitlement</th><th>Justification</th><th>SoD</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  document.querySelectorAll("[data-appr]").forEach((el) => (el as HTMLElement).onclick = async () => {
    const id = (el as HTMLElement).dataset.appr!; const sod = (el as HTMLElement).dataset.sod === "1";
    let r = await postJSON(`/api/access-governance/request/${id}/decide`, { decision: "approve" });
    if (r.status === 409 || (r.body && r.body.needsOverride)) {
      if (!confirm("⚠ This grant creates a Segregation-of-Duties conflict. Approve anyway and ACCEPT the risk (audited)?")) return;
      r = await postJSON(`/api/access-governance/request/${id}/decide`, { decision: "approve", overrideSod: true });
    }
    if (r.body && r.body.error && !r.body.ok) alert("⚠️ " + r.body.error);
    load(); void sod;
  });
  document.querySelectorAll("[data-deny]").forEach((el) => (el as HTMLElement).onclick = async () => { await postJSON(`/api/access-governance/request/${(el as HTMLElement).dataset.deny}/decide`, { decision: "deny" }); load(); });
}

function renderJit(j: any[]): void {
  const rows = j.map((x) => `<tr><td>${esc(x.identityName)}</td><td><b>${esc(x.entitlement)}</b></td><td>${esc(String(x.expiresDate).slice(0, 16).replace("T", " "))}</td><td class="${x.hoursLeft <= 2 ? "r-high" : "r-low"}">${x.hoursLeft}h left</td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">No active time-bound (JIT) grants.</td></tr>`;
  $("ag-jitgrants").innerHTML = `<table class="tt"><thead><tr><th>Identity</th><th>Entitlement</th><th>Expires</th><th>Window</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderRules(rules: any[]): void {
  const rows = rules.map((r) => `<tr>
    <td><b>${esc(r.name)}</b></td>
    <td><span class="pair"><b>${esc(r.functionA)}</b> ⚔ <b>${esc(r.functionB)}</b></span></td>
    <td class="${rk(r.risk)}">${esc(r.risk)}</td>
    <td class="muted" style="font-size:11px">${esc(r.mitigation || "—")}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No SoD rules.</td></tr>`;
  $("ag-rules").innerHTML = `<table class="tt"><thead><tr><th>Rule</th><th>Conflicting functions</th><th>Risk</th><th>Mitigating control</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="frm" style="margin-top:8px"><div class="grid">
      <div style="grid-column:span 2"><label>Rule name</label><input class="in" id="r-name" placeholder="Create Vendor + Pay Invoice"></div>
      <div><label>Function A</label><input class="in" id="r-a" placeholder="AP_VENDOR_MAINT"></div>
      <div><label>Function B</label><input class="in" id="r-b" placeholder="AP_PAYMENT"></div>
      <div><label>Risk</label><select class="in" id="r-risk"><option>critical</option><option selected>high</option><option>medium</option><option>low</option></select></div>
      <div style="grid-column:span 2"><label>Mitigating control</label><input class="in" id="r-mit" placeholder="Dual control on payment run"></div>
    </div><button class="btn sm" id="r-add">+ Add SoD rule</button></div>`;
  $("r-add").onclick = async () => {
    const name = ($("r-name") as HTMLInputElement).value.trim(), a = ($("r-a") as HTMLInputElement).value.trim(), b = ($("r-b") as HTMLInputElement).value.trim();
    if (!name || !a || !b) return;
    await postJSON("/api/access-governance/sod-rule", { name, functionA: a, functionB: b, risk: ($("r-risk") as HTMLSelectElement).value, mitigation: ($("r-mit") as HTMLInputElement).value });
    load();
  };
}

function renderEntitlements(ents: any[]): void {
  const rows = ents.map((e) => `<tr>
    <td><b>${esc(e.name)}</b>${e.privileged ? ` <span class="tag priv">privileged</span>` : ""}</td>
    <td><span class="tag app">${esc(e.app)}</span></td>
    <td class="${rk(e.risk)}">${esc(e.risk)}</td>
    <td>${e.holders}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No entitlements.</td></tr>`;
  $("ag-ents").innerHTML = `<table class="tt"><thead><tr><th>Entitlement</th><th>Application</th><th>Risk</th><th>Holders</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderOutliers(o: any[]): void {
  $("ag-outliers").innerHTML = o.length
    ? `<table class="tt"><thead><tr><th>Identity</th><th>Entitlement</th><th>Risk</th><th>Why flagged</th></tr></thead><tbody>${o.map((x) => `<tr><td>${esc(x.identityName)}</td><td><b>${esc(x.entitlement)}</b></td><td class="${rk(x.risk)}">${esc(x.risk)}</td><td class="muted" style="font-size:11px">${esc(x.reason)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">✓ No peer-group access outliers.</div>`;
}

document.addEventListener("DOMContentLoaded", load);
