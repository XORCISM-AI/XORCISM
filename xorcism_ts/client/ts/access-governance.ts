/**
 * access-governance.ts — Access Governance cockpit (/access-governance).
 * KPIs + SoD violations worklist (mitigate/accept), pending access requests (approve/deny with SoD
 * override), JIT active grants, entitlement catalogue, SoD rules (+ add), and peer outliers.
 * All from /api/access-governance*.
 *
 * i18n: FR retrofit via the global `window.t` (set by session-ui.ts). Local `t(k, fb)` returns the
 * FR value when a key exists, else the English `fb` argument — so keys are FR-only (no EN dict entry).
 * Static HTML chrome is annotated with data-t / data-t-html and localized by translateChrome().
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

// FR retrofit helpers — window.t is set globally by session-ui.ts; FR-only keys, English via fb.
function t(k: string, fb: string): string {
  const fn = (window as any).t as ((k: string) => string) | undefined;
  const v = fn ? fn(k) : k;
  return v === k ? fb : v;
}
const fmt = (k: string, fb: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [kk, vv]) => s.split(`{${kk}}`).join(String(vv)), t(k, fb));
// Risk / status enums: translated for display, raw value kept for the CSS class (rk / st-).
const riskLabel = (r: string): string => t(`agov.risk.${String(r).toLowerCase()}`, String(r));
const statusLabel = (st: string): string => t(`agov.status.${String(st).toLowerCase()}`, String(st));

async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return { status: r.status, body: await r.json().catch(() => ({})) }; }

const rk = (r: string): string => `r-${esc(r)}`;
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ag-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function translateChrome(): void {
  document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim()); });
  document.querySelectorAll<HTMLElement>("[data-t-html]").forEach((el) => { el.innerHTML = t(el.getAttribute("data-t-html")!, el.innerHTML.trim()); });
}

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/access-governance"); } catch (e) { $("ag-body").innerHTML = `<div class="muted" style="padding:20px">${t("agov.loadFail", "Failed to load:")} ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  if (!s.entitlements) {
    $("ag-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">${t("agov.emptyIntro", "No entitlements yet. Seed a demo estate (entitlements, assignments, SoD rules, an access request & a JIT grant) to explore the cockpit, or import via the Saviynt connector.")}</div><button class="btn" id="seed">${t("agov.seedDemo", "Seed demo")}</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/access-governance/seed"); load(); };
    return;
  }
  const cards = [
    card(t("agov.cEnt", "Entitlements"), String(s.entitlements ?? 0), fmt("agov.cEntFoot", "{p} privileged · {h} high-risk", { p: s.privilegedEnt ?? 0, h: s.highRiskEnt ?? 0 })),
    card(t("agov.cViol", "SoD violations"), String(s.sodViolations ?? 0), fmt("agov.cViolFoot", "{n} critical/high", { n: s.sodCritical ?? 0 }), (s.sodViolations ? "#f87171" : "#22c55e")),
    card(t("agov.cRules", "SoD rules"), String(s.sodRules ?? 0), fmt("agov.cRulesFoot", "{n} mitigated/accepted", { n: s.sodMitigated ?? 0 })),
    card(t("agov.cReq", "Pending requests"), String(s.pendingRequests ?? 0), fmt("agov.cReqFoot", "{n} SoD-blocked", { n: s.sodBlockedPending ?? 0 }), (s.sodBlockedPending ? "#fbbf24" : s.pendingRequests ? "#60a5fa" : "#94a3b8")),
    card(t("agov.cJit", "JIT active"), String(s.jitActive ?? 0), t("agov.cJitFoot", "time-bound grants"), (s.jitActive ? "#c4b5fd" : "#94a3b8")),
    card(t("agov.cAssign", "Assignments"), String(s.assignments ?? 0), fmt("agov.cAssignFoot", "{n} identities", { n: s.identitiesWithAccess ?? 0 })),
    card(t("agov.cOut", "Peer outliers"), String(s.outliers ?? 0), t("agov.cOutFoot", "rare privileged access"), (s.outliers ? "#fb923c" : "#22c55e")),
  ].join("");

  $("ag-body").innerHTML = `
    <div class="ag-cards">${cards}</div>
    <div class="row">
      <button class="btn" id="ag-detect">&#128270; ${t("agov.runDetect", "Run SoD detection")}</button>
      <button class="btn sec" id="ag-jit">&#9203; ${t("agov.jitSweep", "JIT expiry sweep")}</button>
      <span class="muted" style="font-size:11px;margin-left:auto">${t("agov.tagline", "Saviynt-style IGA: entitlements · SoD · access requests · JIT")}</span>
    </div>
    <div class="ag-sec">${t("agov.secViol", "Segregation-of-Duties violations")}</div>
    <div id="ag-viol" style="overflow-x:auto"></div>
    <div class="ag-sec">${t("agov.secReq", "Pending access requests")}</div>
    <div id="ag-req" style="overflow-x:auto"></div>
    <div class="ag-sec">${t("agov.secJit", "Active JIT grants")}</div>
    <div id="ag-jitgrants" style="overflow-x:auto"></div>
    <div class="ag-sec">${t("agov.secRules", "SoD ruleset")}</div>
    <div id="ag-rules"></div>
    <div class="ag-sec">${t("agov.secEnt", "Entitlement catalogue")}</div>
    <div id="ag-ents" style="overflow-x:auto"></div>
    <div class="ag-sec">${t("agov.secOut", "Peer-group outliers")} <span class="muted" style="font-weight:400;text-transform:none">${t("agov.secOutHint", "— rare privileged access vs. same-type peers")}</span></div>
    <div id="ag-outliers"></div>`;

  renderViolations(d.sodViolations || []);
  renderRequests(d.pendingRequests || []);
  renderJit(d.jitActive || []);
  renderRules(d.sodRules || []);
  renderEntitlements(d.topEntitlements || []);
  renderOutliers(d.outliers || []);
  $("ag-detect").onclick = async () => { const r = await postJSON("/api/access-governance/detect"); if (r.body) alert(fmt("agov.detectMsg", "SoD detection: {v} open violation(s) (+{c} new / -{r} cleared) across {rules} rules.", { v: r.body.violations, c: r.body.created, r: r.body.resolved, rules: r.body.rules })); load(); };
  $("ag-jit").onclick = async () => { const r = await postJSON("/api/access-governance/jit-sweep"); if (r.body) alert(fmt("agov.sweepMsg", "JIT sweep: revoked {rev} expired grant(s), expired {exp} request(s).", { rev: r.body.revoked, exp: r.body.expired })); load(); };
}

function renderViolations(v: any[]): void {
  const rows = v.map((x) => `<tr>
    <td><b>${esc(x.ruleName)}</b><div class="muted" style="font-size:10px">${esc(x.detectedDate).slice(0, 10)}</div></td>
    <td>${esc(x.identityName)}</td>
    <td><span class="pair"><b>${esc(x.left)}</b> + <b>${esc(x.right)}</b></span></td>
    <td class="${rk(x.risk)}">${esc(riskLabel(x.risk))}</td>
    <td class="st-${esc(x.status)}">${esc(statusLabel(x.status))}${x.notes ? `<div class="muted" style="font-size:10px">${esc(x.notes)}</div>` : ""}</td>
    <td style="white-space:nowrap">${x.status === "open" ? `<button class="btn sm warn" data-mit="${x.id}">${t("agov.mitigate", "Mitigate")}</button> <button class="btn sm sec" data-acc="${x.id}">${t("agov.accept", "Accept")}</button>` : `<button class="btn sm sec" data-reopen="${x.id}">${t("agov.reopen", "Reopen")}</button>`}</td>
  </tr>`).join("") || `<tr><td colspan="6" class="muted">${t("agov.noViol", "No SoD violations — run detection after assigning access.")}</td></tr>`;
  $("ag-viol").innerHTML = `<table class="tt"><thead><tr><th>${t("agov.thRule", "Rule")}</th><th>${t("agov.thIdentity", "Identity")}</th><th>${t("agov.thConflictEnt", "Conflicting entitlements")}</th><th>${t("agov.thRisk", "Risk")}</th><th>${t("agov.thStatus", "Status")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  const setStatus = (id: string, status: string, prompt0: boolean) => async () => { let note = ""; if (prompt0) { note = window.prompt(fmt("agov.notePrompt", "{status} — note (mitigating control / justification):", { status: statusLabel(status) }), "") || ""; } await postJSON(`/api/access-governance/violation/${id}/status`, { status, note }); load(); };
  document.querySelectorAll("[data-mit]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.mit!, "mitigated", true));
  document.querySelectorAll("[data-acc]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.acc!, "accepted", true));
  document.querySelectorAll("[data-reopen]").forEach((el) => (el as HTMLElement).onclick = setStatus((el as HTMLElement).dataset.reopen!, "open", false));
}

function renderRequests(reqs: any[]): void {
  const rows = reqs.map((r) => `<tr>
    <td>${esc(r.identityName)}</td>
    <td><b>${esc(r.entitlementName)}</b>${r.jitHours ? ` <span class="tag jit">${fmt("agov.jitTag", "JIT {h}h", { h: r.jitHours })}</span>` : ""}</td>
    <td class="muted" style="font-size:11px">${esc(r.justification || "—")}</td>
    <td>${r.sodConflict ? `<span class="conf" title="${esc(r.sodDetail)}">⚠ ${t("agov.sodConflict", "SoD conflict")}</span>` : `<span class="r-low">${t("agov.clean", "clean")}</span>`}</td>
    <td style="white-space:nowrap"><button class="btn sm" data-appr="${r.id}" data-sod="${r.sodConflict ? 1 : 0}">${t("agov.approve", "Approve")}</button> <button class="btn sm danger" data-deny="${r.id}">${t("agov.deny", "Deny")}</button></td>
  </tr>`).join("") || `<tr><td colspan="5" class="muted">${t("agov.noReq", "No pending access requests.")}</td></tr>`;
  $("ag-req").innerHTML = `<table class="tt"><thead><tr><th>${t("agov.thIdentity", "Identity")}</th><th>${t("agov.thEnt", "Entitlement")}</th><th>${t("agov.thJustif", "Justification")}</th><th>${t("agov.thSod", "SoD")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  document.querySelectorAll("[data-appr]").forEach((el) => (el as HTMLElement).onclick = async () => {
    const id = (el as HTMLElement).dataset.appr!; const sod = (el as HTMLElement).dataset.sod === "1";
    let r = await postJSON(`/api/access-governance/request/${id}/decide`, { decision: "approve" });
    if (r.status === 409 || (r.body && r.body.needsOverride)) {
      if (!confirm(t("agov.sodOverride", "⚠ This grant creates a Segregation-of-Duties conflict. Approve anyway and ACCEPT the risk (audited)?"))) return;
      r = await postJSON(`/api/access-governance/request/${id}/decide`, { decision: "approve", overrideSod: true });
    }
    if (r.body && r.body.error && !r.body.ok) alert("⚠️ " + r.body.error);
    load(); void sod;
  });
  document.querySelectorAll("[data-deny]").forEach((el) => (el as HTMLElement).onclick = async () => { await postJSON(`/api/access-governance/request/${(el as HTMLElement).dataset.deny}/decide`, { decision: "deny" }); load(); });
}

function renderJit(j: any[]): void {
  const rows = j.map((x) => `<tr><td>${esc(x.identityName)}</td><td><b>${esc(x.entitlement)}</b></td><td>${esc(String(x.expiresDate).slice(0, 16).replace("T", " "))}</td><td class="${x.hoursLeft <= 2 ? "r-high" : "r-low"}">${fmt("agov.hLeft", "{h}h left", { h: x.hoursLeft })}</td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">${t("agov.noJit", "No active time-bound (JIT) grants.")}</td></tr>`;
  $("ag-jitgrants").innerHTML = `<table class="tt"><thead><tr><th>${t("agov.thIdentity", "Identity")}</th><th>${t("agov.thEnt", "Entitlement")}</th><th>${t("agov.thExpires", "Expires")}</th><th>${t("agov.thWindow", "Window")}</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderRules(rules: any[]): void {
  const rows = rules.map((r) => `<tr>
    <td><b>${esc(r.name)}</b></td>
    <td><span class="pair"><b>${esc(r.functionA)}</b> ⚔ <b>${esc(r.functionB)}</b></span></td>
    <td class="${rk(r.risk)}">${esc(riskLabel(r.risk))}</td>
    <td class="muted" style="font-size:11px">${esc(r.mitigation || "—")}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("agov.noRules", "No SoD rules.")}</td></tr>`;
  $("ag-rules").innerHTML = `<table class="tt"><thead><tr><th>${t("agov.thRule", "Rule")}</th><th>${t("agov.thConflictFn", "Conflicting functions")}</th><th>${t("agov.thRisk", "Risk")}</th><th>${t("agov.thMitControl", "Mitigating control")}</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="frm" style="margin-top:8px"><div class="grid">
      <div style="grid-column:span 2"><label>${t("agov.fRuleName", "Rule name")}</label><input class="in" id="r-name" placeholder="Create Vendor + Pay Invoice"></div>
      <div><label>${t("agov.fFnA", "Function A")}</label><input class="in" id="r-a" placeholder="AP_VENDOR_MAINT"></div>
      <div><label>${t("agov.fFnB", "Function B")}</label><input class="in" id="r-b" placeholder="AP_PAYMENT"></div>
      <div><label>${t("agov.thRisk", "Risk")}</label><select class="in" id="r-risk"><option value="critical">${t("agov.risk.critical", "critical")}</option><option value="high" selected>${t("agov.risk.high", "high")}</option><option value="medium">${t("agov.risk.medium", "medium")}</option><option value="low">${t("agov.risk.low", "low")}</option></select></div>
      <div style="grid-column:span 2"><label>${t("agov.thMitControl", "Mitigating control")}</label><input class="in" id="r-mit" placeholder="Dual control on payment run"></div>
    </div><button class="btn sm" id="r-add">${t("agov.addRule", "+ Add SoD rule")}</button></div>`;
  $("r-add").onclick = async () => {
    const name = ($("r-name") as HTMLInputElement).value.trim(), a = ($("r-a") as HTMLInputElement).value.trim(), b = ($("r-b") as HTMLInputElement).value.trim();
    if (!name || !a || !b) return;
    await postJSON("/api/access-governance/sod-rule", { name, functionA: a, functionB: b, risk: ($("r-risk") as HTMLSelectElement).value, mitigation: ($("r-mit") as HTMLInputElement).value });
    load();
  };
}

function renderEntitlements(ents: any[]): void {
  const rows = ents.map((e) => `<tr>
    <td><b>${esc(e.name)}</b>${e.privileged ? ` <span class="tag priv">${t("agov.privileged", "privileged")}</span>` : ""}</td>
    <td><span class="tag app">${esc(e.app)}</span></td>
    <td class="${rk(e.risk)}">${esc(riskLabel(e.risk))}</td>
    <td>${e.holders}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("agov.noEnt", "No entitlements.")}</td></tr>`;
  $("ag-ents").innerHTML = `<table class="tt"><thead><tr><th>${t("agov.thEnt", "Entitlement")}</th><th>${t("agov.thApp", "Application")}</th><th>${t("agov.thRisk", "Risk")}</th><th>${t("agov.thHolders", "Holders")}</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderOutliers(o: any[]): void {
  $("ag-outliers").innerHTML = o.length
    ? `<table class="tt"><thead><tr><th>${t("agov.thIdentity", "Identity")}</th><th>${t("agov.thEnt", "Entitlement")}</th><th>${t("agov.thRisk", "Risk")}</th><th>${t("agov.thWhy", "Why flagged")}</th></tr></thead><tbody>${o.map((x) => `<tr><td>${esc(x.identityName)}</td><td><b>${esc(x.entitlement)}</b></td><td class="${rk(x.risk)}">${esc(riskLabel(x.risk))}</td><td class="muted" style="font-size:11px">${esc(x.reason)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("agov.noOut", "✓ No peer-group access outliers.")}</div>`;
}

document.addEventListener("DOMContentLoaded", () => { translateChrome(); load(); });
