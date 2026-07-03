/**
 * agent-firewall.ts — Agent Policy Firewall cockpit (/agent-firewall).
 * KPIs + the signed-receipt-chain integrity badge, a "test the gate" simulator (POST /evaluate), the
 * policy list (+ add/delete), and the action ledger with verdicts, blast-radius, replay/SoD flags and
 * pending-approval controls. All from /api/agent-firewall*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

const blastColor = (n: number): string => (n >= 80 ? "#ef4444" : n >= 60 ? "#fb923c" : n >= 35 ? "#fbbf24" : "#22c55e");
let REF: any = { actionTypes: [], decisions: [], sensitivity: [] };
const opts = (arr: string[], sel?: string): string => arr.map((o) => `<option${sel === o ? " selected" : ""}>${esc(o)}</option>`).join("");
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="af-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/agent-firewall"); } catch (e) { $("af-body").innerHTML = `<div class="muted" style="padding:20px">${t("af.failLoad", "Failed to load")}: ${esc(String(e))}</div>`; return; }
  REF = d; const s = d.summary || {}; const rc = d.receipts || { ok: true, total: 0, verified: 0 };
  if (!d.policies.length && !s.actions) {
    $("af-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">${t("af.emptyMsg", "No policies yet. Seed the default firewall policy set + sample actions to begin.")}</div><button class="btn" id="seed">${t("af.seedBtn", "Seed firewall")}</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/agent-firewall/seed"); load(); };
    return;
  }
  const cards = [
    card(t("af.k.governed", "Actions governed"), String(s.actions ?? 0), t("af.k.governedFoot", "evaluated by the gate")),
    card(t("af.k.allowed", "Allowed"), String(s.allowed ?? 0), t("af.k.allowedFoot", "auto + approved"), "#22c55e"),
    card(t("af.k.denied", "Denied"), String(s.denied ?? 0), t("af.k.deniedFoot", "blocked before running"), (s.denied ? "#f87171" : "#94a3b8")),
    card(t("af.k.pending", "Pending approval"), String(s.pending ?? 0), t("af.k.pendingFoot", "awaiting a human"), (s.pending ? "#fbbf24" : "#94a3b8")),
    card(t("af.k.blast", "Avg blast radius"), String(s.avgBlast ?? 0), "0–100", blastColor(s.avgBlast ?? 0)),
    card(t("af.k.replay", "Replay blocked"), String(s.replayBlocked ?? 0), t("af.k.replayFoot", "duplicate actions"), (s.replayBlocked ? "#fb923c" : "#94a3b8")),
    card(t("af.k.sod", "SoD violations"), String(s.sodViolations ?? 0), t("af.k.sodFoot", "self-approval attempts"), (s.sodViolations ? "#f87171" : "#94a3b8")),
    card(t("af.k.receipt", "Receipt chain"), rc.ok ? `✓ ${t("af.intact", "intact")}` : `✗ ${t("af.broken", "broken")}`, `${rc.verified}/${rc.total} ${t("af.signed", "signed")}`, rc.ok ? "#22c55e" : "#f87171"),
  ].join("");

  $("af-body").innerHTML = `
    <div class="af-cards">${cards}</div>

    <div class="af-sec">${t("af.owaspSec", "OWASP Agentic Top 10 verification")} <span class="muted" style="font-weight:400;text-transform:none">— ${t("af.owaspSub", "governance evidence from the firewall's controls (like AGT `agt verify`)")}</span></div>
    <div id="af-owasp"><div class="muted" style="font-size:12px;padding:4px 0">…</div></div>

    <div class="af-sec">${t("af.testGate", "Test the gate")}</div>
    <div class="frm">
      <div class="grid">
        <div><label>${t("af.actionType", "Action type")}</label><select class="in" id="t-type">${opts(REF.actionTypes)}</select></div>
        <div><label>${t("af.actor", "Actor (agent)")}</label><input class="in" id="t-actor" placeholder="remediation-agent"></div>
        <div><label>${t("af.sensitivity", "Sensitivity")}</label><select class="in" id="t-sens">${opts(REF.sensitivity, "medium")}</select></div>
        <div style="grid-column:span 2"><label>${t("af.target", "Target")}</label><input class="in" id="t-target" placeholder="${t("af.targetPh", "isolate prod database host")}"></div>
        <div style="grid-column:span 2"><label>${t("af.params", "Params (optional)")}</label><input class="in" id="t-params" placeholder="${t("af.paramsPh", "shutdown all sessions")}"></div>
      </div>
      <button class="btn" id="t-eval">&#9889; ${t("af.evalBtn", "Evaluate action")}</button>
      <div id="t-out"></div>
    </div>

    <div class="af-sec">${t("af.policies", "Policies")}</div>
    <div id="af-policies"></div>

    <div class="af-sec">${t("af.ledger", "Action ledger")} <span class="muted" style="font-weight:400;text-transform:none">— ${t("af.ledgerSub", "signed, tamper-evident")}</span></div>
    <div id="af-ledger" style="overflow-x:auto"></div>`;

  renderPolicies(d.policies);
  renderLedger(d.actions);
  void renderOwasp();
  $("t-eval").onclick = evalAction;
}

function renderPolicies(pols: any[]): void {
  const rows = pols.map((p) => `<tr>
    <td><b>${esc(p.name)}</b></td>
    <td><span class="tag">${esc(p.actionType || "*")}</span></td>
    <td>${esc(p.targetPattern || "—")}</td>
    <td>≥ ${p.minBlastRadius}</td>
    <td class="d-${p.decision === "deny" ? "denied" : p.decision === "approve" ? "pending" : "allowed"}">${esc(p.decision)}${p.decision === "approve" ? ` (${p.requireApprovers})` : ""}</td>
    <td>${p.enabled ? "✓" : `<span class='muted'>${t("af.off", "off")}</span>`}</td>
    <td><span class="xdel" data-delpol="${p.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="7" class="muted">${t("af.noPolicies", "No policies.")}</td></tr>`;
  $("af-policies").innerHTML = `<table class="tt"><thead><tr><th>${t("af.th.policy", "Policy")}</th><th>${t("af.actionType", "Action type")}</th><th>${t("af.th.targetPat", "Target pattern")}</th><th>${t("af.th.minBlast", "Min blast")}</th><th>${t("af.th.decision", "Decision")}</th><th>${t("af.th.on", "On")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <div class="frm" style="margin-top:8px">
      <div class="grid">
        <div style="grid-column:span 2"><label>${t("af.name", "Name")}</label><input class="in" id="p-name" placeholder="${t("af.namePh", "Approve high-blast cloud actions")}"></div>
        <div><label>${t("af.actionType", "Action type")}</label><select class="in" id="p-type"><option value="*">${t("af.anyType", "* any")}</option>${opts(REF.actionTypes)}</select></div>
        <div><label>${t("af.th.targetPat", "Target pattern")}</label><input class="in" id="p-target" placeholder="prod"></div>
        <div><label>${t("af.minBlastRadius", "Min blast radius")}</label><input class="in" id="p-blast" type="number" min="0" max="100" value="0"></div>
        <div><label>${t("af.th.decision", "Decision")}</label><select class="in" id="p-dec">${opts(REF.decisions)}</select></div>
        <div><label>${t("af.approvers", "Approvers (if approve)")}</label><input class="in" id="p-appr" type="number" min="0" value="1"></div>
      </div>
      <button class="btn sm" id="p-add">+ ${t("af.addPolicy", "Add policy")}</button>
    </div>`;
  document.querySelectorAll("[data-delpol]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/agent-firewall/policy/${(el as HTMLElement).dataset.delpol}`); load(); }; });
  $("p-add").onclick = async () => {
    const name = ($("p-name") as HTMLInputElement).value.trim(); if (!name) return;
    await postJSON("/api/agent-firewall/policy", { name, actionType: ($("p-type") as HTMLSelectElement).value, targetPattern: ($("p-target") as HTMLInputElement).value, minBlastRadius: Number(($("p-blast") as HTMLInputElement).value), decision: ($("p-dec") as HTMLSelectElement).value, requireApprovers: Number(($("p-appr") as HTMLInputElement).value) });
    load();
  };
}

function renderLedger(acts: any[]): void {
  const rows = acts.map((a) => `<tr>
    <td><span class="tag">${esc(a.actionType)}</span></td>
    <td>${esc(a.target)}${a.policy ? `<div class="muted" style="font-size:10px">${esc(a.policy)}</div>` : ""}</td>
    <td>${esc(a.actor)}</td>
    <td><span class="blast" style="color:${blastColor(a.blastRadius)}">${a.blastRadius}<span class="blastbar"><i style="width:${a.blastRadius}%;background:${blastColor(a.blastRadius)}"></i></span></span></td>
    <td class="d-${esc(a.status)}">${esc(a.status)}${a.replay ? `<span class="flag">${t("af.replay", "replay")}</span>` : ""}${a.sod ? `<span class="flag">SoD</span>` : ""}</td>
    <td class="muted" style="font-family:ui-monospace,monospace;font-size:10px">${esc(a.receipt)}…</td>
    <td>${a.status === "pending" ? `<button class="btn sm" data-appr="${a.id}">${t("af.approve", "approve")}</button> <button class="btn danger sm" data-deny="${a.id}">${t("af.deny", "deny")}</button>` : (a.approvedBy ? `<span class="muted" style="font-size:10px">✓ ${esc(a.approvedBy)}</span>` : "")}</td>
  </tr>`).join("") || `<tr><td colspan="7" class="muted">${t("af.noActions", "No actions evaluated yet — use “Test the gate”.")}</td></tr>`;
  $("af-ledger").innerHTML = `<table class="tt"><thead><tr><th>${t("af.lt.type", "Type")}</th><th>${t("af.target", "Target")}</th><th>${t("af.lt.actor", "Actor")}</th><th>${t("af.lt.blast", "Blast")}</th><th>${t("af.lt.verdict", "Verdict")}</th><th>${t("af.lt.receipt", "Receipt")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  document.querySelectorAll("[data-appr]").forEach((el) => { (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/agent-firewall/action/${(el as HTMLElement).dataset.appr}/approve`); if (r && r.error) alert(r.error); load(); }; });
  document.querySelectorAll("[data-deny]").forEach((el) => { (el as HTMLElement).onclick = async () => { await postJSON(`/api/agent-firewall/action/${(el as HTMLElement).dataset.deny}/deny`); load(); }; });
}

async function evalAction(): Promise<void> {
  const target = ($("t-target") as HTMLInputElement).value.trim(); if (!target) { ($("t-target") as HTMLInputElement).focus(); return; }
  const out = await postJSON("/api/agent-firewall/evaluate", {
    actionType: ($("t-type") as HTMLSelectElement).value, actor: ($("t-actor") as HTMLInputElement).value || undefined,
    sensitivity: ($("t-sens") as HTMLSelectElement).value, target, params: ($("t-params") as HTMLInputElement).value || undefined,
  });
  const color = out.status === "denied" ? "#f87171" : out.status === "pending" ? "#fbbf24" : "#22c55e";
  $("t-out").innerHTML = `<div class="verdict"><b style="color:${color}">${esc((out.status || "").toUpperCase())}</b> · ${t("af.blastRadius", "blast radius")} <b style="color:${blastColor(out.blastRadius)}">${out.blastRadius}</b>${out.replay ? ` · <span class="flag">${t("af.replayBlocked", "replay blocked")}</span>` : ""}
    \n${esc(out.rationale || "")}
    \n${t("af.signedReceipt", "Signed receipt")}: ${esc(String(out.receipt || "").slice(0, 24))}…</div>`;
  load();
}

// OWASP Agentic Top 10 verification panel (replicates AGT `agt verify` from the firewall's controls).
async function renderOwasp(): Promise<void> {
  const host = document.getElementById("af-owasp"); if (!host) return;
  let d: any;
  try { d = await getJSON("/api/agent-firewall/owasp-agentic"); } catch { host.innerHTML = ""; return; }
  const st = d.summary;
  const dot = (s: string): string => s === "covered" ? "#22c55e" : s === "partial" ? "#fbbf24" : "#f87171";
  const lbl = (s: string): string => s === "covered" ? t("af.owCovered", "covered") : s === "partial" ? t("af.owPartial", "partial") : t("af.owGap", "gap");
  const barColor = st.pct >= 80 ? "#22c55e" : st.pct >= 50 ? "#fbbf24" : "#f87171";
  const cells = (d.categories as any[]).map((c) => `<div style="background:#0f1322;border:1px solid #2d3250;border-left:3px solid ${dot(c.status)};border-radius:8px;padding:8px 10px">
    <div style="display:flex;align-items:center;gap:6px"><span class="tag" style="background:#1e2440;color:#c4b5fd;font-size:10px">${esc(c.code)}</span><b style="font-size:12px;color:#e2e8f0">${esc(c.name)}</b><span style="flex:1"></span><span style="font-size:10.5px;color:${dot(c.status)};font-weight:700">${esc(lbl(c.status))}</span></div>
    <div class="muted" style="font-size:10.5px;margin-top:3px">${esc(c.control)} · <span style="color:#94a3b8">NIST ${esc(c.nist)}</span></div>
    <div class="muted" style="font-size:10px;margin-top:2px">${esc(c.detail)}</div></div>`).join("");
  host.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
      <div style="font-size:26px;font-weight:800;color:${barColor}">${st.pct}%</div>
      <div style="flex:1;max-width:320px"><div style="height:8px;border-radius:4px;background:#1e2133;overflow:hidden"><i style="display:block;height:100%;width:${st.pct}%;background:${barColor}"></i></div>
        <div class="muted" style="font-size:11px;margin-top:3px">${st.covered} ${t("af.owCovered", "covered")} · ${st.partial} ${t("af.owPartial", "partial")} · ${st.gap} ${t("af.owGap", "gap")}</div></div>
      <span style="flex:1"></span>
      <span class="muted" style="font-size:11px">${d.summary.policies} ${t("af.owPolicies", "active policies")} · ${st.receiptChainOk ? "✓ " + t("af.owReceipts", "receipt chain intact") : t("af.owNoReceipts", "no receipt chain")}</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:8px">${cells}</div>`;
}

document.addEventListener("DOMContentLoaded", load);
