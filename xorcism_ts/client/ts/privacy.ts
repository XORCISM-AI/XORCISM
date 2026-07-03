/** privacy.ts — GDPR / DPO cockpit (/privacy). RoPA + DSAR + DPIA + breach register + worklist.
 *  Reads /api/privacy; create paths POST processing / dsar / breach. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2800); }

interface Data {
  summary: { processing: number; processingNoBasis: number; dsarTotal: number; dsarOpen: number; dsarOverdue: number; dpiaTotal: number; dpiaApproved: number; dpiaGaps: number; breaches: number; breachesUnnotified: number; breach72: number; processors: number; processorsNoClauses: number; actionsTotal: number; actionsOpen: number; actionsOverdue: number; actionsApplied: number; score: number; grade: string };
  processing: any[]; dsars: any[]; dpias: any[]; breaches: any[]; processors: any[]; actions: any[]; worklist: { kind: string; label: string; severity: string; ref: string }[];
  legalBases: string[]; dsarTypes: string[]; processorStatuses: string[]; actionStatuses: string[]; dpiaTriggers: { code: string; label: string }[];
}
let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pill = (txt: string, cls: string): string => `<span class="pill ${cls}">${esc(txt)}</span>`;

function render(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card(t("priv.cPosture"), `<span class="grade g-${s.grade}">${s.score}</span><span style="font-size:13px;color:#64748b">/100</span>`, fmt("priv.cPosture.foot", { g: s.grade })),
    card(t("priv.cProcessing"), String(s.processing), fmt("priv.cProcessing.foot", { n: s.processingNoBasis }), s.processingNoBasis ? "#fb923c" : "#34d399"),
    card(t("priv.cDsar"), String(s.dsarOpen), fmt("priv.cDsar.foot", { o: s.dsarOverdue, t: s.dsarTotal }), s.dsarOverdue ? "#f87171" : "#34d399"),
    card(t("priv.cDpia"), `${s.dpiaApproved}/${s.dpiaTotal}`, fmt("priv.cDpia.foot", { n: s.dpiaGaps }), s.dpiaGaps ? "#fb923c" : "#34d399"),
    card(t("priv.cBreaches"), String(s.breaches), fmt("priv.cBreaches.foot", { n: s.breach72 }), s.breach72 ? "#f87171" : s.breachesUnnotified ? "#fbbf24" : "#34d399"),
    card(t("priv.cProcessors"), String(s.processors), fmt("priv.cProcessors.foot", { n: s.processorsNoClauses }), s.processorsNoClauses ? "#fb923c" : "#34d399"),
    card(t("priv.cActions"), `${s.actionsApplied}/${s.actionsTotal}`, fmt("priv.cActions.foot", { n: s.actionsOverdue }), s.actionsOverdue ? "#f87171" : "#34d399"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev sv-${["Critical", "High", "Medium", "Low"].includes(w.severity) ? w.severity : "Low"}">${esc(w.severity)}</span> <span>${esc(w.label)}</span><span class="muted" style="margin-left:auto;font-size:11px">${esc(w.ref)}</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noWork")}</div>`;

  const proc = d.processing.length
    ? `<table class="pt"><thead><tr><th>${t("priv.thActivity")}</th><th>${t("priv.thPurpose")}</th><th>${t("priv.thBasis")}</th><th>${t("priv.thData")}</th><th>DPIA</th></tr></thead><tbody>${d.processing.map((p) => `<tr>
        <td><span class="nm">${esc(p.name)}</span>${p.crossBorder ? " " + pill(t("priv.pTransfer"), "p-info") : ""}${p.triggerCount ? " " + pill(fmt("priv.pTriggers", { n: p.triggerCount }), "p-warn") : ""}</td>
        <td class="muted">${esc(p.purpose || "—")}</td>
        <td>${p.legalBasis ? esc(p.legalBasis) : pill(t("priv.pMissing"), "p-bad")}</td>
        <td>${p.special ? pill(t("priv.pSpecial"), "p-warn") + " " : ""}<span class="pill ${/high/i.test(p.riskLevel) ? "p-bad" : "p-info"}">${esc(p.riskLevel || "—")}</span></td>
        <td>${p.dpiaApproved ? pill(t("priv.pApproved"), "p-ok") : p.hasDpia ? pill(t("priv.pDraft"), "p-warn") : (/high/i.test(p.riskLevel) || p.special ? pill(t("priv.pRequired"), "p-bad") : "<span class='muted'>n/a</span>")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noProcessing")}</div>`;

  const dsarRows = d.dsars.length
    ? `<table class="pt"><thead><tr><th>${t("priv.thSubject")}</th><th>${t("priv.thType")}</th><th>${t("priv.thReceived")}</th><th>${t("priv.thDue")}</th><th>${t("priv.thStatus")}</th><th></th></tr></thead><tbody>${d.dsars.map((r) => `<tr>
        <td class="nm">${esc(r.subject)}</td><td>${esc(r.type)}</td><td class="muted">${esc(r.received)}</td>
        <td>${r.overdue ? pill(fmt("priv.pOverdue", { d: esc(r.due) }), "p-bad") : esc(r.due) + (r.daysLeft != null && !r.closed ? ` <span class="muted">(${fmt("priv.daysLeft", { n: r.daysLeft })})</span>` : "")}</td>
        <td>${r.closed ? pill(esc(r.status || t("priv.done")), "p-ok") : pill(esc(r.status || t("priv.new")), r.overdue ? "p-bad" : "p-warn")}</td>
        <td>${r.closed ? "" : `<button class="btn-sm2" data-dsar-done="${r.id}">${t("priv.complete")}</button>`}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noDsar")}</div>`;

  const breachRows = d.breaches.length
    ? `<table class="pt"><thead><tr><th>${t("priv.thBreach")}</th><th>${t("priv.thDetected")}</th><th>${t("priv.thAffected")}</th><th>${t("priv.thSeverity")}</th><th>${t("priv.th72h")}</th></tr></thead><tbody>${d.breaches.map((b) => `<tr>
        <td class="nm">${esc(b.title)}</td><td class="muted">${esc(String(b.detected))}</td><td>${b.affected || "—"}</td>
        <td><span class="pill ${/high|crit/i.test(b.severity) ? "p-bad" : "p-info"}">${esc(b.severity || "—")}</span></td>
        <td>${b.notifiedAuthority ? pill(t("priv.pNotified"), "p-ok") : b.breached72 ? pill(fmt("priv.pBreached", { h: b.hoursSinceDetected ?? "?" }), "p-bad") : pill(fmt("priv.pElapsed", { h: b.hoursSinceDetected ?? 0 }), "p-warn")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noBreaches")}</div>`;

  const prioTxt = (n: number): string => n === 1 ? t("priv.prioHigh") : n === 3 ? t("priv.prioLow") : t("priv.prioMed");
  const procrRows = d.processors.length
    ? `<table class="pt"><thead><tr><th>${t("priv.thProcessor")}</th><th>${t("priv.thService")}</th><th>${t("priv.thArt28")}</th><th>${t("priv.thTransfer")}</th><th>${t("priv.thStatus")}</th></tr></thead><tbody>${d.processors.map((p) => `<tr>
        <td><span class="nm">${esc(p.name)}</span>${p.location ? ` <span class="muted">(${esc(p.location)})</span>` : ""}${p.linkedProcessing ? `<br><span class="muted" style="font-size:11px">→ ${esc(p.linkedProcessing)}</span>` : ""}</td>
        <td class="muted">${esc(p.service || "—")}</td>
        <td>${p.clausesVerified ? pill(t("priv.pClausesOk"), "p-ok") : pill(t("priv.pClausesGap"), "p-bad")}${p.dpoAppointed ? " " + pill(t("priv.pDpo"), "p-info") : ""}</td>
        <td>${p.transfersOutsideEU ? pill(t("priv.pOutsideEU"), "p-warn") : "<span class='muted'>—</span>"}</td>
        <td>${esc(p.status || "—")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noProcessors")}</div>`;

  const actRows = d.actions.length
    ? `<table class="pt"><thead><tr><th>${t("priv.thAction")}</th><th>${t("priv.thOwner")}</th><th>${t("priv.thPriority")}</th><th>${t("priv.thDue")}</th><th>${t("priv.thStatus")}</th><th></th></tr></thead><tbody>${d.actions.map((a) => `<tr>
        <td><span class="nm">${esc(a.name)}</span>${a.linkRef ? ` <span class="muted">→ ${esc(a.linkRef)}</span>` : ""}</td>
        <td class="muted">${esc(a.owner || "—")}</td>
        <td><span class="pill ${a.priority === 1 ? "p-bad" : a.priority === 3 ? "p-info" : "p-warn"}">${esc(prioTxt(a.priority))}</span></td>
        <td>${a.overdue ? pill(fmt("priv.pOverdue", { d: esc(a.due) }), "p-bad") : (a.due ? esc(a.due) : "—")}</td>
        <td>${a.done ? pill(esc(a.status || t("priv.done")), "p-ok") : pill(esc(a.status || t("priv.new")), a.overdue ? "p-bad" : "p-warn")}</td>
        <td>${a.done ? "" : `<button class="btn-sm2" data-action-done="${a.id}">${t("priv.markApplied")}</button>`}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("priv.noActions")}</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">⚖️ ${fmt("priv.secWorklist", { n: d.worklist.length })}</div><div class="panel">${work}</div>
    <div class="sec">📒 ${fmt("priv.secRopa", { n: d.processing.length })}</div><div class="panel">${proc}</div>
    <div class="sec">🏢 ${fmt("priv.secProcessors", { n: d.processors.length })}</div><div class="panel">${procrRows}</div>
    <div class="sec">📨 ${fmt("priv.secDsar", { n: d.dsars.length })}</div><div class="panel">${dsarRows}</div>
    <div class="sec">🚨 ${fmt("priv.secBreach", { n: d.breaches.length })}</div><div class="panel">${breachRows}</div>
    <div class="sec">✅ ${fmt("priv.secActions", { n: d.actions.length })}</div><div class="panel">${actRows}</div>`;

  Array.prototype.forEach.call(document.querySelectorAll("[data-dsar-done]"), (b: HTMLElement) => {
    b.onclick = () => act(`/api/privacy/dsar/${b.getAttribute("data-dsar-done")}/status`, { status: "Completed" }, t("priv.requestCompleted"));
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-action-done]"), (b: HTMLElement) => {
    b.onclick = () => act(`/api/privacy/action/${b.getAttribute("data-action-done")}/status`, { status: "Applied" }, t("priv.actionApplied"));
  });
}

function act(url: string, body: unknown, okMsg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function closeModal(): void { $("modal").classList.remove("show"); }
function openModal(html: string): void { $("dlg").innerHTML = html; $("modal").classList.add("show"); const c = document.getElementById("dlg-close"); if (c) c.onclick = closeModal; }

function procDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${t("priv.dProcTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${t("priv.close")}</button></div>
    <label>${t("priv.fName")}<input id="f-name" placeholder="${t("priv.fNamePh")}"></label>
    <label>${t("priv.fPurpose")}<input id="f-purpose" placeholder="${t("priv.fPurposePh")}"></label>
    <div class="row"><label>${t("priv.fBasis")}<select id="f-basis"><option value="">${t("priv.optSelect")}</option>${d.legalBases.map((b) => `<option>${esc(b)}</option>`).join("")}</select></label>
      <label>${t("priv.fRisk")}<select id="f-risk"><option value="Low">${t("priv.lvLow")}</option><option value="Medium" selected>${t("priv.lvMedium")}</option><option value="High">${t("priv.lvHigh")}</option></select></label></div>
    <label>${t("priv.fCats")}<input id="f-cats" placeholder="${t("priv.fCatsPh")}"></label>
    <label>${t("priv.fSubjects")}<input id="f-subj" placeholder="${t("priv.fSubjectsPh")}"></label>
    <label>${t("priv.fRetention")}<input id="f-ret" placeholder="${t("priv.fRetentionPh")}"></label>
    <div class="chk"><input type="checkbox" id="f-special"> ${t("priv.fSpecial")}</div>
    <div class="chk"><input type="checkbox" id="f-cross"> ${t("priv.fCross")}</div>
    <label>${t("priv.fSafeguard")}<input id="f-safeguard" placeholder="${t("priv.fSafeguardPh")}"></label>
    <div style="margin-top:8px;font-size:12px;color:#94a3b8">${t("priv.fTriggers")}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:2px 10px;margin-top:4px">${d.dpiaTriggers.map((tr) => `<label class="chk" style="font-size:12px"><input type="checkbox" class="f-trigger" value="${esc(tr.code)}"> ${esc(tr.label)}</label>`).join("")}</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#fb923c;color:#fdba74">${t("priv.addRopa")}</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const name = ($("f-name") as HTMLInputElement).value.trim();
    if (!name) { toast(t("priv.nameRequired")); return; }
    const dpiaTriggers = Array.prototype.slice.call(document.querySelectorAll(".f-trigger")).filter((c: HTMLInputElement) => c.checked).map((c: HTMLInputElement) => c.value);
    fetch("/api/privacy/processing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, purpose: ($("f-purpose") as HTMLInputElement).value, legalBasis: ($("f-basis") as HTMLSelectElement).value, riskLevel: ($("f-risk") as HTMLSelectElement).value,
      dataCategories: ($("f-cats") as HTMLInputElement).value, dataSubjects: ($("f-subj") as HTMLInputElement).value, retention: ($("f-ret") as HTMLInputElement).value,
      specialCategories: ($("f-special") as HTMLInputElement).checked, crossBorder: ($("f-cross") as HTMLInputElement).checked, transferSafeguard: ($("f-safeguard") as HTMLInputElement).value, dpiaTriggers }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("priv.addedRopa")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function processorDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${t("priv.dProcessorTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${t("priv.close")}</button></div>
    <label>${t("priv.fName")}<input id="f-name" placeholder="${t("priv.fProcNamePh")}"></label>
    <label>${t("priv.fService")}<input id="f-service" placeholder="${t("priv.fServicePh")}"></label>
    <div class="row"><label>${t("priv.fReferent")}<input id="f-ref"></label><label>${t("priv.fLocation")}<input id="f-loc" placeholder="${t("priv.fLocationPh")}"></label></div>
    <label>${t("priv.fLinkedProc")}<input id="f-linked" placeholder="${t("priv.fLinkedProcPh")}"></label>
    <div class="chk"><input type="checkbox" id="f-clauses"> ${t("priv.fClauses")}</div>
    <div class="chk"><input type="checkbox" id="f-sec"> ${t("priv.fSecAdopted")}</div>
    <div class="chk"><input type="checkbox" id="f-ropa"> ${t("priv.fMaintainsRopa")}</div>
    <div class="chk"><input type="checkbox" id="f-transfer"> ${t("priv.fTransferOut")}</div>
    <div class="chk"><input type="checkbox" id="f-dpo"> ${t("priv.fDpoAppointed")}</div>
    <label>${t("priv.fStatus")}<select id="f-status">${d.processorStatuses.map((sv) => `<option>${esc(sv)}</option>`).join("")}</select></label>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#34d399;color:#6ee7b7">${t("priv.addProcessor")}</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const name = ($("f-name") as HTMLInputElement).value.trim();
    if (!name) { toast(t("priv.nameRequired")); return; }
    fetch("/api/privacy/processor", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, service: ($("f-service") as HTMLInputElement).value, referent: ($("f-ref") as HTMLInputElement).value, location: ($("f-loc") as HTMLInputElement).value,
      linkedProcessing: ($("f-linked") as HTMLInputElement).value, status: ($("f-status") as HTMLSelectElement).value,
      clausesVerified: ($("f-clauses") as HTMLInputElement).checked, securityAdopted: ($("f-sec") as HTMLInputElement).checked, maintainsRopa: ($("f-ropa") as HTMLInputElement).checked,
      transfersOutsideEU: ($("f-transfer") as HTMLInputElement).checked, dpoAppointed: ($("f-dpo") as HTMLInputElement).checked }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("priv.addedProcessor")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function actionDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${t("priv.dActionTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${t("priv.close")}</button></div>
    <label>${t("priv.fName")}<input id="f-name" placeholder="${t("priv.fActionNamePh")}"></label>
    <label>${t("priv.fDescription")}<textarea id="f-desc" rows="2"></textarea></label>
    <div class="row"><label>${t("priv.fOwner")}<input id="f-owner"></label>
      <label>${t("priv.fPriority")}<select id="f-prio"><option value="1">${t("priv.prioHigh")}</option><option value="2" selected>${t("priv.prioMed")}</option><option value="3">${t("priv.prioLow")}</option></select></label>
      <label>${t("priv.fDue")}<input id="f-due" type="date"></label></div>
    <label>${t("priv.fStatus")}<select id="f-status">${d.actionStatuses.map((sv) => `<option>${esc(sv)}</option>`).join("")}</select></label>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#60a5fa;color:#93c5fd">${t("priv.addAction")}</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const name = ($("f-name") as HTMLInputElement).value.trim();
    if (!name) { toast(t("priv.nameRequired")); return; }
    fetch("/api/privacy/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, description: ($("f-desc") as HTMLTextAreaElement).value, owner: ($("f-owner") as HTMLInputElement).value,
      priority: Number(($("f-prio") as HTMLSelectElement).value), dueDate: ($("f-due") as HTMLInputElement).value || undefined, status: ($("f-status") as HTMLSelectElement).value }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("priv.addedAction")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function dsarDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${t("priv.dDsarTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${t("priv.close")}</button></div>
    <label>${t("priv.fSubject")}<input id="f-subject" placeholder="${t("priv.fSubjectPh")}"></label>
    <label>${t("priv.fEmail")}<input id="f-email" placeholder="${t("priv.fEmailPh")}"></label>
    <div class="row"><label>${t("priv.fType")}<select id="f-type">${d.dsarTypes.map((tt) => `<option>${esc(tt)}</option>`).join("")}</select></label>
      <label>${t("priv.fReceived")}<input id="f-recv" type="date"></label></div>
    <div class="muted" style="font-size:11px;margin-top:6px">${t("priv.dsarDueNote")}</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#fb923c;color:#fdba74">${t("priv.logRequest")}</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const subjectName = ($("f-subject") as HTMLInputElement).value.trim();
    if (!subjectName) { toast(t("priv.subjectRequired")); return; }
    fetch("/api/privacy/dsar", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      subjectName, subjectEmail: ($("f-email") as HTMLInputElement).value, requestType: ($("f-type") as HTMLSelectElement).value, receivedDate: ($("f-recv") as HTMLInputElement).value || undefined }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then((j) => { toast(fmt("priv.logged", { d: j.dueDate || "" })); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function breachDialog(): void {
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">${t("priv.dBreachTitle")}</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">${t("priv.close")}</button></div>
    <label>${t("priv.fTitle")}<input id="f-title" placeholder="${t("priv.fTitlePh")}"></label>
    <label>${t("priv.fDescription")}<textarea id="f-desc" rows="3"></textarea></label>
    <div class="row"><label>${t("priv.fAffected")}<input id="f-aff" type="number" placeholder="${t("priv.fAffectedPh")}"></label>
      <label>${t("priv.fSeverity")}<select id="f-sev"><option value="Low">${t("priv.lvLow")}</option><option value="Medium" selected>${t("priv.lvMedium")}</option><option value="High">${t("priv.lvHigh")}</option><option value="Critical">${t("priv.lvCritical")}</option></select></label>
      <label>${t("priv.fRiskSubjects")}<select id="f-risk"><option value="Low">${t("priv.lvLow")}</option><option value="Medium" selected>${t("priv.lvMedium")}</option><option value="High">${t("priv.lvHigh")}</option></select></label></div>
    <label>${t("priv.fCats")}<input id="f-cats" placeholder="${t("priv.fCatsBreachPh")}"></label>
    <div class="muted" style="font-size:11px;margin-top:6px">${t("priv.breach72Note")}</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#f87171;color:#fca5a5">${t("priv.recordBreach")}</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const title = ($("f-title") as HTMLInputElement).value.trim();
    if (!title) { toast(t("priv.titleRequired")); return; }
    fetch("/api/privacy/breach", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      title, description: ($("f-desc") as HTMLTextAreaElement).value, affectedSubjects: Number(($("f-aff") as HTMLInputElement).value) || 0,
      severity: ($("f-sev") as HTMLSelectElement).value, riskToSubjects: ($("f-risk") as HTMLSelectElement).value, dataCategories: ($("f-cats") as HTMLInputElement).value }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(t("priv.breachRecorded")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function reload(): Promise<void> {
  return fetch("/api/privacy").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
  ($("btn-proc") as HTMLButtonElement).onclick = procDialog;
  ($("btn-processor") as HTMLButtonElement).onclick = processorDialog;
  ($("btn-dsar") as HTMLButtonElement).onclick = dsarDialog;
  ($("btn-breach") as HTMLButtonElement).onclick = breachDialog;
  ($("btn-action") as HTMLButtonElement).onclick = actionDialog;
  reload().then(render).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
