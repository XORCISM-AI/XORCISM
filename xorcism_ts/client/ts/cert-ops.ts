/** cert-ops.ts — CERT/CSIRT operations cockpit (/cert-ops): forensic cases + chain of custody. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2400); }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const CHK_STATUS = ["compliant", "non-compliant", "in-progress", "to-verify"];
const chkLabel: Record<string, string> = { "compliant": "Compliant", "non-compliant": "Non-compliant", "in-progress": "In progress", "to-verify": "To verify" };

function renderChecklist(id: number, cl: any): string {
  if (!cl || !cl.started) {
    return `<div class="muted" style="font-size:12px;margin:6px 0">No methodology checklist yet — the FORENSIX DFIR methodology has <b>85 controls</b> across 6 phases (ISO/IEC 27037, RFC 3227, French CPP/RGPD, NIS2, ANSSI, MITRE ATT&CK).</div>
      <button class="btn-sm2" id="seed-chk" data-id="${id}">▶ Start methodology checklist (85 controls)</button>`;
  }
  const s = cl.summary;
  const bar = (pct: number): string => `<span class="cbar"><span style="width:${pct}%"></span></span> <b>${pct}%</b>`;
  const head = `<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin:4px 0 10px">
    ${bar(s.conformity)} <span class="muted" style="font-size:12px">${s.compliant}/${s.total} compliant</span>
    <span class="pill ok">${s.compliant} compliant</span> <span class="pill bad">${s.nonCompliant} non-compliant</span>
    <span class="pill" style="background:#3a2f12;color:#fbbf24">${s.inProgress} in progress</span> <span class="pill">${s.toVerify} to verify</span></div>`;
  const phases = cl.phases.map((ph: any) => `
    <div class="phbox"><div class="phhdr"><span class="pn">${esc(ph.name)}</span><span class="muted" style="font-size:11px">${esc(ph.sub)}</span>
      <span class="pa">${ph.conformity}% <span class="muted" style="font-weight:400">(${ph.compliant}/${ph.total})</span></span></div>
      ${ph.items.map((it: any) => `<div class="chk">
        <span class="cref">${esc(it.ref)}</span>
        <span class="ct">${esc(it.title)}<div class="cn" title="normative reference">${esc(it.norm)}</div></span>
        <select class="chk-st" data-id="${it.id}">${CHK_STATUS.map((x) => `<option value="${x}" ${x === it.status ? "selected" : ""}>${chkLabel[x]}</option>`).join("")}</select>
        <input class="chk-ev" data-id="${it.id}" value="${esc(it.evidenceRef)}" placeholder="evidence / proof ref…">
      </div>`).join("")}
    </div>`).join("");
  return head + phases;
}

function load(): void {
  fetch("/api/cert-ops").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card("Cases", String(s.cases), `${s.openCases} open`),
      card("Evidence", String(s.evidenceItems), "exhibits acquired"),
      card("Custody events", String(s.custodyEvents), "chain-of-custody log", "#60a5fa"),
      card("Activities", String(s.activities), `${s.openActivities} open`),
      card("Custody gaps", String(s.brokenCustody), "evidence w/o custody log", s.brokenCustody ? "#f87171" : "#4ade80"),
    ].join("");
    const cases = d.cases.length
      ? `<table class="t"><thead><tr><th>Case</th><th>Title</th><th>Sev</th><th>Examiner</th><th>Evidence</th><th>Custody</th><th>Status</th><th></th></tr></thead><tbody>${d.cases.map((c: any) => `<tr>
          <td class="mono">${esc(c.number)}</td><td><span class="nm">${esc(c.title)}</span>${c.incidentId ? ` <span class="muted" style="font-size:10px">inc #${c.incidentId}</span>` : ""}</td>
          <td><span class="sev ${scls(c.severity)}">${esc(c.severity || "—")}</span></td><td>${esc(c.examiner || "—")}</td>
          <td>${c.evidence}</td><td>${c.custody ? `<span class="pill ok">${c.custody}</span>` : `<span class="pill bad">0</span>`}</td>
          <td>${esc(c.status)}</td><td><button class="btn-sm2 open" data-id="${c.id}">Open</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No forensic cases yet.</div>`;
    const acts = d.activities.length
      ? `<table class="t"><thead><tr><th>Activity</th><th>Service</th><th>Type</th><th>Priority</th><th>Owner</th><th>Status</th></tr></thead><tbody>${d.activities.map((a: any) => `<tr><td><span class="nm">${esc(a.title)}</span></td><td><span class="pill">${esc(a.service)}</span></td><td>${esc(a.type)}</td><td>${esc(a.priority)}</td><td>${esc(a.assignedTo || "—")}</td><td>${esc(a.status)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No CERT activities.</div>`;
    const refs = d.references.map((r: any) => `<div class="refrow"><b>${esc(r.ref)}</b> — ${esc(r.title)}</div>`).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">Forensic cases (${d.cases.length})<span class="spacer"></span><button class="btn-sm2" id="new-case">+ New case</button></div>${cases}
      <div class="sec">CERT activities (${d.activities.length})<span class="spacer"></span><button class="btn-sm2" id="new-act">+ New activity</button></div>${acts}
      <div class="grid2" style="margin-top:8px"><div class="panel"><div class="sec" style="margin-top:0">State-of-the-art references</div>${refs}</div>
        <div class="panel"><div class="sec" style="margin-top:0">CSIRT services</div>${(d.services || []).map((x: string) => `<span class="pill" style="margin:3px 4px 3px 0;display:inline-block">${esc(x)}</span>`).join("")}</div></div>`;
    Array.prototype.forEach.call(document.querySelectorAll(".open"), (b: HTMLElement) => { b.onclick = () => openCase(Number(b.getAttribute("data-id"))); });
    $("new-case").onclick = newCase;
    $("new-act").onclick = newActivity;
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function openCase(id: number): void {
  fetch(`/api/cert-ops/case/${id}`).then((r) => r.json()).then((d) => {
    const c = d.case;
    const ev = d.evidence.length ? d.evidence.map((e: any) => `<div class="ev">
      <div style="display:flex;align-items:center;gap:8px"><span class="pill">${esc(e.exhibit)}</span><b style="color:#e2e8f0">${esc(e.description)}</b><span class="muted" style="font-size:11px">${esc(e.type)}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2 add-cust" data-ev="${e.id}">+ custody</button></div>
      <div class="muted" style="font-size:11px;margin:4px 0">${esc(e.source)} · ${esc(e.tool)} · ${esc(e.size)} · ${esc(e.storage)}</div>
      ${e.sha256 ? `<div class="mono" style="color:#94a3b8">sha256: ${esc(e.sha256)}</div>` : ""}
      <div style="margin-top:6px;font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px">Chain of custody (${e.custody.length})</div>
      ${e.custody.map((x: any) => `<div class="cust"><span class="pill">${esc(x.action)}</span> ${esc(x.from || "?")} → <b style="color:#e2e8f0">${esc(x.to || "?")}</b> <span class="muted">${esc(x.purpose)}</span> ${x.verified ? `<span class="pill ok">hash ✓</span>` : `<span class="pill bad">unverified</span>`} <span class="muted" style="margin-left:auto;font-size:11px">${esc(x.at)}</span></div>`).join("") || `<div class="muted" style="font-size:11px">(no custody events)</div>`}
    </div>`).join("") : `<div class="muted">No evidence yet.</div>`;
    const cl = d.checklist;
    const clSummary = cl && cl.started ? ` · methodology conformity <b>${cl.summary.conformity}%</b>` : "";
    $("dlg").innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><span class="mono">${esc(c.number)}</span><b style="font-size:16px;color:#e7ebf3">${esc(c.title)}</b><span class="sev ${scls(c.severity)}">${esc(c.severity)}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2" id="add-ev">+ evidence</button><button class="btn-sm2" id="close">Close</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:10px">${esc(c.description)} · methodology: ${esc(c.methodology)} · opened ${esc(c.opened)}${c.incidentId ? ` · incident #${c.incidentId}` : ""}${clSummary}</div>
      <div style="margin-bottom:10px"><span class="tab on" data-tab="chk">🔎 Forensic methodology</span><span class="tab" data-tab="ev">📦 Evidence & custody</span></div>
      <div id="pane-chk">${renderChecklist(id, cl)}</div>
      <div id="pane-ev" style="display:none"><div class="sec" style="margin-top:0">Evidence & chain of custody</div>${ev}</div>`;
    $("modal").classList.add("show");
    $("close").onclick = () => $("modal").classList.remove("show");
    // tab switching
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), (t: HTMLElement) => { t.onclick = () => {
      Array.prototype.forEach.call(document.querySelectorAll(".tab"), (x: HTMLElement) => x.classList.remove("on"));
      t.classList.add("on"); const which = t.getAttribute("data-tab");
      $("pane-chk").style.display = which === "chk" ? "" : "none"; $("pane-ev").style.display = which === "ev" ? "" : "none";
    }; });
    const seedBtn = document.getElementById("seed-chk");
    if (seedBtn) seedBtn.onclick = () => post(`/api/cert-ops/case/${id}/checklist/seed`, {}, () => openCase(id));
    const saveCheck = (checkId: string, body: unknown) => fetch(`/api/cert-ops/check/${checkId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json()).then(() => openCase(id)).catch((e) => toast("⚠️ " + e));
    Array.prototype.forEach.call(document.querySelectorAll(".chk-st"), (sel: HTMLSelectElement) => { sel.onchange = () => saveCheck(sel.getAttribute("data-id")!, { status: sel.value }); });
    Array.prototype.forEach.call(document.querySelectorAll(".chk-ev"), (inp: HTMLInputElement) => { inp.onchange = () => saveCheck(inp.getAttribute("data-id")!, { evidenceRef: inp.value }); });
    $("add-ev").onclick = () => {
      const description = prompt("Evidence description:"); if (!description) return;
      const type = prompt("Type (disk-image / memory / log / file / network):", "disk-image") || "file";
      const sha256 = prompt("SHA-256 (optional):") || "";
      post(`/api/cert-ops/case/${id}/evidence`, { description, type, sha256, collectedBy: "Analyst", source: "Source system" }, () => openCase(id));
    };
    Array.prototype.forEach.call(document.querySelectorAll(".add-cust"), (b: HTMLElement) => { b.onclick = () => {
      const action = prompt("Custody action (Transferred / Analyzed / Sealed / Returned):", "Transferred"); if (!action) return;
      const to = prompt("To (party):") || ""; const purpose = prompt("Purpose:") || "";
      post(`/api/cert-ops/evidence/${b.getAttribute("data-ev")}/custody`, { action, to, from: "Examiner", purpose, verified: true }, () => openCase(id));
    }; });
  }).catch((e) => toast("⚠️ " + e));
}

function post(url: string, body: unknown, cb: () => void): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast("Saved"); cb(); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function newCase(): void {
  const title = prompt("Forensic case title:"); if (!title) return;
  const severity = prompt("Severity (Critical/High/Medium/Low):", "Medium") || "Medium";
  const examiner = prompt("Examiner:") || "";
  post("/api/cert-ops/case", { title, severity, examiner }, () => {});
}
function newActivity(): void {
  const title = prompt("CERT activity title:"); if (!title) return;
  const service = prompt("Service (Incident handling / Forensics & analysis / Threat intelligence / Coordination & disclosure):", "Incident handling") || "Incident handling";
  post("/api/cert-ops/activity", { title, service }, () => {});
}
document.addEventListener("DOMContentLoaded", () => { $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").classList.remove("show"); }); load(); });
