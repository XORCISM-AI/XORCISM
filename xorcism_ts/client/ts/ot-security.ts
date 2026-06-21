/**
 * ot-security.ts — OT / ICS / SCADA / IoT Security cockpit (/ot-security). Dashboard of OT
 * assessments (IEC 62443 / NIST SP 800-82, over AUDIT), OT assets (by tag), IEC 62443 zones, the
 * findings worklist and the seeded requirement catalogues, + a guided "New OT assessment" modal.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Assessment { id: number; name: string; standard: string; status: string; date: string | null; findings: number; open: number; high: number; overdue: number; score: number; }
interface Finding { id: number; assessment: string; name: string; severity: string; overdue: boolean; }
interface OtAsset { id: number; name: string; criticality: string; tags: string[]; }
interface Zone { id: number; name: string; purdue: string | null; slt: number | null; sla: number | null; criticality: string | null; }
interface Inventory {
  assessments: Assessment[]; findings: Finding[]; otAssets: OtAsset[]; zones: Zone[];
  summary: {
    assessments: number; inProgress: number; completed: number; openFindings: number; highOpen: number; overdue: number;
    otAssets: number; byTag: Record<string, number>; zones: number; conduits: number; slGaps: number;
    catalogue: { iec62443?: number; nist80082?: number; total: number }; bySeverity: Record<string, number>; byStandard: Record<string, number>;
  };
}

const stClass = (s: string): string => (/complet|clos|done/i.test(s) ? "st-done" : /progress|review|field|scoping/i.test(s) ? "st-prog" : "st-plan");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ot-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function assessmentRow(a: Assessment): string {
  const posture = a.open ? `<span class="chip">${a.open} open</span>${a.high ? `<span class="chip" style="color:#fca5a5">${a.high} high</span>` : ""}${a.overdue ? `<span class="chip" style="color:#fca5a5">${a.overdue} overdue</span>` : ""}` : `<span class="chip" style="color:#86efac">clean</span>`;
  return `<tr>
    <td><div class="aname">${esc(a.name)}</div></td>
    <td><span class="chip">${esc(a.standard)}</span></td>
    <td><span class="st ${stClass(a.status)}">${esc(a.status)}</span></td>
    <td>${a.findings}</td><td>${posture}</td>
    <td class="score ${scoreClass(a.score)}">${a.score || ""}</td>
    <td><a class="chip" href="/?db=XCOMPLIANCE&table=AUDITFINDING&filterCol=AuditID&filterVal=${a.id}">findings ↗</a>
        <a class="chip" href="/?db=XCOMPLIANCE&table=AUDIT&editCol=AuditID&editVal=${a.id}">edit ↗</a></td>
  </tr>`;
}

function slCell(z: Zone): string {
  if (z.slt == null) return `<span class="muted">—</span>`;
  const gap = z.sla == null || z.sla < z.slt;
  return `<span class="sl ${gap ? "sl-gap" : "sl-ok"}">SL-A ${z.sla ?? "?"} / SL-T ${z.slt}</span>`;
}

function referenceHtml(cat: Inventory["summary"]["catalogue"]): string {
  return `<div class="ref">
    <div class="col"><h4>IEC 62443 foundational requirements</h4><ul>
      <li><b>FR1</b> Identification &amp; authentication control</li><li><b>FR2</b> Use control</li>
      <li><b>FR3</b> System integrity</li><li><b>FR4</b> Data confidentiality</li>
      <li><b>FR5</b> Restricted data flow (zones &amp; conduits)</li><li><b>FR6</b> Timely response to events</li>
      <li><b>FR7</b> Resource availability</li></ul></div>
    <div class="col"><h4>Security Levels (SL 1-4)</h4><ul>
      <li><b>SL 1</b> protect against casual / coincidental violation</li>
      <li><b>SL 2</b> intentional, simple means, low resources</li>
      <li><b>SL 3</b> sophisticated means, moderate resources (ICS-specific skills)</li>
      <li><b>SL 4</b> sophisticated means, extended resources (nation-state)</li></ul>
      <div class="muted" style="font-size:11px;margin-top:5px">Each zone/conduit carries a target (SL-T), achieved (SL-A) and capability (SL-C) level.</div></div>
    <div class="col"><h4>Seeded requirement catalogues</h4><ul>
      <li><b>IEC 62443-3-3</b>: ${cat.iec62443 ?? 0} system requirements (FR1-7 / SR x.y)</li>
      <li><b>NIST SP 800-82 Rev 3</b>: ${cat.nist80082 ?? 0} OT control-overlay families</li></ul>
      ${cat.total ? `<a class="chip" href="/?db=XCOMPLIANCE&table=REFERENCECONTROL">browse the catalogue ↗</a>`
        : `<div class="muted" style="font-size:11px">Run <code>python xorcism_python/importers/import_iec62443.py</code> to seed the catalogues.</div>`}</div>
  </div>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/ot-security"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ot-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  const cards = [
    card("OT assessments", String(s.assessments), `${s.inProgress} in progress · ${s.completed} done`),
    card("OT assets", String(s.otAssets), "tagged ot/ics/scada/iot…", s.otAssets ? "#7dd3fc" : undefined),
    card("Zones / conduits", `${s.zones}/${s.conduits}`, "IEC 62443 segmentation"),
    card("SL gaps", String(s.slGaps), "zones below target SL", s.slGaps ? "#f87171" : "#34d399"),
    card("Open findings", String(s.openFindings), `${s.highOpen} high/critical`, s.highOpen ? "#f87171" : s.openFindings ? "#fb923c" : "#34d399"),
    card("Catalogue", String(s.catalogue.total), "IEC 62443 + 800-82 reqs", s.catalogue.total ? undefined : "#fbbf24"),
  ].join("");

  const byTag = Object.entries(s.byTag).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="chip"><span class="tag">${esc(k)}</span> ${n}</span>`).join("");
  const byStd = Object.entries(s.byStandard).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="chip">${esc(k)} <b>${n}</b></span>`).join("");

  const assessTable = d.assessments.length
    ? `<table class="ot"><thead><tr><th>Assessment</th><th>Standard</th><th>Status</th><th>Findings</th><th>Posture</th><th title="Posture score">Score</th><th></th></tr></thead>
        <tbody>${d.assessments.map(assessmentRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:16px 0">No OT assessment yet. Click <b>+ New OT assessment</b> to start one against IEC 62443 / NIST 800-82.</div>`;

  const assetTable = d.otAssets.length
    ? `<table class="ot"><thead><tr><th>OT asset</th><th>Criticality</th><th>Tags</th></tr></thead>
        <tbody>${d.otAssets.map((a) => `<tr><td><a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}">${esc(a.name)}</a></td>
          <td>${esc(a.criticality) || "<span class='muted'>—</span>"}</td>
          <td>${a.tags.map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">No assets tagged as OT yet. Tag your ICS/SCADA/IoT assets <span class="tag">ot</span><span class="tag">ics</span><span class="tag">scada</span>… on the ASSET form (these tags also drive CVE→asset matching).</div>`;

  const zonesTable = d.zones.length
    ? `<table class="ot"><thead><tr><th>Zone</th><th>Purdue</th><th>Criticality</th><th>Security Level</th></tr></thead>
        <tbody>${d.zones.map((z) => `<tr><td class="aname">${esc(z.name)}</td><td>${esc(z.purdue ?? "") || "—"}</td>
          <td>${esc(z.criticality ?? "") || "—"}</td><td>${slCell(z)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">No IEC 62443 zones defined yet — add <a href="/?db=XCOMPLIANCE&table=OTZONE">zones &amp; conduits</a> with target/achieved Security Levels.</div>`;

  $("ot-body").innerHTML = `<div class="ot-cards">${cards}</div>
    ${byTag ? `<div class="ot-section">OT assets by tag</div><div>${byTag}</div>` : ""}
    ${byStd ? `<div class="ot-section">Assessments by standard</div><div>${byStd}</div>` : ""}
    <div class="ot-section">OT assessments (${d.assessments.length})</div>${assessTable}
    <div class="ot-section">Open findings (${d.findings.length})</div>${d.findings.length
      ? `<ul style="list-style:none;margin:0;padding:0">${d.findings.slice(0, 40).map((f) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="sev-${esc(f.severity)}">${esc(f.severity)}</span> · <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">${esc(f.assessment)}</a> — ${esc(f.name)}${f.overdue ? ' <span class="chip" style="color:#fca5a5">overdue</span>' : ""}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">✓ No open OT findings.</div>`}
    <div class="ot-section">OT assets (${d.otAssets.length})</div>${assetTable}
    <div class="ot-section">IEC 62443 zones (${d.zones.length})</div>${zonesTable}
    <div class="ot-section">IEC 62443 / NIST SP 800-82 reference</div>${referenceHtml(s.catalogue)}
    <div class="legend">↳ OT assessments reuse the AUDIT workflow (type <b>OT Security</b>); manage findings under
      <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">Findings</a>, zones/conduits under
      <a href="/?db=XCOMPLIANCE&table=OTZONE">OTZONE</a>/<a href="/?db=XCOMPLIANCE&table=OTCONDUIT">OTCONDUIT</a>.</div>`;
}

// ── Guided "new OT assessment" modal ───────────────────────────────────────────
function openModal(): void {
  for (const id of ["ot-f-name", "ot-f-auditor", "ot-f-scope", "ot-f-desc"]) (document.getElementById(id) as HTMLInputElement).value = "";
  (document.getElementById("ot-f-standard") as HTMLSelectElement).value = "IEC 62443-3-3";
  (document.getElementById("ot-f-status") as HTMLSelectElement).value = "Planned";
  (document.getElementById("ot-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("ot-f-err").textContent = "";
  $("ot-modal").classList.add("open");
  ($("ot-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("ot-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAssessment(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("ot-f-name").trim();
  const err = $("ot-f-err");
  if (!name) { err.textContent = "⚠️ Enter a name."; ($("ot-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("ot-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = "Creating…";
  try {
    const body = {
      name, standard: v("ot-f-standard"), status: v("ot-f-status"),
      auditor: v("ot-f-auditor").trim() || undefined, date: v("ot-f-date") || undefined,
      scope: v("ot-f-scope").trim() || undefined, description: v("ot-f-desc").trim() || undefined,
    };
    const r = await fetch("/api/ot-security/assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    toast(`✅ OT assessment created — <a href="/?db=XCOMPLIANCE&table=AUDIT&editCol=AuditID&editVal=${d.id}" style="color:#7dd3fc">open it ↗</a>`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("ot-new").addEventListener("click", openModal);
  $("ot-cancel").addEventListener("click", closeModal);
  $("ot-create").addEventListener("click", () => void createAssessment());
  $("ot-modal").addEventListener("click", (e) => { if (e.target === $("ot-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("ot-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAssessment(); });
  void load();
});
