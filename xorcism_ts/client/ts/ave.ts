/**
 * ave.ts — AVE (Agentic Vulnerability Enumeration) — /ave.
 * Two views: the reference Catalogue (filterable records) and Agent exposure (the AVE catalogue
 * mapped onto the discovered AI agents — a behavioral scan, governance-aware). All from /api/ave*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

let VIEW: "catalogue" | "exposure" | "scan" = "catalogue";
let STATE = { severity: "", componentType: "", q: "" };
const chips = (v: string, cls: string): string => (v || "").split(/,\s*/).filter(Boolean).map((x) => `<span class="chip ${cls}">${esc(x)}</span>`).join("");
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="av-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
const sevTag = (sv: string): string => `<span class="sev ${esc((sv || "").toUpperCase())}">${esc(sv || "-")}</span>`;

function tabs(): string {
  const tb = (k: string, label: string) => `<button class="btn ${VIEW === k ? "" : "sec"} sm" data-view="${k}">${esc(label)}</button>`;
  return `<div class="bar" style="margin-bottom:14px">${tb("catalogue", t("ave.tab.catalogue", "Catalogue"))} ${tb("exposure", t("ave.tab.exposure", "Agent exposure"))} ${tb("scan", t("ave.tab.scan", "Scan findings"))}</div>`;
}

function route(): void {
  $("av-body").innerHTML = tabs() + `<div id="av-view"><div class="muted" style="padding:20px">Loading…</div></div>`;
  document.querySelectorAll<HTMLElement>("[data-view]").forEach((b) => { b.onclick = () => { VIEW = b.dataset.view as any; route(); }; });
  if (VIEW === "catalogue") loadCatalogue(); else if (VIEW === "exposure") loadExposure(); else loadScan();
}

// ── Catalogue view ───────────────────────────────────────────────────────────
async function loadCatalogue(): Promise<void> {
  const qs = new URLSearchParams();
  if (STATE.severity) qs.set("severity", STATE.severity);
  if (STATE.componentType) qs.set("componentType", STATE.componentType);
  if (STATE.q) qs.set("q", STATE.q);
  let d: any;
  try { d = await getJSON("/api/ave?" + qs.toString()); } catch (e) { $("av-view").innerHTML = `<div class="muted">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  if (!s.total) {
    $("av-view").innerHTML = `<div class="av-card" style="max-width:600px"><div class="muted" style="margin-bottom:10px">${esc(t("ave.empty", "No AVE records loaded yet. Seed the bundled sample, or import a full AVE export via the ave connector."))}</div>
      <button class="btn" id="seed">${esc(t("ave.seed", "Load AVE sample"))}</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/ave/seed"); loadCatalogue(); };
    return;
  }
  const comps = Object.keys(s.byComponent || {});
  const cards = [
    card(t("ave.kpi.total", "AVE records"), String(s.total ?? 0), t("ave.kpi.totalFoot", "behavioral classes")),
    card(t("ave.kpi.critical", "Critical"), String(s.critical ?? 0), t("ave.kpi.criticalFoot", "AIVSS ≥ 9.0"), (s.critical ? "#fca5a5" : "#94a3b8")),
    card(t("ave.kpi.high", "High"), String(s.high ?? 0), t("ave.kpi.highFoot", "AIVSS 7.0–8.9"), (s.high ? "#fcd34d" : "#94a3b8")),
    card(t("ave.kpi.avg", "Avg AIVSS"), String(s.avgAivss ?? 0), t("ave.kpi.avgFoot", "agentic-amplified"), "#60a5fa"),
    card(t("ave.kpi.atlas", "ATLAS-mapped"), `${s.atlasMapped ?? 0}/${s.total ?? 0}`, t("ave.kpi.atlasFoot", "MITRE ATLAS"), "#c4b5fd"),
  ].join("");
  const sevOpt = (v: string) => `<option value="${v}"${STATE.severity === v ? " selected" : ""}>${v || t("ave.allSev", "All severities")}</option>`;
  const compOpt = (v: string) => `<option value="${esc(v)}"${STATE.componentType === v ? " selected" : ""}>${esc(v || t("ave.allComp", "All components"))}</option>`;
  const rows = (d.records || []).map((r: any, i: number) => `
    <tr class="row" data-i="${i}">
      <td><span class="aveid">${esc(r.AveId)}</span></td>
      <td><b>${esc(r.Title)}</b><div class="muted" style="font-size:10px">${esc(r.AttackClass)}</div></td>
      <td>${esc(r.ComponentType)}</td>
      <td>${sevTag(r.Severity)}</td>
      <td style="text-align:center;font-weight:700">${r.AivssScore ?? "-"}</td>
      <td>${chips(r.MitreAtlas, "atlas")}${chips(r.OwaspMcp, "mcp")}${chips(r.OwaspAgentic, "asi")}</td>
    </tr>
    <tr class="det-row" id="det-${i}" style="display:none"><td colspan="6" class="det">
      <p>${esc(r.Description)}</p>
      <h4>${esc(t("ave.frameworks", "Framework mappings"))}</h4>
      <div>${chips(r.OwaspAgentic, "asi")}${chips(r.OwaspMcp, "mcp")}${chips(r.MitreAtlas, "atlas")}${chips(r.NistAiRmf, "chip")}</div>
      ${r.Iocs ? `<h4>${esc(t("ave.iocs", "Indicators of compromise"))}</h4><p>${esc(r.Iocs)}</p>` : ""}
      ${r.Remediation ? `<h4>${esc(t("ave.remediation", "Remediation"))}</h4><p>${esc(r.Remediation)}</p>` : ""}
      <div class="muted" style="font-size:10px;margin-top:6px">${esc(t("ave.behavioral", "Behavioral vector"))}: ${esc(r.BehavioralVector || "—")} · CVSS base ${esc(r.CvssBase ?? "—")} · ${esc(r.Researcher || "")} · ${esc((r.Published || "").slice(0, 10))}</div>
    </td></tr>`).join("");
  $("av-view").innerHTML = `
    <div class="av-cards">${cards}</div>
    <div class="bar">
      <select class="in" id="f-sev">${["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sevOpt).join("")}</select>
      <select class="in" id="f-comp">${["", ...comps].map(compOpt).join("")}</select>
      <input class="in" id="f-q" placeholder="${esc(t("ave.search", "Search id / title / attack class…"))}" value="${esc(STATE.q)}" style="flex:1;min-width:180px">
      <button class="btn sec sm" id="reseed">${esc(t("ave.reseed", "Reload sample"))}</button>
    </div>
    <table class="tt"><thead><tr>
      <th>AVE ID</th><th>${esc(t("ave.col.title", "Title / class"))}</th><th>${esc(t("ave.col.comp", "Component"))}</th>
      <th>${esc(t("ave.col.sev", "Severity"))}</th><th style="text-align:center">AIVSS</th><th>${esc(t("ave.col.frameworks", "Frameworks"))}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  (document.getElementById("f-sev") as HTMLSelectElement).onchange = (e) => { STATE.severity = (e.target as HTMLSelectElement).value; loadCatalogue(); };
  (document.getElementById("f-comp") as HTMLSelectElement).onchange = (e) => { STATE.componentType = (e.target as HTMLSelectElement).value; loadCatalogue(); };
  const qi = document.getElementById("f-q") as HTMLInputElement;
  let timer: any; qi.oninput = () => { clearTimeout(timer); timer = setTimeout(() => { STATE.q = qi.value.trim(); loadCatalogue(); }, 300); };
  $("reseed").onclick = async () => { await postJSON("/api/ave/seed"); loadCatalogue(); };
  document.querySelectorAll<HTMLElement>("tr.row").forEach((tr) => { tr.onclick = () => { const det = document.getElementById("det-" + tr.dataset.i)!; det.style.display = det.style.display === "none" ? "table-row" : "none"; }; });
}

// ── Agent exposure view (the behavioral scan) ─────────────────────────────────
async function loadExposure(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/ave/exposure"); } catch (e) { $("av-view").innerHTML = `<div class="muted">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  const assessBtn = `<button class="btn" id="assess">⚡ ${esc(t("ave.assess", "Assess agents"))}</button>`;
  if (!s.findings) {
    $("av-view").innerHTML = `<div class="av-card" style="max-width:640px"><div class="muted" style="margin-bottom:10px">${esc(t("ave.exp.empty", "Map the AVE catalogue onto your discovered AI agents to see which behavioral vulnerability classes each agent is exposed to. Needs AI agents (discover via /ai-guardrails, the aware connector, or the AWARE demo fleet) and the AVE catalogue loaded."))}</div>${assessBtn}</div>`;
    const ab = document.getElementById("assess"); if (ab) ab.onclick = async () => { await postJSON("/api/ave/assess"); loadExposure(); };
    return;
  }
  const cards = [
    card(t("ave.exp.agents", "Agents assessed"), String(s.agents ?? 0), t("ave.exp.agentsFoot", "discovered AI agents")),
    card(t("ave.exp.exposed", "Exposed findings"), String(s.exposed ?? 0), `${s.mitigated ?? 0} ${esc(t("ave.exp.mitigated", "mitigated"))}`, (s.exposed ? "#fca5a5" : "#22c55e")),
    card(t("ave.exp.critical", "Critical exposed"), String(s.criticalExposed ?? 0), `${s.highExposed ?? 0} ${esc(t("ave.exp.highExposed", "high"))}`, (s.criticalExposed ? "#fca5a5" : "#94a3b8")),
    card(t("ave.exp.risk", "AIVSS risk"), String(s.aivssRisk ?? 0), t("ave.exp.riskFoot", "Σ exposed AIVSS"), "#fcd34d"),
    card(t("ave.exp.worst", "Most exposed"), esc(s.worstAgent || "—"), t("ave.exp.worstFoot", "highest agent risk"), "#f87171"),
  ].join("");
  const agentRows = (d.perAgent || []).map((a: any) => `<tr>
    <td><b>${esc(a.name)}</b></td>
    <td><span class="sev ${a.tier && a.tier !== "none" ? "MEDIUM" : "CRITICAL"}">${esc(a.tier && a.tier !== "none" ? a.tier : "ungoverned")}</span></td>
    <td style="text-align:center;color:${a.exposed ? "#fca5a5" : "#86efac"};font-weight:700">${a.exposed}</td>
    <td style="text-align:center;color:#86efac">${a.mitigated}</td>
    <td style="text-align:center">${a.worst ? sevTag(a.worst) : "-"}</td>
    <td style="text-align:center;font-weight:700;color:#fcd34d">${a.aivssRisk}</td></tr>`).join("");
  const classRows = (d.byClass || []).slice(0, 12).map((c: any) => `<tr>
    <td><span class="aveid">${esc(c.aveId)}</span></td><td>${esc(c.title)}</td><td>${sevTag(c.severity)}</td>
    <td style="text-align:center;font-weight:700;color:#fca5a5">${c.exposedCount}</td></tr>`).join("");
  const top = (d.topExposed || []).slice(0, 12).map((x: any) => `<div class="src">
    <span class="aveid">${esc(x.aveId)}</span> <b>${esc(x.title)}</b> ${sevTag(x.severity)} <span class="muted">AIVSS ${esc(x.aivss ?? "-")}</span>
    <p>${esc(t("ave.exp.agentLbl", "Agent"))} <b>${esc(x.agent)}</b> (${esc(x.tier && x.tier !== "none" ? x.tier : "ungoverned")}) · ${esc(t("ave.exp.behaviorLbl", "behavior"))}: ${esc(x.match || "—")} · ${esc(x.rationale)}</p></div>`).join("");
  $("av-view").innerHTML = `
    <div style="margin-bottom:10px">${assessBtn} <span class="muted" style="font-size:11px;margin-left:6px">${esc(t("ave.exp.hint", "Exposure = an applicable AVE class whose required governance tier exceeds the agent's. Re-assess after governing agents in /aware."))}</span></div>
    <div class="av-cards">${cards}</div>
    <div style="display:grid;grid-template-columns:1.3fr 1fr;gap:16px">
      <div><div class="sec-h" style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:6px 0">${esc(t("ave.exp.perAgent", "Per-agent exposure"))}</div>
        <table class="tt"><thead><tr><th>${esc(t("ave.exp.agentLbl", "Agent"))}</th><th>${esc(t("ave.exp.tier", "Tier"))}</th><th style="text-align:center">${esc(t("ave.exp.exposed", "Exposed"))}</th><th style="text-align:center">${esc(t("ave.exp.mitigated", "Mitigated"))}</th><th style="text-align:center">${esc(t("ave.exp.worstSev", "Worst"))}</th><th style="text-align:center">AIVSS</th></tr></thead><tbody>${agentRows}</tbody></table></div>
      <div><div class="sec-h" style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:6px 0">${esc(t("ave.exp.byClass", "Top exposed AVE classes"))}</div>
        <table class="tt"><thead><tr><th>AVE</th><th>${esc(t("ave.col.title", "Title"))}</th><th>${esc(t("ave.col.sev", "Sev"))}</th><th style="text-align:center">#</th></tr></thead><tbody>${classRows}</tbody></table></div>
    </div>
    <div class="sec-h" style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:16px 0 6px">${esc(t("ave.exp.top", "Top exposures (AIVSS-ranked)"))}</div>
    ${top}`;
  document.getElementById("assess")!.onclick = async () => { await postJSON("/api/ave/assess"); loadExposure(); };
}

// ── Scan findings view (bawbel-scanner per-artifact detections) ────────────────
async function loadScan(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/ave/scan"); } catch (e) { $("av-view").innerHTML = `<div class="muted">Failed to load: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {};
  const sampleBtn = `<button class="btn sec sm" id="sample">${esc(t("ave.scan.sample", "Load sample scan"))}</button>`;
  if (!s.total) {
    $("av-view").innerHTML = `<div class="av-card" style="max-width:660px"><div class="muted" style="margin-bottom:10px">${esc(t("ave.scan.empty", "No bawbel-scanner findings imported yet. Run the scanner over your agent components (pip install bawbel-scanner; bawbel-scanner scan ./repo --sarif scan.sarif) and import the SARIF via the bawbel-scanner connector — these are real, located per-artifact detections (file:line, AIVSS), distinct from the inferred agent exposure."))}</div>${sampleBtn}</div>`;
    document.getElementById("sample")!.onclick = async () => { await postJSON("/api/ave/scan/seed"); loadScan(); };
    return;
  }
  const cards = [
    card(t("ave.scan.total", "Scan findings"), String(s.total ?? 0), t("ave.scan.totalFoot", "located detections")),
    card(t("ave.scan.critical", "Critical"), String(s.critical ?? 0), `${s.high ?? 0} ${esc(t("ave.exp.highExposed", "high"))}`, (s.critical ? "#fca5a5" : "#94a3b8")),
    card(t("ave.scan.files", "Files affected"), String(s.files ?? 0), t("ave.scan.filesFoot", "components"), "#60a5fa"),
    card(t("ave.scan.classes", "AVE classes"), String(s.classes ?? 0), t("ave.scan.classesFoot", "distinct"), "#c4b5fd"),
    card(t("ave.scan.risk", "AIVSS risk"), String(s.aivssRisk ?? 0), t("ave.scan.riskFoot", "Σ AIVSS"), "#fcd34d"),
  ].join("");
  const rows = (d.findings || []).map((f: any) => `<tr>
    <td><span class="sev ${esc((f.Severity || "").toUpperCase())}">${esc(f.Severity || "-")}</span></td>
    <td><span class="aveid">${esc(f.AveId)}</span>${f.RuleId ? `<div class="muted" style="font-size:10px">${esc(f.RuleId)}</div>` : ""}</td>
    <td><b>${esc(f.Title)}</b><div class="muted" style="font-size:10px">${esc(f.Message)}</div></td>
    <td style="font-family:ui-monospace,monospace;font-size:11px">${esc(f.File)}${f.Line ? ":" + f.Line : ""}</td>
    <td style="text-align:center;font-weight:700">${f.AivssScore ?? "-"}</td>
    <td style="text-align:center">${f.Confidence != null ? Math.round(f.Confidence * 100) + "%" : "-"}</td></tr>`).join("");
  $("av-view").innerHTML = `
    <div style="margin-bottom:10px">${sampleBtn} <span class="muted" style="font-size:11px;margin-left:6px">${esc(t("ave.scan.hint", "Per-artifact detections from the bawbel-scanner (file:line, AIVSS, confidence), cross-linked to the AVE catalogue. Import full scans via the bawbel-scanner connector."))}</span></div>
    <div class="av-cards">${cards}</div>
    <table class="tt"><thead><tr>
      <th>${esc(t("ave.col.sev", "Severity"))}</th><th>AVE / ${esc(t("ave.scan.rule", "rule"))}</th><th>${esc(t("ave.col.title", "Detection"))}</th>
      <th>${esc(t("ave.scan.location", "Location"))}</th><th style="text-align:center">AIVSS</th><th style="text-align:center">${esc(t("ave.scan.conf", "Conf."))}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  document.getElementById("sample")!.onclick = async () => { await postJSON("/api/ave/scan/seed"); loadScan(); };
}

route();
