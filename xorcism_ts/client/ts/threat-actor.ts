/**
 * threat-actor.ts — Threat-actor profiling cockpit (/threat-actor).
 * A list/summary view + a per-actor profile that renders the Diamond Model of Intrusion Analysis
 * (Adversary / Capability / Infrastructure / Victim + the socio-political & technology meta-axes)
 * as an SVG, with builder modals to create/edit the profile, the diamond narrative, and curated
 * infrastructure IOCs. All from /api/threat-actors*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

let VOCAB: any = { actorTypes: [], sophistication: [], resourceLevel: [], motivations: [] };
const COLORS = { adversary: "#f87171", capability: "#c4b5fd", infrastructure: "#60a5fa", victim: "#86efac" };

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ta-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

// ── List / summary view ───────────────────────────────────────────────────────
async function loadList(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/threat-actors"); } catch (e) { $("ta-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  VOCAB = d.vocab || VOCAB;
  const s = d.summary || {};
  const actors: any[] = d.actors || [];
  if (!actors.length) {
    $("ta-body").innerHTML = `<div class="ta-card" style="max-width:600px"><div class="muted" style="margin-bottom:10px">${esc(t("ta.empty", "No threat-actor profiles yet. Create one, or seed a fully-profiled demo actor to see the Diamond Model."))}</div>
      <button class="btn" id="new">+ ${esc(t("ta.newActor", "New actor"))}</button> <button class="btn sec" id="seed">${esc(t("ta.seedDemo", "Seed demo actor"))}</button></div>`;
    $("new").onclick = () => openProfileModal(null);
    $("seed").onclick = async () => { await postJSON("/api/threat-actors/seed"); loadList(); };
    return;
  }
  const cards = [
    card(t("ta.kpi.actors", "Actors profiled"), String(s.total ?? 0), t("ta.kpi.actorsFoot", "in scope")),
    card(t("ta.kpi.nationState", "Nation-state / spy"), String(s.nationState ?? 0), t("ta.kpi.nationStateFoot", "by actor type"), "#fca5a5"),
    card(t("ta.kpi.advanced", "Advanced+"), String(s.advanced ?? 0), t("ta.kpi.advancedFoot", "sophistication"), "#c4b5fd"),
    card(t("ta.kpi.diamond", "Diamond complete"), `${s.profiled ?? 0}/${s.total ?? 0}`, t("ta.kpi.diamondFoot", "all 4 vertices"), (s.profiled >= s.total ? "#22c55e" : "#fbbf24")),
    card(t("ta.kpi.avgCap", "Avg capabilities"), String(s.avgCapabilities ?? 0), t("ta.kpi.avgCapFoot", "ATT&CK techniques"), "#60a5fa"),
  ].join("");
  const rows = actors.map((a) => `<tr class="row" data-id="${a.id}">
    <td><b>${esc(a.name)}</b>${a.Active === 0 ? ' <span class="muted">(inactive)</span>' : ""}${a.Aliases ? `<div class="muted" style="font-size:10px">${esc(a.Aliases)}</div>` : ""}</td>
    <td>${(a.ActorTypes || "").split(/[,;]+/).filter(Boolean).slice(0, 3).map((x: string) => `<span class="badge ${/nation|spy/i.test(x) ? "ns" : "adv"}">${esc(x.trim())}</span>`).join(" ")}</td>
    <td>${esc(a.Sophistication || "-")}</td>
    <td>${esc(a.Motivation || "-")}</td>
    <td>${esc(a.TargetSectors || "-")}</td>
    <td style="text-align:center">${a.capabilityCount || 0}</td>
    <td style="text-align:center"><span class="badge ${a.diamondComplete >= 4 ? "ok" : "adv"}">${a.diamondComplete}/4</span></td></tr>`).join("");
  $("ta-body").innerHTML = `
    <div class="ta-cards">${cards}</div>
    <div style="margin-bottom:10px"><button class="btn" id="new">+ ${esc(t("ta.newActor", "New actor"))}</button> <button class="btn sec" id="seed">${esc(t("ta.seedDemo", "Seed demo actor"))}</button></div>
    <table class="tt"><thead><tr>
      <th>${esc(t("ta.col.actor", "Actor"))}</th><th>${esc(t("ta.col.type", "Type"))}</th><th>${esc(t("ta.col.soph", "Sophistication"))}</th>
      <th>${esc(t("ta.col.motiv", "Motivation"))}</th><th>${esc(t("ta.col.sectors", "Target sectors"))}</th>
      <th style="text-align:center">${esc(t("ta.col.cap", "Capabilities"))}</th><th style="text-align:center">${esc(t("ta.col.diamond", "Diamond"))}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  $("new").onclick = () => openProfileModal(null);
  $("seed").onclick = async () => { await postJSON("/api/threat-actors/seed"); loadList(); };
  document.querySelectorAll<HTMLElement>("tr.row").forEach((tr) => { tr.onclick = () => openActor(Number(tr.dataset.id)); });
}

// ── Diamond Model SVG ─────────────────────────────────────────────────────────
function diamondNode(cx: number, cy: number, color: string, title: string, count: number, lines: string[]): string {
  const w = 196, h = 78, x = cx - w / 2, y = cy - h / 2;
  const body = lines.slice(0, 2).map((l, i) => `<tspan x="${cx}" dy="${i === 0 ? 16 : 13}">${esc(l).slice(0, 34)}</tspan>`).join("");
  return `<g class="dnode" data-vertex="${esc(title.toLowerCase())}">
    <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="#13162a" stroke="${color}" stroke-width="2"/>
    <text x="${cx}" y="${y + 18}" text-anchor="middle" font-size="12" font-weight="700" fill="${color}">${esc(title)} <tspan fill="#64748b" font-weight="400">· ${count}</tspan></text>
    <text x="${cx}" y="${y + 30}" text-anchor="middle" font-size="10" fill="#94a3b8">${body}</text></g>`;
}
function edge(x1: number, y1: number, x2: number, y2: number, dash = false, color = "#3a4170"): string {
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${dash ? 1.5 : 2}"${dash ? ' stroke-dasharray="5 4"' : ""}/>`;
}
function diamondSVG(dm: any): string {
  const A = { x: 330, y: 66 }, C = { x: 132, y: 270 }, I = { x: 528, y: 270 }, V = { x: 330, y: 474 };
  const cap = dm.capability || {}, infra = dm.infrastructure || {}, vic = dm.victim || {}, adv = dm.adversary || {};
  const techLine = (cap.techniques || []).slice(0, 2).map((x: any) => x.id).join(", ");
  const edges = [
    edge(A.x, A.y + 39, C.x, C.y - 39), edge(A.x, A.y + 39, I.x, I.y - 39),
    edge(V.x, V.y - 39, C.x, C.y + 39), edge(V.x, V.y - 39, I.x, I.y + 39),
    edge(A.x, A.y + 39, V.x, V.y - 39, true, "#5a3a52"),   // socio-political axis
    edge(C.x + 98, C.y, I.x - 98, I.y, true, "#3a4a6a"),    // technology axis
  ].join("");
  const labels = `
    <text x="345" y="270" font-size="9" fill="#7a8bbf" font-style="italic">socio-political</text>
    <text x="330" y="262" text-anchor="middle" font-size="9" fill="#6a7aaa" font-style="italic">technology axis</text>`;
  const nodes = [
    diamondNode(A.x, A.y, COLORS.adversary, "Adversary", 0, [adv.label || "—", [adv.types, adv.country].filter(Boolean).join(" · ")]),
    diamondNode(C.x, C.y, COLORS.capability, "Capability", cap.count || 0, [techLine || "—", (cap.malware || []).slice(0, 2).join(", ")]),
    diamondNode(I.x, I.y, COLORS.infrastructure, "Infrastructure", infra.count || 0, [(infra.iocs || [])[0]?.value || infra.text || "—", (infra.iocs || [])[1]?.value || ""]),
    diamondNode(V.x, V.y, COLORS.victim, "Victim", vic.count || 0, [(vic.sectors || []).slice(0, 2).join(", ") || "—", (vic.regions || []).join(", ")]),
  ].join("");
  return `<svg viewBox="0 0 660 540" width="100%" style="max-width:660px">${edges}${labels}${nodes}</svg>`;
}

// ── Profile view ──────────────────────────────────────────────────────────────
async function openActor(id: number): Promise<void> {
  let p: any;
  try { p = await getJSON("/api/threat-actors/" + id); } catch { return; }
  const a = p.actor, dm = p.diamond;
  const adv = dm.adversary, cap = dm.capability, infra = dm.infrastructure, vic = dm.victim, meta = dm.meta;
  const techChips = (cap.techniques || []).map((x: any) => `<span class="chip cap" title="${esc(x.name)}">${esc(x.id)}${x.name ? " " + esc(x.name) : ""}</span>`).join("") || '<span class="muted">—</span>';
  const malChips = (cap.malware || []).map((m: string) => `<span class="chip mal">${esc(m)}</span>`).join("");
  const secChips = (vic.sectors || []).map((x: string) => `<span class="chip sec">${esc(x)}</span>`).join("") + (vic.regions || []).map((x: string) => `<span class="chip">${esc(x)}</span>`).join("");
  const infraRows = (infra.iocs || []).map((i: any) => `<tr><td><span class="chip">${esc(i.type || "ioc")}</span></td><td style="font-family:ui-monospace,monospace;font-size:11px">${esc(i.value)}</td><td>${esc(i.role || "")}</td><td>${esc(i.Confidence || "")}</td><td><button class="btn danger sm" data-rmi="${i.id}">✕</button></td></tr>`).join("")
    || `<tr><td colspan="5" class="muted">${esc(t("ta.noIoc", "No curated infrastructure IOCs yet."))}</td></tr>`;
  const incRows = (vic.incidents || []).map((x: any) => `<span class="chip">#${x.id} ${esc(x.name || "")}</span>`).join("") || "";

  const panel = (color: string, title: string, inner: string) => `<div class="dpanel"><h3><span class="dot" style="background:${color}"></span>${esc(title)}</h3>${inner}</div>`;
  $("ta-body").innerHTML = `
    <div style="margin-bottom:10px"><button class="btn sec sm" id="back">← ${esc(t("ta.back", "All actors"))}</button></div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px">
      <h1 style="margin:0">${esc(a.ThreatActorName)}</h1>
      ${(a.ActorTypes || "").split(/[,;]+/).filter(Boolean).map((x: string) => `<span class="badge ${/nation|spy/i.test(x) ? "ns" : "adv"}">${esc(x.trim())}</span>`).join(" ")}
      <span class="spacer" style="flex:1"></span>
      <button class="btn sm" id="edit">✎ ${esc(t("ta.editProfile", "Edit profile"))}</button>
      <button class="btn sec sm" id="editDiamond">◆ ${esc(t("ta.editDiamond", "Edit Diamond"))}</button></div>
    <div class="ta-sub">${esc(a.ThreatActorDescription || "")}</div>
    <div class="kv" style="margin-bottom:12px">
      <b>${esc(t("ta.f.aliases", "Aliases"))}:</b> ${esc(a.Aliases || "—")} &nbsp;·&nbsp;
      <b>${esc(t("ta.f.motiv", "Motivation"))}:</b> ${esc(a.Motivation || "—")} &nbsp;·&nbsp;
      <b>${esc(t("ta.f.soph", "Sophistication"))}:</b> ${esc(a.Sophistication || "—")} &nbsp;·&nbsp;
      <b>${esc(t("ta.f.resource", "Resources"))}:</b> ${esc(a.ResourceLevel || "—")} &nbsp;·&nbsp;
      <b>${esc(t("ta.f.seen", "Active"))}:</b> ${esc(meta.firstSeen || "?")} → ${esc(meta.lastSeen || "?")} &nbsp;·&nbsp;
      <b>${esc(t("ta.f.conf", "Confidence"))}:</b> ${esc(meta.confidence || "—")}</div>

    <div class="ta-sec">◆ ${esc(t("ta.diamondTitle", "Diamond Model of Intrusion Analysis"))} <span class="muted" style="text-transform:none;font-weight:400">— ${dm.completeness}/4 ${esc(t("ta.verticesSet", "vertices populated"))}</span></div>
    <div class="diamond-grid">
      <div>${diamondSVG(dm)}</div>
      <div>
        ${panel(COLORS.adversary, t("ta.v.adversary", "Adversary"), `<p>${esc(adv.text || "—")}</p><div class="kv"><b>${esc(adv.country || "")}</b> ${adv.aliases ? "· " + esc(adv.aliases) : ""}</div>`)}
        ${panel(COLORS.capability, t("ta.v.capability", "Capability"), `<p>${esc(cap.text || "—")}</p><div style="margin:5px 0">${techChips}</div><div>${malChips}</div>`)}
        ${panel(COLORS.infrastructure, t("ta.v.infrastructure", "Infrastructure"), `<p>${esc(infra.text || "—")}</p>
          <table class="tt" style="margin-top:4px"><tbody>${infraRows}</tbody></table>
          <button class="btn sec sm" id="addInfra" style="margin-top:6px">+ ${esc(t("ta.addIoc", "Add IOC"))}</button>`)}
        ${panel(COLORS.victim, t("ta.v.victim", "Victim"), `<p>${esc(vic.text || "—")}</p><div style="margin:5px 0">${secChips}</div>${incRows ? `<div class="kv" style="margin-top:4px"><b>${esc(t("ta.incidents", "Linked incidents"))}:</b> ${incRows}</div>` : ""}`)}
      </div>
    </div>
    <div class="dpanel" style="margin-top:6px">
      <div class="meta-axis"><b style="color:#cbd5e1">↕ ${esc(t("ta.meta.socio", "Socio-political (Adversary ↔ Victim)"))}:</b> ${esc(meta.sociopolitical || "—")}</div>
      <div class="meta-axis"><b style="color:#cbd5e1">↔ ${esc(t("ta.meta.tech", "Technology (Capability ↔ Infrastructure)"))}:</b> ${esc(meta.technology || "—")}</div>
    </div>`;
  $("back").onclick = () => loadList();
  $("edit").onclick = () => openProfileModal(a);
  $("editDiamond").onclick = () => openDiamondModal(id, dm);
  const ai = document.getElementById("addInfra"); if (ai) ai.onclick = () => openInfraModal(id);
  document.querySelectorAll<HTMLElement>("[data-rmi]").forEach((b) => { b.onclick = async () => { await delJSON("/api/threat-actors/infra/" + b.dataset.rmi); openActor(id); }; });
}

// ── Modals ────────────────────────────────────────────────────────────────────
function closeModal(): void { $("modal").classList.remove("on"); }
function showModal(html: string): void { $("modal-inner").innerHTML = html; $("modal").classList.add("on"); }
$("modal").onclick = (e) => { if (e.target === $("modal")) closeModal(); };
const opts = (arr: string[], cur: string): string => `<option value=""></option>` + arr.map((o) => `<option${o === cur ? " selected" : ""}>${esc(o)}</option>`).join("");

function openProfileModal(a: any | null): void {
  const g = (k: string) => esc(a ? a[k] || "" : "");
  showModal(`<h2>${a ? esc(t("ta.editProfile", "Edit profile")) : "+ " + esc(t("ta.newActor", "New actor"))}</h2>
    <div class="frm">
      <div class="full"><label>${esc(t("ta.f.name", "Name"))} *</label><input class="in" id="f-name" value="${g("ThreatActorName")}"></div>
      <div class="full"><label>${esc(t("ta.f.desc", "Description"))}</label><textarea class="in" id="f-description">${g("ThreatActorDescription")}</textarea></div>
      <div class="full"><label>${esc(t("ta.f.aliases", "Aliases"))} (comma-separated)</label><input class="in" id="f-aliases" value="${g("Aliases")}"></div>
      <div><label>${esc(t("ta.f.types", "Actor type(s)"))}</label><input class="in" id="f-actorTypes" list="dl-types" value="${g("ActorTypes")}"><datalist id="dl-types">${VOCAB.actorTypes.map((o: string) => `<option>${esc(o)}</option>`).join("")}</datalist></div>
      <div><label>${esc(t("ta.f.country", "Origin / country"))}</label><input class="in" id="f-country" value="${g("country")}"></div>
      <div><label>${esc(t("ta.f.motiv", "Motivation"))}</label><select class="in" id="f-motivation">${opts(VOCAB.motivations, g("Motivation"))}</select></div>
      <div><label>${esc(t("ta.f.soph", "Sophistication"))}</label><select class="in" id="f-sophistication">${opts(VOCAB.sophistication, g("Sophistication"))}</select></div>
      <div><label>${esc(t("ta.f.resource", "Resource level"))}</label><select class="in" id="f-resourceLevel">${opts(VOCAB.resourceLevel, g("ResourceLevel"))}</select></div>
      <div><label>${esc(t("ta.f.conf", "Confidence"))}</label><input class="in" id="f-confidence" value="${g("Confidence")}"></div>
      <div><label>${esc(t("ta.f.first", "First seen"))}</label><input class="in" id="f-firstSeen" placeholder="YYYY-MM-DD" value="${g("FirstSeen")}"></div>
      <div><label>${esc(t("ta.f.last", "Last seen"))}</label><input class="in" id="f-lastSeen" placeholder="YYYY-MM-DD" value="${g("LastSeen")}"></div>
      <div class="full"><label>${esc(t("ta.f.attack", "Capabilities — ATT&CK technique ids"))} (e.g. T1566, T1059)</label><input class="in" id="f-attackTags" value="${g("AttackTags")}"></div>
      <div class="full"><label>${esc(t("ta.f.malware", "Malware / tools"))} (comma-separated)</label><input class="in" id="f-malwareTags" value="${g("MalwareTags")}"></div>
      <div><label>${esc(t("ta.f.sectors", "Target sectors"))}</label><input class="in" id="f-targetSectors" value="${g("TargetSectors")}"></div>
      <div><label>${esc(t("ta.f.regions", "Target regions"))}</label><input class="in" id="f-targetRegions" value="${g("TargetRegions")}"></div>
      <div class="full"><label>${esc(t("ta.f.infraNotes", "Infrastructure notes"))}</label><textarea class="in" id="f-infrastructureNotes">${g("InfrastructureNotes")}</textarea></div>
    </div>
    <div style="margin-top:14px;text-align:right"><button class="btn sec" id="cancel">${esc(t("ta.cancel", "Cancel"))}</button> <button class="btn" id="save">${esc(t("ta.save", "Save"))}</button></div>`);
  $("cancel").onclick = closeModal;
  $("save").onclick = async () => {
    const v = (id: string) => (document.getElementById("f-" + id) as HTMLInputElement)?.value || "";
    if (!v("name").trim()) { (document.getElementById("f-name") as HTMLInputElement).focus(); return; }
    const body: any = { id: a ? a.ThreatActorID : 0 };
    for (const k of ["name", "description", "aliases", "actorTypes", "country", "motivation", "sophistication", "resourceLevel", "confidence", "firstSeen", "lastSeen", "attackTags", "malwareTags", "targetSectors", "targetRegions", "infrastructureNotes"]) body[k] = v(k);
    const r = await postJSON("/api/threat-actors", body);
    closeModal();
    if (r.id) openActor(r.id); else loadList();
  };
}

function openDiamondModal(id: number, dm: any): void {
  const g = (v: string) => esc(v || "");
  showModal(`<h2>◆ ${esc(t("ta.editDiamond", "Edit Diamond Model"))}</h2>
    <div class="frm">
      <div class="full"><label style="color:${COLORS.adversary}">${esc(t("ta.v.adversary", "Adversary"))}</label><textarea class="in" id="d-adversary">${g(dm.adversary.text)}</textarea></div>
      <div class="full"><label style="color:${COLORS.capability}">${esc(t("ta.v.capability", "Capability"))}</label><textarea class="in" id="d-capability">${g(dm.capability.text)}</textarea></div>
      <div class="full"><label style="color:${COLORS.infrastructure}">${esc(t("ta.v.infrastructure", "Infrastructure"))}</label><textarea class="in" id="d-infrastructure">${g(dm.infrastructure.text)}</textarea></div>
      <div class="full"><label style="color:${COLORS.victim}">${esc(t("ta.v.victim", "Victim"))}</label><textarea class="in" id="d-victim">${g(dm.victim.text)}</textarea></div>
      <div class="full"><label>↕ ${esc(t("ta.meta.socio", "Socio-political (Adversary ↔ Victim)"))}</label><textarea class="in" id="d-sociopolitical">${g(dm.meta.sociopolitical)}</textarea></div>
      <div class="full"><label>↔ ${esc(t("ta.meta.tech", "Technology (Capability ↔ Infrastructure)"))}</label><textarea class="in" id="d-technology">${g(dm.meta.technology)}</textarea></div>
    </div>
    <div style="margin-top:14px;text-align:right"><button class="btn sec" id="cancel">${esc(t("ta.cancel", "Cancel"))}</button> <button class="btn" id="save">${esc(t("ta.save", "Save"))}</button></div>`);
  $("cancel").onclick = closeModal;
  $("save").onclick = async () => {
    const v = (k: string) => (document.getElementById("d-" + k) as HTMLTextAreaElement)?.value || "";
    await postJSON(`/api/threat-actors/${id}/diamond`, { adversary: v("adversary"), capability: v("capability"), infrastructure: v("infrastructure"), victim: v("victim"), sociopolitical: v("sociopolitical"), technology: v("technology") });
    closeModal(); openActor(id);
  };
}

function openInfraModal(id: number): void {
  showModal(`<h2>+ ${esc(t("ta.addIoc", "Add infrastructure IOC"))}</h2>
    <div class="frm">
      <div><label>${esc(t("ta.ioc.type", "Type"))}</label><input class="in" id="i-type" list="dl-ioc" placeholder="domain / ipv4-addr / sha256 / url"><datalist id="dl-ioc"><option>domain</option><option>ipv4-addr</option><option>ipv6-addr</option><option>url</option><option>email-addr</option><option>sha256</option><option>md5</option></datalist></div>
      <div><label>${esc(t("ta.ioc.role", "Role"))}</label><input class="in" id="i-role" placeholder="C2 / phishing / payload"></div>
      <div class="full"><label>${esc(t("ta.ioc.value", "Value"))} *</label><input class="in" id="i-value"></div>
      <div><label>${esc(t("ta.f.conf", "Confidence"))}</label><input class="in" id="i-confidence" placeholder="High / Medium / Low"></div>
      <div><label>${esc(t("ta.ioc.source", "Source"))}</label><input class="in" id="i-source"></div>
    </div>
    <div style="margin-top:14px;text-align:right"><button class="btn sec" id="cancel">${esc(t("ta.cancel", "Cancel"))}</button> <button class="btn" id="save">${esc(t("ta.save", "Save"))}</button></div>`);
  $("cancel").onclick = closeModal;
  $("save").onclick = async () => {
    const v = (k: string) => (document.getElementById("i-" + k) as HTMLInputElement)?.value || "";
    if (!v("value").trim()) { (document.getElementById("i-value") as HTMLInputElement).focus(); return; }
    await postJSON(`/api/threat-actors/${id}/infra`, { type: v("type"), role: v("role"), value: v("value"), confidence: v("confidence"), source: v("source") });
    closeModal(); openActor(id);
  };
}

loadList();
