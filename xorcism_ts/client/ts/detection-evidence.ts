/**
 * detection-evidence.ts — the proof behind a detection (/detection-evidence).
 * Pick a Sigma/YARA rule → see its provenance meter (intel / poc / log / prompt / reference /
 * test-result), attach evidence (text/url or a file: PCAP, log, PoC → CAS), download or remove it.
 * All from /api/detection-evidence*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

let CUR: { type: string; id: number; name: string } | null = null;
let META: any = { evidenceTypes: [], verdicts: [] };
const TYPE_LABEL: Record<string, string> = { intel: "Intel", poc: "PoC code", log: "Log sample", pcap: "PCAP", prompt: "AI prompt", reference: "Reference", "test-result": "Test result" };
const FILE_TYPES = new Set(["pcap", "log", "poc"]);
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="de-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;

async function init(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/detection-evidence/detections"); } catch (e) { $("de-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  META = d.summary || META;
  const dets: any[] = d.detections || [];
  if (!dets.length) {
    $("de-body").innerHTML = `<div class="muted" style="padding:20px">${esc(t("de.noDetections", "No Sigma or YARA detection rules found. Import or create detections first (Purple Team / Threat-Informed Defense / the yara connector)."))}</div>`;
    return;
  }
  const sel = $("pick") as HTMLSelectElement;
  sel.innerHTML = dets.map((x) => `<option value="${x.type}:${x.id}">[${x.type.toUpperCase()}] ${esc(x.name)}${x.evidence ? ` — ${x.evidence} proof · ${x.completeness}%` : ""}</option>`).join("");
  sel.onchange = () => { const [type, id] = sel.value.split(":"); const det = dets.find((x) => x.type === type && String(x.id) === id); CUR = { type, id: Number(id), name: det?.name || "" }; loadEvidence(); };
  const first = dets[0]; CUR = { type: first.type, id: first.id, name: first.name };
  loadEvidence();
}

async function loadEvidence(): Promise<void> {
  if (!CUR) return;
  let d: any;
  try { d = await getJSON(`/api/detection-evidence?type=${CUR.type}&id=${CUR.id}`); } catch (e) { $("de-body").innerHTML = `<div class="muted">Failed: ${esc(String(e))}</div>`; return; }
  const s = d.summary || {}, items: any[] = d.items || [];
  const cards = [
    card(t("de.kpi.evidence", "Evidence items"), String(s.total ?? 0), t("de.kpi.evidenceFoot", "attached proofs")),
    card(t("de.kpi.completeness", "Provenance"), `${s.completeness ?? 0}%`, t("de.kpi.completenessFoot", "proof-class coverage"), (s.completeness >= 80 ? "#22c55e" : s.completeness >= 40 ? "#fbbf24" : "#f87171")),
    card(t("de.kpi.validated", "Validated"), s.validated ? "✓" : "—", t("de.kpi.validatedFoot", "a matched test result"), (s.validated ? "#22c55e" : "#94a3b8")),
    card(t("de.kpi.files", "Files"), String(s.files ?? 0), t("de.kpi.filesFoot", "PCAP / logs / PoC in CAS"), "#60a5fa"),
  ].join("");
  const meter = (s.provenanceClasses || []).map((c: any) => `<span class="pchip ${c.present ? "on" : "off"}"><span class="dot"></span>${c.present ? "✓ " : ""}${esc(TYPE_LABEL[c.type] || c.type)}</span>`).join("");

  const groups = (META.evidenceTypes || []).map((et: string) => {
    const list = items.filter((i) => i.evidenceType === et);
    if (!list.length) return "";
    return `<div class="evgroup"><h3>${esc(TYPE_LABEL[et] || et)} (${list.length})</h3>${list.map(evCard).join("")}</div>`;
  }).join("");

  $("de-body").innerHTML = `
    <div class="de-cards">${cards}</div>
    <div class="prov">${meter}</div>
    ${addBox()}
    ${groups || `<div class="muted" style="padding:8px">${esc(t("de.empty", "No proof attached to this detection yet. Add the intel, PoC, logs/PCAP, the AI prompt that generated it, or a reference above."))}</div>`}`;
  wireAdd();
  document.querySelectorAll<HTMLElement>("[data-rm]").forEach((b) => { b.onclick = async () => { if (confirm(t("de.rmConfirm", "Remove this evidence?"))) { await delJSON("/api/detection-evidence/" + b.dataset.rm); loadEvidence(); } }; });
}

function evCard(i: any): string {
  const body = i.hasFile
    ? `<a class="dl" href="/api/detection-evidence/${i.id}/download">⬇ ${esc(i.fileName)} (${Math.round((i.size || 0) / 1024)} KB)</a>`
    : (i.url ? `<a class="dl" href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.url)}</a>` : "") + (i.content ? `<pre>${esc(i.content)}</pre>` : "");
  return `<div class="ev"><div class="h"><div><span class="etag ${esc(i.evidenceType)}">${esc(i.evidenceType)}</span> <span class="t">${esc(i.title || i.fileName || "—")}</span>${i.verdict ? ` <span class="verdict ${esc(i.verdict)}">${esc(i.verdict)}</span>` : ""}</div><button class="btn danger sm" data-rm="${i.id}">✕</button></div>
    ${body}
    <div class="m">${i.source ? esc(i.source) + " · " : ""}${esc(i.addedBy || "")} · ${esc((i.createdDate || "").slice(0, 10))}</div></div>`;
}

function addBox(): string {
  const opts = (META.evidenceTypes || []).map((et: string) => `<option value="${et}">${esc(TYPE_LABEL[et] || et)}</option>`).join("");
  const vopts = (META.verdicts || []).map((v: string) => `<option value="${v}">${esc(v)}</option>`).join("");
  return `<div class="addbox">
    <div style="font-weight:700;font-size:12px;margin-bottom:8px">+ ${esc(t("de.add", "Attach proof"))}</div>
    <div class="frm">
      <div><label>${esc(t("de.f.type", "Evidence type"))}</label><select class="in" id="a-type" style="width:100%">${opts}</select></div>
      <div><label>${esc(t("de.f.title", "Title"))}</label><input class="in" id="a-title" style="width:100%"></div>
      <div class="full" id="a-textwrap"><label id="a-contentlbl">${esc(t("de.f.content", "Content (paste the intel, PoC, prompt or log excerpt)"))}</label><textarea class="in" id="a-content"></textarea></div>
      <div class="full" id="a-urlwrap" style="display:none"><label>${esc(t("de.f.url", "Reference URL"))}</label><input class="in" id="a-url" style="width:100%" placeholder="https://…"></div>
      <div class="full" id="a-filewrap" style="display:none"><label>${esc(t("de.f.file", "File (PCAP / log / PoC — max 15 MB)"))}</label><input type="file" id="a-file" class="in" style="width:100%"></div>
      <div id="a-verdictwrap" style="display:none"><label>${esc(t("de.f.verdict", "Verdict"))}</label><select class="in" id="a-verdict" style="width:100%">${vopts}</select></div>
      <div><label>${esc(t("de.f.source", "Source"))}</label><input class="in" id="a-source" style="width:100%" placeholder="${esc(t("de.f.sourceph", "report / tool / analyst"))}"></div>
    </div>
    <div style="margin-top:10px"><button class="btn" id="a-save">${esc(t("de.save", "Attach"))}</button> <span class="muted" id="a-msg" style="font-size:11px;margin-left:8px"></span></div>
  </div>`;
}

function wireAdd(): void {
  const typeSel = document.getElementById("a-type") as HTMLSelectElement;
  const refresh = () => {
    const et = typeSel.value;
    const isFile = FILE_TYPES.has(et);
    const isRef = et === "reference";
    (document.getElementById("a-filewrap") as HTMLElement).style.display = isFile ? "block" : "none";
    (document.getElementById("a-textwrap") as HTMLElement).style.display = isFile ? "none" : "block";
    (document.getElementById("a-urlwrap") as HTMLElement).style.display = isRef ? "block" : "none";
    (document.getElementById("a-verdictwrap") as HTMLElement).style.display = et === "test-result" ? "block" : "none";
  };
  typeSel.onchange = refresh; refresh();
  (document.getElementById("a-save") as HTMLButtonElement).onclick = async () => {
    if (!CUR) return;
    const et = typeSel.value;
    const v = (id: string) => (document.getElementById(id) as HTMLInputElement)?.value || "";
    const msg = document.getElementById("a-msg")!;
    if (FILE_TYPES.has(et)) {
      const fi = document.getElementById("a-file") as HTMLInputElement;
      const f = fi.files && fi.files[0];
      if (!f) { msg.textContent = t("de.needFile", "Pick a file."); return; }
      msg.textContent = t("de.uploading", "Uploading…");
      const dataBase64 = await new Promise<string>((res) => { const rd = new FileReader(); rd.onload = () => res(String(rd.result || "")); rd.readAsDataURL(f); });
      const r = await postJSON("/api/detection-evidence/upload", { type: CUR.type, id: CUR.id, evidenceType: et, fileName: f.name, contentType: f.type, dataBase64, title: v("a-title"), source: v("a-source") });
      msg.textContent = r.error || "";
    } else {
      if (!v("a-content").trim() && !v("a-url").trim()) { msg.textContent = t("de.needContent", "Add content or a URL."); return; }
      const r = await postJSON("/api/detection-evidence", { type: CUR.type, id: CUR.id, evidenceType: et, title: v("a-title"), content: v("a-content"), url: v("a-url"), source: v("a-source"), verdict: v("a-verdict") });
      msg.textContent = r.error || "";
    }
    loadEvidence();
  };
}

init();
