/**
 * mitigant.ts — Cloud Attacks Matrix view (Mitigant Threat Catalog, AWS), read from XTHREAT.MITIGANT*
 * via /api/mitigant/matrix. Tactics (columns) → techniques (severity-coloured cells); click a cell for
 * the detail panel (description, AWS service, MITRE ATT&CK id, AWS CLI commands, CloudTrail events).
 */
import { initI18n } from "./i18n";

interface Tech { techId: string; title: string; description: string | null; severity: string | null; service: string | null; mitre: string | null; commands: string[]; cloudtrail: string[]; }
interface Tactic { key: string; name: string; mitre: string | null; techniques: Tech[] }
interface Matrix { tactics: Tactic[]; summary: { techniques: number; tactics: number; services: number; bySeverity: Record<string, number> } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const sevClass = (s: string | null): string => { const v = String(s || "unknown").toLowerCase(); return ["critical", "high", "medium", "low"].includes(v) ? v : "unknown"; };

let MATRIX: Matrix = { tactics: [], summary: { techniques: 0, tactics: 0, services: 0, bySeverity: {} } };
const byId = new Map<string, Tech>();

function render(m: Matrix): void {
  const root = $("mit-matrix"); root.innerHTML = "";
  byId.clear();
  for (const tac of m.tactics) {
    const col = el("div", "att-col");
    const head = el("div", "att-col-head");
    head.innerHTML = `<div class="att-tac-name">${esc(tac.name)}</div><div class="att-tac-meta">${esc(tac.mitre || "")}${tac.mitre ? " · " : ""}${tac.techniques.length} tech.</div>`;
    col.appendChild(head);
    const body = el("div", "att-col-body");
    for (const t of tac.techniques) {
      byId.set(t.techId, t);
      const sc = sevClass(t.severity);
      const cell = el("div", `att-cell cell-${sc}`);
      cell.dataset.s = `${t.techId} ${t.title} ${t.mitre || ""} ${t.service || ""} ${t.severity || ""}`.toLowerCase();
      cell.dataset.svc = (t.service || "").toLowerCase();
      cell.dataset.sev = sc;
      cell.dataset.id = t.techId;
      cell.innerHTML = `<span class="att-id">${esc(t.techId)}</span><div class="tn">${esc(t.title)}</div>` +
        `<div class="meta"><span class="sev sev-${sc}">${esc(t.severity || "—")}</span>${t.service ? `<span class="svc">${esc(t.service)}</span>` : ""}</div>`;
      cell.onclick = () => openDetail(t.techId);
      body.appendChild(cell);
    }
    col.appendChild(body);
    root.appendChild(col);
  }
  const s = m.summary;
  const sev = ["critical", "high", "medium", "low"].filter((k) => s.bySeverity[k]).map((k) => `${s.bySeverity[k]} ${k}`).join(" · ");
  $("mit-stats").textContent = `${s.tactics} tactics · ${s.techniques} techniques · ${s.services} AWS services${sev ? " · " + sev : ""}`;
}

function openDetail(id: string): void {
  const t = byId.get(id); if (!t) return;
  const sc = sevClass(t.severity);
  const cmds = t.commands.length ? `<div class="sech">AWS CLI commands</div><pre>${esc(t.commands.join("\n"))}</pre>` : "";
  const ct = t.cloudtrail.length ? `<div class="sech">CloudTrail events (detection)</div><div>${t.cloudtrail.map((c) => `<span class="ct">${esc(c)}</span>`).join("")}</div>` : "";
  const mitre = t.mitre ? `<a href="/attack" style="color:#7dd3fc;text-decoration:none">${esc(t.mitre)}</a>` : "—";
  $("mit-modal").innerHTML =
    `<button class="mit-close" id="mit-x" aria-label="Close">&times;</button>
     <h3>${esc(t.title)}</h3><div class="mid">${esc(t.techId)}</div>
     <div class="lead">${esc(t.description || "")}</div>
     <div class="row"><span>Severity <b><span class="sev sev-${sc}">${esc(t.severity || "—")}</span></b></span>
       <span>AWS service <b>${esc(t.service || "—")}</b></span>
       <span>MITRE ATT&CK <b>${mitre}</b></span></div>
     ${cmds}${ct}`;
  ($("mit-x") as HTMLButtonElement).onclick = closeDetail;
  $("mit-bg").classList.add("open");
}
function closeDetail(): void { $("mit-bg").classList.remove("open"); }

function applyFilter(): void {
  const q = ($("mit-search") as HTMLInputElement).value.trim().toLowerCase();
  const svc = ($("mit-service") as HTMLSelectElement).value.toLowerCase();
  const sev = ($("mit-severity") as HTMLSelectElement).value.toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-col").forEach((col) => {
    let shown = 0;
    col.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
      const ok = (!q || (c.dataset.s ?? "").includes(q)) && (!svc || c.dataset.svc === svc) && (!sev || c.dataset.sev === sev);
      c.style.display = ok ? "" : "none"; if (ok) shown++;
    });
    col.style.display = shown ? "" : "none";
  });
}

async function load(): Promise<void> {
  const root = $("mit-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted,#94a3b8)">Loading…</div>`;
  try {
    const r = await fetch("/api/mitigant/matrix");
    if (!r.ok) { const d = await r.json().catch(() => ({})); root.innerHTML = `<div style="padding:24px;color:#f87171">${(d as { error?: string }).error || `Error ${r.status}`}</div>`; return; }
    MATRIX = (await r.json()) as Matrix;
    const services = [...new Set(MATRIX.tactics.flatMap((t) => t.techniques.map((x) => x.service).filter(Boolean)))].sort() as string[];
    ($("mit-service") as HTMLSelectElement).insertAdjacentHTML("beforeend", services.map((s) => `<option value="${esc(s.toLowerCase())}">${esc(s)}</option>`).join(""));
    render(MATRIX);
    if (!MATRIX.tactics.some((t) => t.techniques.length)) {
      root.insertAdjacentHTML("afterbegin", `<div style="padding:0 16px 12px;color:#94a3b8;font-size:12px">No techniques imported. Run <code>python xorcism_python/importers/import_mitigant.py</code>.</div>`);
    }
  } catch (e) { root.innerHTML = `<div style="padding:24px;color:#f87171">${esc((e as Error).message)}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("mit-search") as HTMLInputElement).oninput = applyFilter;
  ($("mit-service") as HTMLSelectElement).onchange = applyFilter;
  ($("mit-severity") as HTMLSelectElement).onchange = applyFilter;
  $("mit-bg").addEventListener("click", (e) => { if (e.target === $("mit-bg")) closeDetail(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });
  void load();
});
