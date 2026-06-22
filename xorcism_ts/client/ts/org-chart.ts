/** org-chart.ts — organisation chart (/org-chart). Renders the PERSON management hierarchy
 * (forest from ManagerPersonID, Entra/AD-aligned) as a collapsible tree + headcount KPIs. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Person { id: number; name: string; title: string; department: string; email: string; upn: string; managerId: number | null; enabled: boolean; reports: number; entra: boolean; }
interface Data { people: Person[]; roots: number[]; summary: any; }

let DATA: Data | null = null;
let FILTER = "";

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="oc-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const initials = (name: string): string => name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase() || "?";

function nodeHtml(p: Person, childrenOf: Map<number, Person[]>): string {
  const kids = (childrenOf.get(p.id) || []).slice().sort((a, b) => b.reports - a.reports || a.name.localeCompare(b.name));
  const node = `<span class="node${p.enabled ? "" : " disabled"}">
    <span class="avatar">${esc(initials(p.name))}</span>
    <span><span class="nm">${esc(p.name)}</span>${p.title ? `<div class="ti">${esc(p.title)}</div>` : ""}</span>
    ${p.department ? `<span class="dept">${esc(p.department)}</span>` : ""}
    ${p.reports ? `<span class="rc">${p.reports} report${p.reports > 1 ? "s" : ""}</span>` : ""}
    ${p.entra ? `<span class="entra">ENTRA</span>` : ""}
    ${!p.enabled ? `<span class="muted" style="font-size:10px">disabled</span>` : ""}
  </span>`;
  if (!kids.length) return `<li>${node}</li>`;
  return `<li><span class="toggle" data-toggle="1">▾</span>${node}<ul>${kids.map((k) => nodeHtml(k, childrenOf)).join("")}</ul></li>`;
}

function render(): void {
  const d = DATA!; const s = d.summary;
  if (!d.people.length) {
    $("oc-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No people yet. Add records under <a href="/?db=XORCISM&table=PERSON">PERSON</a> (set Manager, Job title, Department), or import your directory from Microsoft Entra ID.</div>`;
    return;
  }
  const cards = [
    card("People", String(s.total), `${s.withManager} with a manager`),
    card("Managers", String(s.managers), "have direct reports"),
    card("Departments", String(s.departments), "distinct"),
    card("Org depth", String(s.maxDepth), "levels deep"),
    card("From Entra ID", String(s.fromEntra), "synced", s.fromEntra ? "#60a5fa" : undefined),
    card("Disabled", String(s.disabled), "accounts", s.disabled ? "#f87171" : "#34d399"),
  ].join("");
  const byDept = Object.entries(s.byDepartment || {}).filter(([k]) => k !== "—").sort((a: any, b: any) => b[1] - a[1])
    .map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  // filter
  const f = FILTER.toLowerCase();
  const visible = new Set<number>();
  if (f) {
    for (const p of d.people) if (`${p.name} ${p.title} ${p.department} ${p.email} ${p.upn}`.toLowerCase().includes(f)) {
      // include the matched person + their whole ancestor chain so the tree stays connected
      let cur: Person | undefined = p; const byId = new Map(d.people.map((x) => [x.id, x]));
      while (cur) { visible.add(cur.id); cur = cur.managerId != null ? byId.get(cur.managerId) : undefined; }
    }
  }
  const people = f ? d.people.filter((p) => visible.has(p.id)) : d.people;
  const childrenOf = new Map<number, Person[]>();
  for (const p of people) if (p.managerId != null) { const a = childrenOf.get(p.managerId); if (a) a.push(p); else childrenOf.set(p.managerId, [p]); }
  const roots = people.filter((p) => p.managerId == null || !people.some((q) => q.id === p.managerId))
    .sort((a, b) => b.reports - a.reports || a.name.localeCompare(b.name));

  $("oc-body").innerHTML = `<div class="oc-cards">${cards}</div>
    <div class="oc-section">By department</div><div class="breakdown">${byDept || "<span class='muted'>—</span>"}</div>
    <div class="oc-section">Hierarchy (${people.length})</div>
    <div class="filters"><input id="oc-search" placeholder="Filter by name, title, department, UPN…" value="${esc(FILTER)}" style="min-width:300px"></div>
    <ul class="tree">${roots.map((r) => nodeHtml(r, childrenOf)).join("")}</ul>`;

  const si = document.getElementById("oc-search") as HTMLInputElement | null;
  if (si) si.addEventListener("input", () => { FILTER = si.value; const c = si.selectionStart; render(); const n = document.getElementById("oc-search") as HTMLInputElement | null; if (n) { n.focus(); try { n.setSelectionRange(c, c); } catch {} } });
  $("oc-body").querySelectorAll<HTMLElement>(".toggle").forEach((t) => t.addEventListener("click", () => {
    const li = t.closest("li"); if (!li) return; li.classList.toggle("collapsed"); t.textContent = li.classList.contains("collapsed") ? "▸" : "▾";
  }));
}

function load(): void {
  fetch("/api/org-chart").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((d: Data) => { DATA = d; render(); })
    .catch((e) => { $("oc-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
document.addEventListener("DOMContentLoaded", load);
