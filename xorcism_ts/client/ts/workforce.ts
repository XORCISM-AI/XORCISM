/** workforce.ts — NICE + ENISA ECSF workforce roles around PERSON (/workforce). Reads /api/workforce. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2400); }

let DATA: any = null;
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;

function load(): void {
  fetch("/api/workforce").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    DATA = d; const s = d.summary;
    const cards = [
      card("Work roles", String(s.roles), `${s.ecsf} ECSF · ${s.nice} NICE`),
      card("Coverage", `${s.coverage}%`, `${s.covered}/${s.roles} roles staffed`, s.coverage >= 60 ? "#4ade80" : "#fbbf24"),
      card("People mapped", String(s.assigned), "with a work role"),
      card("Role gaps", String(s.gaps), "roles with no holder", s.gaps ? "#fbbf24" : "#4ade80"),
    ].join("");
    const people = d.people.length
      ? `<table class="t"><thead><tr><th>Person</th><th>Work roles (NICE / ECSF)</th></tr></thead><tbody>${d.people.map((p: any) => `<tr><td><span class="nm">${esc(p.name)}</span></td><td>${p.roles.map((r: any) => `<span class="role${r.primary ? " prim" : ""}"><span class="fw fw-${esc(r.framework)}">${esc(r.framework)}</span> ${esc(r.name)}${r.proficiency ? ` · ${esc(r.proficiency)}` : ""} <a style="cursor:pointer;color:#f87171" data-un="${r.id}">×</a></span>`).join("") || "<span class='muted'>none</span>"} <button class="btn-sm2" data-assign="${p.id}">+ role</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No people mapped to work roles yet.</div>`;
    const gaps = d.gaps.length ? d.gaps.map((g: any) => `<span class="gap"><span class="fw fw-${esc(g.framework)}">${esc(g.framework)}</span> ${esc(g.name)} <a style="cursor:pointer" data-assign-role="${g.id}">assign</a></span>`).join("") : `<span class="muted">✓ every role has a holder</span>`;
    const roles = d.roles.map((r: any) => `<tr><td><span class="fw fw-${esc(r.framework)}">${esc(r.framework)}</span> <span class="code">${esc(r.code)}</span></td><td><span class="nm">${esc(r.name)}</span><div class="muted" style="font-size:11px">${esc(r.description)}</div></td><td class="muted" style="font-size:11px">${esc(r.skills)}</td><td>${r.holders.length ? r.holders.map((h: any) => esc(h.person)).join(", ") : "<span class='muted'>—</span>"}</td></tr>`).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">People → work roles (${d.people.length})</div>${people}
      <div class="sec">Role-coverage gaps (${d.gaps.length})</div><div style="margin-bottom:6px">${gaps}</div>
      <div class="sec">Work-role catalogue (${d.roles.length})</div><table class="t"><thead><tr><th>Framework</th><th>Role</th><th>Skills</th><th>Holders</th></tr></thead><tbody>${roles}</tbody></table>`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function rolePicker(): number | null {
  const list = DATA.roles.map((r: any, i: number) => `${i + 1}. [${r.framework}] ${r.name}`).join("\n");
  const pick = prompt(`Pick a work role (number):\n\n${list}`);
  if (!pick) return null;
  const r = DATA.roles[Number(pick) - 1];
  return r ? r.id : null;
}
function personPicker(): number | null {
  const list = DATA.people.map((p: any, i: number) => `${i + 1}. ${p.name}`).join("\n") || "(assign from a person row instead)";
  const pick = prompt(`Pick a person (number):\n\n${list}`);
  if (!pick) return null;
  const p = DATA.people[Number(pick) - 1];
  return p ? p.id : null;
}
function assign(personId: number, workRoleId: number): void {
  fetch("/api/workforce/assign", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ personId, workRoleId, proficiency: "Proficient" }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast("Role assigned"); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll("[data-assign]"), (b: HTMLElement) => { b.onclick = () => { const w = rolePicker(); if (w) assign(Number(b.getAttribute("data-assign")), w); }; });
  Array.prototype.forEach.call(document.querySelectorAll("[data-assign-role]"), (b: HTMLElement) => { b.onclick = () => { const p = personPicker(); if (p) assign(p, Number(b.getAttribute("data-assign-role"))); }; });
  Array.prototype.forEach.call(document.querySelectorAll("[data-un]"), (b: HTMLElement) => { b.onclick = () => { if (!confirm("Remove this role assignment?")) return; fetch(`/api/workforce/assign/${b.getAttribute("data-un")}`, { method: "DELETE" }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then(() => { toast("Removed"); load(); }).catch((e) => toast("⚠️ " + e)); }; });
}
document.addEventListener("DOMContentLoaded", load);
