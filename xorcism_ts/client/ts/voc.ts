/** voc.ts — Vulnerability Operations Center cockpit (/voc). Reads /api/voc. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2400); }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const slaCls = (s: string): string => `sla-${["breached", "approaching", "within"].includes(s) ? s : "within"}`;
const pctColor = (p: number | null): string => (p == null ? "#64748b" : p >= 80 ? "#4ade80" : p >= 50 ? "#fbbf24" : "#f87171");

function load(): void {
  fetch("/api/voc").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card("Open backlog", String(s.backlog), `${s.criticalOpen} critical · ${s.kevOpen} KEV`, s.backlog ? undefined : "#4ade80"),
      card("SLA compliance", s.slaCompliance == null ? "—" : `${s.slaCompliance}%`, `${s.breached} breached`, pctColor(s.slaCompliance)),
      card("MTTR", s.mttrDays == null ? "—" : `${s.mttrDays}d`, "mean time to remediate", s.mttrDays != null && s.mttrDays <= 30 ? "#4ade80" : "#fbbf24"),
      card("Coverage", s.coverage == null ? "—" : `${s.coverage}%`, `${s.remediated}/${s.total} remediated`, pctColor(s.coverage)),
      card("Velocity (30d)", String(s.velocity30), "remediated last 30 days", "#60a5fa"),
      card("Avg age", `${s.avgAgeDays}d`, `${s.unassigned} unassigned`, s.avgAgeDays > 60 ? "#fbbf24" : undefined),
    ].join("");

    const work = d.worklist.length
      ? `<table class="t"><thead><tr><th>CVE</th><th>Asset</th><th>Sev</th><th>EPSS</th><th>SLA</th><th>Age</th><th>Owner</th><th></th></tr></thead><tbody>${d.worklist.map((w: any) => `<tr>
          <td><span class="mono">${esc(w.cve)}</span>${w.kev ? ` <span class="kev">KEV</span>` : ""}</td><td>${esc(w.asset)}</td>
          <td><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span></td><td>${w.epss != null ? Math.round(w.epss * 100) + "%" : "—"}</td>
          <td><span class="sla ${slaCls(w.slaStatus)}">${esc(w.slaStatus)}${w.overdueDays ? ` +${w.overdueDays}d` : ""}</span></td>
          <td>${w.ageDays != null ? w.ageDays + "d" : "—"}</td><td>${w.owner ? esc(w.owner) : "<span class='muted'>unassigned</span>"}</td>
          <td style="white-space:nowrap"><button class="btn-sm2 assign" data-id="${w.id}">Assign</button> <button class="btn-sm2 remed" data-id="${w.id}">✓ Remediate</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">✓ Empty backlog — nothing open.</div>`;

    const sla = d.slaPolicy.map((t: any) => `<div class="slarow"><span class="sev ${scls(t.tier === "KEV" ? "Critical" : t.tier)}">${esc(t.tier)}</span><span class="muted">${esc(t.label)}</span><span class="spacer" style="flex:1"></span><input class="dn sla-d" data-tier="${esc(t.tier)}" type="number" value="${t.days}" min="1"> <span class="muted">days</span></div>`).join("");
    const ageMax = Math.max(1, ...Object.values(d.aging).map((x) => Number(x)));
    const aging = Object.entries(d.aging).map(([k, v]: any) => `<div class="agerow"><span class="nm2">${esc(k)} days</span><div class="bar"><i style="width:${(Number(v) / ageMax) * 100}%;background:${k === "90+" ? "#f87171" : k === "61-90" ? "#fbbf24" : "#4ade80"}"></i></div><span style="min-width:30px;text-align:right">${v}</span></div>`).join("");
    const camps = d.campaigns.length ? d.campaigns.map((c: any) => `<div class="camprow"><span class="nm2">${esc(c.name)}</span><span class="muted" style="font-size:11px">${esc(c.scope)} · target ${esc(c.target)}</span><span class="spacer" style="flex:1"></span><div class="bar"><i style="width:${c.pct}%"></i></div><span style="min-width:60px;text-align:right">${c.done}/${c.total} (${c.pct}%)</span></div>`).join("") : `<div class="muted">No campaigns.</div>`;
    const excs = d.exceptions.length ? d.exceptions.map((e: any) => `<div class="camprow"><span class="nm2" style="min-width:auto"><b style="color:#e2e8f0">${esc(e.title)}</b></span><span class="muted" style="font-size:11px">${esc(e.approvedBy)} · expires ${esc(e.expiry)}${e.expired ? " (expired)" : ""}</span></div>`).join("") : `<div class="muted">No active exceptions.</div>`;

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">Remediation worklist (${d.worklist.length})<span class="spacer"></span><button class="btn-sm2" id="new-camp">+ Campaign</button> <button class="btn-sm2" id="new-exc">+ Risk acceptance</button></div>${work}
      <div class="grid2" style="margin-top:8px">
        <div class="panel"><div class="sec" style="margin-top:0">Remediation SLA policy</div>${sla}</div>
        <div class="panel"><div class="sec" style="margin-top:0">Backlog aging</div>${aging}</div>
      </div>
      <div class="sec">Remediation campaigns (${d.campaigns.length})</div><div class="panel">${camps}</div>
      <div class="sec">Risk-acceptance / exception register (${d.exceptions.length})</div><div class="panel">${excs}</div>`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function post(url: string, body: unknown, msg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast(msg); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll(".remed"), (b: HTMLElement) => { b.onclick = () => post(`/api/voc/instance/${b.getAttribute("data-id")}/remediate`, {}, "Marked remediated"); });
  Array.prototype.forEach.call(document.querySelectorAll(".assign"), (b: HTMLElement) => { b.onclick = () => { const td = prompt("Target remediation date (YYYY-MM-DD):"); if (td == null) return; post(`/api/voc/instance/${b.getAttribute("data-id")}/assign`, { targetDate: td, priority: "High" }, "Assigned"); }; });
  Array.prototype.forEach.call(document.querySelectorAll(".sla-d"), (inp: HTMLInputElement) => { inp.onchange = () => post("/api/voc/sla", { tier: inp.getAttribute("data-tier"), days: Number(inp.value) }, "SLA updated"); });
  $("new-camp").onclick = () => { const name = prompt("Campaign name:"); if (!name) return; const scope = prompt("Scope (all / kev / critical / high / medium / low):", "kev") || "all"; const targetDate = prompt("Target date (YYYY-MM-DD):") || ""; post("/api/voc/campaign", { name, scope, targetDate }, "Campaign created"); };
  $("new-exc").onclick = () => { const title = prompt("Risk-acceptance title:"); if (!title) return; const justification = prompt("Justification:") || ""; const approvedBy = prompt("Approved by:") || ""; const expiryDate = prompt("Expiry date (YYYY-MM-DD):") || ""; post("/api/voc/exception", { title, justification, approvedBy, expiryDate, scope: "cve" }, "Exception recorded"); };
}
document.addEventListener("DOMContentLoaded", load);
