/**
 * control-weight.ts — control-weight calculator (/control-weight), the CapGRC PfC model.
 * Live PfC = (T × E × PfO × P)/100 with band, assign the weight to a control, and see the
 * weighted-control contribution to the Enterprise Risk Score.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

interface Model {
  types: { value: number; label: string }[]; scopes: { value: number; label: string }[];
  objectives: { key: string; label: string }[]; min: number; max: number;
  bands: { low: number; medium: number }; bounds: { floor: number; ceil: number };
  formula: string; source: string;
}
let MODEL: Model | null = null;
const OBJ_KEYS = ["confidentiality", "integrity", "availability", "nonRepudiation"];

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;

function inputs(): Record<string, number> {
  const o: Record<string, number> = {
    type: Number(($("f-type") as HTMLSelectElement).value || 1),
    scope: Number(($("f-scope") as HTMLSelectElement).value || 1),
    qty: Number(($("f-qty") as HTMLInputElement).value || 0),
    qtyTotal: Number(($("f-qtot") as HTMLInputElement).value || 0),
  };
  for (const k of OBJ_KEYS) o[k] = Number((document.getElementById(`o-${k}`) as HTMLInputElement)?.value || 0);
  return o;
}

/** Live recompute (client-side mirror of the server formula; the server stays authoritative on save). */
function recompute(): void {
  if (!MODEL) return;
  const i = inputs();
  const pfo = OBJ_KEYS.reduce((n, k) => n + i[k], 0);
  const p = i.qtyTotal > 0 ? Math.max(0, Math.min(100, (i.qty / i.qtyTotal) * 100)) : 0;
  const raw = (i.type * i.scope * pfo * p) / 100;
  const w = Math.max(MODEL.min, Math.min(MODEL.max, Math.round(raw)));
  const band = w <= MODEL.bands.low ? "low" : w <= MODEL.bands.medium ? "medium" : "high";
  const label = band === "low" ? "Faible" : band === "medium" ? "Moyen" : "Élevé";
  $("pfo-tot").textContent = `— Σ ${pfo} / 20`;
  $("p-val").textContent = String(Math.round(p * 10) / 10);
  $("w-val").textContent = String(w);
  ($("w-val") as HTMLElement).style.color = band === "high" ? "#f87171" : band === "medium" ? "#fbbf24" : "#94a3b8";
  const b = $("w-band"); b.textContent = label; b.className = `band b-${band}`;
  $("w-formula").textContent = `PfC = (${i.type} × ${i.scope} × ${pfo} × ${Math.round(p * 10) / 10}) / 100 = ${Math.round(raw * 10) / 10} → ${w}`;
}

function renderTerm(d: any): void {
  const a = d.assurance, s = d.summary;
  const sign = (v: number): string => `<span class="${v > 0 ? "pos" : v < 0 ? "neg" : "muted"}">${v > 0 ? "+" : ""}${v}</span>`;
  $("term").innerHTML = `
    <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
      <div style="text-align:center"><div style="font-size:34px;font-weight:800" class="${a.term > 0 ? "pos" : a.term < 0 ? "neg" : "muted"}">${a.term > 0 ? "+" : ""}${a.term}</div>
        <div class="muted" style="font-size:11px">risk-score points</div></div>
      <div style="flex:1;min-width:220px">
        <div style="font-size:12.5px;color:#cbd5e1">Weighted coverage <b style="color:#7dd3fc">${a.coverage}%</b>
          <span class="bar" style="margin-left:6px"><span style="width:${a.coverage}%"></span></span></div>
        <div class="muted" style="font-size:11.5px;margin-top:4px">${a.earnedWeight} of ${a.totalWeight} weight earned across ${a.weighted} weighted control(s)</div>
        <div class="muted" style="font-size:11.5px;margin-top:2px">assurance credit ${sign(a.credit)} · weighted gaps ${sign(a.gap)}${
          MODEL && (a.rawTerm < MODEL.bounds.floor || a.rawTerm > MODEL.bounds.ceil)
            ? ` <i>(raw ${a.rawTerm} — clamped to [${MODEL.bounds.floor}, +${MODEL.bounds.ceil}])</i>`
            : a.rawTerm !== a.term ? ` <i>(raw ${a.rawTerm})</i>` : ""}</div>
      </div>
    </div>
    <div class="term">Each weighted control contributes <b>weight × implementation effectiveness</b> as assurance credit
      (negative) and <b>weight × (1 − effectiveness)</b> as a weighted gap (positive). The term is deliberately
      <b>asymmetric</b> — a heavy control left unimplemented costs more than the same control implemented earns —
      and clamped to <b>[−40, +60]</b> so it shifts the Enterprise Risk Score without dominating it.</div>`;
  $("cards").innerHTML = [
    card("Weighted controls", String(s.weighted), `of ${s.catalogue} in catalogue`),
    card("Avg weight", String(s.avgWeight), `max ${MODEL?.max ?? 180}`),
    card("Weighted coverage", `${s.coverage}%`, "implementation-weighted", s.coverage >= 70 ? "#4ade80" : s.coverage >= 40 ? "#fbbf24" : "#f87171"),
    card("Élevé", String(d.distribution.high), "high-weight controls", d.distribution.high ? "#f87171" : undefined),
    card("Risk term", `${a.term > 0 ? "+" : ""}${a.term}`, "EnterpriseRiskScore", a.term > 0 ? "#f87171" : "#4ade80"),
  ].join("");
}

function renderRows(rows: any[]): void {
  $("n-rows").textContent = `(${rows.length})`;
  if (!rows.length) { $("rows").innerHTML = `<div class="muted" style="padding:10px 0">No weighted control yet — use the calculator to assign a weight.</div>`; return; }
  $("rows").innerHTML = `<table class="t"><thead><tr><th>Control</th><th style="width:70px">Weight</th><th style="width:80px">Band</th>
    <th style="width:150px">Status</th><th style="width:90px">Effect.</th><th style="width:100px">Risk pts</th><th style="width:44px"></th></tr></thead><tbody>
    ${rows.map((r) => `<tr>
      <td><span class="mono">${esc(r.cis)}</span> <span class="nm">${esc(r.name)}</span></td>
      <td><b style="color:#7dd3fc">${r.weight}</b></td>
      <td><span class="band b-${esc(r.band)}">${r.band === "low" ? "Faible" : r.band === "medium" ? "Moyen" : "Élevé"}</span></td>
      <td>${esc(r.status || "—")}</td>
      <td>${Math.round(r.effectiveness * 100)}%</td>
      <td class="${r.contribution > 0 ? "pos" : r.contribution < 0 ? "neg" : "muted"}">${r.contribution > 0 ? "+" : ""}${r.contribution}</td>
      <td><button class="btn-sm clr" data-id="${r.controlId}" title="clear weight">×</button></td></tr>`).join("")}
    </tbody></table>`;
  Array.prototype.forEach.call(document.querySelectorAll(".clr"), (b: HTMLElement) => {
    b.onclick = () => {
      fetch(`/api/control-weight/control/${b.getAttribute("data-id")}`, { method: "DELETE" })
        .then((r) => r.json()).then(() => { toast("Weight cleared"); load(); }).catch((e) => toast("⚠️ " + e));
    };
  });
}

function load(): void {
  fetch("/api/control-weight").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    if (!MODEL) {
      MODEL = d.model;
      ($("f-type") as HTMLSelectElement).innerHTML = MODEL!.types.map((t) => `<option value="${t.value}">${esc(t.label)} (${t.value})</option>`).join("");
      ($("f-scope") as HTMLSelectElement).innerHTML = MODEL!.scopes.map((s) => `<option value="${s.value}">${esc(s.label)} (${s.value})</option>`).join("");
      $("objs").innerHTML = MODEL!.objectives.map((o) => `<div class="obj"><span class="on">${esc(o.label)}</span>
        <input type="range" id="o-${esc(o.key)}" min="0" max="5" step="1" value="0" style="flex:1"><span class="ov" id="v-${esc(o.key)}">0</span></div>`).join("");
      for (const o of MODEL!.objectives) {
        const el = document.getElementById(`o-${o.key}`) as HTMLInputElement;
        el.addEventListener("input", () => { document.getElementById(`v-${o.key}`)!.textContent = el.value; recompute(); });
      }
      for (const id of ["f-type", "f-scope", "f-qty", "f-qtot"]) $(id).addEventListener("input", recompute);
      recompute();
    }
    renderTerm(d); renderRows(d.rows || []);
  }).catch((e) => { $("term").innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  // control picker
  let tmr: number | undefined;
  ($("f-ctrl") as HTMLInputElement).addEventListener("input", () => {
    window.clearTimeout(tmr);
    tmr = window.setTimeout(() => {
      const q = ($("f-ctrl") as HTMLInputElement).value.trim();
      if (q.length < 2) return;
      fetch(`/api/control-weight/controls?q=${encodeURIComponent(q)}`).then((r) => r.json()).then((d) => {
        $("ctrl-list").innerHTML = (d.items || []).map((i: any) =>
          `<option value="${esc(i.cis ? i.cis + " — " + i.name : i.name)}" data-id="${i.controlId}">${esc(i.vocabulary)}</option>`).join("");
      }).catch(() => { /* ignore */ });
    }, 220);
  });
  $("apply").addEventListener("click", () => {
    const raw = ($("f-ctrl") as HTMLInputElement).value.trim();
    if (!raw) { toast("Pick a control first"); return; }
    const opt = Array.prototype.find.call($("ctrl-list").querySelectorAll("option"), (o: HTMLOptionElement) => o.value === raw) as HTMLOptionElement | undefined;
    const id = opt?.getAttribute("data-id");
    if (!id) { toast("Select a control from the list"); return; }
    fetch(`/api/control-weight/control/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(inputs()) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then((j) => { $("msg").textContent = `weight ${j.weight} (${j.bandLabel}) assigned`; toast("Weight assigned"); load(); })
      .catch((e) => toast("⚠️ " + (e.message || e)));
  });
});
