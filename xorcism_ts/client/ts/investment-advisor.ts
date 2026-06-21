/** investment-advisor.ts — agentic security-investment "what-if" simulator (/investment-advisor).
 * Loads live posture, simulates a proposed investment (deterministic), and fetches a local-AI
 * board-ready recommendation. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Lever { key: string; label: string; blurb: string; }
interface Baseline { score: number; drivers: Record<string, number>; credits: number; totalALE: number; currency: string; openRisks: number; levers: Lever[]; }
let BASE: Baseline | null = null;
const DLABEL: Record<string, string> = { assets: "Asset hygiene", riskRegister: "Risk register", incidents: "Open incidents", compliance: "Compliance debt", patch: "Overdue patches" };

function money(n: number | null, cur: string): string { if (n == null) return "—"; try { return new Intl.NumberFormat(undefined, { style: "currency", currency: cur || "EUR", maximumFractionDigits: 0, notation: "compact" }).format(n); } catch { return String(n); } }

function render(): void {
  if (!BASE) return;
  const b = BASE;
  const drivers = Object.entries(b.drivers).map(([k, v]) => `<div class="stat"><span class="l">${esc(DLABEL[k] || k)}</span><span class="v">${v}</span></div>`).join("");
  const leverOpts = b.levers.map((l) => `<option value="${esc(l.key)}">${esc(l.label)}</option>`).join("");
  $("iv-body").innerHTML = `<div class="iv-grid">
    <div>
      <div class="panel">
        <h3>Your live posture</h3>
        <div class="big"><div class="bigcard"><div class="v" style="color:${b.score >= 200 ? "#f87171" : b.score >= 80 ? "#fbbf24" : "#34d399"}">${b.score}</div><div class="l">Enterprise Risk Score</div></div>
          <div class="bigcard"><div class="v">${money(b.totalALE, b.currency)}</div><div class="l">Annualized exposure (ALE)</div></div></div>
        ${drivers}
      </div>
      <div class="panel">
        <h3>Propose an investment</h3>
        <label>Name (optional)</label><input id="iv-name" placeholder="e.g. Deploy CrowdStrike Falcon EDR">
        <label>Investment lever</label><select id="iv-lever">${leverOpts}</select>
        <div class="muted" id="iv-blurb" style="font-size:12px;margin-top:4px"></div>
        <label>Coverage / rollout: <span id="iv-cov-l">70%</span></label><input id="iv-cov" type="range" min="5" max="100" step="5" value="70">
        <label>Annual cost (${esc(b.currency)}, optional)</label><input id="iv-cost" type="number" min="0" step="1000" placeholder="120000">
        <label>What-if question for the AI (optional)</label><textarea id="iv-q" placeholder="Does this beat spending the same on a SIEM?"></textarea>
        <div style="display:flex;gap:8px;margin-top:12px"><button class="btn-go" id="iv-sim">Simulate</button><button class="btn-ai" id="iv-ai">🤖 AI recommendation</button></div>
      </div>
    </div>
    <div>
      <div class="panel" id="iv-result"><h3>Simulation</h3><div class="muted">Pick a lever and click <b>Simulate</b> to model the risk reduction against your environment.</div></div>
      <div class="panel" id="iv-rec-panel" style="display:none"><h3>AI recommendation <span class="chip" id="iv-model"></span></h3><div class="rec" id="iv-rec"></div></div>
    </div></div>`;
  const blurb = (): void => { const l = b.levers.find((x) => x.key === ($("iv-lever") as HTMLSelectElement).value); $("iv-blurb").textContent = l ? l.blurb : ""; };
  blurb();
  $("iv-lever").addEventListener("change", blurb);
  $("iv-cov").addEventListener("input", () => { $("iv-cov-l").textContent = ($("iv-cov") as HTMLInputElement).value + "%"; });
  $("iv-sim").addEventListener("click", () => void simulate());
  $("iv-ai").addEventListener("click", () => void advise());
}

function payload(): Record<string, unknown> {
  return { lever: ($("iv-lever") as HTMLSelectElement).value, coverage: Number(($("iv-cov") as HTMLInputElement).value) / 100,
    cost: ($("iv-cost") as HTMLInputElement).value || null, name: ($("iv-name") as HTMLInputElement).value || undefined,
    question: ($("iv-q") as HTMLTextAreaElement).value || undefined };
}

function renderSim(s: any): void {
  const cur = s.currency;
  const affected = (s.affected || []).map((a: any) => `<div class="arrow">${esc(a.driver)}: ${a.from} → <b>${a.to}</b></div>`).join("");
  const warn = (s.overlap || []).map((w: string) => `<div class="warn">⚠ ${esc(w)}</div>`).join("");
  $("iv-result").innerHTML = `<h3>Simulation — ${esc(s.leverLabel)}</h3>
    <div class="big">
      <div class="bigcard"><div class="v" style="color:#34d399">−${s.riskDeltaPct}%</div><div class="l">Risk reduction</div></div>
      <div class="bigcard"><div class="v">${s.baselineScore} → <span style="color:#34d399">${s.projectedScore}</span></div><div class="l">Enterprise Risk Score</div></div>
      <div class="bigcard"><div class="v">${money(s.dollarReduction, cur)}</div><div class="l">Loss avoided / yr</div></div>
      <div class="bigcard"><div class="v">${s.roi != null ? s.roi + "×" : "—"}</div><div class="l">ROI (per ${esc(cur)} spent)</div></div>
    </div>
    <div style="font-size:13px;color:#cbd5e1;margin-bottom:4px">Drivers reduced:</div>${affected || "<div class='muted'>No headroom on the targeted drivers.</div>"}
    ${warn}`;
}

async function simulate(): Promise<void> {
  try { const r = await fetch("/api/investment-advisor/simulate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload()) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); renderSim(d); }
  catch (e) { $("iv-result").innerHTML = `<h3>Simulation</h3><div class="muted">⚠️ ${esc(e)}</div>`; }
}

async function advise(): Promise<void> {
  const btn = $("iv-ai") as HTMLButtonElement; btn.disabled = true; const lbl = btn.textContent; btn.textContent = "Thinking…";
  $("iv-rec-panel").style.display = ""; $("iv-rec").textContent = "Consulting the local AI…";
  try { const r = await fetch("/api/investment-advisor/advise", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload()) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    renderSim(d.simulation); $("iv-rec").textContent = d.recommendation; $("iv-model").textContent = d.offline ? "deterministic (AI offline)" : d.model; }
  catch (e) { $("iv-rec").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; btn.textContent = lbl; }
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/investment-advisor"); if (!r.ok) throw new Error(`HTTP ${r.status}`); BASE = await r.json(); }
  catch (e) { $("iv-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  render();
}
document.addEventListener("DOMContentLoaded", () => void load());
