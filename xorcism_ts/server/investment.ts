/**
 * investment.ts — Agentic Security Investment Advisor.
 *
 * Implements the "what-if" investment decision-making idea (cyesec): instead of justifying spend with
 * industry averages, simulate a proposed investment against THIS organisation's actual posture and show
 * the measurable risk reduction, the dollars of annualized loss avoided, redundancy/overlap with what
 * you already have, and a defensible recommendation. The deterministic engine works off the existing
 * Enterprise Risk model (enterpriseRiskBreakdown drivers + the FAIR/CRQ ALE from the risk register);
 * a local AI (Ollama) layer turns it into a board-ready narrative, with a deterministic offline fallback.
 */
import { enterpriseRiskBreakdown } from "./riskscore";
import { riskRegisterInventory } from "./riskregister";
import { ollamaChat, ollamaStatus, OLLAMA_MODEL } from "./ai";

// Investment "levers" — each maps to the Enterprise-Risk drivers it reduces (fraction of that driver
// removed at full coverage) + whether it earns an assurance credit. Keyed for the UI.
export interface Lever { key: string; label: string; drivers: Partial<Record<string, number>>; credit?: number; blurb: string; }
export const LEVERS: Lever[] = [
  { key: "edr_xdr", label: "EDR / XDR", drivers: { incidents: 0.5, assets: 0.15 }, blurb: "Endpoint detection & response — faster containment, fewer breaches." },
  { key: "mfa", label: "MFA enforcement", drivers: { assets: 0.2, incidents: 0.2 }, blurb: "Phishing-resistant MFA closes the #1 account-takeover path." },
  { key: "patch_automation", label: "Patch automation", drivers: { patch: 0.7, assets: 0.2 }, blurb: "Automated patch orchestration clears the overdue-patch backlog." },
  { key: "vuln_mgmt", label: "Vulnerability management / scanning", drivers: { assets: 0.3 }, blurb: "Continuous discovery + risk-based remediation of exposures." },
  { key: "waf", label: "WAF / edge protection", drivers: { assets: 0.15, incidents: 0.15 }, blurb: "Shields internet-facing apps from common web attacks." },
  { key: "ztna", label: "ZTNA / segmentation", drivers: { assets: 0.2, incidents: 0.2 }, blurb: "Zero-trust access shrinks the blast radius / lateral movement." },
  { key: "siem", label: "SIEM / log monitoring", drivers: { incidents: 0.3 }, blurb: "Detection & response coverage across the estate." },
  { key: "backup_dr", label: "Backup & DR", drivers: { incidents: 0.15 }, credit: 3, blurb: "Resilience to ransomware / destructive attacks." },
  { key: "awareness", label: "Security awareness training", drivers: { incidents: 0.1 }, credit: 5, blurb: "Reduces human-error incidents; earns assurance credit." },
  { key: "pentest", label: "Pen testing / red team", drivers: { riskRegister: 0.1, compliance: 0.1 }, blurb: "Validates controls; surfaces & closes real findings." },
  { key: "grc_automation", label: "GRC / compliance automation", drivers: { compliance: 0.6 }, blurb: "Clears audit findings & continuously proves controls." },
  { key: "control_impl", label: "Implement NIST 800-53 controls", drivers: { compliance: 0.4, assets: 0.1 }, blurb: "Closes control gaps against the baseline." },
];

export interface InvestmentSimulation {
  lever: string; leverLabel: string; coverage: number; cost: number | null;
  baselineScore: number; projectedScore: number; riskDelta: number; riskDeltaPct: number;
  baselineDrivers: Record<string, number>; projectedDrivers: Record<string, number>;
  dollarReduction: number | null; roi: number | null; currency: string;
  overlap: string[]; affected: { driver: string; from: number; to: number }[];
}

const DRIVER_LABEL: Record<string, string> = {
  assets: "Asset hygiene", riskRegister: "Risk register", incidents: "Open incidents",
  compliance: "Compliance debt", patch: "Overdue patches",
};

/** Current posture (the "environment map" the simulation reduces). */
export function investmentBaseline(tenant: number | null): Record<string, unknown> {
  const br = enterpriseRiskBreakdown(tenant);
  let totalALE = 0; let currency = "EUR"; let openRisks = 0;
  try { const rr = riskRegisterInventory(tenant).summary; totalALE = Number(rr.totalALE) || 0; currency = rr.currency || "EUR"; openRisks = Number(rr.open) || 0; } catch { /* none */ }
  return {
    score: br.total,
    drivers: { assets: br.assets, riskRegister: br.riskRegister, incidents: br.incidents, compliance: br.compliance, patch: br.patch },
    credits: br.credits, totalALE, currency, openRisks, levers: LEVERS,
  };
}

/** Deterministic "what-if": reduce the lever's target drivers by factor × coverage; recompute. */
export function simulateInvestment(tenant: number | null, p: { lever: string; coverage?: number; cost?: number | null }): InvestmentSimulation {
  const lv = LEVERS.find((l) => l.key === p.lever) || LEVERS[0];
  const cov = Math.max(0.05, Math.min(1, p.coverage ?? 0.7));
  const br = enterpriseRiskBreakdown(tenant);
  const baseDrivers: Record<string, number> = { assets: br.assets, riskRegister: br.riskRegister, incidents: br.incidents, compliance: br.compliance, patch: br.patch };
  const projDrivers = { ...baseDrivers };
  const affected: { driver: string; from: number; to: number }[] = [];
  const overlap: string[] = [];
  for (const [d, factor] of Object.entries(lv.drivers)) {
    const cur = baseDrivers[d] ?? 0;
    const reduced = Math.max(0, Math.round(cur * (1 - (factor as number) * cov)));
    if (cur <= 2) overlap.push(`${DRIVER_LABEL[d] || d} is already low (${cur}) — limited headroom; existing controls likely cover this.`);
    projDrivers[d] = reduced;
    if (reduced !== cur) affected.push({ driver: DRIVER_LABEL[d] || d, from: cur, to: reduced });
  }
  const credits = br.credits - (lv.credit || 0);
  const baselineScore = br.total;
  const projectedScore = Math.max(0, Math.round(projDrivers.assets + projDrivers.riskRegister + projDrivers.incidents + projDrivers.compliance + projDrivers.patch + credits));
  const riskDelta = Math.max(0, baselineScore - projectedScore);
  const riskDeltaPct = baselineScore > 0 ? Math.round((riskDelta / baselineScore) * 100) : 0;

  let totalALE = 0; let currency = "EUR";
  try { const rr = riskRegisterInventory(tenant).summary; totalALE = Number(rr.totalALE) || 0; currency = rr.currency || "EUR"; } catch { /* none */ }
  const dollarReduction = totalALE > 0 && baselineScore > 0 ? Math.round(totalALE * (riskDelta / baselineScore)) : null;
  const cost = p.cost != null && p.cost > 0 ? p.cost : null;
  const roi = dollarReduction != null && cost ? Math.round((dollarReduction / cost) * 100) / 100 : null;

  return {
    lever: lv.key, leverLabel: lv.label, coverage: cov, cost,
    baselineScore, projectedScore, riskDelta, riskDeltaPct,
    baselineDrivers: baseDrivers, projectedDrivers: projDrivers,
    dollarReduction, roi, currency, overlap, affected,
  };
}

/** Board-ready narrative — local-AI "what-if" recommendation, with a deterministic offline fallback. */
export async function investmentAdvice(tenant: number | null, p: { lever: string; coverage?: number; cost?: number | null; name?: string; question?: string }): Promise<{ recommendation: string; simulation: InvestmentSimulation; model: string; offline: boolean }> {
  const sim = simulateInvestment(tenant, p);
  const money = (n: number | null): string => n == null ? "n/a" : `${n.toLocaleString()} ${sim.currency}`;
  const det =
    `Proposed investment: ${p.name || sim.leverLabel} (≈${Math.round(sim.coverage * 100)}% coverage` +
    `${sim.cost ? `, cost ${money(sim.cost)}` : ""}).\n` +
    `Modelled against your live posture, it lowers the Enterprise Risk Score ${sim.baselineScore} → ${sim.projectedScore} ` +
    `(−${sim.riskDelta}, −${sim.riskDeltaPct}%), chiefly by reducing: ${sim.affected.map((a) => `${a.driver} ${a.from}→${a.to}`).join(", ") || "—"}.\n` +
    (sim.dollarReduction != null ? `Estimated annualized loss avoided: ${money(sim.dollarReduction)}${sim.roi != null ? ` (ROI ${sim.roi}× the cost)` : ""}.\n` : "") +
    (sim.overlap.length ? `Caution: ${sim.overlap.join(" ")}\n` : "") +
    `Decision: ${sim.riskDeltaPct >= 15 ? "materially reduces risk in your environment — recommended." : sim.riskDeltaPct >= 5 ? "moderate, targeted reduction — justified if it closes a specific gap." : "limited reduction here — likely overlaps existing controls; prioritise a higher-impact lever."}`;

  try {
    const st = await ollamaStatus();
    if (st.reachable) {
      const sys = "You are a CISO investment advisor. Given a deterministic simulation of a proposed security investment against the organisation's live risk posture, write a concise, board-ready recommendation (4-7 sentences): what risk it reduces, the dollar/ROI case, any redundancy with existing controls, and a clear go/no-go with rationale. Be specific and grounded ONLY in the numbers given.";
      const user = `${det}\n\n${p.question ? `Question from the security leader: ${p.question}\n\n` : ""}Write the recommendation.`;
      const out = (await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.3)).trim();
      if (out) return { recommendation: out, simulation: sim, model: OLLAMA_MODEL, offline: false };
    }
  } catch { /* fall through to deterministic */ }
  return { recommendation: det, simulation: sim, model: OLLAMA_MODEL, offline: true };
}
