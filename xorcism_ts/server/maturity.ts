/**
 * maturity.ts — aggregates the tenant's maturity-assessment results (SOC-CMM, CTI-CMM, MITRE INFORM,
 * NIST CSF 2.0) into a single 0–100 maturity index and turns it into a signed EnterpriseRiskScore
 * credit: the higher a program's demonstrated security maturity, the lower its enterprise risk.
 *
 * It is a pure credit (0 → −MAX_CREDIT), so a mature program lowers the score and the absence of any
 * maturity assessment is neutral (no penalty for not having assessed). Each model that has a scored
 * assessment for the tenant contributes its overall score normalised to 0–100; the index is their
 * mean. Wired into riskscore.ts as the "maturity" driver.
 */
import { soccmmInventory } from "./soccmm";
import { cticmmDashboard } from "./cticmm";
import { informDashboard } from "./inform";
import { csfMaturityInventory } from "./csfmaturity";
import { aisvsDashboard } from "./aisvs";
import { sprsAssessment } from "./sprs";

/**
 * Maximum enterprise-risk reduction earned at 100% maturity. Configurable via the
 * XORCISM_MATURITY_MAX_CREDIT environment variable (default 40), clamped to [0, 100] so it can
 * shift the EnterpriseRiskScore without dominating it. Read at call time so it can be tuned per
 * deployment without a rebuild.
 */
function maxCredit(): number {
  const raw = Number(process.env.XORCISM_MATURITY_MAX_CREDIT);
  return Number.isFinite(raw) ? Math.max(0, Math.min(100, Math.round(raw))) : 40;
}

export interface MaturitySource { key: string; label: string; pct: number }
export interface MaturityAssurance { term: number; index: number | null; sources: MaturitySource[] }

/** The tenant's 0–100 maturity index across all assessed models + the risk credit it earns. */
export function maturityAssurance(tenant: number | null): MaturityAssurance {
  const sources: MaturitySource[] = [];
  const add = (key: string, label: string, pct: number | null | undefined): void => {
    if (pct != null && Number.isFinite(Number(pct))) {
      sources.push({ key, label, pct: Math.max(0, Math.min(100, Math.round(Number(pct)))) });
    }
  };
  // SOC-CMM: overall maturity 0–5 (XINCIDENT).  CTI-CMM: avg 0–3.  INFORM: already %.  CSF 2.0: %.
  try { const s = soccmmInventory(tenant)?.summary; if (s?.overallMaturity != null) add("soccmm", "SOC-CMM", (s.overallMaturity / 5) * 100); } catch { /* not assessed */ }
  try { const s = cticmmDashboard(tenant)?.summary; if (s?.avgMaturity != null) add("cticmm", "CTI-CMM", (s.avgMaturity / 3) * 100); } catch { /* not assessed */ }
  try { const s = informDashboard(tenant)?.summary; if (s?.avgScore != null) add("inform", "MITRE INFORM", s.avgScore); } catch { /* not assessed */ }
  try { const s = csfMaturityInventory(tenant)?.summary; if (s?.overallCurrent != null) add("csf", "NIST CSF 2.0", s.maturityScore ?? (s.overallCurrent / 5) * 100); } catch { /* not assessed */ }
  // OWASP AISVS: weighted verification % — only when at least one assessment has been scored.
  try { const d = aisvsDashboard(tenant); if (d?.assessments?.some((a) => a.answered > 0)) add("aisvs", "OWASP AISVS", d.summary.avgVerification); } catch { /* not assessed */ }
  // SPRS / NIST 800-171: share of assessable requirements met — only when the self-assessment has begun.
  try { const s = sprsAssessment(tenant)?.summary; if (s && (s.met + s.partial + s.poam + s.na) > 0) add("sprs", "SPRS / 800-171", s.metPct); } catch { /* not assessed */ }

  if (!sources.length) return { term: 0, index: null, sources: [] };
  const index = Math.round(sources.reduce((n, x) => n + x.pct, 0) / sources.length);
  const term = -Math.round((index / 100) * maxCredit()); // credit (0 → −MAX); higher maturity ⇒ lower risk
  return { term, index, sources };
}
