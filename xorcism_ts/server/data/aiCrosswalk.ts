/**
 * aiCrosswalk.ts — the AI Governance Crosswalk Matrix dataset.
 *
 * Implements the core deliverable of *The Enterprise AI Governance Crosswalk* (Akhawat, 2026): a single
 * integrated table where each row is a governance CAPABILITY an enterprise needs, and the columns show how
 * each instrument addresses it — EU AI Act (legal obligation), NIST AI RMF (reasoning / functions), ISO/IEC
 * 42001 (management-system machinery), and Singapore's Model AI Governance Frameworks (complementary
 * operational guidance). Each row also carries the required evidence, the owning role and a priority.
 *
 * "One set of activities. One body of evidence. Multiple instruments satisfied." Rows are grouped into the
 * 17 governance domains from the source checklist. References are pointers, not verbatim text.
 */

export type Priority = "P1" | "P2" | "P3";

export interface CrosswalkRow {
  id: string;            // stable capability id, e.g. "GA-1"
  domain: string;        // one of the 17 governance domains
  capability: string;    // the governance capability (the row header)
  eu: string;            // EU AI Act reference (article)
  nist: string;          // NIST AI RMF function / subcategory reference
  iso: string;           // ISO/IEC 42001 clause / Annex A control reference
  sg: string;            // Singapore Model AI Governance reference (2020 / GenAI 2024 / Agentic 2026)
  evidence: string;      // the artifact that proves the capability
  owner: string;         // the accountable role
  priority: Priority;
}

// The 17 governance domains (row groups), in the source order.
export const CROSSWALK_DOMAINS: string[] = [
  "Governance & Accountability",
  "Risk Management",
  "Security (AI-specific)",
  "Data Governance",
  "Operations & Lifecycle",
  "Compliance & Legal",
  "Monitoring & Measurement",
  "Human Oversight",
  "Documentation & Evidence",
  "Vendor & Third-Party",
  "Training & Competence",
  "Audit & Assurance",
  "Incident & Continuity",
  "Transparency & Explainability",
  "Bias, Fairness & Ethics",
  "Foundation Models & Agentic AI",
  "Program Foundations",
];

// The instruments crosswalked (column order after the capability column).
export const CROSSWALK_INSTRUMENTS = [
  { key: "eu", label: "EU AI Act", sub: "Legal obligation" },
  { key: "nist", label: "NIST AI RMF", sub: "Reasoning / functions" },
  { key: "iso", label: "ISO/IEC 42001", sub: "Management system" },
  { key: "sg", label: "Singapore Model AI Gov", sub: "Complementary guidance" },
] as const;

// The Crosswalk Matrix — one row per governance capability.
export const CROSSWALK_ROWS: CrosswalkRow[] = [
  // 1. Governance & Accountability
  { id: "GA-1", domain: "Governance & Accountability", capability: "Assign clear AI accountability (governance lead + committee) with a documented mandate",
    eu: "Art. 17 (quality management system)", nist: "GOVERN 1.1 / 2.1", iso: "5.3 / A.3 Internal organization", sg: "2020: Internal governance (1); GenAI: Accountability",
    evidence: "Org chart, committee charter, RACI matrix", owner: "AI Governance Lead", priority: "P1" },
  { id: "GA-2", domain: "Governance & Accountability", capability: "Set AI policy, principles and risk appetite approved by leadership",
    eu: "Art. 17", nist: "GOVERN 1.2 / 4.1", iso: "5.2 / A.2 AI policy", sg: "2020: Internal governance (1); OECD: Accountability",
    evidence: "Approved AI policy, risk-appetite statement", owner: "Executive / Board", priority: "P1" },

  // 2. Risk Management
  { id: "RM-1", domain: "Risk Management", capability: "Operate an AI risk-management process across the lifecycle (identify, assess, treat)",
    eu: "Art. 9 (risk management system)", nist: "MAP 1–5 / MANAGE 1", iso: "6.1 / A.5 Impact assessment", sg: "2020: Operations mgmt (3); Agentic: Assess & bound risks (1)",
    evidence: "AI risk register, risk assessments", owner: "Risk Function", priority: "P1" },
  { id: "RM-2", domain: "Risk Management", capability: "Run risk/impact assessments (incl. fundamental-rights) for high-risk systems",
    eu: "Art. 27 (FRIA) / Art. 9", nist: "MAP 1.1 / 5.1", iso: "6.1.2 / A.5.2", sg: "GenAI: Trusted development (3)",
    evidence: "Completed impact/FRIA assessments", owner: "Risk Function", priority: "P1" },

  // 3. Security (AI-specific)
  { id: "SEC-1", domain: "Security (AI-specific)", capability: "Apply security-by-design + accuracy/robustness/cybersecurity controls to AI systems",
    eu: "Art. 15 (accuracy, robustness, cybersecurity)", nist: "MANAGE 2.1 / MEASURE 2.7", iso: "8.x / A.6 lifecycle", sg: "GenAI: Security (6)",
    evidence: "Security test reports, hardening baselines", owner: "Information Security", priority: "P1" },
  { id: "SEC-2", domain: "Security (AI-specific)", capability: "Red-team / adversarially test models for prompt injection, jailbreaks, poisoning",
    eu: "Art. 15 / Art. 55 (GPAI systemic risk)", nist: "MEASURE 2.7 / MANAGE 2.2", iso: "A.6.2 / 9.1", sg: "GenAI: Testing & assurance (5), Security (6)",
    evidence: "Red-team reports, remediation log", owner: "Information Security", priority: "P2" },

  // 4. Data Governance
  { id: "DG-1", domain: "Data Governance", capability: "Govern training/validation data quality, provenance and lineage",
    eu: "Art. 10 (data and data governance)", nist: "MAP 2.3 / MEASURE 2.2", iso: "A.7 Data for AI systems", sg: "2020: Operations mgmt (3); GenAI: Data (2)",
    evidence: "Data lineage records, dataset datasheets", owner: "Data Governance", priority: "P1" },
  { id: "DG-2", domain: "Data Governance", capability: "Address personal-data and copyright concerns in training data",
    eu: "Art. 10 / GDPR interface", nist: "MAP 4.1 / GOVERN 6.1", iso: "A.7 / 6.1", sg: "GenAI: Data (2)",
    evidence: "DPIA, data-provenance & licensing review", owner: "Compliance / Legal", priority: "P2" },

  // 5. Operations & Lifecycle
  { id: "OP-1", domain: "Operations & Lifecycle", capability: "Define an AI system lifecycle with stage gates and approval to deploy",
    eu: "Art. 17 / Art. 16", nist: "MANAGE 1.1 / MAP 1.5", iso: "8.1 / A.6 AI system lifecycle", sg: "2020: Operations mgmt (3); Agentic: Lifecycle controls (3)",
    evidence: "Lifecycle SOP, system approval forms", owner: "AI System Owner", priority: "P1" },
  { id: "OP-2", domain: "Operations & Lifecycle", capability: "Manage model change, versioning, reproducibility and retirement",
    eu: "Art. 72 (post-market monitoring)", nist: "MANAGE 4.1 / MEASURE 2.4", iso: "8.3 / A.6.2", sg: "2020: Operations mgmt (3)",
    evidence: "Model registry, retirement checklist", owner: "Model Owner", priority: "P2" },

  // 6. Compliance & Legal
  { id: "CL-1", domain: "Compliance & Legal", capability: "Determine EU AI Act applicability and classify each system by risk tier",
    eu: "Art. 6 + Annex III (high-risk) / Art. 5 (prohibited)", nist: "MAP 1.1 / GOVERN 1.1", iso: "4.1 / 6.1", sg: "2020: Human involvement (2)",
    evidence: "Applicability determination, risk-tier register", owner: "Compliance / Legal", priority: "P1" },
  { id: "CL-2", domain: "Compliance & Legal", capability: "Track applicable AI obligations and deadlines (incl. conformity/registration)",
    eu: "Art. 16 / Art. 43 (conformity) / Art. 49 (registration)", nist: "GOVERN 1.1 / COMPLY", iso: "9.1.2 / 6.2", sg: "OECD: Interoperable governance (2.3)",
    evidence: "Obligations register, conformity records", owner: "Compliance / Legal", priority: "P2" },

  // 7. Monitoring & Measurement
  { id: "MM-1", domain: "Monitoring & Measurement", capability: "Continuously monitor AI systems for performance, drift and misuse",
    eu: "Art. 72 (post-market monitoring)", nist: "MEASURE 2.x / MANAGE 4.1", iso: "9.1 / A.6.2", sg: "GenAI: Trusted deployment (3)",
    evidence: "Monitoring dashboards, drift alerts", owner: "AI System Owner", priority: "P2" },
  { id: "MM-2", domain: "Monitoring & Measurement", capability: "Define and report KRIs / KPIs on the AI-governance programme",
    eu: "Art. 17 (QMS effectiveness)", nist: "MEASURE 1.1 / MANAGE 4.3", iso: "9.1 / 9.3 Management review", sg: "OECD: Accountability (1.5)",
    evidence: "Board dashboard, metrics pack", owner: "AI Governance Lead", priority: "P2" },

  // 8. Human Oversight
  { id: "HO-1", domain: "Human Oversight", capability: "Design effective human oversight proportionate to risk (in/over/out-of-the-loop)",
    eu: "Art. 14 (human oversight)", nist: "MANAGE 2.1 / GOVERN 3.2", iso: "A.9 Responsible use", sg: "2020: Human involvement (2); Agentic: Human oversight (2)",
    evidence: "Oversight assessment, intervention procedures", owner: "AI System Owner", priority: "P1" },
  { id: "HO-2", domain: "Human Oversight", capability: "Ensure meaningful human accountability and stop/override for autonomous agents",
    eu: "Art. 14 / Art. 26 (deployer)", nist: "GOVERN 3.2 / MANAGE 2.1", iso: "A.9 / 8.1", sg: "Agentic: Human accountability & oversight (2)",
    evidence: "Agent kill-switch, approval-gate logs", owner: "AI System Owner", priority: "P2" },

  // 9. Documentation & Evidence
  { id: "DE-1", domain: "Documentation & Evidence", capability: "Maintain technical documentation and model/system cards",
    eu: "Art. 11 + Annex IV (technical documentation)", nist: "MAP 1.5 / MEASURE 1.1", iso: "7.5 Documented information / A.6", sg: "GenAI: Transparency 'food labels' (3)",
    evidence: "Technical file, model cards", owner: "Model Owner", priority: "P1" },
  { id: "DE-2", domain: "Documentation & Evidence", capability: "Keep a central, audit-ready evidence repository linking controls to artifacts",
    eu: "Art. 18 (documentation retention)", nist: "GOVERN 1.6 / MANAGE 4.3", iso: "7.5.3 / 9.2", sg: "OECD: Transparency (1.3)",
    evidence: "Evidence repository index", owner: "AI Governance Lead", priority: "P2" },

  // 10. Vendor & Third-Party
  { id: "VT-1", domain: "Vendor & Third-Party", capability: "Assess and contract third-party / supplier AI (models, APIs, data)",
    eu: "Art. 25 (value-chain responsibilities)", nist: "MAP 4.1 / MANAGE 3.1", iso: "A.10 Third-party & supplier", sg: "GenAI: Accountability across value chain (1)",
    evidence: "Vendor assessments, contractual clauses", owner: "Procurement / Risk", priority: "P2" },
  { id: "VT-2", domain: "Vendor & Third-Party", capability: "Obtain and review GPAI/foundation-model provider documentation",
    eu: "Art. 53 + Annex XI/XII (GPAI documentation)", nist: "MAP 4.1 / MEASURE 4.1", iso: "A.10 / A.7", sg: "GenAI: Trusted development (3)",
    evidence: "Provider model cards, usage-policy review", owner: "Procurement / Risk", priority: "P3" },

  // 11. Training & Competence
  { id: "TC-1", domain: "Training & Competence", capability: "Ensure AI literacy for staff dealing with AI systems",
    eu: "Art. 4 (AI literacy) — applies 2 Aug 2026", nist: "GOVERN 2.2 / 3.2", iso: "7.2 Competence / 7.3 Awareness", sg: "Agentic: End-user training (4); OECD: Human capacity (2.4)",
    evidence: "Training records, competency matrix", owner: "HR / L&D", priority: "P1" },
  { id: "TC-2", domain: "Training & Competence", capability: "Role-specific training for oversight, risk and incident roles",
    eu: "Art. 4 / Art. 14", nist: "GOVERN 2.2", iso: "7.2 / A.4 Resources", sg: "2020: Staff training (1)",
    evidence: "Role-based curricula, attendance", owner: "HR / L&D", priority: "P3" },

  // 12. Audit & Assurance
  { id: "AA-1", domain: "Audit & Assurance", capability: "Independent internal audit / assurance of the AI-governance programme",
    eu: "Art. 17 (QMS) / Art. 43 (conformity assessment)", nist: "MEASURE 3.x / GOVERN 4.1", iso: "9.2 Internal audit / 9.3", sg: "GenAI: Testing & assurance (5)",
    evidence: "Audit plan, audit reports, CAPA", owner: "Internal Audit", priority: "P2" },
  { id: "AA-2", domain: "Audit & Assurance", capability: "Third-party testing / certification where required or beneficial",
    eu: "Art. 43 / Art. 44 (certificates)", nist: "MEASURE 3.2", iso: "10.x Improvement / ISO 42006 cert", sg: "GenAI: Third-party testing & assurance (5)",
    evidence: "Certification / external test reports", owner: "AI Governance Lead", priority: "P3" },

  // 13. Incident & Continuity
  { id: "IC-1", domain: "Incident & Continuity", capability: "Stand up AI incident response and serious-incident reporting",
    eu: "Art. 73 (serious incident reporting)", nist: "MANAGE 4.1 / MEASURE 2.6", iso: "A.6.2 / 10.1 Nonconformity", sg: "GenAI: Incident reporting (4)",
    evidence: "AI incident procedure, incident reports", owner: "Information Security", priority: "P1" },
  { id: "IC-2", domain: "Incident & Continuity", capability: "Business-continuity / fallback for AI-system failure or withdrawal",
    eu: "Art. 15 (resilience) / Art. 72", nist: "MANAGE 2.4 / 4.2", iso: "8.1 / A.6.2", sg: "Agentic: Lifecycle controls (3)",
    evidence: "BC/DR plan, fallback runbooks", owner: "AI System Owner", priority: "P3" },

  // 14. Transparency & Explainability
  { id: "TE-1", domain: "Transparency & Explainability", capability: "Meet transparency duties (disclose AI use, label AI-generated content)",
    eu: "Art. 50 (transparency) — applies 2 Aug 2026", nist: "MEASURE 2.9 / GOVERN 5.1", iso: "A.8 Information to stakeholders", sg: "2020: Stakeholder communication (4); GenAI: Content provenance (7)",
    evidence: "Disclosures, content-provenance / watermarking", owner: "Product Owner", priority: "P1" },
  { id: "TE-2", domain: "Transparency & Explainability", capability: "Provide explainability / interpretability appropriate to the use case",
    eu: "Art. 13 (transparency to deployers)", nist: "MEASURE 2.9", iso: "A.8 / A.9", sg: "2020: Stakeholder communication (4); OECD: Transparency (1.3)",
    evidence: "Explainability method, user-facing explanations", owner: "Model Owner", priority: "P2" },

  // 15. Bias, Fairness & Ethics
  { id: "BF-1", domain: "Bias, Fairness & Ethics", capability: "Test for and mitigate bias / unfair outcomes",
    eu: "Art. 10(2)(f–g) / Art. 15", nist: "MEASURE 2.11 / MAP 1.1", iso: "A.5 / A.7", sg: "2020: Operations mgmt — minimise bias (3)",
    evidence: "Fairness test results, mitigation log", owner: "Model Owner", priority: "P2" },
  { id: "BF-2", domain: "Bias, Fairness & Ethics", capability: "Embed ethical principles (human rights, well-being) in AI decisions",
    eu: "Art. 27 (FRIA)", nist: "GOVERN 1.1 / MAP 5.1", iso: "A.5.2 / 5.2", sg: "OECD: Human rights & democratic values (1.2)",
    evidence: "Ethics review, FRIA outcomes", owner: "Risk Function", priority: "P3" },

  // 16. Foundation Models & Agentic AI
  { id: "FA-1", domain: "Foundation Models & Agentic AI", capability: "Govern general-purpose / foundation models (GPAI obligations, evaluation)",
    eu: "Art. 51–55 (GPAI, incl. systemic risk)", nist: "MAP 2.x / MEASURE 2.7", iso: "A.6 / A.10", sg: "GenAI: Trusted development, Safety & alignment R&D (3,8)",
    evidence: "GPAI evaluation, systemic-risk assessment", owner: "AI Governance Lead", priority: "P2" },
  { id: "FA-2", domain: "Foundation Models & Agentic AI", capability: "Bound agentic autonomy, permissions and tool use (least privilege)",
    eu: "Art. 14 / Art. 15", nist: "MANAGE 2.1 / 2.2", iso: "A.6 / A.9", sg: "Agentic: Assess & bound risks (1), Lifecycle controls (3)",
    evidence: "Agent permission model, guardrail config", owner: "AI System Owner", priority: "P2" },

  // 17. Program Foundations
  { id: "PF-1", domain: "Program Foundations", capability: "Discover and inventory all AI systems with owners and risk tier",
    eu: "Art. 16 / Art. 49 (registration)", nist: "MAP 1.1 / GOVERN 1.6", iso: "A.4 Resources / 4.3 scope", sg: "2020: Internal governance (1)",
    evidence: "AI inventory register", owner: "AI Governance Lead", priority: "P1" },
  { id: "PF-2", domain: "Program Foundations", capability: "Adopt a single integrated control framework (this crosswalk) and continual improvement",
    eu: "Art. 17 (QMS) / Art. 61", nist: "GOVERN 1.2 / MANAGE 4.3", iso: "10.2 Continual improvement / 4.4 AIMS", sg: "OECD: Interoperable governance (2.3)",
    evidence: "Crosswalk adoption record, improvement log", owner: "AI Governance Lead", priority: "P1" },
];

/**
 * EU AI Act application timeline after the "Digital Omnibus" (approved 29 Jun 2026): the high-risk regime
 * was deferred, but transparency (Art. 50) and AI-literacy (Art. 4) obligations were NOT deferred.
 */
export const EU_TIMELINE = [
  { date: "2 Aug 2026", item: "AI literacy (Art. 4) and transparency (Art. 50) obligations apply — NOT deferred", status: "active" },
  { date: "2 Dec 2027", item: "High-risk stand-alone Annex III systems (deferred by the Digital Omnibus)", status: "deferred" },
  { date: "2 Aug 2028", item: "High-risk embedded Annex I systems (deferred by the Digital Omnibus)", status: "deferred" },
];

/** The AI Governance Navigator — seven gating questions that scope the applicable obligations. */
export const NAVIGATOR_QUESTIONS = [
  "Are you building or buying the AI system?",
  "Are you using foundation / general-purpose models?",
  "Do you have high-risk systems (EU AI Act Annex III)?",
  "Do you have EU-market exposure?",
  "Are you in a regulated sector?",
  "Will you pursue ISO/IEC 42001 certification?",
  "Have you deployed agentic AI?",
];

/** The 90-day + optimisation roadmap phases from the source guidance. */
export const ROADMAP_PHASES = [
  { phase: "Phase 1 — Foundation", window: "Days 1–30", items: ["Appoint AI Governance Lead", "Establish governance committee", "Run AI-system discovery sweep", "Build initial inventory with owners", "Determine EU AI Act applicability"] },
  { phase: "Phase 2 — Classification & Framework", window: "Days 31–60", items: ["Adopt single control framework (this crosswalk)", "Classify each system by EU risk tier", "Establish risk register", "Create evidence repository", "Build RACI matrix"] },
  { phase: "Phase 3 — Core Controls", window: "Days 61–90", items: ["Risk/impact assessments for high-risk systems", "Implement human oversight", "Establish logging / traceability", "Stand up incident response", "Implement 2026 transparency obligations"] },
  { phase: "Phase 4 — Depth & Optimisation", window: "Months 4–12", items: ["Implement monitoring / measurement", "Conduct red-teaming", "Complete vendor assessments", "Pursue ISO certification if planned"] },
];
