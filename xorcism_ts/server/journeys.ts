/**
 * journeys.ts — Guided compliance-journey wizard (XCOMPLIANCE backend).
 *
 * A curated catalogue of framework "journeys" (ISO 27001/42001, SOC 2, NIST CSF/800-53, NIS2, DORA,
 * EU CRA, MiCA, FedRAMP, GDPR…). Each journey is a phased, ordered checklist of concrete steps; every
 * step deep-links into the XORCISM module that actually does the work (risk register, controls,
 * policies, audits, evidence, SCA/SBOM, incidents…). Starting a journey materializes its steps into
 * COMPLIANCEJOURNEYSTEP (per-tenant), tracks status/progress, and optionally spawns a
 * COMPLIANCEASSESSMENT against the existing FRAMEWORK model.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { JOURNEY_FR } from "./journeys_fr";

/** Localize a catalogue string to the request language (currently fr; others fall back to English).
 *  Keyed by the exact English source, so already-materialized journey steps localize on read too. */
function tx(s: string, lang = "en"): string { return lang === "fr" ? (JOURNEY_FR[s] ?? s) : s; }

// ── deep-link targets (existing pages / explorer tables) ───────────────────────
const L = {
  scope: "/?db=XCOMPLIANCE&table=PERIMETER",
  context: "/?db=XORCISM&table=ORGANISATION",
  riskEbios: "/ebios",
  riskNist: "/nist-800-30",
  riskReg: "/risk-register",
  controls53: "/control-management",
  controlsTable: "/?db=XORCISM&table=CONTROL",
  config: "/configuration-management",
  policies: "/policy-management",
  assess: "/compliance-management",
  assessmentTable: "/?db=XCOMPLIANCE&table=COMPLIANCEASSESSMENT",
  evidence: "/?db=XCOMPLIANCE&table=EVIDENCE",
  trust: "/trust-center",
  incident: "/incident-management",
  sla: "/incident-sla",
  sca: "/sca",
  awareness: "/security-awareness",
  identity: "/identities",
  assets: "/asset-management",
  vuln: "/vulnerability-management",
  patch: "/patch-management",
  crisis: "/crisis-management",
  monitoring: "/asset-monitoring",
  fairmam: "/fair-mam",
  pqcmm: "/pqcmm",
  questionnaire: "/?db=XCOMPLIANCE&table=QUESTIONNAIRE",
  regulator: "/?db=XCOMPLIANCE&table=NOTIFICATIONREGULATOR",
  aiguard: "/ai-guardrails",
  agents: "/agents",
  tprm: "/tprm",
  aicmControls: "/?db=XORCISM&table=CONTROL",
  cra: "/cra-compliance",
  threatModel: "/threat-model",
  devsecops: "/devsecops",
  pentest: "/pentest",
  regIncident: "/reg-incident-reporting",
  regCalendar: "/reg-calendar",
  ot: "/ot-security",
  cloud: "/cloud-security",
  backup: "/?db=XORCISM&table=ASSET",
  soc: "/soc",
} as const;

export type StepT = { title: string; desc: string; link?: string };
export type PhaseT = { name: string; steps: StepT[] };
export interface FrameworkT {
  key: string; name: string; provider: string;
  kind: "Certification" | "Attestation" | "Regulation" | "Framework" | "Authorization";
  jurisdiction: string; summary: string; effort: string; phases: PhaseT[];
}

const st = (title: string, desc: string, link?: string): StepT => ({ title, desc, link });

// Shared closing phase used by certification-style journeys.
const auditPhase = (cert: string): PhaseT => ({
  name: "Audit & Certification", steps: [
    st("Internal audit", "Plan and run an internal audit of the management system; record findings and corrective actions.", L.assess),
    st("Management review", "Hold a management review of objectives, risks, incidents, audit results and improvement actions.", L.assess),
    st("Corrective actions & readiness", "Close non-conformities, gather the evidence pack and confirm audit readiness.", L.evidence),
    st(cert, "Engage the certification body / auditor and complete the formal assessment.", L.assess),
  ],
});

// ── the framework journey catalogue ────────────────────────────────────────────
export const FRAMEWORKS: FrameworkT[] = [
  {
    key: "iso27001", name: "ISO/IEC 27001:2022", provider: "ISO/IEC", kind: "Certification", jurisdiction: "International",
    summary: "Information Security Management System (ISMS). The certifiable baseline for security governance, risk treatment and Annex A controls.",
    effort: "6–12 months",
    phases: [
      { name: "Scope & Context", steps: [
        st("Define the ISMS scope", "Document the boundaries: business units, locations, assets and the perimeter the ISMS covers.", L.scope),
        st("Understand context & interested parties", "Capture internal/external issues and the requirements of interested parties (clause 4).", L.context),
        st("Build the asset inventory", "Establish the inventory of information assets in scope with owners and criticality.", L.assets),
      ]},
      { name: "Leadership & Governance", steps: [
        st("Secure leadership commitment", "Obtain top-management commitment, assign ISMS roles and responsibilities (clause 5).", L.identity),
        st("Set the information-security policy", "Approve the top-level information-security policy and supporting policies.", L.policies),
        st("Set objectives & plan", "Define measurable security objectives and the plan to achieve them (clause 6).", L.riskReg),
      ]},
      { name: "Risk Management", steps: [
        st("Risk assessment", "Run an information-security risk assessment (EBIOS RM or NIST 800-30) to identify and rate risks.", L.riskEbios),
        st("Risk treatment plan", "Decide treatment (mitigate/accept/transfer/avoid) and record it in the risk register.", L.riskReg),
        st("Statement of Applicability (SoA)", "Justify the applicability of the 93 Annex A controls and link them to risks.", L.controlsTable),
      ]},
      { name: "Controls Implementation", steps: [
        st("Implement Annex A controls", "Implement the selected Annex A (organizational/people/physical/technological) controls.", L.controls53),
        st("Harden configurations", "Apply secure baselines and verify them (configuration management).", L.config),
        st("Security awareness", "Roll out awareness training and phishing simulations for staff.", L.awareness),
        st("Vulnerability & patch management", "Operate vulnerability and patch management with risk-based SLAs.", L.vuln),
      ]},
      { name: "Operations & Evidence", steps: [
        st("Operate & monitor", "Run monitoring/logging and keep the ISMS operating; collect operational records.", L.monitoring),
        st("Incident management", "Operate the incident process and meet response SLAs.", L.incident),
        st("Collect evidence", "Gather evidence for each control to support the audit.", L.evidence),
      ]},
      auditPhase("Stage 1 & Stage 2 certification audit"),
    ],
  },
  {
    key: "iso42001", name: "ISO/IEC 42001:2023", provider: "ISO/IEC", kind: "Certification", jurisdiction: "International",
    summary: "AI Management System (AIMS). The certifiable standard for governing the responsible development and use of AI systems — a full walkthrough of clauses 4–10 plus the Annex A control objectives (A.2–A.10).",
    effort: "6–12 months",
    phases: [
      { name: "4 · Context of the organization", steps: [
        st("4.1 Organization & its context", "Capture the internal and external issues relevant to the AIMS, including the organization's role(s) — AI provider, developer, deployer or user.", L.context),
        st("4.2 Needs of interested parties", "Identify interested parties (regulators, customers, users, affected individuals, society) and their relevant needs and expectations for the AI systems.", L.context),
        st("4.3 Scope of the AIMS", "Determine and document the boundaries and applicability of the AI management system and the AI systems it covers.", L.scope),
        st("4.4 AI management system", "Establish, implement, maintain and continually improve the AIMS and its processes.", L.assess),
        st("Inventory the AI systems", "Catalogue the AI systems / models / agents in scope — purpose, data, role and owner (supports A.4.2 / A.6.2).", L.agents),
      ]},
      { name: "5 · Leadership · AI policy (A.2, A.3)", steps: [
        st("5.1 Leadership & commitment", "Secure top-management commitment to the AIMS and the responsible use of AI, integrated with business processes.", L.identity),
        st("5.2 AI policy (A.2.2–A.2.4)", "Establish and approve the AI policy, align it with other organizational policies, and review it at planned intervals.", L.policies),
        st("5.3 Roles & responsibilities (A.3.2–A.3.3)", "Assign and communicate AIMS roles, responsibilities and authorities, and put in place a process to report concerns.", L.identity),
      ]},
      { name: "6 · Planning — AI risk & impact (A.5)", steps: [
        st("6.1.1 Risks & opportunities", "Plan actions to address the risks and opportunities relevant to the AIMS and its intended outcomes.", L.riskReg),
        st("6.1.2 AI risk assessment", "Define and run a repeatable AI risk assessment process (safety, fairness/bias, robustness, transparency, privacy, security).", L.riskReg),
        st("6.1.3 AI risk treatment & SoA", "Select Annex A controls to treat the assessed risks and produce the Statement of Applicability (justify each control).", L.controlsTable),
        st("6.1.4 AI system impact assessment (A.5)", "Assess the potential impacts of AI systems on individuals, groups and society, and document the results.", L.assess),
        st("6.2 AI objectives & planning", "Set measurable AI objectives and plan how to achieve them (resources, responsibilities, timing, evaluation).", L.riskReg),
        st("6.3 Planning of changes", "Plan and control changes to the AIMS in a structured way.", L.config),
      ]},
      { name: "7 · Support & resources (A.4)", steps: [
        st("7.1 Resources (A.4.2–A.4.6)", "Identify and document the resources for AI systems — data, tooling, system/computing and human resources.", L.assets),
        st("7.2 Competence", "Determine and ensure the competence of people whose work affects AIMS performance.", L.awareness),
        st("7.3 Awareness", "Make staff aware of the AI policy, their AIMS contribution and the implications of not conforming.", L.awareness),
        st("7.4 Communication", "Determine the internal and external communications relevant to the AIMS.", L.policies),
        st("7.5 Documented information", "Create, update and control the documented information the AIMS requires.", L.evidence),
      ]},
      { name: "Annex A · AI lifecycle controls (A.6–A.10)", steps: [
        st("A.6 AI system life cycle", "Set management direction for responsible AI development and apply lifecycle controls — requirements, design & development documentation, verification & validation, deployment, operation & monitoring, technical documentation and event logging.", L.controls53),
        st("A.7 Data for AI systems", "Govern the data used to develop and operate AI — acquisition, quality, provenance and preparation.", L.sca),
        st("A.8 Information for interested parties", "Provide system documentation and user information, external reporting and incident communication for the AI systems.", L.trust),
        st("A.9 Responsible use of AI", "Establish processes and objectives for the responsible use of AI and define the intended use of each system.", L.aiguard),
        st("A.10 Third-party & customer relationships", "Allocate responsibilities and manage AI suppliers and customers across the value chain.", L.tprm),
        st("Map to AI threats", "Reference the Agentic AI Attack Matrix / SAIF for AI-specific threats and mitigations.", "/a3m"),
      ]},
      { name: "8 · Operation", steps: [
        st("8.1 Operational planning & control", "Plan, implement and control the processes needed to meet AIMS requirements and the actions from clause 6.", L.config),
        st("8.2 AI risk assessment (operational)", "Perform AI risk assessments at planned intervals and when significant changes occur.", L.riskReg),
        st("8.3 AI risk treatment (operational)", "Implement the AI risk treatment plan and keep documented results.", L.controls53),
        st("8.4 AI system impact assessment (operational)", "Perform AI system impact assessments at planned intervals and on change.", L.assess),
        st("Runtime AI guardrails & oversight", "Operate runtime guardrails and human oversight over the AI systems in production.", L.aiguard),
      ]},
      { name: "9 · Performance evaluation", steps: [
        st("9.1 Monitoring, measurement & analysis", "Monitor, measure, analyse and evaluate the AIMS and the performance of the AI systems (incl. drift and incidents).", L.monitoring),
        st("9.2 Internal audit", "Plan and run internal audits of the AIMS at planned intervals; record results and corrective actions.", L.assess),
        st("9.3 Management review", "Hold a management review of the AIMS (status, objectives, risks, incidents, audit results, improvements).", L.assess),
      ]},
      { name: "10 · Improvement & certification", steps: [
        st("10.1 Continual improvement", "Continually improve the suitability, adequacy and effectiveness of the AIMS.", L.assess),
        st("10.2 Nonconformity & corrective action", "React to nonconformities, correct them and act to prevent recurrence.", L.incident),
        st("Evidence pack & readiness", "Assemble the AIMS evidence pack (policies, risk & impact assessments, SoA, records) and confirm audit readiness.", L.evidence),
        st("AIMS certification audit", "Engage the certification body and complete the Stage 1 & Stage 2 assessment.", L.assess),
      ]},
    ],
  },
  {
    key: "nistairmf", name: "NIST AI RMF 1.0", provider: "NIST (AI 100-1)", kind: "Framework", jurisdiction: "United States",
    summary: "The NIST AI Risk Management Framework — a voluntary framework to govern, map, measure and manage the risks of AI systems and build trustworthy AI. Its four functions (GOVERN, MAP, MEASURE, MANAGE) and 72 subcategories are imported as a control catalogue (import_nist_ai_rmf.py); this journey walks them function by function.",
    effort: "3–9 months",
    phases: [
      { name: "GOVERN — culture & accountability", steps: [
        st("Stand up AI governance & policy", "Put AI risk policies, roles, accountability and training in place; integrate the trustworthy-AI characteristics into how you work (GOVERN 1–4).", L.policies),
        st("Inventory AI systems", "Establish and resource a mechanism to inventory AI systems and manage their lifecycle, incl. safe decommissioning (GOVERN 1.6/1.7).", L.identity),
        st("Engagement & third-party AI", "Set processes for feedback from external AI actors and to manage third-party software/data supply-chain AI risk (GOVERN 5–6).", L.tprm),
      ]},
      { name: "MAP — context & risk identification", steps: [
        st("Establish context", "Document intended purpose, users, laws/norms, mission, business value and risk tolerances for each AI system (MAP 1).", L.context),
        st("Categorize the AI system", "Define the task/method, knowledge limits, human oversight and TEVV considerations (MAP 2–3).", L.assess),
        st("Map risks, benefits & impacts", "Map component and third-party risks, and characterize impacts to individuals, groups and society (MAP 4–5).", L.riskReg),
      ]},
      { name: "MEASURE — assess & track", steps: [
        st("Select methods & metrics", "Choose measurement approaches/metrics for the most significant AI risks; involve independent assessors (MEASURE 1).", L.assess),
        st("Evaluate trustworthy characteristics", "Test for validity, safety, security/resilience, transparency, explainability, privacy, fairness/bias and environmental impact (MEASURE 2).", L.aiguard),
        st("Track risks & gather feedback", "Track existing/emergent AI risks over time and gather feedback on measurement efficacy (MEASURE 3–4).", L.monitoring),
      ]},
      { name: "MANAGE — prioritize & act", steps: [
        st("Prioritize & respond to risks", "Decide go/no-go, prioritize treatment, plan responses (mitigate/transfer/avoid/accept) and document residual risk (MANAGE 1).", L.riskReg),
        st("Plan benefits & deactivation", "Maximize benefits, sustain value, recover from unknown risks, and be able to deactivate misbehaving AI (MANAGE 2).", L.crisis),
        st("Manage third-party & monitor post-deployment", "Monitor third-party resources and pre-trained models; run post-deployment monitoring, incident response and continual improvement (MANAGE 3–4).", L.incident),
      ]},
    ],
  },
  {
    key: "hds", name: "HDS (Hébergeur de Données de Santé)", provider: "ANS (France)", kind: "Certification", jurisdiction: "France",
    summary: "The French mandatory certification for hosting personal health data (Art. L.1111-8 CSP). HDS builds on ISO/IEC 27001 + ISO/IEC 20000-1 and adds health-data-specific requirements across 6 certified hosting activities. Import the HDS catalogue (import_hds.py) to track the requirements as controls.",
    effort: "9–15 months",
    phases: [
      { name: "Scope & certified activities", steps: [
        st("Define the HDS scope & activities", "Determine which of the 6 HDS hosting activities you perform and the systems / health data in scope.", L.scope),
        st("Inventory health-data assets & flows", "Catalogue the health-data assets, where they are hosted and how they flow.", L.assets),
      ]},
      { name: "ISO 27001 + 20000-1 foundation", steps: [
        st("ISO/IEC 27001 ISMS over the hosting scope", "HDS requires an ISO/IEC 27001 certified ISMS covering the health-data hosting scope.", L.controls53),
        st("ISO/IEC 20000-1 service management", "Operate IT service management for the hosting service.", L.assess),
      ]},
      { name: "Health-data requirements", steps: [
        st("EU localisation & medical confidentiality", "Keep health data in the EU/EEA; enforce medical-secret confidentiality and need-to-know access.", L.policies),
        st("GDPR Art. 28 processing agreement & DPO", "Sign the controller processing agreement, appoint a DPO and ensure GDPR compliance.", L.policies),
        st("Reversibility & secure destruction", "Document return / migration of health data and certified destruction at end of contract.", L.evidence),
        st("Subcontractors & traceability", "Flow HDS obligations down to subcontractors; log all access to health data.", L.tprm),
      ]},
      auditPhase("HDS certification audit (accredited body)"),
    ],
  },
  {
    key: "tisax", name: "TISAX (VDA-ISA)", provider: "ENX / VDA", kind: "Attestation", jurisdiction: "Automotive (global)",
    summary: "The automotive-industry information-security assessment, based on the VDA-ISA catalogue and performed at assessment level AL1 / AL2 / AL3, leading to shareable TISAX labels on the ENX portal. Import the VDA-ISA catalogue (import_tisax.py).",
    effort: "4–9 months",
    phases: [
      { name: "Scope & assessment level", steps: [
        st("Define scope, locations & objectives", "Pick the assessment objectives (information security, prototype protection, data protection) and the level (AL1/AL2/AL3).", L.scope),
        st("VDA-ISA self-assessment", "Complete the VDA-ISA self-assessment with its 0-5 maturity scale.", L.assess),
      ]},
      { name: "Information security (VDA-ISA)", steps: [
        st("Implement the ISA control areas", "Policies & organization, HR, physical security, IT/cyber security, supplier relationships, compliance.", L.controls53),
        st("Identity, access & cryptography", "Identity / access management and cryptographic key management.", L.identity),
        st("Operations, network & malware protection", "Logging/monitoring, network segmentation, vulnerability & patch management.", L.vuln),
      ]},
      { name: "Prototype & data protection", steps: [
        st("Prototype protection (if in scope)", "Physical & organizational protection of prototypes, vehicles, parts and events / shoots.", L.policies),
        st("Data protection (GDPR Art. 28)", "Processing on behalf and handling of special categories of personal data.", L.policies),
      ]},
      { name: "Assessment & label", steps: [
        st("Plausibility check / on-site audit", "AL2 remote evidence review or AL3 on-site audit by a TISAX auditor.", L.assess),
        st("Obtain & share the TISAX label", "Receive the label on the ENX portal and share it with your partners.", L.trust),
      ]},
    ],
  },
  {
    key: "euaiact", name: "EU AI Act (Regulation (EU) 2024/1689)", provider: "European Union", kind: "Regulation", jurisdiction: "European Union",
    summary: "The EU Artificial Intelligence Act — the world's first horizontal, risk-based AI regulation. Obligations scale with risk: prohibited practices (Art. 5), high-risk AI systems (Art. 6 + Annex III) carrying the heaviest duties, transparency-risk systems (Art. 50) and minimal-risk. This journey walks a provider or deployer from AI governance and an AI-system inventory through risk classification, the Art. 9 risk-management system, technical documentation and the ancillary obligations (conformity assessment, CE marking, EU-database registration, post-market monitoring and serious-incident reporting). Import the EU AI Act control catalogue to track the obligations as controls.",
    effort: "9–18 months (phased: GPAI Aug 2025 · high-risk Aug 2026/2027)",
    phases: [
      { name: "Gouvernance & AI literacy", steps: [
        st("Establish AI governance & roles", "Stand up an AI governance body, assign accountability and determine your role under the Act (provider / deployer / importer / distributor).", L.identity),
        st("AI literacy (Art. 4)", "Ensure staff who operate or oversee AI systems have a sufficient level of AI literacy.", L.awareness),
        st("Quality management system (Art. 17)", "For high-risk AI, put in place the QMS covering processes, change control and responsibilities.", L.policies),
      ]},
      { name: "Cartographie des systèmes d'IA", steps: [
        st("Inventory AI systems & models", "Catalogue every AI system / model / agent in use or placed on the market, with purpose, data, owner and your role under the Act.", L.identity),
        st("Identify GPAI & third-party AI", "Flag general-purpose AI models (Art. 53–55) and AI obtained from third parties; track third-party AI risk in TPRM.", L.tprm),
      ]},
      { name: "Classification du risque", steps: [
        st("Screen for prohibited practices (Art. 5)", "Verify no AI system performs a prohibited practice (social scoring, manipulative techniques, untargeted facial-image scraping, etc.).", L.assess),
        st("Classify high-risk systems (Art. 6 + Annex III)", "Determine which systems are high-risk (Annex III use-cases or safety components) — these carry the full obligation set.", L.assess),
        st("Transparency-risk & minimal-risk (Art. 50)", "Identify limited-risk systems requiring transparency (chatbots, emotion recognition, deepfakes) and the minimal-risk remainder.", L.assess),
      ]},
      { name: "Gérer les risques", steps: [
        st("Risk-management system (Art. 9)", "Run the continuous, iterative risk-management system across the AI lifecycle; record risks in the register.", L.riskReg),
        st("Data & data governance (Art. 10)", "Govern training/validation/test data quality, representativeness and bias examination.", L.evidence),
        st("Fundamental-rights impact assessment (Art. 27)", "Where required (deployers of certain high-risk systems), perform the FRIA on affected persons.", L.assess),
        st("Map AI-specific threats", "Reference the Agentic AI Attack Matrix / SAIF and AI guardrails for AI-specific threats and mitigations.", "/a3m"),
      ]},
      { name: "Documenter (Art. 11–15)", steps: [
        st("Technical documentation (Art. 11 + Annex IV)", "Compile the technical documentation demonstrating conformity before placing the system on the market.", L.evidence),
        st("Record-keeping & logging (Art. 12)", "Ensure automatic logging of events over the system's lifetime for traceability.", L.monitoring),
        st("Transparency & instructions for use (Art. 13)", "Provide deployers with clear instructions and the information needed for compliant operation.", L.policies),
        st("Human oversight (Art. 14)", "Design and document effective human-oversight measures.", L.controls53),
        st("Accuracy, robustness & cybersecurity (Art. 15)", "Demonstrate appropriate accuracy, robustness and cybersecurity; harden and test the system.", L.controls53),
      ]},
      { name: "Obligations annexes", steps: [
        st("Conformity assessment (Art. 43)", "Carry out the applicable conformity-assessment procedure for high-risk systems.", L.assess),
        st("EU declaration of conformity & CE marking (Art. 47–48)", "Draw up the EU declaration of conformity and affix the CE marking.", L.evidence),
        st("Register in the EU database (Art. 49 / 71)", "Register the high-risk AI system (and yourself) in the EU database before placing it on the market.", L.regulator),
        st("Post-market monitoring (Art. 72)", "Operate a post-market monitoring system to collect and analyse performance data.", L.monitoring),
        st("Serious-incident reporting (Art. 73)", "Wire the reporting of serious incidents and malfunctioning to the market-surveillance authority.", L.regulator),
      ]},
    ],
  },
  {
    key: "aisecurity", name: "AI Security Management (AI-TRiSM)", provider: "XORCISM — AI Trust, Risk & Security Management", kind: "Framework", jurisdiction: "International",
    summary: "An end-to-end program to secure and govern AI: stand up AI governance and policy, inventory your AI systems and the non-human identities behind them, comply with the AI standards (ISO/IEC 42001 + the CSA AI Controls Matrix), assess third-party AI with the AICM AI-CAIQ questionnaire, and continuously monitor and guardrail AI at runtime via the XOR agent. Spans governance → identities → compliance → third-party → runtime assurance.",
    effort: "6–12 months",
    phases: [
      { name: "Govern", steps: [
        st("Establish AI governance & roles", "Set up the AI governance body, accountability (RACI) and a named AI security/ethics owner.", L.identity),
        st("AI policy framework", "Adopt the AI policies (responsible AI, acceptable use, data, transparency, human oversight) — 10 AIMS policies are seedable.", L.policies),
        st("AI risk appetite & register", "Define AI risk appetite and open an AI risk register (bias, safety, robustness, privacy, security, misuse).", L.riskReg),
      ]},
      { name: "Inventory & Identities", steps: [
        st("Inventory AI systems, models & agents", "Catalogue every AI system / model / agent, its purpose, data and owner.", L.identity),
        st("Govern non-human identities (NHI)", "Inventory and constrain the service accounts, API keys and agent identities that run or serve AI — least privilege, rotation, lifecycle.", L.identity),
        st("Map AI assets & data flows", "Map the assets, datasets and interconnections supporting the AI systems in scope.", L.assets),
      ]},
      { name: "Comply with the AI standards", steps: [
        st("ISO/IEC 42001 AI Management System", "Run the AIMS clauses & Annex A controls (scope, leadership, AI risk & impact assessment, controls, evidence) — start the dedicated ISO 42001 journey too.", L.assess),
        st("CSA AI Controls Matrix (AICM)", "Implement and track the 247 AICM controls (18 domains) — imported as a framework with built-in mappings to ISO 42001, the EU AI Act and BSI AI C4.", L.aicmControls),
        st("AI system impact assessment", "Run the AI impact assessment on individuals and society (and a DPIA where personal data is processed).", L.assess),
      ]},
      { name: "Third-party AI risk (TPRM)", steps: [
        st("Send the AICM AI-CAIQ questionnaire", "Assess AI vendors and model providers with the CSA AI-CAIQ (320 questions, imported) as a TPRM questionnaire.", L.tprm),
        st("Score & track vendor AI risk", "Collect responses, score third-party AI risk, and set vendor criticality and due dates.", L.tprm),
        st("Supply-chain & model provenance", "Track the AI / software supply chain and model provenance (SBOM, components).", L.sca),
      ]},
      { name: "Monitor & Guardrail (runtime, via the agent)", steps: [
        st("Deploy AI guardrails", "Stand up the AI guardrails (prompt-injection, data-leak, jailbreak, tool-abuse) and review guardrail coverage & violations.", L.aiguard),
        st("Task the XOR agent", "Use the XOR endpoint agent to discover AI usage on hosts and run AI-guardrail / log-hunt scans — 100% local.", L.agents),
        st("Monitor AI assets", "Continuously monitor the availability, health and drift of AI endpoints and services.", L.monitoring),
        st("Detect & respond to AI incidents", "Operate detection and incident response for AI-specific events (misuse, model compromise, data exposure).", L.incident),
        st("AI usage awareness & training", "Roll out AI acceptable-use awareness and role-based training.", L.awareness),
      ]},
      { name: "Assure & Improve", steps: [
        st("Evidence & continuous assurance", "Gather evidence per control and prove the AI controls continuously from live telemetry.", L.evidence),
        st("Publish the AI trust posture", "Share your AI governance & security posture via the Trust Center.", L.trust),
        st("Review & improve", "Review the AIMS, AICM coverage, incidents and metrics; drive corrective actions and re-assess.", L.assess),
      ]},
    ],
  },
  {
    key: "soc2", name: "SOC 2 (Type II)", provider: "AICPA", kind: "Attestation", jurisdiction: "United States",
    summary: "AICPA Trust Services Criteria attestation covering the Common Criteria (CC1–CC9) plus optional Availability, Confidentiality, Processing Integrity and Privacy categories. The de-facto report SaaS vendors provide to customers; Type II covers a 3–12 month operating period.",
    effort: "3–9 months + observation window",
    phases: [
      { name: "Scope & system description", steps: [
        st("Choose report type & period", "Decide Type I (design at a point in time) vs Type II (operating effectiveness over a 3–12 month window) and set the period.", L.scope),
        st("Select Trust Services Categories", "Security (the Common Criteria) is mandatory; add Availability, Confidentiality, Processing Integrity and/or Privacy as relevant.", L.scope),
        st("Define the system boundary", "Scope the system: infrastructure, software, people, procedures and data that are in and out of scope.", L.assets),
        st("Identify subservice organizations", "List subservice organizations and choose carve-out vs inclusive method; map complementary user-entity controls.", L.tprm),
        st("Write the system description", "Draft the section III system description: services, components, boundaries, commitments and data flows.", L.trust),
      ]},
      { name: "CC1–CC2 · Control environment & communication", steps: [
        st("CC1 Control environment", "Establish integrity and ethics, board / owner oversight, organisational structure, authority and accountability (COSO).", L.identity),
        st("CC1 HR & competence", "Run background checks, role definitions, onboarding, performance and disciplinary processes for personnel.", L.identity),
        st("CC2 Communication & information", "Define internal and external communication of objectives, responsibilities and security commitments.", L.policies),
      ]},
      { name: "CC3–CC4 · Risk assessment & monitoring", steps: [
        st("CC3 Risk assessment", "Set objectives, identify and analyse risks (including fraud) and assess the impact of significant change.", L.riskReg),
        st("CC4 Monitoring of controls", "Perform ongoing and separate evaluations and communicate control deficiencies to the right owners.", L.monitoring),
      ]},
      { name: "CC5–CC6 · Control activities & access", steps: [
        st("CC5 Control activities", "Select and develop control activities and technology general controls that mitigate risk to objectives.", L.controls53),
        st("CC6 Logical access", "Provision and deprovision access, enforce least privilege, authentication and MFA across systems.", L.identity),
        st("CC6 Encryption & credentials", "Protect data at rest and in transit, and manage keys and credential storage.", L.config),
        st("CC6 Physical access", "Restrict physical access to facilities and assets and manage media handling and disposal.", L.assets),
      ]},
      { name: "CC7–CC9 · Operations, change & risk mitigation", steps: [
        st("CC7 Detection & monitoring", "Detect and monitor for vulnerabilities and anomalies across the production environment.", L.vuln),
        st("CC7 Incident response", "Operate incident detection, response, recovery and customer-communication processes.", L.incident),
        st("CC8 Change management", "Authorise, design, test and approve changes to infrastructure, data and software.", L.config),
        st("CC9 Risk mitigation & BCP", "Mitigate business-disruption risk and recover operations after a disruption.", L.crisis),
        st("CC9 Vendor & business-partner risk", "Assess and manage risks arising from vendors and business partners on an ongoing basis.", L.tprm),
      ]},
      { name: "Additional category criteria", steps: [
        st("Availability (A1)", "Manage capacity, environmental protections, backup and recovery to meet availability commitments.", L.crisis),
        st("Confidentiality (C1)", "Identify, protect and dispose of confidential information per commitments and requirements.", L.assets),
        st("Processing Integrity (PI1)", "Ensure processing is complete, valid, accurate, timely and authorised.", L.config),
        st("Privacy (P1–P8)", "Operate notice, choice and consent, collection, use / retention / disposal, access, disclosure, quality and monitoring controls.", "/privacy"),
      ]},
      { name: "Operate controls & build the evidence trail", steps: [
        st("Publish the SOC 2 policy set", "Publish the policies the criteria expect: access, change, incident, risk, vendor, BCP and data classification.", L.policies),
        st("Security awareness", "Run recurring security awareness training and track completion (CC1 / CC2).", L.awareness),
        st("Collect evidence each period", "Capture tickets, logs, approvals and reviews continuously across the observation window.", L.evidence),
        st("Subservice & vendor monitoring", "Collect and review subservice SOC reports and vendor evidence throughout the period.", L.tprm),
      ]},
      { name: "Readiness, Type I & Type II examination", steps: [
        st("Readiness / gap assessment", "Run a readiness assessment against the selected criteria and remediate gaps before the audit.", L.assess),
        st("SOC 2 Type I report", "Optionally obtain a Type I report attesting that controls are suitably designed at a point in time.", L.assess),
        st("Operate across the observation window", "Run the controls consistently for the full Type II period (typically 3–12 months).", L.monitoring),
        st("Type II examination by a CPA", "Engage a licensed CPA firm to test operating effectiveness and issue the SOC 2 Type II report.", L.assess),
      ]},
    ],
  },
  {
    key: "nistcsf", name: "NIST CSF 2.0", provider: "NIST", kind: "Framework", jurisdiction: "International",
    summary: "NIST Cybersecurity Framework 2.0. A voluntary outcome-based framework across six functions: Govern, Identify, Protect, Detect, Respond, Recover.",
    effort: "2–6 months",
    phases: [
      { name: "Govern (GV)", steps: [
        st("Establish governance", "Set the cybersecurity strategy, roles, policy and risk-management expectations.", L.policies),
        st("Set current & target profiles", "Define the organizational profile: current vs. target outcomes and tier.", L.assess),
      ]},
      { name: "Identify (ID)", steps: [
        st("Asset management", "Inventory assets, data and suppliers in scope.", L.assets),
        st("Risk assessment", "Identify and assess cybersecurity risks.", L.riskNist),
      ]},
      { name: "Protect (PR)", steps: [
        st("Implement protections", "Identity management, access control, data security, platform security, awareness.", L.controls53),
        st("Awareness & training", "Deliver awareness and role-based training.", L.awareness),
      ]},
      { name: "Detect (DE)", steps: [
        st("Continuous monitoring", "Operate monitoring and adverse-event analysis.", L.monitoring),
      ]},
      { name: "Respond (RS) & Recover (RC)", steps: [
        st("Incident response", "Operate incident management, analysis and reporting.", L.incident),
        st("Recovery & resilience", "Plan and rehearse recovery (crisis exercises, BCP).", L.crisis),
        st("Measure & improve", "Score the profile gap and track improvement over time.", L.assess),
      ]},
    ],
  },
  {
    key: "nist80053", name: "NIST SP 800-53 Rev 5", provider: "NIST", kind: "Framework", jurisdiction: "United States",
    summary: "Security & privacy controls catalogue and the RMF. The control baseline behind FedRAMP and most US federal authorizations.",
    effort: "4–9 months",
    phases: [
      { name: "Categorize", steps: [
        st("Categorize the system (FIPS 199)", "Determine the impact level (Low / Moderate / High) for confidentiality, integrity, availability.", L.scope),
        st("Inventory the boundary", "Define the authorization boundary and asset inventory.", L.assets),
      ]},
      { name: "Select", steps: [
        st("Select the control baseline", "Select the Low/Moderate/High baseline and tailor it.", L.controls53),
        st("Risk assessment", "Perform a NIST 800-30 risk assessment to drive tailoring.", L.riskNist),
      ]},
      { name: "Implement & Document", steps: [
        st("Implement controls", "Implement the selected controls and record implementation status.", L.controls53),
        st("System Security Plan (SSP)", "Document how each control is implemented in the SSP.", L.evidence),
      ]},
      { name: "Assess", steps: [
        st("Assess controls (800-53A)", "Assess control effectiveness and record results.", L.assess),
        st("POA&M", "Track weaknesses and remediation in a Plan of Action & Milestones.", L.controls53),
      ]},
      { name: "Authorize & Monitor", steps: [
        st("Authorize (ATO)", "Produce the authorization package and obtain the authorization decision.", L.assess),
        st("Continuous monitoring", "Operate ongoing monitoring of controls and risk.", L.monitoring),
      ]},
    ],
  },
  {
    key: "fedramp", name: "FedRAMP", provider: "GSA / FedRAMP PMO", kind: "Authorization", jurisdiction: "United States",
    summary: "US government authorization for cloud services, built on NIST 800-53 baselines, assessed by a 3PAO and authorized (JAB/Agency).",
    effort: "12–18 months",
    phases: [
      { name: "Prepare", steps: [
        st("Determine impact level", "Select Low / Moderate / High (or LI-SaaS) and the authorization path (Agency / JAB).", L.scope),
        st("Define the boundary", "Document the system boundary, data flows and inventory.", L.assets),
      ]},
      { name: "Document", steps: [
        st("Implement 800-53 baseline", "Implement the FedRAMP control baseline for the chosen impact level.", L.controls53),
        st("Author the SSP", "Write the System Security Plan with the FedRAMP templates and attachments.", L.evidence),
        st("Policies & procedures", "Provide the required policies and procedures.", L.policies),
      ]},
      { name: "Assess (3PAO)", steps: [
        st("3PAO security assessment", "A FedRAMP-accredited 3PAO executes the SAP and produces the SAR.", L.assess),
        st("Remediate & POA&M", "Remediate findings and maintain the POA&M.", L.controls53),
      ]},
      { name: "Authorize & ConMon", steps: [
        st("Authorization (ATO)", "Submit the package for the Agency/JAB authorization decision.", L.assess),
        st("Continuous monitoring", "Deliver monthly ConMon: scans, POA&M updates and annual assessment.", L.monitoring),
      ]},
    ],
  },
  {
    key: "nis2", name: "NIS2 Directive", provider: "EU (2022/2555)", kind: "Regulation", jurisdiction: "European Union",
    summary: "EU directive raising the cybersecurity baseline for essential and important entities, with management accountability and strict incident reporting.",
    effort: "3–9 months",
    phases: [
      { name: "Applicability", steps: [
        st("Determine entity type", "Establish whether you are an essential or important entity and which sectors apply.", L.scope),
        st("Register with the authority", "Register with the national competent authority / CSIRT as required.", L.regulator),
      ]},
      { name: "Risk-Management Measures (Art. 21)", steps: [
        st("Risk analysis & policies", "Adopt risk-analysis and information-system security policies.", L.riskReg),
        st("Technical & organizational measures", "Implement Art. 21 measures: crypto, access control, MFA, asset & vulnerability handling.", L.controls53),
        st("Business continuity", "Backup management, disaster recovery and crisis management.", L.crisis),
        st("Supply-chain security", "Address security in supplier relationships.", L.assess),
      ]},
      { name: "Incident Reporting (Art. 23)", steps: [
        st("Reporting process (24h / 72h / 1 month)", "Set up early warning (24h), incident notification (72h) and final report (1 month).", L.incident),
        st("Configure regulator notifications", "Wire the CSIRT/authority notification workflow.", L.regulator),
      ]},
      { name: "Governance & Accountability", steps: [
        st("Management oversight & training", "Management bodies approve measures and complete cybersecurity training (Art. 20).", L.awareness),
        st("Measure & report", "Track conformity to the NIS2 measures and report to leadership.", L.assess),
      ]},
    ],
  },
  {
    key: "recyf", name: "Référentiel Cyber France (ReCyF)", provider: "ANSSI (NIS 2 — transposition nationale)", kind: "Regulation", jurisdiction: "France",
    summary: "ANSSI's national framework operationalising NIS 2 for France: 20 security objectives (the mandatory \"what\") with acceptable means of compliance (the \"how\"). Proportionality applies — objectives 1–15 bind Important (EI) and Essential (EE) entities; objectives 16–20 bind EE only. Structured by the Gouvernance / Protection / Défense / Résilience pillar model. (Working v2.5; import the ReCyF catalogue to track the measures as controls.)",
    effort: "6–18 months",
    phases: [
      { name: "Gouvernance (Obj. 1–5, 16–17)", steps: [
        st("Obj. 1 — Recensement des SI", "Maintain a list of all activities/services and the information systems supporting them.", L.assets),
        st("Obj. 2 — Cadre de gouvernance", "Set up the digital-security governance, PSSI and conformity-management framework under the executive's responsibility.", L.policies),
        st("Obj. 16 — Approche par les risques (EE)", "Run a risk-based approach (analysis & treatment) — Essential entities.", L.riskReg),
        st("Obj. 3 — Maîtrise de l'écosystème", "Map suppliers/providers and secure ICT supply-chain relationships contractually.", L.sca),
        st("Obj. 4 — Sécurité & ressources humaines", "Integrate digital security into HR (onboarding/offboarding, awareness, cyber-hygiene).", L.awareness),
        st("Obj. 5 — Maîtrise des SI", "Keep systems mastered: inventory, secure baselines and configuration control.", L.config),
        st("Obj. 17 — Audit de la sécurité (EE)", "Audit the security of information systems — Essential entities.", L.assess),
      ]},
      { name: "Protection (Obj. 6–11, 18–19)", steps: [
        st("Obj. 6 — Accès physiques aux locaux", "Control physical access to premises hosting the information systems.", L.controls53),
        st("Obj. 7 — Architecture des SI", "Secure the architecture (segmentation, interconnections, hardening).", L.config),
        st("Obj. 8 — Accès distants", "Secure remote access (MFA, VPN, exposure control).", L.identity),
        st("Obj. 9 — Codes malveillants", "Protect systems against malware (EDR/AV, scanning).", "/malware-scan"),
        st("Obj. 10 — Identités & accès", "Manage user identities and access (least privilege, lifecycle).", L.identity),
        st("Obj. 11 — Administration des SI", "Master administration (privileged accounts, admin practices).", L.identity),
        st("Obj. 18 — Configuration des ressources (EE)", "Secure the configuration of system resources — Essential entities.", L.config),
        st("Obj. 19 — Administration depuis ressources dédiées (EE)", "Administer from dedicated, hardened resources — Essential entities.", L.config),
      ]},
      { name: "Défense (Obj. 12, 20)", steps: [
        st("Obj. 12 — Réaction aux incidents", "Detect and react to security incidents (process, classification, handling).", L.incident),
        st("Obj. 20 — Supervision de la sécurité (EE)", "Operate security supervision / detection (log collection, monitoring) — Essential entities.", L.monitoring),
      ]},
      { name: "Résilience (Obj. 13–15)", steps: [
        st("Obj. 13 — Continuité & reprise", "Maintain business-continuity and disaster-recovery capability (backups, RTO/RPO).", L.crisis),
        st("Obj. 14 — Réaction aux crises cyber", "Set up cyber-crisis management and secure emergency communications.", L.crisis),
        st("Obj. 15 — Exercices, tests & entraînements", "Run exercises, tests and drills to validate readiness.", L.crisis),
      ]},
    ],
  },
  {
    key: "dora", name: "DORA", provider: "EU (2022/2554)", kind: "Regulation", jurisdiction: "European Union",
    summary: "Digital Operational Resilience Act for EU financial entities: ICT risk management, incident reporting, resilience testing and third-party (ICT) oversight.",
    effort: "6–12 months",
    phases: [
      { name: "ICT Risk Management", steps: [
        st("ICT risk-management framework", "Establish the ICT risk-management framework with board accountability (Ch. II).", L.riskReg),
        st("Asset & dependency mapping", "Map ICT assets and the business functions they support.", L.assets),
        st("Protection & prevention", "Implement controls for ICT security, identity and resilience.", L.controls53),
      ]},
      { name: "Incident Management & Reporting", steps: [
        st("Classify ICT incidents", "Classify ICT-related incidents and cyber threats per the RTS criteria.", L.incident),
        st("Major-incident reporting", "Operate initial / intermediate / final reporting to the competent authority.", L.regulator),
      ]},
      { name: "Resilience Testing", steps: [
        st("Digital resilience testing", "Run the testing programme (vulnerability scans, scenario tests).", L.vuln),
        st("Threat-led penetration testing (TLPT)", "Plan advanced TLPT for entities in scope.", "/pentest"),
        st("Crisis exercises", "Rehearse operational-resilience scenarios.", L.crisis),
      ]},
      { name: "Third-Party Risk", steps: [
        st("ICT third-party register", "Maintain the register of information on ICT third-party arrangements.", L.assess),
        st("Concentration & exit", "Assess concentration risk and document exit strategies for critical providers.", L.assess),
        st("Information sharing", "Participate in threat-intelligence information sharing.", "/threat-feeds"),
      ]},
    ],
  },
  {
    key: "cra", name: "EU Cyber Resilience Act", provider: "EU (2024/2847)", kind: "Regulation", jurisdiction: "European Union",
    summary: "Mandatory cybersecurity for products with digital elements (PDE) across the whole lifecycle. Timeline: in force 10 Dec 2024 · vulnerability & incident reporting from 11 Sep 2026 · full applicability (CE marking) from 11 Dec 2027. This journey runs the practitioner path — scope & classify the product, threat-model and set a target IEC 62443 Security Level, gap-analyse and remediate against Annex I, test technically, operate vulnerability handling, then pass conformity assessment + CE marking and maintain post-market vigilance. Track every product, its release-readiness gate and the Annex I matrix in /cra-compliance; import the CRA control catalogue to track the obligations as controls.",
    effort: "6–12 months (phased: reporting Sep 2026 · CE marking Dec 2027)",
    phases: [
      { name: "1 · Scope & classification", steps: [
        st("Is the product in scope of the CRA?", "Answer the first foundational question: does this hardware/software with digital elements, made available on the EU market, fall under the CRA (and is it not covered by a sector regime)?", L.cra),
        st("Register the product & classify it", "Register the product with digital elements and determine its class — default / important Class I / important Class II / critical (Annex III/IV) — which drives the assessment route.", L.cra),
        st("Determine the conformity-assessment route", "Default & Class I (with harmonised standards) self-assess; Class II and critical products require a third-party / notified body. Set the route on the product.", L.cra),
        st("Map digital elements & dependencies (SBOM)", "Inventory the product's components and third-party / open-source dependencies as a machine-readable SBOM (CycloneDX/SPDX).", L.sca),
      ]},
      { name: "2 · Risk & threat modeling", steps: [
        st("Product cybersecurity risk assessment", "Perform and document the risk assessment that underpins the Annex I requirements and the technical documentation.", L.riskReg),
        st("Threat-model the product", "Model the attack surface, entry points, trust boundaries and abuse cases (e.g. STRIDE) for the product and its update channel.", L.threatModel),
        st("Set a target Security Level (IEC 62443 SL)", "Define a target Security Level (SL1–SL4) proportionate to the product's criticality, as the yardstick for the essential requirements.", L.cra),
      ]},
      { name: "3 · Gap analysis & secure-by-design (Annex I Part I)", steps: [
        st("Gap analysis vs Annex I & IEC 62443", "Assess current controls against the Annex I Part I requirements (and the mapped IEC 62443 SL) to find the gaps; track status in the Annex I matrix.", L.cra),
        st("Implement secure-by-design & by-default", "Implement the Annex I Part I controls — secure defaults, access control, confidentiality/integrity, attack-surface minimisation, logging — across the lifecycle.", L.controls53),
        st("Remediation roadmap", "Turn the gaps into a tracked remediation backlog with owners and due dates.", L.riskReg),
      ]},
      { name: "4 · Technical security testing", steps: [
        st("DevSecOps pipeline testing", "Run SAST / secret scanning / SCA / DAST on the product's code and build, gating releases on the results.", L.devsecops),
        st("Penetration test & deeper analysis", "Execute technical testing proportionate to the class — source-code review, firmware/protocol analysis, fuzzing and authentication-flow testing.", L.pentest),
        st("Validate no known exploitable vulnerabilities", "Confirm the release ships with no known exploitable vulnerabilities (Annex I.1.(2)(a)) by correlating the SBOM against CVE/KEV data.", L.cra),
      ]},
      { name: "5 · Vulnerability handling (Annex I Part II)", steps: [
        st("Operate vulnerability management", "Identify, remediate and issue free security updates for vulnerabilities without delay.", L.vuln),
        st("Coordinated vulnerability disclosure", "Establish a coordinated vulnerability-disclosure policy, a reporting contact and secure update distribution.", L.policies),
        st("Reporting readiness (24h / 72h / 14 days)", "Be ready to report actively-exploited vulnerabilities & severe incidents to ENISA/CSIRT — early warning 24h, notification 72h, final report 14 days.", L.regIncident),
      ]},
      { name: "6 · Conformity assessment & CE marking", steps: [
        st("Run the conformity assessment", "Execute the route for the class — internal self-assessment, or engage a notified body for Class II / critical products.", L.assess),
        st("Compile the technical documentation (Annex VII)", "Assemble the technical documentation: risk assessment, SBOM, test evidence and the description of the essential-requirement controls.", L.evidence),
        st("EU declaration of conformity & CE", "Draw up the EU declaration of conformity (Annex V) and affix the CE marking once the gate is green.", L.cra),
      ]},
      { name: "7 · Post-market vigilance", steps: [
        st("Continuous SBOM & CVE monitoring", "Continuously monitor the released SBOM against new CVEs/KEV over the support period and ship security updates.", L.sca),
        st("Support period & lifecycle", "Maintain the declared support period (≥ 5 years unless justified) and re-assess conformity on any substantial modification.", L.cra),
        st("Track CRA deadlines", "Track the CRA milestones (reporting from 11 Sep 2026, full applicability 11 Dec 2027) in the regulatory calendar.", L.regCalendar),
      ]},
    ],
  },
  {
    key: "nca-ecc", name: "NCA Essential Cybersecurity Controls (ECC)", provider: "Saudi Arabia — NCA (ECC-1:2018)", kind: "Regulation", jurisdiction: "Saudi Arabia",
    summary: "The Saudi National Cybersecurity Authority's baseline framework — 5 main domains, 29 subdomains and 114 controls — mandatory for government and critical-national-infrastructure organisations. This journey runs the 5 domains in order: cybersecurity governance, defence, resilience, third-party & cloud, and industrial control systems. Import the NCA ECC catalogue to track the subdomains as controls and map your existing controls to it.",
    effort: "4–9 months",
    phases: [
      { name: "1 · Cybersecurity Governance (ECC-1)", steps: [
        st("Cybersecurity strategy, management & policies (1-1→1-3)", "Approve a resourced cybersecurity strategy, stand up an independent cybersecurity function, and publish policies & procedures.", L.policies),
        st("Roles, risk management & compliance (1-4→1-7)", "Assign roles, run a cybersecurity risk-management methodology, embed cybersecurity in projects and ensure regulatory compliance.", L.riskReg),
        st("Review, audit, HR & awareness (1-8→1-10)", "Periodically review & audit cybersecurity, address it across the HR lifecycle, and run an awareness & training programme.", L.awareness),
      ]},
      { name: "2 · Cybersecurity Defence (ECC-2)", steps: [
        st("Asset & identity/access management (2-1, 2-2)", "Maintain an asset inventory with owners; enforce least-privilege identity & access management with periodic review.", L.assets),
        st("System, email, network & mobile protection (2-3→2-6)", "Harden systems, protect email, segment & secure networks, and secure mobile/BYOD devices.", L.config),
        st("Data protection, cryptography & backup (2-7→2-9)", "Classify & protect data, apply approved cryptography & key management, and run protected, tested backups.", L.controls53),
        st("Vulnerability management & penetration testing (2-10, 2-11)", "Continuously identify and remediate vulnerabilities and run periodic penetration testing of critical/internet-facing systems.", L.vuln),
        st("Logging, monitoring & incident management (2-12, 2-13)", "Centralise event logging & monitoring and operate detection, response and threat management.", L.soc),
        st("Physical & web application security (2-14, 2-15)", "Protect processing facilities physically and secure external web applications.", L.pentest),
      ]},
      { name: "3 · Cybersecurity Resilience (ECC-3)", steps: [
        st("Cybersecurity in business continuity (3-1)", "Integrate cybersecurity into business-continuity management — resilient systems, incident continuity and recovery objectives.", L.crisis),
      ]},
      { name: "4 · Third-Party & Cloud Cybersecurity (ECC-4)", steps: [
        st("Third-party cybersecurity (4-1)", "Set cybersecurity requirements in third-party contracts and assess & monitor providers before and during the engagement.", L.tprm),
        st("Cloud computing & hosting cybersecurity (4-2)", "Apply cybersecurity requirements for cloud/hosting — data location, segregation and provider assurance.", L.cloud),
      ]},
      { name: "5 · Industrial Control Systems Cybersecurity (ECC-5)", steps: [
        st("ICS / OT protection (5-1)", "Protect OT/ICS environments — segregation from IT, hardening, access control and monitoring (IEC 62443 / NIST 800-82).", L.ot),
      ]},
    ],
  },
  {
    key: "mica", name: "MiCA", provider: "EU (2023/1114)", kind: "Regulation", jurisdiction: "European Union",
    summary: "Markets in Crypto-Assets regulation for issuers and crypto-asset service providers (CASPs): authorization, governance and ICT/operational resilience (via DORA).",
    effort: "9–18 months",
    phases: [
      { name: "Scope & Authorization", steps: [
        st("Determine your role", "Establish whether you are a token issuer (ART/EMT) or a crypto-asset service provider (CASP).", L.scope),
        st("Authorization application", "Prepare the authorization / notification dossier for the competent authority.", L.regulator),
      ]},
      { name: "Governance & Conduct", steps: [
        st("Governance arrangements", "Put in place sound governance, fit-and-proper management and conflict-of-interest controls.", L.identity),
        st("Whitepaper & disclosures", "Produce the crypto-asset whitepaper and required client disclosures (where applicable).", L.policies),
        st("AML / safeguarding", "Implement AML/CFT and client-asset safeguarding controls.", L.controls53),
      ]},
      { name: "ICT & Operational Resilience (DORA)", steps: [
        st("ICT risk management", "Apply the DORA ICT risk-management framework (MiCA references DORA).", L.riskReg),
        st("Incident reporting", "Operate ICT-incident classification and reporting.", L.incident),
        st("Resilience testing", "Run digital operational-resilience testing.", L.vuln),
      ]},
      { name: "Ongoing Compliance", steps: [
        st("Continuous monitoring & reporting", "Maintain ongoing monitoring and regulatory reporting obligations.", L.monitoring),
      ]},
    ],
  },
  {
    key: "gdpr", name: "GDPR", provider: "EU (2016/679)", kind: "Regulation", jurisdiction: "European Union",
    summary: "EU General Data Protection Regulation: lawful processing of personal data, data-subject rights, DPIAs and 72h breach notification.",
    effort: "3–6 months",
    phases: [
      { name: "Map & Lawfulness", steps: [
        st("Records of processing (ROPA)", "Build the Article 30 record of processing activities.", L.assess),
        st("Establish lawful basis", "Determine and document the lawful basis for each processing activity.", L.policies),
        st("Data inventory & flows", "Inventory personal data, systems and cross-border flows.", L.assets),
      ]},
      { name: "Rights & Governance", steps: [
        st("Data-subject rights", "Operate access, rectification, erasure and portability request handling.", L.questionnaire),
        st("Appoint a DPO / roles", "Appoint a Data Protection Officer (where required) and assign roles.", L.identity),
        st("Privacy notices & consent", "Publish privacy notices and manage consent.", L.policies),
      ]},
      { name: "Protect & Assess", steps: [
        st("DPIA", "Run Data Protection Impact Assessments for high-risk processing.", L.riskReg),
        st("Security of processing (Art. 32)", "Implement appropriate technical and organizational measures.", L.controls53),
        st("Processor agreements", "Put Article 28 data-processing agreements in place with processors.", L.assess),
      ]},
      { name: "Breach & Accountability", steps: [
        st("72h breach notification", "Operate the breach-detection and 72h notification process.", L.incident),
        st("Demonstrate accountability", "Maintain evidence of compliance for the supervisory authority.", L.evidence),
      ]},
    ],
  },
  {
    key: "cmmc", name: "CMMC 2.0", provider: "U.S. DoD (32 CFR Part 170)", kind: "Certification", jurisdiction: "United States",
    summary: "Cybersecurity Maturity Model Certification 2.0 for the Defense Industrial Base. Level 1 (17 FAR 52.204-21 practices, protecting FCI) and Level 2 (110 practices = NIST SP 800-171 Rev 2, protecting CUI) are imported as the 'CMMC 2.0' control catalogue; this journey walks scoping, the SSP, the SPRS self-assessment score, POA&M and the C3PAO assessment.",
    effort: "6–18 months",
    phases: [
      { name: "Scope & Level", steps: [
        st("Determine FCI/CUI scope", "Identify where Federal Contract Information and Controlled Unclassified Information are stored, processed or transmitted, and define the assessment boundary.", L.scope),
        st("Select the CMMC level", "Determine the required level from your DoD contracts: Level 1 (FCI), Level 2 (CUI), or Level 3 (CUI, highest priority).", L.assess),
        st("Inventory in-scope assets", "Catalogue the in-scope systems, enclaves and Security Protection Assets (SPAs).", L.assets),
      ]},
      { name: "Implement Practices", steps: [
        st("Map the CMMC practices", "Adopt the CMMC 2.0 control catalogue (Level 1 = 17 practices, Level 2 = 110 = NIST SP 800-171 Rev 2) and map them to your assets and controls.", L.controlsTable),
        st("Access control & MFA", "Implement access control, identification & authentication and MFA (AC / IA domains).", L.identity),
        st("Configuration & vulnerability mgmt", "Harden baselines and run risk-based vulnerability & patch management (CM / RA / SI).", L.config),
        st("Audit logging & monitoring", "Operate audit logging, monitoring and alerting (AU / SI domains).", L.monitoring),
        st("Incident response", "Stand up and test the incident-handling capability (IR domain).", L.incident),
      ]},
      { name: "SSP & Assessment", steps: [
        st("System Security Plan (SSP)", "Document the System Security Plan describing the boundary and how each requirement is met (3.12.4).", L.policies),
        st("Self-assessment & SPRS score", "Assess each practice (Met / Not Met) per the DoD Assessment Methodology, compute the SPRS score (110 max, weighted deductions) and submit it to SPRS.", L.assess),
        st("Collect evidence", "Gather evidence for each practice to support the assessment.", L.evidence),
      ]},
      { name: "POA&M & Certification", steps: [
        st("Plan of Action & Milestones (POA&M)", "Record open items in a POA&M; note that conditional certification allows only certain practices to be deferred and closed within 180 days.", L.riskReg),
        st("C3PAO / DIBCAC assessment", "Engage a C3PAO for the Level 2 third-party assessment (or DIBCAC for Level 3); complete the formal assessment.", L.assess),
        st("Annual affirmation", "Submit the annual senior-official affirmation of continued compliance in SPRS.", L.trust),
      ]},
    ],
  },
  {
    key: "iso21434", name: "ISO/SAE 21434:2021", provider: "ISO/SAE", kind: "Certification", jurisdiction: "International (automotive)",
    summary: "Road-vehicle cybersecurity engineering across the lifecycle of E/E systems (concept → development → validation → production → operations → end-of-support), plus the TARA method. Underpins UNECE WP.29 R155 (CSMS) type approval. The clause 5–15 structure is imported as the 'ISO/SAE 21434:2021' control catalogue; this journey walks it phase by phase.",
    effort: "9–18 months",
    phases: [
      { name: "Organizational & project management", steps: [
        st("Cybersecurity governance & culture", "Establish cybersecurity governance, policy, responsibilities and a cybersecurity culture (clause 5).", L.policies),
        st("Project cybersecurity plan", "Assign project cybersecurity responsibilities and plan the activities and work products (clause 6).", L.riskReg),
        st("Distributed activities & suppliers", "Evaluate supplier capability and agree the cybersecurity interface (responsibilities) with suppliers (clause 7).", L.tprm),
      ]},
      { name: "TARA & concept", steps: [
        st("Item definition", "Define the item, its boundary, functions and operational environment (clause 9.3).", L.assets),
        st("Threat analysis & risk assessment (TARA)", "Identify assets, threat scenarios, impact, attack paths & feasibility, and determine risk (clause 15).", L.riskEbios),
        st("Cybersecurity goals & concept", "Decide risk treatment, set cybersecurity goals/claims and derive the cybersecurity concept (clause 9.4–9.5).", L.riskReg),
      ]},
      { name: "Development & validation", steps: [
        st("Design & implementation", "Refine requirements into an architecture with cybersecurity controls (clause 10.4.1).", L.controlsTable),
        st("Integration & verification", "Verify the implementation meets the cybersecurity requirements, including security testing (clause 10.4.2).", L.config),
        st("Cybersecurity validation", "Validate at vehicle level that the cybersecurity goals are adequate and met (clause 11).", L.assess),
      ]},
      { name: "Production, operations & assurance", steps: [
        st("Production control plan", "Ensure cybersecurity controls are correctly implemented in manufacturing (clause 12).", L.config),
        st("Continual activities & PSIRT", "Operate monitoring, vulnerability management and incident response for fielded items (clauses 8 & 13).", L.incident),
        st("End of support & decommissioning", "Plan end of cybersecurity support and decommissioning (clause 14).", L.assess),
        st("Cybersecurity case & assessment", "Compile the cybersecurity case and complete the independent cybersecurity assessment (clause 6.4.7–6.4.8).", L.evidence),
      ]},
    ],
  },
];

const BY_KEY = new Map(FRAMEWORKS.map((f) => [f.key, f]));
const STATUSES = new Set(["todo", "in_progress", "done", "na"]);

// ── helpers ────────────────────────────────────────────────────────────────────
function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function frameworkSummary(f: FrameworkT, lang = "en") {
  const steps = f.phases.reduce((n, p) => n + p.steps.length, 0);
  return {
    key: f.key, name: f.name, provider: f.provider, kind: f.kind, kindLabel: tx(f.kind, lang),
    jurisdiction: tx(f.jurisdiction, lang), summary: tx(f.summary, lang), effort: tx(f.effort, lang),
    phases: f.phases.length, steps,
  };
}
export function listFrameworks(lang = "en") { return FRAMEWORKS.map((f) => frameworkSummary(f, lang)); }

function tw(tenant: number | null): string { return tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : ""; }

function journeyProgress(journeyId: number): { total: number; done: number; na: number; inProgress: number; pct: number } {
  const rows = getDb("XCOMPLIANCE").prepare("SELECT Status FROM COMPLIANCEJOURNEYSTEP WHERE JourneyID = ?").all(journeyId) as { Status: string }[];
  const total = rows.length;
  const na = rows.filter((r) => r.Status === "na").length;
  const done = rows.filter((r) => r.Status === "done").length;
  const inProgress = rows.filter((r) => r.Status === "in_progress").length;
  const applicable = total - na;
  return { total, done, na, inProgress, pct: applicable ? Math.round((done / applicable) * 100) : 0 };
}

// ── dashboard / read ────────────────────────────────────────────────────────────
export function journeysDashboard(tenant: number | null, lang = "en"): { frameworks: any[]; journeys: any[]; summary: any } {
  const db = getDb("XCOMPLIANCE");
  let journeys: any[] = [];
  try {
    const rows = db.prepare(`SELECT * FROM COMPLIANCEJOURNEY ${tw(tenant)} ORDER BY JourneyID DESC`).all() as Record<string, any>[];
    journeys = rows.map((j) => {
      const p = journeyProgress(Number(j.JourneyID));
      const f = BY_KEY.get(String(j.FrameworkKey));
      return {
        id: Number(j.JourneyID), framework: String(j.FrameworkKey ?? ""), frameworkName: String(j.FrameworkName ?? (f?.name ?? "")),
        kind: f?.kind ?? "", name: String(j.Name ?? ""), scope: String(j.Scope ?? ""), owner: String(j.Owner ?? ""),
        status: String(j.Status ?? "Active"), startedDate: j.StartedDate ? String(j.StartedDate).slice(0, 10) : "", targetDate: j.TargetDate ? String(j.TargetDate).slice(0, 10) : "",
        assessmentId: j.ComplianceAssessmentID != null ? Number(j.ComplianceAssessmentID) : null,
        ...p,
      };
    });
  } catch { journeys = []; }

  const active = journeys.filter((j) => j.status !== "Archived");
  const summary = {
    journeys: journeys.length, frameworksAvailable: FRAMEWORKS.length,
    completed: journeys.filter((j) => j.pct >= 100).length,
    avgProgress: active.length ? Math.round(active.reduce((s, j) => s + j.pct, 0) / active.length) : 0,
    inFlight: active.filter((j) => j.pct < 100).length,
  };
  return { frameworks: listFrameworks(lang), journeys, summary };
}

export function getJourney(id: number, tenant: number | null, lang = "en"): { journey: any; phases: any[]; progress: any } | null {
  const db = getDb("XCOMPLIANCE");
  const j = db.prepare(`SELECT * FROM COMPLIANCEJOURNEY WHERE JourneyID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as Record<string, any> | undefined;
  if (!j) return null;
  const steps = db.prepare("SELECT * FROM COMPLIANCEJOURNEYSTEP WHERE JourneyID = ? ORDER BY PhaseOrder, StepOrder").all(id) as Record<string, any>[];
  const phaseMap = new Map<number, any>();
  for (const s of steps) {
    const po = Number(s.PhaseOrder);
    let ph = phaseMap.get(po);
    if (!ph) { ph = { order: po, name: tx(String(s.Phase ?? `Phase ${po}`), lang), steps: [] }; phaseMap.set(po, ph); }
    ph.steps.push({ id: Number(s.StepID), title: tx(String(s.Title ?? ""), lang), description: tx(String(s.Description ?? ""), lang), link: s.Link || null, status: String(s.Status ?? "todo"), notes: String(s.Notes ?? "") });
  }
  const phases = [...phaseMap.values()].sort((a, b) => a.order - b.order).map((ph) => {
    const applicable = ph.steps.filter((s: any) => s.status !== "na").length;
    const done = ph.steps.filter((s: any) => s.status === "done").length;
    return { ...ph, done, total: ph.steps.length, pct: applicable ? Math.round((done / applicable) * 100) : 0 };
  });
  const f = BY_KEY.get(String(j.FrameworkKey));
  const journey = {
    id: Number(j.JourneyID), framework: String(j.FrameworkKey ?? ""), frameworkName: String(j.FrameworkName ?? (f?.name ?? "")),
    kind: f?.kind ?? "", kindLabel: tx(f?.kind ?? "", lang), summary: tx(f?.summary ?? "", lang), name: String(j.Name ?? ""), scope: String(j.Scope ?? ""), owner: String(j.Owner ?? ""),
    status: String(j.Status ?? "Active"), startedDate: j.StartedDate ? String(j.StartedDate).slice(0, 10) : "", targetDate: j.TargetDate ? String(j.TargetDate).slice(0, 10) : "",
    assessmentId: j.ComplianceAssessmentID != null ? Number(j.ComplianceAssessmentID) : null,
  };
  return { journey, phases, progress: journeyProgress(id) };
}

// ── create / mutate ──────────────────────────────────────────────────────────────
/** Resolve (or create) a FRAMEWORK row + a COMPLIANCEASSESSMENT to tie the journey into the model. */
function spawnAssessment(f: FrameworkT, name: string, tenant: number | null): number | null {
  try {
    const db = getDb("XCOMPLIANCE");
    const fc = cols("FRAMEWORK");
    if (!fc.size) return null;
    let fwId: number | undefined;
    const ex = db.prepare("SELECT FrameworkID FROM FRAMEWORK WHERE Name = ? AND (TenantID = ? OR TenantID IS NULL) LIMIT 1").get(f.name, tenant) as { FrameworkID: number } | undefined;
    if (ex) fwId = ex.FrameworkID;
    else {
      const id = allocId(db, "FRAMEWORK", "FrameworkID");
      const rec: Record<string, unknown> = { FrameworkID: id, FrameworkGUID: randomUUID(), Name: f.name, Description: f.summary.slice(0, 500), Provider: f.provider, Locale: "EN", CreatedDate: new Date().toISOString(), TenantID: tenant };
      const keys = Object.keys(rec).filter((k) => fc.has(k));
      db.prepare(`INSERT INTO FRAMEWORK (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
      fwId = id;
    }
    const cc = cols("COMPLIANCEASSESSMENT");
    if (!cc.size || fwId == null) return null;
    const aid = allocId(db, "COMPLIANCEASSESSMENT", "ComplianceAssessmentID");
    const arec: Record<string, unknown> = { ComplianceAssessmentID: aid, ComplianceAssessmentGUID: randomUUID(), Name: name.slice(0, 300), FrameworkID: fwId, Status: "in_progress", CreatedDate: new Date().toISOString(), TenantID: tenant };
    const akeys = Object.keys(arec).filter((k) => cc.has(k));
    db.prepare(`INSERT INTO COMPLIANCEASSESSMENT (${akeys.map((k) => `"${k}"`).join(",")}) VALUES (${akeys.map(() => "?").join(",")})`).run(...akeys.map((k) => arec[k]));
    return aid;
  } catch { return null; }
}

export function startJourney(p: { framework: string; name?: string; scope?: string; owner?: string; targetDate?: string; spawnAssessment?: boolean }, tenant: number | null, createdBy?: string): { id: number } {
  const f = BY_KEY.get(String(p.framework));
  if (!f) throw new Error("unknown framework");
  const db = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const name = (p.name || `${f.name} compliance journey`).slice(0, 300);
  const assessmentId = p.spawnAssessment ? spawnAssessment(f, name, tenant) : null;

  const jc = cols("COMPLIANCEJOURNEY");
  const jid = allocId(db, "COMPLIANCEJOURNEY", "JourneyID");
  const jrec: Record<string, unknown> = {
    JourneyID: jid, JourneyGUID: randomUUID(), FrameworkKey: f.key, FrameworkName: f.name, Name: name,
    Scope: (p.scope || "").slice(0, 2000), Owner: (p.owner || "").slice(0, 200), Status: "Active",
    StartedDate: now.slice(0, 10), TargetDate: p.targetDate || null, ComplianceAssessmentID: assessmentId,
    TenantID: tenant, CreatedBy: createdBy ?? null, CreatedDate: now,
  };
  const jkeys = Object.keys(jrec).filter((k) => jc.has(k));
  db.prepare(`INSERT INTO COMPLIANCEJOURNEY (${jkeys.map((k) => `"${k}"`).join(",")}) VALUES (${jkeys.map(() => "?").join(",")})`).run(...jkeys.map((k) => jrec[k]));

  const sc = cols("COMPLIANCEJOURNEYSTEP");
  const ins = db.prepare(`INSERT INTO COMPLIANCEJOURNEYSTEP (StepID, JourneyID, PhaseOrder, Phase, StepOrder, Title, Description, Link, Status, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  let sid = allocId(db, "COMPLIANCEJOURNEYSTEP", "StepID");
  if (sc.has("StepID")) {
    f.phases.forEach((ph, pi) => ph.steps.forEach((s, si) => {
      ins.run(sid++, jid, pi + 1, ph.name, si + 1, s.title, s.desc, s.link ?? null, "todo", tenant);
    }));
  }
  return { id: jid };
}

export function updateStep(stepId: number, patch: { status?: string; notes?: string }, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT StepID FROM COMPLIANCEJOURNEYSTEP WHERE StepID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [stepId, tenant] : [stepId])) as { StepID: number } | undefined;
  if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (patch.status != null && STATUSES.has(patch.status)) {
    sets.push("Status = ?"); vals.push(patch.status);
    sets.push("CompletedDate = ?"); vals.push(patch.status === "done" ? new Date().toISOString() : null);
  }
  if (patch.notes != null) { sets.push("Notes = ?"); vals.push(String(patch.notes).slice(0, 2000)); }
  if (!sets.length) return true;
  vals.push(stepId);
  db.prepare(`UPDATE COMPLIANCEJOURNEYSTEP SET ${sets.join(", ")} WHERE StepID = ?`).run(...vals);
  return true;
}

export function deleteJourney(id: number, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT JourneyID FROM COMPLIANCEJOURNEY WHERE JourneyID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as { JourneyID: number } | undefined;
  if (!row) return false;
  db.prepare("DELETE FROM COMPLIANCEJOURNEYSTEP WHERE JourneyID = ?").run(id);
  db.prepare("DELETE FROM COMPLIANCEJOURNEY WHERE JourneyID = ?").run(id);
  return true;
}
