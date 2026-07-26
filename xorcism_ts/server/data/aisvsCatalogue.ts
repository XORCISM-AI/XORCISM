/**
 * aisvsCatalogue.ts — the OWASP AI Security Verification Standard (AISVS) 1.01-dev, verbatim.
 *
 * 16 parts, 203 auditable questions across 192 official control references, each with its assurance
 * levels (L1/L2/L3), a weight, the official requirement, an audit question, expected evidence and
 * cross-framework mappings (ISO/IEC 27001:2022, NIST CSF 2.0, NIS2, and the EU AI Act relation).
 * Source: OWASP AISVS 1.01-dev (LIA-Scan edition, pinned commit 94fbad5, CC BY-SA 4.0). This backs
 * the /aisvs verification-assessment cockpit (aisvs.ts). Do NOT paraphrase — this is the published
 * wording so results are audit-grade.
 */
export interface AisvsControl {
  num: number; ref: string; part: number; title: string; levels: string[]; weight: number;
  requirement: string; question: string; evidence: string[];
  iso27001: string; nistCsf: string; nis2: string; aiAct: string;
}
export interface AisvsPart { num: number; name: string }
export interface AisvsCatalogue { version: string; source: string; parts: AisvsPart[]; controls: AisvsControl[] }

export const AISVS_CATALOGUE: AisvsCatalogue = {
 "version": "1.01-dev",
 "source": "OWASP AISVS 1.01-dev (LIA-Scan edition, CC BY-SA 4.0)",
 "parts": [
  {
   "num": 1,
   "name": "Training Data Integrity & Traceability............................................................................................3 Part 2 — Input Validation...........................................................................................................................29 Part 3 — Model Lifecycle Management & Change Control....................................................................... 50 Part 4 — Infrastructure, Configuration & Deployment Security................................................................. 80 Part 5 — Access Control & Identity for AI Components & Users.............................................................111 Part 6 — Supply Chain Security for Models.............................................................................................127 Part 7 — Model Behavior, Output Control & Safety Assurance...............................................................139 Part 8 — Memory, Embeddings & Vector Database Security..................................................................155 Part 9 — Orchestration & Agentic Security — Execution Budgets, Loop Control, and Circuit Breakers / High-Impact Action Approval and Irreversibility Controls.........................................................................167 Part 10 — Orchestration & Agentic Security — Component Isolation and Tool Authorization................189 Part 11 — Orchestration & Agentic Security — Agent and Orchestrator Identity / Agent Authorization, Delegation, and Continuous Enforcement / Shutdown and Graceful Degradation..................................200 Part 12 — Model Context Protocol (MCP) Security — Component Integrity / Authentication & Authorization............................................................................................................................................216 Part 13 — Model Context Protocol (MCP) Security — Secure Transport / Schema, Message, and Input Validation..................................................................................................................................................227 Part 14 — Adversarial Robustness..........................................................................................................246 Part 15 — Monitoring, Logging & Anomaly Detection — Request & Response Logging / Detection and Alerting.....................................................................................................................................................277 Part 16 — Monitoring, Logging & Anomaly Detection — Model, Data, and Performance Drift Detection / Proactive Security Behavior Monitoring / Training Data & Model Lifecycle Audit....................................297 Traceability and notices........................................................................................................................... 321 Annex A — Evidence Freshness: Continuous Controls Monitoring for AI Controls................................ 322 Part 1 — Training Data Integrity & Traceability"
  },
  {
   "num": 2,
   "name": "Input Validation"
  },
  {
   "num": 3,
   "name": "Model Lifecycle Management & Change Control"
  },
  {
   "num": 4,
   "name": "Infrastructure, Configuration & Deployment Security"
  },
  {
   "num": 5,
   "name": "Access Control & Identity for AI Components & Users"
  },
  {
   "num": 6,
   "name": "Supply Chain Security for Models"
  },
  {
   "num": 7,
   "name": "Model Behavior, Output Control & Safety Assurance"
  },
  {
   "num": 8,
   "name": "Memory, Embeddings & Vector Database Security"
  },
  {
   "num": 9,
   "name": "Orchestration & Agentic Security — Execution Budgets, Loop Control, and Circuit Breakers / High-Impact Action Approval and Irreversibility Controls"
  },
  {
   "num": 10,
   "name": "Orchestration & Agentic Security — Component Isolation and Tool Authorization"
  },
  {
   "num": 11,
   "name": "Orchestration & Agentic Security — Agent and Orchestrator Identity / Agent Authorization, Delegation, and Continuous Enforcement / Shutdown and Graceful Degradation"
  },
  {
   "num": 12,
   "name": "Model Context Protocol (MCP) Security — Component Integrity / Authentication & Authorization"
  },
  {
   "num": 13,
   "name": "Model Context Protocol (MCP) Security — Secure Transport / Schema, Message, and Input Validation"
  },
  {
   "num": 14,
   "name": "Adversarial Robustness"
  },
  {
   "num": 15,
   "name": "Monitoring, Logging & Anomaly Detection — Request & Response Logging / Detection and Alerting"
  },
  {
   "num": 16,
   "name": "Monitoring, Logging & Anomaly Detection — Model, Data, and Performance Drift Detection / Proactive Security Behavior Monitoring / Training Data & Model Lifecycle Audit"
  }
 ],
 "controls": [
  {
   "num": 1,
   "ref": "C1.1.1",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "training data includes only features, attributes, and fields required for the model's stated purpose.",
   "question": "Can the AI product owner show, through an approved feature-to-data matrix and pipeline inspection, that every training attribute is necessary for the model's documented purpose?",
   "evidence": [
    "AI product owner-approved feature-to-purpose matrix covering every field in the current training schema and reviewed after material model-purpose changes",
    "Current training-pipeline schema inspection or automated test proving fields without an approved purpose are rejected before ingestion"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 2,
   "ref": "C1.1.2",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "an up-to-date inventory is kept of every training-data source, including its origin, responsible party, license, collection method, intended use constraints, and processing history.",
   "question": "Does the training-data register allow an auditor to trace every active dataset to its origin, accountable owner, licence, collection method, permitted uses, and complete processing history?",
   "evidence": [
    "Data governance owner-maintained training-source register containing origin, accountable party, licence, collection method, use constraints, and lineage for each active dataset",
    "Quarterly reconciliation record comparing the register with storage, feature-store, and training-job inventories, including closure evidence for discrepancies"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 3,
   "ref": "C1.1.3.a",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "data integrity is provided when training data is stored and transferred.",
   "question": "Are stored training datasets protected by integrity mechanisms whose configuration and verification records demonstrate detection of unauthorised or accidental alteration?",
   "evidence": [
    "Platform security owner-approved design identifying integrity controls for object stores, databases, snapshots, and offline training-data archives",
    "Recent integrity-verification output or controlled tamper test demonstrating that altered stored training data is detected and investigated"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 4,
   "ref": "C1.1.3.b",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "data integrity is provided when training data is stored and transferred.",
   "question": "Do transfer records and negative tests demonstrate that training data remains integrity-protected across every ingestion, replication, and pipeline hand-off?",
   "evidence": [
    "Data engineering owner-maintained flow diagram identifying authenticated integrity protection at every training-data transfer boundary",
    "Current transport configuration and adversarial transfer-test results showing modified payloads or unauthorised endpoints are rejected"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 5,
   "ref": "C1.1.4",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "integrity monitoring is applied to guard against unauthorized modifications or corruption of training data.",
   "question": "Can the security monitoring team demonstrate that changes to training datasets are continuously observed, attributable, and investigated when they fall outside approved pipeline activity?",
   "evidence": [
    "Monitoring owner-approved detection rules covering unauthorised writes, unexpected checksum changes, corruption indicators, and privileged dataset operations",
    "Recent alert samples or controlled tamper exercise showing detection, triage ownership, investigation timeline, and disposition"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 6,
   "ref": "C1.1.5",
   "part": 1,
   "title": "Training Data Origin & Data Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "datasets are watermarked so their use can be attributed and any unauthorized use detected.",
   "question": "Can the dataset owner demonstrate, through provenance records and challenge tests, that watermark signals identify authorised copies and expose reuse outside approved consumers?",
   "evidence": [
    "Dataset owner-approved watermarking specification linking watermark identifiers, embedding method, authorised consumers, and key or secret custody",
    "Recent detection exercise using authorised and unauthorised dataset copies, with measured attribution accuracy and documented false-positive review"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": ""
  },
  {
   "num": 7,
   "ref": "C1.2.1",
   "part": 1,
   "title": "Data Labeling and Annotation Security",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "labeling platforms enforce access controls that restrict who can create, modify, or approve annotations.",
   "question": "Do role assignments, approval workflows, and access tests prove that only explicitly authorised identities can create, modify, or approve training annotations?",
   "evidence": [
    "Annotation service owner-approved role matrix separating creation, modification, and approval privileges for human and service identities",
    "Quarterly access review plus current positive and negative authorisation tests for each annotation operation"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 8,
   "ref": "C1.2.2",
   "part": 1,
   "title": "Data Labeling and Annotation Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "cryptographic integrity is applied to labeling artifacts.",
   "question": "Can annotation owners verify the provenance and integrity of labelling artefacts from creation through approval and downstream training consumption?",
   "evidence": [
    "Labelling pipeline design identifying signatures, hashes, immutable versions, and verification points for annotation artefacts",
    "Controlled alteration test showing that modified labels or approval records fail integrity verification before training use"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 9,
   "ref": "C1.2.3",
   "part": 1,
   "title": "Data Labeling and Annotation Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "sensitive information in labels is redacted, anonymized, or encrypted before being used in any labeling artifact.",
   "question": "Do pre-publication controls and sampled labelling artefacts demonstrate that sensitive information is redacted, anonymised, or encrypted before it enters the annotation workflow?",
   "evidence": [
    "Privacy and data security owner-approved labelling-data handling standard defining sensitive-data classes and permitted redaction, anonymisation, or encryption treatments",
    "Recent sample review or automated detection report proving that untreated sensitive values are blocked before annotation artefacts are created"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 10,
   "ref": "C1.3.1",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "training and fine-tuning pipelines implement poisoning detection techniques to identify potential data poisoning or unintentional corruption in training data.",
   "question": "Do training and fine-tuning pipelines run documented poisoning and corruption checks with thresholds, escalation ownership, and retained results before a dataset is accepted?",
   "evidence": [
    "ML security owner-approved detection design defining poisoning indicators, corruption checks, acceptance thresholds, and escalation paths for each pipeline",
    "Current pipeline execution records and seeded-anomaly test results showing rejected or quarantined suspect training samples"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 11,
   "ref": "C1.3.2.a",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "automatically generated labels are subject to confidence thresholds and consistency checks to detect misleading or low-confidence labels.",
   "question": "Are machine-generated labels blocked or routed for review when their confidence falls below a documented, model-specific acceptance threshold?",
   "evidence": [
    "Model owner-approved confidence threshold register with validation rationale, review cadence, and treatment for each automated labelling model",
    "Recent pipeline records or boundary tests demonstrating routing outcomes immediately above and below each configured threshold"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 12,
   "ref": "C1.3.2.b",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "automatically generated labels are subject to confidence thresholds and consistency checks to detect misleading or low-confidence labels.",
   "question": "Do consistency checks identify contradictory, unstable, or distributionally anomalous machine-generated labels before they are admitted to training data?",
   "evidence": [
    "Data quality owner-approved consistency-check specification covering duplicate conflicts, class drift, annotator disagreement, and repeat-run stability",
    "Current validation report or seeded inconsistency test showing detection, quarantine, investigation, and release decision"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 13,
   "ref": "C1.3.3",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models used in security-relevant decisions are evaluated for bias patterns.",
   "question": "Can the accountable owner produce slice-level fairness results, acceptance decisions, and remediation records for each model that influences a security- sensitive outcome?",
   "evidence": [
    "Accountable model owner-approved bias evaluation plan defining relevant groups, metrics, decision thresholds, data limitations, and review triggers",
    "Latest pre-release or periodic bias assessment with slice-level results, approval decision, and tracked remediation for exceeded thresholds"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 14,
   "ref": "C1.3.4",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "disallowed content is detected and removed before training.",
   "question": "Can data governance demonstrate that ingestion screening prevents prohibited material from reaching released training corpora and records the disposition of every positive match?",
   "evidence": [
    "Data governance owner-approved prohibited-content taxonomy and handling procedure mapped to automated and manual screening controls",
    "Recent screening report and sampled removal or quarantine records demonstrating enforcement before dataset release to training"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art9.2.d — supporting measure only"
  },
  {
   "num": 15,
   "ref": "C1.3.5",
   "part": 1,
   "title": "Training Data Quality and Security Assurance",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "defenses against clean-label poisoning attacks are implemented.",
   "question": "Can the ML security team demonstrate, with representative attack scenarios, that clean-label poisoning defences detect or limit malicious samples that retain plausible labels?",
   "evidence": [
    "ML security owner-maintained threat model and defence design covering clean-label feature collision, influence, and targeted poisoning scenarios",
    "Latest adversarial evaluation report with seeded clean-label attacks, measured detection or impact reduction, residual risk, and approved follow-up actions"
   ],
   "iso27001": "A.5.12, A.5.14, A.8.12",
   "nistCsf": "ID.AM-07, PR.DS-01, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art10.2 — implementation evidence only"
  },
  {
   "num": 16,
   "ref": "C2.1.1",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "input normalization is applied before tokenization or embedding.",
   "question": "Do current inspection records cover the ingress pipeline order and test with Unicode confusables, mixed normalization forms, hidden Markdown/HTML, and extracted OCR/ASR text before the first tokenizer or embedding call?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect the ingress pipeline order and test with Unicode confusables, mixed normalization forms, hidden Markdown/HTML, and extracted OCR/ASR text before the first tokenizer or embedding call; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Use regression corpora from OWASP LLM01 and garak badchars/encoding probes; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 17,
   "ref": "C2.1.2",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "encoding and representation smuggling in inputs is detected and mitigated. Approved mitigations include canonicalization, strict schema validation, policy- based rejection, or explicit marking.",
   "question": "Do adversarial test results cover encoded and mixed-representation payloads through every public prompt, RAG ingestion, tool-output, and URL/query- parameter path?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Submit encoded and mixed- representation payloads through every public prompt, RAG ingestion, tool-output, and URL/query- parameter path; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm canonicalization or strict schema rejection happens before model context assembly, and replay known OWASP, PyRIT, and garak encoding cases; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 18,
   "ref": "C2.1.3",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "all inputs that could steer model behavior are treated as untrusted and screened by a prompt injection detection ruleset or classifier, with flagged inputs blocked.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory every model-steering input, then test each path with direct override, indirect document, log-borne, tool-output, and repository-metadata payloads?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory every model-steering input, then test each path with direct override, indirect document, log-borne, tool-output, and repository- metadata payloads; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm flagged events are blocked before context assembly or action execution and cannot be reintroduced through summarization or memory writes; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 19,
   "ref": "C2.1.4",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "input length controls prevent content from exceeding the context window. The controls must reject inputs that exceed token limits rather than truncating them.",
   "question": "Do boundary tests cover inputs just below, at, and above configured token limits across text, file upload, retrieval, and tool-result paths?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Send inputs just below, at, and above configured token limits across text, file upload, retrieval, and tool-result paths; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify explicit rejection, consistent error handling, and logs that record measured tokens after normalization and expansion; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 20,
   "ref": "C2.1.5",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "the system implements a character set restriction for all inputs. The restriction must use an allow-list approach derived from the languages and use cases the system supports, permitting only characters that are explicitly required.",
   "question": "Do current review records cover field-level allow-lists and test zero-width joiners, Unicode tags, right-to-left overrides, homoglyph keywords, mathematical alphabets, and unsupported scripts?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review field-level allow-lists and test zero-width joiners, Unicode tags, right-to-left overrides, homoglyph keywords, mathematical alphabets, and unsupported scripts; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm disallowed characters are rejected before model use and compare the policy with the OWASP free-form Unicode allow-list guidance and Unicode UTS #39 restriction/confusable mechanisms; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 21,
   "ref": "C2.1.6",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the system enforces an instruction hierarchy in which system and developer messages override user instructions and other untrusted inputs, even after user instructions have been processed.",
   "question": "Do current inspection records cover message construction and run conflicts at each trust boundary: system versus developer, developer versus user, and user versus tool or retrieved content?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect message construction and run conflicts at each trust boundary: system versus developer, developer versus user, and user versus tool or retrieved content; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm framework role fields, policy prompts, and pre-execution gates preserve priority after summarization and memory writes; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 22,
   "ref": "C2.1.7",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "reserved special tokens are encoded as literal characters and cannot be injected into the model context.",
   "question": "Does the maintained inventory and test record cover the model's control tokens and render its actual chat template, then fuzz prompt, tool, RAG, memory, and file-ingestion paths with those markers?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Enumerate the model's control tokens and render its actual chat template, then fuzz prompt, tool, RAG, memory, and file-ingestion paths with those markers; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify attacker text remains message content rather than becoming a role boundary, generation prompt, end-of-sequence marker, or tool envelope; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 23,
   "ref": "C2.1.8",
   "part": 2,
   "title": "Prompt Injection Defenses",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "the system can detect many-shot jailbreaking patterns.",
   "question": "Can the accountable control owner provide current design and operating evidence for sweep the number and ordering of harmful demonstrations across the supported context range, including mixed benign/harmful examples and variations combined with other jailbreak techniques?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Sweep the number and ordering of harmful demonstrations across the supported context range, including mixed benign/harmful examples and variations combined with other jailbreak techniques; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Record classifier scores and block decisions per shot count, and verify the detector or pre-model prompt modification triggers before the target request reaches the model; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 24,
   "ref": "C2.2.1",
   "part": 2,
   "title": "Content & Policy Screening",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "every prompt is scored by a content classifier for violence, self-harm, hate, and sexual content against configurable thresholds. Prompts that exceed those thresholds are rejected or sanitized before reaching the model context.",
   "question": "Do current review records cover classifier placement, category thresholds, fallback behavior, and decision logging?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review classifier placement, category thresholds, fallback behavior, and decision logging; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Replay a representative policy test set across chat, API, file, and tool-originated prompts; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 25,
   "ref": "C2.2.2",
   "part": 2,
   "title": "Content & Policy Screening",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "prompt content classification is evaluated for unsupported languages.",
   "question": "Does the maintained test set cover a language matrix covering each declared supported language plus unsupported, mixed-language, transliterated, short, slang-heavy, and unknown-language prompts?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build a language matrix covering each declared supported language plus unsupported, mixed-language, transliterated, short, slang-heavy, and unknown-language prompts; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run equivalent harmful and benign cases through the same pre-model classifier and confirm unsupported or low-confidence results follow a documented fail-safe path rather than being treated as safe; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 26,
   "ref": "C2.2.3",
   "part": 2,
   "title": "Content & Policy Screening",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "non-text inputs (image/video/audio) are checked for adversarial perturbations, steganographic payloads, hidden or embedded content, or known attack patterns.",
   "question": "Can the accountable control owner provide current design and operating evidence for before context assembly, run OCR, metadata and document-layer extraction, steganography checks, and audio transcription, then feed every extracted representation through the C2.1 pipeline?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Before context assembly, run OCR, metadata and document-layer extraction, steganography checks, and audio transcription, then feed every extracted representation through the C2.1 pipeline; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Add red-team cases for visible instructions, hidden text or metadata, pixel-space perturbations, over-the-air audio, and inputs whose malicious effect appears only after multimodal fusion; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 27,
   "ref": "C2.2.4",
   "part": 2,
   "title": "Content & Policy Screening",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "coordinated attacks spanning multiple input types (e.g., steganographic payloads in images combined with prompt injection in text) are detected and blocked.",
   "question": "Does the maintained test set cover paired tests in which each text, image, document, or audio fragment is benign alone but their combined interpretation is malicious?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build paired tests in which each text, image, document, or audio fragment is benign alone but their combined interpretation is malicious; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Submit each fragment separately as a control, then combine them in different orders and across multi-turn or retrieval flows; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.26, A.8.28",
   "nistCsf": "PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 28,
   "ref": "C3.1.1",
   "part": 3,
   "title": "Model Authorization & Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "a model registry maintains an inventory of all deployed model artifacts and their origin.",
   "question": "Do current inspection records cover model registry (MLflow, Vertex AI Model Registry, SageMaker Model Registry)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect model registry (MLflow, Vertex AI Model Registry, SageMaker Model Registry); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm MBOM/AIBOM export exists in SPDX or CycloneDX format; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art11.1 — supporting measure only"
  },
  {
   "num": 29,
   "ref": "C3.1.2",
   "part": 3,
   "title": "Model Authorization & Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "all model artifacts (weights, configurations, tokenizers, base models, fine-tunes, adapters, and safety/policy models) are cryptographically signed by authorized entities.",
   "question": "Do current verification results show signing workflow exists using OpenSSF Model Signing (OMS) v1.0, Sigstore cosign, in-toto attestations, or GPG?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify signing workflow exists using OpenSSF Model Signing (OMS) v1.0, Sigstore cosign, in-toto attestations, or GPG; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test by deploying an unsigned or modified artifact and confirm it is rejected; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 30,
   "ref": "C3.1.3",
   "part": 3,
   "title": "Model Authorization & Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "model cryptographic signatures are verified at deployment admission and on load.",
   "question": "Do negative test results cover to deploy an unsigned or modified model artifact and confirm the system rejects it?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Attempt to deploy an unsigned or modified model artifact and confirm the system rejects it; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Review admission controller configuration (Sigstore policy-controller, Kyverno verifyImages rules, or Connaisseur); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 31,
   "ref": "C3.2.1.a",
   "part": 3,
   "title": "Model Validation & Testing",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "models undergo automated input validation testing, safety evaluation testing, and output sanitization testing before deployment.",
   "question": "Do pre-deployment test records demonstrate that the model rejects malformed, out-of-range, and policy-invalid inputs across every supported modality?",
   "evidence": [
    "Model assurance owner-approved input-validation test plan covering schemas, boundary values, malformed content, and unsupported modalities for the release candidate",
    "Latest pre-deployment execution report showing pass, fail, exception, and remediation status for the complete input-validation suite"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 32,
   "ref": "C3.2.1.b",
   "part": 3,
   "title": "Model Validation & Testing",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "models undergo automated input validation testing, safety evaluation testing, and output sanitization testing before deployment.",
   "question": "Does the release gate require a documented safety evaluation with defined acceptance thresholds and block promotion when a threshold is exceeded?",
   "evidence": [
    "Model risk owner-approved safety evaluation plan defining prohibited outcomes, test populations, metrics, thresholds, and release authority",
    "Latest release-candidate safety report with measured results, approval decision, exceptions, and linked remediation actions"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 33,
   "ref": "C3.2.1.c",
   "part": 3,
   "title": "Model Validation & Testing",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "models undergo automated input validation testing, safety evaluation testing, and output sanitization testing before deployment.",
   "question": "Do output-control tests prove that unsafe, malformed, or policy-prohibited model responses are sanitised or rejected before reaching downstream consumers?",
   "evidence": [
    "Application security owner-approved output-control specification identifying schemas, prohibited content, sanitisation rules, and downstream trust boundaries",
    "Latest positive and negative output-control test results covering every supported response format and integration path"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 34,
   "ref": "C3.2.2",
   "part": 3,
   "title": "Model Validation & Testing",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models subjected to post-training quantization are re-evaluated against the same safety and alignment test suite on the compressed artifact before deployment.",
   "question": "Can the accountable control owner provide current design and operating evidence for re-run the **same versioned safety and alignment suite** against the exact compressed digest using the actual serving stack?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Re-run the **same versioned safety and alignment suite** against the exact compressed digest using the actual serving stack; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Store per-hazard attack success, refusal, over-refusal, fairness, and capability results rather than only an aggregate or perplexity score; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 35,
   "ref": "C3.2.3",
   "part": 3,
   "title": "Model Validation & Testing",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "provider model, version, or routing changes trigger security re-evaluation before continued use.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory every provider model alias, router rule, region, fallback, guardrail/filter version, reasoning setting, tool set, and harness?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory every provider model alias, router rule, region, fallback, guardrail/filter version, reasoning setting, tool set, and harness; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Resolve and log the exact route that served each evaluation; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — supporting measure only"
  },
  {
   "num": 36,
   "ref": "C3.3.1",
   "part": 3,
   "title": "Controlled Deployment & Rollback",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "production deployments implement rollout mechanisms with automated rollback triggers.",
   "question": "Do current inspection records cover deployment configuration for canary/blue- green settings (e.g., Kubernetes Argo Rollouts, Flagger, Istio traffic splitting, LaunchDarkly AI Configs for feature-flagged model rollout)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect deployment configuration for canary/blue-green settings (e.g., Kubernetes Argo Rollouts, Flagger, Istio traffic splitting, LaunchDarkly AI Configs for feature-flagged model rollout); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify rollback trigger thresholds are defined and automated — confirm they cover behavioral metrics (guardrail alert rates, tool/MCP failure rates) beyond standard latency/error thresholds; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 37,
   "ref": "C3.3.2",
   "part": 3,
   "title": "Controlled Deployment & Rollback",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "rollback capabilities restore the complete model state.",
   "question": "Can the accountable control owner provide current design and operating evidence for execute a rollback and verify that all components (weights, config, adapters, safety/policy models, system prompts) revert to the previous known- good version simultaneously?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Execute a rollback and verify that all components (weights, config, adapters, safety/policy models, system prompts) revert to the previous known-good version simultaneously; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm atomicity — no intermediate state is served during rollback; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 38,
   "ref": "C3.3.3",
   "part": 3,
   "title": "Controlled Deployment & Rollback",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "model versions running in parallel use isolated runtime state so that AI-specific shared resources are not shared across deployments.",
   "question": "Do current verification results show that each deployment cohort (canary, stable, shadow) runs with isolated KV cache instances — confirm no shared GPU memory pools or cache hash namespaces across cohorts?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that each deployment cohort (canary, stable, shadow) runs with isolated KV cache instances — confirm no shared GPU memory pools or cache hash namespaces across cohorts; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: In vLLM deployments, check that cache_salt is configured per-cohort to prevent prefix cache reuse across deployment versions, and that LoRA IDs are included in cache hashing to prevent adapter cross-contamination; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 39,
   "ref": "C3.4.1",
   "part": 3,
   "title": "Secure Development Practices",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "AI-specific runtime components are not shared across environment boundaries (e.g., development, staging, production).",
   "question": "Does the maintained inventory and test record cover all AI-specific runtime components (orchestration services, MCP servers, model registries, prompt/policy stores) across dev/staging/prod?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Enumerate all AI-specific runtime components (orchestration services, MCP servers, model registries, prompt/policy stores) across dev/staging/prod; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify no shared instances exist using cloud provider tools: AWS Resource Access Manager reports, GCP Organization Policy constraints, Azure Resource Graph queries; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 40,
   "ref": "C3.4.2",
   "part": 3,
   "title": "Secure Development Practices",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "model training and fine-tuning environments are isolated from production environments.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory every training and fine-tuning environment — distributed- compute clusters (Ray, Kubeflow, SageMaker training jobs), notebooks, feature/dataset stores, experiment trackers (MLflow, W&B), and the model registry — and confirm each runs in a separate?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory every training and fine-tuning environment — distributed-compute clusters (Ray, Kubeflow, SageMaker training jobs), notebooks, feature/dataset stores, experiment trackers (MLflow, W&B), and the model registry — and confirm each runs in a separate…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For Ray and other distributed- training frameworks, confirm the Jobs API/dashboard is not internet-exposed and sits behind authentication and network isolation — the CVE-2023-48022 mitigation is operational, not a patch — and sweep with shodan search 'Ray…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 41,
   "ref": "C3.5.1",
   "part": 3,
   "title": "Pipeline Fine-Tuning",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models used in RLHF fine-tuning are versioned and integrity-verified before use in a training run.",
   "question": "Does current control evidence confirm reward-model artifacts live in a versioned registry with cryptographic signatures (OpenSSF Model Signing / Sigstore Model Transparency), and that the pipeline verifies the expected signer identity, signature, transparency-log inclusion, and?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm reward-model artifacts live in a versioned registry with cryptographic signatures (OpenSSF Model Signing / Sigstore Model Transparency), and that the pipeline verifies the expected signer identity, signature, transparency-log inclusion, and…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run two negative tests: modify one signed file, then present an intact artifact signed by an unauthorized identity; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 42,
   "ref": "C3.5.2",
   "part": 3,
   "title": "Pipeline Fine-Tuning",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "RLHF training stages include automated detection of reward hacking or reward model over-optimization.",
   "question": "Does current control evidence confirm at least one detection mechanism is wired into training and gates promotion: held-out human-preference probes evaluated during training, KL-divergence monitoring against the reference policy, reward- distribution outlier analysis (InfoRM's Mahalanobis?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm at least one detection mechanism is wired into training and gates promotion: held-out human-preference probes evaluated during training, KL-divergence monitoring against the reference policy, reward-distribution outlier analysis (InfoRM's Mahalanobis…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm threshold breaches automatically block promotion; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 43,
   "ref": "C3.5.3",
   "part": 3,
   "title": "Pipeline Fine-Tuning",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "in multi-stage fine-tuning pipelines, each stage's output is integrity-verified before it is consumed by the next stage.",
   "question": "Do current verification results show each stage's output is registered as a distinct artifact with a unique digest, and that signature/checksum verification (OMS/Sigstore) runs before a downstream stage consumes it?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify each stage's output is registered as a distinct artifact with a unique digest, and that signature/checksum verification (OMS/Sigstore) runs before a downstream stage consumes it; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test by corrupting an intermediate checkpoint and confirming the next stage rejects it; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 44,
   "ref": "C3.5.4",
   "part": 3,
   "title": "Pipeline Fine-Tuning",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "fine-tuning checkpoints are registered as distinct artifacts.",
   "question": "Do current execution results cover a short training job that emits several checkpoints, then query the registry and confirm every emitted checkpoint has its own immutable digest or ID, producing run, training step, parent checkpoint, and model/data/code/reward/environment identifiers?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Run a short training job that emits several checkpoints, then query the registry and confirm every emitted checkpoint has its own immutable digest or ID, producing run, training step, parent checkpoint, and model/data/code/reward/environment identifiers; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: MLflow 3 model tracking assigns a unique model_id to each logged checkpoint and can link checkpoint metrics to datasets; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.25, A.8.32",
   "nistCsf": "ID.IM-02, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art53.1.a — implementation evidence only"
  },
  {
   "num": 45,
   "ref": "C4.1.1",
   "part": 4,
   "title": "AI Workload Sandboxing & Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "AI models execute in isolated sandboxes.",
   "question": "Do current verification results show sandboxing technology is deployed (gVisor, Firecracker, Kata Containers, or process-level sandboxing like nsjail)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify sandboxing technology is deployed (gVisor, Firecracker, Kata Containers, or process-level sandboxing like nsjail); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm untrusted models cannot access the host filesystem, network, or other workloads; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 46,
   "ref": "C4.1.2",
   "part": 4,
   "title": "AI Workload Sandboxing & Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "model artifact loading enforces an explicit allow-list of serialization formats that do not permit arbitrary code execution during deserialization.",
   "question": "Do current verification results show the model loading pipeline enforces an explicit format allowlist?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify the model loading pipeline enforces an explicit format allowlist; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm that SafeTensors is the default/preferred format for model weights -- it stores only raw tensor data with JSON headers and cannot execute code by design; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 47,
   "ref": "C4.1.3",
   "part": 4,
   "title": "AI Workload Sandboxing & Validation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "workload attestation is performed before model loading to provide proof that the execution environment has not been tampered with.",
   "question": "Do current verification results show remote attestation flow: the workload generates an attestation report (signed by hardware root of trust), and the model loading system validates it against expected measurements before releasing model weights or decryption keys?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify remote attestation flow: the workload generates an attestation report (signed by hardware root of trust), and the model loading system validates it against expected measurements before releasing model weights or decryption keys; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test with a modified environment and confirm model loading is refused; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 48,
   "ref": "C4.1.4",
   "part": 4,
   "title": "AI Workload Sandboxing & Validation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "confidential inference services protect model weights during runtime through isolated execution environments.",
   "question": "Do current verification results show that the inference process runs in a hardware-backed isolated environment such as AMD SEV-SNP, Intel TDX, or an NVIDIA confidential GPU configuration, with memory encryption, integrity protection, and production/debug mode settings checked from?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that the inference process runs in a hardware-backed isolated environment such as AMD SEV-SNP, Intel TDX, or an NVIDIA confidential GPU configuration, with memory encryption, integrity protection, and production/debug mode settings checked from…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm model weights remain encrypted at rest and are decrypted only inside the isolated environment after successful attestation; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 49,
   "ref": "C4.2.1.a",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "AI accelerator (GPU) firmware is version-pinned, signed, and attested at boot.",
   "question": "Does the accelerator inventory enforce approved firmware versions and block workloads on devices running an unapproved revision?",
   "evidence": [
    "Infrastructure security owner-approved accelerator firmware baseline with device models, approved revisions, and exception expiry dates",
    "Current fleet compliance report and negative admission test showing rejection of a device with an unapproved firmware revision"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 50,
   "ref": "C4.2.1.b",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "AI accelerator (GPU) firmware is version-pinned, signed, and attested at boot.",
   "question": "Do boot records prove that accelerator firmware signatures are verified against approved trust anchors before the device becomes available to AI workloads?",
   "evidence": [
    "Platform security design identifying firmware signing authorities, trust anchors, verification sequence, and failure behaviour",
    "Recent secure-boot evidence and tampered-signature test showing that an invalid accelerator image is rejected and alerted"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 51,
   "ref": "C4.2.1.c",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "AI accelerator (GPU) firmware is version-pinned, signed, and attested at boot.",
   "question": "Can the workload admission service validate fresh accelerator attestation evidence and deny execution when measured boot state diverges from the approved baseline?",
   "evidence": [
    "Attestation policy maintained by the platform security owner, including accepted measurements, freshness criteria, and workload admission decisions",
    "Latest valid and invalid attestation test results with denial, alert, investigation, and exception-handling evidence"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 52,
   "ref": "C4.2.2.a",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "execution within a trusted execution environment (TEE) provides hardware- enforced isolation, memory encryption, and integrity protection.",
   "question": "Do trusted-execution configuration and escape tests demonstrate hardware- enforced isolation between the AI workload and the host or neighbouring tenants?",
   "evidence": [
    "Confidential-computing owner-approved architecture identifying enclave boundaries, trusted computing base, and prohibited host access paths",
    "Latest isolation and escape-test report for the deployed hardware and runtime versions, including residual-risk disposition"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 53,
   "ref": "C4.2.2.b",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "execution within a trusted execution environment (TEE) provides hardware- enforced isolation, memory encryption, and integrity protection.",
   "question": "Can the platform team prove that sensitive AI workload memory remains encrypted outside the trusted execution boundary throughout processing?",
   "evidence": [
    "Platform cryptography design documenting memory-encryption mechanism, key lifecycle, protected regions, and hardware dependency",
    "Current attestation or platform diagnostic evidence plus a memory-observation test demonstrating ciphertext outside the trusted boundary"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 54,
   "ref": "C4.2.2.c",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "execution within a trusted execution environment (TEE) provides hardware- enforced isolation, memory encryption, and integrity protection.",
   "question": "Do integrity measurements and tamper tests show that trusted-execution code and protected state cannot be altered without detection and workload termination?",
   "evidence": [
    "Trusted-execution integrity policy defining approved measurements, verification points, alert routing, and termination behaviour",
    "Latest controlled tamper exercise showing detection, rejection or termination, investigation ownership, and retained forensic evidence"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 55,
   "ref": "C4.2.3",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "AI accelerator (GPU) integrity is validated using hardware-based attestation mechanisms before each workload executes.",
   "question": "Can the accountable control owner provide current design and operating evidence for before each workload receives model keys or sensitive data, issue a fresh verifier nonce?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Before each workload receives model keys or sensitive data, issue a fresh verifier nonce; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: collect GPU evidence and, where applicable, CPU-TEE, guest-image, and NVSwitch evidence; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 56,
   "ref": "C4.2.4",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "accelerator (GPU) memory is isolated between workloads through partitioning mechanisms with memory sanitization between jobs.",
   "question": "Do current verification results show GPU memory partitioning is active (NVIDIA MIG, AMD memory partitioning)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify GPU memory partitioning is active (NVIDIA MIG, AMD memory partitioning); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm memory sanitization occurs between job switches; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 57,
   "ref": "C4.2.5",
   "part": 4,
   "title": "AI Hardware Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "accelerator interconnects are restricted to approved topologies and authenticated endpoints.",
   "question": "Does the maintained test set cover an allowlist of accelerator, switch, and management-controller identities plus the permitted physical and virtual topology?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build an allowlist of accelerator, switch, and management-controller identities plus the permitted physical and virtual topology; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Compare it with live PCIe/NVLink/NVSwitch or UALink inventory and route state, then attempt peer access across an unapproved link or virtual pod and confirm it is denied; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 58,
   "ref": "C4.3.1",
   "part": 4,
   "title": "Edge & Distributed AI Security",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "edge AI devices authenticate to central infrastructure using strong authentication mechanisms.",
   "question": "Do current verification results show mTLS configuration on both device and server side?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify mTLS configuration on both device and server side; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check certificate validation includes chain verification, revocation checking (CRL/OCSP), and hostname verification; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": ""
  },
  {
   "num": 59,
   "ref": "C4.3.2",
   "part": 4,
   "title": "Edge & Distributed AI Security",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models deployed to edge or mobile devices are cryptographically signed during packaging, and that the on-device runtime validates these signatures or checksums before loading or inference.",
   "question": "Can the accountable control owner provide current design and operating evidence for record the runtime's pinned trust root or expected signing identity and the complete release manifest?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Record the runtime's pinned trust root or expected signing identity and the complete release manifest; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Using the OpenSSF model- signing reference implementation, run model_signing verify on the exact packaged directory and confirm that the signature identity and issuer are authorized and that the signed manifest covers every weight shard, configuration,…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 60,
   "ref": "C4.3.3",
   "part": 4,
   "title": "Edge & Distributed AI Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "inference runtimes enforce process, memory, and file access isolation.",
   "question": "Does current control evidence confirm the inference process runs unprivileged (runAsNonRoot: true), drops all Linux capabilities (capabilities.drop: [ALL]), sets allowPrivilegeEscalation: false, applies a seccomp profile (seccompProfile: RuntimeDefault or a tighter custom filter), and?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm the inference process runs unprivileged (runAsNonRoot: true), drops all Linux capabilities (capabilities.drop: [ALL]), sets allowPrivilegeEscalation: false, applies a seccomp profile (seccompProfile: RuntimeDefault or a tighter custom filter), and…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For untrusted or multi-tenant inference, verify a stronger-than-namespace boundary -- a sandboxed RuntimeClass such as gVisor or a microVM runtime (Kata Containers / Firecracker) rather than a shared-kernel container; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 61,
   "ref": "C4.3.4",
   "part": 4,
   "title": "Edge & Distributed AI Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "model weights and sensitive parameters stored locally are encrypted using hardware-backed key stores or secure enclaves.",
   "question": "Do current inspection records cover the local storage paths and confirm every weight and sensitive-parameter artifact is encrypted at rest?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect the local storage paths and confirm every weight and sensitive-parameter artifact is encrypted at rest; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Trace each data-encryption key to a non-exportable hardware-backed key; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 62,
   "ref": "C4.3.5",
   "part": 4,
   "title": "Edge & Distributed AI Security",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "models packaged within mobile, IoT, or embedded applications are encrypted at rest, and decrypted only inside a trusted runtime or secure enclave, preventing direct extraction from the app package or filesystem.",
   "question": "Can the accountable control owner provide current design and operating evidence for unpack the application, APK, or firmware image and verify that no plaintext weights, tokenizers, adapters, or sensitive parameters exist in assets, resources, expansion files, caches, or update staging?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Unpack the application, APK, or firmware image and verify that no plaintext weights, tokenizers, adapters, or sensitive parameters exist in assets, resources, expansion files, caches, or update staging; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Copy the packaged ciphertext to another device and confirm decryption fails; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.9, A.8.20, A.8.21, A.8.22",
   "nistCsf": "PR.IR-01, PR.PS-01",
   "nis2": "Art21.2.e, Art21.2.h",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 63,
   "ref": "C5.1.1",
   "part": 5,
   "title": "Authentication",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "high-risk AI operations (model deployment, weight export, training data access, production configuration changes) require step-up authentication.",
   "question": "Do current inspection records cover IdP and PAM policies for model deployment, weight export, training-data access, and production config paths?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect IdP and PAM policies for model deployment, weight export, training-data access, and production config paths; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: test WebAuthn/passkey or equivalent step-up prompts; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": "Art55.1.d — implementation evidence only"
  },
  {
   "num": 64,
   "ref": "C5.1.2",
   "part": 5,
   "title": "Authentication",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "AI agents in federated or multi-system deployments authenticate using short- lived, minimal-scoped, cryptographically signed tokens.",
   "question": "Do current review records cover OAuth/OIDC, SPIFFE/SVID, WIMSE, or token- exchange configuration?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review OAuth/OIDC, SPIFFE/SVID, WIMSE, or token-exchange configuration; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify token lifetime, audience, issuer, scope, JWKS or x5c validation, DPoP or mTLS proof where used, and replay rejection at each resource server; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 65,
   "ref": "C5.2.1",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "every AI resource (datasets, endpoints, vector collections, embedding indices, compute instances) enforces access controls with explicit allow-lists and default- deny policies.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory AI resources from cloud IAM, vector DB admin APIs, model registries, and Kubernetes?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory AI resources from cloud IAM, vector DB admin APIs, model registries, and Kubernetes; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: sample deny-by-default behavior with a non-entitled user; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 66,
   "ref": "C5.2.2",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "retrieval pipelines (e.g., RAG queries, embedding lookups) enforce the end- user's authorization context at each retrieval and assembly stage, rather than relying solely on the service account's permissions.",
   "question": "Do trace records cover the caller identity through retriever, reranker, metadata filter, chunk assembly, and citation generation?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Trace the caller identity through retriever, reranker, metadata filter, chunk assembly, and citation generation; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: run negative tests with same query text under users with different entitlements; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 67,
   "ref": "C5.2.3",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "sensitive data is retrieved via retrieval pipelines (e.g., RAG queries, embedding lookups) to prevent permanent storage in models.",
   "question": "Do current review records cover training and fine-tuning manifests, DLP scans, and data-source allow-lists?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review training and fine-tuning manifests, DLP scans, and data-source allow-lists; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: confirm sensitive collections are referenced through retrieval connectors; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 68,
   "ref": "C5.2.4",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "post-inference filtering mechanisms prevent responses from including data that the requester is not authorized to receive.",
   "question": "Do current execution results cover red-team prompts against users with partial access?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Run red-team prompts against users with partial access; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: validate output chunks and cited sources against caller entitlements before delivery; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 69,
   "ref": "C5.2.5",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the policy decision point for agent authorization is isolated from the agent's execution environment.",
   "question": "Does current control evidence confirm PDP execution in an external gateway, sidecar, or service?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm PDP execution in an external gateway, sidecar, or service; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify signed policy bundles and immutable decision logs; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 70,
   "ref": "C5.2.6",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "privileged access to model weights, training pipelines, and production AI configuration is granted just in time, with a defined maximum session duration and automatic expiry. Zero Standing Privilege (ZSP) to these resources is encouraged.",
   "question": "Do current inspection records cover PAM/PIM grants, approval records, maximum session durations, revocation events, and break-glass reviews?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect PAM/PIM grants, approval records, maximum session durations, revocation events, and break-glass reviews; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: test that expired sessions cannot export weights or change deployment config; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 71,
   "ref": "C5.2.7",
   "part": 5,
   "title": "AI Resource Authorization & Classification",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "data classification labels propagate to downstream resources (embeddings, prompt caches, model outputs).",
   "question": "Do trace records cover labels from source documents through ETL, vector metadata, cache keys, prompts, response objects, and logs?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Trace labels from source documents through ETL, vector metadata, cache keys, prompts, response objects, and logs; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: sample derived artifacts for retained sensitivity metadata; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": ""
  },
  {
   "num": 72,
   "ref": "C5.3.1",
   "part": 5,
   "title": "Multi-Tenant Isolation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "shared model serving infrastructure prevents one tenant's fine-tuning, inference, or embedding operations from influencing or observing another tenant's operations.",
   "question": "Do current review records cover tenant isolation for LoRA/adapters, embedding indices, model routing, and prefix/KV-cache reuse?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review tenant isolation for LoRA/adapters, embedding indices, model routing, and prefix/KV-cache reuse; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: test tenant-specific cache salts or namespace separation; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 73,
   "ref": "C5.3.2",
   "part": 5,
   "title": "Multi-Tenant Isolation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "one tenant cannot influence or observe another tenant's operations through shared compute resources. Satisfying this requirement typically requires hardware partitioning, confidential computing, or dedicated per-tenant compute allocation.",
   "question": "Can the accountable control owner provide current design and operating evidence for validate tenant placement policy, MIG or SR-IOV configuration, confidential-computing attestation, firmware/driver patch status, and dedicated allocation for hostile tenants?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Validate tenant placement policy, MIG or SR-IOV configuration, confidential-computing attestation, firmware/driver patch status, and dedicated allocation for hostile tenants; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: run co-residency tests where feasible; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.16, A.5.18, A.8.2, A.8.3",
   "nistCsf": "PR.AA-01, PR.AA-03, PR.AA-05",
   "nis2": "Art21.2.i, Art21.2.j",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 74,
   "ref": "C6.1.1",
   "part": 6,
   "title": "Model Artifact Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "models are scanned for malicious code before import.",
   "question": "Can the accountable control owner provide current design and operating evidence for put scanning before the import/cache boundary and fail closed on scanner errors, timeouts, unsupported formats, or verdict disagreement?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Put scanning before the import/cache boundary and fail closed on scanner errors, timeouts, unsupported formats, or verdict disagreement; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Exercise the gate with a versioned clean fixture and known-malicious fixtures for every permitted format; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 75,
   "ref": "C6.1.2",
   "part": 6,
   "title": "Model Artifact Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "model weights, datasets, and fine-tuning adapters are downloaded only from approved sources.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory the approved registry, organization/publisher, repository, artifact type, and immutable revision for each model, dataset, and adapter?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory the approved registry, organization/publisher, repository, artifact type, and immutable revision for each model, dataset, and adapter; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Enforce that policy at both the deployment controller and network egress layer; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art53.1.a — implementation evidence only"
  },
  {
   "num": 76,
   "ref": "C6.1.3",
   "part": 6,
   "title": "Model Artifact Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "every third-party model artifact can be integrity-verified.",
   "question": "Do current control checks cover that every imported model has a corresponding manifest containing: publisher identity, version tag, and SHA-256/SHA-512 hash?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Check that every imported model has a corresponding manifest containing: publisher identity, version tag, and SHA-256/SHA-512 hash; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify the signature chain back to the publisher's public key; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 77,
   "ref": "C6.1.4",
   "part": 6,
   "title": "Model Artifact Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models pass a behavioral acceptance test suite before being promoted to any non-development environment.",
   "question": "Can the accountable control owner provide current design and operating evidence for define a behavioral acceptance test suite tailored to the deployment context?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Define a behavioral acceptance test suite tailored to the deployment context; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: At minimum, test for: (1) safety — refusal of harmful requests, toxic output rates, jailbreak resistance; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 78,
   "ref": "C6.2.1",
   "part": 6,
   "title": "AI BOM & Supply Chain Monitoring",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "every model artifact publishes a version-controlled, machine-readable AI BOM listing datasets, weights, licenses, and data-origin statements.",
   "question": "Can the accountable control owner provide current design and operating evidence for generate a CycloneDX 1.7 ML-BOM (cdxgen -t ai, v12.7.1) or stable SPDX 3.0.1 AI-profile BOM at build time from training metadata (MLflow/W&B/DVC), not only from source?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Generate a CycloneDX 1.7 ML-BOM (cdxgen -t ai, v12.7.1) or stable SPDX 3.0.1 AI-profile BOM at build time from training metadata (MLflow/W&B/DVC), not only from source; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Following the CycloneDX AI/ML-BOM guide, inspect the document for dataset data components and origin, weight hashes and licenses, tokenizers and prompt templates as assembled components, and the training stack and workflow in formulation or a BOM-linked MBOM; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art11.1 — implementation evidence only"
  },
  {
   "num": 79,
   "ref": "C6.2.2",
   "part": 6,
   "title": "AI BOM & Supply Chain Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "AI BOMs are cryptographically signed before deployment.",
   "question": "Can the accountable control owner provide current design and operating evidence for sign the BOM out-of-band with Cosign (v3.1.1) using keyless Fulcio/OIDC, wrapped in an in-toto Statement (model hash as subject, BOM as predicate) and logged to Rekor v2 — large CycloneDX BOMs now fit since Rekor v2.3.0 dropped the DSSE size limit?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Sign the BOM out-of-band with Cosign (v3.1.1) using keyless Fulcio/OIDC, wrapped in an in-toto Statement (model hash as subject, BOM as predicate) and logged to Rekor v2 — large CycloneDX BOMs now fit since Rekor v2.3.0 dropped the DSSE size limit; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: At deploy time verify the Fulcio cert chain, confirm the subject hash matches the downloaded model, and bind the signing identity to an explicit publisher-workflow allowlist (not merely \"a valid OIDC issuer\"); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art53.1.a — supporting measure only"
  },
  {
   "num": 80,
   "ref": "C6.2.3",
   "part": 6,
   "title": "AI BOM & Supply Chain Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "AI BOM completeness checks fail the build if any component metadata is missing.",
   "question": "Can the accountable control owner provide current design and operating evidence for enforce a fail-closed completeness gate in CI against the CISA 2025 Minimum Elements floor extended with the G7 AI fields and the CycloneDX guide's model, dataset, tokenizer/template, training-stack, workflow, license, and provenance records?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Enforce a fail-closed completeness gate in CI against the CISA 2025 Minimum Elements floor extended with the G7 AI fields and the CycloneDX guide's model, dataset, tokenizer/template, training-stack, workflow, license, and provenance records; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Use cdxgen v12.7.1's aibom plus policy-violation checks or Cisco aibom's YAML policy engine to define the required fields and component types; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.19, A.5.20, A.5.21, A.5.22, A.8.8",
   "nistCsf": "GV.SC-04, GV.SC-05, ID.RA-01",
   "nis2": "Art21.2.d, Art21.2.e",
   "aiAct": "Art53.1.a — supporting measure only"
  },
  {
   "num": 81,
   "ref": "C7.1.1",
   "part": 7,
   "title": "Output Format Enforcement",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "the application validates all model outputs against a defined schema and rejects any output that does not match.",
   "question": "Can the accountable control owner provide current design and operating evidence for provide adversarial prompts designed to produce malformed output (e.g., JSON with extra fields, nested scripts)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Provide adversarial prompts designed to produce malformed output (e.g., JSON with extra fields, nested scripts); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm the application rejects non-conforming responses and does not pass them downstream; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 82,
   "ref": "C7.1.2",
   "part": 7,
   "title": "Output Format Enforcement",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "model-generated output is bounded by length limits and termination controls.",
   "question": "Can the accountable control owner provide current design and operating evidence for set explicit output-token limits and stop sequences for each call path, then force the model to reach each limit?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Set explicit output-token limits and stop sequences for each call path, then force the model to reach each limit; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Assert both that generation stops and that the application distinguishes normal completion, configured stops, output-limit truncation, and context exhaustion from provider termination metadata before parsing or executing the result; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 83,
   "ref": "C7.2.1",
   "part": 7,
   "title": "Hallucination Detection & Mitigation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the system assesses the reliability of generated answers using a confidence estimation method.",
   "question": "Does current control evidence confirm system produces reliability scores. 2?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm system produces reliability scores. 2; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test with known-hallucination- inducing prompts (nonexistent entities, fabricated dates). 3; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art14.4.c — supporting measure only"
  },
  {
   "num": 84,
   "ref": "C7.2.2",
   "part": 7,
   "title": "Hallucination Detection & Mitigation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the application automatically blocks answers or switches to a fallback message if the confidence score drops below a defined threshold.",
   "question": "Do adversarial test results cover prompts producing below-threshold scores?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Submit prompts producing below- threshold scores; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify fallback response. 3; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 85,
   "ref": "C7.2.3",
   "part": 7,
   "title": "Hallucination Detection & Mitigation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "for responses classified as high-risk by policy, the system performs an additional verification step.",
   "question": "Does current control evidence confirm the high-risk class actually triggers a **second, independent** verification mechanism — not a re-read of the same 7.2.1 score. 2?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm the high-risk class actually triggers a **second, independent** verification mechanism — not a re-read of the same 7.2.1 score. 2; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Inspect what the step does: multi-model consensus (route the query through ≥2 independent models and flag disagreement for human review), cross-model majority voting (Binghamton/STAR Protocols seven-model biomedical workflow reported zero unmatched…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art9.2.d — supporting measure only"
  },
  {
   "num": 86,
   "ref": "C7.3.1",
   "part": 7,
   "title": "Output Safety",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "automated classifiers scan every response and block content that matches defined harmful content categories.",
   "question": "Do adversarial test results cover prompts designed to elicit toxic content (red- teaming)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Submit prompts designed to elicit toxic content (red-teaming); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm the classifier catches and blocks outputs matching defined categories; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 87,
   "ref": "C7.3.2",
   "part": 7,
   "title": "Output Safety",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "output filters detect and block responses that disclose system prompt content or backend data.",
   "question": "Does the maintained test set cover a regression corpus from the actual system prompt and developer instructions, then test exact-match, fuzzy-match, and semantic-similarity detectors before any output reaches the user?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build a regression corpus from the actual system prompt and developer instructions, then test exact-match, fuzzy-match, and semantic-similarity detectors before any output reaches the user; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Seed synthetic backend records with unique canaries and distinct user or tenant entitlements across databases, RAG indexes, caches, and tool results; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 88,
   "ref": "C7.3.3",
   "part": 7,
   "title": "Output Safety",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "model-generated output is prevented from triggering outbound requests.",
   "question": "Can the accountable control owner provide current design and operating evidence for inject markdown image tags, HTML iframes, link prefetch directives, redirect chains, URL-preview metadata, and tool-return content into model responses?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inject markdown image tags, HTML iframes, link prefetch directives, redirect chains, URL-preview metadata, and tool-return content into model responses; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify that the client, renderer, and agent runtime make no automatic DNS, HTTP, or tool request solely because model output contains a resource reference, including references to same-platform or otherwise trusted origins; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 89,
   "ref": "C7.3.4",
   "part": 7,
   "title": "Output Safety",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "model outputs are checked for hidden, encoded, or misleading content created through homoglyphs, formatting, metadata, or structured fields.",
   "question": "Can the accountable control owner provide current design and operating evidence for capture the raw output before rendering and exercise a corpus containing Unicode Tags, variation selectors, zero-width joiners/non-joiners, bidirectional overrides, ANSI escape bytes, mixed-script homoglyphs, hidden HTML/markdown, image or document metadata,?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Capture the raw output before rendering and exercise a corpus containing Unicode Tags, variation selectors, zero-width joiners/non-joiners, bidirectional overrides, ANSI escape bytes, mixed-script homoglyphs, hidden HTML/markdown, image or document metadata,…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Compare raw bytes/code points with every rendered and downstream representation; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 90,
   "ref": "C7.4.1",
   "part": 7,
   "title": "Source Attribution & Citation Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "responses generated using retrieval-augmented generation (RAG) include attribution to the source documents.",
   "question": "Do current inspection records cover responses for citation blocks tied to retrieved documents?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect responses for citation blocks tied to retrieved documents; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: run representative queries and confirm each surfaces source IDs/links; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 91,
   "ref": "C7.4.2",
   "part": 7,
   "title": "Source Attribution & Citation Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "RAG attributions are derived from retrieval metadata and are not generated by the model, so provenance cannot be fabricated.",
   "question": "Do trace records cover the citation data path: confirm document/chunk IDs, page numbers, and URLs originate from the retriever's response object and are attached in the application layer, not produced as generated tokens?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Trace the citation data path: confirm document/chunk IDs, page numbers, and URLs originate from the retriever's response object and are attached in the application layer, not produced as generated tokens; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check for retrieval-generation isolation (immutable evidence records; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 92,
   "ref": "C7.4.3",
   "part": 7,
   "title": "Source Attribution & Citation Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "claims in a RAG response can be traced to the retrieved chunk.",
   "question": "Can the accountable control owner provide current design and operating evidence for decompose responses into atomic claims and run NLI entailment against the *cited* chunk, not just any retrieved chunk?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Decompose responses into atomic claims and run NLI entailment against the *cited* chunk, not just any retrieved chunk; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Bind each claim's subject entity to the entity asserted by its supporting passage and run negative tests with topically similar evidence about a different entity; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 93,
   "ref": "C7.4.4",
   "part": 7,
   "title": "Source Attribution & Citation Integrity",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "generated media is watermarked to prove it was AI-generated.",
   "question": "Does current control evidence confirm generated images/audio/video/text carry machine-readable provenance: C2PA Content Credentials (signed, tamper- evident manifests) plus imperceptible watermarking, matching the two-layered marking approach in the EU AI Act Code of Practice on?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm generated images/audio/video/text carry machine-readable provenance: C2PA Content Credentials (signed, tamper- evident manifests) plus imperceptible watermarking, matching the two-layered marking approach in the EU AI Act Code of Practice on…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Validate manifests with a C2PA validator and check the generator's C2PA conformance status; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.12, A.8.26, A.8.28",
   "nistCsf": "PR.DS-10, PR.PS-06",
   "nis2": "Art21.2.e",
   "aiAct": ""
  },
  {
   "num": 94,
   "ref": "C8.1.1",
   "part": 8,
   "title": "Access Controls on Memory & RAG Indices",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "vector identifiers and namespaces enforce uniqueness per tenant and prevent cross-tenant collisions.",
   "question": "Do current review records cover namespace and record-ID construction for tenant/user scoping?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review namespace and record-ID construction for tenant/user scoping; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: attempt duplicate IDs across tenants; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 95,
   "ref": "C8.1.2",
   "part": 8,
   "title": "Access Controls on Memory & RAG Indices",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "document metadata tags are immutable after the initial write.",
   "question": "Do current inspection records cover update/upsert APIs, schema constraints, and policy code for write-once fields?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect update/upsert APIs, schema constraints, and policy code for write-once fields; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: attempt to alter tenant, source, label, and expiry metadata after ingest; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 96,
   "ref": "C8.1.3",
   "part": 8,
   "title": "Access Controls on Memory & RAG Indices",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "retrieval operations enforce scope constraints.",
   "question": "Do trace records cover the policy decision point before retrieval and after context assembly?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Trace the policy decision point before retrieval and after context assembly; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: fuzz filter keys and values; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 97,
   "ref": "C8.2.1",
   "part": 8,
   "title": "Embedding Sanitization & Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "sensitive fields are detected before embedding and are masked, tokenized, or dropped.",
   "question": "Do current execution results cover DLP/PII scanners such as Microsoft Presidio, cloud DLP APIs, or custom detectors before vectorization?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Run DLP/PII scanners such as Microsoft Presidio, cloud DLP APIs, or custom detectors before vectorization; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: seed test records with canary secrets; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 98,
   "ref": "C8.2.2",
   "part": 8,
   "title": "Embedding Sanitization & Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "vectors that fall outside normal clustering patterns are flagged and quarantined before entering production indices.",
   "question": "Can the accountable control owner provide current design and operating evidence for maintain per-corpus baseline distributions for distance, density, cluster membership, and top-k dominance?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Maintain per-corpus baseline distributions for distance, density, cluster membership, and top-k dominance; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: flag sudden centroid shifts and vectors that over-match unrelated probes; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 99,
   "ref": "C8.2.3",
   "part": 8,
   "title": "Embedding Sanitization & Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "agent outputs and tool outputs are not automatically written to trusted agent memory without explicit source validation.",
   "question": "Can the accountable control owner provide current design and operating evidence for require a memory-write gate that records the source, calling principal, tenant, tool, and purpose?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Require a memory-write gate that records the source, calling principal, tenant, tool, and purpose; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify the source is authorized before committing the write; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 100,
   "ref": "C8.2.4",
   "part": 8,
   "title": "Embedding Sanitization & Validation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "content crafted to manipulate retrieval results is detected and rejected or quarantined before vectorization.",
   "question": "Can the accountable control owner provide current design and operating evidence for normalize extracted text across PDF, HTML, and office-document loaders?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Normalize extracted text across PDF, HTML, and office-document loaders; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: scan for hidden text, homoglyphs, out-of-bounds content, prompt-injection markers, suspicious embedding density, and repeated top-k dominance; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 101,
   "ref": "C8.2.5",
   "part": 8,
   "title": "Embedding Sanitization & Validation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "new content written to memory is checked for contradictions with what is already stored and that conflicts trigger alerts.",
   "question": "Do comparison records cover new entries against trusted memory using retrieval plus NLI/cross-encoder contradiction checks?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Compare new entries against trusted memory using retrieval plus NLI/cross-encoder contradiction checks; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: alert when high-trust records conflict; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 102,
   "ref": "C8.3.1",
   "part": 8,
   "title": "Memory Expiry & Revocation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "expired vectors are excluded from retrieval results.",
   "question": "Can the accountable control owner provide current design and operating evidence for encode expiry in immutable metadata?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Encode expiry in immutable metadata; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: enforce it in every retriever filter and post-retrieval guard; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 103,
   "ref": "C8.3.2",
   "part": 8,
   "title": "Memory Expiry & Revocation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "memory can be reset.",
   "question": "Can an authorised operator invoke the documented purge workflow and prove that previously retained context is no longer returned?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Exercise per-user, per-tenant, and per- agent reset flows; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify vector records, summaries, episodic memory, tool traces, caches, and derived indices are removed or rebuilt; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 104,
   "ref": "C8.3.3",
   "part": 8,
   "title": "Memory Expiry & Revocation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "quarantined content is retained but excluded from all retrieval results.",
   "question": "Can the accountable control owner provide current design and operating evidence for mark quarantine as an immutable exclusion state?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Mark quarantine as an immutable exclusion state; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify all retrievers, rerankers, agents, and batch jobs honor it; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.8.3, A.8.10, A.8.11",
   "nistCsf": "ID.AM-07, PR.AA-05, PR.DS-01",
   "nis2": "Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 105,
   "ref": "C9.1.1",
   "part": 9,
   "title": "Execution Budgets, Loop Control, and Circuit Breakers",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "per-tool quotas and timeouts (e.g., CPU, memory, disk, egress, and execution time) are enforced.",
   "question": "Do current inspection records cover the launch specification for **each tool**, not just the parent agent: require separate runtime identity and explicit CPU, memory, local ephemeral-storage, egress, and execution-time limits?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect the launch specification for **each tool**, not just the parent agent: require separate runtime identity and explicit CPU, memory, local ephemeral-storage, egress, and execution-time limits; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: In a canary environment, run five negative probes against one tool at a time: a CPU spinner, allocator beyond the memory limit, disk filler, connection to a denied destination, and a process that sleeps past its deadline; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 106,
   "ref": "C9.1.2",
   "part": 9,
   "title": "Execution Budgets, Loop Control, and Circuit Breakers",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "per-execution budgets (e.g., max recursion depth, token use, and monetary spend) are configured and enforced by the runtime.",
   "question": "Do current inspection records cover orchestration runtime and gateway config for per-chain or per-session spend counters (distinct from per-request limits)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect orchestration runtime and gateway config for per-chain or per-session spend counters (distinct from per-request limits); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm a circuit breaker fires when the cumulative chain threshold is exceeded — not just individual call limits; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 107,
   "ref": "C9.1.3",
   "part": 9,
   "title": "Execution Budgets, Loop Control, and Circuit Breakers",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "a swarm-level kill-switch exists that can halt all active agent instances.",
   "question": "Can the accountable control owner provide current design and operating evidence for start at least two agent replicas plus a delegated child tool and queued work under one swarm identifier, then invoke the out-of-band kill switch while they are active?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Start at least two agent replicas plus a delegated child tool and queued work under one swarm identifier, then invoke the out-of-band kill switch while they are active; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Assert within a documented bound that new admission is closed, queued deliveries and retries are cancelled or quarantined, every active agent and child runtime is terminated, leases and short-lived credentials are revoked, controllers do not respawn workers,…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 108,
   "ref": "C9.2.1",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "the agent runtime blocks execution of privileged or irreversible actions until explicit human approval is received and verified.",
   "question": "Do current review records cover the action taxonomy to confirm all high-impact actions are classified using the four-tier model (Low/Medium/High/Critical) and routed through an approval workflow?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review the action taxonomy to confirm all high-impact actions are classified using the four-tier model (Low/Medium/High/Critical) and routed through an approval workflow; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test by triggering each classified action type and verifying the system pauses for human approval before execution; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 109,
   "ref": "C9.2.2",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "approval requests display canonicalized and complete action parameters, such as diffs, commands, recipients, amounts, resources, and scopes, without truncation or unsafe transformation.",
   "question": "Do current verification results show that the approval payload contains a cryptographic hash or signature of the exact action parameters?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that the approval payload contains a cryptographic hash or signature of the exact action parameters; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: The Microsoft Agent Governance Toolkit uses Ed25519-signed action records for this purpose; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 110,
   "ref": "C9.2.3",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "each high-impact action has a trusted reversibility classification, such as read- only, reversible, externally reversible, or irreversible.",
   "question": "Does the maintained test set cover an authoritative action register covering every high-impact tool and parameter-dependent variant, with an owner, classification rationale, rollback authority, maximum recovery window, and evidence from the downstream system that actually performs the?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build an authoritative action register covering every high-impact tool and parameter-dependent variant, with an owner, classification rationale, rollback authority, maximum recovery window, and evidence from the downstream system that actually performs the…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm the taxonomy distinguishes **read-only** (no state change), **reversible** (the organization can reliably restore the prior state), **externally reversible** (reversal depends on another party or system), and **irreversible** (no dependable…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 111,
   "ref": "C9.2.4",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the agent runtime enforces reversibility classifications by blocking, requiring approval, or restricting actions based on their impact and ability to be reversed.",
   "question": "Do current inspection records cover a versioned decision table that maps each 9.2.3 class to a deterministic outcome, for example: read-only actions may proceed within authorization scope?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect a versioned decision table that maps each 9.2.3 class to a deterministic outcome, for example: read-only actions may proceed within authorization scope; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: reversible actions require an available and tested compensation path plus any policy-defined approval; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 112,
   "ref": "C9.2.5",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "any self-modification capability (e.g., prompt rewriting, tool-list changes, parameter updates) is restricted by enforceable boundaries.",
   "question": "Can the accountable control owner provide current design and operating evidence for treat the agent's system prompt, tool/skill allowlist, model parameters, memory-retention policy, and approval-threshold settings as a protected configuration store that the agent's own runtime identity has **read- only** access to?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Treat the agent's system prompt, tool/skill allowlist, model parameters, memory-retention policy, and approval-threshold settings as a protected configuration store that the agent's own runtime identity has **read-only** access to; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Any change must route through the same non-bypassable propose-commit gate (G_k) used for other high-impact actions (9.2.1) and require a separate, higher-tier approval — never the agent's own consent; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 113,
   "ref": "C9.2.6",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "agentic systems include an AI-augmented review of planned high-risk actions before execution that adds to, and does not replace, the deterministic policy gate.",
   "question": "Does current control evidence confirm the architecture is explicitly layered: the deterministic policy gate (Cedar/OPA/propose-commit G_k) is the necessary condition, and the AI review is **additive** — it can only *further restrict* or escalate (flag for human review, raise the required?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm the architecture is explicitly layered: the deterministic policy gate (Cedar/OPA/propose-commit G_k) is the necessary condition, and the AI review is **additive** — it can only *further restrict* or escalate (flag for human review, raise the required…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run cheap deterministic checks synchronously and route the LLM review in parallel or asynchronously, the defense-in-depth pattern recommended across 2026 guardrail guidance (deterministic checks + LLM-judges + span-level traces outperform any single guardrail); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art9.2.d — supporting measure only"
  },
  {
   "num": 114,
   "ref": "C9.2.7",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the AI-augmented review mechanism is protected against manipulation by adversarial inputs, and cannot be overridden or bypassed through prompt injection.",
   "question": "Does current control evidence confirm the AI reviewer is *isolated* from the content it judges: feed it the canonical action object and structured metadata produced by the trusted control plane, not the raw untrusted prompt, tool output, or RAG text, so injected \"judge output\" cannot?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm the AI reviewer is *isolated* from the content it judges: feed it the canonical action object and structured metadata produced by the trusted control plane, not the raw untrusted prompt, tool output, or RAG text, so injected \"judge output\" cannot…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Treat the reviewer's input/output contract as security-critical — parse only a strict, typed verdict schema (e.g., an enumerated reason code plus a signed boolean), never free text the model can forge, and reject any verdict that does not parse exactly; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 115,
   "ref": "C9.2.8",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "approvals are cryptographically bound to action parameters, requester identity, execution context, and a unique single-use nonce.",
   "question": "Do current inspection records cover the approval artifact and confirm it is a signature (Ed25519 or equivalent) over a deterministic hash of the **canonicalized action parameters** plus the **requester identity**, the **approving principal**, the **agent-instance identity** (SPIFFE?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect the approval artifact and confirm it is a signature (Ed25519 or equivalent) over a deterministic hash of the **canonicalized action parameters** plus the **requester identity**, the **approving principal**, the **agent-instance identity** (SPIFFE…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify the executor reconstructs the canonical signature base and validates the signature *before* any side effect, and that the verifier performs an **atomic check-and-set on a durable nonce registry** so each nonce is consumed exactly once within its…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 116,
   "ref": "C9.2.9",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "cryptographic key material or credentials used to issue approvals are isolated from the agent runtime.",
   "question": "Does current control evidence confirm approval-signing keys live in an HSM, a cloud KMS with non-exportable keys (the runtime calls a Sign API and never receives the private key), an AWS Nitro Enclave / confidential-computing TEE, or a self-hosted MPC signer — so the agent runtime can?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm approval-signing keys live in an HSM, a cloud KMS with non-exportable keys (the runtime calls a Sign API and never receives the private key), an AWS Nitro Enclave / confidential-computing TEE, or a self-hosted MPC signer — so the agent runtime can…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: The approval signer should be a **separate service or process** with its own identity, reachable only over an authenticated channel, and it must verify a valid gate decision (9.2.1) before signing rather than signing anything the runtime asks; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 117,
   "ref": "C9.2.10",
   "part": 9,
   "title": "High-Impact Action Approval and Irreversibility Controls",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "approval gates for multi-step or multi-agent action chains enforce the highest- impact reversibility classification present anywhere in the chain.",
   "question": "Do current verification results show the gate computes the chain's required approval tier as the **maximum reversibility/impact classification over every step in the plan**, including nested sub-agent and tool calls, rather than per-step — a single irreversible leaf forces the whole?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify the gate computes the chain's required approval tier as the **maximum reversibility/impact classification over every step in the plan**, including nested sub-agent and tool calls, rather than per-step — a single irreversible leaf forces the whole…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test by constructing a plan where a low-risk wrapper invokes an irreversible leaf (e.g., a \"generate report\" task that internally calls volume.delete) and confirm the entire chain is gated at the destructive tier and surfaced to the human approver; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 118,
   "ref": "C9.3.1",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "each tool/plugin executes in a least-privilege sandbox or is otherwise isolated from model operations.",
   "question": "Do current inspection records cover the runtime environment for each tool?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect the runtime environment for each tool; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify container/VM/WASM boundaries exist; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 119,
   "ref": "C9.3.2",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "tool outputs are validated against schemas.",
   "question": "Do current review records cover output validation logic for each tool?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review output validation logic for each tool; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify schema validation (type checking, field validation, size limits) is applied; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 120,
   "ref": "C9.3.3",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "tool manifests declare required privileges, resource limits, and output validation requirements.",
   "question": "Do current review records cover tool manifest schema?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review tool manifest schema; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify each tool has a manifest declaring: required filesystem paths, network destinations, syscall capabilities, side-effect classification (read-only vs. mutating), resource limits, and output schema; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 121,
   "ref": "C9.3.4",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "the runtime enforces the privileges, resource limits, and output-validation requirements declared in tool manifests.",
   "question": "Do comparison records cover every manifest declaration to an enforcement artifact: filesystem paths to mounts and read-only flags, network scopes to NetworkPolicy or proxy allowlists, syscall capabilities to seccomp/AppArmor/SELinux profiles, resource limits to cgroups or WASM?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Compare every manifest declaration to an enforcement artifact: filesystem paths to mounts and read-only flags, network scopes to NetworkPolicy or proxy allowlists, syscall capabilities to seccomp/AppArmor/SELinux profiles, resource limits to cgroups or WASM…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Attempt negative tests: call a tool not granted to the identity, write outside declared paths, connect to an undeclared host, request a destructive action from a read-only tool, exceed declared resource limits, return schema-invalid or…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 122,
   "ref": "C9.3.5",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "components processing untrusted data are isolated from tool-calling capabilities, ensuring that compromised data processing cannot trigger unauthorized tool invocations.",
   "question": "Do current verification results show a structural boundary between the component that processes untrusted data and the component that can call tools?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify a structural boundary between the component that processes untrusted data and the component that can call tools; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm one of the recognized isolation patterns from \"Design Patterns for Securing LLM Agents against Prompt Injections\" (Beurer- Kellner et al., arXiv:2506.08837, IBM/Invariant Labs/ETH Zurich/Google/Microsoft): a **Dual-LLM / quarantined-LLM** split where…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 123,
   "ref": "C9.3.6",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "there is architectural separation between processing of untrusted tool outputs and agent operations.",
   "question": "Do current verification results show that processing of tool *outputs* is architecturally separated from agent decision-making and action?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that processing of tool *outputs* is architecturally separated from agent decision-making and action; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm an **Action-Selector** pattern (tool-output content does not flow back unfiltered into the agent's planning context), a **Context- Minimization** step (raw output is reduced to typed results before the agent acts), or an **LLM Map- Reduce** reducer…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 124,
   "ref": "C9.3.7",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "external resources named in model output are verified against an approved allow-list or registry before the agent installs or invokes them.",
   "question": "Do current verification results show a deny-by-default allowlist/registry gate before the agent installs or invokes any model-named resource?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify a deny-by-default allowlist/registry gate before the agent installs or invokes any model-named resource; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For **packages**: confirm AI- suggested dependencies are checked against the target registry (publisher identity, registration date, download history), that lockfile pinning and hash verification are enforced in CI/CD, and that agents cannot run pip…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 125,
   "ref": "C9.3.8",
   "part": 10,
   "title": "Component Isolation and Tool Authorization",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "policy violations trigger automated tool containment.",
   "question": "Can the accountable control owner provide current design and operating evidence for simulate sandbox escape indicators (unexpected network connections, filesystem access outside sandbox, privilege escalation attempts, writes into supervising-tool configuration directories such as .claude/, .gemini/, .codex/ -- including writes routed?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Simulate sandbox escape indicators (unexpected network connections, filesystem access outside sandbox, privilege escalation attempts, writes into supervising-tool configuration directories such as .claude/, .gemini/, .codex/ -- including writes routed…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify approval dialogs display resolved symlink targets, not literal command text; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 126,
   "ref": "C9.4.1",
   "part": 11,
   "title": "Agent and Orchestrator Identity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "each agent instance has a unique cryptographic identity and authenticates as a first-class principal to downstream systems.",
   "question": "Do current verification results show each agent instance has a unique identity (X.509 cert, SPIFFE ID, or service account)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify each agent instance has a unique identity (X.509 cert, SPIFFE ID, or service account); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm agents authenticate to downstream services with their own credentials, not the end-user's; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 127,
   "ref": "C9.4.2",
   "part": 11,
   "title": "Agent and Orchestrator Identity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "agent-initiated actions are cryptographically bound to each step of the execution chain for non-repudiation.",
   "question": "Do current verification results show that every external action, tool call, delegation, and inter-agent message carries the current chain ID plus a parent span/record reference?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that every external action, tool call, delegation, and inter-agent message carries the current chain ID plus a parent span/record reference; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm the action record includes a canonical payload hash, previous-record hash, policy decision hash or policy version, agent identity, delegated principal, timestamp, and signature or MAC; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 128,
   "ref": "C9.4.3",
   "part": 11,
   "title": "Agent and Orchestrator Identity",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "agent identity credentials rotate on a defined schedule.",
   "question": "Does current control evidence confirm a documented rotation schedule exists and that credential lifetime is matched to agent lifetime rather than a human- oriented 90-day cycle -- short-lived agents should receive minutes-scale credentials, longer-running agents hours-scale with automatic?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm a documented rotation schedule exists and that credential lifetime is matched to agent lifetime rather than a human-oriented 90-day cycle -- short-lived agents should receive minutes-scale credentials, longer-running agents hours-scale with automatic…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For SPIFFE/SPIRE, inspect configured agent and workload SVID TTLs plus actual issuance and renewal events; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 129,
   "ref": "C9.4.4",
   "part": 11,
   "title": "Agent and Orchestrator Identity",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "agent state persisted between invocations is integrity-protected.",
   "question": "Do current verification results show every memory/state write carries a cryptographic integrity tag bound to content, writer identity, timestamp, schema/version, and tenant or session boundary?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify every memory/state write carries a cryptographic integrity tag bound to content, writer identity, timestamp, schema/version, and tenant or session boundary; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Use HMAC with a key held outside the state store or a signature whose private key is isolated from the store; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 130,
   "ref": "C9.5.1",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "agent actions are authorized against fine-grained policies enforced by the runtime that restrict which tools an agent may invoke, and which parameter values it may supply.",
   "question": "Do current review records cover the policy engine configuration?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review the policy engine configuration; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify that each tool has an associated policy specifying allowed callers, parameter constraints, and data scopes; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 131,
   "ref": "C9.5.2",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "when an agent acts on a user's behalf, the runtime propagates an integrity- protected, scope-limited token that carries the user's authorization context and is enforced at every downstream call.",
   "question": "Can the accountable control owner provide current design and operating evidence for first draw the credential flow: initiating user, service account, workload, or API?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: First draw the credential flow: initiating user, service account, workload, or API; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: any MCP server or intermediary; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 132,
   "ref": "C9.5.3",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "all access control decisions are enforced by application logic or a policy engine, never by the AI model itself.",
   "question": "Do current review records cover the architecture to confirm all access control checks are performed by deterministic code/policy engines, not by model inference?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review the architecture to confirm all access control checks are performed by deterministic code/policy engines, not by model inference; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Search for patterns where model output influences access decisions (e.g., model output parsed for \"allowed\"/\"denied\" strings); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 133,
   "ref": "C9.5.4",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "secrets and credentials required by an agent at runtime are not exposed within the model's observable context, including the context window, system prompts, or tool call parameters.",
   "question": "Do current verification results show that credentials are never present in the model's observable context by: (1) inspecting system prompts and tool definitions for hardcoded secrets, API keys, or connection strings?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that credentials are never present in the model's observable context by: (1) inspecting system prompts and tool definitions for hardcoded secrets, API keys, or connection strings; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: (2) reviewing tool call logs to confirm credential values do not appear in parameters sent to or returned from the model; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 134,
   "ref": "C9.5.5",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "inter-agent task delegation is restricted by an explicit authorization policy.",
   "question": "Do current verification results show that the system maintains an explicit peer authorization registry (allowlist) specifying which agents may delegate to or accept delegations from which other agents?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that the system maintains an explicit peer authorization registry (allowlist) specifying which agents may delegate to or accept delegations from which other agents; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test by: (a) deploying a new agent that is not in the registry and attempting delegation -- confirm the request is rejected by default; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 135,
   "ref": "C9.5.6",
   "part": 11,
   "title": "Agent Authorization, Delegation, and Continuous Enforcement",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "long-running agent sessions re-evaluate current backend authorization policy on every privileged action.",
   "question": "Do current review records cover the runtime path for every privileged tool call, API call, workflow transition, and queued action?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review the runtime path for every privileged tool call, API call, workflow transition, and queued action; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm the policy enforcement point performs a fresh authorization evaluation against current policy state, or checks a revocation-aware event cache, before executing the action; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 136,
   "ref": "C9.6.1",
   "part": 11,
   "title": "Shutdown and Graceful Degradation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "a manual kill-switch mechanism exists to immediately halt AI model inference and outputs.",
   "question": "Can the accountable control owner provide current design and operating evidence for activate the manual stop while the system is streaming output and while an agent workflow has an in-flight tool request?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Activate the manual stop while the system is streaming output and while an agent workflow has an in-flight tool request; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Record the operator identity, command time, last emitted output, inference termination time, dependent-work cancellation, and resulting safe state; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 137,
   "ref": "C9.6.2",
   "part": 11,
   "title": "Shutdown and Graceful Degradation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "when a human-approval gate is not satisfied within the defined approval time, the system blocks the pending action.",
   "question": "Do adversarial test results cover an action with fixed parameters and withhold approval until the configured deadline passes?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Submit an action with fixed parameters and withhold approval until the configured deadline passes; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify an auditable pending to expired or denied transition, no downstream side effect, and rejection of late approval, replay, and automatic retry; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 138,
   "ref": "C9.6.3",
   "part": 11,
   "title": "Shutdown and Graceful Degradation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "kill-switch commands are implemented through an out-of-band channel that is isolated from the agent runtime.",
   "question": "Can the accountable control owner provide current design and operating evidence for draw the trust boundary around the agent runtime and identify the separate operator identity, administrative endpoint, credential store, policy decision point, and enforcement point used for shutdown?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Draw the trust boundary around the agent runtime and identify the separate operator identity, administrative endpoint, credential store, policy decision point, and enforcement point used for shutdown; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Exercise that path while denying the agent access to each control-plane credential and endpoint; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.15, A.5.24, A.8.2, A.8.31",
   "nistCsf": "PR.AA-05, PR.IR-04, RS.MA-01",
   "nis2": "Art21.2.c, Art21.2.e, Art21.2.i",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 139,
   "ref": "C10.1.1",
   "part": 12,
   "title": "Component Integrity",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP components are obtained only from trusted sources and cryptographically verified.",
   "question": "Do current review records cover package installation procedures for checksum or signature verification?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review package installation procedures for checksum or signature verification; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check CI/CD pipelines for integrity gates (e.g., npm audit signatures, pip hash-checking mode, Docker Content Trust); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 140,
   "ref": "C10.1.2",
   "part": 12,
   "title": "Component Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "only allow-listed MCP servers are permitted.",
   "question": "Does the maintained test set cover a deny-by-default allowlist for each environment?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Build a deny-by-default allowlist for each environment; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Bind every entry to the canonical server ID, local or remote transport, command and package identifier or HTTPS endpoint, publisher and source registry, exact approved version or digest, expected artifact hash when available, and fixed launcher arguments; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 141,
   "ref": "C10.1.3",
   "part": 12,
   "title": "Component Integrity",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "locally launched MCP servers run in a least-privilege sandbox with restricted file system, network, and system access.",
   "question": "Does current control evidence confirm each locally launched server runs inside an OS-enforced sandbox, not as a bare child process. **Container isolation:** run servers via ToolHive with --isolate-network, which deploys an egress-proxy plus DNS container so the server reaches only the?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm each locally launched server runs inside an OS-enforced sandbox, not as a bare child process. **Container isolation:** run servers via ToolHive with --isolate-network, which deploys an egress-proxy plus DNS container so the server reaches only the…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: The Docker MCP Gateway likewise runs each server in an isolated container with restricted privileges, network, and resource caps. **Harden the container/runtime:** cap_drop: ALL, read_only: true root filesystem, tmpfs /tmp:noexec,nosuid, a seccomp profile,…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 142,
   "ref": "C10.2.1",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP servers validate access tokens for each request and do not rely on transport security alone.",
   "question": "Do exercise results cover each HTTP transport endpoint (initialize, tools/list, tools/call, resources/read) with no token, an expired token, a token from another issuer, and a valid token?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Exercise each HTTP transport endpoint (initialize, tools/list, tools/call, resources/read) with no token, an expired token, a token from another issuer, and a valid token; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify unauthenticated and invalid-token requests return 401 with a WWW-Authenticate challenge, while valid but under-scoped requests return 403; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 143,
   "ref": "C10.2.2",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP servers validate the presented access token's issuer, audience, expiration, and scope claims in accordance with OAuth 2.1.",
   "question": "Do current inspection records cover JWT validation or token-introspection middleware for exact issuer allowlists, JWKS pinning/discovery, aud/resource matching, exp/nbf clock-skew limits, and operation-specific scope checks?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect JWT validation or token- introspection middleware for exact issuer allowlists, JWKS pinning/discovery, aud/resource matching, exp/nbf clock-skew limits, and operation-specific scope checks; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test four negative cases: wrong issuer, wrong aud or missing resource, expired token, and valid token missing the requested tool scope; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 144,
   "ref": "C10.2.3",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP servers acting as OAuth 2.1 resource servers do not store or persist access tokens or user credentials.",
   "question": "Do current review records cover source and runtime configuration for token persistence points: structured logs, trace spans, prompt/context archives, session stores, crash dumps, vector indexes, custom MCP server definitions, and tool-call transcripts?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review source and runtime configuration for token persistence points: structured logs, trace spans, prompt/context archives, session stores, crash dumps, vector indexes, custom MCP server definitions, and tool-call transcripts; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run a synthetic token through a full MCP session, then search logs and telemetry backends for the token value and common encodings; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 145,
   "ref": "C10.2.4",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP tools/list returns only tools permitted by resource owners' authorized scopes.",
   "question": "Can the accountable control owner provide current design and operating evidence for call tools/list with tokens of varying scope levels and verify the response only includes authorized tools?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Call tools/list with tokens of varying scope levels and verify the response only includes authorized tools; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test with a minimal-scope token and confirm restricted tools are absent from the response; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 146,
   "ref": "C10.2.5",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers enforce access control on every tool invocation, validating that the user's access token authorizes both the requested tool and the specific argument values supplied.",
   "question": "Do current operating tests cover tool invocations with arguments outside the user's authorized scope (e.g., different tenant IDs, unauthorized file paths)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Test tool invocations with arguments outside the user's authorized scope (e.g., different tenant IDs, unauthorized file paths); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify the server rejects based on token claims, not just tool name; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 147,
   "ref": "C10.2.6",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers ensure all session artifacts are removed when a session terminates.",
   "question": "Do exercise results cover graceful HTTP termination with DELETE, normal connection close, abrupt disconnect, and idle timeout?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Exercise graceful HTTP termination with DELETE, normal connection close, abrupt disconnect, and idle timeout; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: After each path, verify the old session ID receives 404, token and event caches contain no session entries, temporary files are deleted, handles and subscriptions are closed, and a fresh session cannot access the prior resource owner's state; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 148,
   "ref": "C10.2.7",
   "part": 12,
   "title": "Authentication & Authorization",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers only accept tokens explicitly issued for them.",
   "question": "Do current review records cover MCP server code for downstream API calls?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review MCP server code for downstream API calls; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check whether the user's token is forwarded or whether a separate token is obtained; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 149,
   "ref": "C10.3.1",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "authenticated, encrypted streamable HTTP is used for MCP transport for remote services.",
   "question": "Do current review records cover deployment configuration to confirm streamable HTTP is the configured transport for all production remote MCP connections?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review deployment configuration to confirm streamable HTTP is the configured transport for all production remote MCP connections; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm every remote URL uses https:// end to end and that plaintext HTTP, insecure redirects, and TLS connections with an expired, untrusted, or hostname-mismatched certificate fail before credentials or MCP messages are sent; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 150,
   "ref": "C10.3.2",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "stdio transport is permitted only in controlled local environments.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory every stdio launch definition and identify who can create or change its executable, arguments, environment, and working directory?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory every stdio launch definition and identify who can create or change its executable, arguments, environment, and working directory; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Enumerate the resulting processes and confirm each runs under a dedicated non-login, low-privilege account (ps -o user,args -p <pid>), has no sudo or administrator membership, and owns no listening socket (lsof -p <pid> -i; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 151,
   "ref": "C10.3.3.a",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers validate both the Origin header and the Host header independently on all HTTP-based transports to prevent DNS rebinding attacks.",
   "question": "Do HTTP transport tests prove that every MCP request with an untrusted or unexpected Origin value is rejected before session or tool processing?",
   "evidence": [
    "MCP service owner-approved Origin validation policy covering browser, non-browser, proxy, and absent- header cases",
    "Latest positive and negative HTTP test results with allowed, foreign, malformed, null, and missing Origin values"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 152,
   "ref": "C10.3.3.b",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers validate both the Origin header and the Host header independently on all HTTP-based transports to prevent DNS rebinding attacks.",
   "question": "Do HTTP transport tests prove that MCP services independently validate Host routing and reject rebinding or alternate-authority requests?",
   "evidence": [
    "MCP platform owner-approved Host validation and trusted-proxy configuration listing permitted authorities and forwarding rules",
    "Latest DNS-rebinding and alternate-Host test results demonstrating rejection before MCP request dispatch"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 153,
   "ref": "C10.3.4",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP clients enforce a minimum acceptable protocol version and reject initialize responses that propose a version below that minimum.",
   "question": "Can the accountable control owner provide current design and operating evidence for configure an explicit minimum version in the client, then use a controlled server to answer initialize with: the requested version, a supported version at the floor, a supported version below the floor, an unknown future value, and a malformed value?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Configure an explicit minimum version in the client, then use a controlled server to answer initialize with: the requested version, a supported version at the floor, a supported version below the floor, an unknown future value, and a malformed value; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Below-floor and invalid responses must terminate the connection before notifications/initialized, credential release, tool discovery, or any operational request; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 154,
   "ref": "C10.3.5",
   "part": 13,
   "title": "Secure Transport",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "access tokens between the MCP client and server are sender-constrained using mTLS or DPoP.",
   "question": "Can the accountable control owner provide current design and operating evidence for **mTLS path:** verify authorization-server metadata enables certificate-bound access tokens, obtain a token over mTLS, and confirm its cnf.x5t#S256 value matches the client certificate?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: **mTLS path:** verify authorization- server metadata enables certificate-bound access tokens, obtain a token over mTLS, and confirm its cnf.x5t#S256 value matches the client certificate; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: The MCP resource must accept the token only over mTLS with that certificate; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 155,
   "ref": "C10.4.1",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP tools/list and tools/call responses are validated against their declared schemas before being injected into the model context.",
   "question": "Do current review records cover the client and gateway path that handles tools/list, tools/call, structuredContent, and outputSchema?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review the client and gateway path that handles tools/list, tools/call, structuredContent, and outputSchema; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm that tools/list responses conform to the MCP schema, that tool names are canonicalized consistently, and that tools/call results with an outputSchema are validated before model use; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 156,
   "ref": "C10.4.2",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP tools/list and tools/call responses are screened for indirect prompt injection before being injected into the model context.",
   "question": "Can the accountable control owner provide current design and operating evidence for seed tool descriptions, schema fields, text results, resource links, and tool execution errors with prompt-injection fixtures?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Seed tool descriptions, schema fields, text results, resource links, and tool execution errors with prompt-injection fixtures; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify the client treats them as untrusted data, strips or escapes HTML-like instruction tags, flags instruction-like language, and keeps tool return values visually and semantically separate from system/developer instructions; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 157,
   "ref": "C10.4.3",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "MCP servers reject unrecognized or oversized parameters in function calls.",
   "question": "Can the accountable control owner provide current design and operating evidence for for every tool, send unexpected fields, null, wrong scalar types, duplicated keys, oversized strings, large arrays, deeply nested objects, path traversal payloads, absolute paths, shell metacharacters, SQL metacharacters, Unicode edge cases, and boundary?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: For every tool, send unexpected fields, null, wrong scalar types, duplicated keys, oversized strings, large arrays, deeply nested objects, path traversal payloads, absolute paths, shell metacharacters, SQL metacharacters, Unicode edge cases, and boundary…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm rejection happens before filesystem, database, shell, HTTP, cloud, or Kubernetes APIs are reached; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 158,
   "ref": "C10.4.4",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "all MCP servers enforce strict schema validation.",
   "question": "Do current review records cover tool implementation code for input validation against the declared JSON schema?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review tool implementation code for input validation against the declared JSON schema; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test with: (1) wrong types (string where number expected), (2) values outside declared ranges, (3) extra parameters not in the schema, (4) oversized string values, (5) nested objects where scalars are expected; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 159,
   "ref": "C10.4.5",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "all MCP transports enforce maximum payload size limits.",
   "question": "Do exercise results cover every enabled transport with oversized bodies, chunked requests exceeding the configured cap, malformed JSON, invalid UTF-8, truncated frames, concurrent SSE streams, replayed Last-Event-ID values, missing Content-Type, unexpected Accept, absent?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Exercise every enabled transport with oversized bodies, chunked requests exceeding the configured cap, malformed JSON, invalid UTF-8, truncated frames, concurrent SSE streams, replayed Last-Event-ID values, missing Content-Type, unexpected Accept, absent…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm limits are enforced before parsing or dispatching tools, memory remains bounded, errors are sanitized, and reverse-proxy limits match server-side limits; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 160,
   "ref": "C10.4.6",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP servers sign tool responses with a unique nonce and timestamp so MCP clients can detect replay attempts.",
   "question": "Do current inspection records cover whether server-to-client responses include a signature over the canonical payload, timestamp, nonce, signer identity, method/tool binding, and relevant session or request context?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect whether server-to-client responses include a signature over the canonical payload, timestamp, nonce, signer identity, method/tool binding, and relevant session or request context; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Replay the same signed response, modify one byte of the payload, skew timestamps outside the accepted window, reuse a nonce, and swap responses across tools or users; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 161,
   "ref": "C10.4.7",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP clients present users with explicit consent dialogue and cancellation options upon installation of a local MCP server.",
   "question": "Can the accountable control owner provide current design and operating evidence for install a local server through every supported path: UI marketplace, project file, imported configuration, registry link, extension, and command-line helper?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Install a local server through every supported path: UI marketplace, project file, imported configuration, registry link, extension, and command-line helper; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify the consent dialog shows the exact command and arguments without truncation, identifies that code will execute locally, names the publisher or source, and offers an effective cancel option; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 162,
   "ref": "C10.4.8",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "MCP clients maintain a snapshot of tool definitions and that any change to a tool definition triggers re-approval before the modified tool can be invoked.",
   "question": "Can the accountable control owner provide current design and operating evidence for capture a canonical snapshot of each tool name, description, input schema, output schema, annotations, and server identity at approval time?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Capture a canonical snapshot of each tool name, description, input schema, output schema, annotations, and server identity at approval time; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Modify a tool definition on the server, trigger notifications/tools/list_changed, restart the client, and verify the client detects the drift, blocks invocation, shows a semantic diff, and requires re-approval before use; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": "Art14.4 — implementation evidence only"
  },
  {
   "num": 163,
   "ref": "C10.4.9",
   "part": 13,
   "title": "Schema, Message, and Input Validation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "MCP proxy servers using a shared upstream OAuth client identity do not allow a requesting MCP client to inherit authorization established for a different MCP client.",
   "question": "Do current inspection records cover proxy authorization state keyed by requesting client identity?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect proxy authorization state keyed by requesting client identity; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: test two clients sharing an upstream OAuth identity and confirm that authorization granted to one client is rejected for the other; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.14, A.5.15, A.8.20, A.8.21, A.8.26",
   "nistCsf": "PR.AA-03, PR.AA-05, PR.DS-02",
   "nis2": "Art21.2.e, Art21.2.h, Art21.2.i",
   "aiAct": ""
  },
  {
   "num": 164,
   "ref": "C11.1.1",
   "part": 14,
   "title": "Model Alignment, Safety, and Robustness Testing and Training",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "the model has undergone alignment and safety training or fine-tuning to prevent the model from generating disallowed content categories.",
   "question": "Do current review records cover guardrail configuration (system prompts, output filters, classifier layers). 2?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Review guardrail configuration (system prompts, output filters, classifier layers). 2; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test with known disallowed- content prompts across all categories. 3; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.2.d — supporting measure only"
  },
  {
   "num": 165,
   "ref": "C11.1.2",
   "part": 14,
   "title": "Model Alignment, Safety, and Robustness Testing and Training",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "a version-controlled alignment test suite is run on every model update or release.",
   "question": "Do current inspection records cover CI/CD for alignment test integration. 2?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect CI/CD for alignment test integration. 2; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify test suite in version control. 3; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 166,
   "ref": "C11.1.3",
   "part": 14,
   "title": "Model Alignment, Safety, and Robustness Testing and Training",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "models are evaluated against known adversarial attack techniques relevant to their modality.",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory every accepted input and output modality, plus every conversion path, before selecting test cases?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory every accepted input and output modality, plus every conversion path, before selecting test cases; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For text, cover direct and indirect prompt injection, adversarial suffixes, encoding and Unicode transformations, multilingual paraphrases, and multi-turn escalation; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.6 — implementation evidence only"
  },
  {
   "num": 167,
   "ref": "C11.1.4",
   "part": 14,
   "title": "Model Alignment, Safety, and Robustness Testing and Training",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "models are hardened against adversarial inputs.",
   "question": "Can the accountable control owner provide current design and operating evidence for map each implemented hardening layer to the relevant attack families identified under 11.1.3?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Map each implemented hardening layer to the relevant attack families identified under 11.1.3; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Evidence may include adversarial training or fine-tuning, input canonicalization, modality-specific preprocessing and detectors, input and output classifiers, context isolation, or constrained generation, but each claimed layer must be exercised rather than…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 168,
   "ref": "C11.1.5",
   "part": 14,
   "title": "Model Alignment, Safety, and Robustness Testing and Training",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "an automated evaluator measures harmful-content rate and flags regressions beyond a defined threshold.",
   "question": "Can the accountable control owner provide current design and operating evidence for keep the harmful-content corpus and taxonomy in version control?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Keep the harmful-content corpus and taxonomy in version control; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Each case should have a stable ID, harm category, modality and language, expected label or rubric, provenance, and applicability metadata; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 169,
   "ref": "C11.2.1",
   "part": 14,
   "title": "Membership-Inference and Model-Inversion Mitigation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "model-inferred sensitive attributes are not directly returned in outputs.",
   "question": "Can the accountable control owner provide current design and operating evidence for red-team the deployed endpoint with attribute-inference probes and model-inversion reconstructions (e.g., the methods catalogued in the *Model Inversion Attacks* survey, arXiv:2411.10023)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Red-team the deployed endpoint with attribute-inference probes and model-inversion reconstructions (e.g., the methods catalogued in the *Model Inversion Attacks* survey, arXiv:2411.10023); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: confirm outputs, logprobs, and any explanation/counterfactual surfaces do not echo sensitive fields; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.a — implementation evidence only"
  },
  {
   "num": 170,
   "ref": "C11.2.2",
   "part": 14,
   "title": "Membership-Inference and Model-Inversion Mitigation",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "inference endpoints enforce per-principal and global rate limits sized to the extraction threat model, and not solely as a generic API throttle.",
   "question": "Do current inspection records cover gateway/WAF config (e.g., Kong, Envoy, AWS API Gateway, Cloudflare) for per-API-key/per-tenant *and* global quotas tuned to the extraction budget, not a generic 429 throttle?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect gateway/WAF config (e.g., Kong, Envoy, AWS API Gateway, Cloudflare) for per-API-key/per-tenant *and* global quotas tuned to the extraction budget, not a generic 429 throttle; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: verify limits cover logprob/embedding/explanation endpoints, not just chat; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 171,
   "ref": "C11.2.3",
   "part": 14,
   "title": "Membership-Inference and Model-Inversion Mitigation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "model outputs are calibrated to reduce overconfident predictions.",
   "question": "Can the accountable control owner provide current design and operating evidence for measure calibration (ECE, reliability diagrams) before/after temperature or ensemble scaling (e.g., GETS ensemble temperature scaling, ICLR 2025)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Measure calibration (ECE, reliability diagrams) before/after temperature or ensemble scaling (e.g., GETS ensemble temperature scaling, ICLR 2025); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: re-run a confidence-based MIA (IBM ART, Privacy Meter) and confirm the post-calibration attack AUC drops; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art14.4.c — supporting measure only"
  },
  {
   "num": 172,
   "ref": "C11.2.4",
   "part": 14,
   "title": "Membership-Inference and Model-Inversion Mitigation",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "training on sensitive datasets employs differentially-private optimization.",
   "question": "Does current control evidence confirm DP-SGD (or a DP variant) is actually wired in -- inspect Opacus (Fast Gradient Clipping / Ghost Clipping since Aug 2024, FSDP2 support mid-2025, documented LoRA+peft path Dec 2024), TensorFlow Privacy, AWS fastDP, JAX-Privacy, or FlashDP config?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm DP-SGD (or a DP variant) is actually wired in -- inspect Opacus (Fast Gradient Clipping / Ghost Clipping since Aug 2024, FSDP2 support mid-2025, documented LoRA+peft path Dec 2024), TensorFlow Privacy, AWS fastDP, JAX- Privacy, or FlashDP config; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: record the (epsilon, delta) budget and the privacy unit (per-example vs per-user, COLM 2024); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 173,
   "ref": "C11.2.5",
   "part": 14,
   "title": "Membership-Inference and Model-Inversion Mitigation",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "membership-inference attack simulations demonstrate that attack accuracy does not exceed random guessing on evaluated data.",
   "question": "Do current execution results cover a multi-attack ensemble rather than a single method (CCS 2025 shows single-attack audits are unreliable) using maintained harnesses (IBM ART membership-inference module, Privacy Meter) plus current research attacks?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Run a multi-attack ensemble rather than a single method (CCS 2025 shows single-attack audits are unreliable) using maintained harnesses (IBM ART membership-inference module, Privacy Meter) plus current research attacks; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: report results at fixed low-FPR operating points (CMIA: >5x LiRA TPR at 0.001% FPR), not just aggregate AUC; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 174,
   "ref": "C11.3.1",
   "part": 14,
   "title": "Model-Extraction Defense",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "query-pattern analysis feeds an extraction-attempt detector.",
   "question": "Does current control evidence confirm a detector actually consumes query- pattern features rather than just a generic throttle: distribution-shift testing (PRADA query-distribution analysis?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm a detector actually consumes query-pattern features rather than just a generic throttle: distribution-shift testing (PRADA query- distribution analysis; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: the June 2026 MMD two- sample detector over bge-small embeddings reporting 95.1% balanced accuracy at 0.3% FP), account- similarity encoders (SEAT), and ATOM-style RL detection; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 175,
   "ref": "C11.3.2",
   "part": 14,
   "title": "Model-Extraction Defense",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "raw model outputs are not directly exposed beyond the application backend, and that externally visible responses are calibrated to the extraction risk level.",
   "question": "Does current control evidence confirm raw logits, full probability vectors, and internal reasoning traces are not exposed beyond the backend, and that externally visible responses are minimized?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm raw logits, full probability vectors, and internal reasoning traces are not exposed beyond the backend, and that externally visible responses are minimized; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check whether output minimization uses a measured information-leakage objective — ModelGuard information-theoretic perturbation (USENIX Security 2024) or Fang et al. logit purification minimizing conditional mutual information (May 2026) — rather than ad-hoc…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.d — supporting measure only"
  },
  {
   "num": 176,
   "ref": "C11.3.3",
   "part": 14,
   "title": "Model-Extraction Defense",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "model watermarking or fingerprinting techniques are applied so that unauthorized copies can be identified.",
   "question": "Does current control evidence confirm a watermark or fingerprint is genuinely embedded and survives the full deployment pipeline (fine-tuning, quantization, distillation, paraphrasing, merge)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm a watermark or fingerprint is genuinely embedded and survives the full deployment pipeline (fine-tuning, quantization, distillation, paraphrasing, merge); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Favor schemes designed for that survival: ModelShield (IEEE TIFS 2025), Neural Honeytrace (training-free, 200-sample claim), SemMark/GuardEmb for embedding services, Functional Subspace Watermarking, iSeal (AAAI 2026, resistant to thief-controlled…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — supporting measure only"
  },
  {
   "num": 177,
   "ref": "C11.3.4",
   "part": 14,
   "title": "Model-Extraction Defense",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "detection of suspected extraction triggers response measures.",
   "question": "Does current control evidence confirm detector signals can drive gateway actions — challenge, throttle, custom response, timeout, block (Cloudflare) — and graduated output degradation proportional to suspicion (RADEP), reserving poisoning-style traps (HoneypotNet, AMAO) as a last resort?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm detector signals can drive gateway actions — challenge, throttle, custom response, timeout, block (Cloudflare) — and graduated output degradation proportional to suspicion (RADEP), reserving poisoning-style traps (HoneypotNet, AMAO) as a last resort; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify an extraction-specific incident-response playbook aligned to the CoSAI AI Incident Response Framework v1.0, NIST SP 800- 61r3, OASIS CACAO, and GenAI-IRF, including model-version rollback; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 178,
   "ref": "C11.4.1",
   "part": 14,
   "title": "Model Runtime Anomaly Detection",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "inputs from external or untrusted sources pass through anomaly detection before model inference.",
   "question": "Does the maintained inventory and test record cover every external ingestion point (retrieval, tool/MCP responses, memory reads, web scrape) and confirm each routes through a pre-inference detector?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Enumerate every external ingestion point (retrieval, tool/MCP responses, memory reads, web scrape) and confirm each routes through a pre- inference detector; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Look for retriever-stage filtering (GMTP, RAGMask, ProGRank), hybrid BM25+dense retrieval, HTML/Markdown sanitization plus NFKC normalization (OpenRAG-Soc), post-retrieval isolation (RAGDefender), and schema quarantine + SHA- 256 tool pinning for MCP…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 179,
   "ref": "C11.4.2",
   "part": 14,
   "title": "Model Runtime Anomaly Detection",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "inputs flagged as anomalous trigger gating actions.",
   "question": "Does current control evidence confirm flagged inputs are blocked, quarantined, down-ranked, or routed to human review -- not merely logged?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm flagged inputs are blocked, quarantined, down-ranked, or routed to human review -- not merely logged; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Exercise gating layers: NeMo Guardrails input/retrieval/execution rails, Lakera Guard L1--L4, Meta LlamaFirewall, Bedrock contextual grounding, trust-weighted retrieval (ASI06), stateful cross-stage trust scoring (MMA-RAG^T), hard-block on tool-hash…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art9.2.d — supporting measure only"
  },
  {
   "num": 180,
   "ref": "C11.4.3",
   "part": 14,
   "title": "Model Runtime Anomaly Detection",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "the safety violation feedback pipeline includes poisoning detection and human review gates to prevent adversarial manipulation of the improvement mechanism.",
   "question": "Does current control evidence confirm safety-violation and feedback data is screened for poisoning *before* it feeds retraining, fine-tuning, or memory updates, and that human review gates sit on flagged feedback?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm safety-violation and feedback data is screened for poisoning *before* it feeds retraining, fine-tuning, or memory updates, and that human review gates sit on flagged feedback; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Check write-time provenance and authorization on memory writes (OWASP Agent Memory Guard, ASI06 provenance/expiry), cross- model verification on high-impact updates (Microsoft CMVK), and traceback for post-incident cleanup (RAGForensics); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.8.8, A.8.16, A.8.29",
   "nistCsf": "DE.CM-09, ID.RA-01, PR.PS-06",
   "nis2": "Art21.2.e, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 181,
   "ref": "C12.1.1",
   "part": 15,
   "title": "Request & Response Logging",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "AI interactions are logged with session context and AI-specific telemetry.",
   "question": "Do current inspection records cover exported OTel spans/logs for timestamp, user/principal ID, session/conversation ID (gen_ai.conversation.id), and model version on every inference?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inspect exported OTel spans/logs for timestamp, user/principal ID, session/conversation ID (gen_ai.conversation.id), and model version on every inference; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Replay one request end-to-end and confirm correlation IDs survive each hop; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 182,
   "ref": "C12.1.2",
   "part": 15,
   "title": "Request & Response Logging",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "safety filtering and policy decisions are logged with sufficient detail to support audit, debugging, and forensic analysis of content moderation systems.",
   "question": "Does current control evidence confirm policy-decision events carry rule/policy ID, decision outcome, classifier confidence/score, category, applied stage (input prompt vs output completion), actor, request ID (gen_ai.response.id), and a normalized error class -- and that bypass attempts?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm policy-decision events carry rule/policy ID, decision outcome, classifier confidence/score, category, applied stage (input prompt vs output completion), actor, request ID (gen_ai.response.id), and a normalized error class -- and that bypass attempts…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Confirm spans also carry gen_ai.usage.input_tokens/output_tokens, a salted SHA-256 input hash computed pre-redaction, a prompt-version link (Langfuse langfuse_prompt, LangSmith owner/name:commit), and provider confidence (Azure severity, Vertex…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 183,
   "ref": "C12.1.3",
   "part": 15,
   "title": "Request & Response Logging",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "log entries for AI inference events follow a structured, interoperable schema that includes at least the model identifier, token usage (input and output), provider name, and operation type.",
   "question": "Does current control evidence confirm spans follow the OTel GenAI semantic conventions: gen_ai.request.model **and** gen_ai.response.model (the served snapshot), gen_ai.provider.name, gen_ai.operation.name, and gen_ai.usage.input_tokens/output_tokens?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm spans follow the OTel GenAI semantic conventions: gen_ai.request.model **and** gen_ai.response.model (the served snapshot), gen_ai.provider.name, gen_ai.operation.name, and gen_ai.usage.input_tokens/output_tokens; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Diff requested vs served model on every span and alert on drift; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 184,
   "ref": "C12.1.4",
   "part": 15,
   "title": "Request & Response Logging",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "RAG pipeline retrieval events are logged, including the query, documents retrieved, and knowledge source.",
   "question": "Does current control evidence confirm each retrieval emits an OTel GenAI CLIENT span with gen_ai.operation.name=retrieval, gen_ai.data_source.id, gen_ai.retrieval.query.text, and gen_ai.retrieval.documents entries containing at least document id and score?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm each retrieval emits an OTel GenAI CLIENT span with gen_ai.operation.name=retrieval, gen_ai.data_source.id, gen_ai.retrieval.query.text, and gen_ai.retrieval.documents entries containing at least document id and score; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: also record gen_ai.retrieval.top_k when set; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 185,
   "ref": "C12.2.1",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "the system detects and alerts on known jailbreak patterns, prompt injection attempts, and adversarial inputs.",
   "question": "Can the accountable control owner provide current design and operating evidence for replay JailbreakBench/PromptInject and BoN/Unicode variants through the detector?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Replay JailbreakBench/PromptInject and BoN/Unicode variants through the detector; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: confirm alerts fire with a verdict, matched signature ID, and confidence; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 186,
   "ref": "C12.2.2",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "behavioral anomaly detection identifies unusual conversation patterns, excessive retry attempts, or probing behaviors.",
   "question": "Can the accountable control owner provide current design and operating evidence for establish per-user/per-session baselines (retry rate, input-diversity score, query timing, conversation-embedding trajectory) and confirm deviations alert?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Establish per-user/per-session baselines (retry rate, input-diversity score, query timing, conversation-embedding trajectory) and confirm deviations alert; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run session-level trajectory analysis: DeepContext (Feb 2026, RNN hidden-state propagation, 0.84 F1 at sub-20ms) outperforms stateless Llama-Prompt-Guard-2 (0.67 F1); including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art55.1.b — supporting measure only"
  },
  {
   "num": 187,
   "ref": "C12.2.3",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "custom rules detect AI-specific threat patterns for coordinated jailbreak attempts, prompt injection, and system prompt extraction attempts.",
   "question": "Can the accountable control owner provide current design and operating evidence for map custom SIEM rules to ATLAS techniques (v2026.05 tags every technique with Predictive/Generative/Agentic/Enterprise platform)?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Map custom SIEM rules to ATLAS techniques (v2026.05 tags every technique with Predictive/Generative/Agentic/Enterprise platform); refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run rules over **agent action telemetry** (tool, arguments, identity, data object), not prompt content alone, and correlate across users/IPs/time windows for coordinated campaigns; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art15.5 — implementation evidence only"
  },
  {
   "num": 188,
   "ref": "C12.2.4",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "extraction-alert events include offending query metadata to support investigation.",
   "question": "Does current control evidence confirm each extraction/security alert carries the offending query (or hash), model/agent ID, detector confidence, policy action, request ID, and (for indirect injection) source URL plus content hash?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm each extraction/security alert carries the offending query (or hash), model/agent ID, detector confidence, policy action, request ID, and (for indirect injection) source URL plus content hash; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: A distribution-based detector (arxiv:2606.05725, Jun 2026) applies Maximum Mean Discrepancy over query-embedding windows with a benign-calibrated threshold: 0.3% FPR, 100% TPR for pure-attacker and 90.5% across mixed-user traffic (95.1% balanced accuracy),…; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art55.1.d — implementation evidence only"
  },
  {
   "num": 189,
   "ref": "C12.2.5",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "token usage is tracked at granular attribution levels including per user, per session, per feature endpoint, and per team or workspace.",
   "question": "Do metering dashboards and sampled billing records attribute AI consumption to the initiating identity, interaction, product capability, and accountable workspace?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm token counters are keyed at the required attribution levels: per user, per session, per feature endpoint, and per team or workspace, with threshold alerts and budget caps at each level; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run two users across multiple sessions and feature endpoints in one workspace and a third user in a second workspace; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 190,
   "ref": "C12.2.6",
   "part": 15,
   "title": "Detection and Alerting",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "LLM API traffic is monitored for covert-channel indicators and communication signatures to identify malware and command-and-control (C2) activity.",
   "question": "Can the accountable control owner provide current design and operating evidence for monitor unauthorized outbound calls to AI API endpoints, DNS queries to AI service domains from unexpected processes, and entropy anomalies in request/response payloads?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Monitor unauthorized outbound calls to AI API endpoints, DNS queries to AI service domains from unexpected processes, and entropy anomalies in request/response payloads; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: treat AI domains as high-value egress points and alert on automated/unusual usage; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art72"
  },
  {
   "num": 191,
   "ref": "C12.3.1",
   "part": 16,
   "title": "Model, Data, and Performance Drift Detection",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "data drift detection monitors input distribution changes that may impact model performance, using statistically validated methods matched to the input data type (e.g., KS test or PSI for tabular numeric features, embedding-distance metrics for text or image).",
   "question": "Can the accountable control owner provide current design and operating evidence for inventory each production field and modality, then verify that it has a versioned reference window, minimum sample size, test appropriate to its data type, calibrated threshold, slice dimensions, alert owner, and retained samples?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Inventory each production field and modality, then verify that it has a versioned reference window, minimum sample size, test appropriate to its data type, calibrated threshold, slice dimensions, alert owner, and retained samples; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Run negative tests that inject a known numeric, categorical, text-embedding, and image-embedding shift; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 192,
   "ref": "C12.3.2",
   "part": 16,
   "title": "Model, Data, and Performance Drift Detection",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "hallucination detection monitors identify and flag model outputs that contain factually incorrect, inconsistent, or fabricated information.",
   "question": "Do trace records cover a sampled response from generation through a groundedness, factuality, contradiction, self-consistency, or uncertainty scorer to its stored flag and reviewer queue?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Trace a sampled response from generation through a groundedness, factuality, contradiction, self-consistency, or uncertainty scorer to its stored flag and reviewer queue; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Test the monitor with task- specific known-faithful and known-hallucinated cases, including unsupported citations and contradictions with retrieved context; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art72"
  },
  {
   "num": 193,
   "ref": "C12.3.3",
   "part": 16,
   "title": "Model, Data, and Performance Drift Detection",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "hallucination rates are tracked as continuous time-series metrics to enable trend analysis and detection of sustained model degradation.",
   "question": "Do current verification results show that flagged and evaluated response counts produce a time-stamped rate with an explicit numerator, denominator, sampling policy, confidence interval, and minimum-volume rule?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Verify that flagged and evaluated response counts produce a time-stamped rate with an explicit numerator, denominator, sampling policy, confidence interval, and minimum-volume rule; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: The series should retain model, prompt, retrieval-index, detector, detector-version, tenant, task, language, and release dimensions; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art72"
  },
  {
   "num": 194,
   "ref": "C12.3.4",
   "part": 16,
   "title": "Model, Data, and Performance Drift Detection",
   "levels": [
    "L3"
   ],
   "weight": 7,
   "requirement": "unexplained behavioral shifts are distinguished from gradual, expected operational drift.",
   "question": "Does current control evidence confirm drift events are correlated against an authoritative change timeline covering deployments, prompts, data and retrieval updates, provider routes, feature flags, policies, and known seasonal transitions?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm drift events are correlated against an authoritative change timeline covering deployments, prompts, data and retrieval updates, provider routes, feature flags, policies, and known seasonal transitions; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Exercise two cases: a gradual documented population shift that is classified as expected and an abrupt behavior change with no matching change record that triggers security triage; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art15.1 — implementation evidence only"
  },
  {
   "num": 195,
   "ref": "C12.4.1.a",
   "part": 16,
   "title": "Proactive Security Behavior Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "autonomous action triggers include proactive behavior-pattern analysis, security evaluation, and threat-landscape assessment.",
   "question": "Does each autonomous-action trigger evaluate recent behavioural patterns and block execution when activity falls outside the approved operating profile?",
   "evidence": [
    "AI operations owner-approved behavioural profile and trigger policy defining baselines, deviations, decision thresholds, and block actions",
    "Latest replay or simulation results showing autonomous actions allowed for normal behaviour and blocked for anomalous sequences"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 196,
   "ref": "C12.4.1.b",
   "part": 16,
   "title": "Proactive Security Behavior Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "autonomous action triggers include proactive behavior-pattern analysis, security evaluation, and threat-landscape assessment.",
   "question": "Is an independent security evaluation completed and recorded before each high- impact proactive action is authorised for execution?",
   "evidence": [
    "Security architecture owner-approved pre-action evaluation procedure defining impact tiers, required checks, and approval authority",
    "Recent high-impact action samples showing completed evaluation, findings, decision, approver, and execution correlation"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 197,
   "ref": "C12.4.1.c",
   "part": 16,
   "title": "Proactive Security Behavior Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "autonomous action triggers include proactive behavior-pattern analysis, security evaluation, and threat-landscape assessment.",
   "question": "Do proactive-action policies incorporate current threat intelligence and retain evidence showing how relevant threats changed the execution decision?",
   "evidence": [
    "Threat intelligence owner-maintained integration design mapping intelligence sources and threat categories to autonomous-action policy inputs",
    "Latest decision records demonstrating threat-context ingestion, policy effect, reviewer disposition, and stale-feed handling"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": ""
  },
  {
   "num": 198,
   "ref": "C12.4.2",
   "part": 16,
   "title": "Proactive Security Behavior Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "audit logs capture security-critical proactive actions, including approver identity, timestamp, action parameters, and decision outcomes.",
   "question": "Can the accountable control owner provide current design and operating evidence for select samples across scheduled, event-driven, peer-agent, and delegated actions, then join the trigger, policy decision, approval, tool call, and outcome by stable action and tool-call identifiers?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Select samples across scheduled, event- driven, peer-agent, and delegated actions, then join the trigger, policy decision, approval, tool call, and outcome by stable action and tool-call identifiers; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Verify each record contains the approver's accountable identity (or the named automated policy for an auto-decision), trusted timestamp, parameter digest or redacted parameters, allow/deny/timeout outcome, policy version, and execution result; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 199,
   "ref": "C12.4.3",
   "part": 16,
   "title": "Proactive Security Behavior Monitoring",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "kill-switch activations and override commands are logged.",
   "question": "Does current control evidence confirm every kill-switch activation, circuit-breaker trip, and override command emits an immutable, time-stamped audit record capturing the actor or rule that fired it, the triggering condition, the scope of the halt (single agent, session, or fleet), the?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm every kill-switch activation, circuit-breaker trip, and override command emits an immutable, time-stamped audit record capturing the actor or rule that fired it, the triggering condition, the scope of the halt (single agent, session, or fleet), the…; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Trigger a kill switch in a controlled test and confirm the activation source, timestamp, affected agents, and downstream propagation are all logged; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 200,
   "ref": "C12.5.1",
   "part": 16,
   "title": "Training Data & Model Lifecycle Audit",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "dataset lineage records each dataset and its components, including all transformations, augmentations, and merges.",
   "question": "Does current control evidence confirm a lineage graph links every training artifact back to source datasets, the exact transformation/augmentation/merge steps, and the code/parameters that produced them?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm a lineage graph links every training artifact back to source datasets, the exact transformation/augmentation/merge steps, and the code/parameters that produced them; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Reproduce a sample model input from recorded lineage and confirm byte-equivalence or a recorded content hash; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art11.1 — implementation evidence only"
  },
  {
   "num": 201,
   "ref": "C12.5.2",
   "part": 16,
   "title": "Training Data & Model Lifecycle Audit",
   "levels": [
    "L1",
    "L2",
    "L3"
   ],
   "weight": 9,
   "requirement": "all labeling activities are recorded in logs.",
   "question": "Does current control evidence confirm the annotation platform emits an activity log capturing who labeled/relabeled each item, the before/after value, timestamp, and the labeling guideline version, then confirm access and retention controls protect that evidence?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm the annotation platform emits an activity log capturing who labeled/relabeled each item, the before/after value, timestamp, and the labeling guideline version, then confirm access and retention controls protect that evidence; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Review Label Studio annotation history (an Enterprise feature), Amazon SageMaker Ground Truth WorkerActivity logs, output manifests, or equivalent; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art12"
  },
  {
   "num": 202,
   "ref": "C12.5.3",
   "part": 16,
   "title": "Training Data & Model Lifecycle Audit",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "all model changes generate immutable audit records.",
   "question": "Does current control evidence confirm every deployment, config change, alias/stage transition, and retirement produces a tamper-evident record with actor identity, timestamp, artifact digest, and change parameters?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Confirm every deployment, config change, alias/stage transition, and retirement produces a tamper-evident record with actor identity, timestamp, artifact digest, and change parameters; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: Cross-check the model-registry log against an independently administered infrastructure log; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art11.1 — implementation evidence only"
  },
  {
   "num": 203,
   "ref": "C12.5.4",
   "part": 16,
   "title": "Training Data & Model Lifecycle Audit",
   "levels": [
    "L2",
    "L3"
   ],
   "weight": 8,
   "requirement": "every ingested document is tagged at write time with source, writer identity, and timestamp.",
   "question": "Can the accountable control owner provide current design and operating evidence for sample documents/chunks in the vector store or knowledge base and confirm each carries, in its metadata payload, the source URI/origin, the ingesting writer or service identity, and a write-time timestamp -- stamped at ingest, not derived later?",
   "evidence": [
    "Control owner-approved design or review record demonstrating: Sample documents/chunks in the vector store or knowledge base and confirm each carries, in its metadata payload, the source URI/origin, the ingesting writer or service identity, and a write-time timestamp -- stamped at ingest, not derived later; refreshed after material architecture, model, or policy changes",
    "Latest release or quarterly operating-effectiveness record demonstrating: For media/documents, verify cryptographic provenance via C2PA / Content Credentials manifests; including observed result, reviewer, exceptions, and remediation status"
   ],
   "iso27001": "A.5.25, A.8.15, A.8.16",
   "nistCsf": "DE.AE-02, DE.AE-03, DE.CM-09, RS.AN-03",
   "nis2": "Art21.2.b, Art21.2.f",
   "aiAct": "Art11.1 — implementation evidence only"
  }
 ]
} as const;
