/**
 * tidCmmModel.ts — canonical TID-CMM (Threat-Informed Detection Capability Maturity Model) v1.5.0
 * model, fetched from https://tid-cmm.com/api/model.json. Author: Reza Adineh. Licence: CC-BY-4.0.
 * 8 domains / 58 sub-capabilities scored 0–5 (or NA), maturity bands L0–L5, per-sub-capability level
 * descriptors, constraints, and crosswalks (NIST CSF 2.0 / SOC-CMM / …). Aligned to MITRE ATT&CK v19.2.
 * Companion response model: TIR-CMM. Powers /tid-cmm. Refresh: import_tidcmm.py --refresh-model
 */
export const TID_CMM_MODEL = {
 "model": {
  "id": "TID-CMM",
  "name": "Threat-Informed Detection Capability Maturity Model",
  "short_name": "TID-CMM",
  "version": "1.5.0",
  "documents_version": "1.4",
  "site_updated": "2026-08-20",
  "released": "2026-08-17",
  "originated": "2022",
  "first_published": "2026-08-10",
  "author": "Reza Adineh",
  "slogan": "Think smarter, Stay Secure",
  "homepage": "https://tid-cmm.com",
  "repository": "https://github.com/ReZaAdineH/tid-cmm",
  "contact": "hello@tid-cmm.com",
  "licence": "CC-BY-4.0",
  "licensing": {
   "open_model": "CC-BY-4.0",
   "open_data": "CC-BY-4.0",
   "assessment_tool": "Free to use for any purpose including commercial assessment work. Not open source; not licensed for redistribution or derivative tooling.\n"
  },
  "abstract": "TID-CMM measures whether an organisation's detection capability is genuinely driven by adversary behaviour, and whether that capability has been proven to work. It scores eight domains from 0 to 5, anchors coverage claims to MITRE ATT&CK at technique level, and requires adversarial validation as evidence — a control is not \"detected\" until an emulated adversary has triggered it. High-fidelity detection means covering the context-rich, high-impact threats first; identifying those requires mapping the attack surface and building attack trees to crown jewels. A technique detection that does not contribute to narrating a full attack scenario is telemetry, not defence.\n",
  "positioning": "TID-CMM operates within UTIOM (the Unified Threat-Informed Operations Model, utiom doctrine: everything in the SOC is Incident Response). Detection is the first phase of IR; TID-CMM measures how mature and ready that phase is. It is deliberately partial on the later IR phases — containment, recovery and crisis management are UTIOM's territory — which is why the IR domain carries a deliberately modest weight here. The model is technology-agnostic: no level requires a specific product, agent or analytic technique. It applies equally to cloud (AWS, Azure, GCP), SaaS, on-premises and hybrid estates, with or without EDR; what changes per environment is which telemetry is crucial, and the tooling advises on that from ATT&CK data-component mappings.\n"
 },
 "alignment": {
  "attack": {
   "framework": "MITRE ATT&CK Enterprise",
   "version": "19.2",
   "snapshot_date": "2026-08-05",
   "techniques": 697,
   "parent_techniques": 222,
   "sub_techniques": 475,
   "tactics": 15,
   "data_components": 109
  },
  "crosswalks": [
   {
    "id": "nist-csf-2.0",
    "name": "NIST Cybersecurity Framework 2.0",
    "key": "nist_csf_2",
    "relationship": "formal_crosswalk",
    "coverage": "all_sub_capabilities"
   },
   {
    "id": "soc-cmm",
    "name": "SOC-CMM v2.x",
    "key": "soc_cmm",
    "relationship": "formal_crosswalk",
    "coverage": "all_sub_capabilities"
   }
  ],
  "comparative": [
   {
    "id": "iso-27001-2022",
    "name": "ISO/IEC 27001:2022 Annex A",
    "key": "iso_27001_2022",
    "relationship": "referenced",
    "note": "Referenced where an Annex A control maps cleanly, principally A.8.16."
   },
   {
    "id": "ctem",
    "name": "Gartner Continuous Threat Exposure Management",
    "key": "ctem",
    "relationship": "positioning",
    "note": "CTEM asks whether an exposure is exploitable; TID-CMM asks whether the exploitation would be seen."
   },
   {
    "id": "debmm",
    "name": "Elastic Detection Engineering Behavior Maturity Model",
    "key": "debmm",
    "relationship": "positioning",
    "note": "DEBMM covers engineering practice; TID-CMM covers whether that practice is aimed at the right adversary and proven against them."
   },
   {
    "id": "mitre-engage",
    "name": "MITRE Engage",
    "key": "mitre_engage",
    "relationship": "referenced",
    "note": "Supplies the placement and operationalisation vocabulary used by AA.7."
   },
   {
    "id": "mitre-d3fend",
    "name": "MITRE D3FEND",
    "key": "d3fend",
    "relationship": "not_mapped",
    "note": "Listed in earlier releases as a crosswalk. No sub-capability carries a D3FEND mapping, so it is recorded here as unmapped rather than claimed."
   }
  ]
 },
 "levels": [
  {
   "value": 0,
   "key": "absent",
   "name": "Absent",
   "summary": "The capability does not exist in any recognisable form.",
   "evidence_bar": "Nothing to show."
  },
  {
   "value": 1,
   "key": "ad_hoc",
   "name": "Ad hoc",
   "summary": "Happens occasionally, driven by individual initiative or an incident. Undocumented, unrepeatable, lost when the individual leaves.\n",
   "evidence_bar": "Anecdote, a person who \"knows how\"."
  },
  {
   "value": 2,
   "key": "repeatable",
   "name": "Repeatable",
   "summary": "Documented and consistently performed, but driven by compliance, tooling defaults or vendor content rather than by adversary behaviour.\n",
   "evidence_bar": "A written procedure and proof it was followed more than once."
  },
  {
   "value": 3,
   "key": "threat_informed",
   "name": "Threat-Informed",
   "summary": "Driven by a prioritised adversary profile. Work is explicitly mapped to ATT&CK techniques and traceable back to an intelligence requirement or a threat model.\n",
   "evidence_bar": "ATT&CK-mapped artefacts with traceability to a threat driver."
  },
  {
   "value": 4,
   "key": "validated",
   "name": "Measured & Validated",
   "summary": "Quantitatively managed and independently proven. Claims are tested by emulation, results are measured over time, and gaps enter a managed backlog.\n",
   "evidence_bar": "Test results, trended metrics, closed-loop backlog records."
  },
  {
   "value": 5,
   "key": "adaptive",
   "name": "Adaptive",
   "summary": "A self-correcting closed loop. Change in the threat landscape automatically produces changes in telemetry, detection and validation, with measured cycle time. The organisation contributes findings back to the community.\n",
   "evidence_bar": "Automated pipeline metrics, cycle-time trends, external contributions."
  }
 ],
 "scoring": {
  "subcapability_score": "Integer 0-5, or 'NA' if formally scoped out.",
  "domain_score": "Weighted mean of in-scope sub-capability scores, using sub-capability weights.",
  "overall_score": "Weighted mean of domain scores using domain weights. Reported to 2 decimals.",
  "maturity_band": [
   {
    "min": 0,
    "max": 0.99,
    "band": "Level 0 — Absent"
   },
   {
    "min": 1,
    "max": 1.99,
    "band": "Level 1 — Ad hoc"
   },
   {
    "min": 2,
    "max": 2.99,
    "band": "Level 2 — Repeatable"
   },
   {
    "min": 3,
    "max": 3.99,
    "band": "Level 3 — Threat-Informed"
   },
   {
    "min": 4,
    "max": 4.99,
    "band": "Level 4 — Measured & Validated"
   },
   {
    "min": 5,
    "max": 5,
    "band": "Level 5 — Adaptive"
   }
  ],
  "constraints": [
   {
    "id": "C1",
    "name": "Validation ceiling",
    "rule": "No domain may be scored above the AV domain score + 1. You cannot claim measured, validated detection engineering if you have never emulated an adversary against it.\n"
   },
   {
    "id": "C2",
    "name": "Visibility ceiling",
    "rule": "DE (Detection Engineering) may not exceed DC (Telemetry & Detection Coverage) + 1. Detection logic cannot be more mature than the telemetry it runs on.\n"
   },
   {
    "id": "C3",
    "name": "Evidence rule",
    "rule": "Any score of 4 or 5 requires a named artefact recorded in the evidence field. Unevidenced 4s and 5s are downgraded to 3 by the scoring engine in strict mode.\n"
   },
   {
    "id": "C4",
    "name": "Intent ceiling",
    "rule": "DC and DE may not exceed max(TI, TM) + 1. Telemetry and detection content cannot be more mature than the strategy directing them. Sensors without architectural intent produce noise, not defence.\n"
   },
   {
    "id": "C5",
    "name": "Inherited intent ceiling",
    "applies_to": "TI.2",
    "ceiling": 2,
    "rule": "TI.2 may not exceed level 2 where the adversary set was accepted from the tool's suggested threat profile without modification. Accepting it unchanged means the question TI.2 asks — who are you defending against, and how do you know? — was answered by the tool, not by you. Reviewing the set lifts the ceiling: add an actor, remove one, or record why one was excluded.\n",
    "why": "A suggested profile makes the hardest step in an assessment tractable, which is why it is offered. But a model that supplies its own answer and then scores you on it is grading its own homework, and every other constraint here exists to prevent exactly that. This ceiling lets the suggestion be useful without becoming a way to score threat intelligence maturity nobody has.\n",
    "lifted_by": "Any modification to the suggested set, or a recorded rationale for accepting it unchanged.\n"
   }
  ],
  "coverage_score": {
   "name": "ATT&CK Validated Coverage Score (VCS)",
   "formula": "For each in-scope technique: 0 = no telemetry, 1 = telemetry only, 2 = detection logic exists, 3 = detection validated by emulation within the review period. VCS = sum(actual) / (3 * count(in-scope)) expressed as a percentage. Report alongside, never instead of, the domain scores.\n",
   "note": "In-scope techniques are those relevant to the organisation's platforms and prioritised threat profile — not all 697. Reporting coverage against the full ATT&CK matrix is a vanity metric.\n"
  },
  "scenario_coverage": {
   "name": "Scenario Coverage Score (SCS)",
   "principle": "A technique detection that does not contribute to narrating a full attack scenario is telemetry, not defence. A login attempt means nothing on its own; a login attempt on the path to a crown jewel, correlated with the steps before and after it, is a detection. Technique-level VCS is an early-maturity metric; scenario coverage is the mature one.\n",
   "formula": "For each prioritised attack scenario (an attack tree or emulation chain to a named crown-jewel objective): the scenario counts as covered when the chain would be detected at two or more distinct kill-chain stages, at least one of them validated by emulation. SCS = covered scenarios / prioritised scenarios, expressed as a percentage, reported with the scenario count.\n",
   "note": "Requires an attack tree or scenario register (TM.3). An organisation without one has an SCS of \"unmeasurable\", which is itself the finding.\n"
  }
 },
 "domains": [
  {
   "id": "TI",
   "name": "Threat Intelligence & Adversary Prioritisation",
   "weight": 12,
   "intent": "Establishes *who* you are defending against and *why*. Without this domain the rest of the model has no input signal — detection becomes vendor-content-driven rather than threat-informed. This domain is scored on the quality of the prioritisation decision, not on the number of feeds consumed.",
   "anti_pattern": "A large IOC feed volume with no documented threat profile. Feed count is not intelligence; it is procurement.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "TI.1",
     "name": "Intelligence requirements and PIRs",
     "weight": 18,
     "question": "Are there documented, prioritised intelligence requirements that state what the organisation needs to know, tied to business risk and to named decisions?",
     "levels": {
      "0": "No intelligence requirements exist. Collection is undirected.",
      "1": "Informal requirements held by one analyst; expressed as topics of interest rather than questions.",
      "2": "A written PIR list exists and is reviewed annually, but is generic and not tied to specific decisions.",
      "3": "PIRs are decomposed into specific intelligence requirements (SIRs) and essential elements of information (EEIs), each tied to a named decision-maker and a business risk.",
      "4": "PIR satisfaction is measured — each requirement has a coverage and confidence rating, gaps are tracked, and collection is retasked on a defined cadence.",
      "5": "PIRs are dynamically re-prioritised from operational signal (incidents, hunts, emulation results, sector reporting) with measured time-to-retask."
     },
     "evidence": [
      "Signed PIR/SIR register with named decision owners",
      "Requirement satisfaction and collection-gap tracker",
      "Retasking log with dates"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-03",
       "ID.RA-04",
       "GV.RM-01"
      ],
      "soc_cmm": [
       "Intelligence.Business",
       "Intelligence.Process"
      ],
      "iso_27001_2022": [
       "A.5.7"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "TI"
    },
    {
     "id": "TI.2",
     "name": "Threat profile and adversary prioritisation",
     "weight": 20,
     "question": "Is there a maintained, evidenced threat profile that names the actors, campaigns and behaviours most relevant to this organisation, and ranks them?",
     "levels": {
      "0": "No threat profile. \"Everyone is a target\" is the operating assumption.",
      "1": "An informal list of headline actors, largely drawn from vendor marketing and news cycles.",
      "2": "A documented threat profile exists, refreshed annually, based mainly on sector reporting.",
      "3": "Threat profile is built from sector, geography, technology stack, crown-jewel exposure and observed activity; actors are ranked by a documented relevance methodology and mapped to ATT&CK Groups and Campaigns.",
      "4": "Profile is re-scored at least quarterly against new reporting and internal telemetry; changes in ranking produce recorded downstream tasking to threat modeling, detection engineering and emulation.",
      "5": "Profile is continuously maintained, includes emerging and unattributed behaviour clusters, incorporates supply-chain and insider actors, and drives automated re-prioritisation of the detection backlog."
     },
     "evidence": [
      "Threat profile document with ranking methodology and ATT&CK Group/Campaign IDs",
      "Quarterly re-score records",
      "Tasking records showing profile change to backlog change"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-03",
       "ID.RA-05"
      ],
      "soc_cmm": [
       "Intelligence.Process"
      ]
     },
     "attack_link": "Uses ATT&CK Groups (G####), Campaigns (C####) and Software (S####).",
     "profile": "essential",
     "domain_id": "TI"
    },
    {
     "id": "TI.3",
     "name": "Technical CTI ingestion and indicator lifecycle",
     "weight": 14,
     "question": "Are technical indicators ingested, scored, deployed, aged and retired under a defined lifecycle, with measured operational value?",
     "levels": {
      "0": "No indicator ingestion, or manual copy-paste from emails.",
      "1": "Indicators are loaded ad hoc during incidents; nothing is retired.",
      "2": "A TIP or equivalent ingests feeds automatically; deduplication and basic scoring exist; retirement is manual and inconsistent.",
      "3": "Indicators carry confidence, source, ATT&CK context and expiry; deployment target (block, alert, enrich, hunt) is decided by score, not by default.",
      "4": "Indicator hit rates, false-positive rates and feed value are measured per source; low-value feeds are cancelled on the evidence.",
      "5": "Lifecycle is fully automated including sunset, with feedback from detection outcomes re-scoring source reliability, and internally derived indicators promoted back to the TIP."
     },
     "evidence": [
      "TIP configuration and lifecycle policy",
      "Per-feed hit-rate/FP report",
      "Feed decommissioning decision record"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-02",
       "DE.AE-07"
      ],
      "soc_cmm": [
       "Intelligence.Technology"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "TI"
    },
    {
     "id": "TI.4",
     "name": "TTP extraction and ATT&CK mapping discipline",
     "weight": 18,
     "question": "Is finished reporting systematically decomposed into ATT&CK-mapped adversary behaviours with enough procedural detail to build a detection from?",
     "levels": {
      "0": "Reports are read and filed. No structured extraction.",
      "1": "Analysts occasionally note technique IDs in prose.",
      "2": "Reports are tagged with ATT&CK technique IDs, mostly at parent-technique level, stored in a searchable repository.",
      "3": "Extraction reaches sub-technique and *procedure* level — the specific command line, API call, registry path or protocol behaviour — recorded in a structured schema with source citation and confidence.",
      "4": "Extraction quality is reviewed; coverage of the prioritised threat profile by extracted procedures is measured; ambiguous mappings are arbitrated and the rationale recorded.",
      "5": "Extraction is partly automated (NLP-assisted with human validation), feeds a behaviour library reused by threat modeling, detection engineering and emulation, and is contributed to community knowledge bases."
     },
     "evidence": [
      "Structured TTP/procedure library with citations",
      "Mapping quality-review records",
      "Behaviour library referenced by detection tickets"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-03",
       "ID.IM-02"
      ],
      "soc_cmm": [
       "Intelligence.Process"
      ]
     },
     "attack_link": "Mapping must reach sub-technique (T####.###) where one exists.",
     "profile": "standard",
     "domain_id": "TI"
    },
    {
     "id": "TI.5",
     "name": "Intelligence-to-detection tasking",
     "weight": 18,
     "question": "Does intelligence reliably and measurably produce detection, hunting and emulation work — and can you prove the linkage?",
     "levels": {
      "0": "No route from intelligence to engineering. The two functions do not interact.",
      "1": "Occasional informal requests, typically during a live incident.",
      "2": "A defined handoff exists (ticket or email) but is used inconsistently and without SLA.",
      "3": "Every prioritised behaviour produces a tracked work item routed to detection engineering, hunting or emulation, with a documented disposition even when the answer is \"no action\".",
      "4": "Time from publication to deployed-and-validated detection is measured per priority tier, trended, and reported; the backlog is triaged against the threat profile ranking.",
      "5": "Tasking is automated from the behaviour library, with measured cycle time under an agreed target and automatic escalation when a top-tier behaviour has no validated detection."
     },
     "evidence": [
      "Intel-to-detection ticket trail with dispositions",
      "Publication-to-validated-detection cycle-time trend",
      "Escalation records for uncovered top-tier behaviours"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-06",
       "ID.IM-01",
       "DE.AE-08"
      ],
      "soc_cmm": [
       "Intelligence.Process",
       "Analysis.Process"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "TI"
    },
    {
     "id": "TI.6",
     "name": "Dissemination, sharing and community contribution",
     "weight": 12,
     "question": "Is intelligence delivered in the form each consumer can act on, and does the organisation contribute back to sector and community sharing?",
     "levels": {
      "0": "No dissemination. Intelligence stays with the person who produced it.",
      "1": "Ad hoc emails and chat messages, one format for all audiences.",
      "2": "Regular scheduled reporting exists, but is a single product pushed to everyone.",
      "3": "Differentiated products by audience — executive risk narrative, SOC-actionable behaviour briefs, engineering-ready procedure detail — with a defined cadence.",
      "4": "Consumer feedback is collected and acted on; usefulness is measured; participation in ISAC/ISAO or sector sharing is active and reciprocal.",
      "5": "Bidirectional automated sharing (STIX/TAXII or equivalent), original research published, and community detection content contributed under an agreed disclosure policy."
     },
     "evidence": [
      "Product catalogue by audience with cadence",
      "Consumer feedback and usefulness scores",
      "Sharing-community membership and contribution records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-03",
       "GV.OC-02",
       "RS.CO-02"
      ],
      "soc_cmm": [
       "Intelligence.Process",
       "Business.Customers"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "TI"
    }
   ]
  },
  {
   "id": "TM",
   "name": "Threat Modeling & Attack Path Analysis",
   "weight": 12,
   "intent": "Converts \"which adversary\" into \"which path through *our* estate\". Threat intelligence tells you what an adversary does in general; threat modeling and attack path analysis tell you what that behaviour looks like against your specific architecture, identities and crown jewels. This is the domain that stops ATT&CK coverage from being a generic checklist.",
   "anti_pattern": "A threat model produced once for an audit, in a diagram tool, never revisited, and never referenced by a single detection rule.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "TM.1",
     "name": "Asset, identity and crown-jewel identification",
     "weight": 13,
     "question": "Do you know what you are actually protecting — the systems, data, identities and business processes whose compromise would matter most?",
     "levels": {
      "0": "No asset inventory beyond what infrastructure teams happen to hold.",
      "1": "Partial inventories in spreadsheets, stale, no criticality rating.",
      "2": "A CMDB or asset inventory exists with ownership and basic criticality, refreshed periodically; identities and cloud resources are covered inconsistently.",
      "3": "Crown jewels are formally identified through business impact analysis and include data stores, privileged identity paths, build/CI systems and trust relationships; each has a named owner and an impact statement.",
      "4": "Inventory completeness is measured against independent discovery (network, cloud API, identity provider, EDR) and the delta is tracked and closed; criticality is reviewed on change.",
      "5": "Asset, identity and exposure inventories are continuously reconciled and automatically feed threat modeling, detection scoping and validation targeting."
     },
     "evidence": [
      "Crown-jewel register with business impact statements",
      "Discovery-versus-inventory reconciliation report",
      "Owner attestation records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.AM-01",
       "ID.AM-02",
       "ID.AM-05",
       "ID.AM-07"
      ],
      "soc_cmm": [
       "Business.Customers",
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "TM"
    },
    {
     "id": "TM.2",
     "name": "System and data-flow threat modeling",
     "weight": 16,
     "question": "Are systems threat-modelled using a recognised structured method, and does that modelling happen at the right point in the delivery lifecycle?",
     "levels": {
      "0": "No threat modeling.",
      "1": "Occasional whiteboard sessions for high-profile projects, no method, no record.",
      "2": "A method is nominated (STRIDE, PASTA, LINDDUN, or equivalent) and used for major projects at design review; outputs are documents.",
      "3": "Threat modeling is mandatory for crown-jewel systems and material changes, uses data-flow diagrams with trust boundaries, and outputs are recorded as structured, queryable threats rather than prose.",
      "4": "Coverage of the crown-jewel estate by current threat models is measured; model quality is peer-reviewed; findings are tracked to closure with owners and dates.",
      "5": "Threat modeling is embedded in the delivery pipeline (threat-model-as-code, diagrams generated from IaC), automatically re-triggered by architectural change, and its output is machine-consumable by the detection backlog."
     },
     "evidence": [
      "Threat model repository with trust-boundary DFDs",
      "Crown-jewel threat-model coverage metric",
      "Threat-model-as-code artefacts and pipeline hooks"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-01",
       "ID.RA-04",
       "PR.PS-06"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "TM"
    },
    {
     "id": "TM.7",
     "name": "Attack surface enumeration",
     "weight": 14,
     "question": "Do you continuously know every way in — external exposure, APIs, SaaS tenants, cloud services, identity federation, shadow IT and third-party ingress — so attack trees are rooted in reality rather than in the architecture diagram?",
     "levels": {
      "0": "No attack surface enumeration. Exposure is whatever the last audit happened to notice.",
      "1": "An informal, partial picture held by individuals; discovered assets surprise the team regularly.",
      "2": "Periodic external scanning of known ranges and domains; cloud, SaaS and API exposure tracked inconsistently; shadow IT invisible.",
      "3": "Enumeration is continuous and deliberate across external services, APIs, cloud resources and identity federation, reconciled against the asset inventory; deltas are triaged and every internet-reachable path to a crown jewel is known and appears as an attack tree root.",
      "4": "Independent discovery (external ASM, cloud API inventory, certificate and DNS monitoring, SaaS discovery) is diffed against the declared surface; unknown-asset rate is measured and trended; new exposure automatically triggers threat model review and telemetry onboarding.",
      "5": "Attack surface change is handled as a live event — new exposure raises detection and modeling work items in near real time, pre-approved telemetry and baseline detections deploy with the asset, and surface reduction is a reported, incentivised metric."
     },
     "evidence": [
      "Attack surface register reconciled against independent discovery",
      "Unknown-asset rate metric and trend",
      "Change-triggered modeling and onboarding records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.AM-01",
       "ID.AM-02",
       "ID.AM-04",
       "ID.RA-01",
       "DE.CM-06"
      ],
      "soc_cmm": [
       "Business.Services",
       "Process.Use case management"
      ],
      "ctem": [
       "Scoping",
       "Discovery"
      ]
     },
     "attack_link": "Roots the attack trees (TM.3) and scopes the in-scope technique set: surface you do not know about produces techniques you will not scope in.",
     "profile": "essential",
     "domain_id": "TM"
    },
    {
     "id": "TM.3",
     "name": "Attack tree construction",
     "weight": 16,
     "question": "Are attack trees built for the objectives that matter — decomposing an adversary goal into the alternative branches by which it can be achieved — and are all branches carried through to a detection decision?",
     "levels": {
      "0": "No attack trees. Threats are described as single-step statements.",
      "1": "Occasional informal \"how would I break in\" discussions, not recorded.",
      "2": "Attack trees are drawn for selected scenarios but stay as diagrams; leaves are not mapped to techniques or to controls.",
      "3": "Trees are built for prioritised adversary objectives (e.g. \"obtain domain dominance\", \"exfiltrate the customer database\", \"tamper with the payment file\"); every node is mapped to ATT&CK techniques, and every leaf carries a prevent/detect/accept decision.",
      "4": "Trees are annotated with feasibility and cost-to-adversary, are reviewed against real incident and emulation outcomes, and drive an explicitly prioritised choke-point strategy — nodes that appear in many trees are treated as high-value detection targets.",
      "5": "Attack trees are maintained as structured data (not pictures), versioned, automatically re-evaluated when the estate or the threat profile changes, and used to compute residual risk per objective."
     },
     "evidence": [
      "Attack tree library in structured form (YAML/JSON/graph DB)",
      "Node-to-ATT&CK mapping and per-leaf control decisions",
      "Choke-point analysis showing nodes shared across trees"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-01",
       "ID.RA-04",
       "ID.IM-02"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": "Every attack tree node carries one or more ATT&CK technique IDs.",
     "profile": "standard",
     "domain_id": "TM"
    },
    {
     "id": "TM.4",
     "name": "Attack path and exposure analysis",
     "weight": 15,
     "question": "Do you analyse real, computed attack paths through identity, network and cloud relationships in the live estate — not only hypothetical ones?",
     "levels": {
      "0": "No attack path analysis. Exposure is understood only as a vulnerability list.",
      "1": "Path thinking happens only after a red team or pentest report describes one.",
      "2": "Point-in-time path analysis is run occasionally with a tool (identity graph, cloud permission analysis, AD path tooling) for specific reviews.",
      "3": "Path analysis runs on a defined cadence across identity, cloud entitlement, network reachability and trust relationships; results are ranked by proximity to crown jewels and issued as remediation and detection work.",
      "4": "Path exposure is trended as a metric (number and shortest length of viable paths to each crown jewel); choke points are instrumented for detection where remediation is not feasible; reduction is reported.",
      "5": "Continuous path computation is integrated with change management and CTEM cycles; new paths raise alerts in near real time and automatically create both a remediation and a detection work item."
     },
     "evidence": [
      "Attack path analysis output with paths to crown jewels",
      "Trend of viable path count and shortest path length",
      "Choke-point instrumentation records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-01",
       "ID.RA-05",
       "ID.IM-02",
       "PR.AA-05"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ],
      "ctem": [
       "Scoping",
       "Discovery",
       "Prioritisation"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "TM"
    },
    {
     "id": "TM.5",
     "name": "Abuse cases to detection requirements traceability",
     "weight": 14,
     "question": "Can you trace a specific detection rule back to the threat model or attack tree node that justified it — and identify model nodes with no detection?",
     "levels": {
      "0": "No traceability. Detections exist for reasons nobody records.",
      "1": "Traceability exists in individuals' memory only.",
      "2": "Some detection tickets reference a threat model informally in free text.",
      "3": "A maintained traceability matrix links threat model / attack tree nodes to detection requirements, to deployed detections, and to validation results, with a unique identifier at each step.",
      "4": "Orphaned nodes (modelled but undetected and un-prevented) and orphaned detections (deployed but justified by nothing) are both reported as defects and worked down; coverage of model nodes is a reported metric.",
      "5": "Traceability is automated end to end — model node, requirement, rule, test, validation outcome and incident are linked in one queryable graph used for assurance reporting."
     },
     "evidence": [
      "Traceability matrix or graph query output",
      "Orphaned-node and orphaned-detection reports",
      "Assurance report tracing an incident back to a model node"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-01",
       "ID.IM-02",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "TM"
    },
    {
     "id": "TM.6",
     "name": "Model maintenance and change triggers",
     "weight": 12,
     "question": "Are threat models, attack trees and path analyses kept alive by defined triggers, or do they decay silently after first publication?",
     "levels": {
      "0": "Models, where they exist, are never updated.",
      "1": "Updated only when someone remembers or an auditor asks.",
      "2": "A calendar-based review cycle exists (typically annual) and is partially honoured.",
      "3": "Defined triggers force review — architecture change, new crown jewel, new prioritised actor, significant incident, major ATT&CK release — and review completion is tracked.",
      "4": "Model freshness is measured (age distribution, percentage overdue), overdue models are escalated to owners, and drift between model and reality is sampled and reported.",
      "5": "Change detection is automated from CI/CD, cloud control plane and identity change events; affected models are flagged and re-validated with measured turnaround."
     },
     "evidence": [
      "Documented change triggers and review completion log",
      "Model freshness metric and overdue escalations",
      "Automated change-trigger integration"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-03",
       "ID.RA-07",
       "GV.OV-03"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "TM"
    }
   ]
  },
  {
   "id": "DC",
   "name": "Telemetry & Detection Coverage",
   "weight": 14,
   "intent": "Detection is bounded by visibility. This domain measures whether the right telemetry exists, whether it is trustworthy, and whether ATT&CK coverage claims are grounded in data rather than in a spreadsheet of intentions.",
   "anti_pattern": "A green ATT&CK Navigator layer produced by counting rule names, with no check that the underlying data components are actually collected and healthy.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "DC.1",
     "name": "Log source inventory and ownership",
     "weight": 14,
     "question": "Is there a complete, owned inventory of telemetry sources with their scope, coverage percentage and criticality?",
     "levels": {
      "0": "No inventory. Nobody can list what is being collected.",
      "1": "A partial list held by the platform team, out of date.",
      "2": "An inventory exists with source names and destinations, reviewed periodically; deployment coverage per source is estimated.",
      "3": "Each source has a named business and technical owner, defined scope (which estate it covers), measured deployment coverage, criticality rating and mapping to ATT&CK data components.",
      "4": "Inventory completeness is validated against independent asset discovery; unmonitored assets are reported as a defect class with an owner and a target date.",
      "5": "Inventory is continuously reconciled and automatically drives onboarding, alerting on unmonitored crown-jewel assets within a defined time window."
     },
     "evidence": [
      "Log source inventory with owners, coverage % and data-component mapping",
      "Unmonitored asset report and closure trend"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.AM-01",
       "DE.CM-01",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Technology.SIEM tuning",
       "Process.Log management"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DC"
    },
    {
     "id": "DC.2",
     "name": "Telemetry quality, completeness and timeliness",
     "weight": 18,
     "question": "Do you measure whether the data arriving is complete, correctly parsed, timely and unaltered — and do you alert when it is not?",
     "levels": {
      "0": "Data quality is unknown. Gaps are discovered during investigations.",
      "1": "Occasional manual checks; problems found reactively when a search returns nothing.",
      "2": "Basic volume monitoring exists with static thresholds; parsing errors are noticed when someone reports them.",
      "3": "Quality is measured on defined dimensions — completeness, field-level fill rate, parsing success, ingestion latency, time-source accuracy, retention conformance — per source, with alerting on deviation.",
      "4": "Quality SLOs are agreed with source owners, breaches are ticketed and trended, and known-gap periods are recorded so investigations and coverage claims are adjusted for them.",
      "5": "Quality is enforced automatically — schema validation at ingest, synthetic canary events per source to prove the path end to end, self-healing pipelines, and measured mean time to detect a telemetry outage."
     },
     "evidence": [
      "Per-source data quality dashboard with SLOs",
      "Canary event configuration and results",
      "Telemetry outage MTTD metric"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-09",
       "DE.AE-03",
       "PR.PS-04"
      ],
      "soc_cmm": [
       "Technology.Log management",
       "Process.Monitoring"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DC"
    },
    {
     "id": "DC.3",
     "name": "Normalisation and data model discipline",
     "weight": 14,
     "question": "Is telemetry normalised to a documented, versioned data model so detections are portable and analysts are not re-learning field names per source?",
     "levels": {
      "0": "Raw, source-specific fields only. Every search is bespoke.",
      "1": "Inconsistent ad hoc field extractions built by whoever needed them.",
      "2": "A data model is used for the main sources (OCSF, ECS, CIM, ASIM or in-house) but coverage is partial and undocumented.",
      "3": "A documented, versioned schema is mandated for onboarding; conformance is checked at onboarding; entity resolution (user, host, process, identity) is defined.",
      "4": "Schema conformance is measured continuously across all sources; non-conformant sources are tracked as debt; schema changes go through change control with impact analysis on affected detections.",
      "5": "Normalisation is automated and tested, detections are written against the model rather than the source, and the same detection content runs across multiple platforms with proven equivalence."
     },
     "evidence": [
      "Versioned schema document and onboarding conformance gate",
      "Schema conformance metric per source",
      "Cross-platform detection portability proof"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-03",
       "PR.DS-01"
      ],
      "soc_cmm": [
       "Technology.SIEM",
       "Process.Log management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DC"
    },
    {
     "id": "DC.4",
     "name": "ATT&CK technique coverage measurement",
     "weight": 20,
     "question": "Is coverage measured honestly at technique and sub-technique level, grounded in data-component availability and detection validity — not in rule counts?",
     "levels": {
      "0": "Coverage is not measured.",
      "1": "A hand-drawn Navigator layer produced once, based on opinion.",
      "2": "Coverage is mapped by tagging existing rules with technique IDs; parent-technique level only; no distinction between \"we have a rule\" and \"it works\".",
      "3": "Coverage is scored on a defined scale that separates telemetry availability, detection logic presence and detection quality; measured at sub-technique level for the in-scope set defined by the threat profile and platform mix.",
      "4": "Coverage scoring requires evidence from validation (see AV domain); the Validated Coverage Score is trended over time; regressions are investigated.",
      "5": "Coverage is computed automatically from the detection repository, telemetry health and the latest validation results, refreshed on every ATT&CK release, with automated diff reporting on new and deprecated techniques."
     },
     "evidence": [
      "Coverage model definition and scoring scale",
      "Navigator layer generated from the detection repository",
      "Validated Coverage Score trend and ATT&CK release diff report"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-09",
       "ID.IM-02"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": "Scored against ATT&CK Enterprise v19.2 (697 techniques; 222 parent, 475 sub) restricted to the in-scope platform and threat-profile set.",
     "profile": "standard",
     "domain_id": "DC"
    },
    {
     "id": "DC.5",
     "name": "Coverage breadth across attack surfaces",
     "weight": 20,
     "question": "Does visibility extend across every surface the prioritised adversaries use — endpoint, identity, cloud control plane, SaaS, network, email, application, container, OT/IoT and third-party — rather than concentrating on endpoint?",
     "levels": {
      "0": "One or two surfaces instrumented, typically endpoint and perimeter.",
      "1": "Additional sources exist but are unmonitored or only searched during incidents.",
      "2": "Most traditional surfaces are covered; cloud control plane, SaaS and identity are partial; OT/IoT and CI/CD are absent.",
      "3": "Coverage is deliberately scoped per surface against the threat profile, with documented decisions on surfaces deliberately not covered and the risk accepted.",
      "4": "Per-surface coverage is measured and reported separately, preventing a strong endpoint programme from masking a blind cloud or identity plane; gaps carry owners and dates.",
      "5": "New surfaces are onboarded as part of technology adoption governance — no material new platform reaches production without a telemetry plan and baseline detections."
     },
     "evidence": [
      "Per-surface coverage report",
      "Accepted-risk records for uncovered surfaces",
      "Technology-adoption gate requiring a telemetry plan"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-01",
       "DE.CM-02",
       "DE.CM-03",
       "DE.CM-06",
       "ID.AM-04"
      ],
      "soc_cmm": [
       "Technology.Log management",
       "Business.Services"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DC"
    },
    {
     "id": "DC.6",
     "name": "Visibility gap management",
     "weight": 14,
     "question": "Are known blind spots recorded, prioritised, costed and driven to closure — or quietly tolerated?",
     "levels": {
      "0": "Blind spots are not recorded.",
      "1": "Known informally; raised in conversation, not tracked.",
      "2": "A gap list exists but has no owners, priorities or dates.",
      "3": "Gaps are registered with the technique(s) they blind, the crown jewels affected, an owner, a priority derived from the threat profile, and a target date.",
      "4": "Gap closure rate and ageing are reported; gaps that cannot be closed are compensated with alternative detection or explicit risk acceptance at the right level.",
      "5": "Gaps are generated automatically from coverage and validation results, costed, and fed into budget planning with demonstrated closure of the highest-risk items each cycle."
     },
     "evidence": [
      "Visibility gap register with owners and dates",
      "Gap ageing and closure-rate trend",
      "Risk acceptance records for tolerated gaps"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-06",
       "ID.IM-01",
       "ID.IM-03"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DC"
    }
   ]
  },
  {
   "id": "DE",
   "name": "Detection Engineering",
   "weight": 16,
   "intent": "The production engine of the model. Measures whether detection content is built, tested, released, monitored and retired with the discipline of software engineering — and whether the portfolio is deliberately composed rather than accumulated.",
   "anti_pattern": "Thousands of enabled vendor rules, no version control, no test, no owner, and a \"we can't turn it off in case we need it\" culture.",
   "ceiling_rule": "DE may not score more than one level above DC. Detection logic cannot be more mature than the telemetry it runs on.",
   "subcapabilities": [
    {
     "id": "DE.1",
     "name": "Detection lifecycle and intake",
     "weight": 10,
     "question": "Is there a defined lifecycle from requirement through design, build, test, release, monitor and retire — with a controlled intake?",
     "levels": {
      "0": "No lifecycle. Rules appear when someone has an idea or a vendor ships content.",
      "1": "Informal build-and-deploy by individuals; no stages, no record.",
      "2": "A documented process exists covering build and deploy; test and retire stages are weak or skipped under pressure.",
      "3": "A full lifecycle is defined and enforced, with a single intake queue accepting requests from intelligence, threat modeling, hunting, incidents, emulation and audit — each item carrying a source and a priority.",
      "4": "Stage transition criteria are explicit and gated; lifecycle metrics (queue depth, lead time, stage ageing, rejection reasons) are measured and reviewed.",
      "5": "The lifecycle is automated end to end with policy-as-code gates; lead time from intake to validated production is measured against a target and continuously reduced."
     },
     "evidence": [
      "Documented lifecycle with stage gates",
      "Intake queue showing source attribution per item",
      "Lead-time and queue-depth trends"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-09",
       "ID.IM-01"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ],
      "debmm": [
       "Foundational to Advanced"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DE"
    },
    {
     "id": "DE.2",
     "name": "Detection-as-code",
     "weight": 12,
     "question": "Is detection content managed as code — versioned, peer-reviewed, and deployed through an automated pipeline?",
     "levels": {
      "0": "Rules are edited directly in the console. No history beyond the tool's audit log.",
      "1": "Occasional manual exports kept in a shared folder as backup.",
      "2": "Content is stored in version control but deployed manually; commits are not reviewed.",
      "3": "All detection content lives in version control with mandatory peer review, branch protection, meaningful commit history and a documented release process.",
      "4": "CI validates syntax, schema, metadata completeness and test results before merge; deployment is automated with rollback; production drift from the repository is detected and alerted.",
      "5": "Full GitOps — the repository is the single source of truth, environments are reproducible, deployments are automated with progressive rollout, and drift is auto-remediated."
     },
     "evidence": [
      "Repository with branch protection and review history",
      "CI pipeline definition and passing runs",
      "Drift detection alerts and rollback records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "PR.PS-01",
       "PR.PS-06",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Technology.SIEM",
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DE"
    },
    {
     "id": "DE.3",
     "name": "Detection standards, metadata and documentation",
     "weight": 10,
     "question": "Does every detection carry the metadata needed to operate, audit and improve it — and is a shared standard enforced?",
     "levels": {
      "0": "No standard. Rule names are the only documentation.",
      "1": "Some rules have descriptions; quality varies by author.",
      "2": "A template exists; completion is voluntary and partial.",
      "3": "A mandatory schema is enforced — unique ID, author, owner, ATT&CK technique and sub-technique, data sources required, logic rationale, known false positives, severity and risk score, triage guidance, response playbook link, validation reference, and version.",
      "4": "Metadata completeness and accuracy are measured; incomplete content cannot pass CI; analyst-facing triage guidance is reviewed for usability by the people who use it at 3am.",
      "5": "Metadata is machine-consumable and powers automated coverage reporting, response routing, validation targeting and impact analysis when a log source degrades."
     },
     "evidence": [
      "Enforced detection schema (e.g. Sigma-compatible) and CI validation rule",
      "Metadata completeness metric",
      "Automated report built from detection metadata"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-02",
       "DE.CM-09",
       "RS.MA-02"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "Process.Detection engineering"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DE"
    },
    {
     "id": "DE.4",
     "name": "Testing and pre-deployment validation",
     "weight": 13,
     "question": "Is every detection proven to fire on true positive input and stay quiet on benign input, before it reaches production?",
     "levels": {
      "0": "No testing. Rules are enabled and observed.",
      "1": "Author eyeballs a historical search and calls it tested.",
      "2": "Manual testing against sample events for some rules; results not retained.",
      "3": "Every detection has a positive test (a reproducible execution or synthetic event that must trigger it) and a negative test set of benign activity that must not; results are recorded against the rule version.",
      "4": "Tests run automatically in CI against a representative dataset or lab range; regression tests re-run on every change and on data model changes; test coverage of the detection portfolio is measured.",
      "5": "Tests are generated from the emulation library, run continuously against production-like telemetry, and any detection without a passing test in the current period is automatically flagged as unverified in coverage reporting."
     },
     "evidence": [
      "Test definitions stored with the detection content",
      "CI test run history and coverage-of-portfolio metric",
      "Unverified-detection report"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "DE.CM-09",
       "PR.PS-06"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DE"
    },
    {
     "id": "DE.5",
     "name": "Tuning, precision and false-positive management",
     "weight": 10,
     "question": "Is alert precision measured per detection and improved deliberately, rather than by disabling noisy rules?",
     "levels": {
      "0": "No feedback loop. Noisy rules are muted or ignored by analysts.",
      "1": "Tuning happens reactively when analysts complain loudly enough.",
      "2": "Tuning requests are logged and actioned; changes are made in the console without a record of rationale.",
      "3": "Every detection has measured true-positive/false-positive outcomes captured at case closure; precision is calculated per rule; tuning changes are version-controlled with a stated rationale and expected effect.",
      "4": "Precision and volume thresholds are agreed; rules breaching them enter a formal remediation path with a deadline, ending in fix, demote-to-hunt, or retire; the effect of each change is measured after the fact.",
      "5": "Tuning is partly automated with statistical baselining and allow-list governance; suppression is time-boxed and expires by default; precision is trended per rule and per domain with alerting on degradation."
     },
     "evidence": [
      "Per-rule precision and volume report",
      "Tuning change records with rationale and post-change effect",
      "Expiring suppression policy and audit"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-08",
       "ID.IM-01",
       "RS.AN-08"
      ],
      "soc_cmm": [
       "Process.Monitoring",
       "Technology.SIEM tuning"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DE"
    },
    {
     "id": "DE.6",
     "name": "Detection health and silent-failure monitoring",
     "weight": 10,
     "question": "Would you know if a detection stopped working — not because it was deleted, but because its data stopped arriving or its schema changed?",
     "levels": {
      "0": "No health monitoring. Silent failure is discovered during an incident, or never.",
      "1": "Occasional manual review of whether rules have fired recently.",
      "2": "Basic \"rule has not fired in N days\" reporting exists, treated as informational.",
      "3": "Health is monitored on multiple signals — data source availability for each rule's required components, execution errors, schema drift, scheduling failures, and unexpected volume change — with defined thresholds.",
      "4": "Health failures raise operational tickets with SLAs; the percentage of the portfolio in a healthy state is a reported KPI; dependency mapping shows which detections a given log source outage disables.",
      "5": "Health monitoring is closed-loop with canary events proving the full path from generation to alert; failures auto-open incidents, and coverage reporting automatically discounts unhealthy detections."
     },
     "evidence": [
      "Detection health dashboard with dependency mapping",
      "Portfolio-health KPI trend",
      "Canary-to-alert proof and auto-ticketing configuration"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-09",
       "PR.PS-04",
       "DE.AE-03"
      ],
      "soc_cmm": [
       "Technology.SIEM",
       "Process.Monitoring"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "DE"
    },
    {
     "id": "DE.7",
     "name": "Versioning, deprecation and retirement",
     "weight": 8,
     "question": "Is content retired deliberately when it no longer earns its place, with a record of why?",
     "levels": {
      "0": "Nothing is ever retired. The rule set only grows.",
      "1": "Rules are occasionally disabled without record.",
      "2": "Retirement happens during periodic clean-ups, driven by performance not by value.",
      "3": "Retirement criteria are defined (superseded, permanently unsupported telemetry, technique no longer relevant, unfixable precision) and each retirement is recorded with rationale and approval.",
      "4": "The portfolio is reviewed on a cadence against the threat profile; retirement volume and reasons are reported; retired content is archived and recoverable with its history.",
      "5": "Deprecation is automated against ATT&CK changes, telemetry decommissioning and threat profile shifts, with impact analysis run before removal and coverage recomputed after."
     },
     "evidence": [
      "Retirement criteria and decision log",
      "Portfolio review records and retirement statistics",
      "Automated deprecation impact analysis"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-03",
       "PR.PS-06"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DE"
    },
    {
     "id": "DE.8",
     "name": "Portfolio composition and detection strategy",
     "weight": 12,
     "question": "Is the detection portfolio deliberately balanced across the pyramid of pain — or is it a pile of indicator matches with a few behavioural rules on top?",
     "levels": {
      "0": "No concept of portfolio. Content is whatever the tool shipped with.",
      "1": "Predominantly signature and indicator matching; behavioural detection is incidental.",
      "2": "A mix exists but is unplanned; nobody can state the balance or defend it.",
      "3": "The portfolio is explicitly classified — atomic indicator, tool artefact, behavioural/TTP, anomaly, correlation, deception — with a documented target mix, and behavioural detection is prioritised for the top-tier threat profile.",
      "4": "Composition is measured and reported against target; resilience to adversary evasion is assessed (would this survive a renamed binary, a new C2 domain, a different LOLBIN?); brittle detections are identified and reworked.",
      "5": "Detection strategy is derived from attack-tree choke points and cost-to-adversary analysis; the portfolio is optimised to raise adversary cost, and this is demonstrated through emulation results rather than asserted."
     },
     "evidence": [
      "Portfolio classification with target and actual mix",
      "Evasion-resilience assessment",
      "Choke-point-driven detection strategy document"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-09",
       "ID.IM-02",
       "PR.IR-01"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DE"
    },
    {
     "id": "DE.9",
     "name": "Detection content sourcing and provenance",
     "weight": 8,
     "question": "Do you have a deliberate strategy for where detection ideas come from, and is the provenance of every deployed detection recorded?",
     "levels": {
      "0": "Detection content is whatever the platform shipped with. Nobody can say where a rule came from.",
      "1": "Content is copied ad hoc from blog posts and vendor reports when someone happens to read one.",
      "2": "Named sources are used routinely — vendor content subscriptions, community rule repositories — but adoption is uncritical and provenance is not recorded.",
      "3": "A documented sourcing strategy spans annual threat reports (for example Red Canary, CrowdStrike, Mandiant, Verizon DBIR), vendor and government advisories, community rule repositories (SigmaHQ, Elastic, Splunk Security Content, YARA collections), intelligence platforms (MISP, OpenCTI) and in-house research; every deployed detection records its source, licence and adoption date.",
      "4": "Content is evaluated before adoption against the organisation's own threat profile and telemetry — not enabled wholesale — and the value of each source is measured by the true positives and validated coverage it actually produced.",
      "5": "Sourcing is automated and bidirectional: upstream repositories are tracked for updates and deprecations with impact analysis, sector campaign reporting triggers targeted content review within a defined window, and internally developed detections are contributed back."
     },
     "evidence": [
      "Documented sourcing strategy naming the report, repository and intel-platform sources in use",
      "Provenance, licence and adoption date recorded per detection",
      "Per-source value report (true positives, validated coverage contributed)",
      "Upstream change tracking with impact analysis"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.RA-02",
       "ID.RA-03",
       "GV.SC-07",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Intelligence.Process",
       "Process.Use case management"
      ]
     },
     "attack_link": "Adopted content must be ATT&CK-mapped on intake, not after the fact.",
     "profile": "essential",
     "domain_id": "DE"
    },
    {
     "id": "DE.10",
     "name": "Detection modality breadth",
     "weight": 7,
     "question": "Does detection span the modalities the adversary can be caught in — event analytics, file and memory content, network, identity behaviour, integrity and deception — rather than relying on one?",
     "levels": {
      "0": "A single modality, almost always log or event analytics in a SIEM.",
      "1": "A second modality exists incidentally because a product provides it, but nobody plans across them.",
      "2": "Two or three modalities are in use and configured, but chosen by tooling rather than by what the prioritised behaviours require.",
      "3": "Modalities are selected deliberately per behaviour — event and process analytics, file and memory content matching (for example YARA), network signature and protocol analysis, identity and entitlement behaviour, configuration and integrity drift, and deception — with the choice recorded and justified against the threat profile.",
      "4": "Modality coverage is measured per prioritised scenario, and gaps are closed with the modality that fits rather than the tool already owned; where commercial endpoint tooling is absent, open-source equivalents are deliberately deployed to reach the same behaviours.",
      "5": "Modalities are composed rather than parallel — a single scenario is detected across several modalities that corroborate each other, raising both confidence and the cost of evasion, and the composition is validated end to end."
     },
     "evidence": [
      "Modality map per prioritised scenario with justification",
      "Deployed content in more than one modality (for example Sigma plus YARA plus network signatures)",
      "Evidence of corroboration across modalities in a real or emulated case"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-01",
       "DE.CM-02",
       "DE.CM-04",
       "DE.CM-09",
       "PR.DS-06"
      ],
      "soc_cmm": [
       "Technology",
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "DE"
    }
   ]
  },
  {
   "id": "AV",
   "name": "Adversarial Validation & Emulation",
   "weight": 14,
   "intent": "The evidence engine. Every other domain makes claims; this domain tests them. It spans atomic testing, automated breach and attack simulation, threat-actor emulation, purple teaming, penetration testing and red teaming — and, critically, the loop that turns findings into closed detection gaps.",
   "anti_pattern": "An annual penetration test whose report is read by the risk team, filed, and never converted into a single detection or a single re-test.",
   "ceiling_rule": "No other domain may score more than one level above AV. An untested capability is an assumed capability.",
   "subcapabilities": [
    {
     "id": "AV.1",
     "name": "Atomic testing and control verification",
     "weight": 13,
     "question": "Are individual techniques executed safely and repeatably to verify that telemetry, detection and alerting actually fire?",
     "levels": {
      "0": "No technique-level testing.",
      "1": "Occasional manual tests by a curious engineer, undocumented.",
      "2": "A test library (e.g. Atomic Red Team or in-house) is used sporadically against a lab; results are informal.",
      "3": "Atomic tests are run on a defined cadence against a representative production-like environment, mapped to ATT&CK sub-techniques, with recorded outcomes at each stage — telemetry generated, event ingested, detection fired, alert raised.",
      "4": "Test coverage of the in-scope technique set is measured; failures create tracked defects; re-test after fix is mandatory; results feed coverage scoring directly.",
      "5": "Atomic testing is continuous and automated with safe-execution guardrails and change control, results stream into coverage dashboards in near real time, and untested techniques are automatically reported as unproven."
     },
     "evidence": [
      "Test library mapped to sub-technique IDs",
      "Per-stage outcome records (telemetry/ingest/detect/alert)",
      "Defect and re-test records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "DE.CM-09",
       "PR.PS-06"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "AV"
    },
    {
     "id": "AV.2",
     "name": "Breach and attack simulation automation",
     "weight": 12,
     "question": "Is there automated, scheduled simulation providing continuous assurance across prevention and detection layers?",
     "levels": {
      "0": "No automated simulation capability.",
      "1": "A trial or proof of concept was run once.",
      "2": "A BAS tool is deployed against a limited scope, run manually and irregularly.",
      "3": "Simulation runs on a defined schedule across representative segments, covering prevention, detection and alerting layers, with scenarios selected from the prioritised threat profile rather than the vendor default set.",
      "4": "Results are trended, control drift (a previously passing test that now fails) is alerted on, and simulation scope covers all critical segments and cloud/identity planes as well as endpoint.",
      "5": "Simulation is integrated into change management — infrastructure or control changes trigger targeted re-simulation — and results are an input to control investment decisions."
     },
     "evidence": [
      "Simulation schedule, scope and scenario provenance",
      "Control drift alerts and trend",
      "Change-triggered simulation records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "PR.PS-06",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Technology",
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AV"
    },
    {
     "id": "AV.3",
     "name": "Threat-actor emulation plans",
     "weight": 15,
     "question": "Do you emulate the full behaviour chains of the specific adversaries in your threat profile, in sequence, rather than isolated techniques?",
     "levels": {
      "0": "No emulation. Testing, where it exists, is technique-by-technique only.",
      "1": "A single generic scenario borrowed from a public plan, run once.",
      "2": "Public emulation plans are executed occasionally with limited tailoring to the environment.",
      "3": "Emulation plans are authored for the top-ranked actors in the threat profile, sequencing techniques into realistic operations against realistic objectives, tailored to the organisation's platforms and crown jewels.",
      "4": "Plans are refreshed as actor tradecraft evolves; coverage of the prioritised actor set by current emulation plans is measured; detection outcomes are recorded per step in the chain, showing where in the kill chain detection actually occurs.",
      "5": "Emulation is derived automatically from the behaviour library and attack trees, includes evasion variants of previously detected behaviours to test resilience, and produces a measured \"adversary dwell time before detection\" per scenario."
     },
     "evidence": [
      "Emulation plan library referencing ATT&CK Group/Campaign IDs",
      "Per-step detection outcome records showing earliest detection point",
      "Evasion-variant test results"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "ID.RA-03",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "AV"
    },
    {
     "id": "AV.4",
     "name": "Purple team programme",
     "weight": 13,
     "question": "Is there a structured, recurring collaboration in which offensive execution and defensive engineering work the same exercise together and fix gaps live?",
     "levels": {
      "0": "No purple teaming. Offence and defence do not work together.",
      "1": "Occasional informal collaboration after a red team engagement.",
      "2": "Purple team exercises happen once or twice a year, ad hoc in scope, with a report at the end.",
      "3": "A defined programme with a regular cadence, scenarios drawn from the threat profile, agreed rules of engagement, and detection engineers present during execution making fixes in the session.",
      "4": "Every exercise produces measured outcomes per technique (prevented / detected-and-alerted / detected-not-alerted / logged-only / invisible), a tracked backlog, and a mandatory re-test that confirms closure.",
      "5": "Purple teaming is continuous rather than episodic, integrated with the detection pipeline so improvements are shipped within the exercise window, and its findings measurably improve time-to-detect over successive cycles."
     },
     "evidence": [
      "Programme charter, cadence and rules of engagement",
      "Per-technique outcome matrix and re-test confirmations",
      "Time-to-detect improvement trend across cycles"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "ID.IM-01",
       "RS.MA-01"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "People.Training"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "AV"
    },
    {
     "id": "AV.5",
     "name": "Penetration testing integration",
     "weight": 12,
     "question": "Are penetration test findings systematically converted into detection requirements — not only into vulnerability remediation tickets?",
     "levels": {
      "0": "Penetration testing is not performed, or reports never reach the detection team.",
      "1": "Tests are run for compliance; the detection team occasionally hears about the results.",
      "2": "Reports are shared with the SOC after the fact; a few detections may be built informally.",
      "3": "Every engagement has a defined detection-feedback stage — the tester's activity timeline is reconciled against SOC telemetry and alerts to determine what was seen, and each unseen action becomes a detection requirement.",
      "4": "The \"detection rate\" of each engagement is measured (percentage of tester actions that produced telemetry, a detection, and an alert), trended across engagements, and improvement is a stated objective of the testing programme.",
      "5": "Testers deliver machine-readable activity timelines that are automatically diffed against SIEM data; detection gaps are auto-created; scoping of subsequent tests deliberately targets previously blind areas."
     },
     "evidence": [
      "Tester activity timeline reconciled against SOC telemetry",
      "Engagement detection-rate metric and trend",
      "Detection requirements traced to specific test actions"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "ID.RA-01",
       "PR.PS-06"
      ],
      "soc_cmm": [
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AV"
    },
    {
     "id": "AV.6",
     "name": "Red teaming and independent assurance",
     "weight": 12,
     "question": "Is the detection and response capability tested by objective-based, intelligence-led adversarial engagements under realistic constraints?",
     "levels": {
      "0": "No red teaming.",
      "1": "A one-off engagement, scoped as an extended penetration test.",
      "2": "Periodic red team engagements with limited objectives and heavy scope restrictions; the blue team is usually informed.",
      "3": "Objective-based, intelligence-led engagements against crown-jewel objectives, with a genuinely uninformed blue team, control group, and formal rules of engagement and legal cover.",
      "4": "Engagements follow a recognised framework where applicable (TIBER-EU, CBEST, CORIE, AASE, iCAST) or an equivalent internal standard; detection and response performance is measured against defined objectives; findings drive a tracked remediation plan with executive visibility.",
      "5": "A continuous or high-frequency adversarial assurance capability exists; results are compared across cycles to demonstrate improving detection depth and reducing adversary freedom of movement; findings feed threat models and attack trees, not only detections."
     },
     "evidence": [
      "Intelligence-led engagement scope and rules of engagement",
      "Objective-by-objective detection and response performance record",
      "Cross-cycle comparison showing improvement"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "GV.OV-02",
       "RS.MA-01"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Process.Use case management"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "AV"
    },
    {
     "id": "AV.7",
     "name": "Findings-to-closure loop",
     "weight": 13,
     "question": "Do validation findings reliably become closed detection or control changes, confirmed by re-test — and is the loop's speed measured?",
     "levels": {
      "0": "Findings are not tracked. Reports are the deliverable.",
      "1": "Findings are noted in a document; closure is unverified.",
      "2": "Findings enter a tracker; closure is claimed by the assignee without re-test.",
      "3": "Every finding has an owner, a severity derived from threat-profile relevance and crown-jewel proximity, a target date, and a mandatory re-test before it can be closed.",
      "4": "Closure rate, ageing and re-test pass rate are reported; overdue findings escalate; recurrence of previously closed findings is treated as a systemic defect and investigated.",
      "5": "The loop is automated — validation results create work items, deployment triggers re-validation, and mean time from finding to validated closure is a headline KPI under active reduction."
     },
     "evidence": [
      "Findings register with re-test evidence per closure",
      "Ageing, closure-rate and recurrence reports",
      "Mean-time-to-validated-closure trend"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-01",
       "ID.IM-03",
       "RS.MA-05"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AV"
    },
    {
     "id": "AV.8",
     "name": "Control efficacy scoring",
     "weight": 10,
     "question": "Are validation results expressed as a defensible efficacy score per technique across the prevent / detect / alert / respond chain, and used in reporting?",
     "levels": {
      "0": "No efficacy scoring. Controls are described as present or absent.",
      "1": "Subjective assessment of \"good\" or \"weak\" coverage by opinion.",
      "2": "Pass/fail per test, aggregated informally.",
      "3": "A defined scale scores each in-scope technique separately for prevention, telemetry, detection, alerting and response, based on recorded validation evidence with a stated recency window.",
      "4": "Efficacy scores expire — a result older than the defined window is downgraded to unproven; scores drive the Validated Coverage Score and appear in domain reporting; disagreements are arbitrated by evidence.",
      "5": "Efficacy scoring is automated from validation pipelines, feeds risk quantification and investment cases, and is used to demonstrate risk reduction per pound or dollar spent."
     },
     "evidence": [
      "Efficacy scoring scale definition with recency rules",
      "Per-technique efficacy matrix",
      "Investment case referencing efficacy-derived risk reduction"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "GV.RM-06",
       "DE.CM-09"
      ],
      "soc_cmm": [
       "Process.Use case management",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "AV"
    }
   ]
  },
  {
   "id": "AA",
   "name": "Analytics, Automation & Hunting",
   "weight": 12,
   "intent": "Determines whether detection output becomes usable decisions at operational tempo. Covers enrichment, correlation into attack narratives, automation, advanced analytics governance, and hypothesis-driven hunting as a producer of new detection.",
   "anti_pattern": "A SOAR platform used exclusively to close tickets faster, and a \"hunting\" function that is really unstructured dashboard browsing.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "AA.1",
     "name": "Triage enrichment and context automation",
     "weight": 13,
     "question": "Does an alert arrive with the context an analyst needs, automatically, or does triage begin with twenty minutes of manual lookups?",
     "levels": {
      "0": "No enrichment. Analysts pivot manually across consoles.",
      "1": "A few manual lookup shortcuts maintained by individual analysts.",
      "2": "Basic automated enrichment for some alert types (reputation, geolocation, asset name).",
      "3": "Enrichment is defined per detection type and covers asset criticality and owner, identity role and privilege, recent related activity, vulnerability and exposure state, threat intelligence context and prior case history.",
      "4": "Enrichment coverage and its effect on triage time are measured; enrichment failures are monitored; the enrichment set is reviewed against what analysts actually use.",
      "5": "Enrichment is adaptive — driven by detection metadata and case type, includes automated preliminary verdicts with confidence, and demonstrably reduces mean time to triage."
     },
     "evidence": [
      "Enrichment specification per detection class",
      "Triage-time effect measurement",
      "Enrichment failure monitoring"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-02",
       "DE.AE-07",
       "RS.AN-03"
      ],
      "soc_cmm": [
       "Process.Monitoring",
       "Technology.SOAR"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "AA"
    },
    {
     "id": "AA.2",
     "name": "Correlation and attack-chain assembly",
     "weight": 14,
     "question": "Are related alerts assembled into a single narrative of adversary progress, or triaged as isolated events?",
     "levels": {
      "0": "Alerts are handled individually with no relationship awareness.",
      "1": "Analysts manually notice patterns from experience.",
      "2": "Basic correlation by entity (host, user) within a time window.",
      "3": "Correlation assembles alerts into incidents along entity and temporal relationships, annotated with ATT&CK tactic progression so an analyst can see how far along the chain the adversary is.",
      "4": "Risk-based alerting aggregates weak signals into scored entities; the balance between raw alert volume and assembled incidents is measured; correlation quality (false grouping and missed grouping) is reviewed.",
      "5": "Graph-based correlation spans identity, endpoint, cloud and network, reconstructs full attack paths against the estate's real topology, and predicts likely next steps from attack-tree data to prompt pre-emptive containment."
     },
     "evidence": [
      "Correlation logic documentation with tactic progression",
      "Alert-to-incident aggregation ratio and quality review",
      "Graph correlation output showing a reconstructed path"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-02",
       "DE.AE-03",
       "DE.AE-04",
       "DE.AE-06"
      ],
      "soc_cmm": [
       "Process.Monitoring",
       "Technology.SIEM"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AA"
    },
    {
     "id": "AA.3",
     "name": "Response automation and orchestration",
     "weight": 12,
     "question": "Is automation applied to response actions with appropriate safeguards, and is its coverage and value measured?",
     "levels": {
      "0": "All response is manual.",
      "1": "A few scripts maintained by individuals; no governance.",
      "2": "A SOAR platform exists with playbooks for a small number of high-volume alert types; mostly enrichment rather than action.",
      "3": "Playbooks cover the highest-volume and highest-severity detection types, include automated containment for defined scenarios with explicit approval gates, and are version-controlled and tested.",
      "4": "Automation coverage of alert volume is measured, along with time saved and error rate; playbook failures are monitored and remediated; blast-radius controls and rollback procedures exist and are tested.",
      "5": "Automation decisions are risk-adaptive — confidence and asset criticality determine whether an action is automatic or approval-gated — and every detection ships with a linked response action by default."
     },
     "evidence": [
      "Version-controlled playbook repository with tests",
      "Automation coverage and time-saved metrics",
      "Rollback and blast-radius test records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "RS.MA-01",
       "RS.MI-01",
       "RS.MI-02",
       "PR.IR-01"
      ],
      "soc_cmm": [
       "Technology.SOAR",
       "Process.Incident response"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AA"
    },
    {
     "id": "AA.4",
     "name": "Advanced analytics governance",
     "weight": 11,
     "question": "Where machine learning, UEBA or statistical analytics are used, are they governed, explainable and validated like any other detection?",
     "levels": {
      "0": "No advanced analytics, or vendor black boxes running unmonitored.",
      "1": "Vendor ML features enabled with default settings and no evaluation.",
      "2": "Some analytics tuned by trial and error; behaviour is not understood by the team operating it.",
      "3": "Each analytic has a documented purpose, the behaviour it targets mapped to ATT&CK, its input features, training or baselining approach, expected output, and a named owner.",
      "4": "Analytics are evaluated on precision, recall and drift with a defined re-baselining cadence; outputs are explainable enough for an analyst to justify an action; failure modes and adversarial manipulation risks are documented.",
      "5": "Analytics are lifecycle-managed as models — versioned, monitored for drift and poisoning, validated by emulation like signature-based content, and retired when they stop earning their place."
     },
     "evidence": [
      "Analytic register with owners, features and ATT&CK mapping",
      "Precision/recall/drift evaluation records",
      "Model lifecycle and adversarial-risk documentation"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-02",
       "DE.AE-03",
       "GV.SC-04",
       "ID.RA-09"
      ],
      "soc_cmm": [
       "Technology.SIEM",
       "Process.Monitoring"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "AA"
    },
    {
     "id": "AA.5",
     "name": "Threat hunting programme",
     "weight": 15,
     "question": "Is hunting hypothesis-driven, threat-informed and productive of new detection — or is it browsing?",
     "levels": {
      "0": "No hunting capability exists in any form.",
      "1": "Occasional unstructured exploration when analysts have spare time.",
      "2": "Scheduled hunts with loose scope; findings recorded inconsistently; little output beyond \"nothing found\".",
      "3": "Hunts are hypothesis-driven, derived from the threat profile, threat models, attack trees and validation gaps; each has a documented hypothesis, data scope, method, result and a required output — a new detection, a tuning change, a visibility gap, or an evidenced negative result.",
      "4": "Hunt outcomes are measured — coverage of hypotheses against prioritised techniques, conversion rate to deployed detections, findings per hunt — and negative results are retained so the same ground is not re-covered blindly.",
      "5": "Hunting is continuous, partly automated (recurring hunts promoted to scheduled analytics), integrated with emulation so hunts are validated against known-good ground truth, and is a primary source of the detection backlog."
     },
     "evidence": [
      "Hunt library with hypotheses, methods and outcomes",
      "Hunt-to-detection conversion metric",
      "Promoted-hunt-to-analytic records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-02",
       "DE.CM-09",
       "ID.RA-01",
       "ID.IM-02"
      ],
      "soc_cmm": [
       "Process.Threat hunting"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AA"
    },
    {
     "id": "AA.7",
     "name": "Deception and adversary engagement",
     "weight": 13,
     "question": "Are deception assets — honeytokens, canary credentials, decoy hosts and services, tripwire data — deliberately placed at attack-tree choke points, so that touching them is a high-fidelity signal an adversary cannot avoid without abandoning the objective?",
     "levels": {
      "0": "No deception capability of any kind.",
      "1": "An unofficial honeypot someone once stood up; nobody monitors it and nobody would notice it firing.",
      "2": "A small set of deception assets deployed opportunistically — some canary files or a default honeypot — alerting exists but placement is unrelated to any threat model.",
      "3": "Deception is placed deliberately at attack-tree choke points and along modelled paths to crown jewels — canary credentials where credential theft is expected, decoy shares where discovery is expected, honeytokens inside the data an adversary would steal; every asset has an owner, a high-severity alert, and a response playbook, because a deception alert is close to zero false positive.",
      "4": "Deception coverage of modelled choke points is measured; assets are refreshed so they age like the estate around them; breadcrumbs lead credibly toward the decoys rather than leaving them to be stumbled upon; triggers are exercised in purple team scenarios and the alert path is proven end to end; alert noise is measured and kept negligible, and legitimate-touch incidents are investigated as placement defects.",
      "5": "Deception is adaptive — placement is recomputed as attack trees and the estate change, interaction telemetry feeds intelligence and emulation, and measured adversary cost (time wasted, tradecraft revealed, early eviction) is reported as a programme outcome."
     },
     "evidence": [
      "Deception asset register mapped to attack-tree choke points",
      "Choke-point coverage metric and refresh records",
      "Purple-team validation of trigger-to-alert path",
      "Measured alert noise rate, including periods with no trips"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.CM-01",
       "DE.AE-02",
       "ID.RA-01"
      ],
      "soc_cmm": [
       "Process.Threat hunting",
       "Technology"
      ],
      "mitre_engage": [
       "Expose",
       "Affect",
       "Elicit"
      ]
     },
     "attack_link": "Placement is derived from TM.3 attack trees; a deception alert at a choke point contributes status-3 evidence for the techniques that node carries.",
     "profile": "standard",
     "domain_id": "AA"
    },
    {
     "id": "AA.6",
     "name": "Case management and knowledge capture",
     "weight": 11,
     "question": "Is the knowledge generated by every investigation captured in a form that improves the next one?",
     "levels": {
      "0": "Investigations are tracked in email, chat or spreadsheets.",
      "1": "A ticketing system is used, with free-text notes of variable quality.",
      "2": "A case management platform exists with basic categorisation; quality depends on the analyst.",
      "3": "Cases carry a mandatory structure — ATT&CK classification, verdict, root cause, affected assets and identities, actions taken, and the detection(s) that fired or should have — enabling analysis across cases.",
      "4": "Case data is analysed for patterns (which detections produce value, which alert types waste time, which techniques recur) and this analysis directly drives the detection backlog and tuning priorities.",
      "5": "Case knowledge is a managed asset feeding a reusable investigation knowledge base, automated triage guidance, and analyst onboarding, with measured effect on time to competence and time to resolve."
     },
     "evidence": [
      "Mandatory case schema and completion metric",
      "Cross-case analysis driving backlog items",
      "Knowledge base usage and effect on resolution time"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "RS.MA-02",
       "RS.AN-03",
       "RS.AN-08",
       "ID.IM-04"
      ],
      "soc_cmm": [
       "Process.Incident response",
       "Technology.Case management"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "AA"
    },
    {
     "id": "AA.8",
     "name": "Agentic and AI-assisted operations",
     "weight": 11,
     "question": "Where AI assistants or autonomous agents take part in detection, triage, hunting or response, are they governed, bounded, auditable and measured?",
     "levels": {
      "0": "No AI or agentic assistance, or unmanaged personal use of assistants with operational data.",
      "1": "Individual analysts use general-purpose assistants informally; no policy, no record of what was pasted into them.",
      "2": "An approved assistant is available for defined tasks such as summarisation or query drafting, with a data-handling policy, but its output is unmeasured.",
      "3": "Agent roles are defined with an explicit task scope, the data they may see, the actions they may take, and the human approval points; agent-authored detection content enters the same lifecycle, testing and evidence requirements as human-authored content.",
      "4": "Agent output quality is measured against human baselines (triage accuracy, false-verdict rate, detection quality), agent actions are fully audited and attributable, authority is bounded by asset criticality and confidence, and rollback is tested.",
      "5": "Agents operate inside the closed loop with measured cycle-time benefit and no loss of assurance — their work is validated by emulation like any other detection, their identities and tool access are modelled as attack paths, and prompt-injection resistance is explicitly tested using untrusted content in the telemetry they read."
     },
     "evidence": [
      "Agent role definitions with task scope, data scope, authority and approval points",
      "Audit trail attributing agent actions and decisions",
      "Quality measurement against a human baseline",
      "Prompt-injection test results using adversary-controlled log content"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.RR-02",
       "GV.SC-04",
       "ID.RA-09",
       "DE.AE-02",
       "RS.MA-01",
       "PR.AA-05"
      ],
      "soc_cmm": [
       "Technology",
       "People.Roles",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "AA"
    }
   ]
  },
  {
   "id": "IR",
   "name": "Incident Response & Recovery",
   "weight": 10,
   "intent": "Detection without response is an expensive alarm. This domain measures the organisation's ability to act on what it detects, and — uniquely in this model — the strength of the feedback path from incidents back into detection.",
   "anti_pattern": "A polished incident response plan that has never been exercised, and post-incident reviews that produce lessons \"identified\" but never engineered.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "IR.1",
     "name": "Response plan, playbooks and readiness",
     "weight": 18,
     "question": "Are there current, tested response procedures covering the scenarios the threat profile says are most likely?",
     "levels": {
      "0": "No documented incident response plan.",
      "1": "A generic plan exists, out of date, unfamiliar to the people who would use it.",
      "2": "A maintained plan with defined roles and escalation, plus playbooks for a few common scenarios.",
      "3": "Scenario playbooks are derived from the prioritised threat profile and attack trees — ransomware, business email compromise, cloud identity compromise, supply chain, insider, destructive attack, extortion without encryption — each with decision points, authority levels and communication requirements.",
      "4": "Playbook coverage of prioritised scenarios is measured; playbooks are updated after every real incident and every exercise; out-of-hours and degraded-infrastructure operation is explicitly addressed and tested.",
      "5": "Playbooks are living, partly executable (linked to orchestration), version-controlled, and validated in the same cycle as detection content, with measured readiness per scenario."
     },
     "evidence": [
      "Scenario playbook set traced to threat profile",
      "Post-incident and post-exercise update records",
      "Out-of-band operating procedure test"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "RS.MA-01",
       "ID.IM-04",
       "PR.IR-03",
       "RC.RP-01"
      ],
      "soc_cmm": [
       "Process.Incident response"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "IR"
    },
    {
     "id": "IR.2",
     "name": "Detection-to-response handoff and SLAs",
     "weight": 17,
     "question": "Is the path from alert to responder defined, measured and reliable at all hours?",
     "levels": {
      "0": "No defined handoff. Alerts are picked up when noticed.",
      "1": "Informal handoff by chat message; coverage depends on who is awake.",
      "2": "Defined triage tiers and escalation paths; response times are not measured.",
      "3": "Severity-based SLAs exist for acknowledgement, triage and escalation, with defined coverage hours, on-call rotation and escalation-of-last-resort.",
      "4": "SLA attainment is measured per severity and reported; breaches are analysed for cause; queue ageing and abandonment are monitored; detection severity is calibrated against actual incident outcomes.",
      "5": "Handoff is automated with dynamic routing by detection type and asset criticality; time to acknowledge and time to contain are trended and actively reduced; capacity is modelled against alert volume forecasts."
     },
     "evidence": [
      "Severity/SLA matrix with coverage model",
      "SLA attainment and queue ageing reports",
      "Severity calibration analysis"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "DE.AE-08",
       "RS.MA-01",
       "RS.MA-02",
       "RS.MA-03"
      ],
      "soc_cmm": [
       "Process.Incident response",
       "Business.Services"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "IR"
    },
    {
     "id": "IR.3",
     "name": "Forensic readiness and evidence handling",
     "weight": 15,
     "question": "Can you acquire and defensibly preserve the evidence needed to answer what happened — including in cloud and SaaS?",
     "levels": {
      "0": "No forensic capability. Evidence is destroyed by remediation.",
      "1": "Ad hoc collection using whatever tools are to hand; no chain of custody.",
      "2": "Documented collection procedures for endpoints; retention adequate for common cases; cloud and SaaS evidence is uncertain.",
      "3": "Forensic readiness is planned — retention aligned to realistic dwell times, remote acquisition capability, memory capture, cloud and SaaS evidence sources identified and pre-authorised, chain of custody maintained, and legal/HR/regulatory requirements built in.",
      "4": "Readiness is tested (can you actually acquire from that cloud workload, that SaaS tenant, that OT segment, on a Sunday?); acquisition times are measured; gaps in evidential coverage are registered and closed.",
      "5": "Evidence acquisition is automated on incident declaration, forensic data is preserved before containment destroys it, and readiness is validated in every major exercise and red team engagement."
     },
     "evidence": [
      "Forensic readiness plan covering cloud and SaaS",
      "Acquisition test results and timings",
      "Automated preservation-on-declaration configuration"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "RS.AN-03",
       "RS.AN-06",
       "RS.AN-07",
       "PR.DS-01"
      ],
      "soc_cmm": [
       "Process.Incident response",
       "Technology.Forensics"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "IR"
    },
    {
     "id": "IR.4",
     "name": "Containment, eradication and recovery",
     "weight": 17,
     "question": "Can you contain and recover at the speed and scale a real intrusion demands, and have you proven it?",
     "levels": {
      "0": "No defined containment capability; response is improvised.",
      "1": "Manual containment by individual administrators, slow and inconsistent.",
      "2": "Containment options exist for endpoints (isolate, block hash) with defined authority; identity and cloud containment are manual and slow.",
      "3": "Containment is defined across all planes — endpoint isolation, identity disablement and session/token revocation, network segmentation, cloud role and key revocation, email clawback, third-party access suspension — with authority, prerequisites and business impact documented for each.",
      "4": "Containment and recovery times are measured in exercises and real incidents; mass-scale actions are tested; recovery capability is validated against destructive scenarios including backup integrity and immutability testing.",
      "5": "Containment is largely automated with risk-adaptive gating, tested at scale on a defined cadence, and recovery objectives are demonstrated rather than asserted, including for identity infrastructure and cloud control planes."
     },
     "evidence": [
      "Containment action catalogue by plane with authority levels",
      "Timed containment and recovery exercise results",
      "Backup immutability and restoration test evidence"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "RS.MI-01",
       "RS.MI-02",
       "RC.RP-01",
       "RC.RP-05",
       "PR.DS-11"
      ],
      "soc_cmm": [
       "Process.Incident response",
       "Technology"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "IR"
    },
    {
     "id": "IR.5",
     "name": "Exercising and crisis management",
     "weight": 16,
     "question": "Are response and crisis capabilities exercised realistically, including at executive level, with findings tracked?",
     "levels": {
      "0": "No exercises of any kind are conducted.",
      "1": "An occasional informal walkthrough of the plan.",
      "2": "Annual tabletop exercise, generic scenario, limited participation.",
      "3": "A programme of exercises at varying intensity — tabletop, functional, technical simulation, and executive crisis — using scenarios drawn from the threat profile and involving legal, communications, business owners and relevant third parties.",
      "4": "Every exercise generates tracked findings with owners and dates; exercise realism increases over time; participation and performance are measured; regulatory notification and disclosure decision-making is exercised under time pressure.",
      "5": "Exercises are unannounced where appropriate, integrated with red team engagements so the exercise is a real detection event, and improvement across cycles is demonstrated with objective measures."
     },
     "evidence": [
      "Multi-year exercise programme and scenario provenance",
      "Findings register with closure",
      "Evidence of exercises integrated with red team activity"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-02",
       "PR.AT-01",
       "RS.CO-02",
       "RC.CO-03"
      ],
      "soc_cmm": [
       "People.Training",
       "Process.Incident response"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "IR"
    },
    {
     "id": "IR.6",
     "name": "Post-incident review to detection backlog",
     "weight": 17,
     "question": "Does every incident measurably improve detection — and is the \"why did we not see this sooner?\" question answered structurally every time?",
     "levels": {
      "0": "No post-incident review.",
      "1": "Informal debriefs after major incidents only; nothing recorded.",
      "2": "Reviews are held and documented for significant incidents; actions are recorded but rarely closed.",
      "3": "Every incident above a defined threshold gets a blameless review that explicitly reconstructs the timeline, identifies the earliest point at which detection was possible, and produces detection, telemetry and control actions with owners.",
      "4": "Action closure is tracked and reported; the gap between adversary first action and first detection is measured per incident and trended; recurring root causes are escalated as systemic issues.",
      "5": "Reviews feed threat models, attack trees, emulation plans and the detection backlog automatically; \"would we detect this now?\" is answered by re-emulating the incident and proving it, with the result recorded against the review."
     },
     "evidence": [
      "Blameless review records with earliest-detection-point analysis",
      "Action closure and time-to-first-detection trends",
      "Re-emulation proof that the incident is now detected"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-01",
       "ID.IM-04",
       "RC.RP-06",
       "RS.AN-08"
      ],
      "soc_cmm": [
       "Process.Incident response",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "IR"
    }
   ]
  },
  {
   "id": "GV",
   "name": "Governance, Metrics & Continuous Improvement",
   "weight": 10,
   "intent": "Determines whether the capability is deliberately directed and sustainable, or dependent on a few motivated individuals. Also covers the honesty of the metrics used to report it upward.",
   "anti_pattern": "Reporting alert volume and \"threats blocked\" to the board as evidence of security performance, while nobody can state how much of the threat profile is actually detectable.",
   "ceiling_rule": null,
   "subcapabilities": [
    {
     "id": "GV.1",
     "name": "Strategy, mandate and funding",
     "weight": 15,
     "question": "Does the detection capability have an articulated strategy, an explicit mandate and funding tied to the risks it is meant to reduce?",
     "levels": {
      "0": "No strategy. The capability exists as a by-product of tool purchases.",
      "1": "Direction is set informally by whoever leads the function; funding is reactive.",
      "2": "A written plan exists, largely a list of tools and headcount for the year.",
      "3": "A multi-year strategy states target maturity per domain, is explicitly derived from the threat profile and business risk appetite, and has executive sponsorship and committed funding.",
      "4": "Strategy progress is reviewed against measured maturity at least twice a year; investment decisions cite validation evidence and coverage gaps; trade-offs are documented.",
      "5": "Strategy is dynamically adjusted from threat landscape change and measured risk reduction, with funding decisions demonstrably driven by validated efficacy data rather than vendor cycles."
     },
     "evidence": [
      "Signed multi-year strategy with target maturity per domain",
      "Investment cases citing coverage and validation data",
      "Review minutes showing strategy adjustment"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.OC-01",
       "GV.RM-01",
       "GV.RM-03",
       "GV.RR-03"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Business.Strategy"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "GV"
    },
    {
     "id": "GV.2",
     "name": "Roles, skills and capability development",
     "weight": 15,
     "question": "Are the roles the model requires actually defined and staffed, with a deliberate path to build the skills the work needs?",
     "levels": {
      "0": "No defined roles; whoever is available does the work.",
      "1": "Roles exist in name; responsibilities overlap and gaps are covered informally.",
      "2": "Job descriptions exist for core SOC roles; detection engineering, threat modeling and emulation are collateral duties.",
      "3": "Distinct roles are defined and staffed for intelligence, detection engineering, hunting, emulation/purple team and response, with documented responsibilities and a competency framework.",
      "4": "Skills are assessed against the framework, gaps drive a training plan with budget, and key-person dependency is measured and reduced; succession and cross-training are deliberate.",
      "5": "Capability development is continuous — internal ranges, rotation between offensive and defensive roles, published research — and retention and competency are measured as leading indicators of capability."
     },
     "evidence": [
      "Role definitions and competency framework",
      "Skills assessment and funded training plan",
      "Key-person dependency analysis"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.RR-02",
       "GV.RR-04",
       "PR.AT-01",
       "PR.AT-02"
      ],
      "soc_cmm": [
       "People.Employees",
       "People.Training",
       "People.Roles"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "GV"
    },
    {
     "id": "GV.3",
     "name": "Metrics and performance measurement",
     "weight": 18,
     "question": "Are the metrics used to run and report the capability meaningful measures of detection effectiveness, or activity counts?",
     "levels": {
      "0": "No metrics beyond what tools display by default.",
      "1": "Activity counts reported — alerts handled, tickets closed, threats blocked.",
      "2": "Operational metrics exist (volumes, MTTD, MTTR) with inconsistent definitions and no target.",
      "3": "A defined metric set covers effectiveness (Validated Coverage Score, detection precision, time from adversary action to detection), efficiency (triage time, automation rate), and programme health (backlog ageing, gap closure), each with a written definition, owner and target.",
      "4": "Metrics are trended, reviewed in a formal forum, and acted on; the metric set is periodically challenged for gaming and perverse incentives; definitions are stable enough for period-on-period comparison.",
      "5": "Metrics link measured detection capability to business risk reduction and are used in prioritisation and investment; anti-gaming controls are explicit and metrics are independently verifiable from raw evidence."
     },
     "evidence": [
      "Metric catalogue with definitions, owners and targets",
      "Trended reporting pack and review minutes",
      "Anti-gaming review record"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.OV-01",
       "GV.OV-02",
       "GV.OV-03",
       "ID.IM-03"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Process.Reporting"
      ]
     },
     "attack_link": null,
     "profile": "essential",
     "domain_id": "GV"
    },
    {
     "id": "GV.4",
     "name": "Risk and compliance alignment",
     "weight": 14,
     "question": "Is detection capability expressed in the organisation's risk language and mapped to the obligations it must satisfy — without letting compliance drive the design?",
     "levels": {
      "0": "No connection between detection capability and risk management or compliance.",
      "1": "Compliance obligations are met by assertion; detection is not represented in the risk register.",
      "2": "Detection appears in the risk register as a generic control; regulatory obligations are tracked separately.",
      "3": "Detection capability gaps appear as named risks with owners and treatment plans; obligations (NIS2, DORA, sector regulation, contractual) are mapped to specific model sub-capabilities; crosswalks to NIST CSF 2.0 and ISO 27001 are maintained.",
      "4": "Risk assessments cite measured coverage and validation evidence rather than control existence; residual risk per crown jewel is expressed with reference to the attack trees and validated efficacy scores.",
      "5": "Detection risk is quantified and integrated with enterprise risk quantification; compliance evidence is a by-product of the operating model rather than a separate exercise."
     },
     "evidence": [
      "Risk register entries citing coverage and validation data",
      "Obligation-to-sub-capability mapping",
      "Automatically generated compliance evidence"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.RM-02",
       "GV.RM-04",
       "GV.OC-03",
       "ID.RA-05",
       "ID.RA-06"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Business.Compliance"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "GV"
    },
    {
     "id": "GV.5",
     "name": "Executive and board reporting",
     "weight": 13,
     "question": "Do decision-makers receive an honest, comparable picture of what the organisation can and cannot detect?",
     "levels": {
      "0": "No reporting above the security team.",
      "1": "Occasional narrative updates, usually after an incident.",
      "2": "Regular reporting of activity volumes and tool status.",
      "3": "Reporting states maturity by domain, validated coverage against the prioritised threat profile, known blind spots, and the risks accepted as a result — in business language, with the assumptions stated.",
      "4": "Reporting is comparable period on period, includes trend and forecast, distinguishes clearly between what has been tested and what is assumed, and explicitly reports capability that has degraded.",
      "5": "Reporting supports investment decisions with modelled risk reduction per option, is independently assured, and includes benchmarking against sector peers where credible data exists."
     },
     "evidence": [
      "Executive reporting pack showing tested versus assumed capability",
      "Period-on-period comparability statement",
      "Independent assurance or benchmarking record"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.OV-01",
       "GV.OV-02",
       "GV.RR-01",
       "RS.CO-03"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Process.Reporting"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "GV"
    },
    {
     "id": "GV.6",
     "name": "Continuous improvement cadence",
     "weight": 13,
     "question": "Is improvement a managed, funded, scheduled activity with measured outcomes?",
     "levels": {
      "0": "Improvement happens only after a serious incident.",
      "1": "Individuals improve things when time allows.",
      "2": "An improvement backlog exists but competes unsuccessfully with operational work.",
      "3": "A defined cadence exists — regular retrospectives, a prioritised improvement backlog with protected capacity, and reassessment against this model at least annually.",
      "4": "Improvement outcomes are measured against the maturity baseline; reassessment is partly independent to counter self-assessment optimism; regression is investigated as seriously as stagnation.",
      "5": "Improvement is continuous and data-driven, with capacity formally allocated, cycle times measured, and demonstrable maturity progression across multiple assessment cycles."
     },
     "evidence": [
      "Improvement backlog with protected capacity allocation",
      "Successive TID-CMM assessment results showing progression",
      "Independent or peer-reviewed reassessment record"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "ID.IM-01",
       "ID.IM-03",
       "GV.OV-03"
      ],
      "soc_cmm": [
       "Business.Governance",
       "Process"
      ]
     },
     "attack_link": null,
     "profile": "standard",
     "domain_id": "GV"
    },
    {
     "id": "GV.7",
     "name": "Third-party and supply-chain detection",
     "weight": 12,
     "question": "Does detection extend to the third parties, managed services and software supply chain through which adversaries reach you?",
     "levels": {
      "0": "Third-party activity is outside the detection scope entirely.",
      "1": "Third-party access exists but is not distinguished in telemetry.",
      "2": "Third-party accounts are identifiable in logs; managed security providers report to defined SLAs that are not verified.",
      "3": "Third-party and vendor access paths are modelled as attack paths, monitored with specific detections, and outsourced detection responsibilities are explicitly divided in a documented responsibility matrix.",
      "4": "Provider performance is verified independently — including by emulation against provider-monitored scope — rather than accepted from their reporting; software supply chain and CI/CD telemetry is covered; fourth-party dependency risk is considered.",
      "5": "Supply-chain compromise scenarios are emulated end to end, detection responsibilities are contractually specified with testable service levels, and provider detection efficacy is measured as part of the coverage score."
     },
     "evidence": [
      "Responsibility matrix for outsourced detection",
      "Emulation results against provider-monitored scope",
      "Supply-chain scenario emulation records"
     ],
     "crosswalk": {
      "nist_csf_2": [
       "GV.SC-04",
       "GV.SC-07",
       "GV.SC-10",
       "ID.AM-04",
       "DE.CM-06"
      ],
      "soc_cmm": [
       "Business.Customers",
       "Business.Governance"
      ]
     },
     "attack_link": null,
     "profile": "comprehensive",
     "domain_id": "GV"
    }
   ]
  }
 ]
};
export type TidModel = typeof TID_CMM_MODEL;
