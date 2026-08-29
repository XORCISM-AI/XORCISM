/**
 * tirCmmModel.ts — canonical TIR-CMM (Threat-Informed Response Capability Maturity Model) v1.0
 * model, fetched from https://tir-cmm.com/data/tir-cmm-model.json. Author: Reza Adineh.
 * Model © CC BY-ND 4.0; schemas CC BY 4.0 (attribution required, no derivatives of the model text).
 * 8 domains / 58 sub-capabilities, bands L0–L5, evidence VC0–VC3 (score caps), assessment tiers
 * (pulse/baseline/assurance), Containment Lattice (8 stages × 8 asset classes), constraints R1–R8,
 * and a crosswalk to NIST CSF 2.0 / 800-61 / ISO / RE&CT / D3FEND / SOC-CMM. Powers /tir-cmm.
 * Refresh with: python xorcism_python/importers/import_tircmm.py --refresh-model
 */
export const TIR_CMM_MODEL = {
 "model": "TIR-CMM",
 "name": "Threat-Informed Response Capability Maturity Model",
 "version": "1.0",
 "released": "2026-08-24",
 "tool_version": "1.0.0",
 "schema_version": "1.0",
 "licence": {
  "model": "CC BY-ND 4.0",
  "schemas": "CC BY 4.0",
  "tooling": "source-available, all rights reserved"
 },
 "parent": {
  "model": "UTIOM",
  "url": "https://utiom.de"
 },
 "companion": {
  "model": "TID-CMM",
  "url": "https://tid-cmm.com"
 },
 "bands": [
  {
   "id": "L0",
   "min": 0,
   "max": 0.99,
   "name": "Improvised",
   "def": "Response is individual heroics. The outcome depends on who happens to be on shift. This is a build project, not an improvement project."
  },
  {
   "id": "L1",
   "min": 1,
   "max": 1.99,
   "name": "Documented",
   "def": "Plans exist on paper. Execution is unrehearsed and personality-dependent. The document has never met a clock."
  },
  {
   "id": "L2",
   "min": 2,
   "max": 2.99,
   "name": "Repeatable",
   "def": "Playbooks and tooling are in place and consistently executed for known scenarios, but remain unproven under time pressure. The most common band, and the band where response spending most exceeds response capability."
  },
  {
   "id": "L3",
   "min": 3,
   "max": 3.99,
   "name": "Threat-informed",
   "def": "Response traces to modelled attack paths and crown jewels. Containment is pre-authorised. Exercises are regular and evidenced. The realistic target for most organisations."
  },
  {
   "id": "L4",
   "min": 4,
   "max": 4.99,
   "name": "Validated",
   "def": "A standing validation function exists. Containment is demonstrably inside the breakout window for priority actors. Requires tempo evidence."
  },
  {
   "id": "L5",
   "min": 5,
   "max": 5,
   "name": "Adaptive",
   "def": "Response adapts as the threat model changes. Treat any L5 claim with scepticism unless the evidence is exceptional."
  }
 ],
 "evidence": [
  {
   "v": 0,
   "vc": "VC0",
   "name": "Assertion only",
   "cap": 1,
   "expect": "None, or a verbal claim.",
   "means": "The claim may be recorded, but readiness cannot be credited above 1."
  },
  {
   "v": 1,
   "vc": "VC1",
   "name": "Design or policy",
   "cap": 2,
   "expect": "A document, policy, screenshot, or partial implementation.",
   "means": "Something exists on paper. Operational effectiveness is unproven."
  },
  {
   "v": 2,
   "vc": "VC2",
   "name": "Implemented and tested",
   "cap": 4,
   "expect": "Implementation evidence plus a test result, ticket, or system record.",
   "means": "May reach Measured once tests and outcomes are current."
  },
  {
   "v": 3,
   "vc": "VC3",
   "name": "Repeatably validated",
   "cap": 5,
   "expect": "Recent, repeatable, independently reviewable proof from the live environment.",
   "means": "May reach Adaptive where validation is sustained."
  }
 ],
 "evidence_cap": {
  "0": 1,
  "1": 2,
  "2": 4,
  "3": 5
 },
 "stages": [
  {
   "id": "S0",
   "name": "Prevent & Harden",
   "lambda": 1.6,
   "q": "Can architecture stop it, or materially slow it, before response is needed?",
   "attack": "ATT&CK Mitigations (M-codes); D3FEND Harden"
  },
  {
   "id": "S1",
   "name": "Initial Access & Foothold",
   "lambda": 1.5,
   "q": "Can we cut the entry before execution?",
   "attack": "Initial Access, Resource Development"
  },
  {
   "id": "S2",
   "name": "Execution & Persistence",
   "lambda": 1.4,
   "q": "Can we kill it and prevent return?",
   "attack": "Execution, Persistence, Defense Evasion"
  },
  {
   "id": "S3",
   "name": "Privilege Escalation & Credential Access",
   "lambda": 1.3,
   "q": "Can we revoke and re-trust at speed?",
   "attack": "Privilege Escalation, Credential Access"
  },
  {
   "id": "S4",
   "name": "Discovery & Lateral Movement",
   "lambda": 1.2,
   "q": "Can we sever the path mid-flight?",
   "attack": "Discovery, Lateral Movement"
  },
  {
   "id": "S5",
   "name": "Collection & Staging",
   "lambda": 1,
   "q": "Can we interrupt before the data moves?",
   "attack": "Collection"
  },
  {
   "id": "S6",
   "name": "Command & Control and Exfiltration",
   "lambda": 1,
   "q": "Can we block the egress and the channel?",
   "attack": "Command and Control, Exfiltration"
  },
  {
   "id": "S7",
   "name": "Impact & Objective",
   "lambda": 0.8,
   "q": "Can we limit, reverse and restore?",
   "attack": "Impact"
  }
 ],
 "asset_classes": [
  {
   "id": "A1",
   "name": "Identity & Access Infrastructure",
   "short": "Identity",
   "desc": "Tier-0: AD, Entra ID, IdP, PAM, federation",
   "prims": "Disable, revoke session/token, force re-auth, break trust, tier-isolate"
  },
  {
   "id": "A2",
   "name": "Endpoint & User Compute",
   "short": "Endpoint",
   "desc": "Laptops, desktops, VDI, mobile",
   "prims": "EDR network-isolate, kill process, quarantine, reimage"
  },
  {
   "id": "A3",
   "name": "Server & Datacentre Workload",
   "short": "Server",
   "desc": "On-prem and IaaS servers, hypervisors, containers",
   "prims": "Isolate, snapshot, quiesce, failover, rebuild"
  },
  {
   "id": "A4",
   "name": "Cloud Control Plane & SaaS",
   "short": "Cloud/SaaS",
   "desc": "Cloud management planes, SaaS tenants, OAuth apps",
   "prims": "Revoke key/role, quarantine principal, disable API, tenant restrict"
  },
  {
   "id": "A5",
   "name": "Network & Edge",
   "short": "Network",
   "desc": "VPN, firewall, proxy, DNS, email gateway",
   "prims": "Block, sinkhole, ACL, disable tunnel, quarantine mail"
  },
  {
   "id": "A6",
   "name": "Application, Source & CI/CD",
   "short": "App/CI-CD",
   "desc": "Source repos, build pipelines, artefact stores, signing",
   "prims": "Freeze pipeline, revoke signing key, roll back release, disable webhook"
  },
  {
   "id": "A7",
   "name": "Data Stores & Backup",
   "short": "Data/Backup",
   "desc": "Databases, file estates, object stores, backup systems",
   "prims": "Restrict access, immutable snapshot, restore, integrity verify"
  },
  {
   "id": "A8",
   "name": "OT / ICS / IoT & Specialist",
   "short": "OT/ICS",
   "desc": "Industrial control, building systems, medical, specialist",
   "prims": "Segment, safe-state, manual fallback"
  }
 ],
 "response_readiness_status": [
  {
   "v": 0,
   "name": "No option",
   "def": "No means exists to act at this stage on this asset class. You would improvise or watch."
  },
  {
   "v": 1,
   "name": "Manual only",
   "def": "An action is technically possible but ad-hoc, undocumented, dependent on a specific individual, or gated behind an approval path with no defined SLA."
  },
  {
   "v": 2,
   "name": "Engineered",
   "def": "A documented, parameterised playbook exists; tooling can execute it; an owner is named; authority is defined in advance. Unproven."
  },
  {
   "v": 3,
   "name": "Proven",
   "def": "Executed against a real incident or live-fire exercise within the recency window, met its stage time objective, and the blast radius was as designed."
  }
 ],
 "criticality_tiers": [
  {
   "t": 3,
   "id": "T1",
   "name": "Crown jewel",
   "desc": "The cell is a crown jewel, or directly hosts one."
  },
  {
   "t": 2,
   "id": "T2",
   "name": "On path",
   "desc": "The cell lies on a modelled attack path to a crown jewel."
  },
  {
   "t": 1,
   "id": "T3",
   "name": "Peripheral",
   "desc": "In scope, but peripheral to crown-jewel paths."
  }
 ],
 "domains": [
  {
   "id": "RP",
   "name": "Response Preparation & Readiness",
   "weight": 10,
   "question": "Are we set up to run an incident at all?",
   "note": "Cheap to build, catastrophic to lack, and consistently over-scored.",
   "sub_capabilities": [
    {
     "id": "RP-1",
     "name": "Incident response plan and scope",
     "weight": 15,
     "anchor_3": "Plan is organisation-specific, names roles, covers cloud/identity/OT as applicable, reviewed annually.",
     "evidence": "Plan document + version history + incident references",
     "action": {
      "effort": 2,
      "type": "process",
      "owner": "IR lead",
      "act": "Rewrite the IR plan around your own crown jewels, identity estate and cloud tenancy; delete every section that could belong to any other organisation.",
      "outcome": "A plan that names your systems, your people and your regulators."
     }
    },
    {
     "id": "RP-2",
     "name": "Severity and classification model",
     "weight": 15,
     "anchor_3": "Documented severity matrix driven by crown-jewel and business impact, applied consistently.",
     "evidence": "Severity matrix + sample of classified incidents",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "IR lead",
      "act": "Build a one-page severity matrix whose top tier is defined by crown-jewel involvement, then re-classify your last thirty incidents against it.",
      "outcome": "A severity matrix and thirty incidents classified the same way twice."
     }
    },
    {
     "id": "RP-3",
     "name": "Roles, rotas and 24×7 reachability",
     "weight": 15,
     "anchor_3": "Named IR roles, documented rota, tested reachability, defined deputies.",
     "evidence": "Rota + unannounced call-out test records",
     "action": {
      "effort": 1,
      "type": "exercise",
      "owner": "SOC manager",
      "act": "Run an unannounced call-out test against the current rota at 02:00 and record who answered, how quickly, and who never did.",
      "outcome": "A dated reachability test record with real answer times and gaps."
     }
    },
    {
     "id": "RP-4",
     "name": "Response tooling readiness",
     "weight": 15,
     "anchor_3": "Response tooling (EDR console, SOAR, forensic kit, out-of-band comms) is inventoried and access-tested.",
     "evidence": "Tool inventory + access test log",
     "action": {
      "effort": 1,
      "type": "tooling",
      "owner": "IR lead",
      "act": "List every tool you would need in the first hour, then have each on-call responder log into all of them today and record the failures.",
      "outcome": "A tool inventory with a dated access-test log per responder."
     }
    },
    {
     "id": "RP-5",
     "name": "Out-of-band communications and war-room",
     "weight": 10,
     "anchor_3": "Documented out-of-band channel and bridge, contact tree maintained.",
     "evidence": "Exercise report showing out-of-band use",
     "action": {
      "effort": 2,
      "type": "tooling",
      "owner": "IR lead",
      "act": "Stand up a bridge and messaging channel that depend on neither corporate identity nor corporate email, and run the next exercise entirely on them.",
      "outcome": "Out-of-band comms proven in an exercise report, not just documented."
     }
    },
    {
     "id": "RP-6",
     "name": "Third-party, retainer and supplier readiness",
     "weight": 15,
     "anchor_3": "IR retainer or in-house equivalent in place, SLAs known, onboarding pre-completed.",
     "evidence": "Retainer contract + activation or exercise record",
     "action": {
      "effort": 3,
      "type": "governance",
      "owner": "CISO",
      "act": "Put an IR retainer, or a funded in-house equivalent, under contract with a stated activation SLA and complete the onboarding before you need it.",
      "outcome": "A signed retainer with onboarding done and activation tested."
     }
    },
    {
     "id": "RP-7",
     "name": "Legal, regulatory and communications preparation",
     "weight": 15,
     "anchor_3": "Reporting obligations mapped (GDPR/DORA/NIS2/sector), counsel identified, holding statements drafted.",
     "evidence": "Obligation register + evidence of clock adherence",
     "action": {
      "effort": 2,
      "type": "governance",
      "owner": "Legal & compliance",
      "act": "Map every reporting obligation to a named clock and owner, identify your breach counsel, and draft holding statements for your top three scenarios.",
      "outcome": "An obligation register with clocks, named counsel and pre-drafted statements."
     }
    }
   ]
  },
  {
   "id": "RA",
   "name": "Response Authority & Decision Rights",
   "weight": 12,
   "question": "Is someone permitted to act, in time?",
   "note": "The domain no existing maturity model measures. Response fails here more often than it fails on tooling.",
   "sub_capabilities": [
    {
     "id": "RA-1",
     "name": "Pre-authorised containment actions",
     "weight": 25,
     "anchor_3": "A defined set of containment actions is pre-authorised by asset class and severity, documented and signed off by business owners.",
     "evidence": "Signed authorisation matrix mapped to lattice cells",
     "action": {
      "effort": 2,
      "type": "authority",
      "owner": "Business service owner",
      "act": "Draft a containment authorisation matrix covering isolate, disable and revoke per asset class and severity, then get named business owners to sign it.",
      "outcome": "A signed authorisation matrix mapped to lattice cells."
     }
    },
    {
     "id": "RA-2",
     "name": "Decision latency measurement (MTTDecide)",
     "weight": 20,
     "anchor_3": "MTTDecide is measured separately from MTTR, per severity, and reported.",
     "evidence": "Metric series with timestamps from the case system",
     "action": {
      "effort": 1,
      "type": "measurement",
      "owner": "SOC manager",
      "act": "Measure the gap between alert-validated and containment-authorised timestamps on your last twenty incidents, and report it separately from MTTR.",
      "outcome": "A dated MTTDecide series, split from MTTR, per severity."
     }
    },
    {
     "id": "RA-3",
     "name": "Escalation thresholds and triggers",
     "weight": 15,
     "anchor_3": "Documented, objective escalation triggers tied to severity and crown-jewel involvement.",
     "evidence": "Trigger definitions + escalation audit trail",
     "action": {
      "effort": 1,
      "type": "authority",
      "owner": "IR lead",
      "act": "Write objective escalation triggers — crown jewel touched, Tier-0 identity involved, encryption observed — so escalation stops depending on which analyst is on shift.",
      "outcome": "Escalation triggers anyone on shift can apply without asking."
     }
    },
    {
     "id": "RA-4",
     "name": "Out-of-hours and degraded-mode authority",
     "weight": 15,
     "anchor_3": "Named out-of-hours decision authority with documented deputies and a defined maximum response time.",
     "evidence": "Unannounced out-of-hours exercise record",
     "action": {
      "effort": 1,
      "type": "authority",
      "owner": "CISO",
      "act": "Name the person who can authorise containment at 03:00, name two deputies, and publish the maximum time they are permitted to take.",
      "outcome": "A named out-of-hours authority, deputies, and a stated answer time."
     }
    },
    {
     "id": "RA-5",
     "name": "Business impact acceptance and risk ownership",
     "weight": 15,
     "anchor_3": "Business owners have accepted, in advance and in writing, the disruption cost of defined containment tiers.",
     "evidence": "Signed impact-acceptance records",
     "action": {
      "effort": 1,
      "type": "authority",
      "owner": "Business service owner",
      "act": "Get the owner of each crown-jewel service to accept in writing the downtime cost of each containment tier, before an incident forces the conversation.",
      "outcome": "Signed impact-acceptance records for every crown-jewel service."
     }
    },
    {
     "id": "RA-6",
     "name": "Crisis and executive decision structure",
     "weight": 10,
     "anchor_3": "Documented crisis management structure with defined activation criteria and executive decision rights.",
     "evidence": "Crisis activation log + executive exercise record",
     "action": {
      "effort": 1,
      "type": "governance",
      "owner": "Executive sponsor",
      "act": "Write one page defining what activates crisis management, who chairs it and which decisions the executive owns, and take it to the board for sign-off.",
      "outcome": "Board-approved activation criteria and executive decision rights."
     }
    }
   ]
  },
  {
   "id": "RE",
   "name": "Response Engineering & Playbooks",
   "weight": 16,
   "question": "Is response engineered, or written?",
   "note": "The largest domain. Response content deserves the same engineering discipline as detection content.",
   "sub_capabilities": [
    {
     "id": "RE-1",
     "name": "Playbook coverage of the lattice",
     "weight": 15,
     "anchor_3": "Every Tier-1 and Tier-2 lattice cell has an associated playbook or documented response procedure.",
     "evidence": "Playbook-to-cell coverage map",
     "action": {
      "effort": 3,
      "type": "engineering",
      "owner": "Head of security engineering",
      "act": "Map every existing playbook onto the stage-by-asset lattice, then write response procedures for the Tier-1 cells that come back empty.",
      "outcome": "A playbook-to-cell coverage map with no empty crown-jewel cells."
     }
    },
    {
     "id": "RE-2",
     "name": "Threat-informed derivation",
     "weight": 12,
     "anchor_3": "Playbooks derive from modelled attack paths, crown jewels and priority actor TTPs.",
     "evidence": "Traceability matrix: actor → path → stage → asset → playbook",
     "action": {
      "effort": 2,
      "type": "process",
      "owner": "Threat intelligence lead",
      "act": "Take your three priority actors, model their paths to your crown jewels, and record which playbook covers each stage of each path.",
      "outcome": "A traceability matrix from actor to path to stage to playbook."
     }
    },
    {
     "id": "RE-3",
     "name": "Playbook-as-code and version control",
     "weight": 12,
     "anchor_3": "Playbooks are stored in version control with review, history and change approval.",
     "evidence": "Repository + CI pipeline evidence",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Head of security engineering",
      "act": "Move every playbook out of the wiki into version control and require a reviewed pull request for any change to one.",
      "outcome": "Playbooks in a repository with review history and change approval."
     }
    },
    {
     "id": "RE-4",
     "name": "Playbook testing before release",
     "weight": 12,
     "anchor_3": "Every playbook is executed in a test or staging context before production release.",
     "evidence": "CI test results",
     "action": {
      "effort": 3,
      "type": "engineering",
      "owner": "Head of security engineering",
      "act": "Build a staging context where playbooks execute against test assets, and block production release of any playbook until its run passes.",
      "outcome": "CI test results attached to every playbook release."
     }
    },
    {
     "id": "RE-5",
     "name": "Parameterisation and reusability",
     "weight": 8,
     "anchor_3": "Playbooks are built from reusable, parameterised response actions rather than duplicated steps.",
     "evidence": "Response-action library + composition evidence",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Response engineering lead",
      "act": "Extract the response steps repeated across your playbooks into a parameterised action library, then rebuild your three largest playbooks from it.",
      "outcome": "A reusable action library with playbooks composed from it."
     }
    },
    {
     "id": "RE-6",
     "name": "Decision points and human gates",
     "weight": 10,
     "anchor_3": "Playbooks contain explicit decision points, named decision owners, and defined default actions on timeout.",
     "evidence": "Playbook with instrumented decision points",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "IR lead",
      "act": "Annotate every decision point in your playbooks with the named role that decides and the action that fires automatically if nobody does.",
      "outcome": "Playbooks with named deciders and a default action on timeout."
     }
    },
    {
     "id": "RE-7",
     "name": "Playbook lifecycle and deprecation",
     "weight": 8,
     "anchor_3": "Playbooks have owners, review cycles and a deprecation process.",
     "evidence": "Lifecycle register + health metrics",
     "action": {
      "effort": 1,
      "type": "governance",
      "owner": "SOC manager",
      "act": "Give every playbook a named owner and a review date, and retire the ones nobody has opened or executed in a year.",
      "outcome": "A lifecycle register with owners, review dates and retirements."
     }
    },
    {
     "id": "RE-8",
     "name": "Response action mapping to ontology",
     "weight": 8,
     "anchor_3": "Response actions are mapped to RE&CT RA-codes and/or D3FEND techniques.",
     "evidence": "Mapping export",
     "action": {
      "effort": 2,
      "type": "process",
      "owner": "Response engineering lead",
      "act": "Tag each action in your response library with its RE&CT RA-code and D3FEND technique, and export the mapping as a coverage view.",
      "outcome": "A mapping export showing which response techniques you actually hold."
     }
    },
    {
     "id": "RE-9",
     "name": "Cross-domain response content",
     "weight": 8,
     "anchor_3": "Playbooks exist for identity, cloud control plane and SaaS compromise, and OT where applicable.",
     "evidence": "Domain-specific playbooks + exercise evidence",
     "action": {
      "effort": 3,
      "type": "engineering",
      "owner": "Head of security engineering",
      "act": "Write and exercise playbooks for identity provider compromise, cloud control-plane abuse and malicious OAuth applications, not only endpoint malware.",
      "outcome": "Identity, cloud and SaaS playbooks exercised, not only endpoint ones."
     }
    },
    {
     "id": "RE-10",
     "name": "Response content sharing and reuse",
     "weight": 7,
     "anchor_3": "Playbooks and actions are shared across teams and regions against a common standard.",
     "evidence": "Shared repository or contribution record",
     "action": {
      "effort": 2,
      "type": "governance",
      "owner": "Head of security engineering",
      "act": "Publish one playbook standard and one shared repository across regions and teams, and require contributions back into it rather than local forks.",
      "outcome": "One shared repository with contributions from every region."
     }
    }
   ]
  },
  {
   "id": "CE",
   "name": "Containment, Eradication & Recovery",
   "weight": 14,
   "question": "Do we have graded options that actually work?",
   "note": "Maps to D3FEND Isolate, Evict and Restore.",
   "sub_capabilities": [
    {
     "id": "CE-1",
     "name": "Tiered containment options per asset class",
     "weight": 16,
     "anchor_3": "Each asset class has graded containment tiers (observe / restrict / isolate / disable) with documented business impact.",
     "evidence": "Containment tier matrix + exercise data",
     "action": {
      "effort": 2,
      "type": "process",
      "owner": "IR lead",
      "act": "For each asset class, define four graded containment tiers — observe, restrict, isolate, disable — and write the business impact of each beside it.",
      "outcome": "A containment tier matrix with impact stated per asset class."
     }
    },
    {
     "id": "CE-2",
     "name": "Blast radius control and reversibility",
     "weight": 14,
     "anchor_3": "Blast radius is documented per action; every action has a defined rollback.",
     "evidence": "Rollback test records",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Response engineering lead",
      "act": "Document what each containment action actually touches, write the rollback for it, and test that rollback on a non-production asset.",
      "outcome": "A tested rollback record for every containment action."
     }
    },
    {
     "id": "CE-3",
     "name": "Identity containment (Tier-0)",
     "weight": 14,
     "anchor_3": "Session revocation, credential reset, token invalidation and trust-break procedures exist and are owned.",
     "evidence": "Exercise record with timings",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Identity & access lead",
      "act": "Build and time a Tier-0 procedure that revokes sessions, resets credentials, invalidates tokens and breaks federation trust for a compromised administrator.",
      "outcome": "A timed identity containment procedure with a named owner."
     }
    },
    {
     "id": "CE-4",
     "name": "Network and egress containment",
     "weight": 10,
     "anchor_3": "Egress blocking, sinkholing and segment isolation are available and documented.",
     "evidence": "Automation + propagation timing evidence",
     "action": {
      "effort": 1,
      "type": "measurement",
      "owner": "Network lead",
      "act": "Push a block for a controlled test domain through proxy, firewall, DNS and mail gateway, and record how long each control takes to propagate.",
      "outcome": "Measured propagation times for every egress control you rely on."
     }
    },
    {
     "id": "CE-5",
     "name": "Eradication completeness and re-entry prevention",
     "weight": 14,
     "anchor_3": "Eradication addresses persistence, credentials and access paths, with a documented completeness checklist.",
     "evidence": "Eradication verification records + reinfection metric",
     "action": {
      "effort": 2,
      "type": "process",
      "owner": "IR lead",
      "act": "Write an eradication checklist covering persistence, credentials and access paths, and begin recording reinfection within ninety days as a standing metric.",
      "outcome": "An eradication checklist plus a tracked reinfection rate."
     }
    },
    {
     "id": "CE-6",
     "name": "Recovery, restoration and integrity verification",
     "weight": 12,
     "anchor_3": "Recovery procedures are integrated with IR, with defined RTO/RPO for crown jewels and integrity verification before return.",
     "evidence": "Recovery exercise report",
     "action": {
      "effort": 3,
      "type": "process",
      "owner": "Business service owner",
      "act": "Agree RTO and RPO for each crown-jewel service with its owner, then rehearse a restore that verifies integrity before the service returns.",
      "outcome": "A recovery exercise report with agreed RTO/RPO and integrity checks."
     }
    },
    {
     "id": "CE-7",
     "name": "Backup resilience against destructive attack",
     "weight": 10,
     "anchor_3": "Immutable or logically isolated backups exist for crown jewels, with separate credentials.",
     "evidence": "Restore test record at scale",
     "action": {
      "effort": 3,
      "type": "engineering",
      "owner": "Platform/infra lead",
      "act": "Move crown-jewel backups onto immutable or logically isolated storage with credentials separate from production identity, then restore at full scale to prove it.",
      "outcome": "A dated at-scale restore from backups an attacker cannot reach."
     }
    },
    {
     "id": "CE-8",
     "name": "Degraded-mode and business continuity operation",
     "weight": 10,
     "anchor_3": "Documented degraded-mode operation for crown-jewel services, agreed with the business.",
     "evidence": "Continuity exercise record",
     "action": {
      "effort": 3,
      "type": "process",
      "owner": "Business service owner",
      "act": "Design and rehearse how each crown-jewel service runs without its IT dependencies, and agree the manual fallback with the people who would run it.",
      "outcome": "A continuity exercise record showing the service running degraded."
     }
    }
   ]
  },
  {
   "id": "AO",
   "name": "Automation & Orchestration",
   "weight": 12,
   "question": "Does machine speed actually reach the decision?",
   "note": "Constrained by authority — see R2.",
   "sub_capabilities": [
    {
     "id": "AO-1",
     "name": "Enrichment and triage automation",
     "weight": 14,
     "anchor_3": "Automated enrichment of alerts (asset, identity, intel, prior cases) before analyst contact.",
     "evidence": "Time-to-context metric series",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Detection engineering",
      "act": "Automate asset, identity, intelligence and prior-case enrichment onto every alert before an analyst opens it, and report time-to-context weekly.",
      "outcome": "Alerts arriving pre-enriched, with a time-to-context metric series."
     }
    },
    {
     "id": "AO-2",
     "name": "Automated containment coverage",
     "weight": 20,
     "anchor_3": "Automated containment exists for defined low-risk, high-confidence scenarios with pre-authorisation.",
     "evidence": "Automation coverage map + execution success rate",
     "action": {
      "effort": 3,
      "type": "engineering",
      "owner": "Head of security engineering",
      "act": "Take the three highest-confidence, lowest-risk scenarios you have already pre-authorised and automate containment end to end, tracking execution success rate.",
      "outcome": "An automation coverage map with measured success rates."
     }
    },
    {
     "id": "AO-3",
     "name": "Human-in-the-loop gate design",
     "weight": 14,
     "anchor_3": "Gates are explicitly designed: which actions require a human, which do not, and what happens on timeout.",
     "evidence": "Gate design document + latency data",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "IR lead",
      "act": "Write down which response actions may fire without a human, which may not, and what the automation does when nobody answers in time.",
      "outcome": "A gate design document with defined timeout behaviour."
     }
    },
    {
     "id": "AO-4",
     "name": "Integration coverage and API depth",
     "weight": 14,
     "anchor_3": "The orchestration platform integrates with the tools controlling every in-scope asset class.",
     "evidence": "Integration inventory + health monitoring",
     "action": {
      "effort": 3,
      "type": "tooling",
      "owner": "Head of security engineering",
      "act": "List every tool that controls an in-scope asset class, then build and health-monitor an orchestration integration for each one that lacks it.",
      "outcome": "An integration inventory with monitored coverage of every asset class."
     }
    },
    {
     "id": "AO-5",
     "name": "Automation reliability, safety and rollback",
     "weight": 14,
     "anchor_3": "Automation has error handling, safety limits (rate and scope caps) and rollback paths.",
     "evidence": "Reliability metrics + safety test evidence",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Response engineering lead",
      "act": "Add rate and scope caps, error handling and a rollback path to every automated containment action, then test them by deliberately triggering failure.",
      "outcome": "Automation that fails safely, with evidence it was tested."
     }
    },
    {
     "id": "AO-6",
     "name": "Case management and workflow integrity",
     "weight": 14,
     "anchor_3": "A case system holds all incidents with structured timeline, actions and timestamps.",
     "evidence": "Automated derivation of MTTD/MTTDecide/MTTC from case data",
     "action": {
      "effort": 2,
      "type": "tooling",
      "owner": "SOC manager",
      "act": "Make the case system capture detection, decision and containment timestamps as structured fields, and derive MTTD, MTTDecide and MTTC automatically from them.",
      "outcome": "Response metrics derived from case data, not assembled by hand."
     }
    },
    {
     "id": "AO-7",
     "name": "Automation change control",
     "weight": 10,
     "anchor_3": "Automation changes go through review and testing before deployment.",
     "evidence": "CI/CD evidence",
     "action": {
      "effort": 1,
      "type": "governance",
      "owner": "Head of security engineering",
      "act": "Require every automation change to pass review and a test run before deployment, and withdraw direct edit access in the production platform.",
      "outcome": "A change trail for every automation running in production."
     }
    }
   ]
  },
  {
   "id": "FI",
   "name": "Forensics, Evidence & Investigation",
   "weight": 10,
   "question": "Do we know what actually happened?",
   "note": "Scoping accuracy determines eradication completeness. Under-invested almost universally.",
   "sub_capabilities": [
    {
     "id": "FI-1",
     "name": "Triage and scoping capability",
     "weight": 22,
     "anchor_3": "Structured triage produces a defensible scope: affected assets, identities and timeframe.",
     "evidence": "Scope-accuracy review records",
     "action": {
      "effort": 1,
      "type": "measurement",
      "owner": "IR lead",
      "act": "Re-open your last five significant incidents and record where the final scope differed from the scope declared in the first four hours.",
      "outcome": "A scope-accuracy record showing where triage under- or over-scoped."
     }
    },
    {
     "id": "FI-2",
     "name": "Evidence acquisition capability",
     "weight": 18,
     "anchor_3": "Volatile and disk acquisition is possible for each in-scope asset class within a defined time.",
     "evidence": "Acquisition test records including cloud and ephemeral workloads",
     "action": {
      "effort": 2,
      "type": "engineering",
      "owner": "Forensics lead",
      "act": "Test volatile and disk acquisition against one live asset in each in-scope class, including a container and a cloud workload, and time each.",
      "outcome": "Acquisition test records covering ephemeral and cloud assets."
     }
    },
    {
     "id": "FI-3",
     "name": "Chain of custody and evidence handling",
     "weight": 15,
     "anchor_3": "Documented chain of custody suitable for internal disciplinary and insurance purposes.",
     "evidence": "Custody procedure + legal review",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "Legal & compliance",
      "act": "Write a chain-of-custody procedure covering handling, hashing, storage and transfer, and have counsel confirm it survives disciplinary and insurance use.",
      "outcome": "A legally reviewed custody procedure your evidence can pass."
     }
    },
    {
     "id": "FI-4",
     "name": "Timeline reconstruction",
     "weight": 15,
     "anchor_3": "Incident timelines are produced for significant incidents with source attribution.",
     "evidence": "Sample timelines + automation",
     "action": {
      "effort": 2,
      "type": "tooling",
      "owner": "Forensics lead",
      "act": "Produce a source-attributed timeline for every significant incident, and automate collection of the log sources you keep rebuilding by hand.",
      "outcome": "Timelines with sources cited, produced faster each incident."
     }
    },
    {
     "id": "FI-5",
     "name": "Log and evidence retention adequacy",
     "weight": 15,
     "anchor_3": "Retention for crown-jewel-relevant sources exceeds median dwell time for priority actors.",
     "evidence": "Retention policy + successful historical lookback case",
     "action": {
      "effort": 3,
      "type": "tooling",
      "owner": "Platform/infra lead",
      "act": "Compare retention for every crown-jewel-relevant log source against the median dwell time of your priority actors, and fund the shortfall.",
      "outcome": "Retention that outlasts dwell time, proven by a historical lookback."
     }
    },
    {
     "id": "FI-6",
     "name": "Malware and artefact analysis access",
     "weight": 15,
     "anchor_3": "Analysis capability available in-house or via retainer, with defined turnaround.",
     "evidence": "Analysis reports + resulting detection or playbook changes",
     "action": {
      "effort": 3,
      "type": "governance",
      "owner": "CISO",
      "act": "Secure a named malware and artefact analysis route with a contractual turnaround, and require every report to produce a detection or playbook change.",
      "outcome": "Analysis on a clock, feeding detections and playbooks."
     }
    }
   ]
  },
  {
   "id": "RV",
   "name": "Response Validation & Exercising",
   "weight": 14,
   "question": "Have we proven any of this?",
   "note": "The ceiling-setting domain. Every other domain is capped at RV + 1 by constraint R1.",
   "sub_capabilities": [
    {
     "id": "RV-1",
     "name": "Tabletop exercise programme",
     "weight": 12,
     "anchor_3": "Regular tabletops covering crown-jewel scenarios with the right participants, findings tracked.",
     "evidence": "Exercise reports + remediation tracking",
     "action": {
      "effort": 1,
      "type": "exercise",
      "owner": "IR lead",
      "act": "Run a two-hour tabletop on your worst crown-jewel scenario with the actual decision-makers in the room, and log every finding with an owner.",
      "outcome": "An exercise report with tracked, owned remediation actions."
     }
    },
    {
     "id": "RV-2",
     "name": "Technical live-fire exercising",
     "weight": 22,
     "anchor_3": "Playbooks are executed technically against emulated adversary activity in a controlled window.",
     "evidence": "Live-fire schedule + results per lattice cell",
     "action": {
      "effort": 3,
      "type": "exercise",
      "owner": "Head of security engineering",
      "act": "Book a recurring controlled window and execute playbooks technically against emulated adversary activity, recording pass or fail per lattice cell.",
      "outcome": "Live-fire results per lattice cell, on a published schedule."
     }
    },
    {
     "id": "RV-3",
     "name": "Purple team and end-to-end response validation",
     "weight": 18,
     "anchor_3": "Purple team exercises continue through containment and eradication, not stopping at the alert.",
     "evidence": "End-to-end purple team reports",
     "action": {
      "effort": 3,
      "type": "exercise",
      "owner": "Purple team lead",
      "act": "Extend purple team engagements past detection so the red side keeps operating while you contain and eradicate, and report the end-to-end outcome.",
      "outcome": "Purple team reports that end at eradication, not at the alert."
     }
    },
    {
     "id": "RV-4",
     "name": "Containment timing measurement under exercise",
     "weight": 16,
     "anchor_3": "Exercises capture MTTD, MTTDecide and MTTC and compare them to breakout time.",
     "evidence": "Timing dataset across exercises",
     "action": {
      "effort": 1,
      "type": "measurement",
      "owner": "Exercise lead",
      "act": "Capture MTTD, MTTDecide and MTTC in every exercise and record them beside the breakout time of the actor being emulated.",
      "outcome": "A timing dataset comparing your tempo against the adversary."
     }
    },
    {
     "id": "RV-5",
     "name": "Validation recency and coverage tracking",
     "weight": 12,
     "anchor_3": "Validation status and date tracked per lattice cell, with expiry applied.",
     "evidence": "Automated validation register + validation-debt figure",
     "action": {
      "effort": 2,
      "type": "measurement",
      "owner": "SOC manager",
      "act": "Record the date and result of the last validation against every in-scope lattice cell, expire anything older than a year, and publish the debt.",
      "outcome": "A validation register with a standing validation-debt figure."
     }
    },
    {
     "id": "RV-6",
     "name": "Failure injection and response-function resilience",
     "weight": 10,
     "anchor_3": "Response is exercised under degraded conditions (key tool unavailable, key person absent, SIEM down).",
     "evidence": "Degraded-mode exercise records",
     "action": {
      "effort": 2,
      "type": "exercise",
      "owner": "IR lead",
      "act": "Run an exercise with the SIEM declared down and the primary incident commander unreachable, and record what the team can still do.",
      "outcome": "A degraded-mode exercise record showing what survives tool loss."
     }
    },
    {
     "id": "RV-7",
     "name": "Independent assessment and red team",
     "weight": 10,
     "anchor_3": "Periodic independent red team or assessment includes response effectiveness, not just breach success.",
     "evidence": "Independent report + closure evidence",
     "action": {
      "effort": 3,
      "type": "exercise",
      "owner": "CISO",
      "act": "Commission a red team scoped to grade your response — detection, decision and containment — not merely whether they reached the objective.",
      "outcome": "An independent report on response effectiveness, with closure evidence."
     }
    }
   ]
  },
  {
   "id": "RG",
   "name": "Response Governance, Metrics & Improvement",
   "weight": 12,
   "question": "Does the capability compound?",
   "note": "Closes UTIOM's Kaizen loop and feeds findings back into TID-CMM.",
   "sub_capabilities": [
    {
     "id": "RG-1",
     "name": "Response metrics programme",
     "weight": 18,
     "anchor_3": "MTTD, MTTDecide, MTTC, MTTR and containment success are measured and reported.",
     "evidence": "Metric definitions + reporting history",
     "action": {
      "effort": 2,
      "type": "measurement",
      "owner": "SOC manager",
      "act": "Publish written definitions for MTTD, MTTDecide, MTTC, MTTR and containment success, then report them on the same cadence every month.",
      "outcome": "A reported metric series with definitions that do not move."
     }
    },
    {
     "id": "RG-2",
     "name": "Post-incident review discipline",
     "weight": 18,
     "anchor_3": "Blameless post-incident reviews occur for all significant incidents, with tracked actions.",
     "evidence": "PIR records + action closure metrics",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "IR lead",
      "act": "Hold a blameless review within ten working days of every significant incident, and track each action to closure against a named owner.",
      "outcome": "PIR records with a measurable action closure rate."
     }
    },
    {
     "id": "RG-3",
     "name": "Feedback loop into detection (TID-CMM)",
     "weight": 16,
     "anchor_3": "Incident and exercise findings generate detection engineering work items.",
     "evidence": "Linked incident → detection change records",
     "action": {
      "effort": 1,
      "type": "process",
      "owner": "Detection engineering",
      "act": "Make every post-incident and exercise finding raise a linked detection engineering work item, and report how many were closed each quarter.",
      "outcome": "Traceable incident-to-detection change records."
     }
    },
    {
     "id": "RG-4",
     "name": "Feedback loop into architecture and hardening",
     "weight": 12,
     "anchor_3": "Findings generate hardening and architecture work items with owners.",
     "evidence": "Linked findings → architecture changes",
     "action": {
      "effort": 2,
      "type": "governance",
      "owner": "Security architecture lead",
      "act": "Route hardening findings from incidents into the architecture backlog with named owners, and review their closure at the same forum each quarter.",
      "outcome": "Findings traced through to shipped architecture changes."
     }
    },
    {
     "id": "RG-5",
     "name": "Response capability ownership and funding",
     "weight": 12,
     "anchor_3": "Named owner and dedicated budget for response engineering, distinct from SOC staffing.",
     "evidence": "Budget + prioritisation evidence",
     "action": {
      "effort": 3,
      "type": "governance",
      "owner": "CISO",
      "act": "Name an owner for response engineering and fund it as a budget line distinct from SOC staffing, with its own prioritised backlog.",
      "outcome": "A funded response engineering function with a named owner."
     }
    },
    {
     "id": "RG-6",
     "name": "Regulatory and executive reporting",
     "weight": 12,
     "anchor_3": "Defined reporting packs and regulatory notification procedures, with owners and clocks.",
     "evidence": "Reporting evidence with timestamps",
     "action": {
      "effort": 2,
      "type": "governance",
      "owner": "Legal & compliance",
      "act": "Build the regulator and executive reporting packs in advance, attach the notification clock and owner to each, and timestamp every submission.",
      "outcome": "Pre-built reporting packs with evidenced, timestamped submissions."
     }
    },
    {
     "id": "RG-7",
     "name": "Continuous improvement cadence",
     "weight": 12,
     "anchor_3": "A regular cadence reviews response capability against the model and adjusts the backlog.",
     "evidence": "Reassessment history",
     "action": {
      "effort": 1,
      "type": "governance",
      "owner": "CISO",
      "act": "Diarise a quarterly reassessment against this model, and rebuild the response backlog from its results rather than from the previous backlog.",
      "outcome": "A reassessment history showing score and backlog both moving."
     }
    }
   ]
  }
 ],
 "constraints": [
  {
   "id": "R3",
   "name": "Evidence cap",
   "level": "sub",
   "rule": "Every score is capped by its evidence level: VC0 assertion caps at 1, VC1 design at 2, VC2 implemented and tested at 4, VC3 repeatably validated at 5. A blank level is treated as VC0.",
   "why": "The cap is a ceiling, not a conversion. A high evidence grade permits a high score; it does not create one."
  },
  {
   "id": "R4",
   "name": "Detection dependency",
   "level": "domain",
   "targets": [
    "RE",
    "CE",
    "FI"
   ],
   "rule": "RE, CE and FI ≤ TID-CMM overall score + 1.",
   "why": "You cannot respond to what you never saw."
  },
  {
   "id": "R2",
   "name": "Authority ceiling",
   "level": "domain",
   "targets": [
    "AO",
    "CE"
   ],
   "rule": "AO and CE ≤ RA + 1.",
   "why": "Automation you are not permitted to fire is a demonstration, not a capability."
  },
  {
   "id": "R1",
   "name": "Rehearsal ceiling",
   "level": "domain",
   "targets": [
    "RP",
    "RA",
    "RE",
    "CE",
    "AO",
    "FI",
    "RG"
   ],
   "rule": "Every domain other than RV ≤ RV + 1.",
   "why": "An unrehearsed playbook is an assumed capability."
  },
  {
   "id": "R5",
   "name": "Tempo ceiling",
   "level": "band",
   "rule": "Tempo Ratio ≥ 2.0 caps the band at L1; ≥ 1.0 caps at L2; tempo not supplied caps at L3.",
   "why": "A response capability structurally slower than the adversary is not a level 3 capability, whatever the documentation says."
  },
  {
   "id": "R5b",
   "name": "Estimated tempo ceiling",
   "level": "band",
   "rule": "A tempo result computed from an estimated breakout window, or from estimated interval timings, caps the band at L3. \"Estimated\" means not measured in the assessed environment: a published cross-industry benchmark is a legitimate default and is still an estimate for a specific estate.",
   "why": "A validated capability claim rests on knowing your own numbers. Borrowing an adversary figure is sound practice for planning and cannot evidence that your response beats the clock you actually face."
  },
  {
   "id": "R6",
   "name": "Blind-cell gate",
   "level": "band",
   "rule": "Any Tier-1 lattice cell at status 0 caps the band at L2.",
   "why": "If there is a stage on a crown jewel where you have no response option at all, you are not threat-informed."
  },
  {
   "id": "R7",
   "name": "Assessment depth & governance ceiling",
   "level": "band",
   "rule": "Pulse caps the band at L3. Baseline caps at L4. A self-assessment without evidence-led scoring, independent calibration and separation of assessor from approver caps at L4.",
   "why": "Twenty questions cannot evidence adaptive maturity, and a result nobody challenged is not assurance."
  }
 ],
 "tempo_intervals": [
  {
   "id": "mttd",
   "name": "MTTDetect",
   "short": "Detect",
   "start": "The adversary action occurs in the environment.",
   "stop": "A human or system has validated the activity as a real incident requiring a response decision.",
   "note": "Not the time an alert fired. An unread alert has not detected anything."
  },
  {
   "id": "mttdecide",
   "name": "MTTDecide",
   "short": "Decide",
   "start": "The activity has been validated as requiring a containment decision.",
   "stop": "The authorised containment decision is recorded by the person entitled to make it.",
   "note": "The interval this model exists to expose. It disappears inside MTTR, and it is where most of the loss sits."
  },
  {
   "id": "mttc",
   "name": "MTTContain",
   "short": "Contain",
   "start": "The authorised containment decision is recorded.",
   "stop": "The containment action has taken effect and the adversary has lost the capability in question.",
   "note": "Ends when the action works, not when it was issued. A disable that takes twenty minutes to propagate is twenty minutes."
  },
  {
   "id": "breakout",
   "name": "Breakout time",
   "short": "Breakout",
   "start": "The adversary establishes an initial foothold.",
   "stop": "The adversary moves laterally to a second system.",
   "note": "The adversary's clock, not yours. Sourced rather than measured in most organisations — see BREAKOUT_SOURCES."
  }
 ],
 "breakout_sources": [
  {
   "id": "observed",
   "rank": 1,
   "estimated": false,
   "name": "Observed in our own incidents or exercises",
   "means": "Timed from your own incident or exercise records. The strongest basis, and the only one that supports a validated claim without further caveat."
  },
  {
   "id": "actor-intel",
   "rank": 2,
   "estimated": false,
   "name": "Actor-specific threat intelligence",
   "means": "A named-actor figure from intelligence covering the adversaries you have prioritised. Cite the report and its date."
  },
  {
   "id": "sector",
   "rank": 3,
   "estimated": true,
   "name": "Sector-specific evidence",
   "means": "A figure for organisations like yours, but not for your estate. Directionally useful; not a measurement of you."
  },
  {
   "id": "industry",
   "rank": 4,
   "estimated": true,
   "name": "Published industry benchmark",
   "means": "A cross-industry average such as a vendor threat report. A sensible default when nothing better exists, and explicitly an estimate."
  },
  {
   "id": "assessor",
   "rank": 5,
   "estimated": true,
   "name": "Assessor estimate",
   "means": "A professional judgement with no published basis. Record the reasoning; it cannot support a claim above L3."
  }
 ],
 "tempo_min_sample": 10,
 "actor_presets": [
  {
   "id": "ecrime-avg",
   "source": "industry",
   "name": "eCrime — current average",
   "breakout": 29,
   "published": true,
   "reference": "CrowdStrike Global Threat Report 2026",
   "desc": "The published average across observed eCrime intrusions. The sensible default if you have no figure of your own.",
   "estimated": true
  },
  {
   "id": "ecrime-fastest",
   "source": "industry",
   "name": "eCrime — fastest observed",
   "breakout": 1,
   "published": true,
   "reference": "CrowdStrike Global Threat Report 2026 (27 seconds, rounded up)",
   "desc": "The fastest breakout on record. Use it to stress-test: almost nothing survives this, which is the point.",
   "estimated": true
  },
  {
   "id": "ecrime-2024",
   "source": "industry",
   "name": "eCrime — 2024 baseline",
   "breakout": 48,
   "published": true,
   "reference": "CrowdStrike Global Threat Report 2025",
   "desc": "The prior-year average. Useful for showing a board how much faster the adversary has become.",
   "estimated": true
  },
  {
   "id": "ransomware-affiliate",
   "source": "assessor",
   "name": "Ransomware affiliate, hands-on-keyboard",
   "breakout": 45,
   "published": false,
   "reference": "Archetype estimate",
   "desc": "An operator working interactively toward encryption. Slower than the record, faster than most response.",
   "estimated": true
  },
  {
   "id": "big-game",
   "source": "assessor",
   "name": "Big-game ransomware, staged intrusion",
   "breakout": 90,
   "published": false,
   "reference": "Archetype estimate",
   "desc": "A crew that takes time to map the estate and reach backups before acting.",
   "estimated": true
  },
  {
   "id": "espionage",
   "source": "assessor",
   "name": "Espionage / nation-state, patient",
   "breakout": 240,
   "published": false,
   "reference": "Archetype estimate",
   "desc": "Deliberately slow, aiming to remain resident. Tempo pressure is lower; detection dwell matters more.",
   "estimated": true
  },
  {
   "id": "insider",
   "source": "assessor",
   "name": "Insider, low and slow",
   "breakout": 1440,
   "published": false,
   "reference": "Archetype estimate",
   "desc": "Already inside and already authorised. Breakout is a weak concept here; use it as a loose bound.",
   "estimated": true
  }
 ],
 "recency": {
  "window_months": 12,
  "triggers": [
   {
    "id": "tooling",
    "name": "The tooling that executes the action changed (EDR, SOAR, IdP)"
   },
   {
    "id": "oncall",
    "name": "The on-call or escalation model changed"
   },
   {
    "id": "reorg",
    "name": "The response function was reorganised, or the named owner left"
   },
   {
    "id": "architecture",
    "name": "A material architecture change affected this asset class"
   },
   {
    "id": "provider",
    "name": "The managed provider or retainer delivering the action changed"
   }
  ]
 },
 "consistency_checks": 13,
 "assessment_tiers": [
  {
   "id": "pulse",
   "name": "Pulse",
   "time": "20 minutes",
   "ceiling": "L3",
   "tagline": "Where do we stand, roughly, and what should we do first?",
   "desc": "Twenty questions, no lattice, no ATT&CK, no evidence review. Produces a band, the three things holding you back, and a quick-fix list. Indicative, not defensible — and it says so on the report.",
   "audience": "A CISO with a spare coffee break, or a first conversation with a new client.",
   "steps": [
    "context",
    "pulse",
    "tempo",
    "results"
   ]
  },
  {
   "id": "baseline",
   "name": "Baseline",
   "time": "1–2 hours",
   "ceiling": "L4",
   "tagline": "What is our response capability, and can we prove it?",
   "desc": "All 58 sub-capabilities with evidence levels, the containment lattice scoped to your crown jewels, the authority map, and response tempo. Self-service and defensible enough to take to a leadership team.",
   "audience": "A SOC or IR lead running an honest internal baseline.",
   "steps": [
    "context",
    "assets",
    "crown",
    "actors",
    "scope",
    "containment",
    "authority",
    "status",
    "scoring",
    "tempo",
    "results"
   ]
  },
  {
   "id": "assurance",
   "name": "Assurance",
   "time": "2–4 weeks",
   "ceiling": null,
   "tagline": "Can we stand behind this in front of a regulator or a board?",
   "desc": "Everything in Baseline plus telemetry attributes per asset class, exercised scenarios with observed timings, the evidence register, and the governance layer — decision rights, independent calibration and second review. Evidence-led interviews, not self-scoring.",
   "audience": "A facilitated engagement with an assessment lead, business owners and an independent validator.",
   "steps": [
    "context",
    "assets",
    "crown",
    "actors",
    "scope",
    "containment",
    "authority",
    "telemetry",
    "status",
    "scoring",
    "scenarios",
    "tempo",
    "governance",
    "results"
   ]
  }
 ],
 "pulse_subset": [
  "RP-1",
  "RP-3",
  "RA-1",
  "RA-2",
  "RA-4",
  "RE-1",
  "RE-2",
  "RE-3",
  "CE-1",
  "CE-3",
  "CE-5",
  "CE-7",
  "AO-2",
  "AO-6",
  "FI-1",
  "RV-2",
  "RV-4",
  "RG-1",
  "RG-2",
  "RG-3"
 ],
 "telemetry_attributes": [
  {
   "id": "collection",
   "name": "Collection",
   "q": "Is the evidence collected at all from this asset class?"
  },
  {
   "id": "completeness",
   "name": "Completeness",
   "q": "Does it cover the whole estate, or only the parts that were easy?"
  },
  {
   "id": "timeliness",
   "name": "Timeliness",
   "q": "Does it arrive fast enough to act on inside the breakout window?"
  },
  {
   "id": "integrity",
   "name": "Integrity & normalisation",
   "q": "Are entities resolvable and timestamps trustworthy across sources?"
  },
  {
   "id": "retention",
   "name": "Retention",
   "q": "Does it survive longer than your median dwell time?"
  },
  {
   "id": "queryability",
   "name": "Queryability",
   "q": "Can a responder actually search it under pressure, at speed?"
  },
  {
   "id": "health",
   "name": "Health monitoring",
   "q": "Would you know if this source stopped, and how quickly?"
  },
  {
   "id": "protection",
   "name": "Access protection",
   "q": "Can an adversary with a foothold alter or delete it?"
  }
 ],
 "readiness_lenses": [
  {
   "id": "respond",
   "name": "Readiness to respond",
   "q": "If it started now, could we act on it in time?",
   "desc": "Authority to act, playbooks that exist and run, containment options with known blast radius, and the automation and investigation depth to use them.",
   "subs": {
    "RA-1": 2,
    "RA-2": 2,
    "RA-3": 1,
    "RA-4": 2,
    "RA-5": 2,
    "RA-6": 1,
    "RE-1": 2,
    "RE-2": 1,
    "RE-3": 1,
    "RE-4": 1,
    "RE-6": 1,
    "RE-9": 1,
    "CE-1": 2,
    "CE-2": 2,
    "CE-3": 2,
    "CE-4": 1,
    "AO-1": 1,
    "AO-2": 2,
    "AO-3": 1,
    "AO-4": 1,
    "AO-6": 1,
    "FI-1": 2,
    "FI-2": 1,
    "FI-4": 1,
    "RP-2": 1,
    "RP-3": 2,
    "RP-4": 1
   }
  },
  {
   "id": "recover",
   "name": "Readiness to recover",
   "q": "Could we get the business back, clean, and prove it?",
   "desc": "Eradication that actually removes the adversary, restoration with integrity verification, backups that survive a destructive attack, and the legal and communications machinery that runs alongside.",
   "subs": {
    "CE-5": 2,
    "CE-6": 2,
    "CE-7": 2,
    "CE-8": 1,
    "FI-1": 1,
    "FI-3": 1,
    "FI-5": 1,
    "FI-6": 1,
    "RP-1": 1,
    "RP-6": 2,
    "RP-7": 2,
    "RG-6": 1,
    "RA-6": 1,
    "RE-9": 1
   }
  },
  {
   "id": "resilience",
   "name": "Operational resilience",
   "q": "Could we keep running through it, and be harder to hit next time?",
   "desc": "Degraded-mode operation, a response function that survives losing its own tooling or people, and a feedback loop that converts every incident into a structural improvement.",
   "subs": {
    "CE-7": 2,
    "CE-8": 2,
    "RV-6": 2,
    "RV-1": 1,
    "RV-3": 1,
    "RP-3": 1,
    "RP-5": 2,
    "RP-6": 1,
    "RA-4": 2,
    "RG-2": 2,
    "RG-3": 2,
    "RG-4": 2,
    "RG-7": 1,
    "RE-7": 1,
    "AO-5": 1
   }
  }
 ],
 "horizons": [
  {
   "id": "quick",
   "eff": 1,
   "name": "Quick fixes",
   "window": "0–30 days",
   "desc": "One person, no budget, no procurement. Mostly writing things down, getting decisions made, and measuring what you already do."
  },
  {
   "id": "ninety",
   "eff": 2,
   "name": "Ninety-day moves",
   "window": "1–3 months",
   "desc": "Needs coordination, a scheduled exercise, or a contained piece of engineering. Achievable inside a quarter with existing people."
  },
  {
   "id": "structural",
   "eff": 3,
   "name": "Structural work",
   "window": "6–12 months",
   "desc": "Needs budget, procurement, hiring, architecture change or a standing programme. Plan it now; it will not land this quarter."
  }
 ],
 "prerequisite_check": {
  "detection": {
   "label": "Detection reality check",
   "hint": "Five questions. This replaces a TID-CMM import and feeds constraint R4.",
   "q": [
    {
     "id": "PD-1",
     "name": "Telemetry coverage of crown jewels",
     "s0": "We do not know what we collect from our most critical systems.",
     "s3": "We know our log sources and they cover our crown-jewel systems.",
     "s5": "Telemetry coverage is mapped per system, monitored for health, and gaps are tracked."
    },
    {
     "id": "PD-2",
     "name": "Where detection content comes from",
     "s0": "Whatever the vendor shipped, unmodified.",
     "s3": "A mix of vendor content and rules we wrote for our own environment.",
     "s5": "Content derives from adversary behaviours we modelled for our own estate."
    },
    {
     "id": "PD-3",
     "name": "Detection testing",
     "s0": "We have never tested whether our detections fire.",
     "s3": "We test significant detections when we build them.",
     "s5": "Detections are tested on a schedule against emulated adversary behaviour."
    },
    {
     "id": "PD-4",
     "name": "Alert quality reaching a responder",
     "s0": "Analysts triage raw alerts with no context.",
     "s3": "Alerts arrive enriched with asset and identity context.",
     "s5": "Alert-to-case fidelity is measured and false-negative rate is understood."
    },
    {
     "id": "PD-5",
     "name": "Identity and cloud detection coverage",
     "s0": "Detection is essentially endpoint-only.",
     "s3": "We have working detection for identity and cloud control-plane abuse.",
     "s5": "Identity, cloud and SaaS detection is as mature as endpoint, and validated."
    }
   ]
  },
  "modelling": {
   "label": "Threat modelling reality check",
   "hint": "Three questions. Determines how much confidence your lattice scoping carries.",
   "q": [
    {
     "id": "PM-1",
     "name": "Crown jewel definition",
     "s0": "No agreed list of what must not fail.",
     "s3": "An agreed, documented crown-jewel list owned by the business.",
     "s5": "Crown jewels are defined by business impact, reviewed, and drive security investment."
    },
    {
     "id": "PM-2",
     "name": "Attack path modelling",
     "s0": "We have never mapped how an adversary would reach our crown jewels.",
     "s3": "We have modelled the main attack paths to our critical systems.",
     "s5": "Attack paths are modelled, validated by testing, and maintained as the estate changes."
    },
    {
     "id": "PM-3",
     "name": "Adversary prioritisation",
     "s0": "We defend against threats in general.",
     "s3": "We have named the threat actors and scenarios most likely to target us.",
     "s5": "Actor prioritisation is intelligence-led, documented, and drives control decisions."
    }
   ]
  }
 },
 "scenarios": [
  {
   "id": "S01",
   "name": "Enterprise ransomware and double extortion",
   "crit": 5,
   "desc": "Hands-on-keyboard intrusion leading to mass encryption and data theft for leverage.",
   "attack": "T1190, T1078, T1059, T1003, T1486",
   "assets": [
    "A2",
    "A3",
    "A7"
   ]
  },
  {
   "id": "S02",
   "name": "Identity, MFA and session-token compromise",
   "crit": 5,
   "desc": "Adversary obtains credentials, defeats or bypasses MFA, and rides a stolen session.",
   "attack": "T1078, T1110, T1621, T1539, T1550",
   "assets": [
    "A1",
    "A4"
   ]
  },
  {
   "id": "S03",
   "name": "Business email compromise",
   "crit": 4,
   "desc": "Mailbox or identity compromise used for fraud, redirection or onward phishing.",
   "attack": "T1566, T1114, T1078, T1098",
   "assets": [
    "A1",
    "A4"
   ]
  },
  {
   "id": "S04",
   "name": "Cloud control-plane compromise",
   "crit": 5,
   "desc": "Compromise of cloud identities, roles or management APIs.",
   "attack": "T1078.004, T1098.003, T1552.005",
   "assets": [
    "A4",
    "A1"
   ]
  },
  {
   "id": "S05",
   "name": "SaaS data theft and extortion",
   "crit": 5,
   "desc": "Abuse of SaaS accounts, OAuth grants and APIs to remove data at scale.",
   "attack": "T1078, T1528, T1539, T1213",
   "assets": [
    "A4",
    "A7"
   ]
  },
  {
   "id": "S06",
   "name": "CI/CD and software supply-chain compromise",
   "crit": 5,
   "desc": "Compromise of source control, build pipeline, artefacts or signing keys.",
   "attack": "T1195.001, T1195.002, T1078",
   "assets": [
    "A6",
    "A1"
   ]
  },
  {
   "id": "S07",
   "name": "Edge device or VPN exploitation",
   "crit": 5,
   "desc": "Exploitation of an internet-facing appliance for initial access and persistence.",
   "attack": "T1190, T1133, T1505",
   "assets": [
    "A5",
    "A3"
   ]
  },
  {
   "id": "S08",
   "name": "Insider data removal",
   "crit": 4,
   "desc": "Authorised user removing data at volume, before or after departure.",
   "attack": "T1213, T1052, T1567",
   "assets": [
    "A7",
    "A2"
   ]
  },
  {
   "id": "S09",
   "name": "Destructive attack on backups",
   "crit": 5,
   "desc": "Deliberate targeting of backup and recovery infrastructure to remove the way back.",
   "attack": "T1490, T1485, T1078",
   "assets": [
    "A7",
    "A3"
   ]
  },
  {
   "id": "S10",
   "name": "Managed provider or supplier compromise",
   "crit": 4,
   "desc": "Adversary reaches you through a supplier with privileged access to your estate.",
   "attack": "T1199, T1078, T1133",
   "assets": [
    "A1",
    "A3"
   ]
  },
  {
   "id": "S11",
   "name": "OT or safety-critical disruption",
   "crit": 5,
   "desc": "Disruption of industrial control, building or safety systems.",
   "attack": "T0813, T0826, T1486",
   "assets": [
    "A8",
    "A5"
   ]
  },
  {
   "id": "S12",
   "name": "Degraded-mode incident",
   "crit": 4,
   "desc": "A serious incident while the SIEM, the SOAR platform or the incident commander is unavailable.",
   "attack": "any",
   "assets": [
    "A2",
    "A3",
    "A5"
   ]
  }
 ],
 "scenario_stages": [
  {
   "id": "playbook",
   "name": "Playbook",
   "q": "Does a usable, current procedure exist for this scenario?"
  },
  {
   "id": "telemetry",
   "name": "Telemetry & detection",
   "q": "Would the behaviour produce evidence you would actually see?"
  },
  {
   "id": "triage",
   "name": "Triage & investigation",
   "q": "Can analysts confirm it, scope it, and explain what is affected?"
  },
  {
   "id": "authority",
   "name": "Decision & authority",
   "q": "Can containment be authorised inside the response horizon?"
  },
  {
   "id": "containment",
   "name": "Containment",
   "q": "Can the behaviour be interrupted safely, at the intended blast radius?"
  },
  {
   "id": "forensics",
   "name": "Forensics & evidence",
   "q": "Is evidence preserved without delaying urgent risk reduction?"
  },
  {
   "id": "eradication",
   "name": "Eradication",
   "q": "Are persistence, credentials and access paths actually removed?"
  },
  {
   "id": "recovery",
   "name": "Recovery",
   "q": "Can services, data, identities and control integrity be restored and trusted?"
  },
  {
   "id": "comms",
   "name": "Communications",
   "q": "Do internal, executive, customer and regulatory comms run on time?"
  },
  {
   "id": "thirdparty",
   "name": "Third-party coordination",
   "q": "Do suppliers, retainers and partners perform to their agreements?"
  }
 ],
 "scenario_pass_conditions": [
  "Required evidence is generated, retained, accessible and attributable to the correct entities.",
  "Detection and case transitions occur within the approved response horizon.",
  "Analysts can explain the hypothesis, affected scope, confidence, impact and next action.",
  "Authorised containment is feasible, safe, logged, and reversible where it needs to be.",
  "Forensic evidence is preserved without delaying urgent risk reduction beyond tolerance.",
  "Recovery meets agreed objectives and validates identity, data, configuration and control integrity.",
  "Every material deviation becomes a governed finding with an owner and a retest date."
 ],
 "governance_checks": [
  {
   "id": "GV-1",
   "name": "Named executive sponsor",
   "q": "Is there a named sponsor accountable for scope, risk acceptance and publication?"
  },
  {
   "id": "GV-2",
   "name": "Scope frozen before scoring",
   "q": "Was the scope and target agreed and frozen before any score was entered?"
  },
  {
   "id": "GV-3",
   "name": "Evidence-led, not self-declared",
   "q": "Were scores set from evidence interviews and artifacts rather than self-declaration?"
  },
  {
   "id": "GV-4",
   "name": "Independent calibration",
   "q": "Has a second reviewer calibrated every score above 3 and every critical gate?"
  },
  {
   "id": "GV-5",
   "name": "Separation of assessor and approver",
   "q": "Is the person proposing scores different from the person approving them?"
  },
  {
   "id": "GV-6",
   "name": "Risk acceptances expire",
   "q": "Does every accepted risk carry an owner, a compensating control and an expiry date?"
  },
  {
   "id": "GV-7",
   "name": "Closure requires retest",
   "q": "Is closure evidence defined and independently retested before an action is closed?"
  },
  {
   "id": "GV-8",
   "name": "Reassessment triggers defined",
   "q": "Are the triggers that invalidate this assessment written down and monitored?"
  }
 ],
 "calibration_questions": [
  "What would fail if the primary analyst, engineer, administrator or supplier contact were unavailable?",
  "Which score depends on a feature being licensed rather than implemented and tested?",
  "Which evidence proves the control works under the current architecture, and not only in a lab?",
  "What is the oldest evidence supporting a score above 3, and what has changed since it was collected?",
  "Which priority behaviour is visible but cannot be contained inside the required response horizon?",
  "Which recovery assumption has not been proven from an isolated or compromised identity state?",
  "Which cross-domain entity joins fail across identity, endpoint, cloud, SaaS, network and business evidence?",
  "Which alert or case cannot tell the analyst what is believed, why, what is affected, and what to do next?",
  "Which accepted risk lacks an expiry, a compensating control, or an accountable business owner?",
  "Which closed action has not been independently retested?"
 ],
 "anti_gaming_rules": [
  "Do not count out-of-scope items in the denominator.",
  "Do not score the availability of a product feature as an implemented capability.",
  "Do not use stale tests, screenshots, policies or vendor statements as current operational proof.",
  "Do not average away critical gates, failed scenarios, incomplete assessment or missing evidence.",
  "Do not let the assessor be the only approver of their own high scores.",
  "Do not raise an evidence level to lift a cap. The cap is the finding."
 ],
 "crosswalk": [
  {
   "d": "RP",
   "csf": "GV.OC, PR.PS, RS.MA",
   "nist": "Preparation (GV/ID/PR)",
   "iso": "Plan & prepare",
   "react": "RA1000",
   "d3fend": "Model, Harden",
   "soccmm": "Process, People",
   "reg": "ICT continuity, incident mgmt"
  },
  {
   "d": "RA",
   "csf": "GV.RR, RS.MA",
   "nist": "Governance & roles",
   "iso": "Plan & prepare",
   "react": "RA1000",
   "d3fend": "—",
   "soccmm": "Governance",
   "reg": "Management body accountability"
  },
  {
   "d": "RE",
   "csf": "RS.AN, RS.MI",
   "nist": "Response execution",
   "iso": "Detection & reporting; Response",
   "react": "RA2000–RA5000",
   "d3fend": "Isolate, Evict",
   "soccmm": "Process, Technology",
   "reg": "Response & recovery plans"
  },
  {
   "d": "CE",
   "csf": "RS.MI, RC.RP",
   "nist": "Containment / eradication / recovery",
   "iso": "Response; Recovery",
   "react": "RA3000–RA5000",
   "d3fend": "Isolate, Evict, Restore",
   "soccmm": "Technology",
   "reg": "ICT continuity, backup"
  },
  {
   "d": "AO",
   "csf": "RS.MI, DE.AE",
   "nist": "Response execution",
   "iso": "Response",
   "react": "RA3000",
   "d3fend": "Isolate",
   "soccmm": "Technology",
   "reg": "Operational resilience"
  },
  {
   "d": "FI",
   "csf": "RS.AN, ID.RA",
   "nist": "Analysis",
   "iso": "Assessment & decision",
   "react": "RA2000",
   "d3fend": "—",
   "soccmm": "Technology, Process",
   "reg": "Evidence, root cause"
  },
  {
   "d": "RV",
   "csf": "ID.IM, PR.IR",
   "nist": "Continuous improvement",
   "iso": "Lessons learned",
   "react": "RA6000",
   "d3fend": "—",
   "soccmm": "Process",
   "reg": "Testing (DORA TLPT, NIS2)"
  },
  {
   "d": "RG",
   "csf": "GV, ID.IM, RS.CO",
   "nist": "Continuous improvement",
   "iso": "Lessons learned",
   "react": "RA6000",
   "d3fend": "—",
   "soccmm": "Governance, Services",
   "reg": "Reporting clocks (24h/72h/1m)"
  }
 ]
};
export type TirModel = typeof TIR_CMM_MODEL;
