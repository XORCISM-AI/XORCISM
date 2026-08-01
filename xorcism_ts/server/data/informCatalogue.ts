/**
 * informCatalogue.ts — MITRE Center for Threat-Informed Defense (CTID) INFORM: the Threat-Informed
 * Defense maturity model (ctid.mitre.org/inform, Apache 2.0). Three weighted dimensions — Cyber
 * Threat Intelligence (35%), Defensive Measures (40%), Test & Evaluation (25%) — each decomposed
 * into components; each component is a question answered by picking the achieved maturity level
 * (ordered least-to-most threat-informed). Generated from the INFORM docs. Powers /inform.
 */
export interface InformComponent { id: string; name: string; description: string; question: string; levels: string[] }
export interface InformDimension { code: string; name: string; weight: number; components: InformComponent[] }
export interface InformCatalogue { version: string; source: string; url: string; dimensions: InformDimension[] }

export const INFORM_CATALOGUE: InformCatalogue = {
 "version": "2026",
 "source": "MITRE Center for Threat-Informed Defense — INFORM (Threat-Informed Defense maturity model)",
 "url": "https://ctid.mitre.org/inform/",
 "dimensions": [
  {
   "code": "CTI",
   "name": "Cyber Threat Intelligence",
   "weight": 0.35,
   "components": [
    {
     "id": "CTI-1",
     "name": "Depth of Threat Intelligence",
     "description": "This component discusses the depth of your CTI relative to the Pyramid of Pain . More depth corresponds to a higher level on the Pyramid and consequently more robust intelligence. For example, IOCs like IP blocklists tend to be highly dynamic while certain adversary behaviors are more invariant and useful long-term.",
     "question": "What level of information (roughly relative to the Pyramid of Pain) is being used to track adversaries?",
     "levels": [
      "Ephemeral IOCs: hashes, IPs, domains: data sources an adversary can change easily",
      "Tools used by adversaries which can be swapped or modified to evade detection",
      "Techniques and Tactics used by adversaries, which are harder to change",
      "Low-variance adversary behaviors and observables, which are very difficult to change"
     ]
    },
    {
     "id": "CTI-2",
     "name": "Relevance of Threat Intelligence",
     "description": "This component is about how tailored your CTI is to your organization. For example, your industry may have specific intelligence requirements or be prone to certain threats. Note that it is possible that some open-source threat reports are highly relevant to your organization.",
     "question": "How much does the threat information relate to your organization?",
     "levels": [
      "Generic reports or freely available reporting",
      "Industry-specific reporting",
      "In-house or organizationally-specific reporting"
     ]
    },
    {
     "id": "CTI-3",
     "name": "Operational Integration of Threat Reporting",
     "description": "",
     "question": "To what extent is threat reporting incorporated across your organization?",
     "levels": [
      "Reviewed by individuals or siloed teams",
      "Integrated across different security teams",
      "Contextualized and made actionable across organization"
     ]
    },
    {
     "id": "CTI-4",
     "name": "Incorporation of CTI",
     "description": "",
     "question": "How frequently are you bringing threat intelligence into your organization’s workflows?",
     "levels": [
      "Never",
      "Intermittently",
      "Monthly",
      "Weekly",
      "Daily"
     ]
    },
    {
     "id": "CTI-5",
     "name": "Recency of CTI",
     "description": "",
     "question": "How recent is the threat intelligence in the reports you use?",
     "levels": [
      "Unsure",
      "Within the past year",
      "Within the past month",
      "Within the past week"
     ]
    },
    {
     "id": "CTI-6",
     "name": "Speed of CTI Dissemination",
     "description": "This component assesses how quickly your organization processes and disseminates CTI.",
     "question": "How quickly is new threat intelligence - either internally created or externally sourced - processed and disseminated within your organization?",
     "levels": [
      "Not disseminated",
      "Within a month",
      "Within a week",
      "Within a day"
     ]
    },
    {
     "id": "CTI-7",
     "name": "CTI Driven Decision Making",
     "description": "",
     "question": "To what extent is CTI incorporated into decision making?",
     "levels": [
      "CTI is not considered",
      "CTI is considered, but not a driving factor",
      "CTI is strongly weighted for cybersecurity decisions",
      "CTI is strongly weighted for cybersecurity and business decisions"
     ]
    }
   ]
  },
  {
   "code": "DM",
   "name": "Defensive Measures",
   "weight": 0.4,
   "components": [
    {
     "id": "DM-1",
     "name": "Data Collection",
     "description": "This component discusses how your organization handles security-relevant logs. Organizations should aim to store logs from a variety of sources for a sufficient period of time to enable effective incident detection.",
     "question": "To what extent is data collected, stored, and accessible?",
     "levels": [
      "Logs are collected and stored for at least 90 days",
      "Logs are tagged for indexing",
      "Logs are collected from multiple sensor types"
     ]
    },
    {
     "id": "DM-2",
     "name": "Risk Assessments",
     "description": "This component discusses how often risk assessments are conducted and the extent to which their results are integrated into your organization's workflow.",
     "question": "To what extent are risk assessments performed and operationally useful to your organization?",
     "levels": [
      "Perform formal risk assessments at least annually",
      "Results are used operationally, with measures taken to harden security posture based on findings",
      "Assessment is focused on metrics and assets tailored to the organization’s need, informed by CTI team"
     ]
    },
    {
     "id": "DM-3",
     "name": "Attack Surface Scoping",
     "description": "This component assesses the extent of your attack vector scoping.",
     "question": "To what extent is your attack surface mapped out, understood and prioritized?",
     "levels": [
      "No mapping of Attack Vectors",
      "Attack Vectors are mapped",
      "Attack Vectors are mapped and periodically reviewed",
      "Attack Vectors are mapped and prioritized periodically"
     ]
    },
    {
     "id": "DM-4",
     "name": "Detection Rules",
     "description": "This component is about how your organization sources and refines detection rules.",
     "question": "How does your organization manage detection rules?",
     "levels": [
      "Import rules from external source",
      "Tune imported detection rules",
      "Detection rules are correlated with attack surfaces",
      "Detection rules are implemented based on business priorities"
     ]
    },
    {
     "id": "DM-5",
     "name": "Detection Rule Metadata",
     "description": "This component assesses which kinds of metadata are included along with your detection rules.",
     "question": "What metadata are your detection rules annotated with that can help contextualize their alerts?",
     "levels": [
      "Behavioral description",
      "Quantitative metrics",
      "Frameworks and other standardizations",
      "Associated malware, threat groups, or campaigns"
     ]
    },
    {
     "id": "DM-6",
     "name": "Propagation between CTI and Detections",
     "description": "This component assesses the time it takes for new CTI to be integrated and deployed to your detection ruleset.",
     "question": "How long does it take on average to ingest new intelligence into your detection ruleset?",
     "levels": [
      "Within a Month",
      "Within a Week",
      "Within a Day",
      "Within an Hour"
     ]
    },
    {
     "id": "DM-7",
     "name": "Incident Response",
     "description": "This component assesses the extent to which your organization is prepared for and responds to active threats.",
     "question": "How does your organization respond to an active threat?",
     "levels": [
      "Reactive to alerts, containment-focused",
      "Playbook-enabled, some automation for lower-level or repeated threats",
      "Responsive actions are informed by knowledge of likely threat actors and expected TTPs"
     ]
    },
    {
     "id": "DM-8",
     "name": "Incident Recovery and Forensics",
     "description": "This component assesses how well your organization recovers from adverse incidents.",
     "question": "How does your organization recover from adverse incidents?",
     "levels": [
      "Ad-hoc or informal digital forensics capabilities",
      "Documented and standardized forensic processes in place",
      "Threat intelligence feeds are used to link forensic findings to specific threat actors/groups"
     ]
    },
    {
     "id": "DM-9",
     "name": "Threat Hunting",
     "description": "This component assesses how proactive your threat hunting procedures are. Is threat hunting triggered by observed activity or does your organization anticipate likely adversary behaviors for investigation?",
     "question": "How does your organization actively search out threat actors?",
     "levels": [
      "Ad-hoc or informal threat hunts triggered by observed activity",
      "Hunts are conducted based on known/reported relevant vulnerabilities",
      "Formal threat hunts are proactively conducted based on knowledge of likely adversary behaviors"
     ]
    },
    {
     "id": "DM-10",
     "name": "Deception",
     "description": "This component assesses what kinds of systems (e.g., honeynet) or procedures (e.g., posting false information) your organization has set up to deceive adversaries.",
     "question": "To what extent does your organization seek to deceive future threats and keep them from useable/valuable data as defined in MITRE Engage ?",
     "levels": [
      "Some lures or pocket litter",
      "Disinformation spread",
      "As discussed in NIST SP 800-160 Vol 2, this refers to intentionally spreading disinformation to adversaries (e.g., posting false information about a system to public forums, creating decoy accounts and credentials).",
      "Full-scale honeynet"
     ]
    }
   ]
  },
  {
   "code": "TNE",
   "name": "Test & Evaluation",
   "weight": 0.25,
   "components": [
    {
     "id": "TNE-1",
     "name": "Test Focus",
     "description": "This component assesses which kinds of testing your organization conducts, ranging from compliance and IOC-focused assessments to behavior-focused testing.",
     "question": "What is the focus of your organization’s testing?",
     "levels": [
      "Testing is compliance-focused, e.g. security control assessment",
      "Security control assessments evaluate whether security controls are functioning as intended.",
      "Testing is IOC-focused, e.g. vulnerability assessment",
      "Commodity tools are off-the-shelf solutions that enable pen testing or red team activities using software that is well-known and easily detected.",
      "Testing is behavior-focused, executing a single procedure of ATT&CK techniques",
      "Many ATT&CK techniques have different ways, or procedures, that an attacker can use to achieve the same goal. For instance, ``schtask /create`` and ``register-scheduletask`` will both achieve the technique of **Scheduled Task**.",
      "Testing is behavior-focused, executing multiple procedures of a technique, perhaps using custom tooling"
     ]
    },
    {
     "id": "TNE-2",
     "name": "Test Planning",
     "description": "This component assesses how well your organization plans testing and connects those tests with their overall security posture.",
     "question": "How are tests planned within your organization?",
     "levels": [
      "Testing is designed to discover detection gaps and validate coverage for your attack surface",
      "Testing methodology is informed and prioritized by the threats and risks most relevant to your organization",
      "Testing is collaboratively planned with defenders, to include security response and remediation components",
      "Testing is linked to organizational metrics or key performance indicators (KPIs) to measure effectiveness in discovering gaps, validating coverage, and performing incident response and remediation",
      "Example KPIs: time to initial access, time to detection, time from initial access to lateral movement, number of vulnerabilities identified, % of detection evasion, % of recommendations remediated"
     ]
    },
    {
     "id": "TNE-3",
     "name": "Test Relevance",
     "description": "This component assesses how quickly new CTI is ingested into your testing procedures.",
     "question": "How quickly is new CTI incorporated into your testing?* As new security advisories come out, can your team quickly turn those into test procedures?",
     "levels": [
      "Not CTI Driven or only relying on outdated CTI",
      "Within a month",
      "Within a week",
      "Within a day"
     ]
    },
    {
     "id": "TNE-4",
     "name": "Test Triggers",
     "description": "This component assesses if your testing is influenced by recent security events and/or proactively undergoes regular planning.",
     "question": "Are tests planned proactively or reactively?",
     "levels": [
      "Reactive to external security events",
      "Reactive to internal security events",
      "Testing is proactively planned on a periodic basis",
      "Testing is proactively planned on a continuous basis, perhaps through breach and attack simulation platforms"
     ]
    },
    {
     "id": "TNE-5",
     "name": "Test Results",
     "description": "This component assesses how well testing procedures translate into actionable changes within your organization's security posture.",
     "question": "How do test results drive improvements in defensive measures?",
     "levels": [
      "Actions are taken with internal security team to remediate individual hosts**",
      "Findings drive detection and architectural changes",
      "Architectural changes improve the design of systems or networks to enhance security, e.g. strengthening key management, isolating critical subnets through network segmentation.",
      "Findings drive organizational or policy changes",
      "Organizational decisions are made based on the results of security testing, e.g. business strategy shifts, changes in hiring or training."
     ]
    }
   ]
  }
 ]
};
