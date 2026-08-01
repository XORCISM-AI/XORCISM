/**
 * cticmmCatalogue.ts — CTI-CMM (Cyber Threat Intelligence Capability Maturity Model, cti-cmm.org)
 * v1.3 skeleton: 11 stakeholder-aligned domains, each with its purpose, CTI mission, CTI data
 * sources and CTI use cases (with per-level practice counts). Maturity scale CTI0–CTI3
 * (Pre-Foundational / Foundational / Advanced / Leading). Generated from the public CTI-CMM book
 * by scratchpad/cticmm/gen_ts.py. © the CTI-CMM authors — the 230 normative practice statements
 * are NOT reproduced here (structure + short attributed purpose/mission only). Powers /cti-cmm.
 */
export interface CtiUseCase { id: string; name: string; cti1: number; cti2: number; cti3: number; practices: number; targetLevel: number }
export interface CtiDomain { code: string; name: string; purpose: string; mission: string; dataSources: string[]; useCases: CtiUseCase[] }
export interface CtiCmmCatalogue { version: string; source: string; url: string; levels: string[]; levelNames: string[]; domains: CtiDomain[] }

export const CTICMM_CATALOGUE: CtiCmmCatalogue = {
 "version": "1.3",
 "source": "Cyber Threat Intelligence Capability Maturity Model (CTI-CMM) v1.3",
 "url": "https://cti-cmm.org/",
 "levels": [
  "CTI0",
  "CTI1",
  "CTI2",
  "CTI3"
 ],
 "levelNames": [
  "Pre-Foundational",
  "Foundational",
  "Advanced",
  "Leading"
 ],
 "domains": [
  {
   "code": "ASSET",
   "name": "Asset, Change, and Configuration Management",
   "purpose": "Manage the organizations IT and OT assets, including both hardware and software and information assets, commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Monitor the organizations attack surface to rapidly detect atrisk assets and reduce exposures based on the current and anticipated threat landscape.",
   "dataSources": [
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Cybercriminal Underground Intelligence",
    "Internal Organizational Data",
    "Open Source Intelligence",
    "Vulnerability Intelligence"
   ],
   "useCases": [
    {
     "id": "ASSET-1",
     "name": "Asset Visibility",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 4,
     "targetLevel": 3
    },
    {
     "id": "ASSET-2",
     "name": "Safeguard Assets",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 4,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "THREAT",
   "name": "Threat and Vulnerability Management",
   "purpose": "Establish and maintain plans, procedures, and technologies to detect, identify, analyze, manage, and respond to cybersecurity threats and vulnerabilities commensurate with the risk to the organizations infrastructure (such as critical, IT, and operational) and organizational objectives.",
   "mission": "Maintain comprehensive and contemporary knowledge of the relevant evolving threat landscape to reduce the organizations risk against new and emerging adversaries, malware, vulnerabilities, and exploits.",
   "dataSources": [
    "Adversary Intelligence",
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Cybercriminal Underground",
    "Internal Organizational Data",
    "Malware Intelligence",
    "Open Source Intelligence",
    "Vulnerability Intelligence"
   ],
   "useCases": [
    {
     "id": "THREAT-1",
     "name": "Enhance Attack Prevention And Preparedness",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 8,
     "targetLevel": 3
    },
    {
     "id": "THREAT-2",
     "name": "Drive Detection Engineering Improvements And Strategy",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    },
    {
     "id": "THREAT-3",
     "name": "Enhance Threat Hunting",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    },
    {
     "id": "THREAT-4",
     "name": "Inform Offensive Security Operations",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    },
    {
     "id": "THREAT-5",
     "name": "Improve Patch Prioritization",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "RISK",
   "name": "Risk Management",
   "purpose": "Establish, operate, and maintain an enterprise cyber risk management program to identify, analyze, and respond to cyber risk the organization is subject to, including its business units, subsidiaries, related interconnected infrastructure, and stakeholders.",
   "mission": "Align CTI with the organizations risk management strategies to inform and prioritize risk reduction efforts. Improve risk decisions, assessments, and security control tuning by identifying relevant cyber threat activities, impact potential, likelihood of occurrence, and mitigation options for use in risk assessments.",
   "dataSources": [
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Cybercriminal Underground Intelligence",
    "Geopolitical Intelligence",
    "Identity Intelligence",
    "Internal Organizational Data",
    "Open Source Intelligence",
    "Vulnerability Intelligence"
   ],
   "useCases": [
    {
     "id": "RISK-1",
     "name": "Align Cti Practices To Risk Management Strategies",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 5,
     "targetLevel": 3
    },
    {
     "id": "RISK-2",
     "name": "Improve Risk Decisions, Assessments, And Controls",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 5,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "ACCESS",
   "name": "Identity and Access Management",
   "purpose": "Create and manage identities for entities that may be granted logical or physical access to the organizations assets. Control access to the organizations assets commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Proactively inform IAM strategies, reduce incident detection times, accelerate remediation, and enable continuous improvements to safeguard critical assets and build resilience against identityrelated threats.",
   "dataSources": [
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Cybercriminal Underground",
    "Identity Intelligence",
    "Vulnerability Intelligence"
   ],
   "useCases": [
    {
     "id": "ACCESS-1",
     "name": "Accelerate Remediation Of Identity-Related Threats",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 6,
     "targetLevel": 3
    },
    {
     "id": "ACCESS-2",
     "name": "Fortify Identity And Access Protection",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 4,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "SITUATION",
   "name": "Situational Awareness",
   "purpose": "Establish and maintain activities and technologies to collect, monitor, analyze, alarm, report, and use operational, security, and threat information, including status and summary information from the other model domains, to establish situational awareness for both the organizations operational state and cybersecurity state.",
   "mission": "Drive threatinformed decisionmaking for all stakeholders based on the current and forecast threat landscape relative to the organization. Reduce uncertainty and increase predictability of the threat environment to create a commensurate state of security readiness.",
   "dataSources": [
    "Adversary Intelligence",
    "Cybercriminal Underground Intelligence",
    "Geopolitical Intelligence",
    "Internal Organizational Data",
    "Open Source Intelligence",
    "Trust Groups"
   ],
   "useCases": [
    {
     "id": "SITUATION-1",
     "name": "Maintain Comprehensive Understanding Of The Cyber Threat Landscape",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 5,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "RESPONSE",
   "name": "Event and Incident Response, Continuity of Operations",
   "purpose": "Establish and maintain plans, procedures, and technologies to detect, analyze, mitigate, respond to, and recover from cybersecurity events and incidents and to sustain operations during cybersecurity incidents commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Capture, correlate, prioritize, and enrich intrusion activity in the enterprise environment to create an intelligence advantage for incident responders and strengthen the organizations overall security posture.",
   "dataSources": [
    "Adversary Intelligence",
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Identity Intelligence",
    "Internal Organizational Data",
    "Malware Intelligence",
    "Open Source Intelligence",
    "Vulnerability Intelligence",
    "Counter Intelligence",
    "Trust Groups"
   ],
   "useCases": [
    {
     "id": "RESPONSE-1",
     "name": "Strengthen Pre-Incident Preparedness",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 4,
     "targetLevel": 3
    },
    {
     "id": "RESPONSE-2",
     "name": "Improve Incident Analysis And Response",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 5,
     "targetLevel": 3
    },
    {
     "id": "RESPONSE-3",
     "name": "Enhance Post-Incident Recovery And Continuity Of Operations",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 7,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "THIRD-PARTIES",
   "name": "Third-Party Risk Management",
   "purpose": "Establish and maintain controls to manage the cyber risks arising from suppliers and other third parties commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Strengthen thirdparty risk management by continuously monitoring, detecting, assessing, and mitigating potential incidents posed by thirdparty vendors and suppliers. Enhance vendor risk profile evaluations and prioritization using CTI insights and recommendations.",
   "dataSources": [
    "Attack Surface Intelligence",
    "Breach Intelligence",
    "Cybercriminal Underground Intelligence",
    "Geopolitical Intelligence",
    "Identity Intelligence",
    "Open Source Intelligence",
    "Social Media Intelligence",
    "Trust Groups",
    "Vulnerability Intelligence"
   ],
   "useCases": [
    {
     "id": "THIRD-PARTIES-1",
     "name": "Assess Threats To Third Parties",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 6,
     "targetLevel": 3
    },
    {
     "id": "THIRD-PARTIES-2",
     "name": "Mitigate Third-Party Risk Exposure",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 5,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "FRAUD",
   "name": "Fraud and Abuse Management",
   "purpose": "Fraud and Abuse Management shields organizations from malicious digital scams and attacks. It hunts for emerging threats, shares intelligence to strengthen defenses, and guides response to safeguard data, finances, and reputation. This proactive shield against bad actors fosters a secure online environment for all.",
   "mission": "Create awareness around new and emerging trends in fraud and abuse (the malicious use of an organizations name, logo, or brand). Share threats and findings with relevant stakeholders to create detection and monitoring capabilities and to proactively mitigate risk.",
   "dataSources": [
    "Adversary Intelligence",
    "Brand Intelligence",
    "Cybercriminal Underground Intelligence",
    "Identity Intelligence",
    "Internal Organizational Data",
    "Open Source Intelligence",
    "Social Media Intelligence",
    "Trust Groups"
   ],
   "useCases": [
    {
     "id": "FRAUD-1",
     "name": "Mitigate Financial Fraud",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 9,
     "targetLevel": 3
    },
    {
     "id": "FRAUD-2",
     "name": "Improve Brand Impersonation Protection",
     "cti1": 2,
     "cti2": 2,
     "cti3": 2,
     "practices": 9,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "WORKFORCE",
   "name": "Workforce Management",
   "purpose": "Establish and maintain plans, procedures, technologies, and controls to create a culture of cybersecurity and to ensure the ongoing suitability and competence of personnel commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Support hardening of the human element of the organizations attack surface by enhancing workforce management initiatives with insights into adversary tactics and organizationspecific risks.",
   "dataSources": [
    "Cybersecurity Workforce Development",
    "Strategy and Related Documents",
    "Internal Training Resources, Function-",
    "Specific Training Strategy, and Related",
    "Policy Documents",
    "Organization-Specific Cybersecurity",
    "Strategy, Policies, and Standards"
   ],
   "useCases": [
    {
     "id": "WORKFORCE-1",
     "name": "Support And Safeguard Human Resources Practices",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 4,
     "targetLevel": 3
    },
    {
     "id": "WORKFORCE-2",
     "name": "Support Development Of Training And Education Assets",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 8,
     "targetLevel": 3
    },
    {
     "id": "WORKFORCE-3",
     "name": "Support Cybersecurity Management In Workforce Development Efforts",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "ARCHITECTURE",
   "name": "Cybersecurity Architecture",
   "purpose": "Establish and maintain the structure and behavior of the organizations cybersecurity architecture, including controls, processes, technologies, and other elements, commensurate with the risk to critical infrastructure and organizational objectives.",
   "mission": "Support the effort to develop a robust and resilient cybersecurity architecture by providing insights into cyber threats targeting the organization and recommending mitigation options around controls, processes, technologies, and other elements.",
   "dataSources": [
    "Organization IT and Cybersecurity",
    "Architecture",
    "Organization-Specific Cybersecurity",
    "Strategy, Policies, and Standards",
    "Threat and Vulnerability Management",
    "Data Sources"
   ],
   "useCases": [
    {
     "id": "ARCHITECTURE-1",
     "name": "Support Strategy Development For The Cybersecurity Architecture",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 4,
     "targetLevel": 3
    },
    {
     "id": "ARCHITECTURE-2",
     "name": "Support For Cybersecurity Architecture Through Continuous Threat",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    },
    {
     "id": "ARCHITECTURE-3",
     "name": "Support For Cybersecurity Architecture Through Policy & Compliance",
     "cti1": 1,
     "cti2": 1,
     "cti3": 1,
     "practices": 3,
     "targetLevel": 3
    }
   ]
  },
  {
   "code": "PROGRAM",
   "name": "Cybersecurity Program Management",
   "purpose": "Establish and maintain an enterprise cybersecurity program that provides governance, strategic planning, and sponsorship for the organizations cybersecurity activities in a manner that aligns cybersecurity objectives with both the organizations strategic objectives and the risk to critical infrastructure.",
   "mission": "Support the enterprise cybersecurity program by aligning CTI operations to the program strategy, providing organizationspecific insights that support cybersecurity program maturation, and delivering decision support to cybersecurity program management teams.",
   "dataSources": [
    "Applicable Data Sources from Other Domains",
    "Enterprise Cybersecurity Program Documentation",
    "Corporate Annual Reporting (8-K, 10-K, Annual Report, etc.)"
   ],
   "useCases": [
    {
     "id": "PROGRAM-1",
     "name": "Align Cti Program With Enterprise Cybersecurity Strategy",
     "cti1": 1,
     "cti2": 1,
     "cti3": 2,
     "practices": 4,
     "targetLevel": 3
    },
    {
     "id": "PROGRAM-2",
     "name": "Support Maturation Of The Enterprise Cybersecurity Program",
     "cti1": 12,
     "cti2": 12,
     "cti3": 12,
     "practices": 36,
     "targetLevel": 3
    }
   ]
  }
 ]
};
