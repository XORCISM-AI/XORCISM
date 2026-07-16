/**
 * smeMaturityCatalogue.ts — the ENISA SME Cyber Resilience Maturity Assessment Model, verbatim.
 *
 * Authoritative content mined from ENISA's official tool (CRA_Maturity_Model_TOOL.xlsx) and report
 * ("SME Cyber Resilience Maturity Assessment Model", July 2026, TLP:CLEAR). Five domains, 25
 * assessment questions, each scored 1-5 against its own anchored rubric (5 level descriptions),
 * plus the maturity-level definitions, the three overall maturity bands and the Annex B action
 * checklist. Do NOT paraphrase — this is the published wording so results match the ENISA tool.
 *
 * This module is the single source of truth for smematurity.ts (the /cra-maturity cockpit) and is
 * the same shape the enisa-sme-cra connector parses a filled-in official xlsx into.
 */

export interface SmeLevel { level: number; name: string; meaning: string }
export interface SmeBand { key: string; label: string; min: number; max: number; emoji: string; summary: string }
export interface SmeQuestion { ref: string; question: string; anchors: string[] }
export interface SmeDomain { domain: string; key: string; name: string; cra: string; checklistDomains: string[]; questions: SmeQuestion[] }
export interface SmeChecklistItem { action: string; domain: string }
export interface SmeCatalogue {
  title: string; version: string; source: string;
  levels: SmeLevel[]; bands: SmeBand[]; domains: SmeDomain[];
  checklist: Record<string, SmeChecklistItem[]>;
}

export const SME_CATALOGUE: SmeCatalogue = {
  "title": "ENISA SME Cyber Resilience Maturity Assessment Model",
  "version": "July 2026",
  "source": "https://www.enisa.europa.eu/publications/sme-cyber-resilience-maturity-assessment-model",
  "levels": [
    {
      "level": 1,
      "name": "Initial",
      "meaning": "Not implemented — no defined practices exist or activities are not performed."
    },
    {
      "level": 2,
      "name": "Basic",
      "meaning": "Informal or ad hoc — activities are performed occasionally and depend on individuals."
    },
    {
      "level": 3,
      "name": "Developing",
      "meaning": "Documented but inconsistently applied — a process exists but is not consistently followed across products."
    },
    {
      "level": 4,
      "name": "Managed",
      "meaning": "Consistently applied and regularly reviewed — followed for most/all products with evidence."
    },
    {
      "level": 5,
      "name": "Optimised",
      "meaning": "Measured, monitored and continuously improved — practices are measured with KPIs and improved on the results."
    }
  ],
  "bands": [
    {
      "key": "BASIC",
      "label": "Basic",
      "min": 1.0,
      "max": 2.5,
      "emoji": "🟡",
      "summary": "Cybersecurity is mostly informal and reactive. Goal: set up a basic structure, visibility and responsibilities."
    },
    {
      "key": "INTERMEDIATE",
      "label": "Intermediate",
      "min": 2.6,
      "max": 3.9,
      "emoji": "🔵",
      "summary": "Existing practices are in place but not used consistently. Goal: strengthen consistency and ensure practices are used regularly."
    },
    {
      "key": "ADVANCED",
      "label": "Advanced",
      "min": 4.0,
      "max": 5.0,
      "emoji": "🟢",
      "summary": "Security practices are established and applied consistently. Goal: maintain them and continuously improve."
    }
  ],
  "domains": [
    {
      "domain": "1",
      "key": "governance",
      "name": "Governance and Documentation",
      "cra": "Supports Art. 13, Art. 31 and Annex VII (technical documentation, conformity assessment). Not a standalone CRA requirement.",
      "checklistDomains": [
        "Governance"
      ],
      "questions": [
        {
          "ref": "1.1",
          "question": "Do you have written and approved product security policies?",
          "anchors": [
            "No product security policies or guidelines exist",
            "Some basic guidelines exist but are informal or incomplete",
            "Documented policies or guidelines exist but are not formally approved or consistently used",
            "Policies are formally approved, documented and generally applied",
            "Policies are formally approved, consistently applied, regularly reviewed and continuously improved"
          ]
        },
        {
          "ref": "1.2",
          "question": "Are roles and responsibilities clearly defined for product security activities (e.g. development, vulnerability management, updates)?",
          "anchors": [
            "No roles or responsibilities are defined",
            "Responsibilities exist informally but are unclear or inconsistently assigned",
            "Responsibilities are documented but not consistently applied in practice",
            "Responsibilities are clearly defined, documented and consistently applied",
            "Responsibilities are clearly defined, communicated, consistently applied, regularly reviewed and continuously improved"
          ]
        },
        {
          "ref": "1.3",
          "question": "Do you maintain product-level technical documentation describing implemented security features, risk assessments, design decisions and update procedures?",
          "anchors": [
            "No product security documentation exists",
            "Limited or incomplete documentation exists covering only some aspects",
            "Documentation covering most required aspects exists but is incomplete or not consistently maintained",
            "Documentation is complete for most products and consistently maintained",
            "Documentation is complete for all products, formally maintained, regularly reviewed and continuously improved"
          ]
        },
        {
          "ref": "1.4",
          "question": "Is there a process to regularly review product security and the quality of related documentation?",
          "anchors": [
            "No review process exists",
            "Reviews happen informally or occasionally",
            "A documented review process exists but is not consistently applied",
            "Reviews are consistently performed and documented",
            "Reviews are measured, tracked and continuously improved"
          ]
        },
        {
          "ref": "1.5",
          "question": "Are you aware of the Market Surveillance Authority responsible for enforcing the CRA, the conformity assessment procedure applicable to your products, and how to interact with relevant authorities if needed?",
          "anchors": [
            "No awareness of authorities or obligations",
            "Limited awareness but no clear understanding of obligations",
            "Authorities and obligations are known but not formally documented",
            "Authorities, obligations and interaction processes are defined and followed",
            "Awareness and interaction processes are formalised, maintained and regularly reviewed"
          ]
        }
      ]
    },
    {
      "domain": "2",
      "key": "risk",
      "name": "Risk Management, Security by Design & by Default",
      "cra": "CRA Annex I, Part I(1)(2): risk assessment, secure design, protection against vulnerabilities, secure configuration. Article 13.",
      "checklistDomains": [
        "Risk Mgmt"
      ],
      "questions": [
        {
          "ref": "2.1",
          "question": "Do you perform cybersecurity risk assessments and use the results to guide product design, development, configuration and component management decisions?",
          "anchors": [
            "No risk assessments are performed",
            "Risk assessments are informal and rarely influence decisions",
            "Risk assessments are documented but not consistently used",
            "Risk assessments are systematically performed and guide decisions",
            "Risk assessments are formal, integrated into processes and continuously improved"
          ]
        },
        {
          "ref": "2.2",
          "question": "Are products designed using security-by-design principles from the outset?",
          "anchors": [
            "Security-by-design is not considered",
            "Considered occasionally or late in development",
            "Applied during design but not consistently",
            "Consistently applied across products and regularly reviewed",
            "Fully integrated into development and continuously improved"
          ]
        },
        {
          "ref": "2.3",
          "question": "Are products delivered with secure-by-default configurations and settings?",
          "anchors": [
            "No secure defaults are defined",
            "Secure settings exist but are inconsistent",
            "Secure defaults are defined but not consistently applied",
            "Secure defaults are consistently applied and reviewed",
            "Secure defaults are enforced, tested and continuously improved"
          ]
        },
        {
          "ref": "2.4",
          "question": "Do you perform security checks and testing before releasing or updating a product, and to what extent are automated tools used?",
          "anchors": [
            "No security testing is performed",
            "Testing is occasional and mostly manual",
            "Testing is documented and includes some automated tools",
            "Testing is systematically integrated into development workflows and regularly reviewed",
            "Testing is risk-based, automated where appropriate, monitored and continuously improved"
          ]
        },
        {
          "ref": "2.5",
          "question": "When risks change or new threats emerge, are risk assessments, configurations and third-party components reviewed and updated?",
          "anchors": [
            "No structured review or update process exists",
            "Updates are informal or occasional",
            "Reviews are documented but not consistently applied",
            "Reviews and updates are consistently performed across products",
            "Continuous monitoring and structured updates are in place and continuously improved"
          ]
        }
      ]
    },
    {
      "domain": "3",
      "key": "vulnerability",
      "name": "Vulnerability and Patch Management",
      "cra": "CRA Annex I, Part II: vulnerability handling, remediation, security updates, coordinated vulnerability disclosure and SBOM. Articles 13 and 14.",
      "checklistDomains": [
        "Vuln Mgmt"
      ],
      "questions": [
        {
          "ref": "3.1",
          "question": "Do you have a process to receive, acknowledge, record and track vulnerabilities reported by customers, researchers or internal staff?",
          "anchors": [
            "No vulnerability tracking exists",
            "Vulnerabilities are handled informally",
            "A documented tracking process exists but is not consistently applied",
            "Vulnerabilities are consistently tracked and reviewed",
            "Tracking is measured, integrated and continuously improved"
          ]
        },
        {
          "ref": "3.2",
          "question": "Do you have a defined process for creating, testing, delivering and communicating security updates to customers for supported products?",
          "anchors": [
            "No update process exists",
            "Updates are handled informally",
            "A documented process exists but is not consistently followed",
            "Updates are consistently managed, tested and delivered",
            "The process is monitored, measured and continuously improved"
          ]
        },
        {
          "ref": "3.3",
          "question": "Do you maintain and use a SBOM to support vulnerability and dependency management?",
          "anchors": [
            "No SBOM is created or maintained",
            "SBOM is created occasionally or manually",
            "SBOM is documented for most products but not consistently maintained or used",
            "SBOM is systematically maintained and used in vulnerability management",
            "SBOM is integrated, automated where appropriate and continuously improved"
          ]
        },
        {
          "ref": "3.4",
          "question": "Are vulnerabilities and updates prioritized based on risk, potential impact?",
          "anchors": [
            "No prioritisation is performed",
            "Prioritisation is informal",
            "A documented prioritisation approach exists but is not consistently applied",
            "Prioritisation is consistently risk-based and applied",
            "Prioritisation is measured, reviewed and continuously improved"
          ]
        },
        {
          "ref": "3.5",
          "question": "Do you verify that security updates effectively resolve reported vulnerabilities and maintain evidence of this verification?",
          "anchors": [
            "No verification is performed",
            "Verification is informal or occasional",
            "Verification is documented but not consistently applied",
            "Verification is consistently performed and documented",
            "Verification is measured, reviewed and continuously improved"
          ]
        }
      ]
    },
    {
      "domain": "4",
      "key": "lifecycle",
      "name": "Product Lifecycle Management",
      "cra": "CRA Annex I, Part II (security updates throughout the declared support period) and Annex II (support-period information).",
      "checklistDomains": [
        "Lifecycle"
      ],
      "questions": [
        {
          "ref": "4.1",
          "question": "Is there a defined approach to managing product security during the operational phase?",
          "anchors": [
            "No structured approach exists",
            "Some practices exist but are informal",
            "A documented approach exists but is not consistently applied",
            "The approach is consistently applied and reviewed",
            "The approach is monitored, measured and continuously improved"
          ]
        },
        {
          "ref": "4.2",
          "question": "Is the product lifecycle management actively managed, including defined support periods, update responsibilities, end-of-life arrangements and communication with customers?",
          "anchors": [
            "No lifecycle management exists",
            "Lifecycle activities are informal",
            "Lifecycle processes are documented but not consistently applied",
            "Lifecycle management is consistently applied and communicated",
            "Lifecycle management is monitored, reviewed and continuously improved"
          ]
        },
        {
          "ref": "4.3",
          "question": "Is experience from product operation, post-incident reviews and customer input used to improve products over time?",
          "anchors": [
            "No structured improvement exists",
            "Improvements are occasional and informal",
            "A documented improvement approach exists but is not consistently applied",
            "Improvements are consistently implemented and tracked",
            "Continuous improvement is measured and integrated into product management"
          ]
        },
        {
          "ref": "4.4",
          "question": "Is there a structured and tested way to address identified product security issues?",
          "anchors": [
            "No defined method exists",
            "Issues are handled inconsistently",
            "A documented method exists but is not consistently applied or tested",
            "Issues are handled through a consistent and reviewed process",
            "The process is tested, measured and continuously improved"
          ]
        },
        {
          "ref": "4.5",
          "question": "Are products monitored during operation to identify security risks, vulnerabilities and emerging threats?",
          "anchors": [
            "No monitoring exists",
            "Monitoring is informal or occasional",
            "Monitoring is documented but not consistently applied",
            "Monitoring is consistently performed and results are tracked",
            "Monitoring is integrated, risk-based and continuously improved"
          ]
        }
      ]
    },
    {
      "domain": "5",
      "key": "awareness",
      "name": "Awareness, Competence and Skills",
      "cra": "Organisational capability supporting effective implementation of the Annex I requirements. Not a standalone CRA requirement.",
      "checklistDomains": [
        "Awareness"
      ],
      "questions": [
        {
          "ref": "5.1",
          "question": "Are sufficient skills available to design, develop and maintain products in a secure way, including through external expertise where internal capacity is limited?",
          "anchors": [
            "No relevant expertise is available",
            "Limited expertise is available and applied informally",
            "Skills are documented but not consistently sufficient",
            "Skills are sufficient, applied and regularly reviewed",
            "Skills are assessed, developed and continuously improved"
          ]
        },
        {
          "ref": "5.2",
          "question": "Do relevant staff receive appropriate training on cybersecurity practices relevant to their roles, including product risk management, vulnerability management, and security-by-design?",
          "anchors": [
            "No training is provided",
            "Training is informal or occasional",
            "Training is documented but not consistently delivered",
            "Training is regularly delivered and reviewed",
            "Training effectiveness is assessed and continuously improved"
          ]
        },
        {
          "ref": "5.3",
          "question": "Does the organisation promote a culture of responsible product development, open reporting and awareness of product risks?",
          "anchors": [
            "No structured support exists",
            "Risk and product responsibility are discussed occasionally",
            "Expectations are communicated to staff",
            "Responsible practices are part of normal product work",
            "Product risk considerations influence decisions across the organisation"
          ]
        },
        {
          "ref": "5.4",
          "question": "Do you follow relevant external product security information (e.g. advisories, alerts)?",
          "anchors": [
            "No external information is followed",
            "Information is followed occasionally",
            "Sources are documented but not consistently used",
            "Information is consistently monitored and used",
            "Engagement is active, integrated and continuously improved"
          ]
        },
        {
          "ref": "5.5",
          "question": "Do you assess and validate that your team has the required skills and competence to maintain secure products?",
          "anchors": [
            "No assessment exists",
            "Assessment is informal",
            "Assessment is documented but not consistently applied",
            "Assessment is consistently performed and gaps addressed",
            "Competence is measured, tracked and continuously improved"
          ]
        }
      ]
    }
  ],
  "checklist": {
    "BASIC": [
      {
        "action": "Keep a basic record of key product security aspects (e.g. configurations, issues, updates).",
        "domain": "Governance"
      },
      {
        "action": "Assign responsibility for product security activities so that ownership is clear. Without a defined owner, important obligations are easier to overlook.",
        "domain": "Governance"
      },
      {
        "action": "Be clear about roles across the product lifecycle management, including development, maintenance, and vulnerability management.",
        "domain": "Governance"
      },
      {
        "action": "Identify relevant authorities and understand basic reporting expectations under the CRA.",
        "domain": "Governance"
      },
      {
        "action": "From time to time, review documentation to check that they still reflect how things are actually done.",
        "domain": "Governance"
      },
      {
        "action": "Carry out a basic risk assessment for products so that security measures are based on what is actually at risk.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Security should be considered during development, rather than added later once the product is already built.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Record the main security risks for each product to avoid repeated rediscovery.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Ensure products are delivered with secure default settings.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Perform basic security checks before release or update to identify issues early.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Establish a clear contact point for reporting vulnerabilities so that issues can be received and handled without delay.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain a record of vulnerabilities for each product to ensure they are tracked.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Address vulnerabilities based on their potential impact, starting with the most serious ones.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Before releasing an update, check that it actually fixes the reported vulnerability.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Research and plan the SBOM strategy to support the identification of vulnerabilities in the software products.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Generate an inventory of components (SBOM), using a commonly used and machine-readable format where feasible. Start with key components and expand over time.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Be aware of basic CRA reporting expectations for vulnerabilities and incidents.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Put a simple process in place for handling product security issues so teams can respond in a consistent way when something happens.",
        "domain": "Lifecycle"
      },
      {
        "action": "Clarify how communication with customers would be handled if a serious security issue arises.",
        "domain": "Lifecycle"
      },
      {
        "action": "Make product support periods clear so customers know what to expect.",
        "domain": "Lifecycle"
      },
      {
        "action": "Keep a record of product security issues so they can be tracked and used for learning over time.",
        "domain": "Lifecycle"
      },
      {
        "action": "Make sure someone is responsible for product security during the support period.",
        "domain": "Lifecycle"
      },
      {
        "action": "Use feedback from customers and operational experience to spot recurring issues.",
        "domain": "Lifecycle"
      },
      {
        "action": "Perform basic monitoring of products in operation while they are in use to identify potential security risks.",
        "domain": "Lifecycle"
      },
      {
        "action": "Identify the knowledge and skills needed to meet product security obligations.",
        "domain": "Awareness"
      },
      {
        "action": "Consider using external expertise where internal capacity is limited",
        "domain": "Awareness"
      },
      {
        "action": "Make sure security expectations are communicated so staff understand their responsibilities.",
        "domain": "Awareness"
      },
      {
        "action": "Follow relevant external sources of product security information.",
        "domain": "Awareness"
      },
      {
        "action": "Periodically check that staff involved in product development and maintenance have the required competence.",
        "domain": "Awareness"
      },
      {
        "action": "Address the highest-risk gaps first, particularly in vulnerability management and regulatory obligations.",
        "domain": "Planning"
      },
      {
        "action": "Focus on a limited number of achievable actions to ensure progress is made.",
        "domain": "Planning"
      },
      {
        "action": "Assign responsibility for vulnerability management, updates, and product security tasks.",
        "domain": "Planning"
      }
    ],
    "INTERMEDIATE": [
      {
        "action": "Ensure cybersecurity responsibilities are clearly assigned.",
        "domain": "Governance"
      },
      {
        "action": "Maintain product-level documentation covering design decisions, known issues and update procedures.",
        "domain": "Governance"
      },
      {
        "action": "Review documentation regularly to keep it accurate and aligned with current practices.",
        "domain": "Governance"
      },
      {
        "action": "Keep a clear record of interactions with relevant authorities and reporting points of contact.",
        "domain": "Governance"
      },
      {
        "action": "Document reporting obligations, including when incidents must be reported and who is responsible.",
        "domain": "Governance"
      },
      {
        "action": "Identify and document the conformity assessment procedure applicable to each product.",
        "domain": "Governance"
      },
      {
        "action": "Maintain documented risk assessments for each product and keep them up to date.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Use risk assessment results to guide design and configuration decisions.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Make security by design a consistent part of product development.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Perform security checks before each release or update.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Follow vulnerability sources and advisories for components used in products.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Review security architecture periodically to ensure controls remain appropriate.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Assign a severity rating to each vulnerability using a consistent approach.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Set timeframes for addressing vulnerabilities based on their severity.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Notify customers about vulnerabilities and relevant security updates in a timely manner.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain a complete record of vulnerabilities and the actions taken to resolve them.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Generate and maintain an inventory of components (SBOM), using tools or simplified approaches appropriate to the organisation’s size.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Research and plan how to integrate SBOM in the vulnerability identification process.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Consume SBOM for vulnerability identifiacation on a pilot scale.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Verify that security updates resolve the reported vulnerability before release.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain a documented plan for handling product security issues, including roles and communication.",
        "domain": "Lifecycle"
      },
      {
        "action": "Test the plan periodically using approaches appropriate to the organisation (e.g. simple walkthroughs or tabletop exercises)",
        "domain": "Lifecycle"
      },
      {
        "action": "Provide clear information to customers on support timelines and end-of-life.",
        "domain": "Lifecycle"
      },
      {
        "action": "Review product security incidents and customer feedback regularly.",
        "domain": "Lifecycle"
      },
      {
        "action": "Monitor products consistently throughout their support period.",
        "domain": "Lifecycle"
      },
      {
        "action": "Ensure product security training reflects the responsibilities of each role.",
        "domain": "Awareness"
      },
      {
        "action": "Encourage teams to share lessons learned from product security issues.",
        "domain": "Awareness"
      },
      {
        "action": "Follow relevant external sources of product security information.",
        "domain": "Awareness"
      },
      {
        "action": "Periodically check that staff involved in product development and maintenance have the required level of security knowledge.",
        "domain": "Awareness"
      },
      {
        "action": "Define clear and realistic objectives for each area requiring improvement. Vague goals are difficult to measure and are more likely to be deprioritised when competing demands arise.",
        "domain": "Planning"
      },
      {
        "action": "Break larger improvements into smaller, manageable steps. Changes introduced gradually are easier to implement and more likely to be sustained over time.",
        "domain": "Planning"
      },
      {
        "action": "Track progress and update relevant policies or procedures as actions are completed. Improvements that are not reflected in documentation tend to fade from everyday practice.",
        "domain": "Planning"
      }
    ],
    "ADVANCED": [
      {
        "action": "Review cybersecurity arrangements on a regular basis using defined indicators (e.g. incidents, response times), for example through quarterly discussions that cover recent incidents, key indicators, and any open issues.",
        "domain": "Governance"
      },
      {
        "action": "Look at incident and monitoring data over time to spot recurring patterns and address underlying causes, not just individual cases.",
        "domain": "Governance"
      },
      {
        "action": "Make sure staffing and budget decisions reflect the level of risk associated with each product.",
        "domain": "Governance"
      },
      {
        "action": "Clearly assign responsibility for risk reviews and regulatory notifications, and make sure the approach is documented so it can be followed in practice.",
        "domain": "Governance"
      },
      {
        "action": "Keep records of cybersecurity activities, including risk assessments, testing, and vulnerability management, in a way that is complete and easy to trace when needed.",
        "domain": "Governance"
      },
      {
        "action": "Include risk management in product planning and roadmaps so that security considerations influence decisions from the outset.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Apply a consistent set of secure design principles across products to support more predictable and defensible outcomes.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Record key threat scenarios along with the reasoning behind the selected security measures.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Revisit the security architecture periodically to confirm that existing controls remain appropriate as the product evolves.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Integrate security testing into the development workflow and ensure results are addressed before release.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Ensure risk assessment results are clearly reflected in design, configuration and component management decisions.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Measure effectiveness of controls and improve based on results.",
        "domain": "Risk Mgmt"
      },
      {
        "action": "Use automated tools, where appropriate to the organisation’s size and product complexity.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain a clear and consistent process for communicating vulnerabilities to customers and, where required, to authorities.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Keep complete and traceable records of vulnerabilities and how they were handled.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Confirm that fixes resolve the underlying vulnerability and review how effectively the update process worked.",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain and use component inventories (e.g. SBOM) to support vulnerability management, where appropriate",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Assess the exploitability of vulnerabilities where relevant, to support prioritisation of fixes",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Track indicators such as time to detect and resolve vulnerabilities, where feasible, to support improvement",
        "domain": "Vuln Mgmt"
      },
      {
        "action": "Maintain a structured product security management plan with clear roles, responsibilities, and escalation paths.",
        "domain": "Lifecycle"
      },
      {
        "action": "Test and review the plan regularly, and address any gaps that are identified.",
        "domain": "Lifecycle"
      },
      {
        "action": "Carry out structured follow-ups after security incidents to capture lessons learned.",
        "domain": "Lifecycle"
      },
      {
        "action": "Review product support periods and lifecycle commitments to ensure they remain realistic.",
        "domain": "Lifecycle"
      },
      {
        "action": "Ensure processes support coordinated handling of vulnerabilities, including communication with external parties where relevant.",
        "domain": "Lifecycle"
      },
      {
        "action": "Measure effectiveness of incident handling and improve processes based on results.",
        "domain": "Lifecycle"
      },
      {
        "action": "Provide role-appropriate training, using approaches suitable for the organisation that reflects the level of risk and responsibility involved.",
        "domain": "Awareness"
      },
      {
        "action": "Maintain accessible reporting channels and encourage staff to raise security concerns.",
        "domain": "Awareness"
      },
      {
        "action": "Review competence levels regularly and address gaps through training, recruitment or specialist support.",
        "domain": "Awareness"
      },
      {
        "action": "Follow external product security information in a structured way and engage with relevant communities where appropriate.",
        "domain": "Awareness"
      },
      {
        "action": "Assess staff skills on an ongoing basis and use the results to guide training and product security improvements.",
        "domain": "Awareness"
      },
      {
        "action": "Track training effectiveness and improve based on results.",
        "domain": "Awareness"
      },
      {
        "action": "Review improvement plans at regular intervals, for example alongside annual product roadmap reviews, to ensure they remain relevant.",
        "domain": "Planning"
      },
      {
        "action": "Update planned actions when new risks, vulnerabilities, or weaknesses are identified so that efforts reflect the current situation.",
        "domain": "Planning"
      },
      {
        "action": "Keep key records such as policies, risk assessments, component inventories, vulnerability logs, and test results up to date and easy to access when needed.",
        "domain": "Planning"
      },
      {
        "action": "Use measurable indicators, where feasible, to track product security performance (e.g. time to resolve vulnerabilities).",
        "domain": "Planning"
      }
    ]
  }
} as const;
