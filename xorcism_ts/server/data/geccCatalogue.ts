/**
 * geccCatalogue.ts — Saudi NCA "Guide to Essential Cybersecurity Controls (ECC) Implementation"
 * (GECC 2:2024). Per ECC control: objective, control text, relevant cybersecurity tools, official
 * implementation guidelines and the EXPECTED DELIVERABLES (audit evidence). Generated (do not edit
 * by hand) from the public NCA PDF (TLP:CLEAR) by scratchpad/gecc/gen_ts.py. © NCA — used as the
 * implementation guide it is meant to be. Powers the /nca-ecc implementation & evidence cockpit.
 */
export interface GeccSubcontrol { ref: string; text: string }
export interface GeccControl {
  ref: string; domain: string; domainName: string; subdomain: string; subdomainName: string;
  objective: string; text: string; tools: string[]; guidelines: string[]; deliverables: string[];
  subcontrols: GeccSubcontrol[];
}
export interface GeccDomain { num: string; name: string }
export interface GeccSubdomain { code: string; domain: string; name: string; objective: string }
export interface GeccCatalogue {
  version: string; source: string; authority: string; url: string;
  domains: GeccDomain[]; subdomains: GeccSubdomain[]; controls: GeccControl[];
}

export const GECC_CATALOGUE: GeccCatalogue = {
 "version": "GECC 2:2024",
 "source": "NCA Guide to Essential Cybersecurity Controls (ECC) Implementation — GECC 2:2024",
 "authority": "Saudi National Cybersecurity Authority (NCA)",
 "url": "https://cdn.nca.gov.sa/api/files/public/upload/11bb8f2d-706a-4f18-80f1-40d620ebd845_GECC-.pdf",
 "domains": [
  {
   "num": "1",
   "name": "Cybersecurity Governance"
  },
  {
   "num": "2",
   "name": "Cybersecurity Defense"
  },
  {
   "num": "3",
   "name": "Cybersecurity Resilience"
  },
  {
   "num": "4",
   "name": "Third-Party and Cloud Computing Cybersecurity"
  }
 ],
 "subdomains": [
  {
   "code": "1-1",
   "domain": "1",
   "name": "Cybersecurity Strategy",
   "objective": ""
  },
  {
   "code": "1-2",
   "domain": "1",
   "name": "Cybersecurity Management",
   "objective": "To ensure that the Authorized Official of the entity complies with and supports the implementation and management of cybersecurity programs within the entity, as per the relevant legislative and regulatory requirements."
  },
  {
   "code": "1-3",
   "domain": "1",
   "name": "Cybersecurity Policies and Procedures",
   "objective": "compliance therewith the relevant legislative and regulatory requirements."
  },
  {
   "code": "1-4",
   "domain": "1",
   "name": "Cybersecurity Roles and Responsibilities",
   "objective": ""
  },
  {
   "code": "1-5",
   "domain": "1",
   "name": "Cybersecurity Risk Management",
   "objective": "To ensure managing cybersecurity risks in a methodological approach, in order to policies and procedures and the relevant legislative and regulatory requirements."
  },
  {
   "code": "1-6",
   "domain": "1",
   "name": "Cybersecurity in Information and Technology Project Management",
   "objective": "To ensure that cybersecurity requirements are included in the methodology and management, in order to protect the confidentiality, regulatory requirements."
  },
  {
   "code": "1-7",
   "domain": "1",
   "name": "Compliance with Cybersecurity Standard controls, Laws and Regulations",
   "objective": "legislative and regulatory requirements."
  },
  {
   "code": "1-8",
   "domain": "1",
   "name": "Periodical Cybersecurity Review and Audit",
   "objective": "To ensure that the cybersecurity controls adopted by the entity are implemented and national legislative and regulatory requirements, and international requirements imposed on the entity by law."
  },
  {
   "code": "1-9",
   "domain": "1",
   "name": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements."
  },
  {
   "code": "1-10",
   "domain": "1",
   "name": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties."
  },
  {
   "code": "2-1",
   "domain": "2",
   "name": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity."
  },
  {
   "code": "2-2",
   "domain": "2",
   "name": "Identity and Access Management",
   "objective": "To ensure protecting cybersecurity of logical access to information and technology assets of the entity, in order to prevent unauthorized access and restrict access to the extent necessary for accomplishment of the assigned tasks of the entity."
  },
  {
   "code": "2-3",
   "domain": "2",
   "name": "Information System and Information Processing Facilities Protection",
   "objective": ""
  },
  {
   "code": "2-4",
   "domain": "2",
   "name": "Email Protection",
   "objective": ""
  },
  {
   "code": "2-5",
   "domain": "2",
   "name": "Networks Security Management",
   "objective": ""
  },
  {
   "code": "2-6",
   "domain": "2",
   "name": "Mobile Devices Security",
   "objective": "information and business information and protecting them during transfer and storage policy)."
  },
  {
   "code": "2-7",
   "domain": "2",
   "name": "Data and Information Protection",
   "objective": "legislative and regulatory requirements."
  },
  {
   "code": "2-8",
   "domain": "2",
   "name": "Cryptography",
   "objective": "To ensure the proper and efficient use of cryptography to protect electronic and the relevant legislative and regulatory requirements."
  },
  {
   "code": "2-9",
   "domain": "2",
   "name": "Backup and Recovery Management",
   "objective": "policies and procedures and the relevant legislative and regulatory requirements."
  },
  {
   "code": "2-10",
   "domain": "2",
   "name": "Vulnerabilities Management",
   "objective": "To ensure timely detection and effective remediation of technical vulnerabilities to prevent or minimize the probability of exploitation of these vulnerabilities by cyber -"
  },
  {
   "code": "2-11",
   "domain": "2",
   "name": "Penetration Testing",
   "objective": "To assess and test the efficiency of the through simulation of actual cyber -attack methods and technologies to discover unknown weaknesses that may lead to cyber penetration of the entity, as per the relevant legislative and regulatory requirements."
  },
  {
   "code": "2-12",
   "domain": "2",
   "name": "Cybersecurity Event Logs and Monitoring Management",
   "objective": "To ensure timely collection, analysis, and monitoring of cybersecurity event logs for proactive detection and effective management of cyber-attacks to prevent or minimize negative"
  },
  {
   "code": "2-13",
   "domain": "2",
   "name": "Cybersecurity Incident and Threat Management",
   "objective": "To ensure timely identification, detection, and effective management of cybersecurity incidents and proactive response to cybersecurity threats to prevent or minimize business, as per High Order No. 37140, dated 14/08/1438H."
  },
  {
   "code": "2-14",
   "domain": "2",
   "name": "Physical Security",
   "objective": ""
  },
  {
   "code": "2-15",
   "domain": "2",
   "name": "Web Application Security",
   "objective": ""
  },
  {
   "code": "3-1",
   "domain": "3",
   "name": "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)",
   "objective": "business continuity management and remediate and minimize the impacts of -services and information processing systems and facilities caused by cyber risks."
  },
  {
   "code": "4-1",
   "domain": "4",
   "name": "Third-Party Cybersecurity",
   "objective": "-party cybersecurity risks (including Information Technology (IT) outsourcing, cybersecurity outsourcing, and relevant legislative and regulatory requirements."
  },
  {
   "code": "4-2",
   "domain": "4",
   "name": "Cloud Computing and Hosting Cybersecurity",
   "objective": ""
  }
 ],
 "controls": [
  {
   "ref": "1-1-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-1",
   "subdomainName": "Cybersecurity Strategy",
   "objective": "",
   "text": "The cybersecurity strategy of the entity shall be identified, documented, and approved, and it shall be supported by the head of the entity or his/her delegate line with the relevant legislative and regulatory requirements.",
   "tools": [
    "Cybersecurity Strategy and Roadmap"
   ],
   "guidelines": [
    "Conduct a workshop with stakeholders in the entity to align the objectives of the cybersecurity strategy with the entit strategic objectives.",
    "Develop and document cybersecurity the strategy of the entity in order to align the entit cybersecurity strategic objectives with related laws and regulations, including but not limited to (CCC, CSCC). A cybersecurity strategy often includes the following:",
    "Vision",
    "Mission",
    "Strategic Objectives",
    "Strategy Implementation Plan",
    "Projects",
    "Initiatives",
    "In order for the cybersecurity strategy of the entity to be effective, the approval of the representative must be based on the authority matrix approved by the entity"
   ],
   "deliverables": [
    "The cybersecurity strategy document approved by the entity (electronic copy or official hard copy).",
    "Initiatives and projects included in the cybersecurity strategy of the entity."
   ],
   "subcontrols": []
  },
  {
   "ref": "1-1-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-1",
   "subdomainName": "Cybersecurity Strategy",
   "objective": "",
   "text": "The entity shall execute an action plan to apply the cybersecurity strategy.",
   "tools": [
    "Cybersecurity Strategy and Roadmap.",
    "Key Performance Indicator Report."
   ],
   "guidelines": [
    "Develop a roadmap for implementing the cybersecurity strategy including the execution of the strategy's initiatives and projects to:",
    "Define cybersecurity priorities.",
    "Make recommendations related to cybersecurity works in the entity in a manner consistent with the nature of its work.",
    "Monitor the implementation of cybersecurity strategy projects and initiatives and take corrective steps if necessary.",
    "Ensure the implementation of initiatives and projects according to requirements.",
    "Provide a clear and unified vision and communicate it to all internal and external stakeholders.",
    "Obtain NCA's approval for any cybersecurity initiatives that are beyond the scope of the entity."
   ],
   "deliverables": [
    "Strategy implementation roadmap",
    "List of cybersecurity projects and initiatives and their status"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-1-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-1",
   "subdomainName": "Cybersecurity Strategy",
   "objective": "",
   "text": "The cybersecurity strategy shall be reviewed at planned intervals (or in case of changes to the relevant legislative and regulatory requirements).",
   "tools": [],
   "guidelines": [
    "Review and update the cybersecurity strategy periodically according to a documented and approved review plan as follows",
    "In specific intervals according to best practices (to be determined by the entity and documented with the necessary approval in the strategy document)",
    "If there are changes in the relevant laws and regulations (e.g., changes in cybersecurity requirements applicable to the entity)",
    "In the event of material changes in the entity",
    "Document and approve the review procedures and changes to the cybersecurity strategy by the representative."
   ],
   "deliverables": [
    "An approved document that defines the review schedule for the cybersecurity strategy",
    "An updated cybersecurity strategy after documenting changes to the cybersecurity requirements and to be approved by the representative",
    "Project status reports",
    "Formal approval by the representative on the updated strategy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-2-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-2",
   "subdomainName": "Cybersecurity Management",
   "objective": "To ensure that the Authorized Official of the entity complies with and supports the implementation and management of cybersecurity programs within the entity, as per the relevant legislative and regulatory requirements.",
   "text": "A department for cybersecurity shall be established within the entity. This department shall be independent from the Information Technology and Communications Department (As per High Order No. 37140, dated 14/08/1438H.). It is recommended that the Cybersecurity Department reports directly to the head of the entity or his/her delegate while ensuring that this does not result in a conflict of interests.",
   "tools": [
    "Cybersecurity Function Organizational Structure",
    "Cybersecurity Roles and Responsibilities Template",
    "Cybersecurity General Policy Template"
   ],
   "guidelines": [
    "Establish a cybersecurity function within the entity to enable it to carry out its cybersecurity tasks as required, taking into account the following points",
    "Ensure that the cybersecurity function's reporting line is different from that of the IT department or the digital transformation department, as per Royal Decree No. 37140 dated 14/8/1438H",
    "Ensure that the cybersecurity function is reporting to the head of the entity or his/ her deputy/ assistant for the sectors concerned with regulation, including but not limited to, deputy/ assistant head of business sectors or regulatory sectors, or the agents and heads of business sectors in the entity",
    "Ensure the following in order to avoid conflict of interest",
    "The cybersecurity function is responsible for all cybersecurity monitoring activities (including compliance monitoring, operation monitoring, operations, etc.).",
    "The cybersecurity function is responsible for all cybersecurity governance activities (including defining cybersecurity requirements, managing cybersecurity risks, etc.)."
   ],
   "deliverables": [
    "The entity's organizational structure (electronic copy or official hard copy), covering the organizational structure of the cybersecurity function.",
    "The decision to establish the Cybersecurity functions and its mandate (electronic copy or official hard copy)",
    "Reports on the cybersecurity policies compliance results"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-2-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-2",
   "subdomainName": "Cybersecurity Management",
   "objective": "To ensure that the Authorized Official of the entity complies with and supports the implementation and management of cybersecurity programs within the entity, as per the relevant legislative and regulatory requirements.",
   "text": "All cybersecurity positions shall be filled out with full -time and qualified Saudi cybersecurity professionals.",
   "tools": [],
   "guidelines": [
    "Appoint full -time and qualified Saudi cybersecurity professionals to fill all cybersecurity positions.",
    "The Saudi Cybersecurity Workforce Framework (SCyWF) can be utilized as reference regarding the job positions related to cybersecurity.",
    "Define the required academic qualifications and years of experience to serve as the head of the cybersecurity function. For example, but not limited to:",
    "Developing a job description of the head of the cybersecurity function position to include the minimum required number of years of experience and related fields, and the appropriate academic qualifications, and appropriate training and professional certificates in the cybersecurity and technical fields relying on The Saudi Cybersecurity Workforce Framework (SCyWF)"
   ],
   "deliverables": [
    "A detailed list of all personnel (direct or indirect employees and contractors), whose work is related to cybersecurity, that includes names, contractual type, position titles, job roles, years of experience, academic and professional qualifications."
   ],
   "subcontrols": []
  },
  {
   "ref": "1-2-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-2",
   "subdomainName": "Cybersecurity Management",
   "objective": "To ensure that the Authorized Official of the entity complies with and supports the implementation and management of cybersecurity programs within the entity, as per the relevant legislative and regulatory requirements.",
   "text": "A cybersecurity supervisory committee shall be established pursuant to the and monitoring of the implementation of the cybersecurity programs and regulations. identified, documented, and approved. The committee shall include the head of the cybersecurity department as a member. It is recommended that the committee reports directly to the head of the entity or his/her delegate while ensuring that this does not result in a conflict of interests.",
   "tools": [
    "Cybersecurity supervisory committee governance document template"
   ],
   "guidelines": [
    "Establish the cybersecurity supervisory committee as a committee specialized in directing and leading cybersecurity affairs, processes, programs, and initiatives in the entity. The committee's must be directly reporting to the entity's head or his/ her deputy, taking into account non-conflict of interests",
    "Identify the members of the supervisory committee, where the cybersecurity supervisory committee includes members who influence or are influenced by the cybersecurity of the entity. Such members include but are not limited to, the head of the entity or his/ her deputy, the head of the cybersecurity function, the head of the IT department, the head of the Compliance Department, the Head of the Huma",
    "Include the head of cybersecurity function as a permanent member of the committee",
    "Conduct periodic meetings (based on the intervals specified in the committee's charter document). The periodic meetings cover ensuring follow- up on the implementation of cybersecurity programs and regulations in the entity, managing cybersecurity risks, and submitting meeting minutes to the entity head",
    "Review the implementation of all cybersecurity policies and procedures",
    "Update cybersecurity strategy initiatives and objectives",
    "Ensure that the cybersecurity strategy is aligned with the entity's strategy on a regular basis"
   ],
   "deliverables": [
    "Supervisory committee charter in the entity. The charter clarifies the date of establishment of the committee and its reference and its approval by the entity's representative",
    "A documented and approved list showing the names of the entity's cybersecurity supervisory committee members",
    "Cybersecurity supervisory committee's agenda in the entity",
    "Minutes of meetings held for the cybersecurity supervisory committee at the entity"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-3-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-3",
   "subdomainName": "Cybersecurity Policies and Procedures",
   "objective": "compliance therewith the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity department of the entity shall identify and document cybersecurity policies and procedures, including the cybersecurity controls and communicate them to the relevant personnel and parties inside the entity.",
   "tools": [
    "All policies, procedures, and standard controls templates included within cybersecurity toolkit"
   ],
   "guidelines": [
    "Define and document cybersecurity requirements in cybersecurity policies, procedures, and standard controls , and approve them by the entity's representative based on the authority matrix approved by the entity",
    "Ensure the communication of policies and procedures to the entity's personnel and internal and external stakeholders. Such communication must be done through the approved communication channels as per the scope specified in the policy ( e.g., publishing policies and procedures through the entity's internal portal, or publishing policies and procedures by e-mail)"
   ],
   "deliverables": [
    "All cybersecurity policies, procedures, and standard controls documented and approved by the entity's representative or his/ her deputy",
    "Communicate cybersecurity policies, procedures, and standard controls to personnel and stakeholders"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-3-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-3",
   "subdomainName": "Cybersecurity Policies and Procedures",
   "objective": "compliance therewith the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity department shall ensure that the cybersecurity policies and procedures, including the relevant controls and requirements, are implemented at the entity.",
   "tools": [
    "A template of personnel acknowledgment and approval to follow the cybersecurity policies",
    "A template of personnel acknowledgment and approval to maintain information confidentiality"
   ],
   "guidelines": [
    "Develop an action plan to implement cybersecurity policies, procedures, and standard controls . Such plan must include all internal and external stakeholders, to whom the entity's policies, procedures, and standard controls apply. Such stakeholders must be followed- up and monitored periodically to ensure the full and effective implementation of all requirements",
    "The cybersecurity function must ensure the implementation of cybersecurity controls and adherence to the approved and documented cybersecurity policies, procedures, and standard controls",
    "Ensure the implementation of cybersecurity policies, procedures, and standard controls , including controls and requirements, manually or electronically (automated)"
   ],
   "deliverables": [
    "An action plan to implement the cybersecurity policies and procedures of the entity",
    "A report that outlines the review of the implementation of cybersecurity policies and procedures"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-3-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-3",
   "subdomainName": "Cybersecurity Policies and Procedures",
   "objective": "compliance therewith the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity policies and procedures shall be supported by technical security standards (e.g. technical security standards for firewall, databases, operating systems, etc.).",
   "tools": [
    "A template of all standard controls included in cybersecurity tools."
   ],
   "guidelines": [
    "Define, document, and approve technical standard controls to cover the entity's information and technology assets (e.g., firewall technical security standard controls , network devices, databases, server operating systems, BYOD operating systems, secure development standard, cryptography standard, etc.).",
    "Communicate the technical standard controls to the relevant departments in the entity (e.g., IT department) and ensure that they are applied periodically to information and technology assets"
   ],
   "deliverables": [
    "The entity's approved technical cybersecurity standard controls documents"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-3-4",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-3",
   "subdomainName": "Cybersecurity Policies and Procedures",
   "objective": "compliance therewith the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity policies and procedures shall be reviewed and updated at planned intervals (or in case of changes to the relevant legislative and regulatory requirements and standards). Changes shall be documented and approved.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity policies, procedures, and standard controls in the entity periodically according to a documented and approved plan for review and based on a period specified in the policy ( e.g., periodic review must be conducted annually)",
    "Review and update the cybersecurity policies, procedures, and standard controls in the entity in the event of changes in the relevant laws and regulations (for example, when a new cybersecurity law is issued that applies to the entity).",
    "Document the review and changes to the cybersecurity policies, procedures, and standard controls and approve them by the head of the entity or his/her deputy"
   ],
   "deliverables": [
    "An approved document that defines the review schedule",
    "An approved document that clarifies the review of cybersecurity policies, procedures and standard controls in the entity on a periodic basis based on the period of time set for review",
    "Policies, procedures, and standard controls documents indicating that they have been reviewed and updated, and that changes have been documented and approved by the representative",
    "Official approval and approval by the representative on updated policies, procedures, and standard controls"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-4-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-4",
   "subdomainName": "Cybersecurity Roles and Responsibilities",
   "objective": "",
   "text": "The Authorized Official shall identify, document, and approve the governance assign the persons concerned therewith. The necessary support shall be provided for the implementation thereof while ensuring that this does not result in a conflict of interests.",
   "tools": [
    "Cybersecurity Roles and Responsibilities Template"
   ],
   "guidelines": [
    "Define and document cybersecurity roles and responsibilities and inform and ensure all parties involved in the implementation of cybersecurity controls at the entity of their responsibilities in implementing cybersecurity programs and requirements",
    "Support the organizational structure, roles, and responsibilities of the entity by the executive management This must be done through the approval of the representative",
    "Include the following roles and responsibilities (but not limited to)",
    "Roles and responsibilities related to the cybersecurity supervisory committee",
    "Roles and responsibilities related to the head of the cybersecurity function",
    "Roles and responsibilities related to the cybersecurity function ( e.g., develop and update cybersecurity policies and standard controls , conduct cybersecurity risk assessment, conduct compliance checks on cybersecurity policies and legislation, monitor cybersecurity events, assess vulnerabilities, manage access, develop and implement cybersecurity awareness programs, etc.).",
    "Roles and responsibilities related to cybersecurity for other departments in the entity (e.g., IT, personnel, physical security, etc.)",
    "Cybersecurity roles and responsibilities for all personnel",
    "Assign roles and responsibilities to the entity's personnel, taking into consideration the non-conflict of interests"
   ],
   "deliverables": [
    "Cybersecurity Function Organizational Structure Document",
    "The entity's approved cybersecurity roles and responsibilities document (electronic copy or official hard copy)",
    "A document that clarifies the assignment of cybersecurity roles and responsibilities to the entity's personnel"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-4-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-4",
   "subdomainName": "Cybersecurity Roles and Responsibilities",
   "objective": "",
   "text": "The cybersecurity roles and responsibilities within the entity shall be reviewed and updated at planned intervals (or in case of changes to the relevant legislative and regulatory requirements).",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity roles and responsibilities in the entity periodically according to a documented and approved plan for review and based on a planned interval (e.g., periodic review must be conducted annually)",
    "Review and update the cybersecurity roles and responsibilities in the entity in the event of changes in the relevant laws and regulations (for example, when a new cybersecurity law is issued that applies to the entity)",
    "Document the review and changes to the cybersecurity requirements related to cybersecurity roles and responsibilities and approve them by the representative"
   ],
   "deliverables": [
    "An approved document that defines the review schedule for the roles and responsibilities",
    "Roles and responsibilities document indicating that they are up to date and the changes to the cybersecurity requirements for roles and responsibilities have been documented and approved by the representative"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-5-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-5",
   "subdomainName": "Cybersecurity Risk Management",
   "objective": "To ensure managing cybersecurity risks in a methodological approach, in order to policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity department of the entity shall identify, document, and approve the cybersecurity risk management methodology and procedures within the entity, in accordance with considerations of confidentiality, and the integrity and availability of information and technology assets.",
   "tools": [
    "Cybersecurity Risk Management Policy Template.",
    "Cybersecurity Risk Management Procedures Template."
   ],
   "guidelines": [
    "Define and document cybersecurity risk management requirements which are based on relevant regulations, best practices, and standard controls of cybersecurity risk management, taking into account the confidentiality, availability, and integrity of information and technology assets to cover the following",
    "The methodology and procedures of cybersecurity risk management in the entity must include - Identification of assets and their value - Identification of risks to the business, assets, or personnel of the entity - Risk assessment, so that the likelihood and impact of the identified risks are defined - Risk response, where cyber risk treatment methods are identified - Risk monitoring, so that the r",
    "Support the cybersecurity risk management methodology and procedures in the entity by the Executive Management through the approval of the representative"
   ],
   "deliverables": [
    "The approved cybersecurity risk management methodology (electronic copy or official hard copy)",
    "Approved cybersecurity risk management procedures"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-5-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-5",
   "subdomainName": "Cybersecurity Risk Management",
   "objective": "To ensure managing cybersecurity risks in a methodological approach, in order to policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity department shall implement the cybersecurity risk management methodology and procedures within the entity.",
   "tools": [
    "Cybersecurity Risk Management Register Template"
   ],
   "guidelines": [
    "Implement all requirements of the cybersecurity risk management methodology and procedures adopted by the entity",
    "Establish a cybersecurity risk register to document and monitor risks",
    "Develop plans to address cybersecurity risks of the entity"
   ],
   "deliverables": [
    "Cybersecurity Risk Register of the entity",
    "Cybersecurity Risk Treatment Plan of the entity",
    "A report that outlines the cybersecurity risk assessment and monitoring"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-5-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-5",
   "subdomainName": "Cybersecurity Risk Management",
   "objective": "To ensure managing cybersecurity risks in a methodological approach, in order to policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity risk assessment procedures shall be implemented at least in the following cases:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Include cybersecurity requirements within the first phase of the information and technology projects lifecycle (Technical Project Lifecycle) within the entity",
    "Implement cybersecurity risk assessment procedures at an early stage of technical projects to avoid events or circumstances that could compromise the confidentiality, integrity, and availability of information and technology assets, including, in particula r, the identification of information and technology assets in technology projects, potential exposure to threats, and relevant vulnerabilities.",
    "Remediate all cybersecurity risks in accordance with the approved cybersecurity risk management methodology.",
    "Include cybersecurity requirements within the IT Change Management lifecycle in the entity",
    "Implement cybersecurity risk assessment procedures before making a material change in the technology architecture to avoid events or circumstances that could compromise the confidentiality, integrity, and availability of information and technology assets, including, in particular, the identification of information and technology assets in technology projects, potential exposure to threats, and rel",
    "Remediate all cybersecurity risks in accordance with the approved cybersecurity risk management methodology",
    "Include cybersecurity requirements within the third -party, contracts, and procurement management procedures in the entity",
    "Implement cybersecurity risk assessment procedures when planning to acquire services from a third party. to avoid events or circumstances that could compromise the confidentiality, integrity, and availability of information and technology assets, including, in particular, the identification of information and technology assets in technology projects, potential exposure to threat s, and relevant vu",
    "Include cybersecurity requirements within the Release Management procedures in the entity",
    "Implement cybersecurity risk assessment procedures at the planning stage and before the release of new technology products and services to avoid events or circumstances that could compromise the confidentiality, integrity, and availability of information and technology assets, including, in particular, the identification of information and technology assets in technology projects, potential exposu"
   ],
   "deliverables": [
    "A report that outlines the identification, assessment, and remediation of cybersecurity risks throughout the technical project lifecycle in the entity",
    "A report that outlines the identification, assessment, and remediation of the cybersecurity risks of material changes to the production environment of the entity's information and technology assets",
    "A report that outlines the identification, assessment, and remediation of third- party cybersecurity risks that provide outsourcing services to IT or managed services",
    "A report that outlines the identification, assessment, and remediation of cybersecurity risks in the planning stage and before releasing new technical products and services in the production environment"
   ],
   "subcontrols": [
    {
     "ref": "1-5-3-1",
     "text": "At early stage of technology projects."
    },
    {
     "ref": "1-5-3-2",
     "text": "Before making major changes to technology infrastructure."
    },
    {
     "ref": "1-5-3-3",
     "text": "During planning to obtain third party services."
    },
    {
     "ref": "1-5-3-4",
     "text": "During planning and before the release of new technology services and products."
    }
   ]
  },
  {
   "ref": "1-5-4",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-5",
   "subdomainName": "Cybersecurity Risk Management",
   "objective": "To ensure managing cybersecurity risks in a methodological approach, in order to policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "The cybersecurity risk management methodology and procedures shall be reviewed and updated at planned intervals (or in case of changes to the relevant legislative and regulatory requirements and standards). Changes shall be documented and approved.",
   "tools": [],
   "guidelines": [
    "Review and update the cybersecurity risk management methodology and procedures and cybersecurity risk management requirements in the entity periodically according to a documented and approved plan for review and based on a planned interval ( e.g., periodic review must be conducted annually)",
    "Review and update the cybersecurity risk management methodology and procedures and cybersecurity risk management requirements in the entity in the event of changes in the relevant laws and regulations (for example, when a new cybersecurity law is issued that applies to the entity)",
    "Document the review and changes to the cybersecurity requirements related to cybersecurity risk management methodology and procedures and approve them by the representative"
   ],
   "deliverables": [
    "An approved document that defines the review schedule for the cybersecurity risk management methodology and procedures",
    "Cybersecurity risk methodology and procedures indicating that they have been reviewed and updated, and that changes have been documented and approved by the representative"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-6-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-6",
   "subdomainName": "Cybersecurity in Information and Technology Project Management",
   "objective": "To ensure that cybersecurity requirements are included in the methodology and management, in order to protect the confidentiality, regulatory requirements.",
   "text": "Cybersecurity requirements shall be included in the project management methodology and procedures and in the information and technology asset change management within the entity to ensure identifying and managing cybersecurity risks as part of the technolo gy project lifecycle. The cybersecurity requirements shall be a key part of the requirements for technology projects.",
   "tools": [
    "Secure Software Development Cycle Policy Template.",
    "Secure Software Development Cycle Procedure Template."
   ],
   "guidelines": [
    "Include cybersecurity requirements in the project management methodology and procedures and in the change management of the information and technology assets in the entity to ensure that cybersecurity risks are identified and addressed. Such requirements include",
    "Assess and detect vulnerabilities before the deployment of services or systems online, or upon any change to systems within Information and Technology Project Management",
    "Fix identified vulnerabilities before launching projects and changes",
    "Review Secure Configuration and Hardening and Patching and address observations identified before launching projects and changes",
    "Define the requirements for connection with cyber surveillance systems",
    "Support cybersecurity requirements of the project management methodology and procedures by the Executive Management through the approval of the head of the entity or his/ her deputy"
   ],
   "deliverables": [
    "Project Management Methodology Document in the entity",
    "Change management methodology or procedures in the entity's information and technology assets document"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-6-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-6",
   "subdomainName": "Cybersecurity in Information and Technology Project Management",
   "objective": "To ensure that cybersecurity requirements are included in the methodology and management, in order to protect the confidentiality, regulatory requirements.",
   "text": "The cybersecurity requirements for project management and information and technology asset changes within the entity shall include the following as a minimum:",
   "tools": [
    "Cybersecurity Requirements Checklist Template for Project Management and Changes to Information and Technology Assets.",
    "Cybersecurity Requirements Checklist Template for Application Development."
   ],
   "guidelines": [
    "Define and document the requirements of this control in the cybersecurity requirements document and approve them by the representative",
    "Define systems, services, and technology components subject to Vulnerabilities Assessment within the scope of technical projects and change requests",
    "Develop and adopt procedures for the implementation of Vulnerabilities Assessment and remediation in accordance with related laws and regulations",
    "Conduct Vulnerabilities Assessment before launching technical projects in the production environment and assess it in a timely manner and address it effectively.",
    "Conduct Vulnerabilities Assessment before the implementation of changes to the production environment and assess it in a timely manner and address it effectively.",
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Define systems, services, and technology components subject to Secure Configuration and Hardening review within the scope of technical projects and change requests",
    "Provide technical Security Standard controls for systems, services, and technology components subject to Secure Configuration and Hardening review",
    "Develop and adopt procedures for the implementation of Secure Configuration and Hardening review in accordance with the relevant laws and regulations",
    "Review secure Configuration and Hardening and Patching before launching technology projects in the production environment",
    "Review secure Configuration and Hardening and Patching before implementing changes to the production environment"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "A report that outlines the assessment and remediation of cybersecurity vulnerabilities throughout the technical project lifecycle and changes to information and technology assets",
    "Technical Security Standard controls for systems, services, and technology components subject to Secure Configuration and Hardening review",
    "A report that outlines the assessment and review of Secure Configuration and Hardening throughout the technical project lifecycle and changes to information and technology assets in the entity before launching projects and implementing changes"
   ],
   "subcontrols": [
    {
     "ref": "1-6-2-1",
     "text": "Vulnerability assessment and remediation"
    },
    {
     "ref": "1-6-2-2",
     "text": "Reviewing secure configuration and hardening and updates packages before launching projects and changes."
    }
   ]
  },
  {
   "ref": "1-6-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-6",
   "subdomainName": "Cybersecurity in Information and Technology Project Management",
   "objective": "To ensure that cybersecurity requirements are included in the methodology and management, in order to protect the confidentiality, regulatory requirements.",
   "text": "The cybersecurity requirements for software and application development projects within the entity shall include the following as a minimum:",
   "tools": [
    "Secure Coding Standard Template.",
    "Cybersecurity Requirements Checklist Template for Application Development."
   ],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Define and document technical cybersecurity requirements for Secure Coding Standard controls (covering all phases of the secure coding process) based on relevant laws and regulations, best practices and standard controls related to the development and protection of software and applications against internal and external threats in the entity to minimize cyber risks and focus on key security object",
    "Communicate Secure Coding Standard controls to the relevant departments in the entity (e.g., IT department) and their implementation periodically",
    "Use only modern, reliable and licensed sources for software development tools and libraries",
    "Conduct testing to verify that applications meet the cybersecurity requirements of the entities, such as penetration testing, to ensure that cybersecurity controls are applied to the development of secure coding standard controls and detect weaknesses, vulnerabilities, and issues in software",
    "Access Management requirements for users and review the cybersecurity architecture",
    "Ensure security of integration between applications by, but not limited to, security testing of various integration technologies, including",
    "Perform System Integration Testing (SIT)",
    "Perform API testing",
    "Review secure Configuration and Hardening and Patching before launching applications and ensure their implementation in the following cases",
    "Secure Configuration and Hardening of information and technology assets and applications must be reviewed periodically and their implementation according to the approved technical security standard controls must be ensured",
    "Secure configuration and hardening must be reviewed before launching projects and changes in information and technology assets",
    "Secure Configuration and Hardening must be reviewed before launching applications",
    "Approve the Image for the Secure configuration and hardening of information and technology assets in accordance with the technical security standard controls and kept it in a safe place"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Secure Coding Standard controls approved by the entity",
    "Documents that confirm the implementation of Secure Coding Standard controls to information and technology assets",
    "An updated list of licensed and documented software used for application development tools and libraries",
    "List of application development projects and list of security tests performed to verify the comprehensiveness of the tests and the extent to which the applications meet the entity's cybersecurity requirements and implementation reports",
    "A report that outlines the testing and assessment of secure Integration between applications based on the entity's cybersecurity requirements and implementation reports",
    "Reports or evidence that Secure Configuration and Hardening and patching are reviewed before launching applications",
    "Reports or evidence that Secure Configuration and Hardening and patching are periodically reviewed"
   ],
   "subcontrols": [
    {
     "ref": "1-6-3-1",
     "text": "Using the secure coding standards."
    },
    {
     "ref": "1-6-3-2",
     "text": "Using trusted and licensed sources for software development tools and libraries."
    },
    {
     "ref": "1-6-3-3",
     "text": "Conducting compliance test for software against the cybersecurity requirements within the entity."
    },
    {
     "ref": "1-6-3-4",
     "text": "Secure integration between applications."
    },
    {
     "ref": "1-6-3-5",
     "text": "Reviewing secure configuration and hardening and updates packages before launching software products."
    }
   ]
  },
  {
   "ref": "1-6-4",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-6",
   "subdomainName": "Cybersecurity in Information and Technology Project Management",
   "objective": "To ensure that cybersecurity requirements are included in the methodology and management, in order to protect the confidentiality, regulatory requirements.",
   "text": "The cybersecurity requirements for project management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity project management requirements periodically according to a documented and approved plan for review and based on a planned interval (e.g., periodic review must be conducted annually)",
    "Document the review and changes to the cybersecurity requirements for project management in the entity and approve them by the head of the entity or his/her deputy"
   ],
   "deliverables": [
    "An approved document that defines the review schedule for the cybersecurity requirements for project management",
    "Evidence that the periodic review of cybersecurity requirements in project management and changes to the information and technology assets of the entity is performed"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-7-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-7",
   "subdomainName": "Compliance with Cybersecurity Standard controls, Laws and Regulations",
   "objective": "legislative and regulatory requirements.",
   "text": "If there are nationally approved international agreements or commitments that include cybersecurity requirements, the entity shall identify and comply with these requirements.",
   "tools": [],
   "guidelines": [
    "Work with the entity's stakeholders to identify, document , approve and periodically update the list of international cybersecurity agreements or commitments, and periodically identify, document, and update them; subject to prior approval by the National Cybersecurity Authority",
    "Ensure compliance with all national cybersecurity laws and regulations requirements approved by the National Cybersecurity Authority within the entity",
    "Provide necessary technologies to verify compliance with the laws and regulations related to cybersecurity"
   ],
   "deliverables": [
    "A document (such as an approved policy or procedure) outlining the identification and documentation of the requirements related to this control",
    "An updated identified-list of locally approved international agreements and commitments applicable to cybersecurity function",
    "A report that outlines the extent of compliance with cybersecurity international agreements and obligations applicable to the entity"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-8-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-8",
   "subdomainName": "Periodical Cybersecurity Review and Audit",
   "objective": "To ensure that the cybersecurity controls adopted by the entity are implemented and national legislative and regulatory requirements, and international requirements imposed on the entity by law.",
   "text": "The cybersecurity department of the entity shall periodically review the implementation of cybersecurity controls by the entity.",
   "tools": [
    "Cybersecurity Review and Audit Template.",
    "Cybersecurity Review and Audit Log Template."
   ],
   "guidelines": [
    "Review the implementation of cybersecurity requirements at the entity by the cybersecurity function periodically according to a documented and approved plan for review and based on a period specified in the policy ( e.g., quarterly review), to ensure that the cybersecurity controls of the entity are effectively implemented and operate in accordance with the regulatory policies and procedures of th"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Approved plan to review the implementation of cybersecurity controls",
    "Documents that confirm the implementation of Cybersecurity Standard controls to information, technology, and physical assets",
    "Periodic review reports of cybersecurity controls implementation in the entity"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-8-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-8",
   "subdomainName": "Periodical Cybersecurity Review and Audit",
   "objective": "To ensure that the cybersecurity controls adopted by the entity are implemented and national legislative and regulatory requirements, and international requirements imposed on the entity by law.",
   "text": "The implementation of cybersecurity controls by the entity shall be reviewed and audited by parties other than the cybersecurity department at the entity, provided that the audit and review are to be conducted independently while considering the principle of conflict of interest, as per the Generally Accepted Auditing Standards (GAAS) and the relevant legislative and regulatory requirements.",
   "tools": [
    "Cybersecurity Review and Audit Template.",
    "Cybersecurity Review and Audit Log Template."
   ],
   "guidelines": [
    "Review and audit cybersecurity controls implementation at the entity by parties independent of the cybersecurity function, such as the internal audit department, or by third parties that cooperated with independently from the relevant cybersecurity function to achieve the principle of non -conflict of interests when reviewi ng the implementation of all cybersecurity requirements in the entity",
    "Perform the review periodically according to a documented and approved plan for review and based on a period specified in the policy (e.g., review must be conducted annually), in order to ensure that the entity's cybersecurity controls are effectively implemented and operate in accordance with the regulatory policies and procedures of the entity, the national laws and regulations approved by NCA,"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Approved plan to review and audit the implementation of cybersecurity"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-8-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-8",
   "subdomainName": "Periodical Cybersecurity Review and Audit",
   "objective": "To ensure that the cybersecurity controls adopted by the entity are implemented and national legislative and regulatory requirements, and international requirements imposed on the entity by law.",
   "text": "The results of cybersecurity audits and reviews shall be documented and presented to the cybersecurity supervisory committee and the Authorized Official. Results shall include the audit and review scope, observations, recommendations, corrective actions, and remediation plans.",
   "tools": [
    "Cybersecurity Review Report Template."
   ],
   "guidelines": [
    "Review and document results of cybersecurity review and audit. The review report must include",
    "Scope of review and audit",
    "Discovered observations.",
    "Recommendations and corrective actions.",
    "Observations remediation plan.",
    "Share and discuss the results of cybersecurity review and audit with the cybersecurity supervisory committee and the representative"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Audit reports (by the internal audit departmentor compliance department or an independent external auditor) on all cybersecurity requirements of the entity",
    "Evidence that the results of the cybersecurity review and audit presented to the cybersecurity supervisory committee and the representative"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-9-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for personnel of the entity shall be identified, documented, and approved prior to, during, and upon the end or termination of their employment.",
   "tools": [
    "Human Resources Cybersecurity Policy Template"
   ],
   "guidelines": [
    "Define and document personnel cybersecurity requirements in the cybersecurity requirements document and approved by the representativ e Requirements include, but are not limited to",
    "Include cybersecurity responsibilities and non -disclosure clauses in the contracts of employees in the entity (to cover the periods during and after the end/termination of the job relationship with the entity)",
    "Conduct screening or vetting for the personnel of cybersecurity functions, technical functions with privileged access, and critical systems functions",
    "Ensure the comprehensiveness of the cybersecurity requirements related to employees during the employee's lifecycle in the entity, including the following requirements",
    "Cybersecurity requirements prior to recruitment",
    "Cybersecurity requirements during work",
    "Cybersecurity requirements upon completion or termination of work",
    "Support the entity's policy by the Executive Management This must be done through the approval of the entity head or his/ her deputy"
   ],
   "deliverables": [
    "Cybersecurity policy for human resources approved by the representative"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-9-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for personnel of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all personnel -related cybersecurity requirements that have been identified, documented and approved in the Human Resources Cybersecurity Policy",
    "Develop an action plan to implement cybersecurity requirements related to the personnel of the entity",
    "Include personnel cybersecurity requirements in the entity's HR procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders"
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to personnel as documented in the HR Cybersecurity Policy",
    "Cybersecurity Function Personnel Contract Forms (signed copy)",
    "Screening or vetting requests for the personnel of cybersecurity functions and technical functions with privileged access"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-9-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements prior to the commencement of the employment relationship between personnel and the entity shall include the following as a minimum:",
   "tools": [
    "Acknowledgment and confidentiality templates"
   ],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Work with relevant departments to include cybersecurity responsibilities and non-disclosure clauses in the contracts of employees in the entity (to cover the periods during and after the end/termination of the job relationship with the entity)",
    "Include such requirements in the entity's HR procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders",
    "Work with relevant departments to ensure Screening or Vetting of all employees in cybersecurity functions",
    "Work with relevant departments to ensure the Screening or Vetting of all employees working in technical functions with privileged access, including database management personnel, firewall management personnel, and systems management personnel"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Entity personnel contract forms (signed copy)",
    "Cybersecurity Function Personnel Contract Forms (signed copy)",
    "Evidence that the Screening or Vetting of employees working in cybersecurity functions and technical functions with privileged access was performed, including but not limited to",
    "An official document from the relevant authorities indicating the performance of Screening or Vetting"
   ],
   "subcontrols": [
    {
     "ref": "1-9-3-1",
     "text": "non-disclosure clauses in their employment contracts with the entity (including during and after employment end/termination with the entity)."
    },
    {
     "ref": "1-9-3-2",
     "text": "Conducting screening or vetting for personnel in cybersecurity positions and technical positions with critical and privileged powers."
    }
   ]
  },
  {
   "ref": "1-9-4",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for personnel during their employment relationship with the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Work with relevant departments to provide cybersecurity awareness at the beginning and during work through the entity's approved communication channels",
    "Include such requirements in the entity's HR procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders",
    "Support the entity's policy by the Executive Management This must be done through the approval of the representative",
    "Inform all employees of the entity and obtain their approval on the cybersecurity policies and procedures, in order to educate the entity's employees of the importance of their role in implementing the cybersecurity requirements",
    "Include personnel cybersecurity requirements in the entity's HR procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Documents that confirm the provision of awareness content to employees in cybersecurity before work at the entity and providing them with access through e-mails, workshops, or any other means, including but not limited to",
    "Review cybersecurity awareness messages shared with employees through emails.",
    "Review of content presented in the workshop.",
    "Review the cybersecurity awareness plan.",
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "An acknowledgment form for approving cybersecurity policies by one of the entity's employees (signed copy)"
   ],
   "subcontrols": [
    {
     "ref": "1-9-4-1",
     "text": "Cybersecurity awareness (during on-boarding and during employment)."
    },
    {
     "ref": "1-9-4-2",
     "text": "Implementation and compliance with cybersecurity requirements, as per"
    }
   ]
  },
  {
   "ref": "1-9-5",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "end/termination of their employment with the entity.",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Review access of employees and revoke it immediately after the end/termination of their employment with the entity, which may include the following",
    "Define professional end-of-service, end of their employment with the entity, or termination procedures covering cybersecurity requirements",
    "Ensure the return of all entity's assets and revoke employees' access rights immediately upon the end of their employment with the entity"
   ],
   "deliverables": [
    "A clearance form with a signed and approved sample for the implementation of the procedures"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-9-6",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-9",
   "subdomainName": "Cybersecurity in Human Resources",
   "objective": "To ensure that cybersecurity risks and requirements for personnel (employees and contractors) of the entity are managed efficiently prior to, during, and upon the end procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for personnel of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review and update the cybersecurity policy and requirements for personnel in the entity periodically according to a documented and approved plan for review and based on a planned interval ( e.g., review must be conducted annually) or in the event of changes in related laws and regulations Document the review and changes to the cybersecurity requirements for personnel in the entity and approve them"
   ],
   "deliverables": [
    "An approved document that sets the policy's review schedule",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for personnel have been documented and approved by the head of the entity or his/her deputy",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-10-1",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-10",
   "subdomainName": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties.",
   "text": "A cybersecurity awareness program, delivered through multiple channels, shall be periodically developed and approved by the entity to strengthen the awareness about cybersecurity, cyber threats, and risks, and to build a positive cybersecurity awareness culture.",
   "tools": [
    "Awareness program template.",
    "Awareness content template for all employees.",
    "Awareness content form for supervisory and executive positions.",
    "Information and Technology Assets Operators Awareness Content Form."
   ],
   "guidelines": [
    "Develop and approve cybersecurity awareness program and plan in the entity through multiple channels periodically, including but not limited to",
    "Awareness emails.",
    "Cybersecurity awareness workshops",
    "Distribution of awareness publications",
    "Awareness presentation through billboards",
    "Launch of a cybersecurity training and awareness platform",
    "The program may include a plan to coordinate with the Human Resources department, the Media and Internal Communications department, and the cybersecurity function to raise awareness of cybersecurity, its threats and risks, and build a positive cybersecurity culture",
    "The entity's program must be supported by the Executive Management This must be done through the approval of the representative."
   ],
   "deliverables": [
    "The awareness program document approved by the entity"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-10-2",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-10",
   "subdomainName": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties.",
   "text": "The approved cybersecurity awareness program shall be implemented within the entity.",
   "tools": [],
   "guidelines": [
    "Implement the approved cybersecurity awareness and training program in coordination with the cybersecurity awareness and training department, which may include the following",
    "Implement the approved cybersecurity awareness program in the entity, including but not limited to sending awareness emails or conducting cybersecurity awareness workshops",
    "Evaluate cybersecurity awareness of all personnel and define and address cybersecurity weaknesses"
   ],
   "deliverables": [
    "Action plan to implement the cybersecurity awareness program adopted by the entity",
    "Awareness programs to be shared with employees",
    "List of beneficiaries of awareness programs"
   ],
   "subcontrols": []
  },
  {
   "ref": "1-10-3",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-10",
   "subdomainName": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties.",
   "text": "The cybersecurity awareness program shall include how to protect the entity against the most important and latest cyber risks and threats, including:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Provide cybersecurity awareness programs that cover the safe handling of e- mail services, especially with emails and social engineering",
    "Provide cybersecurity awareness programs to cover the safe handling of mobile devices and storage media",
    "Provide cybersecurity awareness programs that cover the safe handling of internet browsing services, especially dealing with suspicious websites such as phantom phishing sites and suspicious websites and links",
    "Provide cybersecurity awareness programs that cover the safe handling of social media"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Action plan to implement the cybersecurity awareness program adopted by the entity",
    "Evidence of providing awareness content for the safe handling of e -mail services, especially with phishing emails",
    "Evidence that awareness content is provided for the safe handling of mobile devices and storage media",
    "Evidence that awareness content is provided for the secure handling of internet browsing services",
    "Evidence that awareness content is provided for safe handling of social media"
   ],
   "subcontrols": [
    {
     "ref": "1-10-3-1",
     "text": "Secure handling of email services, especially phishing emails."
    },
    {
     "ref": "1-10-3-2",
     "text": "Secure handling of mobile devices and storage media."
    },
    {
     "ref": "1-10-3-3",
     "text": "Secure Internet browsing."
    },
    {
     "ref": "1-10-3-4",
     "text": "Secure use of social media."
    }
   ]
  },
  {
   "ref": "1-10-4",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-10",
   "subdomainName": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties.",
   "text": "Specialized skills and necessary training shall be provided to personnel in positions that are linked directly to cybersecurity within the entity. Such skills and training shall be classified in line with their cybersecurity responsibilities, including:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Develop and implement an approved cybersecurity training plan for employees of the cybersecurity function in coordination with the training department in the entity, which may include the following",
    "Implement the cybersecurity training plan for the entity in coordination with the Training and Employee Development Department",
    "Assist in the establishment of cybersecurity career paths to allow career progression, deliberate development, and growth within and between cybersecurity career fields",
    "Support in advocating for adequate funding for cybersecurity training resources, to include both internal and industry -provided courses, instructors, and related materials",
    "Develop and implement an approved training plan in the field of secure program and application development, and the safe management of the entity's information and technology assets for relevant employees in coordination with the training department in the entity. This may include the following",
    "Training plan to develop programs, applications and employees operating the entity's information and technology assets must be implemented in coordination with Training and Employee Development Department",
    "Assistance in defining career paths for software and application developers and the employees operating the entity's information and technology assets must be provided to allow for professional growth and upgrades in professional areas related to software development",
    "Provide support in requesting the adequate funding of training resources related to the development of programs, applications and employees operating the entity's information and technology assets, including internal and sector - related courses, trainers and related materials",
    "Develop and implement an approved cybersecurity training plan for employees of the cybersecurity Supervisory and executive functions in coordination with the training department in the entity, which may include the following",
    "Awareness of the importance of cybersecurity, developing the cybersecurity culture and the key risks and threats, such as phishing emails for supervisory and executive positions (Whale phishing) must be conducted",
    "Training plan for supervisory and executive positions in the entity must be implemented in coordination with the Training and Employee Development Department",
    "Assistance in the establishment of cybersecurity career paths to allow career progression, deliberate development, and growth within and between cybersecurity career fields must be provided",
    "Support in advocating for adequate funding for cybersecurity training resources, including both internal and industry -provided courses, instructors, and related materials must be provided"
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Approved training plans and programs for the cybersecurity department employees at the entity",
    "Cybersecurity training certificates",
    "Approved training programs for employees involved in the development of programs, applications, and employees operating the entity's information and technology assets",
    "Training certificates in software and application development",
    "Security training programs dedicated to supervisory and executive positions in the entity",
    "Training certificates in supervisory and executive positions"
   ],
   "subcontrols": [
    {
     "ref": "1-10-4-1",
     "text": "Cybersecurity department personnel."
    },
    {
     "ref": "1-10-4-2",
     "text": "Personnel working on software/application development and those working on information and technology assets of the entity."
    },
    {
     "ref": "1-10-4-3",
     "text": "Executive and supervisory positions."
    }
   ]
  },
  {
   "ref": "1-10-5",
   "domain": "1",
   "domainName": "Cybersecurity Governance",
   "subdomain": "1-10",
   "subdomainName": "Cybersecurity Awareness and Training Program",
   "objective": "are aware of their cybersecurity responsibilities, and are equipped with the required information and technology assets and fulfill their cybersecurity duties.",
   "text": "The implementation of cybersecurity awareness program within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of cybersecurity awareness and training programs by conducting a periodic assessment (according to a documented and approved plan for review and based on a planned interval (e.g., quarterly) ) to implement awareness and training plans by the Cybersecurity function and in cooperation with relevant departments (such as the Awareness and Training Department)",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system The entity may develop a review plan explaining the cybersecurity requirements implementation review schedule for cybersecurity awareness and training programs"
   ],
   "deliverables": [
    "Results of cybersecurity awareness program implementation review in the entity",
    "A document that defines the cybersecurity awareness and training implementation review cycle (Compliance Assessment Schedule)",
    "Compliance assessment report that shows the assessment of the implementation of cybersecurity requirements for cybersecurity awareness and training programs"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "Cybersecurity requirements for managing information and technology assets of the entity shall be identified, documented, and approved.",
   "tools": [
    "Asset Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity requirements for information and technology assets management in the entity, including the following",
    "The cybersecurity requirements for types and description of information and technology asset management must be identified",
    "Information and technology asset classification levels requirements in terms of data included and processed, and the criticality of the technology asset from a cybersecurity perspective must be defined",
    "Requirements for the defined stages of the information and technology assets life cycle ( including but not limited to: preservation, processing, storage, destruction, etc.) must be defined",
    "Roles and responsibilities requirements for the ownership and management of information and technology assets must be defined",
    "Support the entity's developed requirements by the Executive Management This must be done through the approval of the representative"
   ],
   "deliverables": [
    "Information asset management cybersecurity requirements (in form of policy or standard) approved by the entity (e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or his/her deputy on the requirements (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "Cybersecurity requirements for managing information and technology assets of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "All cybersecurity requirements to manage information and technology assets of the entity, which may include the following",
    "Approved cybersecurity requirements for the management of information and technology assets in the entity must be implemented, including but not limited to, classifying all information and technology assets of the entity, documenting and approving them in an approved and official document (e.g., a documented record for the management of the entity's information and technology assets), as well as e",
    "Specific procedures for dealing with assets based on their classification and in accordance with the relevant laws and regulations must be established."
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to information and technology asset management as documented in the policy",
    "An action plan to implement the cybersecurity requirements of information and technology assets management",
    "A documented and up-to-date record of all information and technology assets (e.g., Excel spreadsheet or displayed through automated means using solutions such as CMDB) must be provided",
    "Specific procedures for dealing with assets based on their classification and in accordance with the relevant laws and regulations."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "The policy of acceptable use of information and technology assets of the entity shall be identified, documented, approved, and communicated.",
   "tools": [
    "Asset Acceptable Use Policy Template."
   ],
   "guidelines": [
    "Develop acceptable use policy for information and technology assets of the entity, which may include the following",
    "Set of specific regulations for access to and use of assets.",
    "A set of clear examples of unacceptable use.",
    "Consequences if defined rules of acceptable use of assets are breached",
    "The method used to monitor adherence to the defined rules of acceptable use of the entity's information and technology assets",
    "Acceptable use policy of the entity's information and technology assets must be communicated to all employees and stakeholders in the entity through, including but not limited to the official email or through the entity's website",
    "Support the entity's policy by the Executive Management . This must be done through the approval of the entity head or his/ her deputy"
   ],
   "deliverables": [
    "Approved policy that covers the requirements for acceptable use of the entity's information and technology assets (e.g., electronic copy or official hard copy).",
    "Acceptable use policy of the entity's information and technology assets must be communicated to all employees and stakeholders in the entity through, including but not limited to the official email or through the entity's website. Evidence that all employees and stakeholders are aware and informed must be provided.",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "The policy of acceptable use of information and technology assets of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Cybersecurity policy for the acceptable use policy of the information and technology assets of the entity must be implemented, including the following",
    "Requirements for the acceptable use of information and technology assets by the entity must be implemented, including but not limited to: requesting each employee view and approve the Acceptable Use Policy of information and technology assets",
    "These requirements must be communicated through the entity's approved communication channels to educate the entity's internal and external stakeholders to implement these requirements",
    "Appropriate mechanisms and techniques must be developed to monitor violations of the Acceptable Use Policy requirements and warn of disciplinary actions in the event of violations"
   ],
   "deliverables": [
    "An action plan to implement the acceptable use requirements of information and technology assets of the entity",
    "Evidence of communicating these requirements through the communication channels approved by the entity",
    "A completed and approved form that clarifies the approval of the Acceptable Use Policy by all entity's employees ( e.g., scanned physical copy, digital platform, or official hard copy)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-5",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "Information and technology assets of the entity shall be classified, labeled, and handled as per the relevant legislative and regulatory requirements.",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of information and technology assets management at the entity and must be approved by the representative",
    "Work with the concerned departments to identify all information and technology assets, including (but not limited to)",
    "Infrastructure (e.g., servers)",
    "Applications and services",
    "Networks (e.g., router)",
    "Workstations",
    "Peripherals (e.g., printers)",
    "Operating systems (if any)",
    "Document all information and technology assets in a single register with characteristics such as (asset name, description, owner and criticality)",
    "Work with asset owners to identify, document and approve asset classification in the register in accordance with the relevant laws and regulations",
    "Work with the concerned departments to ensure the coding of assets based on their classification, including but not limited to labelling the assets or automatically coding them through modern systems",
    "Work with the concerned departments to ensure that assets are handled according to the defined and approved classification level and based on the approved procedures for dealing with each asset"
   ],
   "deliverables": [
    "A cybersecurity policy that covers the information and technology asset management requirements of the entity (e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)",
    "A document that outlines the method and system of asset classification, coding and requirements",
    "An action plan to implement the requirements of classification and coding of information and technology assets (Labelling) in accordance with the relevant laws and regulations.",
    "An up -to-date register that includes all information and technology assets, indicating the level of classification for each asset ( e.g., Excel or through automated means using technical solutions such as CMDB)",
    "Evidence that outlines that the entity's assets are classified according to the defined and approved classification level",
    "Evidence that outlines that the entity's assets have been labelled according to the classification level defined and based on but not limited to the coding labels that demonstrate the coding of all assets within the entity",
    "Evidence of the implementation of controls on the entity's assets in accordance with their classification level, including but not limited to the procedures followed when dealing with each asset based on its classification"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-1-6",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-1",
   "subdomainName": "Asset Management",
   "objective": "To ensure that the entity has an accurate and updated inventory of assets, including details of all information and technology assets of the entity, in order to support the integrity, accuracy, and availability of information and technology assets of the entity.",
   "text": "Cybersecurity requirements for managing information and technology assets of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review and update cybersecurity requirements for information and technology assets management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document and approve review and changes to the entity's cybersecurity requirements of the information and technology assets management by the head of the entity or his/ her deputy"
   ],
   "deliverables": [
    "Results of information and technology assets management cybersecurity requirements implementation review in the entity",
    "A document that defines the cybersecurity requirements implementation review cycle to manage the information and technology assets of the entity (Compliance Assessment Schedule)",
    "Log of updates and changes to the information and technology asset management cybersecurity requirements",
    "Compliance assessment report that outlines the results of the cybersecurity requirements implementation assessment for information and technology asset management",
    "An approved document that sets the policy's review schedule",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-2-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-2",
   "subdomainName": "Identity and Access Management",
   "objective": "To ensure protecting cybersecurity of logical access to information and technology assets of the entity, in order to prevent unauthorized access and restrict access to the extent necessary for accomplishment of the assigned tasks of the entity.",
   "text": "Cybersecurity requirements for identity and access management of the entity shall be identified, documented, and approved.",
   "tools": [
    "Identity and Access Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for identity and access management in the entity, which may include, but is not limited to",
    "Grant access, including - Access to user accounts - Privileged Access to accounts - Remote access to the entity's networks and systems - Define and approve the authority of each type of users",
    "Revoke and Change Access.",
    "Review Identity and Access",
    "Manage passwords",
    "Support the entity's policy by the Executive Management This must be done through the approval of the representative"
   ],
   "deliverables": [
    "Cybersecurity policy that covers Identity and Access Management ( e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-2-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-2",
   "subdomainName": "Identity and Access Management",
   "objective": "To ensure protecting cybersecurity of logical access to information and technology assets of the entity, in order to prevent unauthorized access and restrict access to the extent necessary for accomplishment of the assigned tasks of the entity.",
   "text": "Cybersecurity requirements for identity and access management of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "All cybersecurity requirements must be implemented for the entity's approved identity and access management procedures. It is also recommended that the identity and access management cover the following, but not limited to",
    "User Authentication based on user login management.",
    "Password management based on the entity's password policy",
    "User authorization management based on a need -to-know and Need - to-use basis.",
    "User authorization management based on least privilege and Segregation of Duties",
    "Remote access management to the entity's networks.",
    "Access Cancellation and Update Management."
   ],
   "deliverables": [
    "Action plan for cybersecurity requirements for Identity and Access Management",
    "Evidence that the identity and access management controls must be implemented on all technical and information assets in the entity, including but not limited to, the configuration of all technical information systems in line with the cybersecurity controls and requirements of identity and access management"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-2-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-2",
   "subdomainName": "Identity and Access Management",
   "objective": "To ensure protecting cybersecurity of logical access to information and technology assets of the entity, in order to prevent unauthorized access and restrict access to the extent necessary for accomplishment of the assigned tasks of the entity.",
   "text": "Cybersecurity requirements for identity and access management of the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of identity and access management at the entity and must be approved by the representative",
    "Ensure all employees have a unique identifier, which may be a job number, employee name, or other naming mechanisms to ensure that usernames are unique",
    "Prepare password standard controls taking into consideration best practices, including but not limited to",
    "Expiration Period",
    "Complexity",
    "Lockout",
    "Activation",
    "Password History",
    "A secure mechanism to create a password and provide it to the user",
    "Develop procedures for remote access and for privileged accounts with Multi- Factor Authentication and define the suitable authentication factors and their numbers as well as the suitable authentication techniques based on the result of impact assessment of authentication failure and bypass.",
    "Provide appropriate and advanced multi-factor authentication techniques and link them to remote access technologies (e.g., VPN) must be ensured",
    "Use two or more of the following authentication elements to apply multi-factor authentication (as per defined in the procedures for remote access and for privileged accounts)",
    "Something you know, e.g., using the password",
    "Something you have, e.g., using One time password through SMS or applications"
   ],
   "deliverables": [
    "Cybersecurity policy that covers Identity and Access Management ( e.g., electronic copy or official hard copy)",
    "Password management policy in the entity (e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or system owner or his/her deputy on such policies ( e.g., via the entity's official e -mail, paper or electronic signature)",
    "Evidence that the identity and access management controls must be implemented on all technical and information assets in the entity, including but not limited to, the configuration of all technical information systems in line with the cybersecurity controls and requirements of identity and access management",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)",
    "Evidence that outlines the implementation of multi -factor authentication requirements for remote access and for privileged accounts, including but not limited to a screenshot showing the configuration of systems to ensure that the multi-factor authentication request for remote access and for privileged accounts is verified",
    "Evidence that outlines the implementation of User authorization management requirements, including but not limited to a screenshot showing the configuration of systems to ensure the implementation of user authorization management based on a Need to Know and Need to Use basis and least privilege and Segregation of Duties",
    "Privileged Access Management Policy in the entity (e.g., electronic copy or official hard copy)",
    "Evidence that outlines the implementation of privileged access management requirements, including but not limited to a screenshot showing the configuration of systems to ensure that administrators are granted privileged access",
    "Evidence that outlines the implementation of periodic review requirements of identity and access, e.g., an official and approved document that clarifies the periodic review of the identity and access"
   ],
   "subcontrols": [
    {
     "ref": "2-2-3-1",
     "text": "Single-factor authentication based on username and password."
    },
    {
     "ref": "2-2-3-2",
     "text": "Multi-factor authentication, and defining the suitable authentication factors and their numbers as well as the suitable authentication techniques based on the result of impact assessment of authentication failure and bypass for remote access and for privileged accounts."
    },
    {
     "ref": "2-2-3-3",
     "text": "User authorization based on identity and access control principles (Need - to-Know and Need -to-Use principle, Least Privilege principle, and Segregation of Duties principle)."
    },
    {
     "ref": "2-2-3-4",
     "text": "Privileged access management."
    },
    {
     "ref": "2-2-3-5",
     "text": "Periodic review of identities and access rights."
    }
   ]
  },
  {
   "ref": "2-2-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-2",
   "subdomainName": "Identity and Access Management",
   "objective": "To ensure protecting cybersecurity of logical access to information and technology assets of the entity, in order to prevent unauthorized access and restrict access to the extent necessary for accomplishment of the assigned tasks of the entity.",
   "text": "The implementation of cybersecurity requirements for identity and access management of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of identity and access management by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement identity and access managem ent requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department)",
    "Review and update cybersecurity requirements for identity and access management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations",
    "Document the review and changes to the cybersecurity requirements for identity and access management in the entity and approve them by the head of the entity or his/her deputy"
   ],
   "deliverables": [
    "Results of identity and access management requirements implementation review in the entity",
    "A document that defines the cybersecurity requirements implementation review cycle for identity and access management at the entity (Compliance Assessment Schedule)",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for identity and access management in the entity",
    "An approved document that sets the policy's review schedule",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-3-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-3",
   "subdomainName": "Information System and Information Processing Facilities Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information system and processing facilities of the entity shall be identified, documented, and approved.",
   "tools": [
    "Database Security Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for Information System and Processing Facilities Protection in the entity, including the following",
    "Modern and advanced protection techniques and mechanisms, providing them and ensuring their reliability",
    "Malware Protection Solution Configuration",
    "Scope of devices to be protected, including all workstations, critical systems in the entity, etc",
    "Secure copies of the operating systems used in the entity must be built and prepared in a secure manner, protection programs must be installed, and unused services must be disabled. Such copied must be used in the configuration of desktops and servers",
    "Workstations and systems in the entity must be periodically scanned against malware",
    "Use of external storage media and its security must be restricted",
    "Patch management for systems, applications and devices",
    "Central sources of time synchronization in the entity must be defined to be from a reliable source",
    "Support the entity's policy by the Executive Management This must be done through the approval of the entity head or his/ her deputy"
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of Information System and Processing Facilities Protection at the entity (e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)",
    "Secure Configuration and Hardening Policy Template.",
    "Server Security Policy Template.",
    "Malware Protection Policy Template.",
    "Storage Media Policy Template.",
    "Patch Management Policy Template."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-3-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-3",
   "subdomainName": "Information System and Information Processing Facilities Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information systems and processing facilities of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements for Information System and Processing Facilities Protection in the entity. This may include the following",
    "Modern and advanced protection techniques and mechanisms' availability and reliability must be ensured",
    "Scope of devices to be protected and reviewed periodically must be ensured",
    "Use of external storage media and its security must be restricted",
    "Patches throughout the entity's devices, systems, and applications must be implemented",
    "Central Clock Synchronization and from a reliable source must be implemented"
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to information systems and processing facilities as documented in the policy",
    "An up-to-date list of the entity's virus protection systems and the extent of their download",
    "Restrict the use of external storage media and procedures for approving their use",
    "Evidence that the scope of patches covers all devices, systems and applications",
    "Evidence that the entity uses a central server and a reliable source for timing synchronization"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-3-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-3",
   "subdomainName": "Information System and Information Processing Facilities Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information systems and processing facilities of the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative",
    "Provide anti -virus, suspicious programs, and malware protection techniques and mechanisms, including the following",
    "Continuously ensure that the technologies used are current and advanced and contain protection against advanced persistent threat (APT)",
    "Determine the domain of the assets on which the protection system will be installed and identify and update their status",
    "Install the protection system throughout the workstations, systems and servers of the entity",
    "Review the protection system periodically to ensure that the scope of the protection system is comprehensive for all workstations, systems, and servers of the entity through the protection system's control unit",
    "Develop and implement a remediation action plan (when needed) to install the protection system on all devices while taking action against devices and systems where it is frequently observed that the modern and advanced protection system is not installed",
    "Follow up on the protection system periodically to ensure updates are installed and released on all workstations, systems and servers of the entity",
    "Restrict the use of external storage media by",
    "Groups in the privileged access management system must be created according to authority so that the use of external storage media is automatically not activated on all workstations, the entity's systems, and servers",
    "Documented procedures must be defined to provide approval for the use of external storage media (including but not limited to: requesting approvals via e -mail, paper, or through an internal system). Such procedures include - Reason for requesting approval for use - Use start and end date. - Mechanism for handling data stored in storage media so that it is checked prior to use and data is erased a",
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Define procedures for patch management for systems, devices and applications, which include:",
    "The scope of systems where patches are implemented must be defined to include: - Workstations - Operating Systems - Network Devices - Databases - Applications"
   ],
   "deliverables": [
    "Documents indicating the identification and documentation of the requirements of this ECC in the policies or procedures of the entity approved by the representative.",
    "List of antivirus systems and evidence of protection against APT (including but not limited to a screenshot or direct example from the APT Monitoring page of the protection system)",
    "Reports or evidence of installing the protection technologies across all workstations, systems and servers of the entity",
    "Reports or evidence of following -up the scope of installing and periodic updating of these technologies",
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "Report or evidence indicating the restriction of using external storage media (including but not limited to a screenshot or direct example from access management system showing the vigor restriction of the use of external storage media on workstations and servers).",
    "Approval procedures for the use of storage media for part of the approved devices.",
    "Evidence indicating the inclusion of change management in patches (including but not limited to: including patches in change management methodology or enforcing change management by including it in the requirements of Patch Management).",
    "Approval procedures indicate that change management approval is required for patches.",
    "Reports or evidence that the scope of patches covers all devices, systems and applications.",
    "Reports or evidence that the patches are performed according to the period specified in the procedures (including but not limited to: a screenshot or direct example that displays the date and scope for several samples of patches approved by e-mail, internal system or paper that are performed in advance to include all the entity's devices, systems and applications periodically).",
    "Evidence that the entity uses a central server to synchronize timing (including but not limited to: a screenshot or direct example of the presence of this server in the network with all server details)."
   ],
   "subcontrols": [
    {
     "ref": "2-3-3-1",
     "text": "Protection from viruses, suspicious programs and activities, and malware on workstations and servers, using modern and advanced protection technologies and mechanisms, and securely managing them."
    },
    {
     "ref": "2-3-3-2",
     "text": "Strict restriction on the use of external storage media and their security."
    },
    {
     "ref": "2-3-3-3",
     "text": "Patch management for systems, applications, and devices."
    },
    {
     "ref": "2-3-3-4",
     "text": "Centralized clock synchronization with an accurate and trusted source, such as sources provided by the Saudi Standards, Metrology and Quality Organization (SASO)."
    }
   ]
  },
  {
   "ref": "2-3-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-3",
   "subdomainName": "Information System and Information Processing Facilities Protection",
   "objective": "",
   "text": "The implementation of cybersecurity requirements for protection of the information system and processing facilities of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements for Information System and Processing Facilities Protection in the entity periodically according to a documented and approved plan for review and based on a planned interval (e.g., periodic review must be conducted annually).",
    "Document the review and changes to the cybersecurity requirements for Information System and Processing Facilities Protection in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "An approved document that defines the review schedule for the requirements document.",
    "Evidence that the periodic review of security requirements is performed to protect information systems and processing facilities in the entity.",
    "Formal approval by the head of the entity or his/her deputy on the updated requirements (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-4-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-4",
   "subdomainName": "Email Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of the email service of the entity shall be identified, documented, and approved.",
   "tools": [
    "Email Security Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for email protection in the entity, including the following:",
    "Modern and advanced protection techniques and mechanisms' availability and reliability must be ensured.",
    "Email Protection Solution Configuration Requirements.",
    "Email roles and responsibilities requirements for public and joint accounts.",
    "Size of incoming and outgoing email attachments and the capacity of the mailbox for each user.",
    "Secure design requirements for email infrastructure.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Email security policy and standard document approved by the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-4-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-4",
   "subdomainName": "Email Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of email service of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Email protection cybersecurity requirements in the entity must be implemented, including:",
    "Approved cybersecurity requirements must be implemented to protect the entity's email, including but not limited to the use of appropriate and advanced technologies to analyze and filter emails.",
    "Advanced technologies must be used to protect the entity's email from phishing emails and spam messages, including but not limited to the presence of an official and effective subscription with email protection service providers.",
    "Email access must be through an intermediary, including but not limited to Load balancer."
   ],
   "deliverables": [
    "An action plan to implement Email protection cybersecurity requirements at the entity.",
    "Email protection controls in the entity must be implemented, including but not limited to:",
    "Advanced email protection and filtering technologies must be used by the entity to block suspicious messages, such as spam and phishing emails.",
    "Antivirus solutions must be configured to email servers in order to scan all inbound and outbound emails.",
    "Email field of the entity must be documented by using necessary means, such as the Sender Policy Framework, and reliability of incoming mail fields must be ensured through modern technologies such as (Incoming Message DMARC verification)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-4-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-4",
   "subdomainName": "Email Protection",
   "objective": "",
   "text": "Cybersecurity requirements for protection of the email service of the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of email security at the entity and must be approved by the representative.",
    "Define and provide advanced technologies to analyze and filter the entity's emails.",
    "Activate analysis and filtering features in the email protection system through the dashboard.",
    "Periodically review the list of suspicious emails such as phishing messages, spam messages, etc. through the system by the specialized team to follow up email protection.",
    "Add new intrusion indicators related to email in the protection system on an ongoing basis.",
    "Activate multi-factor authentication (the requirements for which are specified in the cybersecurity requirements document for email protection) f or remote access and entity's webmail access by, but not limited to, one of the following methods:",
    "Text messages linked to the email user's number must be used.",
    "Advanced and reliable applications for multi-factor authentication.",
    "Mobile device management applications must be used to allow users' devices (as another element of access) to email for protocols (such as EWS, outlook anywhere protocols) that do not support text messages or applications that provide verification code.",
    "Define technologies compatible with the entity's technical systems and infrastructure to backup and archive the entity's email.",
    "Define retention period for backup and archiving of the entity's email.",
    "Perform backup at the level of the entity's email servers.",
    "Activate archiving of all email boxes of the entity.",
    "Define and provide advanced technologies within the entity to provide email protection against advanced persistent threats and zero-day malware."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "Screenshot or direct example showing subscription and use of modern and advanced technologies to analyze and filter emails in the entity.",
    "Screenshot or direct example of the configuration of email to prove the feature of analyzing and filtering emails, including phishing emails and spam emails.",
    "Screenshot or direct example of email configuration to prove the activation of multi-factor authentication (the requirements for which are specified in the cybersecurity requirements document for email protection) to access via the entity's email webmail.",
    "Screenshot or direct example that proves the use of advanced and reliable technologies for multi-factor authentication.",
    "Screenshot or direct example showing subscription and use of modern and advanced technologies for backup and archiving of email, as well as the approved capacity and duration.",
    "Backup reports for the entity's email servers.",
    "Screenshot or direct example that shows the activation of the email boxes archiving feature.",
    "Screenshot or direct example showing subscription and use of modern and advanced technologies for email ATP protection in the entity.",
    "Screenshot or direct example showing email configuration in the entity and the activation of ATP protection.",
    "Screenshot showing the preparation of the following:",
    "SPF Record, which shows the servers authorized to send email from the entity scope."
   ],
   "subcontrols": [
    {
     "ref": "2-4-3-1",
     "text": "Analyzing and filtering email messages (specifically phishing emails and spam emails) using modern and advanced email protection techniques and mechanisms."
    },
    {
     "ref": "2-4-3-2",
     "text": "Multi-factor authentication, and defining the suitable authentication factors and their numbers as well as the suitable authentication techniques based on the result of impact assessment of authentication failure and bypass for remote and webmail access."
    },
    {
     "ref": "2-4-3-3",
     "text": "Email archiving and backup."
    },
    {
     "ref": "2-4-3-4",
     "text": "Secure management and protection against Advanced Persistent Threats (APT), which normally utilize zero-day malware and viruses."
    },
    {
     "ref": "2-4-3-5",
     "text": "Framework (SPF), Domain Keys Identified Mail (DKIM), and Domain Message Authentication Reporting and Conformance (DMARC)."
    }
   ]
  },
  {
   "ref": "2-4-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-4",
   "subdomainName": "Email Protection",
   "objective": "",
   "text": "The implementation of cybersecurity requirements for email service of the entity shall be periodically reviewed .",
   "tools": [],
   "guidelines": [
    "Review the implementation of cybersecurity requirements for email protection by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement the entity's email protection procedures by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the cybersecurity requirements implementation review schedule for email protection.",
    "Review and update Cybersecurity requirements for email protection in the entity must be reviewed and updated periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for email protection in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of email protection cybersecurity requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements application review cycle for the entity's email protection (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for the entity's email protection",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-5-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-5",
   "subdomainName": "Networks Security Management",
   "objective": "",
   "text": "identified, documented, and approved.",
   "tools": [
    "Network Security Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for network security in the entity, including the following:",
    "Network Access Requirements.",
    "Third Parties Access Requirements to the Network.",
    "Network Protection Requirements.",
    "Physical and environmental security requirements to ensure that network devices are stored in a secure and appropriate environment.",
    "Security technology standard controls for all network devices used within the entity must be defined, documented and approved.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Network security management policy approved by the entity (e.g., electronic copy or official hard copy).",
    "Cybersecurity policy that covers the requirements of technical security standard controls and network security management in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy and technical standard ( e.g., via the entity's official e -mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-5-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-5",
   "subdomainName": "Networks Security Management",
   "objective": "",
   "text": "implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements for network security in the entity, including the following:",
    "Ensure physical or logical segregation and division of the entity's network parts.",
    "Use Firewall to protect the entity's networks.",
    "Implement the principle of multi -stage security defense (Defense -in- Depth) to provide advanced and more effective protection for the entity's network devices.",
    "Isolate the production environment network from the development and testing networks of the entity.",
    "Ensure security of navigation and internet connection in the entity, including setting up network devices and restricting access to suspicious websites.",
    "Protect the internet browsing channel from advanced persistent threats.",
    "Ensure the security and protection of wireless networks at the entity.",
    "Ensure the security of the entity's network ports, protocols, and services restrictions and management.",
    "Use advanced protection systems to detect and prevent intrusions in the entity's networks.",
    "Ensure the security of the entity's DNS.",
    "Establish procedures to ensure the continuous implementation of cybersecurity requirements adopted for the entity's network security management in accordance with the relevant laws and regulations."
   ],
   "deliverables": [
    "An action plan to implement the cybersecurity requirements of information and technology assets management.",
    "Sample showing the implementation of the entity's network security management controls, including but not limited to:",
    "Sample that shows the entity's use of modern technologies for network security management, as well as restrictions and management of network ports, protocols and services.",
    "Sample that shows network configuration to prevent critical systems from being connected to the entity's wireless network.",
    "Sample showing implementation of logical isolation between production environment network, test environment network, and other networks.",
    "Sample of defined and approved procedures for handling critical network devices and systems of the entity."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-5-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-5",
   "subdomainName": "Networks Security Management",
   "objective": "",
   "text": "the following as a minimum:",
   "tools": [
    "Wireless Network Security Standard Template."
   ],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of network security management at the entity and must be approved by the representative.",
    "Define network zones based on trust level e.g., trust in the internet zone is \"low\", trust level in an internet-isolated zone hosting databases is \"high\".",
    "Define necessary procedures to ensure the physical or logical isolation and segregation of network parts in the entity (for example but not limited to procedures for using the internal virtual network to isolate network parts).",
    "Activate appropriate and advanced technologies for the safe physical or logical isolation and segregation of network parts, including but not limited to:",
    "Firewall Isolation.",
    "Isolation for systems accessed from outside the entity in a neutral zone (DMZ).",
    "Insulation of network parts via VLAN.",
    "Implement the principle of multi -stage security defense (Defense -in- Depth), which includes the implementation of technical controls and administrative controls for protection.",
    "Network domains must be logically separated to clarify production environment network addresses and development and testing environment networks (e.g., using VLANs).",
    "Network must be configured to ensure that production environment networks are isolated from development and testing environment networks through the use of firewall systems.",
    "Network segregation and network diagram must be documented to illustrate the isolation of production environment networks from development and testing networks.",
    "Define necessary procedures to ensure navigation and internet connection security at the entity, including but not limited to:",
    "Procedures for restriction of suspicious websites, file sharing and storage sites, and remote access sites.",
    "Configuration of firewall systems to connect by using Proxy to analyze and filter data transmitted to and from the entity."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of network security management in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Sample showing the implementation of requirements related to the safe physical or logical isolation and segregation of network parts, including but not limited to:",
    "Evidence showing the implementation of requirements related to the safe physical or logical isolation and segregation of network parts and defense in depth strategy (e.g., a screenshot showing evidence of the subscription and use of modern and advanced technologies to implement the physical or logical isolation and segregation of network parts in a secure manner).",
    "Sample showing the implementation of the requirements of appropriate and advanced technologies for the safe physical or logical isolation and segregation of network parts and defense in depth (e.g., a screenshot showing evidence of the safe physical or logical isolation and segregation of network parts, as well as viewing and reviewing Network Diagram.",
    "Cybersecurity policy that covers all the requirements of network security management in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such requirements (e.g., via the entity's official e-mail, paper or electronic signature).",
    "List of server addresses in production environment and development and testing environment.",
    "An up-to-date network diagram document that shows logical segregation and clarifies the isolation between the production environment network from the development and testing networks.",
    "Sample showing the implementation of requirements related to browsing and internet connection security, including but not limited to:",
    "Sample showing the implementation of browsing and internet connection security requirements ( e.g., screenshot showing evidence of use of modern and advanced technologies for browsing and internet connection security).",
    "Sample showing the implementation of the requirements of appropriate and advanced technologies for browsing and internet connection security (e.g., a screenshot showing evidence that the network settings and firewall systems are conducted and configured to ensure security of browsing and internet connection, evidence of restriction of suspicious websites, file sharing and storage sites, remote acc"
   ],
   "subcontrols": [
    {
     "ref": "2-5-3-1",
     "text": "Logical or physical isolation and segmentation of network segments in a secure manner which is required to control relevant cybersecurity risks, using firewall and defense-in-depth principle."
    },
    {
     "ref": "2-5-3-2",
     "text": "Isolation of production network from testing and development environment networks."
    },
    {
     "ref": "2-5-3-3",
     "text": "Secure browsing and internet connectivity, including strict restrictions on suspicious websites, file storage/sharing websites, and remote access websites."
    },
    {
     "ref": "2-5-3-4",
     "text": "Wireless network security and protection using secure authentication and encryption techniques and avoiding the connection of wireless networks to subsequent risks, with handling the m in a way that protects the technology assets of the entity."
    },
    {
     "ref": "2-5-3-5",
     "text": "Restricting and managing network services, protocols, and ports."
    },
    {
     "ref": "2-5-3-6",
     "text": "Intrusion Prevention Systems (IPS)."
    },
    {
     "ref": "2-5-3-7",
     "text": "Security of Domain Name Service (DNS)."
    },
    {
     "ref": "2-5-3-8",
     "text": "Secure management and protection of Internet browsing channel against Advanced Persistent Threats (APT), which normally utilize zero-day malware and viruses."
    },
    {
     "ref": "2-5-3-9",
     "text": "Protecting against Distributed Denial of Service (DDoS) attacks to limit risks arising from these attacks."
    }
   ]
  },
  {
   "ref": "2-5-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-5",
   "subdomainName": "Networks Security Management",
   "objective": "",
   "text": "management shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of network security in the entity by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement network security management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels (e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation of cybersecurity requirements to network security management in the entity.",
    "Review and update cybersecurity requirements for network security management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for network security in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of network security cybersecurity requirements implementation review in the entity.",
    "An approved document that defines the cybersecurity requirements implementation review cycle to manage the entity's network security (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for the entity's network security.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-6-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-6",
   "subdomainName": "Mobile Devices Security",
   "objective": "information and business information and protecting them during transfer and storage policy).",
   "text": "Cybersecurity requirements for mobile devices and BYOD security when connected to",
   "tools": [
    "Workstations, Mobile Devices and BYOD Security Policy Template."
   ],
   "guidelines": [
    "Develop and document Cybersecurity policy for mobile devices and BYOD in the entity, including the following:",
    "Mobile Devices Cybersecurity Requirements.",
    "BOYD Cybersecurity Requirements.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy and standard for mobile devices and personal devices (BYOD) at the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy and technical standard ( e.g., via the entity's official e -mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-6-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-6",
   "subdomainName": "Mobile Devices Security",
   "objective": "information and business information and protecting them during transfer and storage policy).",
   "text": "Cybersecurity requirements for mobile devices and BYOD security of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "All cybersecurity requirements related to the security of mobile devices and BYOD for the entity must be implemented, which may include the following:",
    "Ensure the isolation, segregation, and cryptography of data and information of the entity stored on mobile devices and BYOD from the rest of the information and data on the device.",
    "Ensure the use must be specified and restricted to the requirements of the entity.",
    "Provide us of workstations and mobile devices with privileged access following the principle of least privilege.",
    "Ensure that the storage media of critical and sensitive workstations and mobile devices are encrypted and have privileged access.",
    "Ensure that data and information of the entity stored on mobile devices and BYOD must be deleted when devices are lost or after the end/termination of the functional relationship with the entity.",
    "Ensure the activation of Remote Wipe on all mobile devices that store or process the entity's classified information.",
    "Implement the entity's Group Policy and apply it to all workstations and mobile devices to ensure compliance with regulatory and security controls.",
    "Provide security awareness to users.",
    "Centrally manage workstations and mobile devices through, but not limited to, the Active Directory server or through a centralized management system.",
    "Implement secure configuration and hardening controls to workstations and mobile devices in accordance with cybersecurity standard controls.",
    "Establish procedures to ensure the implementation of cybersecurity requirements adopted for the entity's mobile devices and personal devices (BYOD) management in accordance with the relevant laws and regulations."
   ],
   "deliverables": [
    "An action plan to implement the cybersecurity requirements for mobile devices and personal devices (BYOD) security management.",
    "Sample showing the implementation of mobile devices and BYOD security controls at the entity, including but not limited to:",
    "Sample showing that the entity's use of advanced technologies for mobile devices and personal devices (BYOD) security (e.g., the existence of advanced technologies necessary to separate and encrypt the entity's data and information stored on mobile devices and BYOD).",
    "Sample showing the central management of workstations and mobile devices, including but not limited to a screenshot from the Active Directory server in addition to configuration.",
    "Defined and approved procedures for handling mobile devices and personal devices (BYOD) at the entity."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-6-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-6",
   "subdomainName": "Mobile Devices Security",
   "objective": "information and business information and protecting them during transfer and storage policy).",
   "text": "Cybersecurity requirements for mobile devices and BYOD security of the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of mobile devices and BYOD at the entity and must be approved by the representative.",
    "Implement the requirements of separating and encrypting the entity's data and information stored on mobile devices and BYOD devices, which may include the following:",
    "Separation and cryptography of data and information.",
    "Appropriate and advanced technologies for separating and encrypting data and information.",
    "Use necessary technologies (such as Mobile Device Management) to encrypt the entity's data and information stored on mobile devices and BYOD.",
    "Implement the specified and restricted use requirements based on the requirements of the entity's business interest. These requirements may include the following:",
    "The use must be specified and restricted to the requirements of the entity.",
    "Appropriate and advanced technologies for specific and restricted use based on the requirements of the entity's business interest.",
    "Develop necessary procedures to restrict the use of mobile devices and link them to their network based on the requirements of the business interest.",
    "Assess mobile devices configuration and security controls, including but not limited to the implementation of (Patches, AV) prior to linking them to the entity's domain or network.",
    "Ensure that data and information of the entity stored on mobile devices and BYOD must be deleted when devices are lost or after the end/termination of the functional relationship with the entity.",
    "Use necessary technologies (such as Mobile Device Management) to ensure the deletion of sensitive data and information when the devices are lost, and after the end/termination of the functional relationship with the entity.",
    "Implement security awareness requirements for users, which may include the following:",
    "Provide security awareness to users."
   ],
   "deliverables": [
    "Cybersecurity policy that covers all the security requirements of mobile devices and personal devices (BYOD) at the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such requirements (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Sample showing the implementation of mobile devices and BYOD security requirements, including but not limited to:",
    "Sample showing the implementation of the requirements of appropriate and advanced technologies for the security of mobile devices and BYOD ( e.g., screenshot showing the use of advanced systems to provide and ensure data cryptography on mobile devices and BYOD at the entity).",
    "Defined and approved procedures for encrypting data and information stored on mobile devices and BYOD.",
    "Sample showing the implementation of requirements related to the specific and restricted use based on the entity's business interest, including but not limited to:",
    "Sample showing the implementation of the specific and restricted use requirements based on the entity's business interest ( e.g., a screenshot showing evidence that the necessary procedures are in place to restrict the use of mobile devices and link them to their network based on the business interest).",
    "Defined and approved procedures for restricting the use of mobile devices (e.g., a form of procedures, as well as a sample report showing evidence of ensuring that the mobile device settings and security controls are assessed, including the implementation of patches and antivirus updates prior to being linked to the network).",
    "Sample showing the implementation of requirements related to the deletion of data and information stored on mobile devices and BYOD to include, but not limited to:",
    "Sample showing the implementation of deletion requirements for data and information stored on mobile devices and BYOD devices ( e.g., a screenshot showing evidence of deleting data and information stored on mobile devices and personal devices when, for example, the subscription with a data deletion service and integrated secure management of mobile devices and BYOD devices provider is no longer va",
    "Sample of the followed procedures template showing evidence of ensuring the deletion of data and information stored on mobile devices and personal devices BOYD when they are lost or after the end/termination of the functional relationship with the entity.",
    "Sample showing the implementation of security awareness requirements for users, including but not limited to:"
   ],
   "subcontrols": [
    {
     "ref": "2-6-3-1",
     "text": "mobile devices and BYODs."
    },
    {
     "ref": "2-6-3-2",
     "text": "Controlled and restricted use based on the requirements of the interest of the entity's business."
    },
    {
     "ref": "2-6-3-3",
     "text": "BYOD in cases of device loss or after the ending/termination of employment with the entity."
    },
    {
     "ref": "2-6-3-4",
     "text": "Security awareness for users."
    }
   ]
  },
  {
   "ref": "2-6-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-6",
   "subdomainName": "Mobile Devices Security",
   "objective": "information and business information and protecting them during transfer and storage policy).",
   "text": "The implementation of cybersecurity requirements for mobile devices and BYOD security of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the implementation of cybersecurity requirements for mobile devices and BYOD security by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement the entity's mobile devices and BYOD security procedures by the Cybersecurity function and in cooperation with relevant departments (such as IT Depart",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan outlining the cybersecurity requirements implementation review schedule for mobile devices and BYOD security.",
    "Review and update cybersecurity requirements for mobile devices and BYOD security in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for mobile devices and BYOD security in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of mobile devices and BYOD cybersecurity requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for mobile devices and BYOD security (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for the entity's mobile devices and BYOD security.",
    "An approved document that sets the policy's review schedule",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-7-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-7",
   "subdomainName": "Data and Information Protection",
   "objective": "legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for protecting and handling data and information of the entity shall be identified, documented, and approved, as per the relevant legislative and regulatory requirements.",
   "tools": [
    "Data Security Policy Template"
   ],
   "guidelines": [
    "Cybersecurity requirements for data and information protection must be included and documented in line with policies issued by the National Data Management Office, including but not limited to:",
    "Data and Information Protection Requirements.",
    "Data and Information Ownership Requirements.",
    "Data and information Classification and Labelling Requirements.",
    "Data and Information Privacy Requirements.",
    "The policy must be supported by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of Data and Information Protection in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-7-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-7",
   "subdomainName": "Data and Information Protection",
   "objective": "legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for protecting data and information of the entity shall be implemented, based on its classification level.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements and procedures related to data and information protection based on its classification level.",
    "Develop an action plan to implement all cybersecurity requirements related to data and information protection based on its classification level.",
    "Implement data protection controls to ensure its protection according to its classification level and impact.",
    "The entity may also develop an action plan to implement cybersecurity requirements related to data and information protection based on its classification level , in order to ensure that the entity complies with all cybersecurity requirements for all internal and external stakeholders and follow up and monitor them periodically to ensure implementation."
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to information and data protection as documented in the policy.",
    "An action plan to implement cybersecurity requirements for data and information protection based on its classification level.",
    "Evidence showing the implementation of data and information protection controls based on its classification level, including but not limited to:",
    "Availability of procedures to deal with data according to their classification and impact.",
    "Sample of modern technologies used to protect the entity data and information ( e.g., the existence of advanced technologies necessary to protect, encrypt, and save the entity's data and information from modification and leakage)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-7-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-7",
   "subdomainName": "Data and Information Protection",
   "objective": "legislative and regulatory requirements.",
   "text": "The implementation of cybersecurity requirements for protecting data and information of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of data and information protection by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for data and information protection.",
    "Review and update cybersecurity requirements for data and information protection in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for data and information protection in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of data and information protection cybersecurity requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for the entity's data and information security (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for data and information protection in the entity.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for data and information protection have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-8-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-8",
   "subdomainName": "Cryptography",
   "objective": "To ensure the proper and efficient use of cryptography to protect electronic and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for cryptography within the entity shall be identified, documented, and approved.",
   "tools": [
    "Cryptography Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for cryptography in the entity, including the following:",
    "Standard controls of approved cryptography solutions and applicable restrictions (technically and regulatorily).",
    "Secure management of cryptographic keys during their lifecycle.",
    "Information must be encrypted in transit and storage based on classification as well as the relevant laws and regulations.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers all the requirements of cryptography in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-8-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-8",
   "subdomainName": "Cryptography",
   "objective": "To ensure the proper and efficient use of cryptography to protect electronic and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for cryptography within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements to the entity's approved cryptography procedures. It is also recommended that the cryptography procedures cover the following, but not limited to:",
    "Standard controls of approved cryptography solutions and applicable restrictions (technically and regulatorily).",
    "Secure management of cryptographic keys during their lifecycle.",
    "Information must be encrypted in transit and storage based on classification as well as the relevant laws and regulations.",
    "Approved cryptographic hash functions should be defined based on national cryptographic standard controls.",
    "Implementation of cryptography to technical and information assets.",
    "Use of approved TLS certificates for web servers and public applications issued by a trusted third party."
   ],
   "deliverables": [
    "An action plan to implement cybersecurity requirements for cryptography.",
    "Evidence showing the uses modern cryptography technologies in the entity (e.g., the presence of advanced encryption technologies in the entity, security procedures and standard controls that support the implementation of cryptography in the entity)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-8-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-8",
   "subdomainName": "Cryptography",
   "objective": "To ensure the proper and efficient use of cryptography to protect electronic and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for cryptography shall include at least the requirements in the National Cryptographic Standards, published by NCA. The appropriate cryptographic standard level shall be implemented based on the nature and sensitivity and as per the relevant legislative and regulatory requirements, as follows:",
   "tools": [
    "Cryptography Standard Template."
   ],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and must be approved by the representative.",
    "Define standard controls of approved cryptographic solutions and use NCA's cryptographic standard controls, including, but not limited to:",
    "Acceptable symmetric and asymmetric cryptographic fundamentals.",
    "PKI Procedures.",
    "Key Cycle Management Procedure.",
    "Define standard controls and technical limitations of approved cryptographic solutions and ensure their compliance with national cryptography standard controls, including but not limited to:",
    "Acceptable symmetric and asymmetric cryptographic designs.",
    "Acceptable common application protocols related to cryptography.",
    "PKI technologies and tools.",
    "Key cycle management techniques and tools.",
    "Define and approve procedures for the secure management of cryptographic keys during their lifecycle.",
    "Define and implement appropriate and advanced techniques for the secure management of cryptographic keys during their lifecycle, including, but not limited to:",
    "Cryptographic key storage mechanism.",
    "Cryptographic key transfer mechanism."
   ],
   "deliverables": [
    "Cryptography standard controls document approved by the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such standard controls (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Evidence showing the implementation of the requirements of the approved technical cryptographic solutions standard controls and the restrictions applied to them ( e.g., a screenshot showing evidence of ensuring that modern and advanced technologies are used to implement the standard controls of approved technical cryptography solutions and the restrictions applied to all systems in the entity).",
    "Cybersecurity policy that covers all the requirements of cryptography in the entity (e.g., electronic copy or official hard copy).",
    "Cybersecurity procedure that covers all the requirements of cryptographic keys. management in the entity (e.g., electronic copy or official hard copy).",
    "Document that defines the technology effectiveness review cycle used for the secure management of cryptographic keys during their lifecycle.",
    "Formal approval by the head of the entity or his/her deputy on such documents (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Evidence that the secure management requirements for cryptographic keys are implemented throughout their lifecycle (e.g., a screenshot showing evidence to ensure that cryptographic key settings are configured to the best standard controls for the secure management of cryptographic keys during their lifecycle).",
    "Cryptography of data in transit document approved by the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such procedures (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Evidence that data in transit cryptography requirements must be implemented based on their classification (but not limited to a screenshot showing the implementation of data in transit encryption based on its classification)."
   ],
   "subcontrols": [
    {
     "ref": "2-8-3-1",
     "text": "Approved cryptographic systems and solutions standards and their technical and regulatory restrictions."
    },
    {
     "ref": "2-8-3-2",
     "text": "Secure management of cryptographic keys during their lifecycles."
    },
    {
     "ref": "2-8-3-3",
     "text": "Encryption of data in-transit and at -rest, as per their classification and the relevant legislative and regulatory requirements."
    }
   ]
  },
  {
   "ref": "2-8-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-8",
   "subdomainName": "Cryptography",
   "objective": "To ensure the proper and efficient use of cryptography to protect electronic and the relevant legislative and regulatory requirements.",
   "text": "The implementation of cybersecurity requirements for cryptography within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of cryptography by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity funct ion and in cooperation with relevant departments (such as IT Department).",
    "Review and update cybersecurity requirements for cryptography in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for cryptography in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of cryptography requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for cryptography in the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for cryptography in the entity.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for cryptography have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-9-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-9",
   "subdomainName": "Backup and Recovery Management",
   "objective": "policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for backup and recovery management within the entity shall be identified, documented, and approved.",
   "tools": [
    "Backup and Recovery Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for backup management in the entity, including the following:",
    "Scope and coverage of critical information and technology systems backups.",
    "Fast recovery of data and systems after exposure to cybersecurity incidents.",
    "Periodic inspection of backup recovery effectiveness.",
    "Time limit for backups.",
    "Appropriate and advanced technologies for backups must be defined",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of Backup and Recovery Management in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-9-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-9",
   "subdomainName": "Backup and Recovery Management",
   "objective": "policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for backup and recovery management within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "All cybersecurity requirements must be implemented for the entity's approved Backup and Recovery Management procedures. It is also recommended that the Backup and Recovery Management procedures cover the following, but not limited to:",
    "Appropriate and advanced technologies for backups must be used.",
    "Scope and coverage of critical information and technology systems backups.",
    "Fast recovery of data and systems after exposure to cybersecurity incidents must be implemented.",
    "Periodic inspection of backup recovery effectiveness must be implemented.",
    "Period required for backup must be defined, including but not limited to, backup of changing data in the last 24 hours."
   ],
   "deliverables": [
    "An action plan to implement cybersecurity requirements for backup and recovery management.",
    "Evidence such as, but not limited to, a screenshot of a backup tool showing the latest backups taken, schedule and scope of backups."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-9-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-9",
   "subdomainName": "Backup and Recovery Management",
   "objective": "policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for backup and recovery management shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements of backups management at the entity and must be approved by the representative.",
    "Define the scope of backups for all critical information and technology assets in the entity, including but not limited to:",
    "Databases",
    "Applications",
    "Servers",
    "Network Devices",
    "Define specialized technologies for backup.",
    "Determine the period required to backup all information and technology assets according to sensitivity and classification.",
    "Implement backup to all critical information and technology assets in the entity.",
    "Review the entity backups periodically, to include the aforementioned scope and any information and technology assets that have been identified by the entity.",
    "Identify appropriate procedures to recover data and systems after exposure to cybersecurity incidents, by but not limited to:",
    "Define the scope of backup recovery, which may contain all devices, systems, and servers, and classify them according to their importance and criticality.",
    "Determine the recovery period according to classification and importance of specified scope.",
    "Use specialized technologies for data and system recovery."
   ],
   "deliverables": [
    "Documents indicating the identification and documentation of the requirements of this ECC in the policies or procedures of the entity approved by the representative.",
    "A report of periodic backups as per the defined duration for all asset domains.",
    "Report on specific procedures for recovery of backups.",
    "Backup effectiveness test reports showing the difference between the expected duration and the test duration to recover all backups."
   ],
   "subcontrols": [
    {
     "ref": "2-9-3-1",
     "text": "Scope of backups to cover critical technology and information assets."
    },
    {
     "ref": "2-9-3-2",
     "text": "Ability to perform quick recovery of data and systems after cybersecurity incidents."
    },
    {
     "ref": "2-9-3-3",
     "text": "Periodic testing for the effectiveness of backup recovery."
    }
   ]
  },
  {
   "ref": "2-9-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-9",
   "subdomainName": "Backup and Recovery Management",
   "objective": "policies and procedures and the relevant legislative and regulatory requirements.",
   "text": "The implementation of cybersecurity requirements for backup and recovery management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of Backup and Recovery Management by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for Backup and Recovery Management.",
    "Review and update cybersecurity requirements for backups management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for Backup and Recovery Management in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of backup management requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements application review cycle for backup management at the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for Backup and Recovery Management in the entity.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for Backup and Recovery Management have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-10-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-10",
   "subdomainName": "Vulnerabilities Management",
   "objective": "To ensure timely detection and effective remediation of technical vulnerabilities to prevent or minimize the probability of exploitation of these vulnerabilities by cyber -",
   "text": "Cybersecurity requirements for technical vulnerabilities management within the entity shall be identified, documented, and approved.",
   "tools": [
    "Vulnerabilities Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for vulnerabilities management in the entity, including the following:",
    "Vulnerabilities assessment and testing requirements for all technology assets.",
    "Requirements for periodic vulnerability assessment.",
    "Requirements for the classification of vulnerabilities according to their severity.",
    "Requirements to address vulnerabilities using effective tools and methods.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of vulnerabilities management (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-10-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-10",
   "subdomainName": "Vulnerabilities Management",
   "objective": "To ensure timely detection and effective remediation of technical vulnerabilities to prevent or minimize the probability of exploitation of these vulnerabilities by cyber -",
   "text": "Cybersecurity requirements for technical vulnerabilities management within the entity shall be implemented.",
   "tools": [
    "Vulnerability Management Process Template.",
    "Vulnerability Management Log Template."
   ],
   "guidelines": [
    "Implement all cybersecurity requirements to the entity's approved vulnerabilities management. It is also recommended that the vulnerabilities management procedures cover the following, but not limited to:",
    "Periodic vulnerability assessment and detection procedures",
    "The mechanism for classifying vulnerabilities according to their severity.",
    "Procedures for addressing vulnerabilities based on their classification and associated cyber risks.",
    "Mechanism and procedure for escalation of technical vulnerabilities.",
    "Methods of linking vulnerabilities management procedures to the security patch management procedures."
   ],
   "deliverables": [
    "Vulnerability Management Procedure.",
    "Patch Management Procedures.",
    "Vulnerabilities detection and testing reports (pre - and post -treatment) indicating classification of vulnerabilities."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-10-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-10",
   "subdomainName": "Vulnerabilities Management",
   "objective": "To ensure timely detection and effective remediation of technical vulnerabilities to prevent or minimize the probability of exploitation of these vulnerabilities by cyber -",
   "text": "Cybersecurity requirements for technical vulnerabilities management shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Identify technologies and tools to assess and detect vulnerabilities of information and technology assets.",
    "Install and link vulnerabilities assessment and detection technologies and tools with the entity's information and technology assets.",
    "Develop periodic plan and procedures to inspect and detect vulnerabilities in the information and technology assets in the entity, including:",
    "Applications",
    "Devices and servers",
    "Databases",
    "Entity's Networks",
    "Prepare and review vulnerabilities assessment reports on the information and technology assets in the entity, including the classification of vulnerabilities based on the following:",
    "Description of vulnerabilities and their exploitative potential and the expected impact of the entity.",
    "Network segmentation.",
    "Classification of vulnerabilities by concerned assets.",
    "Classification of vulnerabilities based on Common Vulnerability Scoring System (CVSS).",
    "Share the entity's information and technology asset vulnerabilities assessment and detection reports with the relevant departments, including but not limited to:"
   ],
   "deliverables": [
    "Cybersecurity policy that covers the periodical assessment and detecting vulnerabilities (based on the plan and planned interval specified in the policy) of the following assets:",
    "Applications",
    "Devices and servers",
    "Databases",
    "Entity's Networks (e.g., electronic copy or official hard copy)",
    "Formal approval by the head of the entity or his/her deputy on such requirements (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Vulnerabilities management procedures and a periodic plan to assess and detect vulnerabilities.",
    "Periodic reports to assess and detect vulnerabilities.",
    "Cybersecurity policy that covers the vulnerabilities classification mechanism and methodology based on their criticality and cyber risks and based on the entity's network segmentation (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Vulnerabilities management procedures that illustrate the classification mechanism.",
    "Vulnerabilities detection and assessment reports indicating the classification of vulnerabilities."
   ],
   "subcontrols": [
    {
     "ref": "2-10-3-1",
     "text": "Periodic vulnerabilities assessment and detection."
    },
    {
     "ref": "2-10-3-2",
     "text": "Vulnerabilities classification based on their severities."
    },
    {
     "ref": "2-10-3-3",
     "text": "Vulnerabilities remediation based on their classification and the associated cyber risks."
    },
    {
     "ref": "2-10-3-4",
     "text": "Patch management to remediate vulnerabilities."
    },
    {
     "ref": "2-10-3-5",
     "text": "Communication and subscription with trusted resources for new and up - to-date vulnerabilities."
    }
   ]
  },
  {
   "ref": "2-10-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-10",
   "subdomainName": "Vulnerabilities Management",
   "objective": "To ensure timely detection and effective remediation of technical vulnerabilities to prevent or minimize the probability of exploitation of these vulnerabilities by cyber -",
   "text": "The implementation of cybersecurity requirements for technical vulnerabilities management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of Vulnerabilities Management by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity functio n and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for Vulnerabilities Management.",
    "Review and update cybersecurity requirements for vulnerabilities management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for Vulnerabilities Management in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of vulnerabilities management cybersecurity requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for vulnerabilities management in the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for the entity's Vulnerabilities Management.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-11-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-11",
   "subdomainName": "Penetration Testing",
   "objective": "To assess and test the efficiency of the through simulation of actual cyber -attack methods and technologies to discover unknown weaknesses that may lead to cyber penetration of the entity, as per the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for penetration testing within the entity shall be identified, documented, and approved.",
   "tools": [
    "Penetration Testing Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for penetration testing in the entity, including the following:",
    "Determine the scope of the penetration test in the entity.",
    "Define periodic penetration testing requirements.",
    "Define penetration testing requirements using effective tools and methods.",
    "Define the requirements for the team responsible for performing the penetration testing.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of penetration testing management (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-11-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-11",
   "subdomainName": "Penetration Testing",
   "objective": "To assess and test the efficiency of the through simulation of actual cyber -attack methods and technologies to discover unknown weaknesses that may lead to cyber penetration of the entity, as per the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for penetration testing within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements to the entity's approved penetration testing. It is also recommended that the penetration testing cover the following, but not limited to:",
    "Perform penetration testing periodically.",
    "Determine the scope of the penetration testing in the entity."
   ],
   "deliverables": [
    "Action plan for penetration testing",
    "Penetration Testing Reports"
   ],
   "subcontrols": []
  },
  {
   "ref": "2-11-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-11",
   "subdomainName": "Penetration Testing",
   "objective": "To assess and test the efficiency of the through simulation of actual cyber -attack methods and technologies to discover unknown weaknesses that may lead to cyber penetration of the entity, as per the relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for penetration testing shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Identify and document all services provided online at the entity.",
    "Identify all technical components that support these external services, including:",
    "Websites and web applications",
    "Smartphones and tablets applications",
    "This includes items on Apple Store, Google Play Store and other app stores.",
    "This also includes phone applications that are not available on stores, which are specific to the entity.",
    "API",
    "Servers used for external services (e.g., web servers)",
    "Servers used for remote access services",
    "Servers used by the email service",
    "Network devices used to provide external services",
    "Develop and implement an action plan for penetration testing, including the above.",
    "Develop procedures for penetration testing."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the penetration testing of the following assets: all services provided externally (online) and its technology components including infrastructure, websites, web applications, smartphone and tablet applications, email and remote access.",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Action plan for penetration testing.",
    "Penetration Testing Reports.",
    "Cybersecurity policy that covers penetration testing on a regular basis."
   ],
   "subcontrols": [
    {
     "ref": "2-11-3-1",
     "text": "Scope of penetration testing to include all externally provided services (via the Internet) and their technical components, including infrastructure, websites, web applications, smartphone and tablet applications, email, and remote access."
    },
    {
     "ref": "2-11-3-2",
     "text": "Conducting penetration tests periodically."
    }
   ]
  },
  {
   "ref": "2-11-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-11",
   "subdomainName": "Penetration Testing",
   "objective": "To assess and test the efficiency of the through simulation of actual cyber -attack methods and technologies to discover unknown weaknesses that may lead to cyber penetration of the entity, as per the relevant legislative and regulatory requirements.",
   "text": "The implementation of cybersecurity requirements for penetration testing shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of penetration testing by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval (\"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for penetration testing.",
    "Review and update cybersecurity requirements for penetration testing in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for penetration testing in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of penetration testing cybersecurity requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for penetration testing in the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for the entity's penetration testing.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-12-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-12",
   "subdomainName": "Cybersecurity Event Logs and Monitoring Management",
   "objective": "To ensure timely collection, analysis, and monitoring of cybersecurity event logs for proactive detection and effective management of cyber-attacks to prevent or minimize negative",
   "text": "Cybersecurity requirements for cybersecurity event logs and monitoring management within the entity shall be identified, documented, and approved.",
   "tools": [
    "Cybersecurity Event Logs and Monitoring Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for event logs and cybersecurity monitoring management in the entity, including the following:",
    "Define the scope of information assets to which event logs must be activated.",
    "Activate cybersecurity event logs on critical information assets in the entity.",
    "Activate cybersecurity event logs of privileged access accounts on critical information assets and events of remote access in the entity.",
    "Define technologies to collect activated cybersecurity event logs.",
    "Continuous monitor cybersecurity event logs.",
    "Define retention period for cybersecurity event logs (not less than 12 months).",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of Event Logs and Monitoring Management (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-12-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-12",
   "subdomainName": "Cybersecurity Event Logs and Monitoring Management",
   "objective": "To ensure timely collection, analysis, and monitoring of cybersecurity event logs for proactive detection and effective management of cyber-attacks to prevent or minimize negative",
   "text": "Cybersecurity requirements for cybersecurity event logs and monitoring management within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement cybersecurity requirements to Information System and Processing Facilities Protection, including, but not limited to, the following:",
    "Define the scope of information assets to which event logs are activated, and the entity's information and technology asset register and the assets mentioned in the risk register can be used to determine the scope.",
    "Activate cybersecurity event logs on critical information assets in the entity.",
    "Activate cybersecurity event logs of privileged access accounts on critical information assets and events of remote access in the entity.",
    "Define technologies to collect activated cybersecurity event logs.",
    "Define a team to continuously monitor cybersecurity event logs.",
    "Define the retention period for cybersecurity event logs (not less than 12 months) and identify this item in contracts and agreements if the Security Operations Center is at the service provider premises and ensure compliance with it."
   ],
   "deliverables": [
    "A visit to the entity's Security Operations Center (if any), where the SIEM is viewed directly.",
    "A copy of the contract or agreement if the Security Operations Center or the monitoring are provided by a service provider.",
    "A report showing the connection of all the entity's devices and systems to the SIEM system.",
    "Entity's shift breakdown table covering the approved monitoring model."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-12-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-12",
   "subdomainName": "Cybersecurity Event Logs and Monitoring Management",
   "objective": "To ensure timely collection, analysis, and monitoring of cybersecurity event logs for proactive detection and effective management of cyber-attacks to prevent or minimize negative",
   "text": "Cybersecurity requirements for cybersecurity event logs and monitoring management shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Activate cybersecurity event logs on critical information assets in the entity, which may include, but are not limited to, the following:",
    "Network Devices",
    "Applications",
    "Databases",
    "Servers",
    "Workstations (through the protection system).",
    "Activate these records through the configuration of the previously mentioned devices and systems that can be controlled through their control panel.",
    "Develop rules in SIEM system to enable the monitoring team to monitor the activated records of critical information assets (after linking them).",
    "Activate cybersecurity event logs of privileged access accounts ( e.g., database and systems management).",
    "Information assets, so that all changes made through them are recorded and archived.",
    "Remote access events, as these processes must only be for the necessary cases and any remote access must be recorded to follow up on the changes made.",
    "Develop a number of rules in the SIEM system so that the special team can monitor the activated logs of privileged access accounts (after linking them).",
    "Provide the necessary technologies (SIEM) to collect cybersecurity event logs."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "A screenshot or a direct example from the control panel of the mentioned systems that indicates the activation of event logs.",
    "Screenshot or a direct example showing the activation of logs through SIEM.",
    "Screenshot or a direct example showing the activation of logs for some privileged access accounts on the access management system.",
    "Screenshot or a direct example showing the activation of logs for some privileged access accounts on the remote access system.",
    "A visit to the entity's Security Operations Center (if any), where the SIEM is viewed directly.",
    "A report showing the connection of all the entity's devices and systems with the SIEM system (including but not limited to a list in Excel or electronic version) and highlighting the addition of any new devices or systems in the entity.",
    "A contract explaining the above if the Security Operations Center is by a service provider.",
    "Entity's shift breakdown table covering the approved monitoring model.",
    "A contract showing the monitoring model followed if the security operations center or the monitoring is provided by a service provider.",
    "A screenshot or direct directory from the SIEM system showing record - keeping configuration for at least 12 months.",
    "A sample of stored logs extracted from the SIEM system where records have been kept for at least 12 months."
   ],
   "subcontrols": [
    {
     "ref": "2-12-3-1",
     "text": "Activation of cybersecurity event logs for critical information assets within the entity."
    },
    {
     "ref": "2-12-3-2",
     "text": "Activation of cybersecurity event logs for critical and privileged accounts accessing information assets as well as for remote access events within the entity."
    },
    {
     "ref": "2-12-3-3",
     "text": "Identification of Security Information and Event Management (SIEM) techniques required for cybersecurity event logs collection."
    },
    {
     "ref": "2-12-3-4",
     "text": "Continuous monitoring of cybersecurity event logs."
    },
    {
     "ref": "2-12-3-5",
     "text": "Retention period of cybersecurity event logs (shall be at least 12 months)."
    }
   ]
  },
  {
   "ref": "2-12-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-12",
   "subdomainName": "Cybersecurity Event Logs and Monitoring Management",
   "objective": "To ensure timely collection, analysis, and monitoring of cybersecurity event logs for proactive detection and effective management of cyber-attacks to prevent or minimize negative",
   "text": "The implementation of cybersecurity requirements for cybersecurity event logs and monitoring management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of Cybersecurity Event Logs and Monitoring Management by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement cybersecurity Event Logs and Monitoring Management requirements by the Cybersecurity function and in cooperation with relevant departments (such as sec",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for Cybersecurity Event Logs and Monitoring Management.",
    "Review and update cybersecurity requirements for Cybersecurity Event Logs and Monitoring Management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for Cybersecurity Event Logs and Monitoring Management in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of Cybersecurity Event Logs and Monitoring Management requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for Cybersecurity Event Logs and Monitoring Management within the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for Cybersecurity Event Logs and Monitoring Management.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-13-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-13",
   "subdomainName": "Cybersecurity Incident and Threat Management",
   "objective": "To ensure timely identification, detection, and effective management of cybersecurity incidents and proactive response to cybersecurity threats to prevent or minimize business, as per High Order No. 37140, dated 14/08/1438H.",
   "text": "Requirements for cybersecurity incident and threat management within the entity shall be identified, documented, and approved.",
   "tools": [
    "Cybersecurity Incident and Threat Management Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for Cybersecurity Incident and Threat management in the entity, including the following:",
    "Define a cybersecurity incident response plan.",
    "Classify cybersecurity incidents by severity.",
    "Define the roles and responsibilities for cybersecurity incident response and how to communicate with all stakeholders.",
    "Define a mechanism for notifying the National Cybersecurity Authority in the event of a cybersecurity incident.",
    "Share incidents notifications, threat intelligence, intrusion indicators and reports with NCA.",
    "Collect and handle threat intelligence feeds.",
    "Periodically review of cybersecurity incident response plan.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of Cybersecurity Incident and Threat management requirements in the entity (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-13-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-13",
   "subdomainName": "Cybersecurity Incident and Threat Management",
   "objective": "To ensure timely identification, detection, and effective management of cybersecurity incidents and proactive response to cybersecurity threats to prevent or minimize business, as per High Order No. 37140, dated 14/08/1438H.",
   "text": "Requirements for cybersecurity incident and threat management within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement cybersecurity requirements to Cybersecurity Incident and Threat management, including, but not limited to, the following:",
    "Define a cybersecurity incident response plan.",
    "Classify cybersecurity incidents by severity.",
    "Define the roles and responsibilities for cybersecurity incident response and how to communicate with all stakeholders.",
    "Define a mechanism for notifying the National Cybersecurity Authority in the event of a cybersecurity incident.",
    "Share incidents notifications, threat intelligence, intrusion indicators and reports with NCA.",
    "Collect and handle threat intelligence feeds.",
    "Periodically review of cybersecurity incident response plan."
   ],
   "deliverables": [
    "The approved cybersecurity incident response plan (electronic copy).",
    "A sample of a previous cybersecurity incident report.",
    "Cybersecurity incidents classification mechanism based on severity."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-13-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-13",
   "subdomainName": "Cybersecurity Incident and Threat Management",
   "objective": "To ensure timely identification, detection, and effective management of cybersecurity incidents and proactive response to cybersecurity threats to prevent or minimize business, as per High Order No. 37140, dated 14/08/1438H.",
   "text": "Requirements for cybersecurity incident and threat management shall include the following as a minimum:",
   "tools": [
    "Event Management Plan Template.",
    "Event Management Procedure Template."
   ],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Develop cybersecurity incident response plans containing:",
    "Define the types of accidents and their classification according to their level of severity on the entity's business.",
    "Define the roles and responsibilities for cybersecurity incident response and how to communicate with all stakeholders.",
    "Define communication channels and methods for emergencies.",
    "Define a playbook for incident response that contains the following: - Classify the incident by its severity, the level of response required, and entities that should be involved in response activities. - Report cybersecurity threats and incidents to the NCA. - Define workflow procedures for responding to cybersecurity incidents according to .",
    "Develop cybersecurity incident report upon completion of the response including, but not limited to, the following:",
    "Persons involved in responding to the incident and the means of communication.",
    "The key information of the incident, including but not limited to, date and time, scope of incident, severity, etc.",
    "Summary of the incident.",
    "Containment and removal steps.",
    "Current and future recommendations.",
    "Review the response plan periodically and update it if necessary.",
    "Define the entity's cybersecurity incident classification mechanism and ensure its inclusion in the incident response policy and its alignment with the entity's risk classification mechanism."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "The approved cybersecurity incident response plan (electronic copy).",
    "A sample of a previous cybersecurity incident report.",
    "Document that outlines the mechanism for classifying cybersecurity incidents according to sensitivity and risk level.",
    "Sample from a previous incident report showing incident and reporting classification",
    "Copy of the file of the procedures followed to report to NCA cybersecurity incidents.",
    "Sample of NCA's notification of a previous cybersecurity incident, including but not limited to: a screenshot or direct example of the email sent to NCA.",
    "Procedures followed to share alerts, threat intelligence, and penetration indicators with NCA (including but not limited to: a previous email through which the indicators report was sent to NCA).",
    "Sample of a cybersecurity incident report sent to NCA (including but not limited to a previous email through which a cybersecurity incident report was sent to NCA).",
    "Screenshot or direct example showing the entity's subscription in a platform.",
    "Screenshot or direct example of alerts that have been dealt with in advance according to the necessary procedures."
   ],
   "subcontrols": [
    {
     "ref": "2-13-3-1",
     "text": "Cybersecurity incident response plans and escalation procedures."
    },
    {
     "ref": "2-13-3-2",
     "text": "Cybersecurity incidents classification."
    },
    {
     "ref": "2-13-3-3",
     "text": "Reporting cybersecurity incidents to the NCA."
    },
    {
     "ref": "2-13-3-4",
     "text": "Sharing cybersecurity incident notifications, threat intelligence, penetration indicators, and incident reports with the NCA."
    },
    {
     "ref": "2-13-3-5",
     "text": "Collecting and handling threat intelligence feeds."
    }
   ]
  },
  {
   "ref": "2-13-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-13",
   "subdomainName": "Cybersecurity Incident and Threat Management",
   "objective": "To ensure timely identification, detection, and effective management of cybersecurity incidents and proactive response to cybersecurity threats to prevent or minimize business, as per High Order No. 37140, dated 14/08/1438H.",
   "text": "The implementation of cybersecurity requirements for incident and threat management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of cybersecurity incident and threat management by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval \"e.g., quarterly\") to implement cybersecurity incident and threat management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for cybersecurity incident and threat management.",
    "Review and update cybersecurity requirements for cybersecurity incident and threat management in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for cybersecurity incident and threat management in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of Cybersecurity Incident and Threat management requirements implementation review in the entity.",
    "A document that defines the cybersecurity requirements implementation review cycle for cybersecurity incident and threat management within the entity (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for cybersecurity incident and threat management."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-14-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-14",
   "subdomainName": "Physical Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information and technology assets of the entity against unauthorized physical access, loss, theft, and damage shall be identified, documented, and approved.",
   "tools": [
    "Physical Security Policy Template."
   ],
   "guidelines": [
    "Include and document cybersecurity requirements for information and technology assets protection against unauthorized physical access and cyber risks, including, but not limited to:",
    "Authorized access to critical areas within the entity.",
    "CCTV.",
    "Protection of facility entry/exit and surveillance records.",
    "Secure destruction and re -use of physical assets that hold classified information.",
    "Security of devices and equipment inside and outside the entity facilities.",
    "Cybersecurity requirements for the protection of information and technology assets in the entity against unauthorized physical access must be supported by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "A cybersecurity policy that covers the information and technology asset protection requirements against unauthorized physical access and cyber risks (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-14-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-14",
   "subdomainName": "Physical Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information and technology assets of the entity against unauthorized physical access, loss, theft, and damage shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements for information and technology assets protection against unauthorized physical access, loss, theft, and vandalism. The procedures must cover at least the following, but not limited to:",
    "Authorized access to critical areas within the entity.",
    "CCTV.",
    "Protection of facility entry/exit and surveillance records.",
    "Secure destruction and re -use of physical assets that hold classified information.",
    "Security of devices and equipment inside and outside the entity facilities.",
    "Develop an action plan to implement all cybersecurity requirements for the protection of information and technology assets against unauthorized physical access, loss, theft and vandalism.",
    "Include cybersecurity requirements for the protection of information and technology assets against unauthorized physical access, loss, theft, and vandalism in the protection procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders."
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to the protection of information and technology assets against unauthorized physical access, loss, theft, and vandalism as documented in the policy.",
    "An action plan to implement cybersecurity requirements for information and technology assets protection against unauthorized physical access, loss, theft, and vandalism.",
    "Evidence that clarifies the implementation of information and technology asset protection controls against unauthorized physical access, loss, theft and vandalism, including, but not limited to:",
    "An approved user access request form.",
    "Schedule of a visit to CCTV log room to assess the monitoring process and the devices used.",
    "Schedule of a visit to the secure storage room containing archived records.",
    "Sample of the digital media destruction implementation (e.g., email).",
    "Documented and approved procedures for the security of devices and equipment inside and outside the entity representative."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-14-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-14",
   "subdomainName": "Physical Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information and technology assets of the entity against unauthorized physical access, loss, theft, and damage shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Identify the scope of the entity's critical areas, including (but not limited to):",
    "Data centers.",
    "Disaster Recovery Center.",
    "Sensitive information processing facilities.",
    "Security Control Center.",
    "Network communication rooms.",
    "Supply areas for hardware and technology hardware.",
    "Develop access request form for critical areas, including (but not limited to):",
    "Name of the concerned person.",
    "Reason for requesting access.",
    "Access duration.",
    "Develop approval procedures for the access request by administrators.",
    "Identify access mechanism to critical areas (e.g., card access, fingerprint access, face access, etc.)."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "An approved user access request form.",
    "Schedule of visit to a critical area (data center but not limited to) to assess access.",
    "Evidence of revoking access authorities after the expiry of the period documented on the approved application form (e.g., by email).",
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Schedule of a visit to CCTV log room to assess the monitoring process and the devices used.",
    "Schedule of visit to the entity's buildings that contain surveillance cameras to assess their effectiveness, locations and monitoring.",
    "Schedule of a visit to the CCTV logroom to ensure that access and monitoring logs are protected in a separate location and secure access.",
    "Schedule of a visit to the secure storage room containing archived records.",
    "Sample of the paper document destruction implementation ( e.g., an email addressed to stakeholders confirming the destruction of the sample).",
    "Sample of the digital media destruction implementation (e.g., email).",
    "Procedures for reusing physical assets containing classified information documented and approved by the representative."
   ],
   "subcontrols": [
    {
     "ref": "2-14-3-1",
     "text": "center, disaster recovery center, critical information processing facilities, security surveillance center, network connection rooms, technical device and equipment supply areas, etc.)."
    },
    {
     "ref": "2-14-3-2",
     "text": "Access and monitoring logs (CCTV)."
    },
    {
     "ref": "2-14-3-3",
     "text": "Protection of access and monitoring log information."
    },
    {
     "ref": "2-14-3-4",
     "text": "Security of the destruction and re-use of physical assets that hold classified information (including paper documents and storage media)."
    },
    {
     "ref": "2-14-3-5",
     "text": ""
    }
   ]
  },
  {
   "ref": "2-14-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-14",
   "subdomainName": "Physical Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of information and technology assets of the entity against unauthorized physical access, loss, theft, and damage shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the implementation of cybersecurity requirements for the entity's information and technology assets protection against unauthorized physical access, loss, theft, and vandalism by conducting a periodic assessment (as per a documented and approved audit plan, and based on a planned interval (\"e.g., quarterly\") to protect the entity information and technology assets against unauthorized physic",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for the entity's information and technology assets protection against unauthorized physical access, loss, theft, and vandalism.",
    "Review and update cybersecurity requirements for information and technology assets protection against unauthorized physical access, loss, theft, and vandalism in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for the information and technology assets protection against unauthorized physical access, loss, theft, and vandalism in the entity and approve them by the head of the entity or his/ her deputy."
   ],
   "deliverables": [
    "Results of information and technology assets protection against unauthorized physical access, loss, theft, and vandalism requirements implementation review in the entity.",
    "a document that defines the cybersecurity requirements implementation review cycle for information and technology assets protection against unauthorized physical access, loss, theft, and vandalism requirements implementation review in the entity (Compliance Assessment Schedule).",
    "A compliance assessment report that shows the assessment of the implementation of cybersecurity requirements for information and technology assets protection against unauthorized physical access, loss, theft, and vandalism.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-15-1",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-15",
   "subdomainName": "Web Application Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of external web applications of the entity shall be identified, documented, and approved.",
   "tools": [
    "Web Application Protection Policy Template."
   ],
   "guidelines": [
    "Include and document cybersecurity requirements for the entity's external web applications security against cyber risks, including, but not limited to:",
    "Web Application Firewall.",
    "Multi-tier Architecture.",
    "Use secure protocols such as HTTPS.",
    "Use of applications development and update standards and testing them.",
    "Clarify secure user usage policy.",
    "Multi-Factor Authentication of users' access.",
    "Screening for application -specific vulnerabilities (Vulnerability Assessment).",
    "Regular backups in secure locations (Backup Log Files).",
    "Regular screening of open ports, services, processes, and unused protocols.",
    "Cybersecurity requirements for the security of external web applications must be supported by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "A cybersecurity policy that covers the requirements for the entity's external web applications security against cyber risks (electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-15-2",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-15",
   "subdomainName": "Web Application Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of external web applications of the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement all cybersecurity requirements to External web applications security procedures in the entity. The External web applications security procedures must cover at least the following, but not limited to:",
    "Web Application Firewall.",
    "Multi-tier Architecture.",
    "Use secure protocols such as HTTPS.",
    "Clarify secure user usage policy.",
    "Multi-Factor Authentication of users' access.",
    "Develop an action plan to implement all cybersecurity requirements related to external web applications security.",
    "Include cybersecurity requirements for external web applications security in the entity's external web applications security procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders."
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to the protection of external web applications as documented in the policy.",
    "An action plan document to implement the cybersecurity requirements for external web applications security.",
    "Evidence showing the implementation of external web applications security controls, including but not limited to:",
    "Screenshot of web application firewall used by the entity.",
    "Sample of web application designs that demonstrate the use of a multi -tier architecture principle for the entity's web application.",
    "Screenshot from a web application showing the use of HTTPS in its link.",
    "Screenshot from the entity's website indicating the publication of the secure usage policy for users.",
    "Multiple screenshots showing entry process including MFA."
   ],
   "subcontrols": []
  },
  {
   "ref": "2-15-3",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-15",
   "subdomainName": "Web Application Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of external web applications of the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Web applications must be identified, including:",
    "Purchased external applications.",
    "Internally developed applications.",
    "If there are web applications purchased and operated by a third party, the following must be done:",
    "Ensure the supplier's compliance with cybersecurity policies and standard controls including the use of a web application firewall system.",
    "If there are internally developed applications or external applications purchased from a third -party that are operated by the entity, the following must be done:",
    "Identify the firewall technologies that the entity wishes to acquire, including but not limited to:",
    "Firewall with pre-managed rules managed by the system itself.",
    "A firewall with the option to customize the rules by the entity.",
    "Identify and assign several application firewall systems that include the technologies supplied by the entity, while defining the positive and negative aspects of each system separately.",
    "Identify and assign a specific firewall system to be used for the entity's external web applications.",
    "Implement and install the firewall system for all web applications operated by the entity.",
    "Include an application and install the firewall in the application development lifecycle to ensure the protection of future applications."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control.",
    "Documents indicating the identification and documentation of the requirements of this ECC in the policies or procedures of the entity approved by the representative (e.g., electronic copy or official hard copy).",
    "Screenshot of web application firewall used by the entity.",
    "A document approved policy indicating the identification and documentation of the requirements related to this control.",
    "A document approved procedure indicating the identification and documentation of the requirements related to this control.",
    "Sample of web application designs that demonstrate the use of a multi -tier architecture principle for the entity's web application.",
    "Sample of web application designs that demonstrate the use of a multi -tier architecture principle for the entity's web application purchased from a third party.",
    "Screenshot from a web application showing the use of HTTPS in its link.",
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Secure Use of Web Application Users Policy.",
    "Screenshot from the entity's website indicating the publication of the secure usage policy for users.",
    "Multiple screenshots showing entry process including the authentication as per the specified number and elements in the cybersecurity requirements document."
   ],
   "subcontrols": [
    {
     "ref": "2-15-3-1",
     "text": "Use of web application firewall."
    },
    {
     "ref": "2-15-3-2",
     "text": "Adoption of the multi-tier architecture principle."
    },
    {
     "ref": "2-15-3-3",
     "text": "Use of secure protocols (e.g., HTTPS)."
    },
    {
     "ref": "2-15-3-4",
     "text": "Clarification of the secure usage policy for users."
    },
    {
     "ref": "2-15-3-5",
     "text": "User authentication, and the suitable authentication factors and their numbers as well as the authentication techniques shall be defined based on the result of impact assessment of authentication failure and bypass for"
    }
   ]
  },
  {
   "ref": "2-15-4",
   "domain": "2",
   "domainName": "Cybersecurity Defense",
   "subdomain": "2-15",
   "subdomainName": "Web Application Security",
   "objective": "",
   "text": "Cybersecurity requirements for protection of web applications of the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review the cybersecurity requirements of external web applications security by conducting a periodic assessment (according to a documented and approved plan for review, and based on a planned interval (\"e.g., quarterly\") to implement identity and access management requirements by the Cybersecurity function and in cooperation with relevant departments (such as IT Department).",
    "Conduct application review through traditional channels ( e.g., email) or automated channels using a compliance management system. The entity may develop a review plan explaining the implementation review schedule for external web applications protection.",
    "Review and update cybersecurity requirements for external web applications security in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for external web applications security in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "Results of external web applications protection requirements implementation review in the entity.",
    "a document that defines the cybersecurity requirements application review cycle for the entity's external web applications (Compliance Assessment Schedule).",
    "Compliance assessment report that outlines the assessment of the implementation of cybersecurity requirements for external web applications security.",
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "3-1-1",
   "domain": "3",
   "domainName": "Cybersecurity Resilience",
   "subdomain": "3-1",
   "subdomainName": "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)",
   "objective": "business continuity management and remediate and minimize the impacts of -services and information processing systems and facilities caused by cyber risks.",
   "text": "Cybersecurity requirements for business continuity management within the entity shall be identified, documented, and approved.",
   "tools": [
    "Cybersecurity Business Continuity Policy Template."
   ],
   "guidelines": [
    "Include and document cybersecurity requirements within the entity's business continuity management, including but not limited to:",
    "Ensure the continuity of cybersecurity -related systems and procedures.",
    "Develop cybersecurity incident response plans that may affect the business continuity of the entity.",
    "Develop Disaster Recovery Plan.",
    "Cybersecurity requirements within business continuity management must be supported by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of business continuity management (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on such document (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "3-1-2",
   "domain": "3",
   "domainName": "Cybersecurity Resilience",
   "subdomain": "3-1",
   "subdomainName": "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)",
   "objective": "business continuity management and remediate and minimize the impacts of -services and information processing systems and facilities caused by cyber risks.",
   "text": "Cybersecurity requirements for business continuity management within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement cybersecurity requirements within business continuity management that have been identified, documented, and approved in the policy.",
    "Develop an action plan to implement all cybersecurity requirements to ensure BCM in the entity.",
    "Include cybersecurity requirements for BCM in the entity's BCM procedures to ensure compliance with cybersecurity requirements for all internal and external stakeholders."
   ],
   "deliverables": [
    "Documents that confirm the implementation of cybersecurity requirements related to BCM as documented in the policy.",
    "An action plan to implement cybersecurity requirements for BCM in the entity.",
    "Evidence showing the implementation of BCM controls at the entity, including but not limited to:",
    "Documented and approved business continuity plans for the entity.",
    "Approved plans to respond to cybersecurity incidents that may affect the business continuity of the entity.",
    "Reports on the implementation of disaster recovery plans tests at the entity."
   ],
   "subcontrols": []
  },
  {
   "ref": "3-1-3",
   "domain": "3",
   "domainName": "Cybersecurity Resilience",
   "subdomain": "3-1",
   "subdomainName": "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)",
   "objective": "business continuity management and remediate and minimize the impacts of -services and information processing systems and facilities caused by cyber risks.",
   "text": "Cybersecurity requirements for business continuity management within the entity shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this ECC in the cybersecurity requirements document and approve them by the representative.",
    "Laws and regulations related to business continuity in the entity must be defined.",
    "Include high -risk cybersecurity incidents as a rationale for activating the entity's business continuity plan.",
    "Develop Business Continuity Management Program in the entity.",
    "Document and approve business continuity plans, including but not limited to:",
    "Procedures for assessing risks that may affect the entity's business continuity.",
    "Business Impact Analysis.",
    "Definition of the cybersecurity systems, procedures and assets and their importance to the entity.",
    "Cybersecurity-related systems continuity procedures, including technical requirements such as high availability, and regulatory requirements, such as the presence of a deputy that replaces the operators of cybersecurity systems when needed.",
    "Definition of cybersecurity services and their importance to the entity and develop a plan to ensure the continuity of these services.",
    "Review the entity's business continuity plans periodically and update them if necessary.",
    "Develop the plans for cybersecurity incident response that may affect the entity's business continuity, including (but not limited to):",
    "An explanation of the types of accidents and their classification according to their impact on the entity's business continuity.",
    "Roles and responsibilities for responding to cybersecurity incidents affecting the entity's business continuity."
   ],
   "deliverables": [
    "A document (such as approved policy or procedure) indicating the identification and documentation of the requirements related to this control",
    "Documented and approved business continuity management program for the entity.",
    "Documented and approved business continuity plans for the entity.",
    "Formal approval by the head of the entity or his/her deputy on such documents (e.g., via the entity's official e-mail, paper or electronic signature).",
    "Reports on the implementation of the entity's business continuity plans tests.",
    "Report showing the sharing of the periodic meetings for sharing cybersecurity business continuity plans with the enterprise business continuity and involvement of stakeholders.",
    "Approved plans to respond to cybersecurity incidents that may affect the business continuity of the entity.",
    "Entity -approved disaster recovery plans.",
    "Reports on the implementation of disaster recovery plans tests at the entity."
   ],
   "subcontrols": [
    {
     "ref": "3-1-3-1",
     "text": "Ensuring the continuity of cybersecurity systems and procedures."
    },
    {
     "ref": "3-1-3-2",
     "text": "Developing plans for response to cybersecurity incidents that may affect"
    },
    {
     "ref": "3-1-3-3",
     "text": "Developing disaster recovery plans."
    }
   ]
  },
  {
   "ref": "3-1-4",
   "domain": "3",
   "domainName": "Cybersecurity Resilience",
   "subdomain": "3-1",
   "subdomainName": "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)",
   "objective": "business continuity management and remediate and minimize the impacts of -services and information processing systems and facilities caused by cyber risks.",
   "text": "Cybersecurity requirements for business continuity management within the entity shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review and update cybersecurity requirements for business continuity in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for business continuity management in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for business continuity have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "4-1-1",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-1",
   "subdomainName": "Third-Party Cybersecurity",
   "objective": "-party cybersecurity risks (including Information Technology (IT) outsourcing, cybersecurity outsourcing, and relevant legislative and regulatory requirements.",
   "text": "shall be identified, documented, and approved.",
   "tools": [
    "Third-party Cybersecurity Policy Template."
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for Third -Party Cybersecurity in the entity, including the following:",
    "Cybersecurity requirements within contracts and agreements with third parties.",
    "Third-party risk assessment procedures.",
    "Data and Information Protection.",
    "Cybersecurity Incident Management.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of contracts and agreements with third- parties (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "4-1-2",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-1",
   "subdomainName": "Third-Party Cybersecurity",
   "objective": "-party cybersecurity risks (including Information Technology (IT) outsourcing, cybersecurity outsourcing, and relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for contracts and agreements with third parties, e.g. Service Level Agreement (SLA), which, if impaired, may affect the entity's data or services shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this control in the cybersecurity requirements and approve them by the representative, provided that the cybersecurity requirements include non -disclosure requirements and secure removal by the third party of the entity's data upon service termination.",
    "Include in the entity's contracts with third clauses stating the third party's commitment to maintain the confidentiality of the information.",
    "Include in the entity's contracts with third parties clauses stating that the third party must be obligated to safely remove the entity's data upon the expiry of the contract/service period.",
    "Define and document the requirements of this control in the cybersecurity requirements document and approve them by the representative, provided that they include the requirements of the communication procedures in the event of a cybersecurity incident.",
    "Include in the entity's contracts with third parties clauses stating the third party's obligation to define the communication procedures in the event of a cybersecurity incident.",
    "Ensure that third parties develop communication procedures with the entity, including communication means and data in the event of a cybersecurity incident that may affect the entity's data or service provided by the third party. These requirements include:",
    "Communication data (e.g., e-mail).",
    "The mechanism for reporting the cybersecurity incident (and its classification) to the entity.",
    "Escalation mechanisms.",
    "Define and document the requirements of this control in the cybersecurity requirements document and approve them by the representative, provided that they include the requirements of third parties' obligation to apply the entity's cybersecurity requirements and policies and the relevant laws and regulations.",
    "Include in the entity's contracts with third parties clauses stating that the third party must be obligated to implement the entity's cybersecurity requirements and policies and the relevant laws and regulations."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of contracts and agreements with third- parties (e.g., electronic copy or official hard copy).",
    "Signed sample of a contract or agreement with third parties indicating the inclusion of confidentiality clauses and secure removal of data (hard copy or electronic copy).",
    "Procedures adopted with third parties to communicate in the event of a cybersecurity incident through which the entity's data or service may be affected.",
    "Signed sample of a contract or agreement with third parties indicating the obligation of third parties to apply the entity policies and the relevant laws and regulations."
   ],
   "subcontrols": [
    {
     "ref": "4-1-2-1",
     "text": "Clauses of non- third party upon the end of service."
    },
    {
     "ref": "4-1-2-2",
     "text": "Communication procedures in case of the occurrence of a cybersecurity incident."
    },
    {
     "ref": "4-1-2-3",
     "text": "and policies and the relevant legislative and regulatory requirements."
    }
   ]
  },
  {
   "ref": "4-1-3",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-1",
   "subdomainName": "Third-Party Cybersecurity",
   "objective": "-party cybersecurity risks (including Information Technology (IT) outsourcing, cybersecurity outsourcing, and relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for contracts and agreements with third parties providing IT or cybersecurity outsourcing or managed services shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Define and document the requirements of this control in the cybersecurity requirements document and approve them by the representative, provided that they include the requirements of conducting a cybersecurity risk assessment, and ensuring that there is a guarantee to control those risks before signing contracts and agreements or in the event of changes in the relevant laws and regulations.",
    "Conduct a third -party cybersecurity risk assessment by the entity in the following cases:",
    "Before the entity signs any contracts or agreements with third parties.",
    "In the event of changes in relevant laws and regulations.",
    "Define and document the requirements of this control in the cybersecurity requirements document and approve them by the representative, provided that they include the requirements for the managed operation and monitoring cybersecurity operations centers, which use remote access method, to be located within the Kingdom.",
    "Ensure that Cybersecurity operation centers managed for operation and monitoring are located within the Kingdom.",
    "Ensure that remote access to Cybersecurity operation centers managed for operation and monitoring is performed within the Kingdom.",
    "Include a clause in the contract or service level agreement signed with the third party that obliges the third party to have operations centers for operating and monitoring cybersecurity services, which use remote access within the Kingdom."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of contracts and agreements with third- parties (e.g., electronic copy or official hard copy).",
    "Sample of the third -party cyber risk assessment report before signing the contract or in the event of changes in relevant laws and regulations.",
    "A sample of the evidence of hosting or managing the cybersecurity operations center within the Kingdom (e.g., as an item of the signed contract or having a Service Level Agreement (SLA) signed between the third party and the entity)."
   ],
   "subcontrols": [
    {
     "ref": "4-1-3-1",
     "text": "Conducting a cybersecurity risk assessment and ensuring the availability of risk mitigation controls before signing contracts and agreements or upon making changes to the relevant legislative and regulatory requirements."
    },
    {
     "ref": "4-1-3-2",
     "text": "Cybersecurity managed service centers for monitoring and operations which use remote access shall be fully located in the Kingdom of Saudi Arabia."
    }
   ]
  },
  {
   "ref": "4-1-4",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-1",
   "subdomainName": "Third-Party Cybersecurity",
   "objective": "-party cybersecurity risks (including Information Technology (IT) outsourcing, cybersecurity outsourcing, and relevant legislative and regulatory requirements.",
   "text": "Cybersecurity requirements for third parties shall be periodically reviewed.",
   "tools": [],
   "guidelines": [
    "Review and update cybersecurity requirements for third party cybersecurity in the entity periodically according to a documented and approved plan for review and based on a planned interval or in the event of changes in relevant laws and regulations.",
    "Document the review and changes to the cybersecurity requirements for third party cybersecurity in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it has been reviewed and updated, and that changes have been documented and approved by the head of the entity or his/her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "4-2-1",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-2",
   "subdomainName": "Cloud Computing and Hosting Cybersecurity",
   "objective": "",
   "text": "Cybersecurity requirements for use of cloud computing and hosting services shall be identified, documented, and approved.",
   "tools": [
    "Cloud Computing and Hosting Cybersecurity Policy Template"
   ],
   "guidelines": [
    "Develop and document cybersecurity policy for cloud computing and hosting services in the entity, including the following:",
    "Cloud computing and hosting services providers contract requirements.",
    "Requirements for the location of hosting and storing the entity's systems and data.",
    "Requirements for data removal and retrieval.",
    "Classification of data prior to hosting/ storing on cloud computing or hosting services.",
    "inclusion of Service Level Agreement \"SLA\".",
    "Inclusion of Non-disclosure Clauses.",
    "Support the entity's policy by the Executive Management. This must be done through the approval of the entity head or his/ her deputy."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of the use of cloud computing and hosting services (e.g., electronic copy or official hard copy).",
    "Formal approval by the head of the entity or his/her deputy on the policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  },
  {
   "ref": "4-2-2",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-2",
   "subdomainName": "Cloud Computing and Hosting Cybersecurity",
   "objective": "",
   "text": "Cybersecurity requirements for the cloud computing and hosting services within the entity shall be implemented.",
   "tools": [],
   "guidelines": [
    "Implement cybersecurity requirements for cloud computing and hosting services for the entity, including, but not limited to:",
    "Ensure that the location of hosting and storing the entity's information is within the Kingdom.",
    "Ensure the activation of event logs on hosted information assets.",
    "Ensure that cloud computing and hosting service providers must return data (in a usable format) and remove it in a non -recoverable manner upon termination/expiry of the service.",
    "Ensure that the entity's environment (including virtual servers, networks and databases) is separated from other entities' environments in cloud computing services.",
    "Ensure that data and information transmitted to, stored in, or transmitted from cloud services are encrypted in accordance with the relevant laws and regulations of the entity.",
    "Ensure that the cloud computing and hosting service provider must periodically backup and protect backups in accordance with the entity's backup policy.",
    "The entity may also develop an action plan to implement cybersecurity requirements related to cloud computing and hosting service, in order to ensure that the entity complies with all cybersecurity requirements for all internal and external stakeholders and follow up and monitor them periodically to ensure implementation.",
    "Ensure continuous compliance with cloud computing cybersecurity controls for (CCC)."
   ],
   "deliverables": [
    "An action plan to implement the cybersecurity requirements for cloud computing and hosting services.",
    "A signed sample of the agreement or contract between the entity and the cloud service provider.",
    "Evidence by the cloud computing service provider of the implementation of the cybersecurity requirements of cloud computing and hosting services."
   ],
   "subcontrols": []
  },
  {
   "ref": "4-2-3",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-2",
   "subdomainName": "Cloud Computing and Hosting Cybersecurity",
   "objective": "",
   "text": "In In accordance with the relevant legislative and regulatory requirements, and in addition to the applicable controls in the Main Domains (1), (2), and (3) and thereto, cybersecurity requirements for use of cloud computing and hosting services shall include the following as a minimum:",
   "tools": [],
   "guidelines": [
    "Ensure the p accordance with its classification level , ensuring that such data is handled according to that classification and that such data is returned by the service provider upon the expiry of the contract/service with the entity through the following steps:",
    "Identify all data to be sent to the cloud computing service provider.",
    "Classify and label the identified data in line with the data classification and labelling mechanism in the entity and the related laws and regulations.",
    "Share this data with the cloud service provider for cloud hosting , and protecting it in accordance with its classification level.",
    "Develop procedures to ensure data is returned by the cloud computing service provider (in a usable format) after the contract/service ends.",
    "Define the entity's environment separation requirements (especially virtual servers) from other entities' environments in cloud computing services.",
    "Include in the entity's contracts with cloud computing and hosting providers clauses stating that the entity's environment must be separated from other entities' environments in the cloud computing services.",
    "Ensure that the documented and approved policy includes the requirements for the location of hosting and storing the entity's information and must be within the Kingdom.",
    "Ensure that the location of hosting and storing the entity's information is within the Kingdom by, but not limited to:",
    "Include a clause in the contract or service level agreement signed with the service provider that data storage must be within the Kingdom.",
    "Include a clause regarding the service provider's compliance with the controls of NCA related to cloud computing and hosting services, taking into account the classification of hosted data."
   ],
   "deliverables": [
    "Cybersecurity policy that covers the requirements of the use of cloud computing and hosting services (e.g., electronic copy or official hard copy).",
    "Sample of the data list that was classified before hosting it with cloud computing service providers, including but not limited to (a file) showing the data that were classified, prior to sharing with the cloud service provider.",
    "A signed sample of the agreement or contract between the entity and the cloud service provider; showing the service providers in accordance with its classification level.",
    "Approved procedures for data return after the termination of cloud computing services.",
    "Classification policies and procedures for data to be hosted on computing and hosting services.",
    "Up to date list of hosted services and their classification.",
    "Evidence that outlines the separation of the entity's environment from other entities' environments in cloud computing services ( e.g., as an item of the signed contract or having an agreement signed between the service provider and the entity).",
    "Evidence by the cloud computing service provider' that the entity's environment is separated from other entities' environments in cloud computing services.",
    "Evidence of the location of hosting and storing the entity's information within the Kingdom ( e.g., one of the clauses of the signed contract or service level agreement (SLA) signed between the service provider and the entity).",
    "Evidence by the service provider proving the storage of data within the Kingdom."
   ],
   "subcontrols": [
    {
     "ref": "4-2-3-1",
     "text": "accordance with its classification level and returning data (in a usable format) upon service completion."
    },
    {
     "ref": "4-2-3-2",
     "text": "environments of other entities within the cloud computing service provider."
    },
    {
     "ref": "4-2-3-3",
     "text": "Cybersecurity requirements for cloud computing and hosting services shall be periodically reviewed."
    }
   ]
  },
  {
   "ref": "4-2-4",
   "domain": "4",
   "domainName": "Third-Party and Cloud Computing Cybersecurity",
   "subdomain": "4-2",
   "subdomainName": "Cloud Computing and Hosting Cybersecurity",
   "objective": "",
   "text": "The cybersecurity requirements related to the use of hosting and cloud computing services must be reviewed periodically.",
   "tools": [],
   "guidelines": [
    "Review and update the cybersecurity policy that covers the requirements of using cloud computing and hosting services periodically according to a documented and approved plan for review based on a planned interval ( e.g., periodic review must be conducted annually).",
    "Review and update the cybersecurity policy covering the requirements of using cloud computing and hosting services in the event of changes in the relevant laws and regulations (for example, when a new cybersecurity law is issued that applies to the entity).",
    "Document the review and changes to the cybersecurity requirements for cloud computing and hosting services in the entity and approve them by the head of the entity or his/her deputy."
   ],
   "deliverables": [
    "An approved document that sets the policy's review schedule.",
    "Policy indicating that it is up to date and the changes to the cybersecurity requirements for cloud computing and hosting services have been documented and approved by the head of the entity or his/ her deputy.",
    "Formal approval by the head of the entity or his/her deputy on the updated policy (e.g., via the entity's official e-mail, paper or electronic signature)."
   ],
   "subcontrols": []
  }
 ]
};
