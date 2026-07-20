/**
 * forensixMethodology.ts - the FORENSIX DFIR investigation methodology (85 controls, 6 phases).
 *
 * A digital-forensics / incident-response mission checklist replicated from the Forensix DFIR
 * workbook: each phase (methodology & legal framework, disk acquisition, network PCAP, memory &
 * live forensics, correlation & report, logs & SIEM) carries controls with a normative reference
 * (ISO/IEC 27037, RFC 3227, French CPP, GDPR/RGPD, Code penal, NIS2, ANSSI, MITRE ATT&CK). It backs
 * the per-case forensic conformity checklist in certops.ts (/cert-ops). Control titles are English;
 * the normative references are kept verbatim from the source workbook.
 */
export interface ForensicControl { ref: string; title: string; description: string; norm: string }
export interface ForensicPhase { key: string; name: string; sub: string; controls: ForensicControl[] }
export interface ForensicMethodology { title: string; source: string; phases: ForensicPhase[] }

export const FORENSIX_METHODOLOGY: ForensicMethodology = {
  "title": "FORENSIX DFIR methodology",
  "source": "Forensix DFIR workbook (ISO/IEC 27037, RFC 3227, French CPP/RGPD, NIS2, ANSSI, MITRE ATT&CK)",
  "phases": [
    {
      "key": "P1",
      "name": "Methodology & legal framework",
      "sub": "Methodology and chain of evidence",
      "controls": [
        {
          "ref": "P1.1",
          "title": "Unique incident identifier assigned",
          "description": "Every engagement receives a unique identifier at intake.",
          "norm": "ISO/IEC 27037 §6.2"
        },
        {
          "ref": "P1.2",
          "title": "Legal framework and mandate verified",
          "description": "Authorization and legal scope confirmed before any action, per the applicable procedural framework (flagrante / preliminary inquiry / rogatory commission).",
          "norm": "CPP art. 56 (flagrance) / art. 76 (préliminaire) / art. 94, 97 (commission rogatoire) / art. 60"
        },
        {
          "ref": "P1.3",
          "title": "Order of volatility respected",
          "description": "Acquisition planned RAM to network connections to disk, in that order.",
          "norm": "ISO/IEC 27037 §7"
        },
        {
          "ref": "P1.4",
          "title": "Forensic Git repository initialized",
          "description": "Versioned, timestamped and hashed action log (chain of evidence).",
          "norm": "Bonnes pratiques ANSSI"
        },
        {
          "ref": "P1.5",
          "title": "Acquisition protocol written",
          "description": "Document describing the planned steps for the compromised workstation.",
          "norm": "ISO/IEC 27037 §6.3"
        },
        {
          "ref": "P1.6",
          "title": "Seizure report (PV) completed",
          "description": "Signed seizure record per exhibit, consistent with the procedural framework.",
          "norm": "CPP art. 56 (flagrance) ; art. 76 (préliminaire) ; art. 94, 97 (commission rogatoire)"
        },
        {
          "ref": "P1.7",
          "title": "Chain-of-custody form initiated",
          "description": "Who / when / where / how tracking for each piece of evidence.",
          "norm": "ISO/IEC 27037 §8"
        },
        {
          "ref": "P1.8",
          "title": "Lessons from similar incidents leveraged",
          "description": "Methodological and legal lessons from comparable incidents integrated into the approach.",
          "norm": "Retour d'expérience ANSSI"
        },
        {
          "ref": "P1.9",
          "title": "Digital scene documented",
          "description": "Power state, devices present and persons on site recorded.",
          "norm": "ISO/IEC 27037 §6.1"
        },
        {
          "ref": "P1.10",
          "title": "Unauthorized access prevented",
          "description": "Perimeter isolated and access restricted during the engagement.",
          "norm": "ISO/IEC 27037 §6.1"
        },
        {
          "ref": "P1.11",
          "title": "Official forensic tools identified",
          "description": "Validated toolset (Autopsy, FTK Imager, Wireshark, Volatility 3).",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P1.12",
          "title": "Investigator responsibilities recalled",
          "description": "Neutrality, integrity and professional ethics of the expert.",
          "norm": "CPP art. 60 / Déontologie"
        },
        {
          "ref": "P1.13",
          "title": "GDPR compliance verified",
          "description": "Processing of personal data contained in the evidence is framed.",
          "norm": "RGPD art. 5, 32"
        },
        {
          "ref": "P1.14",
          "title": "Secure evidence storage prepared",
          "description": "Restricted access, physical or logical seals planned.",
          "norm": "ISO/IEC 27037 §8"
        },
        {
          "ref": "P1.15",
          "title": "Evidence integrity guaranteed (criminal offence)",
          "description": "Destroying, altering, removing or falsifying digital evidence exposes the author to criminal prosecution and engages the responder liability.",
          "norm": "Code pénal art. 434-4"
        },
        {
          "ref": "P1.16",
          "title": "Evidence and data retention period defined",
          "description": "Retention set per data-minimisation and the applicable prescription (e.g. 6 years for delits); disposal organised at term.",
          "norm": "RGPD art. 5 ; CPP art. 8 (prescription des délits)"
        },
        {
          "ref": "P1.17",
          "title": "Regulatory incident-response obligations identified",
          "description": "Check whether the entity is subject to sector obligations for detection, handling and notification (OIV/OSE, banking, telecom operators).",
          "norm": "Code de la défense art. L.2321-1 et s. ; RGPD art. 33-34 ; Directive (UE) 2022/2555 (NIS2)"
        }
      ]
    },
    {
      "key": "P2",
      "name": "Disk acquisition & analysis",
      "sub": "Imaging E01, hashing, Autopsy & Plaso",
      "controls": [
        {
          "ref": "P2.1",
          "title": "Write blocker used",
          "description": "Source medium protected read-only before any handling.",
          "norm": "ISO/IEC 27037 §7.2"
        },
        {
          "ref": "P2.2",
          "title": "Bit-for-bit acquisition performed",
          "description": "Full forensic image of the medium, E01 or raw format (dd / FTK Imager).",
          "norm": "ISO/IEC 27037 §7.3"
        },
        {
          "ref": "P2.3",
          "title": "SHA-256 hash computed before/after",
          "description": "Image integrity verified by comparing fingerprints.",
          "norm": "ISO/IEC 27037 §7.4"
        },
        {
          "ref": "P2.4",
          "title": "Image stored as E01 / DD",
          "description": "Standard format usable by Autopsy and FTK Imager.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.5",
          "title": "Original sealed, working copy created",
          "description": "Distinction between the original medium and the analysis copy.",
          "norm": "ISO/IEC 27037 §8"
        },
        {
          "ref": "P2.6",
          "title": "Autopsy analysis performed",
          "description": "Timeline, keyword search and browser / USB / registry artefacts explored.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.7",
          "title": "Timeline built (Autopsy / Plaso)",
          "description": "Super timeline cross-referencing the available timestamps (log2timeline).",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.8",
          "title": "Deleted files searched",
          "description": "Recovery and documentation of erased data.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.9",
          "title": "Browser artefacts extracted",
          "description": "History, downloads and cookies documented.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.10",
          "title": "Windows registry analyzed",
          "description": "SAM, SYSTEM, SOFTWARE and NTUSER.DAT hives examined.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.11",
          "title": "Persistence and autoruns checked",
          "description": "Search for persistent malware and scheduled tasks.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P2.12",
          "title": "5 significant artefacts documented",
          "description": "Minimum expected deliverable for the disk-analysis report.",
          "norm": "Livrable client"
        },
        {
          "ref": "P2.13",
          "title": "MAC metadata preserved",
          "description": "Modified / Accessed / Created timestamps kept intact.",
          "norm": "ISO/IEC 27037 §7.5"
        },
        {
          "ref": "P2.14",
          "title": "Hidden partitions explored",
          "description": "Search for disk space not visible by default.",
          "norm": "Procédure interne SOC"
        }
      ]
    },
    {
      "key": "P3",
      "name": "Network analysis (PCAP)",
      "sub": "Wireshark / Zeek network forensics",
      "controls": [
        {
          "ref": "P3.1",
          "title": "Network capture collected (PCAP)",
          "description": "Relevant network traffic captured for analysis.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.2",
          "title": "PCAP integrity preserved",
          "description": "Capture hashed and stored so it cannot be silently altered.",
          "norm": "ISO/IEC 27037 §7"
        },
        {
          "ref": "P3.3",
          "title": "Wireshark filters applied",
          "description": "Display / capture filters used to isolate the relevant traffic.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.4",
          "title": "Follow TCP/HTTP Stream performed",
          "description": "Streams reassembled to read the exchanged payloads.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.5",
          "title": "Expert Info reviewed",
          "description": "Wireshark Expert Info consulted for anomalies.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.6",
          "title": "Zeek run on the capture",
          "description": "PCAP turned into structured logs (conn/dns/http/ssl).",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.7",
          "title": "Scan / brute-force patterns identified",
          "description": "Reconnaissance and credential-guessing patterns detected.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.8",
          "title": "Beaconing / C2 searched",
          "description": "Periodic implant-to-C2 communication looked for.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.9",
          "title": "Exfiltration searched",
          "description": "Large or covert outbound data transfers looked for.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.10",
          "title": "Objects extracted from the PCAP",
          "description": "Files / objects carved out of the capture.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.11",
          "title": "Extracted files verified",
          "description": "Carved files hashed and safely inspected (never executed directly).",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P3.12",
          "title": "Network IoCs consolidated",
          "description": "Network indicators of compromise gathered for the report.",
          "norm": "Livrable client"
        },
        {
          "ref": "P3.13",
          "title": "Network incident timeline established",
          "description": "Chronology of the network events reconstructed.",
          "norm": "Livrable client"
        },
        {
          "ref": "P3.14",
          "title": "Network recommendations formulated",
          "description": "Network hardening / containment recommendations produced.",
          "norm": "Livrable client"
        }
      ]
    },
    {
      "key": "P4",
      "name": "Memory & live forensics",
      "sub": "Volatility 3 memory analysis",
      "controls": [
        {
          "ref": "P4.1",
          "title": "Order of volatility respected",
          "description": "Memory prioritised over less-volatile sources.",
          "norm": "ISO/IEC 27037 §7"
        },
        {
          "ref": "P4.2",
          "title": "Live memory acquisition performed",
          "description": "RAM captured with winpmem (Windows) or LiME (Linux).",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.3",
          "title": "Memory dump hash computed",
          "description": "Dump fingerprinted to prove integrity.",
          "norm": "ISO/IEC 27037 §7.4"
        },
        {
          "ref": "P4.4",
          "title": "Volatility profile / symbol table identified",
          "description": "Correct OS profile / symbols selected for analysis.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.5",
          "title": "pslist / pstree executed",
          "description": "Process list and tree enumerated.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.6",
          "title": "netscan executed",
          "description": "Network connections and sockets recovered from memory.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.7",
          "title": "malfind executed",
          "description": "Injected / hidden code regions detected.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.8",
          "title": "cmdline executed",
          "description": "Process command lines recovered.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.9",
          "title": "DLL injection searched",
          "description": "Injected DLLs looked for.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.10",
          "title": "Rootkits / concealment searched",
          "description": "Hidden processes, hooks and rootkit artefacts looked for.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.11",
          "title": "Anti-forensic techniques assessed",
          "description": "Timestomping, fileless and evasion techniques evaluated.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P4.12",
          "title": "Memory / disk comparison performed",
          "description": "Memory findings cross-checked against the disk image.",
          "norm": "Livrable client"
        },
        {
          "ref": "P4.13",
          "title": "Memory IOCs consolidated",
          "description": "Memory indicators of compromise gathered for the report.",
          "norm": "Livrable client"
        },
        {
          "ref": "P4.14",
          "title": "Memory analysis report written",
          "description": "Findings of the memory analysis documented.",
          "norm": "Livrable client"
        }
      ]
    },
    {
      "key": "P5",
      "name": "Correlation & final report",
      "sub": "Cross-source correlation and reporting",
      "controls": [
        {
          "ref": "P5.1",
          "title": "Multiple sources cross-referenced",
          "description": "Disk, memory, network and log sources correlated.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.2",
          "title": "Correlated timeline built",
          "description": "Single timeline merging all sources.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.3",
          "title": "Divergences between sources explained",
          "description": "Conflicts between sources reconciled and explained.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.4",
          "title": "Incident storytelling written",
          "description": "Coherent narrative of the incident produced.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.5",
          "title": "Report structure respected",
          "description": "Standard report template and structure followed.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.6",
          "title": "Methodology documented in the report",
          "description": "Methods and tools recorded for reproducibility.",
          "norm": "ISO/IEC 27037 §9"
        },
        {
          "ref": "P5.7",
          "title": "Chain of evidence traced in the report",
          "description": "Evidence provenance traceable throughout the report.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.8",
          "title": "Factual and neutral conclusions",
          "description": "Conclusions stay factual, neutral and evidence-backed.",
          "norm": "Déontologie de l'expert"
        },
        {
          "ref": "P5.9",
          "title": "Remediation recommendations formulated",
          "description": "Actionable remediation recommendations provided.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.10",
          "title": "Plain-language summary prepared",
          "description": "Non-technical summary prepared for a lay audience.",
          "norm": "Procédure interne SOC"
        },
        {
          "ref": "P5.11",
          "title": "Report reviewed and validated by the team",
          "description": "Cross-review before submission.",
          "norm": "Bonnes pratiques"
        },
        {
          "ref": "P5.12",
          "title": "Client debrief material prepared",
          "description": "Restitution deck / material prepared for the client.",
          "norm": "Livrable client"
        },
        {
          "ref": "P5.13",
          "title": "Speaking roles distributed",
          "description": "Presentation roles assigned across the team.",
          "norm": "Livrable client"
        },
        {
          "ref": "P5.14",
          "title": "Final report submitted on time",
          "description": "Report delivered within the contractual deadline.",
          "norm": "Contrat / SLA client"
        }
      ]
    },
    {
      "key": "P6",
      "name": "Logs & SIEM",
      "sub": "Log collection, correlation and ATT&CK mapping",
      "controls": [
        {
          "ref": "P6.1",
          "title": "Centralized log collection",
          "description": "Logs centrally collected across sources.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.2",
          "title": "Event correlation configured",
          "description": "Correlation rules configured in the SIEM.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.3",
          "title": "Anomaly detection enabled",
          "description": "Behavioural / anomaly detection active.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.4",
          "title": "MITRE ATT&CK mapping performed",
          "description": "Observed activity mapped to ATT&CK tactics/techniques.",
          "norm": "MITRE ATT&CK"
        },
        {
          "ref": "P6.5",
          "title": "IOC identification",
          "description": "Indicators of compromise identified from the logs.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.6",
          "title": "Authentication-failure analysis",
          "description": "Failed-authentication patterns analysed.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.7",
          "title": "Privileged-access audit",
          "description": "Privileged access reviewed.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.8",
          "title": "Log normalization",
          "description": "Logs normalised to a common schema.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.9",
          "title": "Consistent timestamps across sources",
          "description": "All sources aligned to a single time reference (NTP).",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.10",
          "title": "Log retention compliant",
          "description": "Retention durations meet legal / regulatory requirements.",
          "norm": "RGPD / LPM"
        },
        {
          "ref": "P6.11",
          "title": "Critical alerts qualified",
          "description": "Critical alerts triaged and qualified.",
          "norm": "Cadre SOC"
        },
        {
          "ref": "P6.12",
          "title": "SIEM report produced",
          "description": "SIEM findings documented in a report.",
          "norm": "Cadre SOC"
        }
      ]
    }
  ]
} as const;
