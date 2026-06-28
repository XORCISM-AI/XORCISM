/**
 * app.ts — XORCISM Database Explorer (TypeScript client)
 * Replaces the inline JS in xorcism_web.ps1 $HTML here-string
 */

import { api, ColumnInfo, NotificationItem } from "./api";
import { mkRichText, isRichTextCol } from "./rte";
import { initI18n, t } from "./i18n";

// ── State ─────────────────────────────────────────────────────────────────────

let currentDb = "";
let currentTable = "";
let currentSort = "";
let currentDir: "asc" | "desc" = "asc";
let currentSearch = "";
let currentVocab = ""; // selected VocabularyID (filter); "" = all
let currentFilters: Record<string, string> = {}; // per-column filters (LIKE)
let schema: ColumnInfo[] = [];
let gridRows: Record<string, unknown>[] = []; // last rendered rows (local re-render, e.g. column reorder)
let gridCols: string[] = []; // columns currently displayed (order/selection) — reused by the export

const PAGE_SIZE = 100;
let currentPage = 0;
let totalRows = 0;

let searchDebounce: ReturnType<typeof setTimeout> | null = null;
let filterDebounce: ReturnType<typeof setTimeout> | null = null;
// Column whose filter field has focus (to restore it after re-render).
let activeFilterCol: string | null = null;

// ── DOM helpers ───────────────────────────────────────────────────────────────

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

// Current date in "YYYY-MM-DD HH:MM:SS" format (same as the BIA server)
function todayStr(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

// *GUID columns NOT to auto-initialize: real hardware/external
// identifiers (not record identifiers to generate).
const GUID_INIT_EXCLUDE = new Set<string>(["motherboardguid"]);

// "Global identifier" column to pre-fill with a UUIDv4 (e.g. AssetGUID,
// VocabularyGUID) — except excluded columns (e.g. motherboardguid).
function isGuidColumn(col: string): boolean {
  return /guid$/i.test(col) && !GUID_INIT_EXCLUDE.has(col.toLowerCase());
}

// Generates a UUIDv4 (RFC 9562 / RFC 4122) — the UUID version required by STIX 2.1
// (OASIS) for identifiers. crypto.randomUUID first, otherwise fallback via
// getRandomValues (available even outside a secure context).
function newGuid(): string {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
  } catch {
    /* randomUUID is reserved for secure contexts: we switch to the fallback */
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0"));
  return (
    `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-` +
    `${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`
  );
}

// Columns rendered as a dropdown: key "TABLE.Column" → values.
const ENUM_COLUMNS: Record<string, string[]> = {
  "INCIDENT.Criticity": ["Critical", "High", "Medium", "Low"],
  // STIX 2.1 object type of the bundle generated from the THREAT form
  "THREAT.STIXType": [
    "threat-actor", "attack-pattern", "malware", "tool",
    "intrusion-set", "campaign", "indicator", "infrastructure",
  ],
  "THREATMODELTHREAT.STRIDECategory": [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
  ],
  // XCOMPLIANCE — audits / findings / reports
  "AUDIT.AuditType": ["Internal", "External", "Certification", "Surveillance", "Gap Assessment", "Tabletop Exercise"],
  // Audit assessment dimension (ISAE 3000 / SOC 2): control design vs documentation adequacy vs operating effectiveness.
  "AUDIT.AssessmentType": ["Design Assessment", "Documentation Assessment", "Operating Effectiveness", "Combined (Design + Operating)", "Readiness Assessment"],
  "AUDITFINDING.AssessmentType": ["Design Assessment", "Documentation Assessment", "Operating Effectiveness"],
  // XCOMPLIANCE — crisis management / tabletop exercises
  "CRISISSCENARIO.ScenarioType": ["Ransomware", "Data Breach", "DDoS", "Insider Threat", "Supply Chain", "Cloud Account Compromise", "Business Email Compromise", "Phishing", "Physical / Environmental", "Third-Party Outage", "Other"],
  "CRISISSCENARIO.Severity": ["Critical", "High", "Medium", "Low"],
  "EXERCISEINJECT.InjectType": ["Event", "Decision", "Escalation", "Media", "Technical", "Communication"],
  "EXERCISEINJECT.Channel": ["email", "sms", "whatsapp", "phone", "media", "technical", "decision", "manual"],
  "EXERCISEINJECT.Status": ["Template", "Pending", "Delivered", "In progress", "Responded", "Done", "Skipped"],
  "EXERCISEPARTICIPANT.CrisisRole": ["Incident Commander", "Communications Lead", "Legal / DPO", "HR", "IT / Security Lead", "Executive Sponsor", "Operations", "Scribe / Notetaker", "Observer", "Facilitator"],
  "AUDITFINDINGREMEDIATION.Status": ["Planned", "In progress", "Implemented", "Verified", "Closed", "Cancelled"],
  "AUDITFINDINGREMEDIATION.RemediationType": ["Corrective", "Preventive", "Compensating", "Mitigation", "Risk acceptance"],
  "AUDITFINDINGREMEDIATION.Priority": ["Critical", "High", "Medium", "Low"],
  // XCOMPLIANCE — PQCMM post-quantum-crypto maturity assessments
  "PQCMMASSESSMENT.SubjectType": ["Asset", "Application", "Service", "Product", "Protocol", "Library", "Certificate / PKI"],
  "PQCMMASSESSMENT.Status": ["Active", "Planned", "Retired", "Superseded"],
  "PQCMMASSESSMENT.CurrentLevel": ["0", "1", "2", "3", "4", "5"],
  "PQCMMASSESSMENT.TargetLevel": ["0", "1", "2", "3", "4", "5"],
  // XORCISM — SCA / SBOM (Software Composition Analysis)
  "SBOM.Format": ["CycloneDX", "SPDX"],
  "SBOM.Source": ["upload", "import", "connector", "generated", "agent"],
  "COMPONENT.ComponentType": ["application", "library", "framework", "operating-system", "container", "device", "firmware", "file", "data"],
  "COMPONENT.Scope": ["required", "optional", "excluded"],
  // OCIL — result associated with an answer/choice (ResultType, NIST IR 7692)
  "ANSWERFORQUESTION.Result": ["PASS", "FAIL", "ERROR", "UNKNOWN", "NOT_TESTED", "NOT_APPLICABLE"],
  // THREAT — confidence / reliability levels (qualitative scale)
  "THREAT.ConfidenceLevel": ["Very Low", "Low", "Moderate", "High", "Very High"],
  // TOOLDOCUMENT — confidence of the tool↔document association
  "TOOLDOCUMENT.ConfidenceLevel": ["Very Low", "Low", "Moderate", "High", "Very High"],
  "THREAT.TrustLevel": ["Very Low", "Low", "Moderate", "High", "Very High"],
};

// Columns edited in WYSIWYG (in addition to those detected by name in rte.ts).
// Key "TABLE.Column".
const RICHTEXT_COLUMNS = new Set<string>([
  "INCIDENT.summary",
  "ASSET.notes",
  "THREATAGENT.ThreatAgentDescription",
  "THREATEVENT.Description",
  "CONTROL.ControlDescription",
  "CONTROL.Minimal",
  "CONTROL.Balanced",
  "CONTROL.Comprehensive",
  "THREATMODEL.Description",
  "THREATMODEL.Scope",
  "THREATMODELTHREAT.Description",
  "AUDIT.AuditDescription",
  "AUDITFINDING.FindingDescription",
  "AUDITREPORT.ReportDescription",
  "TICKET.Description",
  "TICKET.Resolution",
  "TICKETCOMMENT.Body",
  "ATTACKTOOL.AttackToolDescription",
  "THREATCAMPAIGN.ThreatCampaignDescription",
  "DOCUMENT.DocumentDescription",
  "VOCABULARY.VocabularyDescription",
  // GRC
  "FRAMEWORK.Description",
  "REQUIREMENTNODE.Description",
  "REFERENCECONTROL.Description",
  "APPLIEDCONTROL.Description",
  "COMPLIANCEASSESSMENT.Description",
  "REQUIREMENTASSESSMENT.Observation",
  "RISKASSESSMENT.Description",
  "RISKSCENARIO.Description",
  "RISKSCENARIO.Justification",
  "RISKACCEPTANCE.Justification",
  "SECURITYEXCEPTION.Description",
  "PERIMETER.Description",
  "RISKMATRIX.Description",
  "GRCTHREAT.Description",
  // Risk Register
  "RISKREGISTER.Description",
  "RISKREGISTERENTRY.Description",
  "RISKREGISTERENTRY.TreatmentPlan",
  "RISKREGISTERENTRY.Justification",
  // Policy & document bodies (full WYSIWYG documents)
  "POLICY.PolicyContent",
  "POLICY.PolicyDescription",
  "POLICY.Scope",
  "CRISISSCENARIO.Objectives",
  // VULNERABILITY long-form prose fields (VULDescription/VULTechnicalDescription are already
  // rich-text via the *Description rule; VULRequest/VULResponse stay plain — they're raw HTTP data)
  "VULNERABILITY.VULSolution",
  "VULNERABILITY.VULConsequence",
  "VULNERABILITY.VULDetailedInformation",
  "VULNERABILITY.VULManualTestingNotes",
]);

function isRichTextField(table: string, col: string): boolean {
  return isRichTextCol(col) || RICHTEXT_COLUMNS.has(`${table}.${col}`);
}

// Rich-text columns rendered with a TALL editor (long documents, not short notes).
const TALL_RICHTEXT_COLUMNS = new Set<string>(["POLICY.PolicyContent", "CRISISSCENARIO.Objectives", "BUGBOUNTYSUBMISSION.Description"]);
function richTextOpts(table: string, col: string): { minHeight?: number } | undefined {
  return TALL_RICHTEXT_COLUMNS.has(`${table}.${col}`) ? { minHeight: 340 } : undefined;
}

// Columns rendered as a PROMINENT input — the record's "title": large font, full width.
const PROMINENT_INPUT_COLUMNS = new Set<string>(["POLICY.PolicyName", "CPE.CPEName", "RISKREGISTERENTRY.Title", "CRISISSCENARIO.ScenarioName", "AUDIT.AuditName", "BUGBOUNTYSUBMISSION.Title"]);
function isProminentInput(table: string, col: string): boolean {
  return PROMINENT_INPUT_COLUMNS.has(`${table}.${col}`);
}
const PROMINENT_INPUT_CSS =
  "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:11px 13px;color:var(--text);font-size:18px;font-weight:600";

// Columns rendered FULL-WIDTH with a slightly larger, normal-styled input — for long
// identifiers/URLs (e.g. a submission GUID) that need room but not the bold "title" styling.
const WIDE_INPUT_COLUMNS = new Set<string>(["BUGBOUNTYSUBMISSION.SubmissionGUID"]);
function isWideInput(table: string, col: string): boolean {
  return WIDE_INPUT_COLUMNS.has(`${table}.${col}`);
}
const WIDE_INPUT_CSS =
  "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--text);font-size:15px";

// Columns never shown in forms: handled server-side from
// the session (e.g. TenantID, multi-tenant). Case-insensitive comparison.
const HIDDEN_FORM_COLUMNS = new Set<string>(["tenantid"]);
function isHiddenFormColumn(name: string): boolean {
  return HIDDEN_FORM_COLUMNS.has(name.toLowerCase());
}

// Columns computed/managed by the server: shown read-only in the
// forms and excluded from the save (the server owns them).
// Key "TABLE.Column". E.g. ASSET.RiskScore is recomputed every 30 s.
const READONLY_FORM_COLUMNS = new Set<string>([
  "ASSET.RiskScore",
  // EBIOS RM — computed automatically on write (threat level = exposure / cyber reliability).
  "EBIOSSTAKEHOLDER.ThreatLevel", "EBIOSSTAKEHOLDER.Zone",
]);
function isReadonlyFormColumn(table: string, col: string): boolean {
  return READONLY_FORM_COLUMNS.has(`${table}.${col}`);
}

// Tables whose modal is widened (relational sub-panels).
const WIDE_MODAL_TABLES = new Set<string>(["ASSET", "THREATMODEL", "THREATMODELTHREAT", "OVALDEFINITION", "QUESTIONNAIRE", "ANSWER", "THREAT", "CRISISSCENARIO", "VULNERABILITY", "AUDIT", "ASSETVULNERABILITY", "DOCUMENT", "BUGBOUNTYSUBMISSION", "IDENTITY", "AUDITFINDING", "RISKREGISTERENTRY", "BUGBOUNTYPROGRAM", "HUNT", "SIGMARULE", "INTELEXCHANGE", "TICKET", "ASSETVULNERABILITYREMEDIATION"]);

// Display reordering of fields in the forms:
// table → list of [columnToMove, columnAfterWhich].
const FIELD_REORDER: Record<string, [string, string][]> = {
  INCIDENT: [["Criticity", "IncidentID"], ["IncidentName", "IncidentID"]],
  AUDIT: [["AuditName", "AuditGUID"], ["AuditCategory", "AuditName"]],
  ASSET: [["RiskScore", "AssetDescription"], ["Currency", "FinancialValue"]],
  VOCABULARY: [["VocabularyDescription", "VocabularyReference"]],
  QUESTIONNAIRE: [["FileName", "QuestionnaireDescription"]],
};

// Display of values in the GRID (table only, not the form):
// raw value → label. Key "TABLE.Column". E.g. 0 → No, 1 → Yes.
const YES_NO = { "0": "No", "1": "Yes" } as const;
const GRID_VALUE_LABELS: Record<string, Record<string, string>> = {
  "ASSET.TaskCriticalAsset": { ...YES_NO },
  "ASSET.DefenseCriticalAsset": { ...YES_NO },
  "ASSET.Enabled": { ...YES_NO },
  "ASSET.personal": { ...YES_NO },
  "ASSET.managedbythirdparty": { ...YES_NO },
  "ASSET.hostedbythirdparty": { ...YES_NO },
  "ASSET.virtual": { ...YES_NO },
  "ASSET.ADParticipation": { ...YES_NO },
  "ASSET.PublicFacing": { ...YES_NO },
  "ASSET.MFAEnabled": { ...YES_NO },
  // Patch status: 0 → Unpatched, 1 → Patched
  "ASSETVULNERABILITY.Status": { "0": "Unpatched", "1": "Patched" },
  // Business value 1–5 → label (form select stores the int; grid shows the label).
  "ASSET.BusinessValue": { "1": "Very Low", "2": "Low", "3": "Medium", "4": "High", "5": "Very High" },
};
// Cell color based on the DISPLAYED value (key "TABLE.Column" → value → CSS color).
// E.g. "Yes" in red for the computed columns Exploited / KEV.
const GRID_VALUE_COLORS: Record<string, Record<string, string>> = {
  "ASSETVULNERABILITY.Exploited": { Yes: "var(--danger)" },
  "ASSETVULNERABILITY.KEV": { Yes: "var(--danger)" },
  // Business value heat scale (low → critical importance). Keyed by the DISPLAYED
  // label (the grid colors on the displayed value, which comes from GRID_VALUE_LABELS).
  "ASSET.BusinessValue": { "Very Low": "#22c55e", "Low": "#84cc16", "Medium": "#eab308", "High": "#f97316", "Very High": "#ef4444" },
};
function gridLabel(table: string, col: string, val: unknown): string | null {
  const map = GRID_VALUE_LABELS[`${table}.${col}`];
  if (!map || val == null || val === "") return null;
  const key = String(val);
  return key in map ? map[key] : null;
}

// Default sort when opening a table. Key "DB.TABLE" → [column, direction].
const DEFAULT_SORT: Record<string, [string, "asc" | "desc"]> = {
  "XVULNERABILITY.VULNERABILITY": ["VulnerabilityID", "desc"], // largest ID first
  "XORCISM.ASSETVULNERABILITY": ["AssetVulnerabilityID", "desc"], // most recent first
  "XORCISM.ASSETFINANCIALVALUE": ["AssetFinancialValueID", "desc"], // most recent first
  "XORCISM.ASSET": ["AssetName", "asc"], // alphabetical by name
  "XCOMPLIANCE.AUDIT": ["AuditID", "desc"], // most recent first
};

// Conditional visibility: a "controller" field shows the dependent
// fields only when its value is in `showWhen` (otherwise hidden).
interface CondRule { controller: string; showWhen: string[]; dependents: string[] }
const CONDITIONAL_FIELDS: Record<string, CondRule[]> = {
  INCIDENT: [
    { controller: "exercise", showWhen: ["1"], dependents: ["exercise_name"] },
  ],
};

// Applies the conditional visibility rules of a modal (field id prefix:
// "f_" for insertion, "ef_" for editing).
function applyConditionalFields(prefix: string): void {
  const rules = CONDITIONAL_FIELDS[currentTable];
  if (!rules) return;
  for (const rule of rules) {
    const ctrl = document.getElementById(`${prefix}${rule.controller}`) as
      | HTMLInputElement
      | HTMLSelectElement
      | null;
    if (!ctrl) continue;
    const update = () => {
      const show = rule.showWhen.includes(String(ctrl.value));
      for (const dep of rule.dependents) {
        const div = document.getElementById(`${prefix}field_${dep}`);
        if (div) div.style.display = show ? "" : "none";
      }
    };
    ctrl.addEventListener("change", update);
    ctrl.addEventListener("input", update);
    update(); // initial state
  }
}

// "Foreign key" columns: dropdown showing `labelCol` of a
// reference table and submitting the corresponding `idCol`.
// db optional (default: current database); default = value preselected at insertion.
// distinct: deduplicates the options by label (first id encountered per label).
interface FkSpec { table: string; idCol: string; labelCol: string; db?: string; default?: string; distinct?: boolean }

// Table-specific rules: key "TABLE.Column".
const FK_COLUMNS: Record<string, FkSpec> = {
  // TOOLDOCUMENT (XORCISM): a TOOL ↔ DOCUMENT link with provenance + confidence reason.
  "TOOLDOCUMENT.ToolID": { db: "XORCISM", table: "TOOL", idCol: "ToolID", labelCol: "ToolName", distinct: true },
  "TOOLDOCUMENT.DocumentID": { db: "XORCISM", table: "DOCUMENT", idCol: "DocumentID", labelCol: "DocumentName", distinct: true },
  "TOOLDOCUMENT.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true },
  "TOOLDOCUMENT.ConfidenceReasonID": { db: "XORCISM", table: "CONFIDENCEREASON", idCol: "ConfidenceReasonID", labelCol: "ConfidenceReasonName", distinct: true },
  // ORGANISATIONRISKSCORE (XORCISM): per-organisation risk-score history.
  "ORGANISATIONRISKSCORE.OrganisationID": { db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", labelCol: "OrganisationName", distinct: true },
  // PQCMM assessments (XCOMPLIANCE): subject asset + owner.
  "PQCMMASSESSMENT.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true },
  "PQCMMASSESSMENT.OwnerPersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true },
  // SCA / SBOM (XORCISM): SBOM → asset/application/person; component → SBOM/asset/CPE.
  "SBOM.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true },
  "SBOM.ApplicationID": { db: "XORCISM", table: "APPLICATION", idCol: "ApplicationID", labelCol: "ApplicationName", distinct: true },
  "SBOM.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true },
  "COMPONENT.SbomID": { db: "XORCISM", table: "SBOM", idCol: "SbomID", labelCol: "Name", distinct: true },
  "COMPONENT.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true },
  "COMPONENTDEPENDENCY.SbomID": { db: "XORCISM", table: "SBOM", idCol: "SbomID", labelCol: "Name", distinct: true },
  // Crisis management (XCOMPLIANCE): tabletop-exercise injects/participants ↔ audit / scenario / person
  "EXERCISEINJECT.AuditID": { db: "XCOMPLIANCE", table: "AUDIT", idCol: "AuditID", labelCol: "AuditName", distinct: true },
  "EXERCISEINJECT.ScenarioID": { db: "XCOMPLIANCE", table: "CRISISSCENARIO", idCol: "ScenarioID", labelCol: "ScenarioName", distinct: true },
  "EXERCISEPARTICIPANT.AuditID": { db: "XCOMPLIANCE", table: "AUDIT", idCol: "AuditID", labelCol: "AuditName", distinct: true },
  "EXERCISEPARTICIPANT.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true },
  // Asset financial value history (ASSETFINANCIALVALUE)
  "ASSETFINANCIALVALUE.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "ASSETFINANCIALVALUE.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName" },
  "ASSETVULNERABILITYREMEDIATION.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName" },
  // HUNT cross-links (XTHREAT): dropdowns for manual linking.
  "HUNTIOC.HuntID": { db: "XTHREAT", table: "HUNT", idCol: "HuntID", labelCol: "HuntName", distinct: true },
  "HUNTIOC.IOCID": { db: "XTHREAT", table: "IOC", idCol: "IOCID", labelCol: "IOCName", distinct: true },
  "HUNTATTACK.HuntID": { db: "XTHREAT", table: "HUNT", idCol: "HuntID", labelCol: "HuntName", distinct: true },
  "HUNTATTACK.AttackTechniqueID": { db: "XTHREAT", table: "ATTACKTECHNIQUE", idCol: "AttackTechniqueID", labelCol: "Name", distinct: true },
  // APPLICATION ↔ ASSET link: dropdowns (displayed name → stored ID)
  "APPLICATIONFORASSET.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "APPLICATIONFORASSET.ApplicationID": { db: "XORCISM", table: "APPLICATION", idCol: "ApplicationID", labelCol: "ApplicationName", distinct: true },
  // APPLICATION ↔ PERSON link: dropdowns (distinct names → stored ID)
  "APPLICATIONPERSON.ApplicationID": { db: "XORCISM", table: "APPLICATION", idCol: "ApplicationID", labelCol: "ApplicationName", distinct: true },
  "APPLICATIONPERSON.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true },
  "INCIDENT.IncidentCategoryID": {
    table: "INCIDENTCATEGORY",
    idCol: "IncidentCategoryID",
    labelCol: "IncidentCategoryName",
  },
  // THREAT → threat actor (STIX relationship of the generated bundle)
  "THREAT.ThreatActorID": {
    db: "XTHREAT",
    table: "THREATACTOR",
    idCol: "ThreatActorID",
    labelCol: "ThreatActorName",
  },
  "ASSETRISKSCORE.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  "ASSETVULNERABILITY.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  // Linked document (dropdown of documents by name)
  "DOCUMENTPERSON.DocumentID": { db: "XCOMPLIANCE", table: "DOCUMENT", idCol: "DocumentID", labelCol: "DocumentName" },
  // OCIL: linked questionnaire (dropdown of QuestionnaireName → QuestionnaireID)
  "QUESTIONFORQUESTIONNAIRE.QuestionnaireID": { table: "QUESTIONNAIRE", idCol: "QuestionnaireID", labelCol: "QuestionnaireName" },
  // ── GRC: structuring relations (all in XCOMPLIANCE → implicit db) ──
  "REQUIREMENTNODE.FrameworkID": { table: "FRAMEWORK", idCol: "FrameworkID", labelCol: "Name" },
  "COMPLIANCEASSESSMENT.FrameworkID": { table: "FRAMEWORK", idCol: "FrameworkID", labelCol: "Name" },
  "COMPLIANCEASSESSMENT.PerimeterID": { table: "PERIMETER", idCol: "PerimeterID", labelCol: "Name" },
  "REQUIREMENTASSESSMENT.ComplianceAssessmentID": { table: "COMPLIANCEASSESSMENT", idCol: "ComplianceAssessmentID", labelCol: "Name" },
  "REQUIREMENTASSESSMENT.RequirementNodeID": { table: "REQUIREMENTNODE", idCol: "RequirementNodeID", labelCol: "Name" },
  "APPLIEDCONTROL.ReferenceControlID": { table: "REFERENCECONTROL", idCol: "ReferenceControlID", labelCol: "Name" },
  "APPLIEDCONTROL.FolderID": { table: "FOLDER", idCol: "FolderID", labelCol: "Name" },
  "PERIMETER.FolderID": { table: "FOLDER", idCol: "FolderID", labelCol: "Name" },
  "RISKASSESSMENT.PerimeterID": { table: "PERIMETER", idCol: "PerimeterID", labelCol: "Name" },
  "RISKASSESSMENT.RiskMatrixID": { table: "RISKMATRIX", idCol: "RiskMatrixID", labelCol: "Name" },
  "RISKSCENARIO.RiskAssessmentID": { table: "RISKASSESSMENT", idCol: "RiskAssessmentID", labelCol: "Name" },
  "RISKACCEPTANCE.RiskScenarioID": { table: "RISKSCENARIO", idCol: "RiskScenarioID", labelCol: "Name" },
  // ── Risk Register ──
  "RISKREGISTER.PerimeterID": { table: "PERIMETER", idCol: "PerimeterID", labelCol: "Name" },
  "RISKREGISTERENTRY.RiskRegisterID": { table: "RISKREGISTER", idCol: "RiskRegisterID", labelCol: "Name" },
  "RISKREGISTERENTRY.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "RISKREGISTERENTRY.ThreatID": { table: "GRCTHREAT", idCol: "ThreatID", labelCol: "Name" },
  "RISKREGISTERENTRYASSET.RiskRegisterEntryID": { table: "RISKREGISTERENTRY", idCol: "RiskRegisterEntryID", labelCol: "Title" },
  "RISKREGISTERENTRYASSET.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "RISKREGISTERENTRYCONTROL.RiskRegisterEntryID": { table: "RISKREGISTERENTRY", idCol: "RiskRegisterEntryID", labelCol: "Title" },
  "RISKREGISTERENTRYCONTROL.AppliedControlID": { table: "APPLIEDCONTROL", idCol: "AppliedControlID", labelCol: "Name" },
  "ASSETTHREAT.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  "ASSETTHREAT.ThreatID": {
    db: "XTHREAT", // THREAT lives in XTHREAT.db
    table: "THREAT",
    idCol: "ThreatID",
    labelCol: "ThreatName",
  },
  "ASSETAUDIT.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  "ASSETAUDIT.AuditID": {
    db: "XCOMPLIANCE", // AUDIT lives in XCOMPLIANCE.db
    table: "AUDIT",
    idCol: "AuditID",
    labelCol: "AuditDescription",
  },
  "ASSETAUDITFINDING.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  "ACCESSRECORD.AssetID": {
    table: "ASSET",
    idCol: "AssetID",
    labelCol: "AssetName",
  },
  "ASSET.PersonID": {
    table: "PERSON",
    idCol: "PersonID",
    labelCol: "FullName",
  },
  "TRAININGFORPERSON.PersonID": {
    table: "PERSON",
    idCol: "PersonID",
    labelCol: "FullName",
  },
  "TRAININGFORPERSON.TrainingID": {
    table: "TRAINING",
    idCol: "TrainingID",
    labelCol: "TrainingName",
  },
  "ASSETAUDITFINDING.AuditFindingID": {
    db: "XCOMPLIANCE", // AUDITFINDING lives in XCOMPLIANCE.db
    table: "AUDITFINDING",
    idCol: "AuditFindingID",
    labelCol: "FindingName",
  },
  "AUDITEVIDENCE.AuditID": {
    db: "XCOMPLIANCE",
    table: "AUDIT",
    idCol: "AuditID",
    labelCol: "AuditName",
  },
  "AUDITEVIDENCE.EvidenceID": {
    db: "XCOMPLIANCE",
    table: "EVIDENCE",
    idCol: "EvidenceID",
    labelCol: "EvidenceName",
  },
  // status: list of status names; the stored VALUE is the name itself
  // (idCol = labelCol = IncidentStatusName). db = current database (XINCIDENT).
  "INCIDENT.status": {
    table: "INCIDENTSTATUS",
    idCol: "IncidentStatusName",
    labelCol: "IncidentStatusName",
  },
  // Threat models — foreign keys (direct table editing in the explorer)
  "THREATMODELTHREAT.ThreatModelID": { table: "THREATMODEL", idCol: "ThreatModelID", labelCol: "ThreatModelName" },
  "THREATMODELTHREAT.ThreatAgentID": { db: "XTHREAT", table: "THREATAGENT", idCol: "ThreatAgentID", labelCol: "ThreatAgentName" },
  "THREATMODELASSET.ThreatModelID": { table: "THREATMODEL", idCol: "ThreatModelID", labelCol: "ThreatModelName" },
  "THREATMODELASSET.AssetID": { table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "THREATMODELCONTROL.ThreatModelThreatID": { table: "THREATMODELTHREAT", idCol: "ThreatModelThreatID", labelCol: "Title" },
  "THREATMODELCONTROL.ControlID": { table: "CONTROL", idCol: "ControlID", labelCol: "ControlName" },
  // XTICKET
  "TICKET.CategoryID": { db: "XTICKET", table: "TICKETCATEGORY", idCol: "TicketCategoryID", labelCol: "TicketCategoryName" },
  "TICKETCOMMENT.TicketID": { db: "XTICKET", table: "TICKET", idCol: "TicketID", labelCol: "Subject" },
  "TICKETATTACHMENT.TicketID": { db: "XTICKET", table: "TICKET", idCol: "TicketID", labelCol: "Subject" },
};

// Rules by column NAME (all tables / all databases). Key in lowercase.
const FK_BY_COLUMN: Record<string, FkSpec> = {
  vocabularyid: {
    db: "XORCISM", // VOCABULARY is always in XORCISM.db
    table: "VOCABULARY",
    idCol: "VocabularyID",
    labelCol: "VocabularyName",
    default: "1", // XORCISM
  },
  // Confidence reason: dropdown of CONFIDENCEREASON (stores the ID)
  confidencereasonid: {
    db: "XORCISM",
    table: "CONFIDENCEREASON",
    idCol: "ConfidenceReasonID",
    labelCol: "ConfidenceReasonName",
  },
};

function getFkSpec(table: string, col: string): FkSpec | null {
  return FK_COLUMNS[`${table}.${col}`] ?? FK_BY_COLUMN[col.toLowerCase()] ?? null;
}

// Pre-loads the options of all the FK columns of the current schema.
async function fetchFkOptions(): Promise<Record<string, { id: unknown; label: unknown }[]>> {
  const map: Record<string, { id: unknown; label: unknown }[]> = {};
  for (const col of schema) {
    const fk = getFkSpec(currentTable, col.name);
    if (!fk) continue;
    try {
      let opts = await api.getLookup(fk.db ?? currentDb, fk.table, fk.idCol, fk.labelCol);
      if (fk.distinct) {
        // Deduplicates by label (first id encountered per label) — e.g. distinct ApplicationName.
        const seen = new Set<string>();
        opts = opts.filter((o) => {
          const lbl = o.label == null ? "" : String(o.label);
          if (seen.has(lbl)) return false;
          seen.add(lbl);
          return true;
        });
      }
      map[col.name] = opts;
    } catch {
      map[col.name] = [];
    }
  }
  return map;
}

// ── "Name hint": shows read-only the label corresponding to an
// identifier field (e.g. AssetID → AssetName), right after that field, and updates
// it when the identifier changes. Key "TABLE.Column".
// lazy = large table → on-demand resolution (1 request per identifier)
// instead of preloading the whole lookup table.
// Text fields with autocompletion (datalist) on a column of a table: the
// input stays free, but suggests/filters the existing values. Key "TABLE.Column".
// labelCol  : values suggested in the datalist (and stored in the field)
// idCol/idTargetCol (optional): when a recognized label is chosen, the corresponding
//   identifier (idCol) is written into the form's sibling field (idTargetCol).
interface DatalistSpec { db: string; table: string; labelCol: string; idCol?: string; idTargetCol?: string }
const DATALIST_COLUMNS: Record<string, DatalistSpec> = {
  // Auditor name: search in PERSON.FullName (stored value = the name)
  "AUDIT.AuditorName": { db: "XORCISM", table: "PERSON", labelCol: "FullName" },
  // Platform: free input + distinct values from PLATFORM.PlatformName
  "ASSET.PlatformID": { db: "XORCISM", table: "PLATFORM", labelCol: "PlatformName" },
  // Location: free input + distinct values already present in ASSET.AssetLocation
  "ASSET.AssetLocation": { db: "XORCISM", table: "ASSET", labelCol: "AssetLocation" },
  // Tool category: free input + distinct values already present in TOOL.Category
  "TOOL.Category": { db: "XORCISM", table: "TOOL", labelCol: "Category" },
  // Report author: search in PERSON.FullName; the corresponding PersonID
  // is filled automatically (the field stores the displayed name).
  "AUDITREPORT.ReportAuthor": {
    db: "XORCISM", table: "PERSON", labelCol: "FullName", idCol: "PersonID", idTargetCol: "PersonID",
  },
  // Document author: search in PERSON.FullName (stored value = the name)
  "DOCUMENT.Author": { db: "XORCISM", table: "PERSON", labelCol: "FullName" },
};
function getDatalistSpec(table: string, col: string): DatalistSpec | null {
  return DATALIST_COLUMNS[`${table}.${col}`] ?? null;
}

// Dropdown WITH INPUT (datalist with static options): suggests
// fixed values while allowing free input. Key "TABLE.Column".
const STATIC_DATALIST_COLUMNS: Record<string, string[]> = {
  "DOCUMENTPERSON.Role": ["Author", "Reviewer", "Validator"],
  "ASSETVULNERABILITY.AssetVulnerabilityStatusID": [
    "Open", "In Progress", "Mitigated", "Patched", "Fixed", "Closed",
  ],
  "ASSETVULNERABILITY.Priority": ["Very Low", "Low", "Moderate", "High", "Very High", "Critical"],
  "ASSETVULNERABILITYREMEDIATION.Priority": ["Very Low", "Low", "Moderate", "High", "Very High", "Critical"],
  // Risk Register
  "RISKREGISTER.Status": ["Active", "Draft", "Archived"],
  "RISKREGISTERENTRY.Category": [
    "Strategic", "Operational", "Financial", "Compliance",
    "Technical", "Security", "Reputational", "Legal", "Third-party",
  ],
  "RISKREGISTERENTRY.TreatmentStrategy": ["Accept", "Avoid", "Transfer", "Mitigate"],
  "RISKREGISTERENTRY.Status": ["Open", "Assessed", "In Treatment", "Monitored", "Closed"],
  // Usage of an APPLICATION by a PERSON: free input, suggested values User/Owner.
  "APPLICATIONPERSON.Usage": ["User", "Owner"],
};
// Default value of a "dropdown with input" at CREATION (key "TABLE.Column").
const STATIC_DATALIST_DEFAULTS: Record<string, string> = {
  "APPLICATIONPERSON.Usage": "User",
};
function staticDatalistDefault(table: string, col: string): string {
  return STATIC_DATALIST_DEFAULTS[`${table}.${col}`] ?? "";
}
function getStaticDatalist(table: string, col: string): string[] | null {
  return STATIC_DATALIST_COLUMNS[`${table}.${col}`] ?? null;
}

const FIELD_INPUT_CSS =
  "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";

// <input list> + <datalist> with static options (free input + suggestions).
function mkStaticDatalistInput(id: string, options: string[], currentVal: string): HTMLElement {
  const wrap = document.createElement("div");
  const input = document.createElement("input");
  input.id = id;
  input.value = currentVal;
  input.setAttribute("list", `${id}_sdl`);
  input.autocomplete = "off";
  input.style.cssText = FIELD_INPUT_CSS;
  const dl = document.createElement("datalist");
  dl.id = `${id}_sdl`;
  options.forEach((o) => {
    const op = document.createElement("option");
    op.value = o;
    dl.appendChild(op);
  });
  wrap.appendChild(input);
  wrap.appendChild(dl);
  return wrap;
}

// <select> that DISPLAYS a label but stores/submits the option value (e.g. an
// ordinal kept as an int, like ASSET.BusinessValue 1–5). Key "TABLE.Column".
interface LabeledOption { value: string; label: string }
const LABELED_SELECT_COLUMNS: Record<string, LabeledOption[]> = {
  "ASSET.BusinessValue": [
    { value: "1", label: "Very Low" },
    { value: "2", label: "Low" },
    { value: "3", label: "Medium" },
    { value: "4", label: "High" },
    { value: "5", label: "Very High" },
  ],
};
function getLabeledSelect(table: string, col: string): LabeledOption[] | null {
  return LABELED_SELECT_COLUMNS[`${table}.${col}`] ?? null;
}
// <select> showing the label; value (submitted) = the stored int. Empty option = unset.
function mkLabeledSelectInput(id: string, options: LabeledOption[], currentVal: string): HTMLElement {
  const sel = document.createElement("select");
  sel.id = id;
  sel.style.cssText = FIELD_INPUT_CSS;
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "—";
  sel.appendChild(blank);
  for (const o of options) {
    const op = document.createElement("option");
    op.value = o.value;
    op.textContent = o.label;
    sel.appendChild(op);
  }
  sel.value = currentVal || "";
  return sel;
}

// Read-only <input> for a server-computed column (e.g. ASSET.RiskScore).
// The value is never sent back to the save (the server owns it).
function mkReadonlyComputedInput(id: string, currentVal: unknown): HTMLElement {
  const wrap = document.createElement("div");
  const input = document.createElement("input");
  input.id = id;
  input.value = currentVal == null ? "" : String(currentVal);
  input.readOnly = true;
  input.style.cssText = FIELD_INPUT_CSS + ";opacity:.7;cursor:not-allowed";
  input.title = t("tip.autoCalc30s");
  const hint = document.createElement("div");
  hint.textContent = "Calculé automatiquement (toutes les 30 s)";
  hint.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:3px";
  wrap.appendChild(input);
  wrap.appendChild(hint);
  return wrap;
}

// Derived risk levels (probability × impact) — read-only, computed
// live on the form side AND authoritatively on the server side. Key "TABLE.Column".
interface RiskLevelSpec { prob: string; impact: string }
const RISK_LEVEL_COLUMNS: Record<string, RiskLevelSpec> = {
  "RISKREGISTERENTRY.InherentRiskLevel": { prob: "InherentProbability", impact: "InherentImpact" },
  "RISKREGISTERENTRY.CurrentRiskLevel": { prob: "CurrentProbability", impact: "CurrentImpact" },
  "RISKREGISTERENTRY.ResidualRiskLevel": { prob: "ResidualProbability", impact: "ResidualImpact" },
};
function getRiskLevelSpec(table: string, col: string): RiskLevelSpec | null {
  return RISK_LEVEL_COLUMNS[`${table}.${col}`] ?? null;
}

// Read-only <input> for a risk level (= probability × impact).
function mkRiskLevelInput(id: string, currentVal: unknown): HTMLElement {
  const wrap = document.createElement("div");
  const input = document.createElement("input");
  input.id = id;
  input.value = currentVal == null ? "" : String(currentVal);
  input.readOnly = true;
  input.style.cssText = FIELD_INPUT_CSS + ";opacity:.85;cursor:not-allowed";
  input.title = t("tip.riskCalc");
  const hint = document.createElement("div");
  hint.textContent = "Calculé : probabilité × impact";
  hint.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:3px";
  wrap.appendChild(input);
  wrap.appendChild(hint);
  return wrap;
}

// Recomputes the level live (prob × impact) when either of the two changes.
function wireRiskLevelLive(levelId: string, probId: string, impactId: string): void {
  const level = document.getElementById(levelId) as HTMLInputElement | null;
  if (!level) return;
  const prob = document.getElementById(probId) as (HTMLInputElement | HTMLSelectElement) | null;
  const impact = document.getElementById(impactId) as (HTMLInputElement | HTMLSelectElement) | null;
  const recompute = () => {
    const p = Number((prob as HTMLInputElement | null)?.value);
    const i = Number((impact as HTMLInputElement | null)?.value);
    level.value = p > 0 && i > 0 ? String(p * i) : "";
  };
  for (const el of [prob, impact]) {
    el?.addEventListener("change", recompute);
    el?.addEventListener("input", recompute);
  }
  recompute();
}

// <input> + <datalist>: autocompletion on the values of spec.table.labelCol.
// fillTargetId (optional): id of the ID field to fill when a label is chosen.
function mkDatalistInput(
  id: string,
  spec: DatalistSpec,
  currentVal: string,
  fillTargetId?: string
): HTMLElement {
  const wrap = document.createElement("div");
  const input = document.createElement("input");
  input.id = id;
  input.value = currentVal;
  input.setAttribute("list", `${id}_dl`);
  input.autocomplete = "off";
  input.placeholder = `Rechercher (${spec.table}.${spec.labelCol})…`;
  input.style.cssText = FIELD_INPUT_CSS;
  const dl = document.createElement("datalist");
  dl.id = `${id}_dl`;
  wrap.appendChild(input);
  wrap.appendChild(dl);
  if (spec.idCol && fillTargetId) {
    void populateDatalistWithId(dl, input, spec, fillTargetId); // labels + name→ID map
  } else {
    void populateDatalist(dl, spec); // asynchronous fill (input usable right away)
  }
  return wrap;
}

// Variant: fills the datalist AND populates fillTargetId with the identifier
// (spec.idCol) corresponding to the entered/chosen label.
async function populateDatalistWithId(
  dl: HTMLDataListElement,
  input: HTMLInputElement,
  spec: DatalistSpec,
  fillTargetId: string
): Promise<void> {
  const nameToId = new Map<string, string>();
  try {
    const opts = await api.getLookup(spec.db, spec.table, spec.idCol!, spec.labelCol);
    for (const o of opts) {
      const nm = o.label == null ? "" : String(o.label);
      const id = o.id == null ? "" : String(o.id);
      if (nm && !nameToId.has(nm)) {
        nameToId.set(nm, id);
        const op = document.createElement("option");
        op.value = nm;
        dl.appendChild(op);
      }
    }
  } catch {
    /* rights/unavailable: input stays free, the ID is not filled */
  }
  const resolve = () => {
    const target = document.getElementById(fillTargetId) as HTMLInputElement | null;
    if (!target) return;
    const id = nameToId.get(input.value.trim());
    if (id !== undefined) target.value = id; // recognized label → fills the ID
  };
  input.addEventListener("input", resolve);
  input.addEventListener("change", resolve);
}

async function populateDatalist(dl: HTMLDataListElement, spec: DatalistSpec): Promise<void> {
  try {
    const opts = await api.getLookup(spec.db, spec.table, spec.labelCol, spec.labelCol);
    const seen = new Set<string>();
    for (const o of opts) {
      const v = o.label == null ? "" : String(o.label);
      if (v && !seen.has(v)) {
        seen.add(v);
        const op = document.createElement("option");
        op.value = v;
        dl.appendChild(op);
      }
    }
  } catch {
    /* insufficient rights / unavailable: input stays free */
  }
}

// SEARCH field by name that automatically fills an ID field, inserted
// BEFORE the ID field (inverse of the "name hint"). Key "TABLE.IDColumn".
interface NameSearchSpec { db: string; table: string; idCol: string; labelCol: string; searchLabel?: string; replaceIdField?: boolean }
const NAME_SEARCH_COLUMNS: Record<string, NameSearchSpec> = {
  // OCIL: linked question — dropdown (input) of QuestionName → QuestionID.
  // replaceIdField: the dropdown replaces the ID field (which stays hidden).
  "QUESTIONFORQUESTIONNAIRE.QuestionID": { db: "XCOMPLIANCE", table: "QUESTION", idCol: "QuestionID", labelCol: "QuestionName", searchLabel: "QuestionName", replaceIdField: true },
  "ANSWERFORQUESTION.QuestionID": { db: "XCOMPLIANCE", table: "QUESTION", idCol: "QuestionID", labelCol: "QuestionName", searchLabel: "QuestionName", replaceIdField: true },
  "ANSWERFORQUESTION.AnswerID": { db: "XCOMPLIANCE", table: "ANSWER", idCol: "AnswerID", labelCol: "Answer", searchLabel: "Answer", replaceIdField: true },
  "ASSETPLATFORM.PlatformID": { db: "XORCISM", table: "PLATFORM", idCol: "PlatformID", labelCol: "PlatformName" },
  "ASSETPLATFORM.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "ASSETPRODUCT.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName" },
  "ASSETPRODUCT.ProductID": { db: "XORCISM", table: "PRODUCT", idCol: "ProductID", labelCol: "ProductName" },
  // ASSETBLACKLIST: searchable name comboboxes replace the raw ID fields (fill the IDs).
  "ASSETBLACKLIST.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", searchLabel: "AssetName", replaceIdField: true },
  "ASSETBLACKLIST.OrganisationID": { db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", labelCol: "OrganisationName", searchLabel: "OrganisationName", replaceIdField: true },
  "ASSETBLACKLIST.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "PersonName", replaceIdField: true },
  // ASSETFORASSET: both endpoints are ASSETs → searchable AssetName comboboxes (fill AssetID).
  "ASSETFORASSET.AssetRefID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", searchLabel: "AssetName (Ref)", replaceIdField: true },
  "ASSETFORASSET.AssetSubjectID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", searchLabel: "AssetName (Subject)", replaceIdField: true },
  // THREATFORASSET: ThreatID → searchable ThreatName combobox. AssetID → searchable AssetName
  // combobox in EDIT mode; in INSERT mode the combobox is hidden in favour of the multi-asset
  // selector (see openInsertModal: one THREATFORASSET per checked asset).
  "THREATFORASSET.ThreatID": { db: "XTHREAT", table: "THREAT", idCol: "ThreatID", labelCol: "ThreatName", searchLabel: "ThreatName", replaceIdField: true },
  "THREATFORASSET.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", searchLabel: "AssetName", replaceIdField: true },
  // ASSETFORORGANISATION: searchable name comboboxes replace the raw ID fields (fill the IDs).
  "ASSETFORORGANISATION.OrganisationID": { db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", labelCol: "OrganisationName", searchLabel: "OrganisationName", replaceIdField: true },
  "ASSETFORORGANISATION.AssetID": { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", searchLabel: "AssetName", replaceIdField: true },
  "ASSET.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "Owner" },
  // Location: search in ASSETLOCATION.AssetLocationName → fills AssetLocationID
  // (the dropdown replaces the ID field, kept hidden). The detail of the chosen location
  // is shown by a dedicated panel (appendAssetLocationTable).
  "ASSET.AssetLocationID": { db: "XORCISM", table: "ASSETLOCATION", idCol: "AssetLocationID", labelCol: "AssetLocationName", searchLabel: "Location (AssetLocationName)", replaceIdField: true },
  "DOCUMENTPERSON.PersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "PersonName" },
  // Risk Register: owners (search PERSON.FullName → fills the ID)
  "RISKREGISTER.OwnerPersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "OwnerName" },
  "RISKREGISTERENTRY.RiskOwnerPersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "RiskOwnerName" },
  // Asset-vuln remediation owner: searchable PERSON.FullName combobox → fills RemediationOwnerPersonID (replaces the raw ID field).
  "ASSETVULNERABILITY.RemediationOwnerPersonID": { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "Remediation owner", replaceIdField: true },
};
function getNameSearch(table: string, col: string): NameSearchSpec | null {
  return NAME_SEARCH_COLUMNS[`${table}.${col}`] ?? null;
}

// Inserts a search field (datalist of names) BEFORE the ID field. When a
// recognized name is chosen, fills the ID field (prefix+idCol). In editing, the field
// is pre-filled with the name corresponding to the current ID.
function appendNameSearchField(
  body: HTMLElement,
  prefix: string,
  idCol: string,
  spec: NameSearchSpec,
  currentIdVal: string
): void {
  const div = document.createElement("div");
  div.id = `${prefix}field_${idCol}_search`;
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = spec.searchLabel ?? spec.labelCol; // e.g. "PlatformName"
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const input = document.createElement("input");
  input.id = `${prefix}${idCol}_search`;
  input.setAttribute("list", `${prefix}${idCol}_search_dl`);
  input.autocomplete = "off";
  input.placeholder = `Rechercher (${spec.table}.${spec.labelCol})…`;
  input.style.cssText = FIELD_INPUT_CSS;
  const dl = document.createElement("datalist");
  dl.id = `${prefix}${idCol}_search_dl`;
  div.appendChild(label);
  div.appendChild(input);
  div.appendChild(dl);
  body.appendChild(div);

  void (async () => {
    const nameToId = new Map<string, string>();
    const idToName = new Map<string, string>();
    try {
      const opts = await api.getLookup(spec.db, spec.table, spec.idCol, spec.labelCol);
      for (const o of opts) {
        const id = o.id == null ? "" : String(o.id);
        const nm = o.label == null ? "" : String(o.label);
        if (nm && !nameToId.has(nm)) {
          nameToId.set(nm, id);
          const op = document.createElement("option");
          op.value = nm;
          dl.appendChild(op);
        }
        if (id && !idToName.has(id)) idToName.set(id, nm);
      }
    } catch {
      /* rights/unavailable: the search is inoperative, the ID stays editable */
    }
    if (currentIdVal && idToName.has(currentIdVal)) input.value = idToName.get(currentIdVal)!;
    const resolve = () => {
      const idInput = document.getElementById(`${prefix}${idCol}`) as HTMLInputElement | null;
      if (!idInput) return;
      const id = nameToId.get(input.value.trim());
      if (id !== undefined) idInput.value = id; // recognized name → fills the ID
    };
    input.addEventListener("input", resolve);
    input.addEventListener("change", resolve);
  })();
}

// VULNERABILITY search field (by VULReferential / CVE) inserted BEFORE the
// VulnerabilityID field: large table (~355k) → server search (live),
// no preloaded datalist. Key "TABLE.IDColumn".
const VULN_SEARCH_COLUMNS = new Set<string>([
  "ASSETVULNERABILITY.VulnerabilityID",
  "RISKREGISTERENTRY.VulnerabilityID",
]);
function hasVulnSearch(table: string, col: string): boolean {
  return VULN_SEARCH_COLUMNS.has(`${table}.${col}`);
}

// Inserts a live search field (VULNERABILITY.VULReferential) that fills
// the VulnerabilityID field (prefix+idCol) when a result is chosen. In editing, we
// pre-fill with the current VULReferential (resolved on demand).
function appendVulnSearchField(
  body: HTMLElement,
  prefix: string,
  idCol: string,
  currentVulnId: string
): void {
  const div = document.createElement("div");
  div.id = `${prefix}field_${idCol}_vulnsearch`;
  div.style.cssText = "margin-bottom:10px;position:relative";
  const label = document.createElement("label");
  label.textContent = "Recherche vulnérabilité (VULReferential / CVE)";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const input = document.createElement("input");
  input.id = `${prefix}${idCol}_vulnsearch`;
  input.autocomplete = "off";
  input.placeholder = "ex. CVE-2024-… (min. 2 caractères)";
  input.style.cssText = FIELD_INPUT_CSS;
  const results = document.createElement("div");
  results.style.cssText =
    "position:absolute;left:0;right:0;z-index:20;max-height:220px;overflow:auto;background:var(--bg);" +
    "border:1px solid var(--border);border-radius:6px;margin-top:2px;display:none";
  div.appendChild(label);
  div.appendChild(input);
  div.appendChild(results);
  body.appendChild(div);

  // Pre-fill in editing: VULReferential corresponding to the current ID.
  if (currentVulnId) {
    void (async () => {
      try {
        const r = await api.getLookupOne(
          "XVULNERABILITY", "VULNERABILITY", "VulnerabilityID", currentVulnId, "VULReferential"
        );
        if (r.label != null && r.label !== "") input.value = String(r.label);
      } catch {
        /* unavailable: the search stays usable */
      }
    })();
  }

  const hideResults = () => { results.style.display = "none"; };
  const pick = (vid: number, ref: string) => {
    const idInput = document.getElementById(`${prefix}${idCol}`) as HTMLInputElement | null;
    if (idInput) {
      idInput.value = String(vid);
      idInput.dispatchEvent(new Event("input")); // updates the "name hint" (VULGUID)
    }
    input.value = ref;
    hideResults();
  };

  let timer: number | undefined;
  input.addEventListener("input", () => {
    const q = input.value.trim();
    window.clearTimeout(timer);
    if (q.length < 2) { hideResults(); return; }
    timer = window.setTimeout(async () => {
      let rows: { VulnerabilityID: number; VULReferential: string; VULReferentialID: string; VULDescription: string }[] = [];
      try {
        rows = await api.searchVulnerabilities(q);
      } catch {
        hideResults();
        return;
      }
      results.innerHTML = "";
      if (!rows.length) {
        results.innerHTML =
          `<div style="padding:7px 10px;font-size:12px;color:var(--text-dim)">Aucun résultat</div>`;
      } else {
        rows.forEach((r) => {
          const item = document.createElement("div");
          item.style.cssText =
            "padding:7px 10px;font-size:12px;color:var(--text-soft);cursor:pointer;border-bottom:1px solid var(--surface)";
          const ref = r.VULReferential || r.VULReferentialID || `#${r.VulnerabilityID}`;
          const desc = (r.VULDescription || "").slice(0, 70);
          item.textContent = desc ? `${ref} — ${desc}` : ref;
          item.addEventListener("mouseenter", () => (item.style.background = "var(--surface)"));
          item.addEventListener("mouseleave", () => (item.style.background = ""));
          item.addEventListener("click", () => pick(r.VulnerabilityID, ref));
          results.appendChild(item);
        });
      }
      results.style.display = "";
    }, 250);
  });
  input.addEventListener("blur", () => window.setTimeout(hideResults, 200));
}

// Dropdowns whose options come from a reference table
// FILTERED by the form's current VocabularyID. The STORED value is the
// text value (not an ID). Re-populated when the vocabulary changes.
interface VocabValueSelectSpec { db: string; table: string; valueCol: string; defaultVocab: number }
const VOCAB_VALUE_SELECT_COLUMNS: Record<string, VocabValueSelectSpec> = {
  "THREATACTOR.ThreatMotive": { db: "XTHREAT", table: "THREATMOTIVE", valueCol: "ThreatMotive", defaultVocab: 1 },
};
function getVocabValueSelect(table: string, col: string): VocabValueSelectSpec | null {
  return VOCAB_VALUE_SELECT_COLUMNS[`${table}.${col}`] ?? null;
}

// Cache of the values (id = VocabularyID, label = value) per db.table.valueCol.
const _vocabValuesCache: Record<string, { id: unknown; label: unknown }[]> = {};
async function getVocabValues(spec: VocabValueSelectSpec): Promise<{ id: unknown; label: unknown }[]> {
  const key = `${spec.db}.${spec.table}.${spec.valueCol}`;
  if (_vocabValuesCache[key]) return _vocabValuesCache[key];
  let rows: { id: unknown; label: unknown }[] = [];
  try {
    rows = await api.getLookup(spec.db, spec.table, "VocabularyID", spec.valueCol);
  } catch {
    rows = [];
  }
  _vocabValuesCache[key] = rows;
  return rows;
}

function mkVocabValueSelect(
  prefix: string,
  col: string,
  spec: VocabValueSelectSpec,
  currentVal: string
): HTMLSelectElement {
  const sel = document.createElement("select");
  sel.id = `${prefix}${col}`;
  sel.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";

  const populate = async (keepSelected: string) => {
    const vocabSel = document.getElementById(`${prefix}VocabularyID`) as HTMLSelectElement | null;
    const vocab = vocabSel && vocabSel.value ? Number(vocabSel.value) : spec.defaultVocab;
    const all = await getVocabValues(spec);
    sel.innerHTML = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "—";
    sel.appendChild(blank);
    const seen = new Set<string>();
    for (const r of all) {
      if (Number(r.id) !== vocab) continue;
      const v = r.label == null ? "" : String(r.label);
      if (!v || seen.has(v)) continue;
      seen.add(v);
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      opt.style.background = "var(--surface)";
      if (v === keepSelected) opt.selected = true;
      sel.appendChild(opt);
    }
    // Existing value absent from the current vocabulary: we keep it (editing).
    if (keepSelected && !seen.has(keepSelected)) {
      const opt = document.createElement("option");
      opt.value = keepSelected;
      opt.textContent = `${keepSelected} (hors vocabulaire)`;
      opt.selected = true;
      sel.appendChild(opt);
    }
  };

  void populate(currentVal);
  // Re-populates when the vocabulary changes (the VocabularyID select exists once
  // the form is fully built).
  setTimeout(() => {
    const vocabSel = document.getElementById(`${prefix}VocabularyID`) as HTMLSelectElement | null;
    if (vocabSel) vocabSel.addEventListener("change", () => void populate(sel.value));
  }, 0);
  return sel;
}

interface NameHintSpec { db: string; table: string; idCol: string; labelCol: string; hintLabel: string; lazy?: boolean }

// Computed columns shown in the grid (read-only, not sortable/filterable):
// value of a linked table, inserted right after the source column. Several per
// table possible. Key = table.
// yesno: the resolved value (0/1 field, nullable) is shown "Yes" (≠0) / "No" (0/empty).
// keyCol: column of the ROW used as the lookup key (default = srcCol). Allows
//   resolving by a column ≠ from the insertion position (e.g. REMEDIATION inserted after
//   KEV but looked up by AssetVulnerabilityID).
// emptyLabel: label shown when there is no match (e.g. "Remediate").
interface GridDisplaySpec extends NameHintSpec {
  srcCol: string; colLabel: string; yesno?: boolean; keyCol?: string; emptyLabel?: string;
}
const GRID_DISPLAY_COLUMNS: Record<string, GridDisplaySpec[]> = {
  // AUDITFINDING: the parent audit's name, resolved from AuditID, shown just LEFT of FindingName
  // (inserted after AuditFindingGUID since AuditID itself sits far right in the schema).
  AUDITFINDING: [
    { db: "XCOMPLIANCE", table: "AUDIT", idCol: "AuditID", labelCol: "AuditName", hintLabel: "AuditName", srcCol: "AuditFindingGUID", keyCol: "AuditID", colLabel: "AuditName" },
  ],
  // ASSETCONTROL: resolved asset & control names, shown right after AssetID / ControlID.
  ASSETCONTROL: [
    { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", hintLabel: "AssetName", srcCol: "AssetID", colLabel: "AssetName" },
    { db: "XORCISM", table: "CONTROL", idCol: "ControlID", labelCol: "ControlName", hintLabel: "ControlName", srcCol: "ControlID", colLabel: "ControlName" },
    { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", hintLabel: "PersonName", srcCol: "PersonID", colLabel: "PersonName" },
  ],
  // BACKUPPLAN: resolved asset & owner names, shown right after AssetID / PersonID.
  BACKUPPLAN: [
    { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", hintLabel: "AssetName", srcCol: "AssetID", colLabel: "AssetName" },
    { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", hintLabel: "PersonName", srcCol: "PersonID", colLabel: "PersonName" },
  ],
  // IDENTITY: resolved owner & bound-asset names, shown right after OwnerPersonID / AssetID.
  IDENTITY: [
    { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", hintLabel: "OwnerName", srcCol: "OwnerPersonID", colLabel: "OwnerName" },
    { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", hintLabel: "AssetName", srcCol: "AssetID", colLabel: "AssetName" },
  ],
  // IDENTITYPERSON: resolved identity & person names, shown right after IdentityID / PersonID.
  IDENTITYPERSON: [
    { db: "XORCISM", table: "IDENTITY", idCol: "IdentityID", labelCol: "IdentityName", hintLabel: "IdentityName", srcCol: "IdentityID", colLabel: "IdentityName" },
    { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", hintLabel: "PersonName", srcCol: "PersonID", colLabel: "PersonName" },
  ],
  // OVALCRITERIA: resolved operator (AND/OR…), shown right after OperatorEnumerationID.
  OVALCRITERIA: [
    {
      db: "XOVAL",
      table: "OPERATORENUMERATION",
      idCol: "OperatorEnumerationID",
      labelCol: "OperatorValue",
      hintLabel: "Operator",
      srcCol: "OperatorEnumerationID",
      colLabel: "Operator",
    },
  ],
  // ASSETTAG: resolved asset name, shown right after AssetID.
  ASSETTAG: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
  ],
  // ASSETFINANCIALVALUE: resolved asset name, shown right after AssetID.
  ASSETFINANCIALVALUE: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
  ],
  // CPEFORASSET: resolved asset name (after AssetID) + CPE name (after CPEID).
  CPEFORASSET: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
    {
      db: "XORCISM",
      table: "CPE",
      idCol: "CPEID",
      labelCol: "CPEName",
      hintLabel: "CPEName",
      srcCol: "CPEID",
      colLabel: "CPEName",
    },
  ],
  // APPLICATIONFORASSET: ApplicationName (after ApplicationGUID, looked up by ApplicationID)
  // + AssetName (after AssetGUID, looked up by AssetID). The matching GRID_FIELD_REORDER
  // rules keep each name beside its GUID once the GUID columns are repositioned.
  APPLICATIONFORASSET: [
    {
      db: "XORCISM",
      table: "APPLICATION",
      idCol: "ApplicationID",
      labelCol: "ApplicationName",
      hintLabel: "ApplicationName",
      srcCol: "ApplicationGUID",
      keyCol: "ApplicationID",
      colLabel: "ApplicationName",
    },
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetGUID",
      keyCol: "AssetID",
      colLabel: "AssetName",
    },
  ],
  // ASSETAUDIT: resolved asset name (after AssetID) + audit name (after AuditID).
  ASSETAUDIT: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
    {
      db: "XCOMPLIANCE",
      table: "AUDIT",
      idCol: "AuditID",
      labelCol: "AuditName",
      hintLabel: "AuditName",
      srcCol: "AuditID",
      colLabel: "AuditName",
    },
  ],
  // INCIDENTFORASSET: resolved asset name (after AssetID) + incident name (after IncidentID).
  INCIDENTFORASSET: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
    {
      db: "XINCIDENT",
      table: "INCIDENT",
      idCol: "IncidentID",
      labelCol: "IncidentName",
      hintLabel: "IncidentName",
      srcCol: "IncidentID",
      colLabel: "IncidentName",
    },
  ],
  RISKREGISTERENTRY: [
    {
      db: "XCOMPLIANCE",
      table: "RISKREGISTER",
      idCol: "RiskRegisterID",
      labelCol: "Name",
      hintLabel: "Register",
      srcCol: "RiskRegisterID",
      colLabel: "Register",
    },
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
  ],
  ATTACKPATTERNCWE: [
    {
      db: "XATTACK",
      table: "ATTACKPATTERN",
      idCol: "AttackPatternID",
      labelCol: "capec_id",
      hintLabel: "AttackPattern",
      srcCol: "AttackPatternID",
      colLabel: "AttackPattern", // shown right after AttackPatternID
    },
  ],
  OVALDEFINITIONPLATFORM: [
    {
      db: "XOVAL",
      table: "OVALDEFINITION",
      idCol: "OVALDefinitionID",
      labelCol: "OVALDefinitionIDPattern",
      hintLabel: "OVALDefinitionIDPattern",
      srcCol: "OVALDefinitionID",
      colLabel: "OVALDefinitionIDPattern",
    },
    {
      db: "XORCISM",
      table: "PLATFORM",
      idCol: "PlatformID",
      labelCol: "PlatformName",
      hintLabel: "PlatformName",
      srcCol: "PlatformID",
      colLabel: "PlatformName",
    },
  ],
  ASSETVULNERABILITY: [
    {
      db: "XORCISM",
      table: "ASSET",
      idCol: "AssetID",
      labelCol: "AssetName",
      hintLabel: "AssetName",
      srcCol: "AssetID",
      colLabel: "AssetName",
    },
    {
      db: "XVULNERABILITY",
      table: "VULNERABILITY",
      idCol: "VulnerabilityID",
      labelCol: "VULReferential",
      hintLabel: "VULReferential",
      srcCol: "VulnerabilityID",
      colLabel: "VULReferential",
      lazy: true, // ~355k rows: on-demand resolution (lookup-many bounded to visible rows)
    },
    // Yes/No indicators resolved from VULNERABILITY (by VulnerabilityID), to the right of VULReferential
    {
      db: "XVULNERABILITY",
      table: "VULNERABILITY",
      idCol: "VulnerabilityID",
      labelCol: "Exploited",
      hintLabel: "Exploited",
      srcCol: "VulnerabilityID",
      colLabel: "Exploited",
      lazy: true,
      yesno: true,
    },
    {
      db: "XVULNERABILITY",
      table: "VULNERABILITY",
      idCol: "VulnerabilityID",
      labelCol: "EasilyExploitable",
      hintLabel: "EasilyExploitable",
      srcCol: "VulnerabilityID",
      colLabel: "EasilyExploitable",
      lazy: true,
      yesno: true,
    },
    {
      db: "XVULNERABILITY",
      table: "VULNERABILITY",
      idCol: "VulnerabilityID",
      labelCol: "KEV",
      hintLabel: "KEV",
      srcCol: "VulnerabilityID",
      colLabel: "KEV",
      lazy: true,
      yesno: true,
    },
    // Remediation: AssetVulnerabilityRemediationID of the ASSETVULNERABILITYREMEDIATION row
    // whose AssetVulnerabilityID = that of the row, otherwise "Remediate". Inserted after KEV
    // (srcCol = VulnerabilityID) but looked up by AssetVulnerabilityID (keyCol). Clickable
    // cell (cf. renderTable): integer → edits the remediation; "Remediate" → creation.
    {
      db: "XORCISM",
      table: "ASSETVULNERABILITYREMEDIATION",
      idCol: "AssetVulnerabilityID",
      labelCol: "AssetVulnerabilityRemediationID",
      hintLabel: "REMEDIATION",
      srcCol: "VulnerabilityID",
      keyCol: "AssetVulnerabilityID",
      colLabel: "REMEDIATION",
      emptyLabel: "Remediate",
    },
  ],
  // APPLICATION ↔ PERSON: resolved names to the right of PersonID and ApplicationID
  APPLICATIONPERSON: [
    {
      db: "XORCISM",
      table: "PERSON",
      idCol: "PersonID",
      labelCol: "FullName",
      hintLabel: "FullName",
      srcCol: "PersonID",
      colLabel: "FullName",
    },
    {
      db: "XORCISM",
      table: "APPLICATION",
      idCol: "ApplicationID",
      labelCol: "ApplicationName",
      hintLabel: "ApplicationName",
      srcCol: "ApplicationID",
      colLabel: "ApplicationName",
    },
  ],
  AUDITEVIDENCE: [
    {
      db: "XCOMPLIANCE",
      table: "AUDIT",
      idCol: "AuditID",
      labelCol: "AuditName",
      hintLabel: "AuditName",
      srcCol: "AuditID",
      colLabel: "AuditName",
    },
    {
      db: "XCOMPLIANCE",
      table: "EVIDENCE",
      idCol: "EvidenceID",
      labelCol: "EvidenceName",
      hintLabel: "EvidenceName",
      srcCol: "EvidenceID",
      colLabel: "EvidenceName",
    },
  ],
  // Remediations: person name shown to the right of PersonID
  ASSETVULNERABILITYREMEDIATION: [
    {
      db: "XORCISM",
      table: "PERSON",
      idCol: "PersonID",
      labelCol: "FullName",
      hintLabel: "Person",
      srcCol: "PersonID",
      colLabel: "Person",
    },
  ],
  // OCIL: names shown to the right of QuestionnaireID and QuestionID
  QUESTIONFORQUESTIONNAIRE: [
    {
      db: "XCOMPLIANCE",
      table: "QUESTIONNAIRE",
      idCol: "QuestionnaireID",
      labelCol: "QuestionnaireName",
      hintLabel: "Questionnaire",
      srcCol: "QuestionnaireID",
      colLabel: "Questionnaire",
    },
    {
      db: "XCOMPLIANCE",
      table: "QUESTION",
      idCol: "QuestionID",
      labelCol: "QuestionName",
      hintLabel: "Question",
      srcCol: "QuestionID",
      colLabel: "Question",
    },
  ],
  // OCIL: names shown to the right of QuestionID and AnswerID
  ANSWERFORQUESTION: [
    {
      db: "XCOMPLIANCE",
      table: "QUESTION",
      idCol: "QuestionID",
      labelCol: "QuestionName",
      hintLabel: "Question",
      srcCol: "QuestionID",
      colLabel: "Question",
    },
    {
      db: "XCOMPLIANCE",
      table: "ANSWER",
      idCol: "AnswerID",
      labelCol: "Answer",
      hintLabel: "Answer",
      srcCol: "AnswerID",
      colLabel: "Answer",
    },
  ],
  // MITRE ATT&CK: resolved names to the right of ThreatID and AttackTechniqueID
  THREATTTP: [
    {
      db: "XTHREAT",
      table: "THREAT",
      idCol: "ThreatID",
      labelCol: "ThreatName",
      hintLabel: "Threat",
      srcCol: "ThreatID",
      colLabel: "Threat",
    },
    {
      db: "XTHREAT",
      table: "ATTACKTECHNIQUE",
      idCol: "AttackTechniqueID",
      labelCol: "Name",
      hintLabel: "Technique",
      srcCol: "AttackTechniqueID",
      colLabel: "Technique",
    },
  ],
  // OCIL: evidence linked to an answer — Answer + EvidenceName resolved
  ANSWEREVIDENCE: [
    {
      db: "XCOMPLIANCE",
      table: "ANSWER",
      idCol: "AnswerID",
      labelCol: "Answer",
      hintLabel: "Answer",
      srcCol: "AnswerID",
      colLabel: "Answer",
    },
    {
      db: "XCOMPLIANCE",
      table: "EVIDENCE",
      idCol: "EvidenceID",
      labelCol: "EvidenceName",
      hintLabel: "EvidenceName",
      srcCol: "EvidenceID",
      colLabel: "EvidenceName",
    },
  ],
};

const NAME_HINT_COLUMNS: Record<string, NameHintSpec> = {
  // ASSETVULNERABILITY.AssetID is now a dropdown (FK_COLUMNS):
  // no redundant "name hint". We keep the hint for VulnerabilityID.
  "ASSETVULNERABILITY.VulnerabilityID": {
    db: "XVULNERABILITY",
    table: "VULNERABILITY",
    idCol: "VulnerabilityID",
    labelCol: "VULGUID",
    hintLabel: "VULGUID",
    lazy: true, // ~355k rows: on-demand lookup
  },
  // Shows the capec_id of the linked pattern, after the AttackPatternID field
  // (updated on input at creation, and on display at modification).
  "ATTACKPATTERNCWE.AttackPatternID": {
    db: "XATTACK",
    table: "ATTACKPATTERN",
    idCol: "AttackPatternID",
    labelCol: "capec_id",
    hintLabel: "AttackPattern",
  },
};

function getNameHint(table: string, col: string): NameHintSpec | null {
  return NAME_HINT_COLUMNS[`${table}.${col}`] ?? null;
}

// Cache of id→label maps for the "name hints" (key db.table.idCol.labelCol).
const _nameHintCache: Record<string, Map<string, string>> = {};

async function getNameHintMap(spec: NameHintSpec): Promise<Map<string, string>> {
  const key = `${spec.db}.${spec.table}.${spec.idCol}.${spec.labelCol}`;
  if (_nameHintCache[key]) return _nameHintCache[key];
  const m = new Map<string, string>();
  try {
    const opts = await api.getLookup(spec.db, spec.table, spec.idCol, spec.labelCol);
    opts.forEach((o) => m.set(String(o.id), o.label == null ? "" : String(o.label)));
  } catch {
    /* insufficient rights / unavailable: empty map */
  }
  _nameHintCache[key] = m;
  return m;
}

// Clears the "name hint" map cache (after writing a table referenced by a
// computed column, e.g. creation/edit of ASSETVULNERABILITYREMEDIATION → REMEDIATION).
function clearNameHintCache(): void {
  for (const k of Object.keys(_nameHintCache)) delete _nameHintCache[k];
}

// Inserts, into each grid row, the computed column (value of a linked
// table) right after the source column. Reuses the "name hints" cache.
// Resolves the identifiers present in the visible rows in a SINGLE
// lookup-many call (large table); returns an id→label map.
async function resolveLazyGridMap(
  spec: GridDisplaySpec,
  rows: Record<string, unknown>[]
): Promise<Map<string, string>> {
  const keyCol = spec.keyCol ?? spec.srcCol; // lookup key (≠ insertion position possible)
  const ids = Array.from(
    new Set(
      rows
        .map((r) => (r[keyCol] == null ? "" : String(r[keyCol])))
        .filter((v) => v !== "")
    )
  );
  const map = new Map<string, string>();
  if (!ids.length) return map;
  try {
    const found = await api.getLookupMany(spec.db, spec.table, spec.idCol, spec.labelCol, ids);
    for (const r of found) {
      if (r.id != null) map.set(String(r.id), r.label == null ? "" : String(r.label));
    }
  } catch {
    // best-effort: empty map → computed columns shown empty.
  }
  return map;
}

// Applies the display transformation of a computed column (e.g. yesno, emptyLabel).
function gridDisplayValue(spec: GridDisplaySpec, resolved: string): string {
  if (spec.yesno) return resolved !== "" && resolved !== "0" ? "Yes" : "No";
  if (resolved === "" && spec.emptyLabel) return spec.emptyLabel; // e.g. "Remediate"
  return resolved;
}

// Grid cells rendered as LINKS: a click opens the edit form of
// ANOTHER table (db/table) for the identifier carried by the row. Key = current table.
// col = clickable column (often computed); srcCol = column carrying the id;
// db/table/idCol = edited target.
interface GridLinkSpec { col: string; srcCol: string; db: string; table: string; idCol: string }
const GRID_LINK_COLUMNS: Record<string, GridLinkSpec[]> = {
  ASSETVULNERABILITY: [
    // AssetName → edits the corresponding ASSET (XORCISM)
    { col: "AssetName", srcCol: "AssetID", db: "XORCISM", table: "ASSET", idCol: "AssetID" },
    // VULReferential → edits the corresponding VULNERABILITY (XVULNERABILITY)
    { col: "VULReferential", srcCol: "VulnerabilityID", db: "XVULNERABILITY", table: "VULNERABILITY", idCol: "VulnerabilityID" },
  ],
  // FindingName → edits this AUDITFINDING row itself (self-link); AuditName → edits the parent AUDIT
  AUDITFINDING: [
    { col: "FindingName", srcCol: "AuditFindingID", db: "XCOMPLIANCE", table: "AUDITFINDING", idCol: "AuditFindingID" },
    { col: "AuditName", srcCol: "AuditID", db: "XCOMPLIANCE", table: "AUDIT", idCol: "AuditID" },
  ],
  // DocumentName → edits this DOCUMENT row itself (self-link).
  DOCUMENT: [
    { col: "DocumentName", srcCol: "DocumentID", db: "XCOMPLIANCE", table: "DOCUMENT", idCol: "DocumentID" },
  ],
  // Title → edits this BUGBOUNTYSUBMISSION row itself (self-link). PK is SubmissionID.
  BUGBOUNTYSUBMISSION: [
    { col: "Title", srcCol: "SubmissionID", db: "XVULNERABILITY", table: "BUGBOUNTYSUBMISSION", idCol: "SubmissionID" },
  ],
  // Title → edits this RISKREGISTERENTRY row itself (self-link). PK is RiskRegisterEntryID.
  RISKREGISTERENTRY: [
    { col: "Title", srcCol: "RiskRegisterEntryID", db: "XCOMPLIANCE", table: "RISKREGISTERENTRY", idCol: "RiskRegisterEntryID" },
  ],
  // Name → edits this BUGBOUNTYPROGRAM row itself (self-link). PK is ProgramID.
  BUGBOUNTYPROGRAM: [
    { col: "Name", srcCol: "ProgramID", db: "XVULNERABILITY", table: "BUGBOUNTYPROGRAM", idCol: "ProgramID" },
  ],
  // HuntName → edits this HUNT row itself (self-link). PK is HuntID (XTHREAT).
  HUNT: [
    { col: "HuntName", srcCol: "HuntID", db: "XTHREAT", table: "HUNT", idCol: "HuntID" },
  ],
  // SigmaRuleName → edits this SIGMARULE row itself (self-link). PK is SigmaRuleID (XTHREAT).
  SIGMARULE: [
    { col: "SigmaRuleName", srcCol: "SigmaRuleID", db: "XTHREAT", table: "SIGMARULE", idCol: "SigmaRuleID" },
  ],
  // IntelName → edits this INTELEXCHANGE row itself (self-link). PK is IntelID (XTHREAT).
  INTELEXCHANGE: [
    { col: "IntelName", srcCol: "IntelID", db: "XTHREAT", table: "INTELEXCHANGE", idCol: "IntelID" },
  ],
};
function getGridLink(table: string, col: string): GridLinkSpec | undefined {
  return (GRID_LINK_COLUMNS[table] ?? []).find((s) => s.col === col);
}

async function injectGridDisplayColumn(rows: Record<string, unknown>[]): Promise<void> {
  const specs = GRID_DISPLAY_COLUMNS[currentTable];
  if (!specs || !specs.length || !rows.length) return;
  // Large tables (lazy): lookup-one bounded to the visible rows; otherwise full map.
  const maps = await Promise.all(
    specs.map((s) => (s.lazy ? resolveLazyGridMap(s, rows) : getNameHintMap(s)))
  );
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(r)) {
      out[k] = v;
      specs.forEach((s, si) => {
        // Lookup key = keyCol (default srcCol); insertion position = after srcCol.
        if (k === s.srcCol) {
          const keyVal = r[s.keyCol ?? s.srcCol];
          out[s.colLabel] = gridDisplayValue(s, maps[si].get(String(keyVal)) ?? "");
        }
      });
    }
    // Source column absent: computed column at the end (with possible emptyLabel).
    specs.forEach((s, si) => {
      void si;
      if (!(s.colLabel in out)) out[s.colLabel] = gridDisplayValue(s, "");
    });
    rows[i] = out;
  }
}

// Inserts, right after each identifier field with a "name hint", a
// read-only label field. prefix = "f_" (insertion) or "ef_" (editing).
async function appendNameHints(prefix: string): Promise<void> {
  for (const col of schema) {
    const spec = getNameHint(currentTable, col.name);
    if (!spec) continue;
    const fieldDiv = document.getElementById(`${prefix}field_${col.name}`);
    const idInput = document.getElementById(`${prefix}${col.name}`) as HTMLInputElement | null;
    if (!fieldDiv || !idInput) continue;

    const div = document.createElement("div");
    div.id = `${prefix}field_${col.name}_namehint`;
    div.style.marginBottom = "10px";
    const label = document.createElement("label");
    label.textContent = spec.hintLabel;
    label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
    const out = document.createElement("input");
    out.id = `${prefix}${col.name}_namehint`;
    out.readOnly = true;
    out.tabIndex = -1;
    out.style.cssText =
      "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px;opacity:0.7";

    if (spec.lazy) {
      // Large table: on-demand resolution (1 request/identifier), cached + anti-stale.
      const cache = new Map<string, string | null>();
      let timer: number | undefined;
      const resolve = async () => {
        const v = (idInput.value || "").trim();
        if (!v) { out.value = ""; return; }
        if (cache.has(v)) { out.value = cache.get(v) ?? "(introuvable)"; return; }
        out.value = "…";
        try {
          const r = await api.getLookupOne(spec.db, spec.table, spec.idCol, v, spec.labelCol);
          const lbl = r.label == null ? null : String(r.label);
          cache.set(v, lbl);
          if ((idInput.value || "").trim() === v) out.value = lbl ?? "(introuvable)";
        } catch {
          if ((idInput.value || "").trim() === v) out.value = "";
        }
      };
      const debounced = () => {
        if (timer) clearTimeout(timer);
        timer = window.setTimeout(resolve, 300);
      };
      idInput.addEventListener("input", debounced);
      idInput.addEventListener("change", debounced);
      resolve(); // immediate on opening
    } else {
      // Small table: full preload (id → label).
      const map = await getNameHintMap(spec);
      const update = () => {
        const v = (idInput.value || "").trim();
        out.value = v ? (map.get(v) ?? "(introuvable)") : "";
      };
      idInput.addEventListener("input", update);
      idInput.addEventListener("change", update);
      update();
    }

    div.appendChild(label);
    div.appendChild(out);
    fieldDiv.after(div); // right after the identifier field
  }
}

// Builds a FK <select>: value = id, text = label, preselection on `selected`.
function mkFkSelect(
  id: string,
  options: { id: unknown; label: unknown }[],
  selected: string
): HTMLSelectElement {
  const sel = document.createElement("select");
  sel.id = id;
  sel.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "—";
  sel.appendChild(blank);
  options.forEach((o) => {
    const opt = document.createElement("option");
    opt.value = String(o.id);
    opt.textContent = o.label == null || o.label === "" ? String(o.id) : String(o.label);
    opt.style.background = "var(--surface)";
    if (String(o.id) === selected) opt.selected = true;
    sel.appendChild(opt);
  });
  if (!selected) blank.selected = true;
  return sel;
}

// Returns a copy of the schema reordered according to FIELD_REORDER (display only).
function reorderSchema(table: string, cols: ColumnInfo[]): ColumnInfo[] {
  const rules = FIELD_REORDER[table];
  if (!rules) return cols;
  const arr = cols.slice();
  for (const [moveName, afterName] of rules) {
    const mi = arr.findIndex((c) => c.name === moveName);
    if (mi < 0) continue;
    const [moved] = arr.splice(mi, 1);
    const ai = arr.findIndex((c) => c.name === afterName);
    if (ai < 0) arr.push(moved);
    else arr.splice(ai + 1, 0, moved);
  }
  return arr;
}

// Reordering of the columns in the GRID (key = table; rule [move, after]).
const GRID_FIELD_REORDER: Record<string, [string, string][]> = {
  // ToolURL shown just to the right of ToolDescription
  TOOL: [["ToolURL", "ToolDescription"]],
  // IncidentName shown just to the right of IncidentID
  INCIDENT: [["IncidentName", "IncidentID"]],
  // ApplicationID right of AssetApplicationID, then ApplicationGUID right of ApplicationID;
  // the resolved names (injected after their GUID) follow their GUID once it is moved.
  APPLICATIONFORASSET: [
    ["ApplicationID", "AssetApplicationID"], ["ApplicationGUID", "ApplicationID"],
    ["ApplicationName", "ApplicationGUID"], ["AssetName", "AssetGUID"],
  ],
  // AUDIT: the audit's own name shown just to the right of AuditDate.
  AUDIT: [["AuditName", "AuditDate"]],
};

// Column headers renamed for the grid DISPLAY (the real column and the
// sort/filter/reorder stay on the original name). Key "TABLE.Column" → label.
const GRID_COL_LABELS: Record<string, string> = {
  "ASSETVULNERABILITY.AssetVulnerabilityID": "AssetVulnID",
  "ASSETVULNERABILITY.EasilyExploitable": "EasilyExploit",
};
function gridColLabel(table: string, col: string): string {
  return GRID_COL_LABELS[`${table}.${col}`] ?? col;
}
function reorderGridCols(table: string, cols: string[]): string[] {
  const rules = GRID_FIELD_REORDER[table];
  if (!rules) return cols;
  const arr = cols.slice();
  for (const [moveName, afterName] of rules) {
    const mi = arr.indexOf(moveName);
    if (mi < 0) continue;
    const [moved] = arr.splice(mi, 1);
    const ai = arr.indexOf(afterName);
    if (ai < 0) arr.push(moved);
    else arr.splice(ai + 1, 0, moved);
  }
  return arr;
}

// ── Column reordering by the user (drag-and-drop, persistent) ──
// Custom order saved per table in localStorage (list of column names).
function colOrderKey(db: string, table: string): string {
  return `xorcism.colorder.${db}.${table}`;
}
function loadColOrder(db: string, table: string): string[] | null {
  try {
    const raw = localStorage.getItem(colOrderKey(db, table));
    if (!raw) return null;
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? (arr as string[]) : null;
  } catch {
    return null;
  }
}
function saveColOrder(db: string, table: string, order: string[]): void {
  try { localStorage.setItem(colOrderKey(db, table), JSON.stringify(order)); } catch { /* ignore */ }
}
// Clears the current table's custom column order → back to the default order.
function resetColOrder(): void {
  if (!currentDb || !currentTable) { toast(t("toast.selectTableFirst"), "err"); return; }
  try { localStorage.removeItem(colOrderKey(currentDb, currentTable)); } catch { /* ignore */ }
  loadRows(); // re-renders with the default order
  toast(t("explorer.colsReset") || "Ordre des colonnes réinitialisé", "ok");
}
// Applies the user order to the currently visible columns: known columns
// in the saved order first, then any new (unsaved) column at the end.
function applyUserColOrder(db: string, table: string, cols: string[]): string[] {
  const saved = loadColOrder(db, table);
  if (!saved || !saved.length) return cols;
  const present = new Set(cols);
  const known = saved.filter((c) => present.has(c));
  const savedSet = new Set(saved);
  const rest = cols.filter((c) => !savedSet.has(c));
  return [...known, ...rest];
}

// Makes a column header draggable (drag-and-drop) to reorder the grid.
// `cols` = current order of the displayed columns (captured at render). Persists + re-renders.
function makeColHeaderDraggable(th: HTMLElement, col: string, cols: string[]): void {
  th.draggable = true;
  th.addEventListener("dragstart", (e) => {
    e.dataTransfer?.setData("text/plain", col);
    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
    th.style.opacity = "0.4";
  });
  th.addEventListener("dragend", () => { th.style.opacity = ""; });
  th.addEventListener("dragover", (e) => {
    e.preventDefault(); // allows the drop
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
    th.style.borderLeft = "2px solid var(--accent)"; // visual insertion marker
  });
  th.addEventListener("dragleave", () => { th.style.borderLeft = ""; });
  th.addEventListener("drop", (e) => {
    e.preventDefault();
    th.style.borderLeft = "";
    const from = e.dataTransfer?.getData("text/plain") || "";
    if (!from || from === col) return;
    const order = cols.slice();
    const fi = order.indexOf(from);
    const ti = order.indexOf(col);
    if (fi < 0 || ti < 0) return;
    order.splice(fi, 1);
    const newTi = order.indexOf(col);
    order.splice(fi < ti ? newTi + 1 : newTi, 0, from); // after the target if moving down, before if moving up
    saveColOrder(currentDb, currentTable, order);
    renderTable(gridRows); // immediate local re-render with the new order
  });
}

function getEnumOptions(table: string, col: string): string[] | null {
  return ENUM_COLUMNS[`${table}.${col}`] ?? null;
}

// Dropdowns where the label differs from the stored value
// (e.g. Yes/No → 1/0). default = value preselected at insertion.
interface LabeledOption { label: string; value: string }
// Probability/impact scale (1–5) reused by the Risk Register fields.
const RISK_PI_OPTIONS: LabeledOption[] = [
  { label: "—", value: "" },
  { label: "Very Low (1)", value: "1" },
  { label: "Low (2)", value: "2" },
  { label: "Moderate (3)", value: "3" },
  { label: "High (4)", value: "4" },
  { label: "Very High (5)", value: "5" },
];

const VALUE_ENUM_COLUMNS: Record<string, { options: LabeledOption[]; default?: string }> = {
  // Risk Register: probability/impact (inherent, current, residual) on 1–5
  "RISKREGISTERENTRY.InherentProbability": { options: RISK_PI_OPTIONS },
  "RISKREGISTERENTRY.InherentImpact": { options: RISK_PI_OPTIONS },
  "RISKREGISTERENTRY.CurrentProbability": { options: RISK_PI_OPTIONS },
  "RISKREGISTERENTRY.CurrentImpact": { options: RISK_PI_OPTIONS },
  "RISKREGISTERENTRY.ResidualProbability": { options: RISK_PI_OPTIONS },
  "RISKREGISTERENTRY.ResidualImpact": { options: RISK_PI_OPTIONS },
  // Asset publicly exposed / on the Internet: Yes/No → 1/0, default No (0)
  "ASSET.PublicFacing": {
    options: [
      { label: "No", value: "0" },
      { label: "Yes", value: "1" },
    ],
    default: "0",
  },
  "INCIDENT.exercise": {
    options: [
      { label: "No", value: "0" },
      { label: "Yes", value: "1" },
    ],
    default: "0",
  },
  "INCIDENT.confirmed": {
    options: [
      { label: "No", value: "0" },
      { label: "Yes", value: "1" },
    ],
    default: "0",
  },
  "ASSETVULNERABILITY.AssetVulnerabilityStatusID": {
    options: [
      { label: "Unpatched", value: "0" },
      { label: "Patched", value: "1" },
    ],
    default: "0",
  },
  // Patch status: Unpatched/Patched → 0/1, default Unpatched (0)
  "ASSETVULNERABILITY.Status": {
    options: [
      { label: "Unpatched", value: "0" },
      { label: "Patched", value: "1" },
    ],
    default: "0",
  },
  "ASSET.TaskCriticalAsset": {
    options: [
      { label: "No", value: "0" },
      { label: "Yes", value: "1" },
    ],
    default: "0",
  },
  "ASSET.DefenseCriticalAsset": {
    options: [
      { label: "No", value: "0" },
      { label: "Yes", value: "1" },
    ],
    default: "0",
  },
  // Criticality level (stored text = label), default Low
  "ASSET.AssetCriticalityLevel": {
    options: [
      { label: "Critical", value: "Critical" },
      { label: "High", value: "High" },
      { label: "Medium", value: "Medium" },
      { label: "Low", value: "Low" },
    ],
    default: "Low",
  },
  // THREATAGENT: scale Very Low → Very High (stored text = label), default Low
  "THREATAGENT.Capability": {
    options: [
      { label: "Very Low", value: "Very Low" },
      { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" },
      { label: "High", value: "High" },
      { label: "Very High", value: "Very High" },
    ],
    default: "Low",
  },
  "THREATAGENT.Intent": {
    options: [
      { label: "Very Low", value: "Very Low" },
      { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" },
      { label: "High", value: "High" },
      { label: "Very High", value: "Very High" },
    ],
    default: "Low",
  },
  "THREATAGENT.Targeting": {
    options: [
      { label: "Very Low", value: "Very Low" },
      { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" },
      { label: "High", value: "High" },
      { label: "Very High", value: "Very High" },
    ],
    default: "Low",
  },
  // ── Threat models ──
  "THREATMODEL.Methodology": {
    options: [
      { label: "STRIDE", value: "STRIDE" }, { label: "PASTA", value: "PASTA" },
      { label: "DREAD", value: "DREAD" }, { label: "Attack Tree", value: "Attack Tree" },
      { label: "LINDDUN", value: "LINDDUN" }, { label: "VAST", value: "VAST" },
      { label: "Other", value: "Other" },
    ],
    default: "STRIDE",
  },
  "THREATMODEL.Status": {
    options: [
      { label: "Draft", value: "Draft" }, { label: "In Review", value: "In Review" },
      { label: "Approved", value: "Approved" }, { label: "Archived", value: "Archived" },
    ],
    default: "Draft",
  },
  "THREATMODEL.RiskLevel": {
    options: [
      { label: "Critical", value: "Critical" }, { label: "High", value: "High" },
      { label: "Medium", value: "Medium" }, { label: "Low", value: "Low" },
    ],
    default: "Medium",
  },
  "THREATMODELTHREAT.Likelihood": {
    options: [
      { label: "Very Low", value: "Very Low" }, { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" }, { label: "High", value: "High" },
      { label: "Very High", value: "Very High" },
    ],
    default: "Moderate",
  },
  "THREATMODELTHREAT.Impact": {
    options: [
      { label: "Very Low", value: "Very Low" }, { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" }, { label: "High", value: "High" },
      { label: "Very High", value: "Very High" },
    ],
    default: "Moderate",
  },
  "THREATMODELTHREAT.RiskScore": {
    options: [
      { label: "Critical", value: "Critical" }, { label: "High", value: "High" },
      { label: "Medium", value: "Medium" }, { label: "Low", value: "Low" },
    ],
    default: "Medium",
  },
  "THREATMODELTHREAT.Status": {
    options: [
      { label: "Open", value: "Open" }, { label: "Mitigated", value: "Mitigated" },
      { label: "Accepted", value: "Accepted" }, { label: "Transferred", value: "Transferred" },
    ],
    default: "Open",
  },
  "THREATMODELCONTROL.Status": {
    options: [
      { label: "Proposed", value: "Proposed" }, { label: "Implemented", value: "Implemented" },
      { label: "Verified", value: "Verified" },
    ],
    default: "Proposed",
  },
  // ── XCOMPLIANCE ──
  "AUDIT.AuditStatus": {
    options: [
      { label: "Planned", value: "Planned" }, { label: "In Progress", value: "In Progress" },
      { label: "Completed", value: "Completed" }, { label: "Closed", value: "Closed" },
    ],
    default: "Planned",
  },
  "AUDITFINDING.FindingStatus": {
    options: [
      { label: "Open", value: "Open" }, { label: "In Remediation", value: "In Remediation" },
      { label: "Resolved", value: "Resolved" }, { label: "Accepted", value: "Accepted" },
      { label: "Closed", value: "Closed" },
    ],
    default: "Open",
  },
  "AUDITFINDING.FindingCriticity": {
    options: [
      { label: "Critical", value: "Critical" }, { label: "High", value: "High" },
      { label: "Medium", value: "Medium" }, { label: "Low", value: "Low" },
      { label: "Informational", value: "Informational" },
    ],
    default: "Medium",
  },
  "AUDITREPORT.ReportStatus": {
    options: [
      { label: "Draft", value: "Draft" }, { label: "In Review", value: "In Review" },
      { label: "Final", value: "Final" }, { label: "Delivered", value: "Delivered" },
    ],
    default: "Draft",
  },
  // AUDITEVIDENCE: confidence level (text), 6 levels; empty allowed
  "AUDITEVIDENCE.ConfidenceLevel": {
    options: [
      { label: "—", value: "" },
      { label: "Very Low", value: "Very Low" }, { label: "Low", value: "Low" },
      { label: "Moderate", value: "Moderate" }, { label: "High", value: "High" },
      { label: "Very High", value: "Very High" }, { label: "Certain", value: "Certain" },
    ],
  },
  // ASSETPLATFORM: confidence level, scale 0–4, default Moderate (2)
  "ASSETPLATFORM.ConfidenceLevelID": {
    options: [
      { label: "Very Low", value: "0" }, { label: "Low", value: "1" },
      { label: "Moderate", value: "2" }, { label: "High", value: "3" },
      { label: "Very High", value: "4" },
    ],
    default: "2",
  },
  // THREATCAMPAIGN: scale 0–4 (empty allowed, no default imposed)
  "THREATCAMPAIGN.ConfidenceLevelID": {
    options: [
      { label: "—", value: "" },
      { label: "Very Low", value: "0" }, { label: "Low", value: "1" },
      { label: "Moderate", value: "2" }, { label: "High", value: "3" },
      { label: "Very High", value: "4" },
    ],
  },
  "THREATCAMPAIGN.ImportanceID": {
    options: [
      { label: "—", value: "" },
      { label: "Very Low", value: "0" }, { label: "Low", value: "1" },
      { label: "Moderate", value: "2" }, { label: "High", value: "3" },
      { label: "Very High", value: "4" },
    ],
  },
  // ── XTICKET ──
  "TICKET.Status": {
    options: [
      { label: "Open", value: "Open" }, { label: "In Progress", value: "In Progress" },
      { label: "On Hold", value: "On Hold" }, { label: "Resolved", value: "Resolved" },
      { label: "Closed", value: "Closed" }, { label: "Cancelled", value: "Cancelled" },
    ],
    default: "Open",
  },
  "TICKET.Priority": {
    options: [
      { label: "Low", value: "Low" }, { label: "Medium", value: "Medium" },
      { label: "High", value: "High" }, { label: "Urgent", value: "Urgent" },
    ],
    default: "Medium",
  },
  "TICKET.Severity": {
    options: [
      { label: "S1 - Critical", value: "S1-Critical" }, { label: "S2 - High", value: "S2-High" },
      { label: "S3 - Medium", value: "S3-Medium" }, { label: "S4 - Low", value: "S4-Low" },
    ],
    default: "S3-Medium",
  },
  "TICKET.TicketType": {
    options: [
      { label: "Incident", value: "Incident" }, { label: "Service Request", value: "Service Request" },
      { label: "Problem", value: "Problem" }, { label: "Change", value: "Change" },
      { label: "Question", value: "Question" },
    ],
    default: "Incident",
  },
  "TICKETCOMMENT.IsInternal": {
    options: [{ label: "No (visible to requester)", value: "0" }, { label: "Yes (internal note)", value: "1" }],
    default: "0",
  },
};

// Dropdowns (label ≠ value) by column NAME, valid in ALL
// tables (key in lowercase). Handy for the cross-cutting XORCISM columns.
const VALUE_ENUM_BY_COLUMN: Record<string, { options: LabeledOption[]; default?: string }> = {
  // Confidence level: scale 0–5, stored integer value, default Moderate (2)
  // Criticality: scale 0–5, stored integer value, default Moderate (2).
  // Applies to any column named Criticity (ASSETAUDITFINDING, ASSETTHREAT, THREAT…).
  criticity: {
    options: [
      { label: "Very Low", value: "0" },
      { label: "Low", value: "1" },
      { label: "Moderate", value: "2" },
      { label: "High", value: "3" },
      { label: "Very High", value: "4" },
      { label: "Critical", value: "5" },
    ],
    default: "2",
  },
  trustlevelid: {
    options: [
      { label: "Very Low", value: "0" },
      { label: "Low", value: "1" },
      { label: "Moderate", value: "2" },
      { label: "High", value: "3" },
      { label: "Very High", value: "4" },
      { label: "Certain", value: "5" },
    ],
    default: "2",
  },
  // Currency (any "Currency" column): USD/EUR first, USD by default.
  currency: {
    options: [
      { label: "USD", value: "USD" }, { label: "EUR", value: "EUR" },
      { label: "GBP", value: "GBP" }, { label: "CHF", value: "CHF" },
      { label: "JPY", value: "JPY" }, { label: "CAD", value: "CAD" },
      { label: "AUD", value: "AUD" }, { label: "CNY", value: "CNY" },
      { label: "INR", value: "INR" }, { label: "BRL", value: "BRL" },
      { label: "SEK", value: "SEK" }, { label: "NOK", value: "NOK" },
      { label: "SGD", value: "SGD" }, { label: "AED", value: "AED" },
    ],
    default: "USD",
  },
  // Confidence level: Very Low/Low/Moderate/High/Very High → 0/1/2/3/4.
  // Applies to any column named ConfidenceLevelID (THREAT, TOOL, VULNERABILITY…).
  confidencelevelid: {
    options: [
      { label: "Very Low", value: "0" },
      { label: "Low", value: "1" },
      { label: "Moderate", value: "2" },
      { label: "High", value: "3" },
      { label: "Very High", value: "4" },
    ],
    default: "2",
  },
  // Confidence reason: integer value 1–6, empty allowed (no default).
  trustreasonid: {
    options: [
      { label: "—", value: "" },
      { label: "Evidence", value: "1" },
      { label: "Logic", value: "2" },
      { label: "Verification", value: "3" },
      { label: "Consistency", value: "4" },
      { label: "Credibility", value: "5" },
      { label: "Corroboration", value: "6" },
    ],
  },
};

function getValueEnum(table: string, col: string) {
  return VALUE_ENUM_COLUMNS[`${table}.${col}`] ?? VALUE_ENUM_BY_COLUMN[col.toLowerCase()] ?? null;
}

// <select> whose options have label ≠ value.
function mkValueSelect(id: string, options: LabeledOption[], selected: string): HTMLSelectElement {
  const sel = document.createElement("select");
  sel.id = id;
  sel.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";
  options.forEach((o) => {
    const opt = document.createElement("option");
    opt.value = o.value;
    opt.textContent = o.label;
    opt.style.background = "var(--surface)";
    if (o.value === selected) opt.selected = true;
    sel.appendChild(opt);
  });
  return sel;
}

// Columns rendered as a CHECKBOX. Key "TABLE.Column".
// checked/unchecked = stored values; default = initial value at insertion.
interface CheckboxSpec { checked: string; unchecked: string; default: string }
const CHECKBOX_COLUMNS: Record<string, CheckboxSpec> = {
  "ASSET.Enabled": { checked: "1", unchecked: "0", default: "1" },
  "ASSET.personal": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.managedbythirdparty": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.hostedbythirdparty": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.virtual": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.ADParticipation": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.HostPII": { checked: "1", unchecked: "0", default: "0" },
  "ASSET.MFAEnabled": { checked: "1", unchecked: "0", default: "0" }, // MFA implemented? (boolean 0/1)
  "VULNERABILITY.Exploited": { checked: "1", unchecked: "0", default: "0" },
  "VULNERABILITY.EasilyExploitable": { checked: "1", unchecked: "0", default: "0" },
  "VULNERABILITY.KEV": { checked: "1", unchecked: "0", default: "0" },
  "VULNERABILITY.FalsePositive": { checked: "1", unchecked: "0", default: "0" },
  "INCIDENTFORASSET.Compromised": { checked: "1", unchecked: "0", default: "0" },
  "ASSETVULNERABILITY.TotalControl": { checked: "1", unchecked: "0", default: "0" },
  "ASSETVULNERABILITY.FalsePositive": { checked: "1", unchecked: "0", default: "0" },
};

// ── OpenCTI/STIX properties on the XTHREAT tables (adapted by ensureOpenctiColumns) ──
// Bulk injection: TLP marking (list + color), Confidence/Score (OpenCTI scale),
// Revoked/Detection/Negative (checkboxes), Sighting → IOC (dropdown).
const OPENCTI_TLP_VALUES = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];
const OPENCTI_CONFIDENCE_PRESETS = ["100", "85", "75", "50", "15", "0"]; // OpenCTI confidence scale
const OPENCTI_TLP_COLORS: Record<string, string> = {
  "TLP:RED": "var(--danger)", "TLP:AMBER": "#f59e0b", "TLP:AMBER+STRICT": "#f59e0b",
  "TLP:GREEN": "#22c55e", "TLP:CLEAR": "var(--text-dim)",
};
// Workflow status (OpenCTI): values + grid colors.
const OPENCTI_WORKFLOW_VALUES = ["New", "In progress", "Analyzed", "Closed"];
const OPENCTI_WORKFLOW_COLORS: Record<string, string> = {
  "New": "#3b82f6", "In progress": "#f59e0b", "Analyzed": "#2dd4bf", "Closed": "#22c55e",
};
// STIX observable types (SCO) — OBSERVABLE.ObservableType.
const STIX_SCO_TYPES = [
  "ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr", "email-message",
  "mac-addr", "user-account", "windows-registry-key", "autonomous-system", "mutex",
  "process", "software", "x509-certificate", "directory", "network-traffic", "artifact",
];
const OPENCTI_ENTITY_TABLES = [
  "THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKGROUP", "ATTACKSOFTWARE",
  "ATTACKTECHNIQUE", "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "IOC", "RELATIONSHIP",
  "SIGHTING", "OBSERVABLE", "THREATREPORT",
];
for (const t of OPENCTI_ENTITY_TABLES) {
  STATIC_DATALIST_COLUMNS[`${t}.TLP`] = OPENCTI_TLP_VALUES;
  STATIC_DATALIST_DEFAULTS[`${t}.TLP`] = "TLP:AMBER";
  STATIC_DATALIST_COLUMNS[`${t}.Confidence`] = OPENCTI_CONFIDENCE_PRESETS;
  GRID_VALUE_COLORS[`${t}.TLP`] = OPENCTI_TLP_COLORS;
}
for (const t of ["THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKGROUP", "ATTACKSOFTWARE",
  "ATTACKTECHNIQUE", "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "IOC", "RELATIONSHIP", "THREATREPORT"]) {
  CHECKBOX_COLUMNS[`${t}.Revoked`] = { checked: "1", unchecked: "0", default: "0" };
}
// Workflow status (entities + indicators): dropdown + default + colors.
for (const t of ["THREAT", "THREATACTOR", "THREATCAMPAIGN", "ATTACKGROUP", "ATTACKSOFTWARE",
  "ATTACKTECHNIQUE", "ATTACKMITIGATION", "HUNT", "HYPOTHESIS", "IOC", "THREATREPORT"]) {
  STATIC_DATALIST_COLUMNS[`${t}.WorkflowStatus`] = OPENCTI_WORKFLOW_VALUES;
  STATIC_DATALIST_DEFAULTS[`${t}.WorkflowStatus`] = "New";
  GRID_VALUE_COLORS[`${t}.WorkflowStatus`] = OPENCTI_WORKFLOW_COLORS;
}
STATIC_DATALIST_COLUMNS["IOC.Score"] = OPENCTI_CONFIDENCE_PRESETS;
STATIC_DATALIST_COLUMNS["OBSERVABLE.Score"] = OPENCTI_CONFIDENCE_PRESETS;
STATIC_DATALIST_COLUMNS["OBSERVABLE.ObservableType"] = STIX_SCO_TYPES;
CHECKBOX_COLUMNS["ASSET.Backed"] = { checked: "1", unchecked: "0", default: "0" }; // backed up? (boolean 0/1)
CHECKBOX_COLUMNS["IOC.Detection"] = { checked: "1", unchecked: "0", default: "0" };
CHECKBOX_COLUMNS["SIGHTING.Negative"] = { checked: "1", unchecked: "0", default: "0" };
FK_COLUMNS["SIGHTING.IOCID"] = { db: "XTHREAT", table: "IOC", idCol: "IOCID", labelCol: "IOCName", distinct: true };
// "based-on" relationship: indicator (IOC) ↔ observable.
FK_COLUMNS["INDICATOROBSERVABLE.IOCID"] = { db: "XTHREAT", table: "IOC", idCol: "IOCID", labelCol: "IOCName", distinct: true };
FK_COLUMNS["INDICATOROBSERVABLE.ObservableID"] = { db: "XTHREAT", table: "OBSERVABLE", idCol: "ObservableID", labelCol: "Value", distinct: true };
// THREATREPORT author → PERSON (cross-database FK to XORCISM.PERSON).
FK_COLUMNS["THREATREPORT.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "Author" };
FK_COLUMNS["AUDITFINDINGREMEDIATION.AuditFindingID"] = { db: "XCOMPLIANCE", table: "AUDITFINDING", idCol: "AuditFindingID", labelCol: "FindingName", distinct: true };
FK_COLUMNS["AUDITFINDINGREMEDIATION.OwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };

// Labels columns handled by a chip selector (reuses the ASSET tag-picker UX).
const OPENCTI_LABEL_TABLES = new Set([...OPENCTI_ENTITY_TABLES]);
function isLabelsField(table: string, col: string): boolean {
  return col === "Labels" && OPENCTI_LABEL_TABLES.has(table);
}

// ── Adversary emulation / security validation (BAS — AttackIQ/OpenBAS-like) ──
const BAS_OUTCOMES: LabeledOption[] = [
  { value: "Prevented", label: "Prevented" }, { value: "Blocked", label: "Blocked" },
  { value: "Detected", label: "Detected" }, { value: "Alerted", label: "Alerted" },
  { value: "Logged", label: "Logged" }, { value: "No result", label: "No result" },
];
VALUE_ENUM_COLUMNS["EMULATIONRESULT.Outcome"] = { options: BAS_OUTCOMES };
GRID_VALUE_COLORS["EMULATIONRESULT.Outcome"] = {
  Prevented: "#22c55e", Blocked: "#22c55e", Detected: "#2dd4bf", Alerted: "#2dd4bf",
  Logged: "#f59e0b", "No result": "var(--danger)",
};
STATIC_DATALIST_COLUMNS["ATOMICTEST.Executor"] = ["command_prompt", "powershell", "sh", "bash", "python", "manual"];
STATIC_DATALIST_COLUMNS["ATOMICTEST.Platform"] = ["windows", "linux", "macos", "containers", "cloud", "network", "office-365", "azure-ad"];
STATIC_DATALIST_COLUMNS["EMULATIONSCENARIO.Status"] = ["Draft", "Ready", "Scheduled", "Running", "Completed", "Archived"];
STATIC_DATALIST_DEFAULTS["EMULATIONSCENARIO.Status"] = "Draft";
STATIC_DATALIST_COLUMNS["EMULATIONRUN.Status"] = ["Scheduled", "Running", "Completed", "Failed"];
STATIC_DATALIST_DEFAULTS["EMULATIONRUN.Status"] = "Scheduled";
FK_COLUMNS["SCENARIOTEST.ScenarioID"] = { db: "XTHREAT", table: "EMULATIONSCENARIO", idCol: "ScenarioID", labelCol: "Name", distinct: true };
FK_COLUMNS["SCENARIOTEST.AtomicTestID"] = { db: "XTHREAT", table: "ATOMICTEST", idCol: "AtomicTestID", labelCol: "Name", distinct: true };
FK_COLUMNS["EMULATIONRUN.ScenarioID"] = { db: "XTHREAT", table: "EMULATIONSCENARIO", idCol: "ScenarioID", labelCol: "Name", distinct: true };
FK_COLUMNS["EMULATIONRUN.TargetAssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
FK_COLUMNS["EMULATIONRESULT.RunID"] = { db: "XTHREAT", table: "EMULATIONRUN", idCol: "RunID", labelCol: "Name", distinct: true };
FK_COLUMNS["EMULATIONRESULT.AtomicTestID"] = { db: "XTHREAT", table: "ATOMICTEST", idCol: "AtomicTestID", labelCol: "Name", distinct: true };
// PIR — Priority Intelligence Requirements (CTI tasking): priority/status dropdowns + owner.
STATIC_DATALIST_COLUMNS["PIR.Priority"] = ["Critical", "High", "Medium", "Low"];
STATIC_DATALIST_DEFAULTS["PIR.Priority"] = "Medium";
STATIC_DATALIST_COLUMNS["PIR.Status"] = ["Active", "Satisfied", "On Hold", "Retired", "Draft"];
STATIC_DATALIST_DEFAULTS["PIR.Status"] = "Active";
FK_COLUMNS["PIR.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
// ASSETCONTROL — asset↔control mapping: FK pickers (asset/control/owner) + status & confidence dropdowns.
FK_COLUMNS["ASSETCONTROL.AssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
FK_COLUMNS["ASSETCONTROL.ControlID"] = { db: "XORCISM", table: "CONTROL", idCol: "ControlID", labelCol: "ControlName", distinct: true };
FK_COLUMNS["ASSETCONTROL.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
STATIC_DATALIST_COLUMNS["ASSETCONTROL.Status"] = ["Planned", "Implemented", "Partial", "Verified", "Failed", "Not Applicable", "Retired"];
STATIC_DATALIST_DEFAULTS["ASSETCONTROL.Status"] = "Planned";
STATIC_DATALIST_COLUMNS["ASSETCONTROL.ConfidenceLevel"] = ["High", "Medium", "Low"];
STATIC_DATALIST_DEFAULTS["ASSETCONTROL.ConfidenceLevel"] = "Medium";

// BACKUPPLAN — backup & recovery plan for an asset: FK pickers (asset/owner) + type/schedule/status dropdowns.
FK_COLUMNS["BACKUPPLAN.AssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
FK_COLUMNS["BACKUPPLAN.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "Owner", distinct: true };
STATIC_DATALIST_COLUMNS["BACKUPPLAN.Type"] = ["Manual", "Automated", "Full", "Incremental", "Differential", "Snapshot", "Continuous", "Cloud", "Offsite", "Tape"];
STATIC_DATALIST_DEFAULTS["BACKUPPLAN.Type"] = "Automated";
STATIC_DATALIST_COLUMNS["BACKUPPLAN.FrequencyUnit"] = ["Hours", "Days", "Weeks", "Months"];
STATIC_DATALIST_DEFAULTS["BACKUPPLAN.FrequencyUnit"] = "Days";
STATIC_DATALIST_COLUMNS["BACKUPPLAN.StorageLocation"] = ["On-site", "Offsite", "Cloud", "Tape", "NAS", "SAN", "Immutable", "Air-gapped"];
STATIC_DATALIST_COLUMNS["BACKUPPLAN.Status"] = ["Planned", "Active", "Tested", "Failed", "Suspended", "Retired"];
STATIC_DATALIST_DEFAULTS["BACKUPPLAN.Status"] = "Active";
// Close the loop: ASSET.BackupPlanID picks a named plan from BACKUPPLAN.
FK_COLUMNS["ASSET.BackupPlanID"] = { db: "XORCISM", table: "BACKUPPLAN", idCol: "BackupPlanID", labelCol: "BackupPlanName", searchLabel: "Backup plan", distinct: true };

// IDENTITY (IAM) — human + non-human identity registry: owner/asset FK pickers + governance dropdowns.
FK_COLUMNS["IDENTITY.OwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", searchLabel: "Owner", distinct: true };
FK_COLUMNS["IDENTITY.AssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
STATIC_DATALIST_COLUMNS["IDENTITY.IdentityType"] = ["Human", "AI Agent", "API", "Container", "Service Account", "Hardcoded Credential", "Certificate", "Device", "Workload", "Bot", "Token", "Service Principal"];
STATIC_DATALIST_DEFAULTS["IDENTITY.IdentityType"] = "Service Account";
STATIC_DATALIST_COLUMNS["IDENTITY.IdentityClass"] = ["Human", "Non-Human"];
STATIC_DATALIST_DEFAULTS["IDENTITY.IdentityClass"] = "Non-Human";
STATIC_DATALIST_COLUMNS["IDENTITY.Status"] = ["Active", "Inactive", "Disabled", "Orphaned", "Compromised", "Retired"];
STATIC_DATALIST_DEFAULTS["IDENTITY.Status"] = "Active";
STATIC_DATALIST_COLUMNS["IDENTITY.PrivilegeLevel"] = ["Standard", "Privileged", "Admin", "Root", "Owner"];
STATIC_DATALIST_DEFAULTS["IDENTITY.PrivilegeLevel"] = "Standard";
STATIC_DATALIST_COLUMNS["IDENTITY.Environment"] = ["Production", "Staging", "Development", "Test"];
STATIC_DATALIST_COLUMNS["IDENTITY.CredentialType"] = ["None", "Password", "API Key", "Certificate", "Token", "SSH Key", "OAuth Secret"];
STATIC_DATALIST_COLUMNS["IDENTITY.MFAEnabled"] = ["Yes", "No", "N/A"];
STATIC_DATALIST_COLUMNS["IDENTITY.RiskLevel"] = ["Critical", "High", "Medium", "Low"];
STATIC_DATALIST_COLUMNS["IDENTITY.Provider"] = ["Entra ID", "Okta", "Active Directory", "AWS IAM", "GCP IAM", "Azure", "Kubernetes", "GitHub", "GitLab", "HashiCorp Vault", "Manual"];
// IDENTITYPERSON — human identity ↔ person mapping.
FK_COLUMNS["IDENTITYPERSON.IdentityID"] = { db: "XORCISM", table: "IDENTITY", idCol: "IdentityID", labelCol: "IdentityName", distinct: true };
FK_COLUMNS["IDENTITYPERSON.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
STATIC_DATALIST_COLUMNS["IDENTITYPERSON.RelationshipType"] = ["Owner", "Primary", "Member", "Delegate", "Manager"];
STATIC_DATALIST_DEFAULTS["IDENTITYPERSON.RelationshipType"] = "Owner";

// SSVC (CISA Stakeholder-Specific Vulnerability Categorization) — decision-point
// dropdowns on the VULNERABILITY form (the inline calculator computes SsvcDecision).
STATIC_DATALIST_COLUMNS["VULNERABILITY.SsvcExploitation"] = ["none", "public poc", "active"];
STATIC_DATALIST_COLUMNS["VULNERABILITY.SsvcAutomatable"] = ["no", "yes"];
STATIC_DATALIST_COLUMNS["VULNERABILITY.SsvcTechnicalImpact"] = ["partial", "total"];
STATIC_DATALIST_COLUMNS["VULNERABILITY.SsvcMissionWellbeing"] = ["low", "medium", "high"];
STATIC_DATALIST_DEFAULTS["VULNERABILITY.SsvcMissionWellbeing"] = "medium";
STATIC_DATALIST_COLUMNS["VULNERABILITY.SsvcDecision"] = ["Track", "Track*", "Attend", "Act"];

// OpenCTI properties on the emulation scenario (TLP / Confidence / Labels).
STATIC_DATALIST_COLUMNS["EMULATIONSCENARIO.TLP"] = OPENCTI_TLP_VALUES;
STATIC_DATALIST_DEFAULTS["EMULATIONSCENARIO.TLP"] = "TLP:AMBER";
GRID_VALUE_COLORS["EMULATIONSCENARIO.TLP"] = OPENCTI_TLP_COLORS;
STATIC_DATALIST_COLUMNS["EMULATIONSCENARIO.Confidence"] = OPENCTI_CONFIDENCE_PRESETS;
OPENCTI_LABEL_TABLES.add("EMULATIONSCENARIO");

// ── Advanced GRC: policy lifecycle, findings workflow, CRQ/FAIR ─────────
const GRC_POLICY_STATUS = ["Draft", "In review", "Approved", "Published", "Retired"];
const GRC_POLICY_COLORS: Record<string, string> = {
  "Draft": "#64748b", "In review": "#f59e0b", "Approved": "#2dd4bf", "Published": "#22c55e", "Retired": "var(--danger)",
};
const GRC_SEVERITY = ["Critical", "High", "Medium", "Low", "Info"];
const GRC_SEVERITY_COLORS: Record<string, string> = {
  Critical: "var(--danger)", High: "#f59e0b", Medium: "#eab308", Low: "#22c55e", Info: "#64748b",
};
for (const col of ["Status", "WorkflowStatus"]) {
  STATIC_DATALIST_COLUMNS[`POLICY.${col}`] = GRC_POLICY_STATUS;
  STATIC_DATALIST_DEFAULTS[`POLICY.${col}`] = "Draft";
  GRID_VALUE_COLORS[`POLICY.${col}`] = GRC_POLICY_COLORS;
}
STATIC_DATALIST_COLUMNS["AUDITFINDING.WorkflowStatus"] = OPENCTI_WORKFLOW_VALUES;
STATIC_DATALIST_DEFAULTS["AUDITFINDING.WorkflowStatus"] = "New";
GRID_VALUE_COLORS["AUDITFINDING.WorkflowStatus"] = OPENCTI_WORKFLOW_COLORS;
STATIC_DATALIST_COLUMNS["AUDITFINDING.Severity"] = GRC_SEVERITY;
GRID_VALUE_COLORS["AUDITFINDING.Severity"] = GRC_SEVERITY_COLORS;
for (const t of ["RISKREGISTERENTRY", "RISKSCENARIO"]) STATIC_DATALIST_COLUMNS[`${t}.Currency`] = ["EUR", "USD", "GBP", "CHF"];
FK_COLUMNS["POLICY.OwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
FK_COLUMNS["POLICY.ApprovedByPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
FK_COLUMNS["AUDITFINDING.RemediationOwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };

// ── Policy & document management metadata (ISO 42001 / 27001 / NIST AI RMF …) ──
const DOC_LANGUAGES = ["en", "fr", "de", "es", "it", "nl", "pt", "ar"];
const DOC_FRAMEWORKS = ["ISO/IEC 42001:2023", "ISO/IEC 27001:2022", "ISO/IEC 27031:2011", "ISO/IEC 27701:2019", "NIST AI RMF 1.0", "NIST SP 800-53", "Secure Controls Framework (SCF)", "CSA CCM v4", "CSA AI Controls Matrix (AICM) v1.1", "OWASP ASVS 4.0.3", "PCI DSS v4.0", "ITMG IRCF v1.0", "CRI Profile v2.2", "EU AI Act", "DORA (EU 2022/2554)", "NIS2", "Référentiel Cyber France (ReCyF)", "SOC 2", "GDPR", "Data (Use and Access) Act 2025 (DUAA)", "CISA Zero Trust Maturity Model v2.0", "DoD Zero Trust", "HDS (Hébergeur de Données de Santé)", "TISAX (VDA-ISA)", "ACSC ISM", "ASD Essential Eight", "Databricks DASF", "MLASVS (MLASTG)", "OWASP SPVS 1.0", "OWASP SPVS 1.5-AI", "OWASP AISVS 1.0", "CMMC 2.0", "ISO/SAE 21434:2021", "ASD AI/ML Supply Chain (2025)"];
const DOC_CLASSIFICATION = ["Public", "Internal", "Confidential", "Restricted"];
const DOC_CATEGORIES = ["AI Management System", "Information Security", "Privacy", "Data Governance", "Risk Management", "Operations", "Human Resources"];
const DOC_TYPES = ["Policy", "Procedure", "Standard", "Guideline", "Record", "Report", "Evidence", "Form", "Plan"];
// Data-sensitivity labels + TLP 2.0 sharing markers (colour-coded badges in the grid).
const DOC_CLASSIFICATION_COLORS: Record<string, string> = {
  Public: "#34d399", Internal: "#60a5fa", Confidential: "#fbbf24", Restricted: "#f87171",
};
const DOC_TLP = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];
const DOC_TLP_COLORS: Record<string, string> = {
  "TLP:CLEAR": "#94a3b8", "TLP:GREEN": "#34d399", "TLP:AMBER": "#fbbf24", "TLP:AMBER+STRICT": "#fb923c", "TLP:RED": "#f87171",
};
for (const t of ["POLICY", "DOCUMENT"]) {
  STATIC_DATALIST_COLUMNS[`${t}.Category`] = DOC_CATEGORIES;
  STATIC_DATALIST_COLUMNS[`${t}.Framework`] = DOC_FRAMEWORKS;
  STATIC_DATALIST_COLUMNS[`${t}.Language`] = DOC_LANGUAGES;
  STATIC_DATALIST_DEFAULTS[`${t}.Language`] = "en";
  STATIC_DATALIST_COLUMNS[`${t}.Classification`] = DOC_CLASSIFICATION;
  GRID_VALUE_COLORS[`${t}.Classification`] = DOC_CLASSIFICATION_COLORS;
  STATIC_DATALIST_COLUMNS[`${t}.TLP`] = DOC_TLP;
  GRID_VALUE_COLORS[`${t}.TLP`] = DOC_TLP_COLORS;
}
// Admiralty / NATO source grading (STANAG 2511) on intel exchanges, reports & actors — reliability A-F, credibility 1-6.
for (const t of ["INTELEXCHANGE", "THREATREPORT", "THREATACTOR", "THREATCAMPAIGN"]) {
  STATIC_DATALIST_COLUMNS[`${t}.SourceReliability`] = ["A", "B", "C", "D", "E", "F"];
  STATIC_DATALIST_COLUMNS[`${t}.InfoCredibility`] = ["1", "2", "3", "4", "5", "6"];
}
// TaHiTI threat-hunting methodology (Targeted Hunting integrating Threat Intelligence) on HUNT.
STATIC_DATALIST_COLUMNS["HUNT.TahitiPhase"] = ["Initiate", "Hunt", "Finalize"];
STATIC_DATALIST_COLUMNS["HUNT.TahitiTrigger"] = ["Threat Intelligence", "Security Monitoring", "Other Hunt", "Red Teaming", "Security Incident", "Vulnerability / Threat Landscape", "Crown Jewel Analysis"];
STATIC_DATALIST_DEFAULTS["HUNT.TahitiPhase"] = "Initiate";
STATIC_DATALIST_COLUMNS["DOCUMENT.Status"] = GRC_POLICY_STATUS;
STATIC_DATALIST_DEFAULTS["DOCUMENT.Status"] = "Draft";
GRID_VALUE_COLORS["DOCUMENT.Status"] = GRC_POLICY_COLORS;
STATIC_DATALIST_COLUMNS["DOCUMENT.DocumentType"] = DOC_TYPES;
FK_COLUMNS["DOCUMENT.OwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
FK_COLUMNS["DOCUMENT.RelatedPolicyID"] = { db: "XORCISM", table: "POLICY", idCol: "PolicyID", labelCol: "PolicyName", distinct: true };
// ISO documentation pyramid: a governed POLICY record is a Policy / Standard / Procedure / Guideline,
// and ParentPolicyID links a child to the document it implements (Procedure → Standard → Policy).
STATIC_DATALIST_COLUMNS["POLICY.DocumentType"] = ["Policy", "Standard", "Procedure", "Guideline"];
STATIC_DATALIST_DEFAULTS["POLICY.DocumentType"] = "Policy";
FK_COLUMNS["POLICY.ParentPolicyID"] = { db: "XORCISM", table: "POLICY", idCol: "PolicyID", labelCol: "PolicyName", distinct: true };
// PERSON org-chart / directory fields (Entra ID / AD aligned) — see /org-chart.
FK_COLUMNS["PERSON.ManagerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
STATIC_DATALIST_COLUMNS["PERSON.EmployeeType"] = ["Employee", "Contractor", "Vendor", "Intern", "Service Account", "Guest"];

// ── Defender XDR-aligned incident & alert metadata (XINCIDENT.ALERT / INCIDENT) ──
const DEFENDER_SEVERITY = ["High", "Medium", "Low", "Informational"];
const DEFENDER_SEVERITY_COLORS: Record<string, string> = {
  High: "var(--danger)", Medium: "#f59e0b", Low: "#eab308", Informational: "#64748b",
};
const ALERT_STATUS = ["New", "In progress", "Resolved"];
const ALERT_STATUS_COLORS: Record<string, string> = { New: "#3b82f6", "In progress": "#f59e0b", Resolved: "#22c55e" };
const DEFENDER_CLASSIFICATION = ["True positive", "Informational, expected activity", "False positive", "Not set"];
const DEFENDER_CLASSIFICATION_COLORS: Record<string, string> = {
  "True positive": "var(--danger)", "Informational, expected activity": "#64748b",
  "False positive": "#22c55e", "Not set": "#64748b",
};
const DEFENDER_DETERMINATION = ["Multistage attack", "Malicious user activity", "Compromised account", "Malware",
  "Phishing", "Unwanted software", "Security testing", "Line-of-business application", "Confirmed activity",
  "Not malicious", "Not enough data to validate", "Other"];
const DEFENDER_DETECTION_SOURCE = ["Manual", "Antivirus", "EDR", "Automated investigation", "Custom detection",
  "SIEM", "Threat intelligence", "Cloud apps", "Other"];
const DEFENDER_CATEGORY = ["Reconnaissance", "Resource development", "Initial access", "Execution", "Persistence",
  "Privilege escalation", "Defense evasion", "Credential access", "Discovery", "Lateral movement", "Collection",
  "Command and control", "Exfiltration", "Impact", "Malware", "Ransomware", "Unwanted software", "Suspicious activity", "Other"];
for (const tbl of ["ALERT", "INCIDENT"]) {
  STATIC_DATALIST_COLUMNS[`${tbl}.Severity`] = DEFENDER_SEVERITY;
  GRID_VALUE_COLORS[`${tbl}.Severity`] = DEFENDER_SEVERITY_COLORS;
  STATIC_DATALIST_COLUMNS[`${tbl}.Classification`] = DEFENDER_CLASSIFICATION;
  GRID_VALUE_COLORS[`${tbl}.Classification`] = DEFENDER_CLASSIFICATION_COLORS;
  STATIC_DATALIST_COLUMNS[`${tbl}.Determination`] = DEFENDER_DETERMINATION;
}
STATIC_DATALIST_COLUMNS["ALERT.Status"] = ALERT_STATUS;
STATIC_DATALIST_DEFAULTS["ALERT.Status"] = "New";
GRID_VALUE_COLORS["ALERT.Status"] = ALERT_STATUS_COLORS;
STATIC_DATALIST_COLUMNS["ALERT.Category"] = DEFENDER_CATEGORY;
STATIC_DATALIST_COLUMNS["ALERT.DetectionSource"] = DEFENDER_DETECTION_SOURCE;
STATIC_DATALIST_DEFAULTS["ALERT.DetectionSource"] = "Manual";
STATIC_DATALIST_COLUMNS["ALERT.ServiceSource"] = ["XORCISM", "Microsoft Defender XDR", "Microsoft Sentinel", "Other"];
STATIC_DATALIST_DEFAULTS["ALERT.ServiceSource"] = "XORCISM";
// "Assigned to" (owner) suggestions from PERSON for both tables.
FK_COLUMNS["ALERT.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
// Defender "Select entities": impacted-assets junction + related evidence (browsable, FK-linked).
FK_COLUMNS["ALERTFORASSET.AlertID"] = { db: "XINCIDENT", table: "ALERT", idCol: "AlertID", labelCol: "AlertName", distinct: true };
FK_COLUMNS["ALERTFORASSET.AssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
FK_COLUMNS["ALERTEVIDENCE.AlertID"] = { db: "XINCIDENT", table: "ALERT", idCol: "AlertID", labelCol: "AlertName", distinct: true };
STATIC_DATALIST_COLUMNS["ALERTEVIDENCE.EvidenceType"] = ["File", "File hash", "Process", "URL", "IP address",
  "Domain", "Email", "Mailbox", "User account", "Registry key", "Command line", "Other"];
// ── ALERT form polish: prominent alert title, wide modal, parent-incident picker,
//    date-only CreatedDate, assigned-to autocomplete, and a MITRE ATT&CK technique picker. ──
PROMINENT_INPUT_COLUMNS.add("ALERT.AlertName");
WIDE_MODAL_TABLES.add("ALERT");
FK_COLUMNS["ALERT.IncidentID"] = { db: "XINCIDENT", table: "INCIDENT", idCol: "IncidentID", labelCol: "IncidentName", distinct: true };
DATALIST_COLUMNS["ALERT.AssignedTo"] = { db: "XORCISM", table: "PERSON", labelCol: "FullName" };

// ── Bug bounty (XVULNERABILITY): platforms, statuses, scope, rewards ────
STATIC_DATALIST_COLUMNS["BUGBOUNTYPROGRAM.Platform"] = ["HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Synack", "Open Bug Bounty", "Self-hosted", "Other"];
STATIC_DATALIST_COLUMNS["BUGBOUNTYRESEARCHER.Platform"] = ["HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Synack", "Open Bug Bounty", "Self-hosted", "Other"];
const BB_PROGRAM_STATUS = ["Draft", "Private", "Public", "Paused", "Closed"];
const BB_PROGRAM_COLORS: Record<string, string> = { Draft: "#64748b", Private: "#f59e0b", Public: "#22c55e", Paused: "#eab308", Closed: "var(--danger)" };
STATIC_DATALIST_COLUMNS["BUGBOUNTYPROGRAM.Status"] = BB_PROGRAM_STATUS;
STATIC_DATALIST_DEFAULTS["BUGBOUNTYPROGRAM.Status"] = "Draft";
GRID_VALUE_COLORS["BUGBOUNTYPROGRAM.Status"] = BB_PROGRAM_COLORS;
const BB_SUB_STATUS = ["New", "Triaging", "Triaged", "Accepted", "Duplicate", "Informative", "Not applicable", "Resolved", "Disclosed"];
const BB_SUB_COLORS: Record<string, string> = {
  New: "#3b82f6", Triaging: "#f59e0b", Triaged: "#eab308", Accepted: "#2dd4bf",
  Resolved: "#22c55e", Disclosed: "#22c55e", Duplicate: "#64748b", Informative: "#64748b", "Not applicable": "var(--danger)",
};
STATIC_DATALIST_COLUMNS["BUGBOUNTYSUBMISSION.Status"] = BB_SUB_STATUS;
STATIC_DATALIST_DEFAULTS["BUGBOUNTYSUBMISSION.Status"] = "New";
GRID_VALUE_COLORS["BUGBOUNTYSUBMISSION.Status"] = BB_SUB_COLORS;
for (const t of ["BUGBOUNTYSUBMISSION", "BUGBOUNTYREWARDTIER"]) {
  STATIC_DATALIST_COLUMNS[`${t}.Severity`] = GRC_SEVERITY;
  GRID_VALUE_COLORS[`${t}.Severity`] = GRC_SEVERITY_COLORS;
}
STATIC_DATALIST_COLUMNS["BUGBOUNTYSCOPE.ScopeType"] = ["in-scope", "out-of-scope"];
GRID_VALUE_COLORS["BUGBOUNTYSCOPE.ScopeType"] = { "in-scope": "#22c55e", "out-of-scope": "var(--danger)" };
STATIC_DATALIST_COLUMNS["BUGBOUNTYSCOPE.AssetType"] = ["web", "api", "mobile", "desktop", "iot", "source-code", "cloud", "network", "hardware"];
STATIC_DATALIST_COLUMNS["BUGBOUNTYREWARD.RewardType"] = ["bounty", "bonus", "swag", "kudos", "points"];
const BB_REWARD_STATUS = ["Pending", "Approved", "Paid", "Rejected"];
STATIC_DATALIST_COLUMNS["BUGBOUNTYREWARD.Status"] = BB_REWARD_STATUS;
STATIC_DATALIST_DEFAULTS["BUGBOUNTYREWARD.Status"] = "Pending";
GRID_VALUE_COLORS["BUGBOUNTYREWARD.Status"] = { Pending: "#f59e0b", Approved: "#2dd4bf", Paid: "#22c55e", Rejected: "var(--danger)" };
for (const t of ["BUGBOUNTYPROGRAM", "BUGBOUNTYSUBMISSION", "BUGBOUNTYREWARD", "BUGBOUNTYREWARDTIER"]) {
  STATIC_DATALIST_COLUMNS[`${t}.Currency`] = ["EUR", "USD", "GBP", "CHF"];
}
FK_COLUMNS["BUGBOUNTYSCOPE.ProgramID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYPROGRAM", idCol: "ProgramID", labelCol: "Name", distinct: true };
FK_COLUMNS["BUGBOUNTYREWARDTIER.ProgramID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYPROGRAM", idCol: "ProgramID", labelCol: "Name", distinct: true };
FK_COLUMNS["BUGBOUNTYSUBMISSION.ProgramID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYPROGRAM", idCol: "ProgramID", labelCol: "Name", distinct: true };
FK_COLUMNS["BUGBOUNTYSUBMISSION.ResearcherID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYRESEARCHER", idCol: "ResearcherID", labelCol: "Handle", distinct: true };
FK_COLUMNS["BUGBOUNTYSUBMISSION.VulnerabilityID"] = { db: "XVULNERABILITY", table: "VULNERABILITY", idCol: "VulnerabilityID", labelCol: "VULReferential", distinct: true };
FK_COLUMNS["BUGBOUNTYREWARD.ProgramID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYPROGRAM", idCol: "ProgramID", labelCol: "Name", distinct: true };
FK_COLUMNS["BUGBOUNTYREWARD.SubmissionID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYSUBMISSION", idCol: "SubmissionID", labelCol: "Title", distinct: true };
FK_COLUMNS["BUGBOUNTYREWARD.ResearcherID"] = { db: "XVULNERABILITY", table: "BUGBOUNTYRESEARCHER", idCol: "ResearcherID", labelCol: "Handle", distinct: true };
FK_COLUMNS["BUGBOUNTYPROGRAM.OrganisationID"] = { db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", labelCol: "OrganisationName", distinct: true };

// Questionnaire ↔ organisation (XCOMPLIANCE.QUESTIONNAIREFORORGANISATION)
FK_COLUMNS["QUESTIONNAIREFORORGANISATION.QuestionnaireID"] = { db: "XCOMPLIANCE", table: "QUESTIONNAIRE", idCol: "QuestionnaireID", labelCol: "QuestionnaireName", distinct: true };
FK_COLUMNS["QUESTIONNAIREFORORGANISATION.OrganisationID"] = { db: "XORCISM", table: "ORGANISATION", idCol: "OrganisationID", labelCol: "OrganisationName", distinct: true };
FK_COLUMNS["QUESTIONNAIREFORORGANISATION.PersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
STATIC_DATALIST_COLUMNS["QUESTIONNAIREFORORGANISATION.Relationship"] = ["Assessed", "Owner", "Reviewer", "Recipient", "Subject", "Vendor", "Customer"];
// TPRM — third-party assessment lifecycle + risk rating.
const TPRM_STATUS = ["Requested", "Sent", "In progress", "Submitted", "Under review", "Completed", "Expired"];
const TPRM_STATUS_COLORS: Record<string, string> = {
  Requested: "#64748b", Sent: "#3b82f6", "In progress": "#f59e0b", Submitted: "#2dd4bf",
  "Under review": "#a78bfa", Completed: "#22c55e", Expired: "var(--danger)",
};
STATIC_DATALIST_COLUMNS["QUESTIONNAIREFORORGANISATION.Status"] = TPRM_STATUS;
STATIC_DATALIST_DEFAULTS["QUESTIONNAIREFORORGANISATION.Status"] = "Requested";
GRID_VALUE_COLORS["QUESTIONNAIREFORORGANISATION.Status"] = TPRM_STATUS_COLORS;
STATIC_DATALIST_COLUMNS["QUESTIONNAIREFORORGANISATION.AssessmentType"] = ["Initial", "Reassessment", "Continuous", "Offboarding"];
for (const col of ["RiskRating", "VendorCriticality"]) {
  STATIC_DATALIST_COLUMNS[`QUESTIONNAIREFORORGANISATION.${col}`] = GRC_SEVERITY; // Critical/High/Medium/Low/Info
  GRID_VALUE_COLORS[`QUESTIONNAIREFORORGANISATION.${col}`] = GRC_SEVERITY_COLORS;
}
STATIC_DATALIST_COLUMNS["QUESTIONNAIREFORORGANISATION.Score"] = OPENCTI_CONFIDENCE_PRESETS;

// ── EBIOS Risk Manager (XCOMPLIANCE) — cyber risk analysis (workshops 1-5).
// Reuses RISKASSESSMENT (study) + RISKSCENARIO (scenarios) + EBIOS* tables.
const EBIOS_SCALE = ["1", "2", "3", "4"];     // EBIOS scale (1 low → 4 high)
const EBIOS_DICT = ["0", "1", "2", "3", "4"]; // DICT impact (0 none → 4 maximal)
const EBIOS_LEVEL_COLORS: Record<string, string> = { "1": "#22c55e", "2": "#eab308", "3": "#f59e0b", "4": "var(--danger)" };
for (const tbl of ["EBIOSBUSINESSVALUE", "EBIOSSUPPORTINGASSET", "EBIOSFEAREDEVENT", "EBIOSRISKSOURCE", "EBIOSSTAKEHOLDER"]) {
  FK_COLUMNS[`${tbl}.RiskAssessmentID`] = { db: "XCOMPLIANCE", table: "RISKASSESSMENT", idCol: "RiskAssessmentID", labelCol: "Name", distinct: true };
}
// Workshop 1 — business values, supporting assets, feared events.
FK_COLUMNS["EBIOSBUSINESSVALUE.OwnerPersonID"] = { db: "XORCISM", table: "PERSON", idCol: "PersonID", labelCol: "FullName", distinct: true };
STATIC_DATALIST_COLUMNS["EBIOSBUSINESSVALUE.Nature"] = ["Process", "Information"];
FK_COLUMNS["EBIOSSUPPORTINGASSET.BusinessValueID"] = { db: "XCOMPLIANCE", table: "EBIOSBUSINESSVALUE", idCol: "BusinessValueID", labelCol: "Name", distinct: true };
FK_COLUMNS["EBIOSSUPPORTINGASSET.AssetID"] = { db: "XORCISM", table: "ASSET", idCol: "AssetID", labelCol: "AssetName", distinct: true };
STATIC_DATALIST_COLUMNS["EBIOSSUPPORTINGASSET.Type"] = ["Hardware", "Software", "Network", "System", "Organization", "Personnel", "Site", "Channel"];
FK_COLUMNS["EBIOSFEAREDEVENT.BusinessValueID"] = { db: "XCOMPLIANCE", table: "EBIOSBUSINESSVALUE", idCol: "BusinessValueID", labelCol: "Name", distinct: true };
for (const col of ["ImpactAvailability", "ImpactIntegrity", "ImpactConfidentiality", "ImpactTraceability"]) {
  STATIC_DATALIST_COLUMNS[`EBIOSFEAREDEVENT.${col}`] = EBIOS_DICT;
}
STATIC_DATALIST_COLUMNS["EBIOSFEAREDEVENT.Severity"] = EBIOS_SCALE;
GRID_VALUE_COLORS["EBIOSFEAREDEVENT.Severity"] = EBIOS_LEVEL_COLORS;
// Workshop 2 — risk sources / targeted objectives (SR/OV).
STATIC_DATALIST_COLUMNS["EBIOSRISKSOURCE.Category"] = ["State", "Cybercriminal", "Terrorist", "Hacktivist", "Competitor", "Insider", "Script kiddie", "Cyber-mercenary", "Ideological"];
for (const col of ["Motivation", "Resources", "Activity", "Pertinence"]) STATIC_DATALIST_COLUMNS[`EBIOSRISKSOURCE.${col}`] = EBIOS_SCALE;
GRID_VALUE_COLORS["EBIOSRISKSOURCE.Pertinence"] = EBIOS_LEVEL_COLORS;
CHECKBOX_COLUMNS["EBIOSRISKSOURCE.Retained"] = { checked: "1", unchecked: "0", default: "0" };
// Workshop 3 — stakeholders (ecosystem mapping).
STATIC_DATALIST_COLUMNS["EBIOSSTAKEHOLDER.Category"] = ["Client", "Partner", "Provider", "Supplier", "Subsidiary", "Regulator"];
STATIC_DATALIST_COLUMNS["EBIOSSTAKEHOLDER.Type"] = ["Digital", "Physical"];
for (const col of ["Dependency", "Penetration", "Maturity", "Trust"]) STATIC_DATALIST_COLUMNS[`EBIOSSTAKEHOLDER.${col}`] = EBIOS_SCALE;
// Zone (control/watch/danger) computed server-side from the threat level — read-only on the form, colored in the grid.
GRID_VALUE_COLORS["EBIOSSTAKEHOLDER.Zone"] = { Control: "#22c55e", Watch: "#f59e0b", Danger: "var(--danger)" };
// EBIOS study (RISKASSESSMENT) + enriched risk scenarios (workshops 3-4).
STATIC_DATALIST_COLUMNS["RISKASSESSMENT.Methodology"] = ["EBIOS RM", "ISO 27005", "Other"];
STATIC_DATALIST_COLUMNS["RISKASSESSMENT.Workshop"] = ["1", "2", "3", "4", "5"];
STATIC_DATALIST_COLUMNS["RISKSCENARIO.ScenarioType"] = ["strategic", "operational"];
GRID_VALUE_COLORS["RISKSCENARIO.ScenarioType"] = { strategic: "#7c83fd", operational: "#2dd4bf" };
for (const col of ["Likelihood", "Severity"]) STATIC_DATALIST_COLUMNS[`RISKSCENARIO.${col}`] = EBIOS_SCALE;
FK_COLUMNS["RISKSCENARIO.RiskAssessmentID"] = { db: "XCOMPLIANCE", table: "RISKASSESSMENT", idCol: "RiskAssessmentID", labelCol: "Name", distinct: true };
FK_COLUMNS["RISKSCENARIO.RiskSourceID"] = { db: "XCOMPLIANCE", table: "EBIOSRISKSOURCE", idCol: "RiskSourceID", labelCol: "Name", distinct: true };
FK_COLUMNS["RISKSCENARIO.FearedEventID"] = { db: "XCOMPLIANCE", table: "EBIOSFEAREDEVENT", idCol: "FearedEventID", labelCol: "Name", distinct: true };
FK_COLUMNS["RISKSCENARIO.StakeholderID"] = { db: "XCOMPLIANCE", table: "EBIOSSTAKEHOLDER", idCol: "StakeholderID", labelCol: "Name", distinct: true };

function getCheckbox(table: string, col: string): CheckboxSpec | null {
  return CHECKBOX_COLUMNS[`${table}.${col}`] ?? null;
}

// Builds a checkbox; the stored values (checked/unchecked) are
// carried by data-* to be read back at submission. currentVal = undefined at
// insertion (→ default).
function mkCheckbox(id: string, spec: CheckboxSpec, currentVal: unknown): HTMLInputElement {
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.id = id;
  const v = currentVal == null || currentVal === "" ? spec.default : String(currentVal);
  cb.checked = v === spec.checked;
  cb.dataset.checked = spec.checked;
  cb.dataset.unchecked = spec.unchecked;
  cb.style.cssText = "width:18px;height:18px;accent-color:var(--accent);cursor:pointer";
  return cb;
}

// Columns with a selector + file upload. The stored value is
// the URL returned by /api/upload (hidden field read at submission). Key "TABLE.Column".
const FILE_UPLOAD_COLUMNS = new Set<string>([
  "EVIDENCE.EvidenceFile",
  "DOCUMENT.DocumentFile",
  "ASSET.AssetImage",
  "QUESTIONNAIRE.FileName",
]);

// "Image only" columns: restricted to JPG/PNG (+ preview). Key "TABLE.Column".
const FILE_UPLOAD_IMAGE_COLUMNS = new Set<string>(["ASSET.AssetImage"]);

function hasFileUpload(table: string, col: string): boolean {
  return FILE_UPLOAD_COLUMNS.has(`${table}.${col}`);
}
function isImageUploadCol(table: string, col: string): boolean {
  return FILE_UPLOAD_IMAGE_COLUMNS.has(`${table}.${col}`);
}

// Original name from the stored URL (<uuid>__<name>).
function fileNameFromUrl(url: string): string {
  const base = url.split("/").pop() || url;
  const i = base.indexOf("__");
  return i >= 0 ? base.slice(i + 2) : base;
}

const UPLOAD_MAX_BYTES = 15 * 1024 * 1024;

/**
 * "select + upload a file" widget: file input + link to the
 * current file + hidden input (id = hiddenId) containing the URL, read by
 * submitInsert/submitEdit like any other field.
 */
function mkFileUpload(
  hiddenId: string,
  currentVal: unknown,
  opts?: { imageOnly?: boolean }
): HTMLElement {
  const imageOnly = !!opts?.imageOnly;
  const wrap = document.createElement("div");

  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.id = hiddenId;
  hidden.value = currentVal == null ? "" : String(currentVal);
  wrap.appendChild(hidden);

  const file = document.createElement("input");
  file.type = "file";
  // image only (JPG/PNG) or broad type set by default
  file.accept = imageOnly
    ? "image/jpeg,image/png,.jpg,.jpeg,.png"
    : "image/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.json,.xml,.zip,.7z";
  file.style.cssText = "width:100%;font-size:13px;color:var(--text)";
  wrap.appendChild(file);

  // Preview (image columns)
  const preview = document.createElement("img");
  preview.id = `${hiddenId}_preview`;
  preview.style.cssText =
    "display:none;max-width:160px;max-height:120px;margin-top:8px;border:1px solid var(--border);border-radius:6px";
  if (currentVal) { preview.src = String(currentVal); preview.style.display = ""; }
  if (imageOnly) wrap.appendChild(preview);

  const status = document.createElement("div");
  status.style.cssText = "font-size:12px;margin-top:4px;color:var(--text-muted)";
  wrap.appendChild(status);

  const renderCurrent = () => {
    const url = hidden.value.trim();
    status.style.color = "var(--text-muted)";
    status.innerHTML = "";
    if (imageOnly) {
      preview.src = url;
      preview.style.display = url ? "" : "none";
    }
    if (!url) {
      status.textContent = imageOnly ? "Aucune image." : "Aucun fichier.";
      return;
    }
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "📎 " + fileNameFromUrl(url);
    a.style.color = "var(--accent)";
    const clear = document.createElement("button");
    clear.type = "button";
    clear.textContent = "✕";
    clear.title = imageOnly ? "Retirer l'image" : "Retirer le fichier";
    clear.style.cssText =
      "margin-left:8px;background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    clear.onclick = () => {
      hidden.value = "";
      file.value = "";
      renderCurrent();
    };
    status.appendChild(a);
    status.appendChild(clear);
  };
  renderCurrent();

  file.addEventListener("change", () => {
    const f = file.files && file.files[0];
    if (!f) return;
    // JPG/PNG restriction (image columns) — MIME type or extension
    if (imageOnly && !/^image\/(jpeg|png)$/i.test(f.type) && !/\.(jpe?g|png)$/i.test(f.name)) {
      status.style.color = "var(--danger)";
      status.textContent = "Format non autorisé : choisissez un fichier JPG ou PNG.";
      file.value = "";
      return;
    }
    if (f.size > UPLOAD_MAX_BYTES) {
      status.style.color = "var(--danger)";
      status.textContent = "Fichier trop volumineux (max 15 Mo).";
      file.value = "";
      return;
    }
    status.style.color = "var(--text-muted)";
    status.textContent = "Téléversement…";
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const res = await fetch("/api/upload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            filename: f.name,
            contentType: f.type,
            dataBase64: String(reader.result),
          }),
        });
        // Response not necessarily JSON (e.g. 404 HTML page if the /api/upload route
        // doesn't exist → server to restart). We avoid an "Unexpected token '<'".
        const ct = res.headers.get("content-type") || "";
        if (!ct.includes("application/json")) {
          throw new Error(
            res.status === 404
              ? "endpoint /api/upload introuvable (redémarrez le serveur)"
              : `réponse inattendue du serveur (HTTP ${res.status})`
          );
        }
        const j = (await res.json()) as { url?: string; error?: string; av?: string };
        if (!res.ok || !j.url) throw new Error(j.error || "échec du téléversement");
        hidden.value = j.url;
        renderCurrent();
        // Result of the antivirus scan (ClamAV) returned by the server.
        if (j.av) {
          const note = document.createElement("span");
          note.style.cssText =
            "margin-left:8px;font-size:11px;color:" + (j.av === "clean" ? "var(--success)" : "var(--text-muted)");
          note.textContent = j.av === "clean" ? "✓ ClamAV : sain" : "ClamAV : non analysé";
          status.appendChild(note);
        }
      } catch (e) {
        status.style.color = "var(--danger)";
        status.textContent = "Échec : " + (e as Error).message;
      }
    };
    reader.onerror = () => {
      status.style.color = "var(--danger)";
      status.textContent = "Lecture du fichier impossible.";
    };
    reader.readAsDataURL(f);
  });

  return wrap;
}

// A BlobSha256 column stores a content-addressed "hash pointer" — the form offers a file upload that
// pushes the bytes to the object store (/api/blob) and keeps only the returned sha256.
function isCasUploadCol(col: string): boolean { return col === "BlobSha256"; }

/** "Upload a file into the content-addressed store" widget: POSTs to /api/blob and stores the returned
 *  sha256 in the hidden field (read at submission like any other value). */
function mkCasUpload(hiddenId: string, currentVal: unknown): HTMLElement {
  const wrap = document.createElement("div");
  const hidden = document.createElement("input");
  hidden.type = "hidden"; hidden.id = hiddenId; hidden.value = currentVal == null ? "" : String(currentVal);
  wrap.appendChild(hidden);
  const file = document.createElement("input");
  file.type = "file";
  file.style.cssText = "width:100%;font-size:13px;color:var(--text)";
  wrap.appendChild(file);
  const status = document.createElement("div");
  status.style.cssText = "font-size:12px;margin-top:4px;color:var(--text-muted)";
  wrap.appendChild(status);
  const render = (): void => {
    const sha = hidden.value.trim(); status.innerHTML = ""; status.style.color = "var(--text-muted)";
    if (!sha) { status.textContent = "Aucun fichier (object store)."; return; }
    const a = document.createElement("a");
    a.href = `/api/blob/${encodeURIComponent(sha)}`; a.target = "_blank"; a.rel = "noopener";
    a.textContent = "🗄️ " + sha.slice(0, 12) + "…"; a.style.color = "var(--accent)"; a.title = sha;
    const clear = document.createElement("button");
    clear.type = "button"; clear.textContent = "✕"; clear.title = "Retirer";
    clear.style.cssText = "margin-left:8px;background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    clear.onclick = () => { hidden.value = ""; file.value = ""; render(); };
    status.appendChild(a); status.appendChild(clear);
  };
  render();
  file.addEventListener("change", () => {
    const f = file.files && file.files[0]; if (!f) return;
    if (f.size > UPLOAD_MAX_BYTES) { status.style.color = "var(--danger)"; status.textContent = "Fichier trop volumineux (max 15 Mo)."; file.value = ""; return; }
    status.style.color = "var(--text-muted)"; status.textContent = "Téléversement (object store)…";
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const dataBase64 = String(reader.result).replace(/^data:[^;]*;base64,/, "");
        const res = await fetch("/api/blob", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ filename: f.name, contentType: f.type, dataBase64 }) });
        const ct = res.headers.get("content-type") || "";
        if (!ct.includes("application/json")) throw new Error(res.status === 404 ? "endpoint /api/blob introuvable (redémarrez le serveur)" : `réponse inattendue (HTTP ${res.status})`);
        const j = (await res.json()) as { sha256?: string; size?: number; dedup?: boolean; error?: string };
        if (!res.ok || !j.sha256) throw new Error(j.error || "échec du téléversement");
        hidden.value = j.sha256; render();
        const note = document.createElement("span");
        note.style.cssText = "margin-left:8px;font-size:11px;color:var(--text-muted)";
        note.textContent = `${j.size ?? 0} o${j.dedup ? " · dédupliqué" : ""}`;
        status.appendChild(note);
      } catch (e) { status.style.color = "var(--danger)"; status.textContent = "Échec : " + (e as Error).message; }
    };
    reader.onerror = () => { status.style.color = "var(--danger)"; status.textContent = "Lecture du fichier impossible."; };
    reader.readAsDataURL(f);
  });
  return wrap;
}

// Value of a form field at submission (handles checkboxes).
function fieldValue(input: HTMLInputElement): string {
  if (input.type === "checkbox") {
    return input.checked ? (input.dataset.checked ?? "1") : (input.dataset.unchecked ?? "0");
  }
  return input.value;
}

// Builds a styled <select> for the enumerated columns.
function mkEnumSelect(id: string, options: string[], selected: string): HTMLSelectElement {
  const sel = document.createElement("select");
  sel.id = id;
  sel.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = "—";
  sel.appendChild(blank);
  options.forEach((o) => {
    const opt = document.createElement("option");
    opt.value = o;
    opt.textContent = o;
    opt.style.background = "var(--surface)";
    if (o === selected) opt.selected = true;
    sel.appendChild(opt);
  });
  if (!selected) blank.selected = true;
  return sel;
}

// Columns with a calendar icon (date picker) WITHOUT
// automatic pre-fill. Key "TABLE.Column".
const DATE_PICKER_COLUMNS = new Set<string>([
  "INCIDENT.datetime_reported",
  "INCIDENT.start_datetime",
  "INCIDENT.end_datetime",
  "INCIDENT.detect_datetime",
  "ASSET.LastCheckedDate",
  "ASSET.DueDate",
  "VULNERABILITY.DueDate",
  // XCOMPLIANCE — date fields
  "AUDIT.AuditDate",
  "AUDIT.AuditClosureDate",
  "AUDITFINDING.FindingDate",
  "AUDITFINDING.DueDate",
  "AUDITREPORT.ReportDate",
  "TICKET.DueDate",
  "TICKET.ResolvedDate",
  "TICKET.ClosedDate",
  "ASSETRISKSCORE.Date",
  "ASSETTHREAT.ValidFrom",
  "ASSETTHREAT.ValidUntil",
  "THREAT.ValidFrom",
  "THREAT.ValidUntil",
  "ASSETAUDIT.Date",
  "ASSETAUDIT.ValidFrom",
  "ASSETAUDIT.ValidUntil",
  "ASSETAUDITFINDING.Date",
  "RISKSCORE.Date",
  "TRAINING.ValidFrom",
  "TRAINING.ValidUntil",
  "TRAININGFORPERSON.DateEnrolled",
  "TRAININGFORPERSON.DateCompleted",
  "TRAININGFORPERSON.ValidFrom",
  "TRAININGFORPERSON.ValidUntil",
  "VULNERABILITYACTION.ValidFrom",
  "VULNERABILITYACTION.ValidUntil",
  "EVIDENCE.EvidenceDate",
  "EVIDENCE.ValidFrom",
  "EVIDENCE.ValidUntil",
  "THREATCAMPAIGN.ValidUntilDate",
  "DOCUMENT.DocumentDate",
  "DOCUMENT.ValidFrom",
  "DOCUMENT.ValidUntil",
  "DOCUMENT.ReviewDate",
  "DOCUMENTPERSON.ValidFrom",
  "DOCUMENTPERSON.ValidUntil",
  // OCIL / questionnaires
  "QUESTIONNAIRE.ValidFrom",
  "QUESTIONNAIRE.ValidUntil",
  "QUESTION.ValidFrom",
  "QUESTION.ValidUntil",
  "ANSWER.ValidFrom",
  "ANSWER.ValidUntil",
  // TPRM — due date / completion date of a third-party assessment
  "QUESTIONNAIREFORORGANISATION.DueDate",
  "QUESTIONNAIREFORORGANISATION.CompletedDate",
  "QUESTIONNAIREFORORGANISATION.CreatedDate",
  "QUESTIONNAIREFORORGANISATION.ValidFrom",
  "QUESTIONNAIREFORORGANISATION.ValidUntil",
  // Asset vulnerability remediations
  "ASSETVULNERABILITYREMEDIATION.ValidFrom",
  "ASSETVULNERABILITYREMEDIATION.ValidUntil",
  "ASSETVULNERABILITYREMEDIATION.TargetDate",
  // Asset vulnerability (patch lifecycle dates)
  "ASSETVULNERABILITY.PatchedDate",
  "ASSETVULNERABILITY.TargetDate",
  // GRC — date fields
  "COMPLIANCEASSESSMENT.Date",
  "COMPLIANCEASSESSMENT.DueDate",
  "RISKASSESSMENT.Date",
  "APPLIEDCONTROL.StartDate",
  "APPLIEDCONTROL.ETA",
  "APPLIEDCONTROL.ExpiryDate",
  "RISKACCEPTANCE.AcceptedDate",
  "RISKACCEPTANCE.ExpiryDate",
  "RISKACCEPTANCE.RevokedDate",
  "SECURITYEXCEPTION.ExpiryDate",
  // Risk Register — date fields
  "RISKREGISTERENTRY.IdentifiedDate",
  "RISKREGISTERENTRY.ReviewDate",
  "RISKREGISTERENTRY.TargetDate",
  "RISKREGISTERENTRY.ClosedDate",
  // Bug bounty — submission lifecycle dates
  "BUGBOUNTYSUBMISSION.SubmittedDate",
  "BUGBOUNTYSUBMISSION.TriagedDate",
  "BUGBOUNTYSUBMISSION.ResolvedDate",
  // Identity & IAM — credential lifecycle dates
  "IDENTITY.ExpiryDate",
  "IDENTITY.LastRotatedDate",
  "IDENTITY.LastUsedDate",
  "IDENTITY.ModifiedDate",
  // Threat hunting / detection content (XTHREAT)
  "HUNT.ValidFrom",
  "HUNT.HuntDate",
  "SIGMARULE.ValidFrom",
]);

function hasDatePicker(table: string, col: string): boolean {
  return DATE_PICKER_COLUMNS.has(`${table}.${col}`);
}

// Columns whose picker returns only a DATE ("YYYY-MM-DD", no time).
const DATE_ONLY_PICKER_COLUMNS = new Set<string>([
  "VULNERABILITY.DueDate",
  "QUESTIONNAIREFORORGANISATION.DueDate",
  "QUESTIONNAIREFORORGANISATION.CompletedDate",
  "ASSETVULNERABILITY.PatchedDate",
  "ASSETVULNERABILITY.TargetDate",
  "ASSETVULNERABILITYREMEDIATION.TargetDate",
  "ALERT.CreatedDate",
  "BUGBOUNTYSUBMISSION.SubmittedDate",
  "BUGBOUNTYSUBMISSION.TriagedDate",
  "BUGBOUNTYSUBMISSION.ResolvedDate",
  "IDENTITY.ExpiryDate",
  "IDENTITY.LastRotatedDate",
  "IDENTITY.LastUsedDate",
  "IDENTITY.ModifiedDate",
  "AUDITFINDING.DueDate",
  "HUNT.ValidFrom",
  "HUNT.HuntDate",
  "SIGMARULE.ValidFrom",
]);
function isDateOnlyPicker(table: string, col: string): boolean {
  return DATE_ONLY_PICKER_COLUMNS.has(`${table}.${col}`);
}

// Detects the date columns to pre-fill (current date) and to give
// a calendar icon: CreatedDate and ValidFromDate.
function isAutoDateCol(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n === "createddate" ||
    n === "created_date" ||
    n === "datecreated" ||
    n === "validfromdate" ||
    n === "valid_from_date"
  );
}

// Columns pre-filled with the current date at the form's OPENING, per
// table (key "TABLE.Column"). Unlike CreatedDate/ValidFromDate, the
// value is also refreshed at the EDIT form's opening ("modification date"
// semantics).
const AUTO_DATE_COLUMNS = new Set<string>(["VOCABULARY.DateModified"]);

function hasAutoDate(table: string, col: string): boolean {
  return isAutoDateCol(col) || AUTO_DATE_COLUMNS.has(`${table}.${col}`);
}

// Date columns with a calendar that pre-fill with the current
// date ONLY if the value is null/empty (otherwise we keep the existing value).
const DEFAULT_TODAY_DATE_COLUMNS = new Set<string>([
  "EVIDENCE.EvidenceDate",
  "DOCUMENT.DocumentDate",
  "DOCUMENTPERSON.ValidFrom",
  "RISKREGISTERENTRY.IdentifiedDate",
]);

// Date columns pre-filled at CREATION opening with "today + N years"
// (e.g. a default validity of one year). Key "TABLE.Column" → number of years.
const DEFAULT_TODAY_PLUS_YEARS: Record<string, number> = {
  "DOCUMENTPERSON.ValidUntil": 1,
};
function defaultPlusYears(table: string, col: string): number | null {
  return DEFAULT_TODAY_PLUS_YEARS[`${table}.${col}`] ?? null;
}
function todayPlusYears(n: number): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + n);
  return d.toISOString().slice(0, 10);
}

function isDefaultTodayDate(table: string, col: string): boolean {
  return DEFAULT_TODAY_DATE_COLUMNS.has(`${table}.${col}`);
}

// "ValidFrom" column (without Date suffix): initialized to the current date at
// CREATION, across all tables. (ValidFromDate is already handled by isAutoDateCol.)
function isValidFromCol(name: string): boolean {
  const n = name.toLowerCase();
  return n === "validfrom" || n === "valid_from";
}

// "YYYY-MM-DD HH:MM:SS" → "YYYY-MM-DDTHH:MM" (valeur datetime-local)
function toLocalInput(value: string): string {
  const m = value.trim().match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})/);
  if (m) return `${m[1]}T${m[2]}`;
  return new Date().toISOString().slice(0, 16);
}

// "YYYY-MM-DDTHH:MM" → "YYYY-MM-DD HH:MM:SS"
function fromLocalInput(value: string): string {
  if (!value) return "";
  return value.replace("T", " ") + (value.length === 16 ? ":00" : "");
}

// Date part of a stored value (date or datetime) → "YYYY-MM-DD" (date-only picker).
function toDateInput(value: string): string {
  const m = value.trim().match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : new Date().toISOString().slice(0, 10);
}

// Wraps a text field with a calendar icon opening a date picker.
// Returns the container to insert into the DOM.
// Floating date-selection window (single). Closed via OK / Cancel /
// Esc / outside click. Positioned near the button and BOUNDED to the viewport
// (flips above if it would overflow at the bottom).
let _datePopup: HTMLElement | null = null;
function closeDatePopup(): void {
  if (!_datePopup) return;
  _datePopup.remove();
  _datePopup = null;
  document.removeEventListener("mousedown", _onDatePopupDocDown, true);
  document.removeEventListener("keydown", _onDatePopupKey, true);
  window.removeEventListener("resize", closeDatePopup);
  window.removeEventListener("scroll", closeDatePopup, true);
}
function _onDatePopupDocDown(e: MouseEvent): void {
  if (_datePopup && !_datePopup.contains(e.target as Node)) closeDatePopup();
}
function _onDatePopupKey(e: KeyboardEvent): void {
  if (e.key === "Escape") closeDatePopup();
}

function openDatePopup(anchor: HTMLElement, textInput: HTMLInputElement, dateOnly = false): void {
  closeDatePopup();
  const pop = document.createElement("div");
  _datePopup = pop;
  pop.style.cssText =
    "position:fixed;z-index:10000;background:var(--surface);border:1px solid var(--border);" +
    "border-radius:8px;padding:10px;box-shadow:0 10px 30px rgba(0,0,0,.55);" +
    "display:flex;flex-direction:column;gap:8px;min-width:240px";

  const dt = document.createElement("input");
  // dateOnly: "date" field that returns "YYYY-MM-DD"; otherwise full datetime.
  dt.type = dateOnly ? "date" : "datetime-local";
  if (!dateOnly) dt.step = "1";
  dt.value = dateOnly ? toDateInput(textInput.value) : toLocalInput(textInput.value);
  dt.style.cssText =
    "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;" +
    "color:var(--text);font-size:14px;color-scheme:dark";
  // Enter = confirm, Esc handled globally
  dt.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      apply();
    }
  });

  const row = document.createElement("div");
  // flex-shrink:0: the button row (OK/Cancel) is never compressed.
  row.style.cssText = "display:flex;justify-content:flex-end;gap:8px;flex-shrink:0";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.textContent = "Annuler";
  cancel.style.cssText =
    "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 12px;color:var(--text-muted);cursor:pointer;font-size:12px";
  cancel.onclick = () => closeDatePopup();
  const ok = document.createElement("button");
  ok.type = "button";
  ok.textContent = "OK";
  ok.style.cssText =
    "background:var(--accent);border:1px solid var(--accent);border-radius:6px;padding:6px 16px;color:#fff;cursor:pointer;font-size:12px;font-weight:600";
  const apply = () => {
    // dateOnly: dt.value is already "YYYY-MM-DD"; otherwise datetime conversion.
    if (dt.value) textInput.value = dateOnly ? dt.value : fromLocalInput(dt.value);
    textInput.dispatchEvent(new Event("change", { bubbles: true })); // triggers the dependencies
    closeDatePopup();
  };
  ok.onclick = apply;
  row.appendChild(cancel);
  row.appendChild(ok);

  pop.appendChild(dt);
  pop.appendChild(row);
  // Never taller than the viewport: the OK button (at the bottom) stays reachable.
  const margin = 8;
  pop.style.maxHeight = `${window.innerHeight - 2 * margin}px`;
  pop.style.overflow = "auto";
  document.body.appendChild(pop);

  // Positioning bounded to the viewport. The real height may only be known after
  // a layout cycle (datetime field render, fonts) → we (re)place right
  // away THEN on the next frame, otherwise the OK button can be pushed off-screen
  // ("shows at the bottom, not selectable" / "OK doesn't always show").
  const place = (): void => {
    const r = anchor.getBoundingClientRect();
    const pw = pop.offsetWidth;
    const ph = pop.offsetHeight;
    let left = r.left;
    if (left + pw > window.innerWidth - margin) left = window.innerWidth - pw - margin;
    if (left < margin) left = margin;
    let top = r.bottom + 4;
    if (top + ph > window.innerHeight - margin) top = r.top - ph - 4; // flips above
    if (top < margin) top = margin;
    // Guard: still overflows at the bottom (very short viewport) → stuck at the bottom, whole.
    if (top + ph > window.innerHeight - margin) top = Math.max(margin, window.innerHeight - ph - margin);
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
  };
  place();
  requestAnimationFrame(place); // re-aligns with the final height

  document.addEventListener("mousedown", _onDatePopupDocDown, true);
  document.addEventListener("keydown", _onDatePopupKey, true);
  window.addEventListener("resize", closeDatePopup);
  window.addEventListener("scroll", closeDatePopup, true);

  // Opens the field's native calendar right away (best-effort, gesture preserved).
  dt.focus();
  const sp = (dt as HTMLInputElement & { showPicker?: () => void }).showPicker;
  if (typeof sp === "function") {
    try {
      sp.call(dt);
    } catch {
      /* showPicker may fail outside a gesture: the field stays usable */
    }
  }
}

function wrapWithCalendar(textInput: HTMLInputElement): HTMLElement {
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;gap:6px;align-items:stretch";
  textInput.style.flex = "1";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "📅";
  btn.title = t("tip.chooseDate");
  btn.style.cssText =
    "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0 11px;color:var(--accent);font-size:15px;cursor:pointer";
  btn.onmouseenter = () => (btn.style.borderColor = "var(--accent)");
  btn.onmouseleave = () => (btn.style.borderColor = "var(--border)");
  // Column inferred from the field id (`f_`/`ef_` + column) → possible date-only mode.
  const col = textInput.id.replace(/^ef_|^f_/, "");
  const dateOnly = isDateOnlyPicker(currentTable, col);
  btn.onclick = () => openDatePopup(btn, textInput, dateOnly);

  wrap.appendChild(textInput);
  wrap.appendChild(btn);
  return wrap;
}

function toast(msg: string, type: "ok" | "err" = "ok"): void {
  const t = $("toast");
  t.textContent = msg;
  t.className = type === "err" ? "toast-err" : "toast-ok";
  (t as HTMLElement).style.opacity = "1";
  setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2800);
}

// ── Init ──────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  // Landing page if no ?db= deep link; otherwise the explorer.
  const qp = new URLSearchParams(location.search);
  const qdb = qp.get("db");
  const landing = document.getElementById("landing");
  const explorer = document.getElementById("explorer-layout");
  if (!qdb) {
    if (landing) landing.style.display = "";
    if (explorer) explorer.style.display = "none";
    void maybeOfferSetupWizard(); // first-run wizard (Admin + no organisation yet)
    return; // no explorer to load: we stay on the landing
  }
  if (landing) landing.style.display = "none";
  if (explorer) explorer.style.display = "";

  try {
    await loadFavorites(); // table favorites before any list render
    await loadCapabilities(); // canPentest (before a possible selectTable deep-link)
    const dbs = await api.getDatabases();
    const dbList = $("db-list");
    dbList.innerHTML = "";

    dbs.forEach((db) => {
      const li = document.createElement("li");
      li.textContent = db;
      li.className = "db-item";
      li.onclick = () => selectDb(db);
      dbList.appendChild(li);
    });

    // Deep link ?db=…&table=… (e.g. "Asset Management" card from the landing).
    // Optional column filter: &filterCol=…&filterVal=… (e.g. OSINT card →
    // TOOL filtered on Category=OSINT). selectTable resets the filters: we
    // therefore apply it after, then reload.
    if (dbs.includes(qdb)) {
      await selectDb(qdb);
      const qtable = qp.get("table");
      if (qtable) {
        await selectTable(qtable);
        const fcol = qp.get("filterCol");
        const fval = qp.get("filterVal");
        if (fcol && fval) {
          currentFilters[fcol] = fval;
          await loadRows();
        }
        // Direct opening of a record's edit form, identified by
        // column=value (e.g. link from the STIX graph: THREATACTOR by ThreatActorName).
        const ecol = qp.get("editCol");
        const eVal = qp.get("editVal");
        if (ecol && eVal) {
          try {
            const resp = await api.getRowById(qdb, qtable, ecol, eVal);
            if (resp.row) await openEditModal(resp.row as Record<string, unknown>);
            else { currentFilters[ecol] = eVal; await loadRows(); toast(`${t("toast.noRecord")} ${ecol} = « ${eVal} »`, "err"); }
          } catch {
            currentFilters[ecol] = eVal; await loadRows(); // invalid column/access: fall back to a filter
          }
        }
      }
      // First-run wizard step 1: open the ORGANISATION create form (reused as-is).
      if (qp.get("setup") === "1" && qdb === "XORCISM" && qtable === "ORGANISATION") {
        setupWizardActive = true;
        showSetupBanner();
        await openInsertModal();
      }
    }
  } catch (e) {
    toast(t("toast.errLoadDbs") + " " + e, "err");
  }
}

// ── First-run setup wizard ────────────────────────────────────────────────
// Fresh install: when an Admin first connects and no ORGANISATION exists, offer
// a one-time wizard → create the first ORGANISATION (reusing its standard form),
// then the "XORCISM Admin account" ASSET + ASSETFORORGANISATION link.
let setupWizardActive = false;

async function maybeOfferSetupWizard(): Promise<void> {
  try {
    const { needed } = await api.setupStatus();
    if (needed) showSetupWelcomeModal();
  } catch {
    /* not logged in / endpoint absent: ignore */
  }
}

function showSetupWelcomeModal(): void {
  if (document.getElementById("setup-wizard-bg")) return;
  const bg = document.createElement("div");
  bg.id = "setup-wizard-bg";
  bg.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;display:flex;align-items:center;justify-content:center";
  const card = document.createElement("div");
  card.style.cssText =
    "background:var(--surface,#1b1f27);border:1px solid var(--border,#333);border-radius:12px;" +
    "max-width:520px;width:92%;padding:24px;color:var(--text,#e6e6e6);box-shadow:0 12px 40px rgba(0,0,0,.5)";
  card.innerHTML =
    '<h2 style="margin:0 0 8px;font-size:20px">\u{1F44B} Welcome to XORCISM</h2>' +
    '<p style="margin:0 0 12px;color:var(--text-muted,#9aa)">This one-time setup wizard will:</p>' +
    '<ol style="margin:0 0 16px;padding-left:20px;line-height:1.8">' +
    "<li>Create your first <b>Organisation</b> (you fill the standard form)</li>" +
    '<li>Create the <b>“XORCISM Admin account”</b> asset</li>' +
    "<li>Link that asset to your organisation</li></ol>" +
    '<div style="display:flex;gap:10px;justify-content:flex-end">' +
    '<button id="setup-later" class="btn btn-ghost">Later</button>' +
    '<button id="setup-now" class="btn btn-primary">Set up now →</button></div>';
  bg.appendChild(card);
  document.body.appendChild(bg);
  (document.getElementById("setup-later") as HTMLButtonElement).onclick = () => bg.remove();
  (document.getElementById("setup-now") as HTMLButtonElement).onclick = () => {
    location.href = location.pathname + "?db=XORCISM&table=ORGANISATION&setup=1";
  };
}

function showSetupBanner(): void {
  if (document.getElementById("setup-banner")) return;
  const b = document.createElement("div");
  b.id = "setup-banner";
  b.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:9998;background:var(--accent,#3b82f6);color:#fff;" +
    "padding:8px 16px;text-align:center;font-size:14px";
  b.textContent =
    "Setup wizard — Step 1 of 2: create your first organisation and save. " +
    "The “XORCISM Admin account” asset and its link are then created automatically.";
  document.body.appendChild(b);
}

// Wizard step 2: after the ORGANISATION is created, create the admin asset + link.
function finishSetupWizard(orgId: number): void {
  setupWizardActive = false;
  void api
    .setupAdminAsset(orgId)
    .then((r) => {
      document.getElementById("setup-banner")?.remove();
      toast(
        "✅ Setup complete — linked to your organisation: the “XORCISM Admin account” asset " +
          `(#${r.adminAssetId}), the “XORCISM” asset (#${r.xorcismAssetId}) and the “XORCISM” application (#${r.applicationId}).`,
        "ok"
      );
    })
    .catch((e) => toast("Setup wizard: " + e, "err"));
}

// ── Table favorites (user preference, keys "DB.TABLE") ─────────────
let favorites = new Set<string>();
let currentTables: string[] = []; // tables of the current database (for re-render)

async function loadFavorites(): Promise<void> {
  try {
    const r = await fetch("/api/prefs/table-favorites");
    if (r.ok) {
      const v = (await r.json()).value;
      if (Array.isArray(v)) favorites = new Set(v.map(String));
    }
  } catch {
    /* preference absent */
  }
}
function saveFavorites(): void {
  void fetch("/api/prefs/table-favorites", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value: [...favorites] }),
  }).catch(() => {});
}
let tableQuery = "";
// Table search field (created once, above #table-list): filters the
// list of tables of the current database; Enter selects the first match.
function ensureTableSearch(): void {
  if (document.getElementById("table-search")) return;
  const list = $("table-list");
  const inp = document.createElement("input");
  inp.id = "table-search";
  inp.type = "search";
  inp.placeholder = t("explorer.searchTable");
  inp.autocomplete = "off";
  inp.style.cssText = "width:100%;box-sizing:border-box;margin:0 0 6px;padding:5px 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px";
  inp.oninput = () => { tableQuery = inp.value.trim().toLowerCase(); renderTableList(); };
  inp.onkeydown = (e) => {
    const ev = e as KeyboardEvent;
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    const q = inp.value.trim().toLowerCase();
    if (!q) return;
    const m = currentTables.filter((tb) => tb.toLowerCase().includes(q));
    if (!m.length) { toast(`${t("toast.noTable")} « ${q} »`, "err"); return; }
    // Best match: exact > prefix > first substring.
    const best = m.find((tb) => tb.toLowerCase() === q)
      || m.find((tb) => tb.toLowerCase().startsWith(q))
      || m[0];
    void selectTable(best);
  };
  list.parentElement?.insertBefore(inp, list);
}
function renderTableList(): void {
  const tblList = $("table-list");
  ensureTableSearch();
  tblList.innerHTML = "";
  const key = (tbl: string) => `${currentDb}.${tbl}`;
  const match = (tbl: string) => !tableQuery || tbl.toLowerCase().includes(tableQuery);
  const mk = (tbl: string): HTMLLIElement => {
    const li = document.createElement("li");
    li.className = "table-item" + (tbl === currentTable ? " active" : "");
    li.dataset.table = tbl;
    li.style.cssText = "display:flex;align-items:center;gap:6px";
    const isFav = favorites.has(key(tbl));
    const star = document.createElement("span");
    star.textContent = isFav ? "★" : "☆";
    star.title = isFav ? t("sidebar.unfav") : t("sidebar.fav");
    star.style.cssText = "cursor:pointer;flex:0 0 auto;color:" + (isFav ? "#fbbf24" : "var(--text-faint)");
    star.onclick = (e) => {
      e.stopPropagation();
      if (favorites.has(key(tbl))) favorites.delete(key(tbl));
      else favorites.add(key(tbl));
      saveFavorites();
      renderTableList();
    };
    const name = document.createElement("span");
    name.textContent = tbl;
    name.style.cssText = "flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
    li.appendChild(star);
    li.appendChild(name);
    li.onclick = () => selectTable(tbl);
    return li;
  };
  const favs = currentTables.filter((tbl) => favorites.has(key(tbl)) && match(tbl));
  const rest = currentTables.filter((tbl) => !favorites.has(key(tbl)) && match(tbl));
  if (tableQuery && !favs.length && !rest.length) {
    const none = document.createElement("li");
    none.textContent = `Aucune table « ${tableQuery} »`;
    none.style.cssText = "color:var(--text-muted);font-size:12px;padding:6px 4px;list-style:none";
    tblList.appendChild(none);
    return;
  }
  if (favs.length) {
    const hdr = document.createElement("li");
    hdr.textContent = "★ " + t("sidebar.favorites");
    hdr.style.cssText = "color:#fbbf24;font-size:10px;text-transform:uppercase;padding:6px 4px 2px;list-style:none;letter-spacing:.5px";
    tblList.appendChild(hdr);
    favs.forEach((tbl) => tblList.appendChild(mk(tbl)));
    const sep = document.createElement("li");
    sep.style.cssText = "border-top:1px solid var(--border);margin:5px 0;list-style:none";
    tblList.appendChild(sep);
  }
  rest.forEach((tbl) => tblList.appendChild(mk(tbl)));
}

// Capabilities of the current user (e.g. access right to Pentest mode).
async function loadCapabilities(): Promise<void> {
  try {
    const r = await fetch("/api/auth/me");
    if (r.ok) canPentest = !!(await r.json()).canPentest;
  } catch {
    /* not authenticated */
  }
}

async function selectDb(db: string): Promise<void> {
  currentDb = db;
  currentTable = "";
  schema = [];
  updateContextNav(); // no table selected → hides the context menus

  // Highlight selected db
  document.querySelectorAll(".db-item").forEach((el) => {
    el.classList.toggle("active", el.textContent === db);
  });

  $("table-section").style.display = "";
  $("table-list").innerHTML = "<li style='color:var(--text-muted);font-size:12px'>Chargement...</li>";
  $("data-section").style.display = "none";

  try {
    currentTables = await api.getTables(db);
    tableQuery = "";
    const si = document.getElementById("table-search") as HTMLInputElement | null;
    if (si) si.value = "";
    renderTableList(); // favorites first + star per table
  } catch (e) {
    toast(t("toast.errLoadTables") + " " + e, "err");
  }
}

// Bar context menus: BIA Audit only on XORCISM/ASSET; ATT&CK + D3FEND
// only on XTHREAT/THREAT. (Links hidden by default; shown according to the view.)
function updateContextNav(): void {
  const isAsset = currentDb === "XORCISM" && currentTable === "ASSET";
  const isThreat = currentDb === "XTHREAT" && currentTable === "THREAT";
  const set = (id: string, show: boolean): void => {
    const e = document.getElementById(id);
    if (e) e.style.display = show ? "" : "none";
  };
  set("nav-bia", isAsset);
  set("nav-attack", isThreat);
  set("nav-d3fend", isThreat);
}

async function selectTable(table: string): Promise<void> {
  currentTable = table;
  // Possible default sort for this table (key "DB.TABLE")
  const def = DEFAULT_SORT[`${currentDb}.${table}`];
  currentSort = def ? def[0] : "";
  currentDir = def ? def[1] : "asc";
  currentSearch = "";
  currentFilters = {};
  activeFilterCol = null;
  currentPage = 0;
  // Reset and enable search input
  const searchInput = $("search-input") as HTMLInputElement;
  searchInput.value = "";
  searchInput.placeholder = `${t("explorer.search")} (${table})`;
  searchInput.disabled = false;
  searchInput.focus();

  document.querySelectorAll(".table-item").forEach((el) => {
    el.classList.toggle("active", (el as HTMLElement).dataset.table === table);
  });

  $("current-title").textContent = `${currentDb} / ${table}`;
  $("data-section").style.display = "";
  updateContextNav(); // BIA Audit (ASSET) / ATT&CK + D3FEND (THREAT) according to the view

  // "Import OSV / CIRCL" buttons restricted to XVULNERABILITY.VULNERABILITY
  const osvBtn = document.getElementById("btn-osv");
  if (osvBtn) osvBtn.style.display = isOsvTable() ? "" : "none";
  const circlBtn = document.getElementById("btn-circl");
  if (circlBtn) circlBtn.style.display = isOsvTable() ? "" : "none";
  const edbBtn = document.getElementById("btn-exploitdb");
  if (edbBtn) edbBtn.style.display = isOsvTable() ? "" : "none";

  // "Pentest Mode" button restricted to XORCISM.ASSET (if right granted)
  const isAssetView = currentDb === "XORCISM" && table === "ASSET";
  const pentestBtn = document.getElementById("btn-pentest");
  if (pentestBtn) pentestBtn.style.display = canPentest && isAssetView ? "" : "none";
  if (!isAssetView && pentestMode) { pentestMode = false; selectedAssets.clear(); }
  updatePentestBar();

  try {
    schema = await api.getSchema(currentDb, table);
    await loadRows();
  } catch (e) {
    toast(t("toast.errLoadSchema") + " " + e, "err");
  }
}

// Navigates to (db, table) then opens the creation form directly.
async function navigateAndCreate(db: string, table: string): Promise<void> {
  try {
    if (currentDb !== db) await selectDb(db);
    await selectTable(table);
    await openInsertModal();
  } catch (e) {
    toast(t("toast.errOpenForm") + " " + e, "err");
  }
}

// ── OSV.dev integration (osv.dev) ─────────────────────────────────────────────
// The target table for OSV enrichment / import.
function isOsvTable(): boolean {
  return currentDb === "XVULNERABILITY" && currentTable === "VULNERABILITY";
}

// Fills the form's `<prefix><column>` fields with the OSV values.
function applyOsvFields(prefix: string, fields: Record<string, string | number>): number {
  let filled = 0;
  for (const [col, val] of Object.entries(fields)) {
    const el = document.getElementById(`${prefix}${col}`) as
      | HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    if (!el) continue;
    if ((el as HTMLInputElement).type === "checkbox") {
      // Checkbox (e.g. KEV, Exploited): we CHECK according to the value, not .value.
      const cb = el as HTMLInputElement;
      const on = (cb.dataset.checked ?? "1").toLowerCase();
      const s = String(val).toLowerCase();
      cb.checked = s === on || s === "1" || s === "true" || s === "yes";
      cb.dispatchEvent(new Event("change", { bubbles: true }));
    } else {
      el.value = String(val);
      el.dispatchEvent(new Event("input", { bubbles: true })); // rich text / datalist
    }
    filled++;
  }
  return filled;
}

// Fills a form field by column name — checkbox (checks according to
// the "enabled" value) OR free field (value). No-op if the field is absent.
function setFormField(prefix: string, col: string, value: string): void {
  const el = document.getElementById(`${prefix}${col}`) as HTMLInputElement | null;
  if (!el) return;
  if (el.type === "checkbox") {
    el.checked = value === (el.dataset.checked ?? "1") || value === "1";
    el.dispatchEvent(new Event("change", { bubbles: true }));
  } else {
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

// "Enrich from OSV" field injected at the top of the VULNERABILITY form.
function appendOsvEnrichField(body: HTMLElement, prefix: string, currentRef: string): void {
  const div = document.createElement("div");
  div.style.cssText =
    "margin-bottom:14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("label");
  label.textContent = t("osv.enrichLabel");
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const rowWrap = document.createElement("div");
  rowWrap.style.cssText = "display:flex;gap:6px";
  const input = document.createElement("input");
  input.id = `${prefix}osv_id`;
  input.autocomplete = "off";
  input.placeholder = "CVE-2021-44228, GHSA-…, PYSEC-…";
  input.value = currentRef || "";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = t("osv.enrichBtn");
  btn.style.flex = "0 0 auto";
  const status = document.createElement("div");
  status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:4px";

  btn.onclick = async () => {
    const id = input.value.trim();
    if (!id) { status.textContent = t("osv.idRequired"); return; }
    btn.disabled = true;
    status.style.color = "var(--text-dim)";
    status.textContent = t("osv.fetching");
    try {
      const r = await api.osvLookup(id);
      const n = applyOsvFields(prefix, r.fields);
      status.style.color = "var(--success)";
      status.textContent = `${r.referential} — ${n} ${t("osv.fieldsFilled")}${r.cvssVector ? ` · ${r.cvssVector}` : ""}`;
    } catch (e) {
      status.style.color = "var(--danger)";
      status.textContent = (e as Error).message;
    } finally {
      btn.disabled = false;
    }
  };

  rowWrap.appendChild(input);
  rowWrap.appendChild(btn);
  div.appendChild(label);
  div.appendChild(rowWrap);
  div.appendChild(status);
  body.appendChild(div);
}

// ── SOCRadar IOC Radar: search a CVE (VULNERABILITY form) ────────
// If VULReferentialID begins with "CVE-", shows a panel (reactive to the field)
// with a link to https://socradar.io/free-tools/ioc-radar/<CVE>. Hidden otherwise.
function appendSocradarIocField(prefix: string): void {
  const after = document.getElementById(`${prefix}field_VULReferentialID`);
  const input = document.getElementById(`${prefix}VULReferentialID`) as HTMLInputElement | null;
  if (!after || !input) return;

  const panel = document.createElement("div");
  panel.style.cssText = "margin:0 0 10px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("div");
  label.textContent = t("socradar.label");
  label.style.cssText = "font-size:12px;color:var(--text-muted);margin-bottom:8px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;align-items:center";
  const code = document.createElement("code");
  code.style.cssText = "flex:1;font-size:12px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
  const btn = document.createElement("a");
  btn.className = "btn btn-ghost btn-sm";
  btn.target = "_blank";
  btn.rel = "noopener";
  btn.textContent = t("socradar.launch");
  btn.style.flex = "0 0 auto";
  row.appendChild(code);
  row.appendChild(btn);
  panel.appendChild(label);
  panel.appendChild(row);
  after.insertAdjacentElement("afterend", panel);

  const update = (): void => {
    const v = input.value.trim();
    const isCve = /^CVE-/i.test(v);
    panel.style.display = isCve ? "" : "none"; // visible only for a CVE
    if (isCve) {
      const cve = v.toUpperCase();
      code.textContent = cve;
      btn.setAttribute("href", `https://socradar.io/free-tools/ioc-radar/${encodeURIComponent(cve)}`);
      btn.style.pointerEvents = ""; btn.style.opacity = "";
    } else {
      btn.removeAttribute("href");
    }
  };
  input.addEventListener("input", update);
  update();
}

// "↓ EPSS" button placed to the RIGHT of the EPSS field (VULNERABILITY form):
// fetches the EPSS score from FIRST.org for the CVE in VULReferentialID.
// Adds a native date picker to the right of a (text) date field and keeps the two
// in sync (YYYY-MM-DD). Lets users pick a date from a calendar while the stored
// value stays a plain text field. Idempotent per field.
function appendDatePicker(prefix: string, col: string): void {
  const input = document.getElementById(`${prefix}${col}`) as HTMLInputElement | null;
  if (!input || input.dataset.dpWired) return;
  const parent = input.parentElement;
  if (!parent) return;
  input.dataset.dpWired = "1";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;align-items:center";
  parent.insertBefore(row, input);
  input.style.flex = "1";
  row.appendChild(input);
  const picker = document.createElement("input");
  picker.type = "date";
  picker.title = `${col}: pick a date`;
  picker.style.cssText =
    "flex:0 0 auto;width:150px;background:var(--bg);border:1px solid var(--border);border-radius:6px;" +
    "color:var(--text);padding:6px 8px;font-size:13px;color-scheme:dark";
  row.appendChild(picker);
  // The native picker only handles YYYY-MM-DD; extract that from the free-text field.
  const isoOf = (v: string): string => (v || "").trim().match(/\d{4}-\d{2}-\d{2}/)?.[0] ?? "";
  picker.value = isoOf(input.value);
  picker.addEventListener("change", () => {
    if (!picker.value) return;
    input.value = picker.value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  input.addEventListener("input", () => {
    const iso = isoOf(input.value);
    if (iso !== picker.value) picker.value = iso;
  });
}

// ASSET form: when AssetName looks like an email address, the address is
// captured into the email directory (EMAIL / EMAILADDRESS / EMAILFORORGANISATION)
// server-side on save. Detection happens on blur and shows an inline hint; the
// actual harvest is triggered at validation (see submitInsert / edit-save).
const ASSET_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Returns the trimmed AssetName value when it is a valid email, "" otherwise.
function assetNameEmail(prefix: string): string {
  const v = ((document.getElementById(`${prefix}AssetName`) as HTMLInputElement | null)?.value || "").trim();
  return ASSET_EMAIL_RE.test(v) ? v : "";
}
function appendEmailHarvestHint(prefix: string): void {
  const input = document.getElementById(`${prefix}AssetName`) as HTMLInputElement | null;
  if (!input || input.dataset.emailHintWired) return;
  const parent = input.parentElement;
  if (!parent) return;
  input.dataset.emailHintWired = "1";
  const hint = document.createElement("div");
  hint.id = `${prefix}assetEmailHint`;
  hint.style.cssText = "display:none;margin-top:4px;font-size:12px;color:var(--accent)";
  hint.textContent = "📧 Looks like an email address — it will be added to the email directory on save.";
  parent.appendChild(hint);
  const refresh = (): void => { hint.style.display = assetNameEmail(prefix) ? "block" : "none"; };
  input.addEventListener("blur", refresh);
  input.addEventListener("input", refresh);
  refresh();
}

// "Attack-surface graph" button on the ASSET edit form — opens the force-directed
// map (/attack-surface) focused on this asset (apps, CPEs, vulns, orgs, persons,
// threats, incidents, related assets, tags) in a new tab.
function appendAttackSurfaceButton(body: HTMLElement, assetId: number | null): void {
  if (!assetId) return;
  const div = document.createElement("div");
  div.style.cssText = "margin:6px 0";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = "🕸️ Attack-surface graph";
  btn.title = "Visualize this asset's attack surface as a graph";
  btn.onclick = () => window.open(`/attack-surface?asset=${assetId}`, "_blank", "noopener");
  div.appendChild(btn);
  body.appendChild(div);
}

// Generic "local-AI action" button + result area appended to a form body.
// `run` returns the text/markdown to display. Used by the CTI agents (vuln triage,
// report enrichment) — the local LLM (Ollama) does the work, the analyst controls.
function appendAiActionButton(body: HTMLElement, label: string, run: () => Promise<string>): void {
  const wrap = document.createElement("div");
  wrap.style.cssText = "margin:10px 0;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = label;
  const out = document.createElement("div");
  out.style.cssText = "margin-top:8px;font-size:12px;color:var(--text-soft);white-space:pre-wrap;line-height:1.5;display:none";
  btn.onclick = async () => {
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = "… (local AI)";
    out.style.display = "block";
    out.style.color = "var(--text-soft)";
    out.textContent = "…";
    try {
      out.textContent = await run();
    } catch (e) {
      out.textContent = "⚠️ " + ((e as Error)?.message || e);
      out.style.color = "var(--danger)";
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  };
  wrap.appendChild(btn);
  wrap.appendChild(out);
  body.appendChild(wrap);
}

// ── POLICY: draft the policy body with the local AI (fills the PolicyContent rich-text field) ──
function appendPolicyAiDraftPanel(body: HTMLElement, prefix: string): void {
  const gv = (id: string): string => {
    const el = document.getElementById(prefix + id) as HTMLInputElement | HTMLTextAreaElement | null;
    return el ? String(el.value || "").trim() : "";
  };
  const wrap = document.createElement("div");
  wrap.style.cssText = "margin:10px 0;padding:10px;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  const head = document.createElement("div");
  head.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap";
  const title = document.createElement("span");
  title.innerHTML = "✨ <b>Draft with local AI</b> <span style='color:var(--text-muted);font-size:11px'>fills Policy content from the title &amp; scope (Ollama, offline-safe — nothing leaves the machine)</span>";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = "✨ Draft policy content";
  const status = document.createElement("span");
  status.style.cssText = "font-size:11px;color:var(--text-muted)";
  head.appendChild(title); head.appendChild(btn); head.appendChild(status);
  wrap.appendChild(head); body.appendChild(wrap);

  btn.onclick = async () => {
    const name = gv("PolicyName");
    if (!name) { status.textContent = "⚠️ enter a Policy name first"; return; }
    const hidden = document.getElementById(prefix + "PolicyContent") as HTMLTextAreaElement | null;
    if (!hidden) { status.textContent = "⚠️ no Policy content field on this form"; return; }
    const editor = hidden.parentElement?.querySelector(".rte-editor") as HTMLElement | null;
    if (editor && (editor.textContent || "").trim().length > 20 && !confirm("Replace the existing Policy content with an AI draft?")) return;
    btn.disabled = true; const old = btn.textContent; btn.textContent = "… (local AI)"; status.textContent = "";
    try {
      const r = await fetch("/api/ai/draft-policy", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description: gv("PolicyDescription") || undefined, scope: gv("Scope") || undefined, category: gv("PolicyCategory") || gv("Category") || undefined, framework: gv("Framework") || undefined }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
      const html = String(j.content || "");
      hidden.value = html;
      if (editor) editor.innerHTML = html;
      status.textContent = j.offline ? "✓ drafted (deterministic — local AI unavailable)" : "✓ drafted by " + j.model;
    } catch (e) {
      status.textContent = "⚠️ " + ((e as Error)?.message || e);
    } finally {
      btn.disabled = false; btn.textContent = old;
    }
  };
}

// ── CRISISSCENARIO: generate the Description with the local AI ───────────────
function appendCrisisScenarioAiPanel(body: HTMLElement, prefix: string): void {
  const gv = (id: string): string => {
    const el = document.getElementById(prefix + id) as HTMLInputElement | HTMLTextAreaElement | null;
    return el ? String(el.value || "").trim() : "";
  };
  const wrap = document.createElement("div");
  wrap.style.cssText = "margin:10px 0;padding:10px;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  const head = document.createElement("div");
  head.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap";
  const title = document.createElement("span");
  title.innerHTML = "✨ <b>Draft with local AI</b> <span style='color:var(--text-muted);font-size:11px'>generates a crisis-scenario Description from the name &amp; type (Ollama, offline-safe)</span>";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = "✨ Draft scenario description";
  const status = document.createElement("span");
  status.style.cssText = "font-size:11px;color:var(--text-muted)";
  head.appendChild(title); head.appendChild(btn); head.appendChild(status);
  wrap.appendChild(head); body.appendChild(wrap);

  btn.onclick = async () => {
    const name = gv("ScenarioName");
    if (!name) { status.textContent = "⚠️ enter a Scenario name first"; return; }
    const hidden = document.getElementById(prefix + "Description") as HTMLTextAreaElement | null;
    if (!hidden) { status.textContent = "⚠️ no Description field on this form"; return; }
    const editor = hidden.parentElement?.querySelector(".rte-editor") as HTMLElement | null;
    if (editor && (editor.textContent || "").trim().length > 20 && !confirm("Replace the existing Description with an AI draft?")) return;
    btn.disabled = true; const old = btn.textContent; btn.textContent = "… (local AI)"; status.textContent = "";
    try {
      const r = await fetch("/api/ai/draft-crisis-scenario", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, scenarioType: gv("ScenarioType") || undefined, severity: gv("Severity") || undefined, objectives: gv("Objectives") || undefined, threatActor: gv("ThreatActor") || undefined }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
      const html = String(j.content || "");
      hidden.value = html;
      if (editor) editor.innerHTML = html;
      status.textContent = j.offline ? "✓ drafted (deterministic — local AI unavailable)" : "✓ drafted by " + j.model;
    } catch (e) {
      status.textContent = "⚠️ " + ((e as Error)?.message || e);
    } finally {
      btn.disabled = false; btn.textContent = old;
    }
  };
}

// ── CRISISSCENARIO: map the scenario to MITRE ATT&CK techniques (replaces the free-text field) ──
function appendCrisisAttackMapping(body: HTMLElement, prefix: string): void {
  const hidden = document.getElementById(prefix + "AttackTechniques") as HTMLInputElement | null;
  if (!hidden) return;
  const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  // Hide the raw free-text field row; keep the input as the serialized storage (still submitted).
  const fieldRow = hidden.closest("div");
  if (fieldRow && fieldRow !== body) (fieldRow as HTMLElement).style.display = "none";

  type Tech = { attackId: string; name: string };
  const parse = (s: string): Tech[] => s.split(/[;\n]+/).map((t) => t.trim()).filter(Boolean).map((t) => {
    const m = t.match(/^(T\d[\w.]*)\s*\((.*)\)$/i) || t.match(/^(T\d[\w.]*)\s*[—–-]\s*(.*)$/i) || t.match(/^(T\d[\w.]*)$/i);
    return m ? { attackId: m[1], name: (m[2] || "").trim() } : { attackId: t, name: "" };
  });
  const serialize = (xs: Tech[]): string => xs.map((x) => x.name ? `${x.attackId} (${x.name})` : x.attackId).join("; ");
  const selected: Tech[] = parse(hidden.value);

  const wrap = document.createElement("div");
  wrap.style.cssText = "margin:10px 0;padding:10px;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  wrap.dataset.fullwidth = "1";
  const head = document.createElement("div");
  head.style.cssText = "margin-bottom:6px";
  head.innerHTML = "🎯 <b>ATT&amp;CK techniques</b> <span style='color:var(--text-muted);font-size:11px'>— map this scenario to MITRE ATT&amp;CK (search by ID or name)</span>";
  const search = document.createElement("input");
  search.type = "text"; search.placeholder = "Search techniques — e.g. phishing, T1566, lateral movement…";
  search.style.cssText = FIELD_INPUT_CSS;
  const results = document.createElement("div");
  results.style.cssText = "margin-top:4px;max-height:220px;overflow:auto;display:none;border:1px solid var(--border);border-radius:6px";
  const tableWrap = document.createElement("div");
  tableWrap.style.cssText = "margin-top:8px";
  wrap.appendChild(head); wrap.appendChild(search); wrap.appendChild(results); wrap.appendChild(tableWrap);
  body.appendChild(wrap);

  const sync = (): void => { hidden.value = serialize(selected); };
  const renderTable = (): void => {
    if (!selected.length) { tableWrap.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:4px 0">No techniques mapped yet — search above to add them.</div>`; return; }
    const rows = selected.map((t, i) => `<tr>
      <td style="padding:4px 8px;font-family:ui-monospace,monospace;white-space:nowrap"><a href="https://attack.mitre.org/techniques/${esc(t.attackId.replace(".", "/"))}/" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">${esc(t.attackId)}</a></td>
      <td style="padding:4px 8px">${esc(t.name || "")}</td>
      <td style="padding:4px 8px;text-align:right"><button type="button" class="btn btn-ghost btn-sm" data-rm="${i}" title="Remove">✕</button></td></tr>`).join("");
    tableWrap.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="color:var(--text-muted);font-size:11px;text-transform:uppercase"><th style="text-align:left;padding:4px 8px">ATT&amp;CK ID</th><th style="text-align:left;padding:4px 8px">Technique</th><th style="width:30px"></th></tr></thead><tbody>${rows}</tbody></table>`;
    Array.prototype.forEach.call(tableWrap.querySelectorAll("[data-rm]"), (b: HTMLElement) => {
      b.onclick = () => { selected.splice(Number(b.getAttribute("data-rm")), 1); sync(); renderTable(); };
    });
  };
  renderTable();

  let timer: number | undefined;
  const doSearch = async (): Promise<void> => {
    const q = search.value.trim();
    if (q.length < 2) { results.style.display = "none"; return; }
    try {
      const r = await fetch(`/api/attack/technique-search?q=${encodeURIComponent(q)}&limit=40`);
      const list = (await r.json()) as { AttackID: string; Name: string }[];
      if (!Array.isArray(list) || !list.length) { results.innerHTML = `<div style="padding:6px 8px;color:var(--text-muted);font-size:12px">No matches.</div>`; results.style.display = "block"; return; }
      results.innerHTML = list.map((t) => `<div class="ctam-r" data-id="${esc(t.AttackID)}" data-nm="${esc(t.Name)}" style="padding:5px 8px;cursor:pointer;border-bottom:1px solid var(--border);font-size:13px"><span style="font-family:ui-monospace,monospace;color:var(--accent)">${esc(t.AttackID)}</span> ${esc(t.Name)}</div>`).join("");
      results.style.display = "block";
      Array.prototype.forEach.call(results.querySelectorAll(".ctam-r"), (el: HTMLElement) => {
        el.onmousedown = (e: Event) => {
          e.preventDefault(); // keep focus / fire before blur
          const id = el.getAttribute("data-id")!, nm = el.getAttribute("data-nm") || "";
          if (!selected.some((s) => s.attackId === id)) { selected.push({ attackId: id, name: nm }); sync(); renderTable(); }
          search.value = ""; results.style.display = "none";
        };
      });
    } catch { results.style.display = "none"; }
  };
  search.addEventListener("input", () => { window.clearTimeout(timer); timer = window.setTimeout(() => void doSearch(), 220) as unknown as number; });
  search.addEventListener("blur", () => setTimeout(() => { results.style.display = "none"; }, 200));
}

// ── SSVC (CISA Stakeholder-Specific Vulnerability Categorization) calculator ──
// CISA "Coordinator" decision table v2.0.3 (verbatim 36-row lookup, matches
// CERTCC/SSVC and the import_nvd_cve.py / ssvc.py Python engine).
const SSVC_TABLE: Map<string, string> = new Map(
  `none,no,partial,low,Track|none,no,partial,medium,Track|none,no,partial,high,Track|none,no,total,low,Track|none,no,total,medium,Track|none,no,total,high,Track*|none,yes,partial,low,Track|none,yes,partial,medium,Track|none,yes,partial,high,Attend|none,yes,total,low,Track|none,yes,total,medium,Track|none,yes,total,high,Attend|public poc,no,partial,low,Track|public poc,no,partial,medium,Track|public poc,no,partial,high,Track*|public poc,no,total,low,Track|public poc,no,total,medium,Track*|public poc,no,total,high,Attend|public poc,yes,partial,low,Track|public poc,yes,partial,medium,Track|public poc,yes,partial,high,Attend|public poc,yes,total,low,Track|public poc,yes,total,medium,Track*|public poc,yes,total,high,Attend|active,no,partial,low,Track|active,no,partial,medium,Track|active,no,partial,high,Attend|active,no,total,low,Track|active,no,total,medium,Attend|active,no,total,high,Act|active,yes,partial,low,Attend|active,yes,partial,medium,Attend|active,yes,partial,high,Act|active,yes,total,low,Attend|active,yes,total,medium,Act|active,yes,total,high,Act`
    .split("|").map((r) => { const p = r.split(","); return [`${p[0]}|${p[1]}|${p[2]}|${p[3]}`, p[4]] as [string, string]; })
);
const SSVC_ALIAS: Record<string, string> = { poc: "public poc", "public-poc": "public poc", exploited: "active", complete: "total", full: "total" };
function ssvcNorm(v: unknown, allowed: string[], def: string): string {
  let s = String(v ?? "").trim().toLowerCase(); s = SSVC_ALIAS[s] ?? s;
  return allowed.includes(s) ? s : def;
}
function ssvcDecide(e: string, a: string, t: string, m: string): string {
  return SSVC_TABLE.get(`${ssvcNorm(e, ["none", "public poc", "active"], "none")}|${ssvcNorm(a, ["no", "yes"], "no")}|${ssvcNorm(t, ["partial", "total"], "partial")}|${ssvcNorm(m, ["low", "medium", "high"], "medium")}`) ?? "Track";
}
function ssvcVectorOf(e: string, a: string, t: string, m: string, d: string): string {
  const E: Record<string, string> = { none: "N", "public poc": "P", active: "A" };
  const A: Record<string, string> = { no: "N", yes: "Y" }, T: Record<string, string> = { partial: "P", total: "T" }, M: Record<string, string> = { low: "L", medium: "M", high: "H" };
  const date = new Date().toISOString().slice(0, 10);
  return `SSVCv2/E:${E[ssvcNorm(e, ["none", "public poc", "active"], "none")]}/Au:${A[ssvcNorm(a, ["no", "yes"], "no")]}/T:${T[ssvcNorm(t, ["partial", "total"], "partial")]}/M:${M[ssvcNorm(m, ["low", "medium", "high"], "medium")]}/D:${d}/${date}/`;
}
const SSVC_DECISION_COLOR: Record<string, string> = { Act: "#f87171", Attend: "#fb923c", "Track*": "#fbbf24", Track: "#34d399" };

/** Inline SSVC calculator on the VULNERABILITY form: live decision from the four
 *  decision-point dropdowns (writes SsvcDecision + SsvcVector), plus a one-click
 *  "Suggest from CVSS / KEV / EPSS" that derives the inputs (mirrors ssvc.py). */
function appendSsvcCalculator(body: HTMLElement, prefix: string): void {
  const fld = (c: string): HTMLInputElement | null => document.getElementById(`${prefix}${c}`) as HTMLInputElement | null;
  if (!fld("SsvcDecision") || (body.dataset.ssvcWired === "1")) return; // SSVC columns present?
  body.dataset.ssvcWired = "1";
  const g = (c: string): string => (fld(c)?.value || "").trim();

  const wrap = document.createElement("div");
  wrap.style.cssText = "margin:10px 0;padding:10px;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  const head = document.createElement("div");
  head.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px";
  const title = document.createElement("span");
  title.innerHTML = "🧮 <b>SSVC</b> <span style='color:var(--text-muted);font-size:11px'>CISA Stakeholder-Specific Vulnerability Categorization</span>";
  const suggest = document.createElement("button");
  suggest.type = "button"; suggest.className = "btn btn-ghost btn-sm"; suggest.textContent = "⤓ Suggest from CVSS / KEV / EPSS";
  suggest.title = "Derive the four decision points from this CVE's KEV flag, EPSS and CVSS metrics";
  const badge = document.createElement("span");
  badge.style.cssText = "margin-left:auto;font-weight:700;border-radius:6px;padding:3px 12px;color:#0b0e14;font-size:14px";
  const vec = document.createElement("div");
  vec.style.cssText = "font-family:ui-monospace,monospace;font-size:11px;color:var(--text-muted);margin-top:4px;word-break:break-all";
  head.appendChild(title); head.appendChild(suggest); head.appendChild(badge);
  wrap.appendChild(head); wrap.appendChild(vec);
  body.appendChild(wrap);

  const recompute = (): void => {
    const e = g("SsvcExploitation") || "none", a = g("SsvcAutomatable") || "no";
    const t = g("SsvcTechnicalImpact") || "partial", m = g("SsvcMissionWellbeing") || "medium";
    const d = ssvcDecide(e, a, t, m);
    const v = ssvcVectorOf(e, a, t, m, d);
    badge.textContent = d; badge.style.background = SSVC_DECISION_COLOR[d] || "#94a3b8";
    vec.textContent = v;
    const dec = fld("SsvcDecision"); if (dec) dec.value = d;
    const vfld = fld("SsvcVector"); if (vfld) vfld.value = v;
  };
  for (const c of ["SsvcExploitation", "SsvcAutomatable", "SsvcTechnicalImpact", "SsvcMissionWellbeing"]) {
    const el = fld(c); if (el) { el.addEventListener("input", recompute); el.addEventListener("change", recompute); }
  }
  suggest.onclick = (): void => {
    const truthy = (x: string): boolean => ["1", "true", "yes", "y", "t"].includes(x.trim().toLowerCase());
    const hi = (x: string): boolean => ["HIGH", "COMPLETE"].includes(x.trim().toUpperCase());
    const e = (truthy(g("KEV")) || truthy(g("Exploited"))) ? "active" : (truthy(g("EasilyExploitable")) || truthy(g("VULExploitable"))) ? "public poc" : "none";
    const base = parseFloat(g("CVSSBaseScore")) || 0;
    const t = ((hi(g("CVSSMetricConfImpact")) && hi(g("CVSSMetricIntegImpact")) && hi(g("CVSSMetricAvailImpact"))) || base >= 9) ? "total" : "partial";
    const av = g("CVSSMetricAccessVector").toUpperCase(), ac = g("CVSSMetricAccessComplexity").toUpperCase(), au = g("CVSSMetricAuthentication").toUpperCase();
    const epss = parseFloat(g("EPSS")) || 0;
    const a = (((av === "NETWORK" || av === "N") && (ac === "LOW" || ac === "L") && (au === "NONE" || au === "N")) || epss >= 0.5) ? "yes" : "no";
    const setF = (c: string, val: string): void => { const el = fld(c); if (el && !el.value.trim()) el.value = val; else if (el && c !== "SsvcMissionWellbeing") el.value = val; };
    setF("SsvcExploitation", e); setF("SsvcAutomatable", a); setF("SsvcTechnicalImpact", t);
    if (!g("SsvcMissionWellbeing")) { const el = fld("SsvcMissionWellbeing"); if (el) el.value = "medium"; }
    recompute();
    toast("SSVC decision points derived from CVSS / KEV / EPSS.");
  };
  recompute();
}

function appendEpssButton(prefix: string): void {
  const input = document.getElementById(`${prefix}EPSS`) as HTMLInputElement | null;
  if (!input || input.dataset.epssWired) return;
  const parent = input.parentElement;
  if (!parent) return;
  input.dataset.epssWired = "1";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;align-items:center";
  parent.insertBefore(row, input);
  input.style.flex = "1";
  row.appendChild(input);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = "↓ EPSS";
  btn.title = "Fetch the EPSS score from FIRST.org for the CVE in VULReferentialID";
  btn.style.flex = "0 0 auto";
  row.appendChild(btn);
  const cveInput = document.getElementById(`${prefix}VULReferentialID`) as HTMLInputElement | null;
  const cveOf = (): string => (cveInput?.value || "").trim().toUpperCase();

  // `silent` suppresses validation/error toasts (used by the auto-on-blur path).
  async function fetchEpss(silent: boolean): Promise<void> {
    const cve = cveOf();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cve)) {
      if (!silent) toast("Set VULReferentialID to a CVE id first (e.g. CVE-2022-27225).");
      return;
    }
    const old = btn.textContent; btn.disabled = true; btn.textContent = "…";
    try {
      const r = await fetch(`/api/epss?cve=${encodeURIComponent(cve)}`);
      const d = await r.json().catch(() => ({})) as { error?: string; epss?: number | null; percentile?: number | null; date?: string };
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      if (d.epss == null) { if (!silent) toast(`No EPSS score published for ${cve}.`); return; }
      input.value = String(d.epss);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      const pct = d.percentile != null ? ` (percentile ${(d.percentile * 100).toFixed(1)}%)` : "";
      toast(`EPSS for ${cve}: ${d.epss}${pct}${d.date ? ` — ${d.date}` : ""}`);
    } catch (e) {
      if (!silent) toast("EPSS fetch failed: " + String(e));
    } finally {
      btn.disabled = false; btn.textContent = old;
    }
  }
  btn.onclick = () => void fetchEpss(false);

  // Auto-populate EPSS when leaving the VULReferentialID field with a CVE id.
  // Tracks the last auto-fetched CVE so re-blurring the same value doesn't refetch.
  if (cveInput && !cveInput.dataset.epssBlurWired) {
    cveInput.dataset.epssBlurWired = "1";
    cveInput.addEventListener("blur", () => {
      const cve = cveOf();
      if (/^CVE-\d{4}-\d{4,7}$/.test(cve) && cveInput.dataset.epssAuto !== cve) {
        cveInput.dataset.epssAuto = cve;
        void fetchEpss(true);
      }
    });
  }
}

// ── CIRCL vulnerability-lookup search (KEV catalogues) ─────────────────────
// Search field injected into the VULNERABILITY form: enter a CVE id
// or "vendor product" → list of results (KEV badge) → fill / import.
function appendCirclSearchField(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText =
    "margin-bottom:14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("label");
  label.textContent = t("circl.label");
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const rowWrap = document.createElement("div");
  rowWrap.style.cssText = "display:flex;gap:6px";
  const input = document.createElement("input");
  input.id = `${prefix}circl_q`;
  input.autocomplete = "off";
  input.placeholder = "CVE-2021-44228  ·  apache log4j";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = t("circl.searchBtn");
  btn.style.flex = "0 0 auto";
  const results = document.createElement("div");
  results.style.cssText = "margin-top:6px;max-height:200px;overflow:auto;display:none";
  const status = document.createElement("div");
  status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:4px";

  async function fillFrom(id: string): Promise<void> {
    status.style.color = "var(--text-dim)";
    status.textContent = t("circl.fetching");
    try {
      const r = await api.circlLookup(id);
      const n = applyOsvFields(prefix, r.fields); // fills the common f_/ef_ fields
      // Business rules on the content of the CIRCL data:
      //  • KEV flag present → checks the KEV box.
      //  • "active exploitation" present → VULExploitable=1 + checks Exploited.
      const dataText = (JSON.stringify(r.fields) + " " + (r.summary ?? "")).toLowerCase();
      if (r.kev) setFormField(prefix, "KEV", "1");
      if (dataText.includes("exploitation active")) {
        setFormField(prefix, "VULExploitable", "1");
        setFormField(prefix, "Exploited", "1");
      }
      status.style.color = r.kev ? "var(--danger)" : "var(--success)";
      status.textContent =
        `${r.referential}${r.kev ? " — ⚠️ KEV (exploitation active)" : ""} · ${n} ${t("osv.fieldsFilled")}` +
        (r.cvssVector ? ` · ${r.cvssVector}` : "");
    } catch (e) {
      status.style.color = "var(--danger)";
      status.textContent = (e as Error).message;
    }
  }

  async function runSearch(): Promise<void> {
    const q = input.value.trim();
    if (!q) return;
    btn.disabled = true;
    results.style.display = "none";
    status.style.color = "var(--text-dim)";
    status.textContent = t("circl.searching");
    try {
      const hits = await api.circlSearch(q);
      results.innerHTML = "";
      if (!hits.length) {
        status.textContent = t("circl.noResult");
      } else {
        status.textContent = `${hits.length} ${t("circl.results")}`;
        for (const h of hits) {
          const kev = h.summary.startsWith("[KEV]");
          const item = document.createElement("div");
          item.style.cssText =
            "display:flex;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px";
          const meta = document.createElement("div");
          meta.style.cssText = "min-width:0;flex:1";
          meta.innerHTML =
            `<div style="font-size:12px;color:var(--text)">${h.id}` +
            (kev ? ` <span style="font-size:9px;background:#7f1d1d;color:#fecaca;border-radius:8px;padding:1px 6px">KEV</span>` : "") +
            `</div><div style="font-size:10px;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.summary.replace(/^\[KEV\]\s*/, "")}</div>`;
          const fill = document.createElement("button");
          fill.type = "button"; fill.className = "btn btn-ghost btn-sm"; fill.textContent = t("circl.fill");
          fill.onclick = () => void fillFrom(h.id);
          item.appendChild(meta);
          item.appendChild(fill);
          results.appendChild(item);
        }
        results.style.display = "";
      }
    } catch (e) {
      status.style.color = "var(--danger)";
      status.textContent = (e as Error).message;
    } finally {
      btn.disabled = false;
    }
  }

  btn.onclick = () => void runSearch();
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); void runSearch(); } };
  rowWrap.appendChild(input);
  rowWrap.appendChild(btn);
  div.appendChild(label);
  div.appendChild(rowWrap);
  div.appendChild(results);
  div.appendChild(status);
  body.appendChild(div);
}

// ── Exploit-DB search (local SearchSploit index) ──────────────────────────────
// Injected into the VULNERABILITY form: looks up public exploits for the CVE,
// links out to exploit-db.com, and can flag the vulnerability as exploitable.
const CVE_RX = /CVE-\d{4}-\d{3,7}/i;
function appendExploitDbSearchField(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("label");
  label.textContent = t("edb.vlabel");
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const rowWrap = document.createElement("div"); rowWrap.style.cssText = "display:flex;gap:6px";
  const input = document.createElement("input");
  input.id = `${prefix}edb_q`; input.autocomplete = "off"; input.placeholder = "CVE-2017-0144";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = t("edb.search"); btn.style.flex = "0 0 auto";
  const openBtn = document.createElement("button");
  openBtn.type = "button"; openBtn.className = "btn btn-ghost btn-sm"; openBtn.textContent = t("edb.openPage"); openBtn.style.flex = "0 0 auto";
  const results = document.createElement("div"); results.style.cssText = "margin-top:6px;max-height:220px;overflow:auto;display:none";
  const status = document.createElement("div"); status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:4px";

  function currentCve(): string {
    for (const col of ["VULReferential", "VULName", "VULReferentialID", "VULDescription"]) {
      const el = document.getElementById(`${prefix}${col}`) as HTMLInputElement | HTMLTextAreaElement | null;
      const m = el?.value?.match(CVE_RX);
      if (m) return m[0].toUpperCase();
    }
    return "";
  }

  async function run(): Promise<void> {
    const m = input.value.trim().match(CVE_RX);
    if (!m) { status.style.color = "var(--text-dim)"; status.textContent = t("edb.needCve"); return; }
    const cve = m[0].toUpperCase();
    btn.disabled = true; results.style.display = "none"; status.style.color = "var(--text-dim)"; status.textContent = t("edb.searching");
    try {
      const r = await api.exploitdbForCve(cve);
      results.innerHTML = "";
      if (!r.results.length) { status.textContent = t("edb.none"); }
      else {
        status.style.color = "var(--danger)";
        status.textContent = `⚠️ ${r.results.length} ${t("edb.found")}`;
        for (const e of r.results) {
          const item = document.createElement("div");
          item.style.cssText = "display:flex;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px";
          const meta = document.createElement("div"); meta.style.cssText = "min-width:0;flex:1";
          meta.innerHTML =
            `<div style="font-size:12px;color:var(--text)">EDB-${e.id} <span style="font-size:10px;color:var(--text-dim)">${e.type}/${e.platform}</span></div>` +
            `<div style="font-size:10px;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.title}</div>`;
          const open = document.createElement("a");
          open.href = e.url; open.target = "_blank"; open.rel = "noopener noreferrer"; open.className = "btn btn-ghost btn-sm"; open.textContent = t("edb.view");
          item.appendChild(meta); item.appendChild(open); results.appendChild(item);
        }
        const flag = document.createElement("button");
        flag.type = "button"; flag.className = "btn btn-ghost btn-sm"; flag.textContent = t("edb.markExploitable"); flag.style.marginTop = "4px";
        flag.onclick = () => { setFormField(prefix, "VULExploitable", "1"); setFormField(prefix, "Exploited", "1"); toast(t("edb.flagged"), "ok"); };
        results.appendChild(flag);
        results.style.display = "";
      }
    } catch (e) {
      status.style.color = "var(--danger)"; status.textContent = (e as Error).message;
    } finally { btn.disabled = false; }
  }

  btn.onclick = () => void run();
  openBtn.onclick = () => { const cve = (input.value.trim().match(CVE_RX)?.[0] || currentCve()); window.open(`/exploitdb${cve ? `?cve=${encodeURIComponent(cve)}` : ""}`, "_blank", "noopener"); };
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); void run(); } };
  rowWrap.appendChild(input); rowWrap.appendChild(btn); rowWrap.appendChild(openBtn);
  div.appendChild(label); div.appendChild(rowWrap); div.appendChild(results); div.appendChild(status);
  body.appendChild(div);
  const cve = currentCve(); if (cve) { input.value = cve; void run(); }
}

// ── GCVE CPE dictionary search (cpe.gcve.eu) — fill the CPE name from an official entry ──
function appendCpeGcveSearch(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("label");
  label.textContent = t("cpegcve.label");
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const rowWrap = document.createElement("div"); rowWrap.style.cssText = "display:flex;gap:6px;flex-wrap:wrap";
  const input = document.createElement("input");
  input.id = `${prefix}gcve_q`; input.autocomplete = "off"; input.placeholder = "apache http_server";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1;min-width:180px";
  const partSel = document.createElement("select");
  partSel.style.cssText = FIELD_INPUT_CSS + ";flex:0 0 auto;width:auto";
  for (const [v, lab] of [["", t("cpegcve.anyPart")], ["a", "application"], ["o", "OS"], ["h", "hardware"]] as [string, string][]) {
    const o = document.createElement("option"); o.value = v; o.textContent = lab; partSel.appendChild(o);
  }
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = t("cpegcve.search"); btn.style.flex = "0 0 auto";
  const results = document.createElement("div"); results.style.cssText = "margin-top:6px;max-height:240px;overflow:auto;display:none";
  const status = document.createElement("div"); status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:4px";

  async function run(): Promise<void> {
    const q = input.value.trim();
    if (q.length < 2) { status.style.color = "var(--text-dim)"; status.textContent = t("cpegcve.need"); return; }
    btn.disabled = true; results.style.display = "none"; status.style.color = "var(--text-dim)"; status.textContent = t("cpegcve.searching");
    try {
      const r = await api.cpeGcveSearch(q, partSel.value);
      results.innerHTML = "";
      if (!r.items.length) { status.textContent = t("cpegcve.none"); }
      else {
        status.textContent = `${r.items.length}${r.total > r.items.length ? `/${r.total}` : ""} ${t("cpegcve.found")}`;
        for (const it of r.items) {
          const item = document.createElement("div");
          item.style.cssText = "display:flex;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px";
          const meta = document.createElement("div"); meta.style.cssText = "min-width:0;flex:1";
          const l1 = document.createElement("div");
          l1.style.cssText = "font-size:11px;font-family:ui-monospace,monospace;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
          l1.textContent = it.cpe;
          if (it.deprecated) { const d = document.createElement("span"); d.style.cssText = "color:var(--danger);font-size:10px;margin-left:6px"; d.textContent = "DEPRECATED"; l1.appendChild(d); }
          const l2 = document.createElement("div");
          l2.style.cssText = "font-size:10px;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
          l2.textContent = it.title || "";
          meta.appendChild(l1); meta.appendChild(l2);
          const use = document.createElement("button");
          use.type = "button"; use.className = "btn btn-ghost btn-sm"; use.textContent = t("cpegcve.use"); use.style.flex = "0 0 auto";
          use.onclick = () => {
            setFormField(prefix, "CPEName", it.cpe);
            const el = document.getElementById(`${prefix}CPEName`) as HTMLInputElement | null;
            if (el) el.dispatchEvent(new Event("input"));
            toast(t("cpegcve.set"), "ok");
          };
          item.appendChild(meta); item.appendChild(use); results.appendChild(item);
        }
        results.style.display = "";
      }
    } catch (e) { status.style.color = "var(--danger)"; status.textContent = (e as Error).message; }
    finally { btn.disabled = false; }
  }
  btn.onclick = () => void run();
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); void run(); } };
  rowWrap.appendChild(input); rowWrap.appendChild(partSel); rowWrap.appendChild(btn);
  div.appendChild(label); div.appendChild(rowWrap); div.appendChild(results); div.appendChild(status);
  body.appendChild(div);
  // Prefill the query from the current CPE name (vendor + product tokens), if any.
  const cur = (document.getElementById(`${prefix}CPEName`) as HTMLInputElement | null)?.value || "";
  const m = cur.match(/^cpe:2\.3:[aoh]:([^:]+):([^:]+)/i);
  if (m) input.value = `${m[1]} ${m[2]}`.replace(/[_*]/g, " ").trim();
}

// ── Multi-engine malware / IOC scan (XMALWARE) ────────────────────────────────
// Injected into the OBSERVABLE form (scan the indicator value) and the DOCUMENT form
// (scan the stored file by its content hash). Renders per-engine verdicts inline and links
// to the full /malware-scan page. mode: "observable" | "documentFile" | "manual".
function appendMalwareScanField(body: HTMLElement, prefix: string, mode: "observable" | "documentFile" | "manual"): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("label");
  label.textContent = "🦠 Malware / IOC scan (multi-engine)";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const rowWrap = document.createElement("div"); rowWrap.style.cssText = "display:flex;gap:6px;flex-wrap:wrap";
  const input = document.createElement("input");
  input.id = `${prefix}mal_q`; input.autocomplete = "off"; input.placeholder = "hash / URL / domain / IP";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1;min-width:200px";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = "Scan"; btn.style.flex = "0 0 auto";
  const docBtn = document.createElement("button");
  docBtn.type = "button"; docBtn.className = "btn btn-ghost btn-sm"; docBtn.textContent = "Scan document file"; docBtn.style.flex = "0 0 auto";
  const openBtn = document.createElement("button");
  openBtn.type = "button"; openBtn.className = "btn btn-ghost btn-sm"; openBtn.textContent = "Open page ↗"; openBtn.style.flex = "0 0 auto";
  const results = document.createElement("div"); results.style.cssText = "margin-top:6px;max-height:240px;overflow:auto;display:none";
  const status = document.createElement("div"); status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:4px";

  function field(col: string): string { return (document.getElementById(`${prefix}${col}`) as HTMLInputElement | HTMLTextAreaElement | null)?.value?.trim() || ""; }

  function render(d: { verdict: string; score: number; positives: number; total: number; summary: string; engines: { engine: string; verdict: string; detection?: string; link?: string; live: boolean }[] }): void {
    const bad = d.verdict === "malicious" || d.verdict === "suspicious";
    status.style.color = bad ? "var(--danger)" : "var(--text-dim)";
    status.textContent = `${bad ? "⚠️ " : ""}${d.verdict.toUpperCase()} — ${d.summary}`;
    results.innerHTML = "";
    for (const e of d.engines) {
      const item = document.createElement("div");
      item.style.cssText = "display:flex;align-items:center;gap:8px;padding:5px 8px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px";
      const meta = document.createElement("div"); meta.style.cssText = "min-width:0;flex:1";
      meta.innerHTML = `<span style="font-size:12px;color:var(--text)">${e.engine}</span> ` +
        `<span style="font-size:10px;color:${e.verdict === "malicious" ? "var(--danger)" : e.verdict === "suspicious" ? "var(--warning,#fbbf24)" : "var(--text-dim)"}">${e.verdict}</span>` +
        (e.detection ? ` <span style="font-size:10px;color:var(--text-dim)">${e.detection}</span>` : "") +
        (e.live ? "" : ` <span style="font-size:9px;color:var(--text-dim)">(${e.verdict === "unconfigured" ? "no key" : "manual"})</span>`);
      item.appendChild(meta);
      if (e.link) { const a = document.createElement("a"); a.href = e.link; a.target = "_blank"; a.rel = "noopener noreferrer"; a.className = "btn btn-ghost btn-sm"; a.textContent = "pivot ↗"; item.appendChild(a); }
      results.appendChild(item);
    }
    results.style.display = "";
  }

  async function postJson(url: string, bodyObj: unknown): Promise<any> {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(bodyObj) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }

  async function runTarget(): Promise<void> {
    const target = input.value.trim();
    if (!target) { status.style.color = "var(--text-dim)"; status.textContent = "Enter a hash, URL, domain or IP."; return; }
    btn.disabled = true; results.style.display = "none"; status.style.color = "var(--text-dim)"; status.textContent = "Scanning…";
    try { render(await postJson("/api/malware-scan/run", { target })); }
    catch (e) { status.style.color = "var(--danger)"; status.textContent = (e as Error).message; }
    finally { btn.disabled = false; }
  }
  async function runDoc(): Promise<void> {
    const id = field("DocumentID");
    if (!id) { status.style.color = "var(--text-dim)"; status.textContent = "Save the document first (no DocumentID yet)."; return; }
    docBtn.disabled = true; results.style.display = "none"; status.style.color = "var(--text-dim)"; status.textContent = "Hashing & scanning the stored file…";
    try { render(await postJson(`/api/malware-scan/document/${encodeURIComponent(id)}`, {})); }
    catch (e) { status.style.color = "var(--danger)"; status.textContent = (e as Error).message; }
    finally { docBtn.disabled = false; }
  }

  btn.onclick = () => void runTarget();
  docBtn.onclick = () => void runDoc();
  openBtn.onclick = () => window.open("/malware-scan", "_blank", "noopener");
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); void runTarget(); } };

  rowWrap.appendChild(input); rowWrap.appendChild(btn);
  if (mode === "documentFile") rowWrap.appendChild(docBtn);
  rowWrap.appendChild(openBtn);
  div.appendChild(label); div.appendChild(rowWrap); div.appendChild(results); div.appendChild(status);
  body.appendChild(div);

  // Prefill the IOC input from the OBSERVABLE value (Value column).
  if (mode === "observable") { const v = field("Value"); if (v) input.value = v; }
}

// Toolbar button: imports a VULNERABILITY from CIRCL (KEV) by id.
async function importFromCircl(): Promise<void> {
  const id = (prompt(t("circl.promptId")) || "").trim();
  if (!id) return;
  try {
    const r = await api.circlImport(id);
    const verb = r.action === "inserted" ? t("osv.inserted") : t("osv.updated");
    toast(`${verb} : ${r.referential}${r.kev ? " ⚠️ KEV" : ""} (VulnerabilityID ${r.vulnerabilityId})`, "ok");
    await loadRows();
  } catch (e) {
    toast("CIRCL : " + (e as Error).message, "err");
  }
}

// ── STIX 2.1 bundle generation from the THREAT form ─────────────────
function isStixTable(): boolean {
  return currentDb === "XTHREAT" && currentTable === "THREAT";
}

function stripHtml(html: string): string {
  const d = document.createElement("div");
  d.innerHTML = html || "";
  return (d.textContent || "").trim();
}

// Builds a STIX 2.1 bundle from the form values.
function buildStixBundle(prefix: string): { bundle: Record<string, unknown>; name: string } {
  const val = (c: string): string => {
    const el = document.getElementById(`${prefix}${c}`) as
      | HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    return el ? el.value : "";
  };
  const selText = (c: string): string => {
    const el = document.getElementById(`${prefix}${c}`) as HTMLSelectElement | null;
    if (el && el.tagName === "SELECT" && el.selectedIndex >= 0) return el.options[el.selectedIndex].text;
    return "";
  };
  const ts = new Date().toISOString();
  const type = val("STIXType") || "threat-actor";
  const guid = val("ThreatGUID") || newGuid();
  const mainId = `${type}--${guid}`;
  const name = val("ThreatName") || type;
  const desc = stripHtml(val("ThreatDescription"));

  const main: Record<string, unknown> = { type, spec_version: "2.1", id: mainId, created: ts, modified: ts, name };
  if (desc) main.description = desc;
  const confRaw = val("ConfidenceLevel");
  if (confRaw !== "" && Number.isFinite(Number(confRaw))) {
    main.confidence = Math.min(100, Math.max(0, Math.round(Number(confRaw) * 25))); // 0–4 → 0–100
  }
  if (type === "indicator" && val("ValidFrom")) {
    const vf = new Date(val("ValidFrom"));
    if (!isNaN(vf.getTime())) main.valid_from = vf.toISOString();
  }

  const objects: Record<string, unknown>[] = [main];
  const actorId = val("ThreatActorID");
  const actorName = selText("ThreatActorID");
  if (actorId && actorName && actorName !== "—") {
    const taId = `threat-actor--${newGuid()}`;
    objects.push({ type: "threat-actor", spec_version: "2.1", id: taId, created: ts, modified: ts, name: actorName });
    objects.push({
      type: "relationship", spec_version: "2.1", id: `relationship--${newGuid()}`,
      created: ts, modified: ts,
      relationship_type: type === "threat-actor" ? "related-to" : "attributed-to",
      source_ref: mainId, target_ref: taId,
    });
  }
  return { bundle: { type: "bundle", id: `bundle--${newGuid()}`, objects }, name };
}

function appendStixBundleButton(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText = "margin:6px 0 14px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("div");
  label.textContent = t("stix.bundleLabel");
  label.style.cssText = "font-size:12px;color:var(--text-muted);margin-bottom:8px";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = t("stix.genBundle");
  const status = document.createElement("div");
  status.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:6px";
  btn.onclick = () => {
    const { bundle, name } = buildStixBundle(prefix);
    const json = JSON.stringify(bundle, null, 2);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    a.download = `${(name || "threat").replace(/[^\w.-]+/g, "_")}.stix.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    status.style.color = "var(--success)";
    status.textContent = `${t("stix.generated")} (${(bundle.objects as unknown[]).length} ${t("stix.objects")})`;
  };
  div.appendChild(label);
  div.appendChild(btn);
  div.appendChild(status);
  body.appendChild(div);
}

// ── Web security scanner (ASSET form) ────────────────────────────────
// If websiteurl is set, offers to launch a web connector (whatweb,
// nuclei, sqlmap, Burp…) on that URL via the Connectors page (which handles
// the engagement/ROE and execution). The panel shows/hides according to websiteurl.
// Auto-capture of websiteurl → AssetImage (ASSET form, creation mode).
// On the field's blur, if the URL is valid and AssetImage empty, visits the URL,
// takes a server-side screenshot and fills AssetImage.
function wireAssetScreenshot(prefix: string): void {
  const urlInput = document.getElementById(`${prefix}websiteurl`) as HTMLInputElement | null;
  const imgHidden = document.getElementById(`${prefix}AssetImage`) as HTMLInputElement | null;
  if (!urlInput || !imgHidden) return;
  urlInput.addEventListener("blur", async () => {
    const url = urlInput.value.trim();
    if (!/^https?:\/\/[^\s.]+\.[^\s]+/i.test(url)) return; // URL format
    if (imgHidden.value) return; // don't overwrite an already-set image
    const prev = document.getElementById(`${prefix}AssetImage_preview`) as HTMLImageElement | null;
    toast(t("asset.screenshotRunning"), "ok");
    try {
      const r = await api.assetScreenshot(url);
      imgHidden.value = r.url;
      if (prev) { prev.src = r.url; prev.style.display = ""; }
      toast(t("asset.screenshotDone"), "ok");
    } catch (e) {
      toast(t("asset.screenshotFail") + " " + (e as Error).message, "err");
    }
  });
}

async function appendWebScanPanel(prefix: string): Promise<void> {
  const after = document.getElementById(`${prefix}field_websiteurl`);
  const urlInput = document.getElementById(`${prefix}websiteurl`) as HTMLInputElement | null;
  if (!after || !urlInput) return;

  const panel = document.createElement("div");
  panel.style.cssText = "margin:0 0 10px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)";
  const label = document.createElement("div");
  label.textContent = t("webscan.label");
  label.style.cssText = "font-size:12px;color:var(--text-muted);margin-bottom:8px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px";
  const sel = document.createElement("select");
  sel.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  const btn = document.createElement("a");
  btn.className = "btn btn-ghost btn-sm";
  btn.target = "_blank";
  btn.rel = "noopener";
  btn.textContent = t("webscan.launch");
  btn.style.flex = "0 0 auto";
  row.appendChild(sel);
  row.appendChild(btn);
  panel.appendChild(label);
  panel.appendChild(row);
  after.insertAdjacentElement("afterend", panel);

  // "Web scanner" connectors: web category (or nuclei) with a URL/host target.
  try {
    const web = (await api.getConnectors()).filter(
      (c) => (c.category === "web" || c.id === "nuclei") &&
        (c.parameters || []).some((p) => p.type === "target" || p.type === "url")
    );
    if (!web.length) { sel.innerHTML = `<option>${t("webscan.none")}</option>`; sel.disabled = true; }
    else for (const c of web) {
      const o = document.createElement("option");
      o.value = c.id; o.textContent = c.name;
      sel.appendChild(o);
    }
  } catch {
    sel.innerHTML = `<option>${t("webscan.none")}</option>`; sel.disabled = true;
  }

  const update = (): void => {
    const url = urlInput.value.trim();
    panel.style.display = url ? "" : "none"; // visible only if websiteurl is non-empty
    if (url && sel.value && !sel.disabled) {
      btn.setAttribute("href", `/connectors?connector=${encodeURIComponent(sel.value)}&target=${encodeURIComponent(url)}`);
      btn.style.pointerEvents = ""; btn.style.opacity = "";
    } else {
      btn.removeAttribute("href"); btn.style.pointerEvents = "none"; btn.style.opacity = "0.5";
    }
  };
  urlInput.addEventListener("input", update);
  sel.addEventListener("change", update);
  update();
}

// ── Network scanner (ASSET form) ─────────────────────────────────────────
// On the ipaddressIPv4 field's blur (if set), shows a panel to
// launch a network scan connector (nmap…) using the asset's IPv4 or IPv6
// as the target, via the Connectors page.
async function appendNetworkScanPanel(prefix: string): Promise<void> {
  const after = document.getElementById(`${prefix}field_ipaddressIPv4`);
  const v4 = document.getElementById(`${prefix}ipaddressIPv4`) as HTMLInputElement | null;
  const v6 = document.getElementById(`${prefix}ipaddressIPv6`) as HTMLInputElement | null;
  if (!after || !v4) return;

  const panel = document.createElement("div");
  panel.style.cssText = "margin:0 0 10px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface-2);display:none";
  const label = document.createElement("div");
  label.textContent = t("netscan.label");
  label.style.cssText = "font-size:12px;color:var(--text-muted);margin-bottom:8px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;flex-wrap:wrap";
  const sel = document.createElement("select");           // network connector
  sel.style.cssText = FIELD_INPUT_CSS + ";flex:1;min-width:140px";
  const ipSel = document.createElement("select");         // IPv4 / IPv6
  ipSel.style.cssText = FIELD_INPUT_CSS + ";flex:0 0 110px";
  for (const v of ["IPv4", "IPv6"]) {
    const o = document.createElement("option"); o.value = v; o.textContent = v; ipSel.appendChild(o);
  }
  const btn = document.createElement("a");
  btn.className = "btn btn-ghost btn-sm";
  btn.target = "_blank";
  btn.rel = "noopener";
  btn.textContent = t("netscan.launch");
  btn.style.flex = "0 0 auto";
  row.appendChild(sel);
  row.appendChild(ipSel);
  row.appendChild(btn);
  panel.appendChild(label);
  panel.appendChild(row);
  after.insertAdjacentElement("afterend", panel);

  // "Network scan" connectors: recon category with a host/IP target
  // (nmap, metasploit-scan…).
  try {
    const net = (await api.getConnectors()).filter(
      (c) => c.category === "recon" && (c.parameters || []).some((p) => p.type === "target")
    );
    if (!net.length) { sel.innerHTML = `<option>${t("netscan.none")}</option>`; sel.disabled = true; }
    else for (const c of net) {
      const o = document.createElement("option");
      o.value = c.id; o.textContent = c.name;
      sel.appendChild(o);
    }
  } catch {
    sel.innerHTML = `<option>${t("netscan.none")}</option>`; sel.disabled = true;
  }

  const update = (): void => {
    const visible = (v4.value || "").trim() !== "";
    panel.style.display = visible ? "" : "none"; // shown if ipaddressIPv4 is set
    const ip = (ipSel.value === "IPv6" ? (v6?.value || "") : v4.value).trim();
    if (ip && sel.value && !sel.disabled) {
      btn.setAttribute("href", `/connectors?connector=${encodeURIComponent(sel.value)}&target=${encodeURIComponent(ip)}`);
      btn.style.pointerEvents = ""; btn.style.opacity = "";
    } else {
      btn.removeAttribute("href"); btn.style.pointerEvents = "none"; btn.style.opacity = "0.5";
    }
  };
  v4.addEventListener("blur", update);   // "on field blur"
  v4.addEventListener("input", update);
  if (v6) v6.addEventListener("input", update);
  sel.addEventListener("change", update);
  ipSel.addEventListener("change", update);
  update(); // visible immediately if already set (edit mode)
}

// Toolbar button: imports a VULNERABILITY from OSV by identifier.
async function importFromOsv(): Promise<void> {
  const id = (prompt(t("osv.promptId")) || "").trim();
  if (!id) return;
  try {
    const r = await api.osvImport(id);
    const verb = r.action === "inserted" ? t("osv.inserted") : t("osv.updated");
    toast(`${verb} : ${r.referential} (VulnerabilityID ${r.vulnerabilityId})`, "ok");
    await loadRows();
  } catch (e) {
    toast("OSV : " + (e as Error).message, "err");
  }
}

// ── "*Name" duplicate check (creation form) ────────────────────
// On the blur of a field whose name ends with "Name", checks that no
// record already carries the same value in the current table; if so,
// asks the user for confirmation.
function attachDuplicateNameCheck(input: HTMLInputElement, col: string): void {
  input.addEventListener("blur", () => void checkDuplicateName(input, col));
}

async function checkDuplicateName(input: HTMLInputElement, col: string): Promise<void> {
  const val = input.value.trim();
  if (!val) return;
  // The user has already confirmed this duplicate: don't ask again.
  if (input.dataset.dupOk === val.toLowerCase()) return;
  let r: { exists: boolean; count: number };
  try {
    r = await api.nameCheck(currentDb, currentTable, col, val);
  } catch {
    return; // best-effort: never blocks the input
  }
  if (!r.exists) {
    delete input.dataset.dupOk;
    return;
  }
  const proceed = confirm(
    `${t("dialog.dupA")} « ${val} » ${t("dialog.dupB")} ${currentTable} (${r.count}).\n\n${t("dialog.addAnyway")}`
  );
  if (proceed) {
    input.dataset.dupOk = val.toLowerCase(); // confirmed: we no longer ask for this value
  } else {
    input.value = "";
    delete input.dataset.dupOk;
    input.focus();
  }
}

// ASSETVULNERABILITY: if the status indicates a fix (Patched/Fixed/Closed),
// offers to add evidence → opens EVIDENCE in creation (EvidenceName pre-filled
// with "<VULReferential> patched"). Returns true if we navigated.
function offerEvidenceForStatus(statusVal: string, vulnerabilityId: string): boolean {
  const s = statusVal.trim().toLowerCase();
  if (s === "patched" || s === "fixed" || s === "closed") {
    if (window.confirm("Do you want to add an evidence for the patching?")) {
      void openEvidenceForPatch(vulnerabilityId);
      return true;
    }
  }
  return false;
}

// Opens EVIDENCE in creation and pre-fills EvidenceName = "<VULReferential> patched".
async function openEvidenceForPatch(vulnerabilityId: string): Promise<void> {
  let ref = "";
  const vid = (vulnerabilityId || "").trim();
  if (vid) {
    try {
      const r = await api.getLookupOne(
        "XVULNERABILITY", "VULNERABILITY", "VulnerabilityID", vid, "VULReferential"
      );
      if (r.label != null) ref = String(r.label);
    } catch {
      /* unavailable: we pre-fill without the reference */
    }
  }
  await navigateAndCreate("XCOMPLIANCE", "EVIDENCE");
  const nameInput = document.getElementById("f_EvidenceName") as HTMLInputElement | null;
  if (nameInput) nameInput.value = `${ref} patched`.trim();
}

// INCIDENT: after creation, offers to create an ALERT/NOTIFICATION → opens the
// ALERT creation form with IncidentID pre-filled. Returns true if we navigated.
function offerAlertForIncident(incidentId: number): boolean {
  if (!incidentId) return false;
  if (window.confirm(t("incident.offerAlert"))) {
    void openAlertForIncident(incidentId);
    return true;
  }
  return false;
}

// Opens XINCIDENT.ALERT in creation and pre-fills IncidentID with the new incident.
async function openAlertForIncident(incidentId: number): Promise<void> {
  await navigateAndCreate("XINCIDENT", "ALERT");
  setFormField("f_", "IncidentID", String(incidentId));
}

// ── Rows ──────────────────────────────────────────────────────────────────────

// Populates the "filter by vocabulary" dropdown (VocabularyName from
// XORCISM.VOCABULARY) and wires it: reloads the table filtered by VocabularyID.
async function initVocabFilter(): Promise<void> {
  const sel = document.getElementById("vocab-filter") as HTMLSelectElement | null;
  if (!sel) return;
  sel.innerHTML = "";
  const all = document.createElement("option");
  all.value = "";
  all.textContent = t("explorer.allVocab");
  sel.appendChild(all);
  try {
    const opts = await api.getLookup("XORCISM", "VOCABULARY", "VocabularyID", "VocabularyName");
    opts.forEach((o) => {
      const opt = document.createElement("option");
      opt.value = String(o.id);
      opt.textContent = o.label == null || o.label === "" ? String(o.id) : String(o.label);
      opt.style.background = "var(--surface)";
      sel.appendChild(opt);
    });
    sel.disabled = false;
  } catch {
    /* lookup unavailable (insufficient rights): we leave "all" */
  }
  sel.onchange = () => {
    currentVocab = sel.value;
    currentPage = 0;
    loadRows();
  };
}

async function loadRows(): Promise<void> {
  if (!currentDb || !currentTable) return;
  try {
    const result = await api.getRows(
      currentDb,
      currentTable,
      PAGE_SIZE,
      currentPage * PAGE_SIZE,
      currentSort || undefined,
      currentDir,
      currentSearch || undefined,
      currentVocab ? Number(currentVocab) : undefined,
      activeColumnFilters()
    );
    totalRows = result.total;
    await injectGridDisplayColumn(result.rows as Record<string, unknown>[]);
    renderTable(result.rows as Record<string, unknown>[]);
    renderPager();
  } catch (e) {
    toast(t("toast.error") + " " + e, "err");
  }
}

// Per-column filters actually active (non-empty value).
function activeColumnFilters(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(currentFilters)) {
    if (v && v.trim()) out[k] = v;
  }
  return out;
}

// Input in a column filter: updates the state + reloads (rate-limited).
function onColumnFilterInput(col: string, value: string): void {
  if (value === "") delete currentFilters[col];
  else currentFilters[col] = value;
  activeFilterCol = col;
  currentPage = 0;
  if (filterDebounce) clearTimeout(filterDebounce);
  filterDebounce = setTimeout(() => void loadRows(), 300);
}

// Clears all the column filters of the current grid and reloads.
function resetFilters(): void {
  if (!Object.keys(currentFilters).length) return; // nothing to reset
  currentFilters = {};
  activeFilterCol = null;
  currentPage = 0;
  if (filterDebounce) clearTimeout(filterDebounce);
  loadRows();
}

// Header cell containing the filter field of a column.
function mkFilterCell(col: string): HTMLTableCellElement {
  const th = document.createElement("th");
  th.style.cssText = "padding:2px 4px;background:var(--surface-2)";
  const inp = document.createElement("input");
  inp.type = "text";
  inp.value = currentFilters[col] ?? "";
  inp.placeholder = t("explorer.filter");
  inp.setAttribute("data-filter-col", col);
  inp.style.cssText =
    "width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);" +
    "border-radius:4px;padding:3px 6px;color:var(--text);font-size:11px;font-weight:400";
  inp.oninput = () => onColumnFilterInput(col, inp.value);
  inp.onfocus = () => (activeFilterCol = col);
  inp.onclick = (e) => e.stopPropagation(); // don't trigger the sort
  th.appendChild(inp);
  return th;
}

// ── Pentest Mode: multiple asset selection + bulk scan ────────────────
let canPentest = false;
let pentestMode = false;
const selectedAssets = new Set<number>();

function isPentestAssetView(): boolean {
  return pentestMode && currentDb === "XORCISM" && currentTable === "ASSET";
}
function updatePentestBar(): void {
  const bar = document.getElementById("pentest-bar");
  if (!bar) return;
  bar.style.display = pentestMode ? "flex" : "none";
  const cnt = document.getElementById("pentest-count");
  if (cnt) cnt.textContent = String(selectedAssets.size);
  const btn = document.getElementById("pentest-launch") as HTMLButtonElement | null;
  if (btn) btn.disabled = selectedAssets.size === 0;
  const ab = document.getElementById("pentest-agent") as HTMLButtonElement | null;
  if (ab) ab.disabled = selectedAssets.size === 0;
}

// Bulk scan of the selected assets with the XOR agent (results auto-populated).
async function bulkAgentScan(): Promise<void> {
  if (!selectedAssets.size) return;
  try {
    const r = await api.agentBulkScan([...selectedAssets], "full");
    toast(
      `${r.queued} ${t("pentest.agentQueued")}` +
        (r.noAgent.length ? ` · ${r.noAgent.length} ${t("pentest.agentNoAgent")}` : ""),
      r.queued ? "ok" : "err"
    );
  } catch (e) {
    toast("XOR agent: " + (e as Error).message, "err");
  }
}
function togglePentestMode(): void {
  pentestMode = !pentestMode;
  selectedAssets.clear();
  document.getElementById("btn-pentest")?.classList.toggle("active", pentestMode);
  updatePentestBar();
  void loadRows(); // re-render with/without the selection column
}
async function openPentestLaunch(): Promise<void> {
  if (!selectedAssets.size) return;
  let engs: { EngagementID: number; name: string }[] = [];
  try { engs = await api.getEngagements(); } catch { /* no engagement */ }

  const overlay = document.createElement("div");
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;display:flex;align-items:center;justify-content:center";
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:22px;width:460px;max-width:94vw";
  const css = "width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;color:var(--text);font-size:13px;margin-bottom:10px";
  card.innerHTML =
    `<div style="font-size:16px;font-weight:600;color:var(--text);margin-bottom:4px">🛡️ ${t("pentest.launchTitle")}</div>` +
    `<div style="font-size:12px;color:var(--text-muted);margin-bottom:14px">${selectedAssets.size} ${t("pentest.assetsSelected")} — ${t("pentest.connectorsNote")}</div>`;
  const lab1 = document.createElement("label");
  lab1.textContent = t("pentest.engagement") + " *";
  lab1.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:3px";
  const engSel = document.createElement("select");
  engSel.style.cssText = css;
  if (!engs.length) {
    engSel.innerHTML = `<option value="">${t("pentest.noEngagement")}</option>`;
  } else {
    engSel.innerHTML = engs.map((e) => `<option value="${e.EngagementID}">${e.name}</option>`).join("");
  }
  const lab2 = document.createElement("label");
  lab2.textContent = t("pentest.worker");
  lab2.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:3px";
  const wk = document.createElement("input");
  wk.value = "local"; wk.style.cssText = css;
  const err = document.createElement("div");
  err.style.cssText = "color:var(--danger);font-size:12px;min-height:16px;margin:2px 0 8px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:8px";
  const launch = document.createElement("button");
  launch.className = "btn btn-primary"; launch.textContent = t("pentest.launchBtn");
  launch.style.cssText = "flex:1;justify-content:center;padding:10px";
  const cancel = document.createElement("button");
  cancel.className = "btn btn-ghost"; cancel.textContent = t("modal.cancel");
  cancel.style.cssText = "flex:0 0 auto;padding:10px 16px";
  cancel.onclick = () => overlay.remove();
  launch.onclick = async () => {
    const engagement = Number(engSel.value);
    if (!engagement) { err.textContent = t("pentest.noEngagement"); return; }
    launch.disabled = true; err.textContent = "";
    try {
      const r = await api.pentestBulkScan([...selectedAssets], engagement, wk.value.trim() || "local");
      overlay.remove();
      toast(`${r.jobs} ${t("pentest.jobsCreated")} (${r.assets} ${t("dash.assetsUnit")}${r.outOfScope ? `, ${r.outOfScope} ${t("pentest.outOfScope")}` : ""})`, "ok");
      selectedAssets.clear();
      updatePentestBar();
      void loadRows();
    } catch (e) {
      err.textContent = (e as Error).message;
      launch.disabled = false;
    }
  };
  row.appendChild(launch); row.appendChild(cancel);
  card.appendChild(lab1); card.appendChild(engSel);
  card.appendChild(lab2); card.appendChild(wk);
  card.appendChild(err); card.appendChild(row);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
}

function renderTable(rows: Record<string, unknown>[]): void {
  gridRows = rows; // remembers for local re-render (e.g. after column reorder)
  const thead = $("data-thead");
  const tbody = $("data-tbody");

  // null/undefined/blank string = empty; 0 and false remain values.
  const isEmptyVal = (v: unknown): boolean =>
    v == null || (typeof v === "string" && v.trim() === "");
  const filtered = activeColumnFilters();
  const hasFilters = Object.keys(filtered).length > 0;

  // Truly empty table (no filter): simple message, no header.
  if (!rows.length && !hasFilters) {
    thead.innerHTML = "";
    tbody.innerHTML = `<tr><td colspan="99" style="text-align:center;padding:32px;color:var(--text-muted)">${t("explorer.noData")}</td></tr>`;
    return;
  }

  // Displayed columns: we hide the empty columns BUT always keep
  // those carrying an active filter (so as not to make their field disappear,
  // even if the filter returns no row).
  const cols = applyUserColOrder(currentDb, currentTable, reorderGridCols(
    currentTable,
    rows.length
      ? Object.keys(rows[0])
          .filter((c) => c !== "rowid")
          .filter((c) => rows.some((r) => !isEmptyVal(r[c])) || filtered[c] != null)
      : schema.map((c) => c.name).filter((c) => c !== "rowid" && filtered[c] != null)
  ));
  gridCols = cols; // remembers the current order/selection (reused by the CSV/Excel export)

  // Computed columns (read-only): neither sort nor filter.
  const computedCols = new Set((GRID_DISPLAY_COLUMNS[currentTable] ?? []).map((s) => s.colLabel));

  // Header — row 1: column names (sort on click, except computed columns)
  thead.innerHTML = "";
  const tr = document.createElement("tr");
  const thAct = document.createElement("th");
  thAct.textContent = "";
  thAct.style.width = "80px";
  tr.appendChild(thAct);

  // Pentest Mode: checkbox column (selection) + "select all"
  if (isPentestAssetView()) {
    const cbTh = document.createElement("th");
    cbTh.style.width = "28px";
    const all = document.createElement("input");
    all.type = "checkbox";
    all.title = t("pentest.selectAll");
    all.checked = rows.length > 0 && rows.every((r) => selectedAssets.has(Number(r["AssetID"])));
    all.onclick = () => {
      for (const r of rows) {
        const aid = Number(r["AssetID"]);
        if (all.checked) selectedAssets.add(aid); else selectedAssets.delete(aid);
      }
      renderTable(rows);
      updatePentestBar();
    };
    cbTh.appendChild(all);
    tr.insertBefore(cbTh, thAct);
  }

  cols.forEach((col) => {
    const th = document.createElement("th");
    th.textContent = gridColLabel(currentTable, col); // display label (real col unchanged)
    if (computedCols.has(col)) {
      th.style.fontStyle = "italic"; // derived column, not sortable
      th.title = t("tip.linkedCol");
    } else {
      th.style.cursor = "pointer";
      th.title = t("tip.sortDrag");
      if (col === currentSort) {
        th.className = currentDir === "asc" ? "sort-asc" : "sort-desc";
      }
      th.onclick = () => setSort(col);
    }
    makeColHeaderDraggable(th, col, cols);
    tr.appendChild(th);
  });
  thead.appendChild(tr);

  // Header — row 2: per-column filter field (empty cell for the computed one).
  // "actions" cell (to the left of the filters): Reset button → clears all the filters.
  const trF = document.createElement("tr");
  const thReset = document.createElement("th");
  const hasActiveFilters = Object.keys(filtered).length > 0;
  const resetBtn = document.createElement("button");
  resetBtn.className = "btn btn-ghost btn-sm";
  resetBtn.textContent = t("explorer.resetFilters") || "Reset";
  resetBtn.title = t("explorer.resetFiltersTitle") || "Réinitialiser tous les filtres";
  resetBtn.style.cssText = "padding:2px 8px;font-size:11px";
  resetBtn.disabled = !hasActiveFilters;
  resetBtn.onclick = resetFilters;
  thReset.appendChild(resetBtn);
  trF.appendChild(thReset); // "actions" column
  if (isPentestAssetView()) trF.insertBefore(document.createElement("th"), trF.firstChild);
  cols.forEach((col) =>
    trF.appendChild(computedCols.has(col) ? document.createElement("th") : mkFilterCell(col))
  );
  thead.appendChild(trF);

  // Restores the focus of the active filter field (re-rendered during typing).
  if (activeFilterCol) {
    const inp = thead.querySelector<HTMLInputElement>(
      `input[data-filter-col="${activeFilterCol}"]`
    );
    if (inp) {
      inp.focus();
      const n = inp.value.length;
      inp.setSelectionRange(n, n);
    }
  }

  // Body
  tbody.innerHTML = "";
  if (!rows.length) {
    // Active filters but no result: message, keeping the filters above.
    const trEmpty = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = cols.length + 1 + (isPentestAssetView() ? 1 : 0);
    td.style.cssText = "text-align:center;padding:24px;color:var(--text-muted)";
    td.textContent = t("explorer.noMatch");
    trEmpty.appendChild(td);
    tbody.appendChild(trEmpty);
    return;
  }
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const tdAct = document.createElement("td");
    const btnEdit = document.createElement("button");
    btnEdit.className = "btn-icon";
    btnEdit.title = "Modifier";
    btnEdit.textContent = "✏️";
    btnEdit.style.color = "var(--accent)";
    btnEdit.onclick = () => openEditModal(row);
    tdAct.appendChild(btnEdit);
    const btnDel = document.createElement("button");
    btnDel.className = "btn-icon btn-danger-icon";
    btnDel.title = "Supprimer";
    btnDel.textContent = "✕";
    btnDel.onclick = () => deleteRow(Number(row["rowid"]));
    tdAct.appendChild(btnDel);
    tr.appendChild(tdAct);

    // Pentest Mode: asset selection checkbox
    if (isPentestAssetView()) {
      const cbTd = document.createElement("td");
      const aid = Number(row["AssetID"]);
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = selectedAssets.has(aid);
      cb.onclick = (e) => {
        e.stopPropagation();
        if (cb.checked) selectedAssets.add(aid); else selectedAssets.delete(aid);
        updatePentestBar();
      };
      cbTd.appendChild(cb);
      tr.insertBefore(cbTd, tdAct);
    }

    cols.forEach((col) => {
      const td = document.createElement("td");
      const val = row[col];
      const lbl = gridLabel(currentTable, col, val); // e.g. 0/1 → No/Yes
      const display = lbl != null ? lbl : val == null ? "" : String(val);
      // REMEDIATION column (ASSETVULNERABILITY): integer → edits the remediation;
      // "Remediate" → creates an ASSETVULNERABILITYREMEDIATION with AssetVulnerabilityID set.
      const linkSpec = getGridLink(currentTable, col);
      const linkId = linkSpec ? row[linkSpec.srcCol] : null;
      if (currentDb === "XORCISM" && currentTable === "ASSET" && col === "AssetName" && display !== "") {
        // AssetName → clickable to open this ASSET in the edit form.
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = display;
        a.style.cssText = "color:var(--accent);cursor:pointer;font-weight:600";
        a.title = t("tip.edit");
        a.onclick = (e) => {
          e.preventDefault();
          e.stopPropagation();
          void openEditModal(row);
        };
        td.appendChild(a);
      } else if (currentDb === "XORCISM" && currentTable === "ASSET" && col === "AssetCriticalityLevel") {
        // AssetCriticalityLevel: show the level; "Critical" highlighted in red.
        if (display !== "") {
          const span = document.createElement("span");
          span.textContent = display;
          if (display.trim().toLowerCase() === "critical") {
            span.style.cssText = "color:var(--danger);font-weight:600";
          }
          td.appendChild(span);
        }
      } else if (currentDb === "XVULNERABILITY" && currentTable === "VULNERABILITY" && col === "VULReferentialID" && display !== "") {
        // VULReferentialID (the CVE/ref) → clickable to edit this VULNERABILITY row.
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = display;
        a.style.cssText = "color:var(--accent);cursor:pointer;font-weight:600";
        a.title = t("tip.edit");
        a.onclick = (e) => {
          e.preventDefault();
          e.stopPropagation();
          void openEditModal(row);
        };
        td.appendChild(a);
      } else if (currentTable === "ASSETVULNERABILITY" && col === "REMEDIATION") {
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = display;
        a.style.cssText = "color:var(--accent);cursor:pointer";
        const avId = String(row["AssetVulnerabilityID"] ?? "");
        const existing = /^\d+$/.test(display); // an integer = existing remediation
        a.title = existing ? t("tip.editRemediation") : t("tip.createRemediation");
        a.onclick = (e) => {
          e.preventDefault();
          e.stopPropagation();
          if (existing) {
            void openForeignEditModal("XORCISM", "ASSETVULNERABILITYREMEDIATION", "AssetVulnerabilityRemediationID", display);
          } else {
            void openForeignInsertModal("XORCISM", "ASSETVULNERABILITYREMEDIATION", { AssetVulnerabilityID: avId });
          }
        };
        td.appendChild(a);
      } else if (currentTable === "RISKREGISTERENTRY" && col === "RiskRegisterID" && display !== "") {
        // "Register" column → clickable to open THIS entry's edit form (not the parent register).
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = display;
        a.style.cssText = "color:var(--accent);cursor:pointer;font-weight:600";
        a.title = t("tip.edit");
        a.onclick = (e) => { e.preventDefault(); e.stopPropagation(); void openEditModal(row); };
        td.appendChild(a);
      } else if (display !== "" && (
        (currentTable === "THREATFEED" && col === "ThreatFeedName") ||
        (currentTable === "POLICY" && col === "PolicyName") ||
        (currentTable === "IDENTITY" && col === "IdentityName") ||
        (currentTable === "CRISISSCENARIO" && col === "ScenarioName") ||
        (currentTable === "OVALDEFINITION" && col === "OVALDefinitionTitle")
      )) {
        // Name column → clickable to open this record's edit form.
        const a = document.createElement("a");
        a.href = "#"; a.textContent = display;
        a.style.cssText = "color:var(--accent);cursor:pointer;font-weight:600";
        a.title = t("tip.edit");
        a.onclick = (e) => { e.preventDefault(); e.stopPropagation(); void openEditModal(row); };
        td.appendChild(a);
      } else if (linkSpec && lbl == null && display !== "" && linkId != null && String(linkId) !== "") {
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = display;
        a.style.color = "var(--accent)";
        a.style.cursor = "pointer";
        a.title = `${t("tip.edit")} ${linkSpec.table} (${linkSpec.idCol}=${linkId})`;
        a.onclick = (e) => {
          e.preventDefault();
          e.stopPropagation();
          void openForeignEditModal(linkSpec.db, linkSpec.table, linkSpec.idCol, String(linkId));
        };
        td.appendChild(a);
      // *URL columns: rendered as a clickable link (opens in a new tab).
      } else if (lbl == null && /url$/i.test(col) && /^https?:\/\//i.test(display)) {
        const a = document.createElement("a");
        a.href = display;
        a.textContent = display;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.style.color = "var(--accent)";
        a.onclick = (e) => e.stopPropagation(); // don't trigger row selection
        td.appendChild(a);
      } else {
        td.textContent = display;
      }
      // Value color (e.g. "Yes" in red for Exploited / KEV).
      const vcolor = GRID_VALUE_COLORS[`${currentTable}.${col}`]?.[display];
      if (vcolor) { td.style.color = vcolor; td.style.fontWeight = "600"; }
      td.title = display;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderPager(): void {
  const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
  $("pager-info").textContent = `Page ${currentPage + 1} / ${totalPages} — ${totalRows.toLocaleString()} lignes`;
  ($("btn-prev") as HTMLButtonElement).disabled = currentPage === 0;
  ($("btn-next") as HTMLButtonElement).disabled =
    currentPage >= totalPages - 1;
}

function setSort(col: string): void {
  if (currentSort === col) {
    currentDir = currentDir === "asc" ? "desc" : "asc";
  } else {
    currentSort = col;
    currentDir = "asc";
  }
  currentPage = 0;
  loadRows();
}

function onSearchInput(value: string): void {
  if (searchDebounce) clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    currentSearch = value;
    currentPage = 0;
    loadRows();
  }, 350); // 350ms debounce — avoids a query per keystroke
}

function clearSearch(): void {
  currentSearch = "";
  currentPage = 0;
  const input = $("search-input") as HTMLInputElement;
  input.value = "";
  input.focus();
  loadRows();
}

// ── Delete ────────────────────────────────────────────────────────────────────

async function deleteRow(rowid: number): Promise<void> {
  if (!rowid) return;
  if (!confirm(`${t("dialog.deleteRow")} rowid=${rowid} ?`)) return;
  try {
    await api.deleteRow(currentDb, currentTable, rowid);
    toast(t("toast.rowDeleted"), "ok");
    loadRows();
  } catch (e) {
    toast(t("toast.error") + " " + e, "err");
  }
}

// ── Edit modal ────────────────────────────────────────────────────────────────

let editRowId = 0;
let editIncidentId = 0;
let editAlertId = 0;
let editThreatId = 0;
let editThreatAgentId = 0;
let editAuditId = 0;

// "Foreign" editing: when editing a row of a table OTHER than the current
// view (e.g. click on VULReferential in ASSETVULNERABILITY → edits
// VULNERABILITY). We temporarily switch the context (db/table/schema) to the
// target table for the duration of the modal; this callback restores the original context on
// close (cancellation or after saving).
let foreignEditReturn: (() => void) | null = null;

// Opens the edit form of a row of a target table (db/table) identified
// by idCol=idVal, from another view. Reuses the whole edit pipeline
// (schema, FK, OSV, submission) by switching the context globals.
async function openForeignEditModal(
  db: string,
  table: string,
  idCol: string,
  idVal: string
): Promise<void> {
  try {
    const resp = await api.getRowById(db, table, idCol, idVal);
    const row = resp.row;
    if (!row) {
      toast(`${table} ${t("toast.notFound")} (${idCol}=${idVal})`, "err");
      return;
    }
    const prevDb = currentDb, prevTable = currentTable, prevSchema = schema;
    currentDb = db;
    currentTable = table;
    schema = await api.getSchema(db, table);
    foreignEditReturn = () => {
      currentDb = prevDb;
      currentTable = prevTable;
      schema = prevSchema;
    };
    await openEditModal(row as Record<string, unknown>);
  } catch (e) {
    if (foreignEditReturn) { foreignEditReturn(); foreignEditReturn = null; }
    toast(t("toast.errOpenEdit") + " " + e, "err");
  }
}

// "Foreign" insertion: opens the CREATION form of a table OTHER than the
// current view (e.g. "Add new vulnerability" from an asset's vuln-links modal
// → creates a VULNERABILITY). Restores the context on close (cancellation
// or after saving).
let foreignInsertReturn: (() => void) | null = null;

async function openForeignInsertModal(
  db: string,
  table: string,
  prefill?: Record<string, string>
): Promise<void> {
  try {
    const prevDb = currentDb, prevTable = currentTable, prevSchema = schema;
    currentDb = db;
    currentTable = table;
    schema = await api.getSchema(db, table);
    foreignInsertReturn = () => {
      currentDb = prevDb;
      currentTable = prevTable;
      schema = prevSchema;
      ($("insert-modal") as HTMLElement).style.zIndex = ""; // restores the default stacking
    };
    await openInsertModal();
    // Pre-fills fields (e.g. AssetVulnerabilityID passed from the grid).
    if (prefill) {
      for (const [col, val] of Object.entries(prefill)) {
        const el = document.getElementById(`f_${col}`) as HTMLInputElement | null;
        if (!el) continue;
        if (el.type === "checkbox") el.checked = val === (el.dataset.checked ?? "1") || val === "1";
        else el.value = val;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }
    // Goes ON TOP of the calling modal/grid (same z-index otherwise: DOM stacking).
    ($("insert-modal") as HTMLElement).style.zIndex = "200";
  } catch (e) {
    if (foreignInsertReturn) { foreignInsertReturn(); foreignInsertReturn = null; }
    fkCreateReturn = null; // avoids a callback leak if the opening fails
    toast(t("toast.errOpenCreate") + " " + e, "err");
  }
}

// ── "+ create" button next to a FK dropdown: opens the target table's form
// in creation and returns the new id into the (refreshed) dropdown. ───────
const FK_CREATE_BUTTON = new Set<string>([
  "QUESTIONNAIREFORORGANISATION.QuestionnaireID",
  "QUESTIONNAIREFORORGANISATION.OrganisationID",
]);
let fkCreateReturn: ((newId: string) => Promise<void>) | null = null;

// Wraps a FK dropdown with a "+" button (creation of the target).
function fkWithCreate(sel: HTMLElement, prefix: string, col: string, fk: FkSpec): HTMLElement {
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;gap:6px;align-items:center";
  sel.style.flex = "1";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = "+";
  btn.title = `${t("tip.create")} ${fk.table}`;
  btn.style.cssText = "flex:0 0 auto;padding:2px 10px";
  btn.onclick = () => void openFkCreate(prefix, col, fk);
  wrap.appendChild(sel);
  wrap.appendChild(btn);
  return wrap;
}

// Opens the creation of the FK table; on return, selects the new id in the dropdown.
async function openFkCreate(prefix: string, col: string, fk: FkSpec): Promise<void> {
  const editing = prefix === "ef_";
  const origDb = currentDb, origTable = currentTable;
  // Snapshot of the original form's values (restored only in creation, because the
  // insert modal is reused by the foreign creation; in editing it stays).
  const snap: Record<string, { value: string; checked?: boolean }> = {};
  for (const c of schema) {
    const el = document.getElementById(`${prefix}${c.name}`) as HTMLInputElement | null;
    if (el) snap[c.name] = el.type === "checkbox" ? { value: el.value, checked: el.checked } : { value: el.value };
  }
  const setFk = (selPrefix: string, newId: string, newLabel: string): void => {
    const sel = document.getElementById(`${selPrefix}${col}`) as HTMLSelectElement | null;
    if (!sel || !newId) return;
    if (!Array.from(sel.options).some((o) => o.value === String(newId))) {
      const o = document.createElement("option"); o.value = String(newId); o.textContent = newLabel || String(newId);
      sel.appendChild(o);
    }
    sel.value = String(newId);
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  };
  fkCreateReturn = async (newId: string): Promise<void> => {
    // Reads the target's label (name field) BEFORE rebuilding the original form.
    const newLabel = (document.getElementById(`f_${fk.labelCol}`) as HTMLInputElement | null)?.value || String(newId);
    if (editing) {
      // The original edit modal stayed open underneath: we just update the dropdown.
      setFk("ef_", newId, newLabel);
    } else {
      currentDb = origDb; currentTable = origTable;
      await openInsertModal(); // rebuilds the original form (FK options refreshed)
      for (const [c, s] of Object.entries(snap)) {
        const el = document.getElementById(`f_${c}`) as HTMLInputElement | null;
        if (!el) continue;
        if (el.type === "checkbox") el.checked = !!s.checked; else el.value = s.value;
      }
      setFk("f_", newId, newLabel);
    }
  };
  await openForeignInsertModal(fk.db ?? currentDb, fk.table);
}

// Vocabulary-dependent CATEGORY dropdown, for the THREATAGENT form.
// Inserted right after the VocabularyID field; recomputed when the vocabulary changes.
// prefix: "f_" (insertion) or "ef_" (editing). currentCategoryId: pre-selection (editing).
// "ThreatActor" field (dropdown with free input) for the
// INCIDENT table: values = THREATACTOR.ThreatActorName (XTHREAT). The form
// submission replaces the link in XTHREAT.THREATACTORFORINCIDENT.
async function appendIncidentThreatActor(body: HTMLElement, prefix: string, currentName: string): Promise<void> {
  const div = document.createElement("div");
  div.id = `${prefix}field_threatactor`;
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = "ThreatActor";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const input = document.createElement("input");
  input.id = `${prefix}threatactor`;
  input.value = currentName || "";
  input.setAttribute("list", `${prefix}threatactor_dl`);
  input.autocomplete = "off";
  input.placeholder = "Acteur de menace (THREATACTOR.ThreatActorName)…";
  input.style.cssText = FIELD_INPUT_CSS;
  const dl = document.createElement("datalist");
  dl.id = `${prefix}threatactor_dl`;
  div.appendChild(label);
  div.appendChild(input);
  div.appendChild(dl);
  body.appendChild(div);
  await populateDatalist(dl, { db: "XTHREAT", table: "THREATACTOR", labelCol: "ThreatActorName" });
}

async function appendThreatAgentCategory(prefix: string, currentCategoryId: number | null): Promise<void> {
  const vocabSel = document.getElementById(`${prefix}VocabularyID`) as HTMLSelectElement | null;
  const afterDiv = document.getElementById(`${prefix}field_VocabularyID`);
  if (!vocabSel || !afterDiv) return;

  const div = document.createElement("div");
  div.id = `${prefix}field_ta_category`;
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = "CategoryName";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const sel = document.createElement("select");
  sel.id = `${prefix}ta_category`;
  sel.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";
  div.appendChild(label);
  div.appendChild(sel);
  afterDiv.after(div);

  const populate = async (preselect: number | null) => {
    const vocab = Number(vocabSel.value);
    sel.innerHTML = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "—";
    sel.appendChild(blank);
    if (!vocab) return;
    let opts: { id: number; label: string }[] = [];
    try {
      opts = await api.getThreatAgentCategories(vocab);
    } catch {
      opts = [];
    }
    opts.forEach((o) => {
      const opt = document.createElement("option");
      opt.value = String(o.id);
      opt.textContent = o.label;
      opt.style.background = "var(--surface)";
      if (preselect != null && o.id === preselect) opt.selected = true;
      sel.appendChild(opt);
    });
  };

  // On vocabulary change: reloads the options (resets the selection)
  vocabSel.addEventListener("change", () => void populate(null));
  await populate(currentCategoryId);
}

// ── Long-form UX: readable labels, required markers, sectioning ──────────
// DB columns are English PascalCase (e.g. "BusinessImpactAnalysisID"). These
// helpers turn them into readable labels and split long forms into collapsible
// sections (required first, optional/system collapsed) — driven entirely by the
// schema metadata already on ColumnInfo (notnull / dflt_value / pk).

const LABEL_ACRONYMS = new Set([
  "ID", "CVE", "CPE", "CWE", "CCE", "IP", "MAC", "OS", "URL", "URI", "DNS", "TLS", "SSL",
  "CVSS", "EPSS", "KEV", "TLP", "RPO", "RTO", "SLA", "SLE", "ALE", "BIA", "TTP", "IOC",
  "STIX", "OCIL", "OVAL", "GRC", "TPRM", "EBIOS", "UUID", "API", "UI", "AI", "XDR", "EDR",
  "SIEM", "VUL", "MFA", "OTP", "PII", "VLAN", "CIDR", "ASN", "ISO", "NIST", "CIS", "XML",
]);

function humanizeColumn(name: string): string {
  const acro = name.match(/^([A-Z]{2,})ID$/); // all-caps PKs: CWEID → CWE
  if (acro && LABEL_ACRONYMS.has(acro[1])) return acro[1];
  const parts = name
    .replace(/_/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/\s+/)
    .filter(Boolean);
  if (parts.length > 1 && /^id$/i.test(parts[parts.length - 1])) parts.pop(); // drop trailing "ID"
  const words = parts.map((w, i) => {
    if (LABEL_ACRONYMS.has(w.toUpperCase())) return w.toUpperCase();
    const lower = w.toLowerCase();
    return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
  });
  return words.join(" ") || name;
}

// A column the user MUST fill in: NOT NULL, no DB default, not the primary key.
function isRequiredFormCol(col: ColumnInfo): boolean {
  return col.pk !== 1 && col.notnull === 1 && col.dflt_value == null;
}

// System / audit / computed columns → collapsed "Advanced" section.
function isAdvancedFormCol(table: string, col: ColumnInfo): boolean {
  if (isReadonlyFormColumn(table, col.name)) return true;
  return /^(Created|Modified|Updated|Deleted|Last)[A-Z]/.test(col.name)
    || /(CreatedBy|ModifiedBy|CreatedDate|ModifiedDate|UpdatedDate)$/.test(col.name)
    || col.name === "TenantID" || col.name === "RowVersion";
}

// Sets a form-field label: readable text + PK key + required "*"; raw name on hover.
function setFieldLabel(label: HTMLElement, col: ColumnInfo, opts?: { pkSuffix?: string }): void {
  label.textContent = humanizeColumn(col.name) + (opts?.pkSuffix ?? (col.pk ? " 🔑" : ""));
  label.title = col.name; // power users keep the raw column name on hover
  // No "required *" on the (often auto-filled) key column — pkSuffix marks it.
  if (!opts?.pkSuffix && isRequiredFormCol(col)) {
    const star = document.createElement("span");
    star.textContent = " *";
    star.style.color = "var(--danger)";
    star.title = "Required";
    label.appendChild(star);
  }
}

// Tracks whether the user typed in the current insert/edit form (unsaved-changes guard).
let formDirty = false;

// A field that should span the full form width (textareas, rich text, file pickers,
// multi-control rows like the labels chips). Short scalars stay half-width.
function isWideField(el: HTMLElement): boolean {
  if (el.querySelector('textarea, [contenteditable], input[type="file"], [data-fullwidth]')) return true;
  return el.querySelectorAll("input, select, textarea").length >= 2;
}

// Splits a long form into collapsible sections (required → details → advanced)
// by reparenting the per-column wrappers (id "<prefix>field_<col>", incl. the
// "_search"/"_vulnsearch" helpers). Adds a field filter + responsive 2-col layout.
// Call it right after the field loop, before appendNameHints() so hints land
// inside their section next to the field.
function groupFormFields(prefix: string, table: string): void {
  const body = document.getElementById(prefix === "ef_" ? "edit-modal-body" : "modal-body");
  if (!body) return;
  const tag = `${prefix}field_`;
  const fieldEls = ([...body.children] as HTMLElement[]).filter((el) => el.id && el.id.startsWith(tag));
  if (fieldEls.length < 8) return; // short forms stay flat — grouping only helps long ones
  const colOf = (el: HTMLElement): string => el.id.slice(tag.length).replace(/_(search|vulnsearch)$/, "");
  const byName = new Map(schema.map((c) => [c.name, c] as const));

  const required: HTMLElement[] = [];
  const details: HTMLElement[] = [];
  const advanced: HTMLElement[] = [];
  for (const el of fieldEls) {
    const ci = byName.get(colOf(el));
    if (ci && isAdvancedFormCol(table, ci)) advanced.push(el);
    else if (ci && isRequiredFormCol(ci)) required.push(el);
    else details.push(el);
  }
  if (!required.length && !advanced.length) return; // nothing to gain by sectioning

  const marker = document.createComment("form-fields");
  body.insertBefore(marker, fieldEls[0]);
  const frag = document.createDocumentFragment();

  // Field filter: type to show only matching fields, auto-expanding their sections.
  const filter = document.createElement("input");
  filter.className = "form-field-filter";
  filter.type = "search";
  filter.placeholder = "🔍 Filter fields…";
  filter.autocomplete = "off";
  frag.appendChild(filter);

  const addSection = (title: string, els: HTMLElement[], collapsed: boolean): void => {
    if (!els.length) return;
    const det = document.createElement("details");
    det.open = !collapsed;
    det.dataset.defaultOpen = collapsed ? "0" : "1";
    det.className = "form-section";
    const sum = document.createElement("summary");
    sum.innerHTML = `<span class="fs-h"><span class="fs-chev">▸</span>${title}</span><span class="fs-n">${els.length}</span>`;
    const wrap = document.createElement("div");
    wrap.className = "fs-body";
    for (const el of els) { if (isWideField(el)) el.classList.add("fs-wide"); wrap.appendChild(el); }
    det.appendChild(sum);
    det.appendChild(wrap);
    frag.appendChild(det);
  };
  addSection("Required", required, false);
  addSection("Details", details, false);
  addSection("Advanced & system", advanced, true);

  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    body.querySelectorAll<HTMLElement>(".form-section").forEach((sec) => {
      let anyVisible = false;
      sec.querySelectorAll<HTMLElement>(".fs-body > div").forEach((f) => {
        const hay = ((f.querySelector("label")?.textContent || "") + " " + f.id).toLowerCase();
        const show = !q || hay.includes(q);
        f.style.display = show ? "" : "none";
        if (show) anyVisible = true;
      });
      sec.style.display = !q || anyVisible ? "" : "none";
      (sec as HTMLDetailsElement).open = q ? anyVisible : sec.dataset.defaultOpen === "1";
    });
  });

  body.insertBefore(frag, marker);
  marker.remove();
}

// Pre-submit check: flag empty required fields, reveal + scroll to the first one.
function validateRequiredForm(prefix: string, table: string): boolean {
  let firstBad: HTMLElement | null = null;
  for (const c of schema) {
    if (isHiddenFormColumn(c.name) || !isRequiredFormCol(c) || isReadonlyFormColumn(table, c.name)) continue;
    const wrap = document.getElementById(`${prefix}field_${c.name}`);
    const input = document.getElementById(`${prefix}${c.name}`) as HTMLInputElement | null;
    if (!wrap || !input) continue;
    if (input.type === "checkbox" || input.type === "file") { wrap.classList.remove("field-invalid"); continue; }
    const empty = !(input.value || "").trim();
    wrap.classList.toggle("field-invalid", empty);
    if (empty && !firstBad) firstBad = wrap;
  }
  if (firstBad) {
    const det = firstBad.closest("details") as HTMLDetailsElement | null;
    if (det) det.open = true;
    firstBad.scrollIntoView({ behavior: "smooth", block: "center" });
    (firstBad.querySelector("input,select,textarea") as HTMLElement | null)?.focus();
    toast("Please fill the required fields (*)", "err");
    return false;
  }
  return true;
}

async function openEditModal(row: Record<string, unknown>): Promise<void> {
  editRowId = Number(row["rowid"]);
  editIncidentId = Number(row["IncidentID"]) || 0;
  editAlertId = currentTable === "ALERT" ? Number(row["AlertID"]) || 0 : 0;
  editThreatId = currentTable === "THREAT" ? Number(row["ThreatID"]) || 0 : 0;
  const body = $("edit-modal-body");
  body.innerHTML = "";
  appendFormJsonImport(body, "ef_"); // "pre-fill from JSON" button at the top of the form

  // Pre-loads the options of the "foreign key" columns
  const fkOpts = await fetchFkOptions();

  // OSV.dev enrichment at the top of the form (XVULNERABILITY.VULNERABILITY),
  // pre-filled with the VULReferential of the current row.
  if (isOsvTable()) {
    appendOsvEnrichField(body, "ef_", String(row["VULReferential"] ?? row["VULReferentialID"] ?? ""));
    appendCirclSearchField(body, "ef_");
    appendExploitDbSearchField(body, "ef_");
  }
  if (currentTable === "OBSERVABLE") appendMalwareScanField(body, "ef_", "observable");
  else if (currentTable === "DOCUMENT") appendMalwareScanField(body, "ef_", currentDb === "XORCISM" ? "documentFile" : "manual");

  reorderSchema(currentTable, schema).forEach((col) => {
    if (isHiddenFormColumn(col.name)) return; // handled server-side (session)
    const currentVal = row[col.name];
    // Search field by name (fills the ID), inserted BEFORE the ID field
    const nsSpec = getNameSearch(currentTable, col.name);
    if (nsSpec) appendNameSearchField(body, "ef_", col.name, nsSpec, currentVal == null ? "" : String(currentVal));
    if (nsSpec?.replaceIdField) {
      // The name dropdown replaces the ID field: we keep a hidden input (filled
      // by the search, read at submission).
      const hid = document.createElement("input");
      hid.type = "hidden"; hid.id = `ef_${col.name}`;
      hid.value = currentVal == null ? "" : String(currentVal);
      body.appendChild(hid);
      return;
    }
    // Vulnerability search (fills VulnerabilityID), inserted BEFORE the ID field
    if (hasVulnSearch(currentTable, col.name))
      appendVulnSearchField(body, "ef_", col.name, currentVal == null ? "" : String(currentVal));
    const div = document.createElement("div");
    div.id = `ef_field_${col.name}`;
    div.style.marginBottom = "10px";
    const label = document.createElement("label");
    setFieldLabel(label, col);
    label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
    div.appendChild(label);

    // Selector + file upload (e.g. EVIDENCE.EvidenceFile, ASSET.AssetImage)
    if (hasFileUpload(currentTable, col.name)) {
      div.appendChild(
        mkFileUpload(`ef_${col.name}`, currentVal, {
          imageOnly: isImageUploadCol(currentTable, col.name),
        })
      );
      body.appendChild(div);
      return;
    }

    // Content-addressed object-store upload (BlobSha256 hash-pointer columns)
    if (isCasUploadCol(col.name)) {
      div.appendChild(mkCasUpload(`ef_${col.name}`, currentVal));
      body.appendChild(div);
      return;
    }

    // Labels selector (chips + autocompletion, OpenCTI style) → CSV Labels column
    if (isLabelsField(currentTable, col.name)) {
      appendLabelsField(div, `ef_${col.name}`, currentVal == null ? "" : String(currentVal));
      body.appendChild(div);
      return;
    }

    // "Foreign key" dropdown (e.g. INCIDENT.IncidentCategoryID)
    const efFk = getFkSpec(currentTable, col.name);
    if (efFk) {
      const efSel = mkFkSelect(`ef_${col.name}`, fkOpts[col.name] ?? [], currentVal == null ? "" : String(currentVal));
      div.appendChild(
        FK_CREATE_BUTTON.has(`${currentTable}.${col.name}`) ? fkWithCreate(efSel, "ef_", col.name, efFk) : efSel
      );
      body.appendChild(div);
      return;
    }

    // Free input with autocompletion (e.g. AUDIT.AuditorName → PERSON.FullName)
    const dlSpec = getDatalistSpec(currentTable, col.name);
    if (dlSpec) {
      div.appendChild(
        mkDatalistInput(
          `ef_${col.name}`,
          dlSpec,
          currentVal == null ? "" : String(currentVal),
          dlSpec.idTargetCol ? `ef_${dlSpec.idTargetCol}` : undefined
        )
      );
      body.appendChild(div);
      return;
    }

    // Labeled <select> (shows a label, stores the int value, e.g. BusinessValue)
    const lsEf = getLabeledSelect(currentTable, col.name);
    if (lsEf) {
      div.appendChild(mkLabeledSelectInput(`ef_${col.name}`, lsEf, currentVal == null ? "" : String(currentVal)));
      body.appendChild(div);
      return;
    }

    // Dropdown with input (static options: e.g. Role, status)
    const sdlEf = getStaticDatalist(currentTable, col.name);
    if (sdlEf) {
      div.appendChild(mkStaticDatalistInput(`ef_${col.name}`, sdlEf, currentVal == null ? "" : String(currentVal)));
      body.appendChild(div);
      return;
    }

    // Derived risk level (= probability × impact), read-only + live computation
    const rlEf = getRiskLevelSpec(currentTable, col.name);
    if (rlEf) {
      div.appendChild(mkRiskLevelInput(`ef_${col.name}`, currentVal));
      body.appendChild(div);
      wireRiskLevelLive(`ef_${col.name}`, `ef_${rlEf.prob}`, `ef_${rlEf.impact}`);
      return;
    }

    // Dropdown filtered by vocabulary (e.g. THREATACTOR.ThreatMotive → THREATMOTIVE)
    const vvSpec = getVocabValueSelect(currentTable, col.name);
    if (vvSpec) {
      div.appendChild(mkVocabValueSelect("ef_", col.name, vvSpec, currentVal == null ? "" : String(currentVal)));
      body.appendChild(div);
      return;
    }

    // Label/value dropdown (e.g. INCIDENT.exercise: Yes/No → 1/0)
    const ve = getValueEnum(currentTable, col.name);
    if (ve) {
      div.appendChild(
        mkValueSelect(`ef_${col.name}`, ve.options, currentVal == null ? (ve.default ?? "") : String(currentVal))
      );
      body.appendChild(div);
      return;
    }

    // Dropdown for the enumerated columns (e.g. INCIDENT.Criticity)
    const opts = getEnumOptions(currentTable, col.name);
    if (opts) {
      div.appendChild(
        mkEnumSelect(`ef_${col.name}`, opts, currentVal == null ? "" : String(currentVal))
      );
      body.appendChild(div);
      return;
    }

    // Checkbox (e.g. ASSET.Enabled)
    const cbSpec = getCheckbox(currentTable, col.name);
    if (cbSpec) {
      div.appendChild(mkCheckbox(`ef_${col.name}`, cbSpec, currentVal));
      body.appendChild(div);
      return;
    }

    // WYSIWYG editor (AssetDescription, INCIDENT.summary…) — never a primary key
    if (isRichTextField(currentTable, col.name) && col.pk !== 1) {
      const rte = mkRichText(currentVal == null ? "" : String(currentVal), col.type, richTextOpts(currentTable, col.name));
      rte.hidden.id = `ef_${col.name}`;
      div.appendChild(rte.hidden);
      div.appendChild(rte.mount);
      body.appendChild(div);
      return;
    }

    // Computed column (e.g. ASSET.RiskScore): read-only + hint
    if (isReadonlyFormColumn(currentTable, col.name)) {
      div.appendChild(mkReadonlyComputedInput(`ef_${col.name}`, currentVal));
      body.appendChild(div);
      return;
    }

    const input = document.createElement("input");
    input.id = `ef_${col.name}`;
    input.value = currentVal == null ? "" : String(currentVal);
    input.placeholder = col.type;
    input.readOnly = col.pk === 1;
    const efProminent = isProminentInput(currentTable, col.name) && col.pk !== 1;
    const efWide = isWideInput(currentTable, col.name) && col.pk !== 1;
    input.style.cssText = efProminent ? PROMINENT_INPUT_CSS : efWide ? WIDE_INPUT_CSS : FIELD_INPUT_CSS;
    if (efProminent || efWide) input.dataset.fullwidth = "1";
    if (col.pk === 1) input.style.opacity = "0.5";
    // Calendar icon for CreatedDate / ValidFromDate + date-picker columns
    if ((hasAutoDate(currentTable, col.name) || hasDatePicker(currentTable, col.name)) && col.pk !== 1) {
      // Modification date (e.g. VOCABULARY.DateModified): reset to the
      // current date at the edit form's opening
      if (AUTO_DATE_COLUMNS.has(`${currentTable}.${col.name}`)) input.value = todayStr();
      // EvidenceDate & co.: default to today if empty (we keep the existing value)
      if (isDefaultTodayDate(currentTable, col.name) && !input.value) input.value = todayStr();
      div.appendChild(wrapWithCalendar(input));
    } else {
      div.appendChild(input);
    }
    body.appendChild(div);
  });

  // Split a long form into collapsible sections (required → details → advanced)
  groupFormFields("ef_", currentTable);

  // Shows the label (e.g. AssetName) after the relevant identifier fields
  await appendNameHints("ef_");

  // STIX 2.1 bundle generation (THREAT form)
  if (isStixTable()) appendStixBundleButton(body, "ef_");

  // Web security scanner + network scanner (ASSET form)
  if (currentTable === "ASSET") { void appendWebScanPanel("ef_"); void appendNetworkScanPanel("ef_"); appendEmailHarvestHint("ef_"); }
  // SOCRadar IOC Radar: search a CVE (VULNERABILITY form)
  if (isOsvTable()) {
    appendSocradarIocField("ef_"); appendEpssButton("ef_"); appendDatePicker("ef_", "ValidUntilDate");
    appendSsvcCalculator(body, "ef_"); // CISA SSVC decision calculator (Track/Track*/Attend/Act)
    appendAiActionButton(body, "🧠 AI triage (KEV / EPSS / affected assets)", async () => {
      const vid = Number((document.getElementById("ef_VulnerabilityID") as HTMLInputElement)?.value) || undefined;
      const cve = ((document.getElementById("ef_VULReferential") as HTMLInputElement)?.value || "").trim() || undefined;
      if (!vid && !cve) throw new Error("VulnerabilityID / CVE manquant");
      return (await api.triageVuln({ vulnerabilityId: vid, cve })).assessment;
    });
  }
  // BUGBOUNTYPROGRAM: date pickers to the right of StartDate / EndDate
  if (currentTable === "BUGBOUNTYPROGRAM") { appendDatePicker("ef_", "StartDate"); appendDatePicker("ef_", "EndDate"); }
  // Any form with a validity-end field gets a date picker (no-op if the field is absent).
  appendDatePicker("ef_", "ValidUntil"); appendDatePicker("ef_", "ValidUntilDate");
  // AI answer suggestion (QUESTION / OCIL form)
  if (currentTable === "QUESTION") appendOcilSuggestPanel(body, "ef_");
  // Draft the policy body with the local AI (POLICY form)
  if (currentTable === "POLICY") appendPolicyAiDraftPanel(body, "ef_");
  // Generate the crisis-scenario Description with the local AI (CRISISSCENARIO form)
  if (currentTable === "CRISISSCENARIO") { appendCrisisScenarioAiPanel(body, "ef_"); appendCrisisAttackMapping(body, "ef_"); }
  if (currentTable === "ALERT") appendCrisisAttackMapping(body, "ef_"); // ALERT.AttackTechniques → MITRE ATT&CK picker

  // Impacted assets (ALERTFORASSET) for the ALERT table (pre-checked) — Defender "Select entities"
  if (currentTable === "ALERT" && editAlertId) {
    let linked: number[] = [];
    try { linked = await api.getAlertAssets(editAlertId); } catch { /* rights / unavailable */ }
    await appendAssetSelector(body, "ef", new Set(linked), "ALERTFORASSET");
  }

  // Many-to-many ASSET relation for the INCIDENT table (pre-checked)
  if (currentTable === "INCIDENT" && editIncidentId) {
    let linked: number[] = [];
    try {
      linked = await api.getIncidentAssets(editIncidentId);
    } catch {
      /* insufficient rights or unavailable */
    }
    await appendAssetSelector(body, "ef", new Set(linked));
    let curActor = "";
    try {
      curActor = (await api.getIncidentThreatActor(editIncidentId)).name;
    } catch {
      /* insufficient rights or unavailable */
    }
    await appendIncidentThreatActor(body, "ef_", curActor);
  }

  // Multi-ASSET selection for the AUDIT table (ASSETAUDIT links, pre-checked)
  if (currentTable === "AUDIT") {
    editAuditId = Number(row["AuditID"]) || 0;
    let linked: number[] = [];
    if (editAuditId) {
      try {
        linked = await api.getAuditAssets(editAuditId);
      } catch {
        /* insufficient rights or unavailable */
      }
    }
    await appendAuditAssetSelector(body, "ef", new Set(linked));
    await appendAuditFindingsChart(body, editAuditId);
  }

  // CATEGORY dropdown (vocabulary-dependent) for the THREATAGENT table
  if (currentTable === "THREATAGENT") {
    editThreatAgentId = Number(row["ThreatAgentID"]) || 0;
    let curCat: number | null = null;
    if (editThreatAgentId) {
      try {
        curCat = (await api.getThreatAgentCategory(editThreatAgentId)).categoryId;
      } catch {
        /* insufficient rights or unavailable */
      }
    }
    await appendThreatAgentCategory("ef_", curCat);
  }

  // Relational sub-panels (widen the modal)
  setModalWide($("edit-modal") as HTMLElement, WIDE_MODAL_TABLES.has(currentTable));
  if (currentTable === "ASSET") {
    const aid = Number(row["AssetID"]) || null;
    appendBackupPlanButton("ef_", aid);
    appendAttackSurfaceButton(body, aid);
    appendAgentScan(body, String(row["AssetName"] ?? ""));
    await appendCpeTable(body, aid);
    await appendOvalTable(body, aid);
    await appendVulnTable(body, aid);
    await appendAuditTable(body, aid);
    await appendGeoTable(body, aid);
    await appendAssetLocationTable(body, "ef_");
    appendTagsPanel(body, "Tags (ASSETTAG)", aid, api.getAssetTags, api.setAssetTags, null);
    await appendAssetOrgPanel(body, aid);
    await appendAssetPersonPanel(body, aid);
  } else if (currentTable === "VULNERABILITY") {
    await appendVulnCpeTable(body, Number(row["VulnerabilityID"]) || null);
    appendTagsPanel(body, "Tags (VULNERABILITYTAG)", Number(row["VulnerabilityID"]) || null,
      api.getVulnerabilityTags, api.setVulnerabilityTags, null);
  } else if (currentTable === "THREATMODEL") {
    const mid = Number(row["ThreatModelID"]) || null;
    await appendThreatModelScope(body, mid);
    await appendThreatModelThreats(body, mid);
  } else if (currentTable === "THREATMODELTHREAT") {
    const tid = Number(row["ThreatModelThreatID"]) || null;
    await appendThreatMitigations(body, tid);
  } else if (currentTable === "OVALDEFINITION") {
    await appendOvalDefinitionXml(body, String(row["OVALDefinitionIDPattern"] ?? ""));
    appendTagsPanel(body, "Tags (OVALDEFINITIONTAG)", Number(row["OVALDefinitionID"]) || null,
      api.getOvalDefinitionTags, api.setOvalDefinitionTags, null);
  } else if (currentTable === "CPE") {
    appendCpeGcveSearch(body, "ef_");
    appendTagsPanel(body, "Tags (CPETAG)", Number(row["CPEID"]) || null,
      api.getCpeTags, api.setCpeTags, null);
  } else if (currentTable === "CWE") {
    appendTagsPanel(body, "Tags (CWETAG)", Number(row["CWEID"]) || null,
      api.getCweTags, api.setCweTags, null);
  } else if (currentTable === "CONTROL") {
    appendTagsPanel(body, "Tags (CONTROLTAG)", Number(row["ControlID"]) || null,
      api.getControlTags, api.setControlTags, null);
  } else if (currentTable === "QUESTIONNAIRE") {
    appendQuestionnaireImportButton(body); // "📥 Excel import" at the top of the form
    await appendQuestionnaireQuestions(body, Number(row["QuestionnaireID"]) || null);
    appendQuestionnaireExcelButton(body, Number(row["QuestionnaireID"]) || null, String(row["QuestionnaireName"] ?? ""));
  } else if (currentTable === "THREATREPORT") {
    appendThreatReportImportButton(body, "ef_"); // PDF ingestion at the top of the form
    appendAiActionButton(body, "🧠 AI enrich (analyst note + CVEs)", async () => {
      const id = Number((document.getElementById("ef_ThreatReportID") as HTMLInputElement)?.value);
      if (!id) throw new Error("ThreatReportID manquant");
      const r = await api.enrichReport(id);
      return r.summary + (r.cves.length ? `\n\nCVEs: ${r.cves.join(", ")}` : "");
    });
  } else if (currentTable === "SIGMARULE") {
    appendSigmaConvertButton(body, "ef_"); // Sigma → SPL/KQL/EQL at the top of the form
    appendTagsPanel(body, "Tags (SIGMARULETAG)", Number(row["SigmaRuleID"]) || null,
      api.getSigmaRuleTags, api.setSigmaRuleTags, null);
  } else if (currentTable === "ANSWER") {
    await appendAnswerEvidences(body, Number(row["AnswerID"]) || null);
  } else if (currentTable === "THREAT") {
    await appendThreatTtps(body, Number(row["ThreatID"]) || null);
    // Linked assets (XTHREAT.THREATFORASSET): search on AssetName + checkbox table.
    const tLinked = editThreatId ? await api.getThreatAssets(editThreatId).catch(() => []) : [];
    await appendAssetSelector(body, "ef", new Set(tLinked), "THREATFORASSET");
  } else if (currentTable === "ASSETVULNERABILITYREMEDIATION") {
    appendRemediationAssetName("ef_");
  }

  applyConditionalFields("ef_");
  formDirty = false; // fresh form — ignore the programmatic value sets above
  showModalAtTop("edit-modal");
}

async function submitEdit(): Promise<void> {
  if (!validateRequiredForm("ef_", currentTable)) return;
  const row: Record<string, string> = {};
  schema
    .filter((col) => col.pk !== 1 && !isReadonlyFormColumn(currentTable, col.name))
    .forEach((col) => {
      const input = document.getElementById(`ef_${col.name}`) as HTMLInputElement;
      if (input) row[col.name] = fieldValue(input);
    });

  try {
    await api.updateRow(currentDb, currentTable, editRowId, row);
    // ASSET: on submit, detects the uncorrected KEV ASSETVULNERABILITY rows and notifies.
    if (currentTable === "ASSET") void api.checkAssetKevNotify().catch(() => {});
    // ASSET: when AssetName is an email, capture it into the email directory.
    if (currentTable === "ASSET") {
      const em = assetNameEmail("ef_");
      if (em) void api.harvestAssetEmail(em).then((r) => {
        if (r.emailInserted || r.addressInserted || r.orgLinkInserted) toast(`📧 ${em} added to the email directory`, "ok");
      }).catch(() => {});
    }
    // Impacted assets (ALERTFORASSET) for the ALERT table
    if (currentTable === "ALERT" && editAlertId) {
      try { await api.setAlertAssets(editAlertId, collectCheckedAssets("ef")); }
      catch (e) { toast(t("toast.assetLinksErr") + " " + e, "err"); }
    }
    // ASSET links (INCIDENTFORASSET)
    if (currentTable === "INCIDENT" && editIncidentId) {
      try {
        await api.setIncidentAssets(editIncidentId, collectCheckedAssets("ef"));
      } catch (e) {
        toast(t("toast.assetLinksErr") + " " + e, "err");
      }
      // THREATACTOR link (XTHREAT.THREATACTORFORINCIDENT)
      const ta = document.getElementById("ef_threatactor") as HTMLInputElement | null;
      if (ta) {
        try {
          await api.setIncidentThreatActor(editIncidentId, ta.value.trim());
        } catch (e) {
          toast(t("toast.threatActorLinkErr") + " " + e, "err");
        }
      }
    }
    // ASSET links (ASSETAUDIT)
    if (currentTable === "AUDIT" && editAuditId) {
      try {
        await api.setAuditAssets(editAuditId, collectAuditAssets("ef"));
      } catch (e) {
        toast(t("toast.assetLinksErr") + " " + e, "err");
      }
    }
    // ASSET links (THREATFORASSET) for the THREAT table
    if (currentTable === "THREAT" && editThreatId) {
      try { await api.setThreatAssets(editThreatId, collectCheckedAssets("ef")); }
      catch (e) { toast(t("toast.assetLinksErr") + " " + e, "err"); }
    }
    // CATEGORY link (THREATAGENTCATEGORY)
    if (currentTable === "THREATAGENT" && editThreatAgentId) {
      const catSel = document.getElementById("ef_ta_category") as HTMLSelectElement | null;
      if (catSel) {
        try {
          await api.setThreatAgentCategory(editThreatAgentId, catSel.value ? Number(catSel.value) : null);
        } catch (e) {
          toast(t("toast.categoryLinkErr") + " " + e, "err");
        }
      }
    }
    ($("edit-modal") as HTMLElement).style.display = "none";
    toast(t("toast.rowUpdated"), "ok");
    // "Foreign" editing: restores the original context then refreshes this
    // view (the resolved label, e.g. VULReferential, may have changed).
    if (foreignEditReturn) {
      const ret = foreignEditReturn;
      foreignEditReturn = null;
      ret();
      clearNameHintCache(); // a table referenced by a computed column may have changed
      loadRows();
      return;
    }
    // ASSETVULNERABILITY: "corrected" status → offer to add evidence.
    if (
      currentTable === "ASSETVULNERABILITY" &&
      offerEvidenceForStatus(
        String(row["AssetVulnerabilityStatusID"] ?? ""),
        String(row["VulnerabilityID"] ?? "")
      )
    ) {
      return; // we navigated to the EVIDENCE form
    }
    // INCIDENT: offer to create an ALERT/NOTIFICATION linked to this incident.
    if (currentTable === "INCIDENT" && offerAlertForIncident(editIncidentId)) {
      return; // we navigated to the ALERT creation form
    }
    loadRows();
  } catch (e) {
    toast(t("toast.errUpdate") + " " + e, "err");
  }
}

// ── Insert modal ──────────────────────────────────────────────────────────────

// ── Multi-ASSET selector (INCIDENT ↔ ASSET relation via INCIDENTFORASSET) ──────
async function appendAssetSelector(
  body: HTMLElement,
  prefix: string,
  selected: Set<number>,
  relLabel = "INCIDENTFORASSET",
  opts?: { tagFilter?: boolean; checkAll?: boolean }
): Promise<void> {
  const div = document.createElement("div");
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = `${t("asset.linked")} (${relLabel})`;
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);

  // Controls: search on AssetName + optional ASSETTAG filter.
  const controls = document.createElement("div");
  controls.style.cssText = "display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:4px";
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = t("asset.searchName");
  search.style.cssText = "flex:1 1 160px;min-width:140px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px";
  controls.appendChild(search);
  const tagSel = document.createElement("select");
  if (opts?.tagFilter) {
    tagSel.style.cssText = "flex:0 0 150px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 8px;color:var(--text);font-size:12px";
    const o0 = document.createElement("option"); o0.value = ""; o0.textContent = "All tags"; tagSel.appendChild(o0);
    controls.appendChild(tagSel);
  }
  div.appendChild(controls);

  const box = document.createElement("div");
  box.id = `${prefix}_m2m_assets`;
  box.style.cssText = "max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg)";
  div.appendChild(box);

  // "Check all (filtered)" — toggles every currently-visible row.
  if (opts?.checkAll) {
    const ca = document.createElement("label");
    ca.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-muted);margin-top:4px;cursor:pointer";
    const cb = document.createElement("input"); cb.type = "checkbox";
    cb.onchange = () => box.querySelectorAll<HTMLElement>("label").forEach((r) => {
      if (r.style.display !== "none") { const c = r.querySelector<HTMLInputElement>("input[type=checkbox]"); if (c) c.checked = cb.checked; }
    });
    const sp = document.createElement("span"); sp.textContent = "Check all (filtered)";
    ca.appendChild(cb); ca.appendChild(sp); div.appendChild(ca);
  }
  body.appendChild(div);

  let rows: { id: number; name: string; tags: string[] }[] = [];
  try {
    if (opts?.tagFilter) {
      rows = (await api.assetsWithTags()).map((a) => ({ id: a.AssetID, name: a.AssetName, tags: (a.Tags || "").split(",").map((s) => s.trim()).filter(Boolean) }));
    } else {
      rows = (await api.getLookup("XORCISM", "ASSET", "AssetID", "AssetName")).map((a) => ({ id: Number(a.id), name: a.label == null || a.label === "" ? `#${a.id}` : String(a.label), tags: [] }));
    }
  } catch (e) {
    box.innerHTML = `<span style="color:var(--danger);font-size:12px">${t("asset.unavailable")} ${e}</span>`;
    return;
  }
  if (!rows.length) { box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">${t("asset.none")}</span>`; return; }

  const allTags = new Set<string>();
  rows.forEach((a) => {
    const row = document.createElement("label");
    row.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
    row.dataset.name = a.name.toLowerCase();
    row.dataset.tags = a.tags.map((s) => s.toLowerCase()).join(",");
    a.tags.forEach((tg) => allTags.add(tg));
    const cb = document.createElement("input"); cb.type = "checkbox"; cb.value = String(a.id); cb.checked = selected.has(a.id);
    row.appendChild(cb);
    const txt = document.createElement("span"); txt.textContent = a.tags.length ? `${a.name}  ·  ${a.tags.join(", ")}` : a.name;
    row.appendChild(txt);
    box.appendChild(row);
  });
  if (opts?.tagFilter) [...allTags].sort().forEach((tg) => { const o = document.createElement("option"); o.value = tg.toLowerCase(); o.textContent = tg; tagSel.appendChild(o); });

  // Filter by AssetName AND tag; checked-but-hidden rows stay selected (collectCheckedAssets reads all).
  const applyFilter = (): void => {
    const q = search.value.trim().toLowerCase();
    const tag = opts?.tagFilter ? tagSel.value.trim().toLowerCase() : "";
    box.querySelectorAll<HTMLElement>("label").forEach((r) => {
      const okName = !q || (r.dataset.name ?? "").includes(q);
      const okTag = !tag || (r.dataset.tags ?? "").split(",").includes(tag);
      r.style.display = okName && okTag ? "flex" : "none";
    });
  };
  search.addEventListener("input", applyFilter);
  if (opts?.tagFilter) tagSel.addEventListener("change", applyFilter);
}

function collectCheckedAssets(prefix: string): number[] {
  const box = document.getElementById(`${prefix}_m2m_assets`);
  if (!box) return [];
  return Array.from(
    box.querySelectorAll<HTMLInputElement>('input[type=checkbox]:checked')
  ).map((c) => Number(c.value));
}

// ── Multi-ASSET selector for AUDIT (relation via XORCISM.ASSETAUDIT) ─────────
// Search field on AssetName + multiple selection in a table.
/** Read-only chart of an audit's AUDITFINDINGs (severity bars + status chips + open/overdue), in the AUDIT form. */
async function appendAuditFindingsChart(body: HTMLElement, auditId: number): Promise<void> {
  if (!auditId) return;
  const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  const div = document.createElement("div");
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = t("audit.findingsChart");
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);
  const box = document.createElement("div");
  box.style.cssText = "border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:10px 12px";
  box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">…</span>`;
  div.appendChild(box);
  body.appendChild(div);

  let d: { total: number; open: number; overdue: number; bySeverity: Record<string, number>; byStatus: Record<string, number> };
  try { const r = await fetch(`/api/audit-findings-stats?auditId=${auditId}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">${esc(String(e))}</span>`; return; }
  if (!d.total) { box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">${esc(t("audit.noFindings"))}</span>`; return; }

  const SEV: [string, string][] = [["Critical", "#f87171"], ["High", "#fb923c"], ["Medium", "#fbbf24"], ["Low", "#34d399"], ["Info", "#60a5fa"]];
  const extras: [string, string][] = Object.keys(d.bySeverity).filter((k) => !SEV.some(([s]) => s === k)).map((k) => [k, "#64748b"]);
  const order = [...SEV, ...extras];
  const max = Math.max(1, ...order.map(([k]) => d.bySeverity[k] || 0));
  const bars = order.filter(([k]) => (d.bySeverity[k] || 0) > 0).map(([k, c]) => {
    const n = d.bySeverity[k] || 0;
    return `<div style="display:flex;align-items:center;gap:8px;margin:3px 0">
      <span style="width:64px;font-size:11px;color:var(--text-muted);text-align:right">${esc(k)}</span>
      <div style="flex:1;background:var(--panel);border:1px solid var(--border);border-radius:4px;height:14px;overflow:hidden"><span style="display:block;height:100%;width:${Math.round((n / max) * 100)}%;background:${c}"></span></div>
      <span style="width:26px;font-size:12px;font-weight:700;color:var(--text)">${n}</span></div>`;
  }).join("");
  const statusChips = Object.entries(d.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) =>
    `<span style="font-size:11px;background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:1px 7px;color:var(--text-muted)">${esc(k)} <b style="color:var(--text)">${n}</b></span>`).join(" ");
  box.innerHTML = `<div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${d.total} finding(s) · <b style="color:#fb923c">${d.open}</b> open${d.overdue ? ` · <b style="color:#f87171">${d.overdue}</b> overdue` : ""}</div>
    ${bars}<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px">${statusChips}</div>`;
}

async function appendAuditAssetSelector(
  body: HTMLElement,
  prefix: string,
  selected: Set<number>
): Promise<void> {
  const div = document.createElement("div");
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = `${t("asset.linked")} (ASSETAUDIT)`;
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);

  // Tag picker: check all assets carrying the chosen ASSETTAG (e.g. all "endpoint")
  const tagSel = document.createElement("select");
  tagSel.style.cssText = "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px;margin-bottom:6px";
  div.appendChild(tagSel);

  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = t("asset.searchName");
  search.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px;margin-bottom:6px";
  div.appendChild(search);

  const box = document.createElement("div");
  box.id = `${prefix}_audit_assets`;
  box.style.cssText =
    "max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  div.appendChild(box);
  body.appendChild(div);

  let assets: { id: unknown; label: unknown; tags: string[] }[] = [];
  try {
    const r = await fetch("/api/assets-with-tags");
    if (r.ok) {
      assets = ((await r.json()) as { AssetID: number; AssetName: string; Tags?: string }[]).map((a) => ({
        id: a.AssetID, label: a.AssetName, tags: String(a.Tags ?? "").split(",").map((x) => x.trim()).filter(Boolean),
      }));
    } else {
      assets = (await api.getLookup("XORCISM", "ASSET", "AssetID", "AssetName")).map((a) => ({ id: a.id, label: a.label, tags: [] as string[] }));
    }
  } catch (e) {
    box.innerHTML = `<span style="color:var(--danger);font-size:12px;padding:6px;display:block">${t("asset.unavailable")} ${e}</span>`;
    return;
  }
  if (!assets.length) {
    box.innerHTML = `<span style="color:var(--text-dim);font-size:12px;padding:6px;display:block">${t("asset.none")}</span>`;
    return;
  }

  const tbl = document.createElement("table");
  tbl.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  tbl.innerHTML =
    `<thead><tr>` +
    `<th style="width:30px;padding:4px 8px;text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border)"></th>` +
    `<th style="padding:4px 8px;text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border)">AssetName</th>` +
    `</tr></thead>`;
  const tbody = document.createElement("tbody");
  assets.forEach((a) => {
    const name = a.label == null || a.label === "" ? `#${a.id}` : String(a.label);
    const tr = document.createElement("tr");
    tr.dataset.name = name.toLowerCase();
    tr.dataset.tags = (a.tags || []).join("|").toLowerCase();
    tr.style.cursor = "pointer";
    const tdCb = document.createElement("td");
    tdCb.style.cssText = "padding:3px 8px;border-bottom:1px solid var(--surface)";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = String(a.id);
    cb.checked = selected.has(Number(a.id));
    tdCb.appendChild(cb);
    const tdName = document.createElement("td");
    tdName.style.cssText = "padding:3px 8px;border-bottom:1px solid var(--surface);color:var(--text-soft)";
    tdName.textContent = name;
    // Click on the row = toggle of the checkbox
    tr.addEventListener("click", (ev) => {
      if (ev.target !== cb) cb.checked = !cb.checked;
    });
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tbody.appendChild(tr);
  });
  tbl.appendChild(tbody);
  box.appendChild(tbl);

  // Filter as you type (the checked rows stay visible)
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    tbody.querySelectorAll<HTMLTableRowElement>("tr").forEach((tr) => {
      const cb = tr.querySelector<HTMLInputElement>("input[type=checkbox]");
      tr.style.display = !q || tr.dataset.name!.includes(q) || cb?.checked ? "" : "none";
    });
  });

  // Tag picker: distinct ASSETTAG values (+ counts); selecting one checks every asset carrying it.
  const escO = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  const allTags = [...new Set(assets.flatMap((a) => a.tags))].sort((x, y) => x.localeCompare(y));
  tagSel.innerHTML = `<option value="">${escO(t("asset.checkByTag"))}</option>` +
    allTags.map((tg) => `<option value="${escO(tg.toLowerCase())}">${escO(tg)} (${assets.filter((a) => a.tags.some((x) => x.toLowerCase() === tg.toLowerCase())).length})</option>`).join("");
  if (!allTags.length) tagSel.style.display = "none";
  tagSel.addEventListener("change", () => {
    const tg = tagSel.value; if (!tg) return;
    tbody.querySelectorAll<HTMLTableRowElement>("tr").forEach((tr) => {
      if ((tr.dataset.tags || "").split("|").includes(tg)) {
        const cb = tr.querySelector<HTMLInputElement>("input[type=checkbox]"); if (cb) cb.checked = true;
        tr.style.display = "";
      }
    });
    tagSel.value = "";
  });
}

function collectAuditAssets(prefix: string): number[] {
  const box = document.getElementById(`${prefix}_audit_assets`);
  if (!box) return [];
  return Array.from(
    box.querySelectorAll<HTMLInputElement>('input[type=checkbox]:checked')
  ).map((c) => Number(c.value));
}

// Widens (or resets) the width of a modal
function setModalWide(modalRoot: HTMLElement, wide: boolean): void {
  const m = modalRoot.querySelector(".modal") as HTMLElement | null;
  if (m) m.style.width = wide ? "820px" : "";
}

// Fills (or reloads) the content of the read-only CPE table
async function renderCpeBox(box: HTMLElement, assetId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!assetId) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">—</div>`;
    return;
  }
  let cpes: { CPEID: number; CPEName: string }[] = [];
  try {
    cpes = await api.getAssetCpes(assetId);
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  if (!cpes.length) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("cpe.noneLinked")}</div>`;
    return;
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  table.innerHTML =
    '<thead><tr>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">CPEName</th>' +
    '<th style="width:30px;border-bottom:1px solid var(--border)"></th></tr></thead>';
  const tb = document.createElement("tbody");
  cpes.forEach((c) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-all";
    td.textContent = c.CPEName == null || c.CPEName === "" ? `#${c.CPEID}` : c.CPEName;
    const tdRm = document.createElement("td");
    tdRm.style.cssText = "padding:2px 6px;border-bottom:1px solid var(--border-subtle);text-align:right";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "✕";
    rm.title = t("tip.unlinkCpe");
    rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    rm.onclick = async () => {
      try {
        const remaining = cpes.filter((x) => x.CPEID !== c.CPEID).map((x) => x.CPEID);
        await api.setAssetCpes(assetId, remaining);
        await renderCpeBox(box, assetId);
      } catch (e) {
        toast(t("link.removeErr") + " " + e, "err");
      }
    };
    tdRm.appendChild(rm);
    tr.appendChild(td);
    tr.appendChild(tdRm);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  box.appendChild(table);
}

// "XOR endpoint agent" section: launch an EDR scan on the endpoint (by AssetName).
// Detail of the chosen location: shows the ASSETLOCATION record(s)
// matching the AssetLocationID selected via the AssetLocationName search.
// Refreshes when the search updates the hidden AssetLocationID field.
// ASSETVULNERABILITYREMEDIATION form: AssetName field (read-only) inserted
// right after AssetVulnerabilityID. Resolution in 2 hops: AssetVulnerabilityID →
// ASSETVULNERABILITY.AssetID → ASSET.AssetName. Recomputed when AssetVulnerabilityID changes.
function appendRemediationAssetName(prefix: string): void {
  const idInput = document.getElementById(`${prefix}AssetVulnerabilityID`) as HTMLInputElement | null;
  const anchor = document.getElementById(`${prefix}field_AssetVulnerabilityID`);
  if (!idInput || !anchor) return;
  const div = document.createElement("div");
  div.id = `${prefix}field_AssetName_resolved`;
  div.style.marginBottom = "10px";
  const label = document.createElement("label");
  label.textContent = "AssetName";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  const out = document.createElement("input");
  out.id = `${prefix}AssetName_resolved`;
  out.readOnly = true;
  out.tabIndex = -1;
  out.style.cssText =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px;opacity:0.7";
  div.appendChild(label);
  div.appendChild(out);
  anchor.after(div); // inserts right after the AssetVulnerabilityID field

  const cache = new Map<string, string>();
  let token = 0;
  const resolve = async (): Promise<void> => {
    const avId = (idInput.value || "").trim();
    if (!avId) { out.value = ""; return; }
    if (cache.has(avId)) { out.value = cache.get(avId)!; return; }
    const my = ++token;
    out.value = "…";
    try {
      const av = (await api.getRowById("XORCISM", "ASSETVULNERABILITY", "AssetVulnerabilityID", avId)).row;
      const assetId = av && av["AssetID"] != null ? String(av["AssetID"]) : "";
      let name = "";
      if (assetId) {
        const a = (await api.getRowById("XORCISM", "ASSET", "AssetID", assetId)).row;
        name = a && a["AssetName"] != null ? String(a["AssetName"]) : "";
      }
      if (my !== token) return; // anti-stale: a more recent input took over
      const display = name || (assetId ? `(asset #${assetId})` : "(introuvable)");
      cache.set(avId, display);
      out.value = display;
    } catch {
      if (my === token) out.value = "";
    }
  };
  idInput.addEventListener("input", resolve);
  idInput.addEventListener("change", resolve);
  void resolve(); // initial (editing: current value; creation: ID possibly pre-filled)
}

// Tag repository (XORCISM.TAG) for autocompletion — loaded once, cached.
let _tagSuggest: string[] | null = null;
async function loadTagSuggestions(): Promise<string[]> {
  if (_tagSuggest) return _tagSuggest;
  try { _tagSuggest = await api.listTags(); } catch { _tagSuggest = []; }
  return _tagSuggest;
}

// Reusable tags panel (ASSET → ASSETTAG, VULNERABILITY → VULNERABILITYTAG…).
// id != null = editing (immediate persistence via save); otherwise creation → buffered
// (staged). Autocompletion from the TAG repository; the TagID is set server-
// side (get-or-create). Tags = chips with removal.
function appendTagsPanel(
  body: HTMLElement,
  labelText: string,
  id: number | null,
  load: (id: number) => Promise<string[]>,
  save: (id: number, tags: string[]) => Promise<unknown>,
  staged: { get: () => string[]; set: (t: string[]) => void } | null
): void {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = labelText;
  label.style.cssText = "font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px";
  const box = document.createElement("div");
  box.style.cssText =
    "border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-height:34px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;margin-top:6px";
  const input = document.createElement("input");
  input.placeholder = t("tag.new");
  input.autocomplete = "off";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  // Autocompletion via a datalist fed by the TAG repository.
  const dl = document.createElement("datalist");
  dl.id = `tagdl_${Math.random().toString(36).slice(2)}`;
  input.setAttribute("list", dl.id);
  void loadTagSuggestions().then((sugg) => {
    for (const s of sugg) { const o = document.createElement("option"); o.value = s; dl.appendChild(o); }
  });
  const addBtn = document.createElement("button");
  addBtn.type = "button"; addBtn.className = "btn btn-ghost btn-sm"; addBtn.textContent = "+ Tag";
  row.appendChild(input); row.appendChild(addBtn); row.appendChild(dl);
  div.appendChild(label); div.appendChild(box); div.appendChild(row);
  body.appendChild(div);

  let tags: string[] = [];
  const persist = async (): Promise<void> => {
    if (id) { try { await save(id, tags); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
    else if (staged) { staged.set(tags); }
  };
  const renderChips = (): void => {
    box.innerHTML = "";
    if (!tags.length) { box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">Aucun tag</span>`; return; }
    tags.forEach((tg, i) => {
      const chip = document.createElement("span");
      chip.style.cssText =
        "display:inline-flex;align-items:center;gap:4px;background:var(--surface-3);border:1px solid var(--border);border-radius:12px;padding:2px 4px 2px 10px;font-size:12px;color:var(--text-soft)";
      chip.appendChild(document.createTextNode(tg));
      const x = document.createElement("button");
      x.type = "button"; x.textContent = "✕"; x.title = "Retirer";
      x.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:11px;padding:0 3px";
      x.onclick = () => { tags.splice(i, 1); renderChips(); void persist(); };
      chip.appendChild(x);
      box.appendChild(chip);
    });
  };
  const addTag = (): void => {
    const v = input.value.trim();
    if (v && !tags.some((x) => x.toLowerCase() === v.toLowerCase())) { tags.push(v); renderChips(); void persist(); }
    input.value = ""; input.focus();
  };
  addBtn.onclick = addTag;
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } });

  if (id) {
    load(id).then((tg) => { tags = tg; renderChips(); }).catch(() => renderChips());
  } else if (staged) {
    tags = staged.get();
    renderChips();
  } else {
    box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</span>`;
    row.style.display = "none";
  }
}

// Labels selector (OpenCTI style) reusing the ASSET tag-picker UX, but linked to the
// CSV `Labels` column via a <hidden input> (read as-is by the form submission,
// so no dedicated endpoint). Autocompletion from the TAG repository (loadTagSuggestions).
function appendLabelsField(container: HTMLElement, hiddenId: string, csv: string): void {
  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.id = hiddenId;
  hidden.value = csv || "";
  let labels: string[] = (csv || "").split(",").map((s) => s.trim()).filter(Boolean);

  const box = document.createElement("div");
  box.style.cssText =
    "border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-height:34px";
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:6px;margin-top:6px";
  const input = document.createElement("input");
  input.placeholder = "Nouveau label…";
  input.autocomplete = "off";
  input.style.cssText = FIELD_INPUT_CSS + ";flex:1";
  const dl = document.createElement("datalist");
  dl.id = `lbldl_${Math.random().toString(36).slice(2)}`;
  input.setAttribute("list", dl.id);
  void loadTagSuggestions().then((sugg) => {
    for (const s of sugg) { const o = document.createElement("option"); o.value = s; dl.appendChild(o); }
  });
  const addBtn = document.createElement("button");
  addBtn.type = "button"; addBtn.className = "btn btn-ghost btn-sm"; addBtn.textContent = "+ Label";
  row.appendChild(input); row.appendChild(addBtn); row.appendChild(dl);

  const sync = (): void => { hidden.value = labels.join(", "); };
  const renderChips = (): void => {
    box.innerHTML = "";
    if (!labels.length) { box.innerHTML = `<span style="color:var(--text-dim);font-size:12px">Aucun label</span>`; return; }
    labels.forEach((lb, i) => {
      const chip = document.createElement("span");
      chip.style.cssText =
        "display:inline-flex;align-items:center;gap:4px;background:var(--surface-3);border:1px solid var(--border);border-radius:12px;padding:2px 4px 2px 10px;font-size:12px;color:var(--text-soft)";
      chip.appendChild(document.createTextNode(lb));
      const x = document.createElement("button");
      x.type = "button"; x.textContent = "✕"; x.title = "Retirer";
      x.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:11px;padding:0 3px";
      x.onclick = () => { labels.splice(i, 1); renderChips(); sync(); };
      chip.appendChild(x);
      box.appendChild(chip);
    });
  };
  const add = (): void => {
    const v = input.value.trim();
    if (v && !labels.some((x) => x.toLowerCase() === v.toLowerCase())) { labels.push(v); renderChips(); sync(); }
    input.value = ""; input.focus();
  };
  addBtn.onclick = add;
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });

  container.appendChild(hidden);
  container.appendChild(box);
  container.appendChild(row);
  renderChips();
}

// "Suggest an answer" button (local AI) on the QUESTION form (OCIL): sends the
// question text to /api/ai/suggest-answer and shows a draft (human-in-the-loop).
function appendOcilSuggestPanel(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = "Suggestion de réponse (IA locale)";
  label.style.cssText = "font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-ghost btn-sm"; btn.textContent = "🤖 Suggérer une réponse";
  const out = document.createElement("div");
  out.style.cssText =
    "white-space:pre-wrap;border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:8px;margin-top:6px;font-size:12px;color:var(--text-soft);display:none";
  const copyBtn = document.createElement("button");
  copyBtn.type = "button"; copyBtn.className = "btn btn-ghost btn-sm"; copyBtn.textContent = "Copier";
  copyBtn.style.cssText = "margin-top:6px;display:none";
  div.appendChild(label); div.appendChild(btn); div.appendChild(out); div.appendChild(copyBtn);
  body.appendChild(div);

  const getVal = (col: string): string =>
    (document.getElementById(`${prefix}${col}`) as HTMLInputElement | HTMLTextAreaElement | null)?.value || "";
  btn.onclick = async (): Promise<void> => {
    const question = (getVal("QuestionText") || getVal("QuestionName")).trim();
    if (!question) { toast(t("toast.questionTextFirst"), "err"); return; }
    const description = getVal("QuestionDescription") || undefined;
    out.style.display = "block"; out.textContent = "⏳ L'IA locale réfléchit…";
    copyBtn.style.display = "none"; btn.disabled = true;
    try {
      const r = await fetch("/api/ai/suggest-answer", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, description }),
      });
      const d = await r.json() as { answer?: string; error?: string };
      if (!r.ok) { out.textContent = "⚠️ " + (d.error || `Erreur ${r.status}`); }
      else {
        out.textContent = d.answer || "(réponse vide)";
        copyBtn.style.display = "inline-block";
        copyBtn.onclick = () => { void navigator.clipboard?.writeText(d.answer || ""); toast(t("toast.copied")); };
      }
    } catch (e) {
      out.textContent = "⚠️ " + String(e);
    } finally {
      btn.disabled = false;
    }
  };
}

async function appendAssetLocationTable(body: HTMLElement, prefix: string): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = "Selected location (ASSETLOCATION)";
  label.style.cssText = "font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px";
  const box = document.createElement("div");
  box.style.cssText = "border:1px solid var(--border);border-radius:6px;background:var(--bg);overflow:auto";
  div.appendChild(label); div.appendChild(box); body.appendChild(div);

  const idEl = () => document.getElementById(`${prefix}AssetLocationID`) as HTMLInputElement | null;
  const FIELDS: [string, string][] = [
    ["AssetLocationID", "ID"],
    ["AssetLocationName", "Name"],
    ["AssetLocationType", "Type"],
    ["AssetLocationDescription", "Description"],
  ];
  let lastId: string | null = null; // sentinel: forces the 1st render
  const refresh = async (): Promise<void> => {
    const id = (idEl()?.value || "").trim();
    if (id === lastId) return; // avoids redundant requests
    lastId = id;
    if (!id) { box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucune localisation sélectionnée.</div>`; return; }
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">…</div>`;
    try {
      const { row } = await api.getRowById("XORCISM", "ASSETLOCATION", "AssetLocationID", id);
      if (id !== (idEl()?.value || "").trim()) return; // anti-stale (selection changed in the meantime)
      if (!row) { box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Localisation #${id} introuvable.</div>`; return; }
      const tb = document.createElement("table");
      tb.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
      for (const [col, lbl] of FIELDS) {
        const v = row[col];
        const tr = document.createElement("tr");
        const k = document.createElement("td");
        k.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-muted);white-space:nowrap;width:120px";
        k.textContent = lbl;
        const d = document.createElement("td");
        d.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-word";
        d.textContent = v == null ? "" : String(v);
        tr.appendChild(k); tr.appendChild(d); tb.appendChild(tr);
      }
      box.innerHTML = ""; box.appendChild(tb);
    } catch {
      box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Détail indisponible.</div>`;
    }
  };
  // The search fills the ID (programmatically, without a "change" event) on input/
  // change: we refresh after the tick to read the ID once resolved.
  const search = document.getElementById(`${prefix}AssetLocationID_search`);
  const onChange = () => window.setTimeout(() => void refresh(), 0);
  search?.addEventListener("input", onChange);
  search?.addEventListener("change", onChange);
  await refresh(); // initial (editing mode: shows the current location)
}

function appendAgentScan(body: HTMLElement, assetName: string): void {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "XOR agent — launch a scan";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);

  const sel = document.createElement("select");
  sel.style.cssText = "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:5px 8px;color:var(--text);font-size:12px";
  ([["full", "Full scan"], ["inventory", "Software inventory"], ["vuln", "Vulnerabilities (CVE)"],
    ["oval", "Config / compliance (OVAL)"], ["av", "Antivirus (ClamAV)"], ["hunt", "Threat hunt (IOC)"]] as const)
    .forEach(([v, t2]) => { const o = document.createElement("option"); o.value = v; o.textContent = t2; sel.appendChild(o); });
  header.appendChild(sel);

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-primary btn-sm";
  btn.textContent = "▶ Launch";
  const out = document.createElement("span");
  out.style.cssText = "font-size:11px;color:var(--text-dim);margin-left:6px";
  btn.onclick = async () => {
    if (!assetName) { out.textContent = "AssetName manquant"; return; }
    btn.disabled = true; out.textContent = "…";
    try {
      const r = await fetch("/api/agent-scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent: assetName, kind: sel.value }),
      });
      const d = await r.json().catch(() => ({}));
      out.textContent = r.ok ? `job #${d.jobId} envoyé (exécuté au prochain check-in de l'agent)` : (d.error || "erreur");
      out.style.color = r.ok ? "var(--success)" : "var(--danger)";
    } catch (e) { out.textContent = String(e); out.style.color = "var(--danger)"; }
    finally { btn.disabled = false; }
  };
  header.appendChild(btn);
  header.appendChild(out);
  div.appendChild(header);
  body.appendChild(div);
}

// ── Pending ASSET links (creation mode: the AssetID does not exist yet) ──────
// In creation, the relational panels (CPE, vuln, OVAL, audits) write into
// this buffer; they are saved automatically after the ASSET insertion
// (once the AssetID is known) — see submitInsert.
interface PendingAssetLinks {
  cpes: Map<number, string>;
  vulns: Map<number, string>;
  ovals: Map<number, string>;
  audits: Map<number, string>;
  tags: Set<string>; // pending tags (ASSETTAG): free text
  orgs: Map<number, string>; // ASSETFORORGANISATION (OrganisationID → name)
  persons: Map<number, { name: string; role: string }>; // PERSONFORASSET (PersonID → {name, role})
}
let pendingAssetLinks: PendingAssetLinks | null = null;
function resetPendingAssetLinks(): void {
  pendingAssetLinks = {
    cpes: new Map(), vulns: new Map(), ovals: new Map(), audits: new Map(), tags: new Set(),
    orgs: new Map(), persons: new Map(),
  };
}

// Predefined PERSONFORASSET roles (editable combobox — free text also allowed).
const ASSET_PERSON_ROLES = ["Owner", "Maintainer", "Auditor", "Contributor", "Custodian", "Approver", "Reviewer", "Reader"];

// Compact searchable combobox: an <input type=search> + a results dropdown.
// `searchFn(q)` returns [{id,name}]; `onPick` fires on selection.
function makeSearchPicker(
  placeholder: string,
  searchFn: (q: string) => Promise<{ id: number; name: string }[]>,
  onPick: (item: { id: number; name: string }) => void
): HTMLElement {
  const wrap = document.createElement("div");
  wrap.style.cssText = "position:relative;flex:1 1 200px;min-width:160px";
  const input = document.createElement("input");
  input.type = "search";
  input.placeholder = placeholder;
  input.style.cssText = "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px";
  const results = document.createElement("div");
  results.style.cssText = "position:absolute;left:0;right:0;z-index:30;max-height:200px;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-top:2px;display:none";
  wrap.appendChild(input); wrap.appendChild(results);
  const hide = () => { results.style.display = "none"; };
  let timer: number | undefined;
  input.addEventListener("input", () => {
    const q = input.value.trim();
    window.clearTimeout(timer);
    if (q.length < 1) { hide(); return; }
    timer = window.setTimeout(async () => {
      let rows: { id: number; name: string }[] = [];
      try { rows = await searchFn(q); } catch { hide(); return; }
      results.innerHTML = "";
      if (!rows.length) {
        results.innerHTML = `<div style="padding:7px 10px;font-size:12px;color:var(--text-dim)">Aucun résultat</div>`;
      } else {
        rows.forEach((r) => {
          const it = document.createElement("div");
          it.style.cssText = "padding:7px 10px;font-size:12px;color:var(--text-soft);cursor:pointer;border-bottom:1px solid var(--surface)";
          it.textContent = `${r.name} (#${r.id})`;
          it.addEventListener("mouseenter", () => (it.style.background = "var(--surface)"));
          it.addEventListener("mouseleave", () => (it.style.background = ""));
          it.addEventListener("click", () => { onPick(r); input.value = ""; hide(); });
          results.appendChild(it);
        });
      }
      results.style.display = "";
    }, 250);
  });
  input.addEventListener("blur", () => window.setTimeout(hide, 200));
  return wrap;
}

// ASSET form: link to ORGANISATION(s) via ASSETFORORGANISATION. Searchable combobox
// on OrganisationName; in creation mode pre-seeded with the current user's org.
async function appendAssetOrgPanel(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.cssText = "margin-top:14px";
  const header = document.createElement("div");
  header.style.cssText = "font-weight:600;font-size:13px;margin-bottom:6px;color:var(--text)";
  header.textContent = "Organisations (ASSETFORORGANISATION)";
  const box = document.createElement("div");
  box.style.cssText = "border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px";
  const model: Map<number, string> = (!assetId && pendingAssetLinks) ? pendingAssetLinks.orgs : new Map();

  const persist = (): void => {
    if (assetId) void api.setAssetOrganisations(assetId, [...model.keys()]).catch((e) => toast(t("link.addErr") + " " + e, "err"));
  };
  const render = (): void => {
    box.innerHTML = "";
    if (!model.size) { box.innerHTML = `<div style="color:var(--text-dim);font-size:12px">No organisation linked.</div>`; return; }
    model.forEach((name, id) => {
      const chip = document.createElement("div");
      chip.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:4px 6px;font-size:12px;border-bottom:1px solid var(--surface)";
      const lbl = document.createElement("span"); lbl.textContent = `${name} (#${id})`;
      const x = document.createElement("button"); x.type = "button"; x.textContent = "✕"; x.className = "btn btn-ghost btn-sm"; x.style.cssText = "padding:0 6px";
      x.onclick = () => { model.delete(id); persist(); render(); };
      chip.appendChild(lbl); chip.appendChild(x); box.appendChild(chip);
    });
  };
  const picker = makeSearchPicker(
    "Search organisation…",
    async (q) => (await api.lookupOrganisations(q)).map((o) => ({ id: o.OrganisationID, name: o.OrganisationName })),
    (item) => { model.set(item.id, item.name); persist(); render(); }
  );
  div.appendChild(header); div.appendChild(box); div.appendChild(picker);
  body.appendChild(div);

  if (assetId) {
    try { (await api.getAssetOrganisations(assetId)).forEach((o) => model.set(o.OrganisationID, o.OrganisationName)); } catch { /* ignore */ }
  } else if (!model.size) {
    // creation: default to the current user's organisation
    try { const d = await api.defaultOrganisation(); if (d.OrganisationID) model.set(d.OrganisationID, d.OrganisationName || `#${d.OrganisationID}`); } catch { /* ignore */ }
  }
  render();
}

// ASSET form: link to PERSON(s) via PERSONFORASSET. Person searchable by name +
// an editable role combobox (Owner default, Maintainer, Auditor, …).
async function appendAssetPersonPanel(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.cssText = "margin-top:14px";
  const header = document.createElement("div");
  header.style.cssText = "font-weight:600;font-size:13px;margin-bottom:6px;color:var(--text)";
  header.textContent = "People (PERSONFORASSET)";
  const box = document.createElement("div");
  box.style.cssText = "border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:6px";
  const model: Map<number, { name: string; role: string }> = (!assetId && pendingAssetLinks) ? pendingAssetLinks.persons : new Map();

  const persist = (): void => {
    if (assetId) {
      void api.setAssetPersons(assetId, [...model.entries()].map(([pid, v]) => ({ personId: pid, relationshiptype: v.role })))
        .catch((e) => toast(t("link.addErr") + " " + e, "err"));
    }
  };
  const render = (): void => {
    box.innerHTML = "";
    if (!model.size) { box.innerHTML = `<div style="color:var(--text-dim);font-size:12px">No person linked.</div>`; return; }
    model.forEach((v, id) => {
      const chip = document.createElement("div");
      chip.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:4px 6px;font-size:12px;border-bottom:1px solid var(--surface)";
      const lbl = document.createElement("span"); lbl.textContent = `${v.name} (#${id}) — ${v.role || "—"}`;
      const x = document.createElement("button"); x.type = "button"; x.textContent = "✕"; x.className = "btn btn-ghost btn-sm"; x.style.cssText = "padding:0 6px";
      x.onclick = () => { model.delete(id); persist(); render(); };
      chip.appendChild(lbl); chip.appendChild(x); box.appendChild(chip);
    });
  };

  const addRow = document.createElement("div");
  addRow.style.cssText = "display:flex;gap:6px;align-items:center;flex-wrap:wrap";
  let picked: { id: number; name: string } | null = null;
  const personLabel = document.createElement("span");
  personLabel.style.cssText = "font-size:12px;color:var(--text-soft);min-width:80px";
  const personPicker = makeSearchPicker(
    "Search person…",
    async (q) => (await api.lookupPersons(q)).map((p) => ({ id: p.PersonID, name: p.PersonName })),
    (item) => { picked = item; personLabel.textContent = `${item.name} (#${item.id})`; }
  );
  const roleListId = `asset-role-${Math.random().toString(36).slice(2)}`;
  const roleInput = document.createElement("input");
  roleInput.setAttribute("list", roleListId);
  roleInput.placeholder = "Role";
  roleInput.value = "Owner";
  roleInput.style.cssText = "flex:0 0 120px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 8px;color:var(--text);font-size:12px";
  const dl = document.createElement("datalist"); dl.id = roleListId;
  ASSET_PERSON_ROLES.forEach((r) => { const o = document.createElement("option"); o.value = r; dl.appendChild(o); });
  const addBtn = document.createElement("button");
  addBtn.type = "button"; addBtn.className = "btn btn-primary btn-sm"; addBtn.textContent = "+ Add";
  addBtn.onclick = () => {
    if (!picked) { toast("Select a person first", "err"); return; }
    model.set(picked.id, { name: picked.name, role: roleInput.value.trim() || "Owner" });
    picked = null; personLabel.textContent = ""; roleInput.value = "Owner";
    persist(); render();
  };
  addRow.appendChild(personPicker); addRow.appendChild(personLabel); addRow.appendChild(roleInput); addRow.appendChild(dl); addRow.appendChild(addBtn);
  div.appendChild(header); div.appendChild(box); div.appendChild(addRow);
  body.appendChild(div);

  if (assetId) {
    try { (await api.getAssetPersons(assetId)).forEach((p) => model.set(p.PersonID, { name: p.PersonName, role: p.relationshiptype })); } catch { /* ignore */ }
  }
  render();
}

// Questions selected/created pending during the CREATION of a QUESTIONNAIRE
// (QuestionnaireID not yet assigned); saved into QUESTIONFORQUESTIONNAIRE
// right after the insertion. The insertion order (Set) = the order of the links.
let pendingQuestionLinks: Set<number> | null = null;

// Evidence (EVIDENCE) selected/created pending during the CREATION of an
// ANSWER; saved into ANSWEREVIDENCE right after the insertion.
let pendingAnswerEvidences: Set<number> | null = null;

// ATT&CK techniques pending during the CREATION of a THREAT (THREATTTP).
let pendingThreatTtps: Set<number> | null = null;

// Tags pending during the CREATION of a VULNERABILITY (VULNERABILITYTAG).
let pendingVulnTags: Set<string> | null = null;
let pendingOvalTags: Set<string> | null = null;
let pendingCpeTags: Set<string> | null = null;
let pendingCweTags: Set<string> | null = null;
let pendingControlTags: Set<string> | null = null;

// Shows a list of pending links (label + removal button) in `box`.
function renderStagedBox(box: HTMLElement, items: Map<number, string>, emptyMsg: string): void {
  box.innerHTML = "";
  if (!items.size) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${emptyMsg}</div>`;
    return;
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed";
  const tb = document.createElement("tbody");
  items.forEach((label, id) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-all";
    td.textContent = label || `#${id}`;
    const tdRm = document.createElement("td");
    tdRm.style.cssText = "padding:2px 6px;border-bottom:1px solid var(--border-subtle);text-align:right;width:30px";
    const rm = document.createElement("button");
    rm.type = "button"; rm.textContent = "✕"; rm.title = "Retirer";
    rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    rm.onclick = () => { items.delete(id); renderStagedBox(box, items, emptyMsg); };
    tdRm.appendChild(rm);
    tr.appendChild(td); tr.appendChild(tdRm); tb.appendChild(tr);
  });
  table.appendChild(tb); box.appendChild(table);
}

// "CPEs for this Asset" section: Add CPE button (above) + table (read)
async function appendCpeTable(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";

  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "CPEs for this Asset (CPEFORASSET)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);

  const box = document.createElement("div");
  box.style.cssText =
    "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "btn btn-ghost btn-sm";
  addBtn.textContent = t("cpe.add");
  if (assetId || pendingAssetLinks) header.appendChild(addBtn);

  div.appendChild(header);
  div.appendChild(box);
  body.appendChild(div);

  if (assetId) {
    addBtn.onclick = () => openCpeModal(assetId, () => renderCpeBox(box, assetId));
    await renderCpeBox(box, assetId);
  } else if (pendingAssetLinks) {
    const m = pendingAssetLinks.cpes;
    addBtn.onclick = () => openCpeModal(0, () => renderStagedBox(box, m, t("link.pendingNone")));
    renderStagedBox(box, m, t("link.pendingNone"));
  } else {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
  }
}

// Read-only table of the CPEs affected by a vulnerability (XVULNERABILITY.VULNERABILITYFORCPE → CPE).
async function appendVulnCpeTable(body: HTMLElement, vulnId: number | null): Promise<void> {
  const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = t("vulncpe.title");
  label.style.cssText = "font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px";
  const box = document.createElement("div");
  box.style.cssText = "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  div.appendChild(label); div.appendChild(box); body.appendChild(div);
  if (!vulnId) { box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`; return; }
  let rows: { CPEID: number; CPEName: string; KnownVulnerable: boolean }[] = [];
  try { rows = await api.getVulnerabilityCpes(vulnId); }
  catch { box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${t("vulncpe.error")}</div>`; return; }
  if (!rows.length) { box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("vulncpe.none")}</div>`; return; }
  label.textContent = `${t("vulncpe.title")} (${rows.length})`;
  box.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:12px">${rows.map((r) => `<tr style="border-bottom:1px solid var(--border)">
    <td style="padding:5px 8px;font-family:ui-monospace,monospace;word-break:break-all">${esc(r.CPEName)}</td>
    <td style="padding:5px 8px;text-align:right;white-space:nowrap">${r.KnownVulnerable ? `<span style="color:var(--danger);font-weight:600">${t("vulncpe.known")}</span>` : `<span style="color:var(--text-dim)">${t("vulncpe.maybe")}</span>`}</td>
  </tr>`).join("")}</table>`;
}

// Fills (or reloads) the table of OVAL definitions linked to the asset (ASSETOVALDEFINITION)
async function renderOvalBox(box: HTMLElement, assetId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!assetId) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">—</div>`;
    return;
  }
  let rows: { AssetOVALDefinitionID: number; Pattern: string; Title: string | null; Status: string | null }[] = [];
  try {
    rows = await api.getAssetOvals(assetId);
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  if (!rows.length) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("oval.none")}</div>`;
    return;
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed";
  table.innerHTML =
    '<thead><tr>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">OVALDefinitionIDPattern</th>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">OVALDefinitionTitle</th>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border);width:110px">Status</th>' +
    '<th style="width:30px;border-bottom:1px solid var(--border)"></th></tr></thead>';
  const tb = document.createElement("tbody");
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-all;vertical-align:top";
    td1.textContent = r.Pattern || "—";
    const tdTitle = document.createElement("td");
    tdTitle.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-word;vertical-align:top";
    tdTitle.textContent = r.Title ?? "";
    const td2 = document.createElement("td");
    td2.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-muted);vertical-align:top";
    td2.textContent = r.Status ?? "";
    const tdRm = document.createElement("td");
    tdRm.style.cssText = "padding:2px 6px;border-bottom:1px solid var(--border-subtle);text-align:right;vertical-align:top";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "✕";
    rm.title = t("oval.unlink");
    rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    rm.onclick = async () => {
      try {
        await api.removeAssetOval(assetId, r.AssetOVALDefinitionID);
        await renderOvalBox(box, assetId);
      } catch (e) {
        toast(t("link.removeErr") + " " + e, "err");
      }
    };
    tdRm.appendChild(rm);
    tr.appendChild(td1);
    tr.appendChild(tdTitle);
    tr.appendChild(td2);
    tr.appendChild(tdRm);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  box.appendChild(table);
}

// "OVAL definitions for this Asset" section: Add button (server search,
// large table) + table of ASSETOVALDEFINITION links (resolved pattern).
async function appendOvalTable(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";

  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "OVAL definitions for this Asset (ASSETOVALDEFINITION)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);

  const box = document.createElement("div");
  box.style.cssText =
    "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";

  // Search+add zone (hidden until the "Add" button is clicked)
  const searchWrap = document.createElement("div");
  searchWrap.style.cssText = "display:none;position:relative;margin-bottom:6px";

  if (assetId || pendingAssetLinks) {
    const addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "btn btn-ghost btn-sm";
    addBtn.textContent = t("oval.addBtn");
    addBtn.onclick = () => {
      const open = searchWrap.style.display !== "none";
      searchWrap.style.display = open ? "none" : "";
      if (!open) (searchWrap.querySelector("input") as HTMLInputElement | null)?.focus();
    };
    header.appendChild(addBtn);

    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = t("oval.search");
    input.style.cssText =
      "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px";
    const results = document.createElement("div");
    results.style.cssText =
      "position:absolute;left:0;right:0;z-index:20;max-height:220px;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-top:2px;display:none";
    searchWrap.appendChild(input);
    searchWrap.appendChild(results);

    const hide = () => { results.style.display = "none"; };
    let timer: number | undefined;
    input.addEventListener("input", () => {
      const q = input.value.trim();
      window.clearTimeout(timer);
      if (q.length < 2) { hide(); return; }
      timer = window.setTimeout(async () => {
        let rows: { OVALDefinitionID: number; OVALDefinitionIDPattern: string; OVALDefinitionTitle: string }[] = [];
        try { rows = await api.searchOvalDefinitions(q); } catch { hide(); return; }
        results.innerHTML = "";
        if (!rows.length) {
          results.innerHTML = `<div style="padding:7px 10px;font-size:12px;color:var(--text-dim)">Aucun résultat</div>`;
        } else {
          rows.forEach((r) => {
            const item = document.createElement("div");
            item.style.cssText = "padding:7px 10px;font-size:12px;color:var(--text-soft);cursor:pointer;border-bottom:1px solid var(--surface)";
            const title = (r.OVALDefinitionTitle || "").slice(0, 60);
            item.textContent = title ? `${r.OVALDefinitionIDPattern} — ${title}` : r.OVALDefinitionIDPattern;
            item.addEventListener("mouseenter", () => (item.style.background = "var(--surface)"));
            item.addEventListener("mouseleave", () => (item.style.background = ""));
            item.addEventListener("click", async () => {
              if (!assetId && pendingAssetLinks) {
                // Creation mode: we remember the link (saved at insertion)
                pendingAssetLinks.ovals.set(r.OVALDefinitionID, r.OVALDefinitionIDPattern || `#${r.OVALDefinitionID}`);
                input.value = "";
                hide();
                renderStagedBox(box, pendingAssetLinks.ovals, t("link.pendingNone"));
                return;
              }
              try {
                await api.addAssetOval(assetId as number, r.OVALDefinitionID);
                input.value = "";
                hide();
                await renderOvalBox(box, assetId as number);
              } catch (e) {
                toast(t("link.addErr") + " " + e, "err");
              }
            });
            results.appendChild(item);
          });
        }
        results.style.display = "";
      }, 250);
    });
    input.addEventListener("blur", () => window.setTimeout(hide, 200));
  }

  div.appendChild(header);
  div.appendChild(searchWrap);
  div.appendChild(box);
  body.appendChild(div);
  if (assetId) await renderOvalBox(box, assetId);
  else if (pendingAssetLinks) renderStagedBox(box, pendingAssetLinks.ovals, t("link.pendingNone"));
  else box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
}

// Fills (or reloads) the "Audits for this Asset" table (AuditName + removal)
async function renderAuditBox(box: HTMLElement, assetId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!assetId) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">—</div>`;
    return;
  }
  let audits: { AuditID: number; AuditName: string }[] = [];
  try {
    audits = await api.getAssetAudits(assetId);
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  if (!audits.length) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucun audit lié.</div>`;
    return;
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  table.innerHTML =
    '<thead><tr>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">AuditName</th>' +
    '<th style="width:30px;border-bottom:1px solid var(--border)"></th></tr></thead>';
  const tb = document.createElement("tbody");
  audits.forEach((a) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft)";
    td.textContent = a.AuditName == null || a.AuditName === "" ? `#${a.AuditID}` : a.AuditName;
    const tdRm = document.createElement("td");
    tdRm.style.cssText = "padding:2px 6px;border-bottom:1px solid var(--border-subtle);text-align:right";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "✕";
    rm.title = t("tip.removeAudit");
    rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    rm.onclick = async () => {
      try {
        const remaining = audits.filter((x) => x.AuditID !== a.AuditID).map((x) => x.AuditID);
        await api.setAssetAudits(assetId, remaining);
        await renderAuditBox(box, assetId);
      } catch (e) {
        toast(t("link.removeErr") + " " + e, "err");
      }
    };
    tdRm.appendChild(rm);
    tr.appendChild(td);
    tr.appendChild(tdRm);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  box.appendChild(table);
}

// "Audits for this Asset" section: audit selector + Add button + table
// of ASSETAUDIT links (AuditName resolved from XCOMPLIANCE.AUDIT).
async function appendAuditTable(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";

  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "Audits for this Asset (ASSETAUDIT)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);
  div.appendChild(header);

  // Add control (datalist of AUDIT.AuditName → AuditID) — active if the asset
  // exists OR in creation (the links are staged then saved).
  if (assetId || pendingAssetLinks) {
    const addWrap = document.createElement("div");
    addWrap.style.cssText = "display:flex;gap:6px;align-items:center;margin-bottom:6px";
    const input = document.createElement("input");
    input.setAttribute("list", "asset_audit_add_dl");
    input.autocomplete = "off";
    input.placeholder = t("assetaudit.search");
    input.style.cssText =
      "flex:1;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--text);font-size:12px";
    const dl = document.createElement("datalist");
    dl.id = "asset_audit_add_dl";
    const nameToId = new Map<string, string>();
    try {
      const opts = await api.getLookup("XCOMPLIANCE", "AUDIT", "AuditID", "AuditName");
      for (const o of opts) {
        const nm = o.label == null ? "" : String(o.label);
        const id = o.id == null ? "" : String(o.id);
        if (nm && !nameToId.has(nm)) {
          nameToId.set(nm, id);
          const op = document.createElement("option");
          op.value = nm;
          dl.appendChild(op);
        }
      }
    } catch {
      /* rights/unavailable: adding is still possible if the user knows an exact AuditName */
    }
    const addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "btn btn-ghost btn-sm";
    addBtn.textContent = t("assetaudit.addBtn");
    addBtn.onclick = async () => {
      const name = input.value.trim();
      const id = nameToId.get(name);
      if (!id) {
        toast(t("assetaudit.unknown"), "err");
        return;
      }
      if (!assetId && pendingAssetLinks) {
        pendingAssetLinks.audits.set(Number(id), name);
        input.value = "";
        renderStagedBox(box, pendingAssetLinks.audits, t("link.pendingNone"));
        return;
      }
      try {
        const cur = await api.getAssetAudits(assetId as number);
        const ids = new Set(cur.map((a) => a.AuditID));
        ids.add(Number(id));
        await api.setAssetAudits(assetId as number, [...ids]);
        input.value = "";
        await renderAuditBox(box, assetId as number);
      } catch (e) {
        toast(t("link.addErr") + " " + e, "err");
      }
    };
    addWrap.appendChild(input);
    addWrap.appendChild(dl);
    addWrap.appendChild(addBtn);
    div.appendChild(addWrap);
  }

  const box = document.createElement("div");
  box.style.cssText =
    "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  div.appendChild(box);
  body.appendChild(div);

  if (assetId) await renderAuditBox(box, assetId);
  else if (pendingAssetLinks) renderStagedBox(box, pendingAssetLinks.audits, t("link.pendingNone"));
  else box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
}

// Fills (or reloads) the "Vulnerabilities for Asset" table (read-only)
async function renderVulnBox(box: HTMLElement, assetId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!assetId) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">—</div>`;
    return;
  }
  let vulns: { VulnerabilityID: number; VULGUID: string; VULDescription: string; AssetVulnerabilityID?: number; PatchStatus?: string | null; RemediationCount?: number; FalsePositive?: number }[] = [];
  try {
    vulns = await api.getAssetVulnerabilities(assetId);
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  if (!vulns.length) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("vuln.noneLinked")}</div>`;
    return;
  }
  // Existing remediation plans for this asset's vuln instances (one call, best-effort).
  let plansByAvId: Record<string, { RemediationName: string; RemediationType: string | null; Status: string | null; Priority: string | null; TargetDate: string | null; OwnerName: string | null }[]> = {};
  if (vulns.some((v) => (v.RemediationCount ?? 0) > 0)) {
    try { plansByAvId = (await api.getAssetRemediations(assetId)).plans; } catch { /* non-fatal */ }
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed";
  table.innerHTML =
    '<thead><tr>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border);width:220px">VULGUID</th>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">VULDescription</th>' +
    `<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border);width:150px">${t("rem.col")}</th>` +
    '<th style="width:30px;border-bottom:1px solid var(--border)"></th>' +
    '</tr></thead>';
  const tb = document.createElement("tbody");
  vulns.forEach((v) => {
    const isFp = Number(v.FalsePositive) === 1;
    const dim = isFp ? "opacity:.5;text-decoration:line-through" : "";
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.style.cssText = `padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-all;vertical-align:top;${dim}`;
    td1.textContent = v.VULGUID ?? `#${v.VulnerabilityID}`;
    const td2 = document.createElement("td");
    td2.style.cssText = `padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);white-space:pre-wrap;word-break:break-word;vertical-align:top;${dim}`;
    td2.textContent = v.VULDescription ?? "";
    // Remediation plan cell: a "+ plan" button (or "✓ planned (N)" when one exists) + a false-positive
    // toggle. Disabled until the asset-vulnerability junction row has a PK (always true here — DB-backed rows).
    const tdPlan = document.createElement("td");
    tdPlan.style.cssText = "padding:3px 8px;border-bottom:1px solid var(--border-subtle);vertical-align:top;white-space:nowrap";
    const avId = v.AssetVulnerabilityID;
    const planned = (v.RemediationCount ?? 0) > 0;
    const planBtn = document.createElement("button");
    planBtn.type = "button";
    planBtn.className = "btn btn-ghost btn-sm";
    planBtn.style.cssText = "padding:2px 8px;font-size:11px";
    planBtn.textContent = planned ? `✓ ${t("rem.plannedN").replace("{n}", String(v.RemediationCount))}` : t("rem.add");
    planBtn.title = t("rem.tip");
    if (avId == null) { planBtn.disabled = true; planBtn.title = t("link.saveFirst"); }
    else if (isFp) { planBtn.disabled = true; planBtn.title = t("rem.fpNoplan"); }
    else planBtn.onclick = () => openRemediationModal(avId, v.VULGUID || `#${v.VulnerabilityID}`, () => renderVulnBox(box, assetId));
    tdPlan.appendChild(planBtn);
    // False-positive toggle — flags ASSETVULNERABILITY.FalsePositive (drops out of risk + worklists).
    const fpBtn = document.createElement("button");
    fpBtn.type = "button";
    fpBtn.className = "btn btn-ghost btn-sm";
    fpBtn.style.cssText = "padding:2px 8px;font-size:11px;margin-left:6px" + (isFp ? ";color:var(--warning,#fbbf24);border-color:var(--warning,#fbbf24)" : "");
    fpBtn.textContent = isFp ? `✓ ${t("rem.fp")}` : t("rem.fp");
    fpBtn.title = isFp ? t("rem.fpTipOn") : t("rem.fpTip");
    if (avId == null) { fpBtn.disabled = true; fpBtn.title = t("link.saveFirst"); }
    else fpBtn.onclick = async () => {
      fpBtn.disabled = true;
      try { await api.setVulnFalsePositive(avId, !isFp); await renderVulnBox(box, assetId); }
      catch (e) { toast(t("rem.fpErr") + " " + e, "err"); fpBtn.disabled = false; }
    };
    tdPlan.appendChild(fpBtn);
    const tdRm = document.createElement("td");
    tdRm.style.cssText = "padding:2px 6px;border-bottom:1px solid var(--border-subtle);text-align:right;vertical-align:top";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "✕";
    rm.title = t("tip.unlinkVuln");
    rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
    rm.onclick = async () => {
      try {
        const remaining = vulns.filter((x) => x.VulnerabilityID !== v.VulnerabilityID).map((x) => x.VulnerabilityID);
        await api.setAssetVulnerabilities(assetId, remaining);
        await renderVulnBox(box, assetId);
      } catch (e) {
        toast(t("link.removeErr") + " " + e, "err");
      }
    };
    tdRm.appendChild(rm);
    tr.appendChild(td1);
    tr.appendChild(td2);
    tr.appendChild(tdPlan);
    tr.appendChild(tdRm);
    tb.appendChild(tr);

    // Inline list of existing remediation plans for this vulnerability instance.
    const plans = avId != null ? plansByAvId[String(avId)] : undefined;
    if (plans && plans.length) {
      const escP = (s: unknown): string => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
      const sub = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 4;
      cell.style.cssText = "padding:0 8px 6px 8px;border-bottom:1px solid var(--border-subtle)";
      const statusColor = (s: string | null): string => /done|complete|resolv|patched/i.test(s || "") ? "var(--success,#34d399)" : /progress/i.test(s || "") ? "#60a5fa" : /defer/i.test(s || "") ? "#fbbf24" : "var(--text-dim)";
      cell.innerHTML =
        `<div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.4px;margin:2px 0 3px">${t("rem.plansFor")}</div>` +
        plans.map((p) => `<div style="display:flex;gap:8px;align-items:baseline;font-size:11px;padding:2px 0;border-top:1px solid var(--border-subtle)">
          <span style="color:var(--text-soft);font-weight:600;min-width:0;flex:1;word-break:break-word">${escP(p.RemediationName)}</span>
          <span style="color:${statusColor(p.Status)};white-space:nowrap">${escP(p.Status || "—")}</span>
          ${p.RemediationType ? `<span style="color:var(--text-dim);white-space:nowrap">${escP(p.RemediationType)}</span>` : ""}
          ${p.Priority ? `<span style="color:var(--text-dim);white-space:nowrap">${escP(p.Priority)}</span>` : ""}
          ${p.TargetDate ? `<span style="color:var(--text-dim);white-space:nowrap">▸ ${escP(String(p.TargetDate).slice(0, 10))}</span>` : ""}
          ${p.OwnerName ? `<span style="color:var(--text-dim);white-space:nowrap">@${escP(p.OwnerName)}</span>` : ""}
        </div>`).join("");
      sub.appendChild(cell);
      tb.appendChild(sub);
    }
  });
  table.appendChild(tb);
  box.appendChild(table);
}

// Remediation-plan modal for an ASSETVULNERABILITY instance — built dynamically (no page HTML
// needed). Mirrors the /patch-management plan fields and POSTs to the same endpoint.
function openRemediationModal(assetVulnId: number, vulnLabel: string, onDone: () => void): void {
  const escHtml = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(5,7,15,.72);display:flex;align-items:center;justify-content:center;z-index:3000";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface-2,#0f1322);border:1px solid var(--border,#2d3250);border-radius:14px;padding:20px 22px;width:min(540px,94vw);max-height:90vh;overflow:auto";
  const lbl = (s: string) => `<label style="display:block;font-size:12px;color:var(--text-muted,#94a3b8);margin:10px 0 4px">${s}</label>`;
  const inputCss = "width:100%;background:var(--bg,#0f1117);border:1px solid var(--border,#2d3250);color:var(--text,#e2e8f0);border-radius:7px;padding:8px 10px;font-size:13px;box-sizing:border-box";
  const opt = (vals: string[]) => vals.map((v) => `<option value="${v}">${v}</option>`).join("");
  card.innerHTML =
    `<h3 style="margin:0 0 4px;font-size:16px;color:var(--text,#e7ebf3)">${t("rem.title")}</h3>
     <div style="font-size:12px;color:var(--text-muted,#94a3b8);margin-bottom:8px">${t("rem.for")} <b style="color:var(--text-soft,#cbd5e1);word-break:break-all">${escHtml(vulnLabel)}</b></div>
     ${lbl(t("rem.name") + " *")}<input id="rmf-name" type="text" style="${inputCss}" placeholder="${t("rem.namePh")}" autocomplete="off">
     ${lbl(t("rem.type"))}<select id="rmf-type" style="${inputCss}">${opt(["Patch", "Mitigation", "Configuration", "Workaround", "Compensating control", "Accept risk"])}</select>
     ${lbl(t("rem.status"))}<select id="rmf-status" style="${inputCss}">${opt(["Planned", "In progress", "Done", "Deferred"])}</select>
     <div style="display:flex;gap:10px">
       <div style="flex:1">${lbl(t("rem.priority"))}<select id="rmf-priority" style="${inputCss}">${opt(["", "Very Low", "Low", "Moderate", "High", "Very High", "Critical"])}</select></div>
       <div style="flex:1">${lbl(t("rem.target"))}<input id="rmf-target" type="date" style="${inputCss}"></div>
     </div>
     ${lbl(t("rem.owner"))}<select id="rmf-owner" style="${inputCss}"><option value="">${t("rem.unassigned")}</option></select>
     ${lbl(t("rem.desc"))}<textarea id="rmf-desc" rows="3" style="${inputCss};resize:vertical" placeholder="${t("rem.descPh")}"></textarea>
     <div id="rmf-err" style="color:var(--danger,#f87171);font-size:12px;min-height:16px;margin-top:8px"></div>
     <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
       <button id="rmf-cancel" type="button" class="btn btn-ghost btn-sm">${t("modal.cancel") || "Cancel"}</button>
       <button id="rmf-create" type="button" class="btn btn-primary btn-sm">${t("rem.create")}</button>
     </div>`;
  bg.appendChild(card);
  document.body.appendChild(bg);
  const g = (id: string) => card.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(`#${id}`)!;
  (g("rmf-name") as HTMLInputElement).focus();
  // Populate the owner picker from PERSON (best-effort; stays "unassigned" on failure).
  void (async () => {
    try {
      const people = await api.getLookup("XORCISM", "PERSON", "PersonID", "FullName");
      const sel = g("rmf-owner") as HTMLSelectElement;
      people.forEach((p) => { if (p.id == null) return; const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label == null || p.label === "" ? `#${p.id}` : String(p.label); sel.appendChild(o); });
    } catch { /* owner stays optional */ }
  })();
  (card.querySelector("#rmf-cancel") as HTMLButtonElement).onclick = () => bg.remove();
  (card.querySelector("#rmf-create") as HTMLButtonElement).onclick = async () => {
    const name = (g("rmf-name") as HTMLInputElement).value.trim();
    const err = card.querySelector("#rmf-err") as HTMLElement;
    if (!name) { err.textContent = t("rem.nameReq"); return; }
    const btn = card.querySelector("#rmf-create") as HTMLButtonElement;
    btn.disabled = true; err.textContent = t("rem.creating");
    try {
      const body = {
        assetVulnId, name,
        type: (g("rmf-type") as HTMLSelectElement).value,
        status: (g("rmf-status") as HTMLSelectElement).value,
        priority: (g("rmf-priority") as HTMLSelectElement).value || undefined,
        targetDate: (g("rmf-target") as HTMLInputElement).value || undefined,
        ownerPersonId: (g("rmf-owner") as HTMLSelectElement).value || undefined,
        description: (g("rmf-desc") as HTMLTextAreaElement).value.trim() || undefined,
      };
      const r = await fetch("/api/patch-management/remediation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      bg.remove();
      toast(t("rem.created") + (d.ticketId ? ` · ${t("rem.ticket")} REM-${d.ticketId}` : ""), "ok");
      onDone();
    } catch (e) { err.textContent = "⚠️ " + (e as Error).message; btn.disabled = false; }
  };
}

// Bulk remediation modal — creates ONE remediation plan for EVERY open vulnerability of an asset
// ("create a remediation plan for all the vulnerabilities"). All plans share the name → one patch
// package. Mirrors openRemediationModal's fields + a scope (only-missing vs every open instance).
function openBulkRemediationModal(assetId: number, onDone: () => void): void {
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(5,7,15,.72);display:flex;align-items:center;justify-content:center;z-index:3000";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface-2,#0f1322);border:1px solid var(--border,#2d3250);border-radius:14px;padding:20px 22px;width:min(540px,94vw);max-height:90vh;overflow:auto";
  const lbl = (s: string) => `<label style="display:block;font-size:12px;color:var(--text-muted,#94a3b8);margin:10px 0 4px">${s}</label>`;
  const inputCss = "width:100%;background:var(--bg,#0f1117);border:1px solid var(--border,#2d3250);color:var(--text,#e2e8f0);border-radius:7px;padding:8px 10px;font-size:13px;box-sizing:border-box";
  const opt = (vals: string[]) => vals.map((v) => `<option value="${v}">${v}</option>`).join("");
  card.innerHTML =
    `<h3 style="margin:0 0 4px;font-size:16px;color:var(--text,#e7ebf3)">${t("rem.allTitle")}</h3>
     <div style="font-size:12px;color:var(--text-muted,#94a3b8);margin-bottom:8px">${t("rem.allLead")}</div>
     ${lbl(t("rem.name") + " *")}<input id="rmb-name" type="text" style="${inputCss}" placeholder="${t("rem.allNamePh")}" autocomplete="off">
     ${lbl(t("rem.scope"))}<select id="rmb-scope" style="${inputCss}"><option value="missing">${t("rem.scopeMissing")}</option><option value="all">${t("rem.scopeAll")}</option></select>
     ${lbl(t("rem.type"))}<select id="rmb-type" style="${inputCss}">${opt(["Patch", "Mitigation", "Configuration", "Workaround", "Compensating control", "Accept risk"])}</select>
     ${lbl(t("rem.status"))}<select id="rmb-status" style="${inputCss}">${opt(["Planned", "In progress", "Done", "Deferred"])}</select>
     <div style="display:flex;gap:10px">
       <div style="flex:1">${lbl(t("rem.priority"))}<select id="rmb-priority" style="${inputCss}">${opt(["", "Very Low", "Low", "Moderate", "High", "Very High", "Critical"])}</select></div>
       <div style="flex:1">${lbl(t("rem.target"))}<input id="rmb-target" type="date" style="${inputCss}"></div>
     </div>
     ${lbl(t("rem.owner"))}<select id="rmb-owner" style="${inputCss}"><option value="">${t("rem.unassigned")}</option></select>
     ${lbl(t("rem.desc"))}<textarea id="rmb-desc" rows="2" style="${inputCss};resize:vertical" placeholder="${t("rem.descPh")}"></textarea>
     <div id="rmb-err" style="color:var(--danger,#f87171);font-size:12px;min-height:16px;margin-top:8px"></div>
     <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
       <button id="rmb-cancel" type="button" class="btn btn-ghost btn-sm">${t("modal.cancel") || "Cancel"}</button>
       <button id="rmb-create" type="button" class="btn btn-primary btn-sm">${t("rem.allCreate")}</button>
     </div>`;
  bg.appendChild(card);
  document.body.appendChild(bg);
  const g = (id: string) => card.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(`#${id}`)!;
  (g("rmb-name") as HTMLInputElement).focus();
  void (async () => {
    try {
      const people = await api.getLookup("XORCISM", "PERSON", "PersonID", "FullName");
      const sel = g("rmb-owner") as HTMLSelectElement;
      people.forEach((p) => { if (p.id == null) return; const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label == null || p.label === "" ? `#${p.id}` : String(p.label); sel.appendChild(o); });
    } catch { /* owner stays optional */ }
  })();
  (card.querySelector("#rmb-cancel") as HTMLButtonElement).onclick = () => bg.remove();
  (card.querySelector("#rmb-create") as HTMLButtonElement).onclick = async () => {
    const name = (g("rmb-name") as HTMLInputElement).value.trim();
    const err = card.querySelector("#rmb-err") as HTMLElement;
    if (!name) { err.textContent = t("rem.nameReq"); return; }
    const btn = card.querySelector("#rmb-create") as HTMLButtonElement;
    btn.disabled = true; err.textContent = t("rem.creating");
    try {
      const d = await api.createRemediationBulk({
        assetId, name,
        scope: (g("rmb-scope") as HTMLSelectElement).value === "all" ? "all" : "missing",
        type: (g("rmb-type") as HTMLSelectElement).value,
        status: (g("rmb-status") as HTMLSelectElement).value,
        priority: (g("rmb-priority") as HTMLSelectElement).value || undefined,
        targetDate: (g("rmb-target") as HTMLInputElement).value || undefined,
        ownerPersonId: (g("rmb-owner") as HTMLSelectElement).value || undefined,
        description: (g("rmb-desc") as HTMLTextAreaElement).value.trim() || undefined,
      });
      bg.remove();
      toast(t("rem.allDone").replace("{created}", String(d.created)).replace("{skipped}", String(d.skipped)).replace("{total}", String(d.total)), d.created ? "ok" : undefined);
      onDone();
    } catch (e) { err.textContent = "⚠️ " + (e as Error).message; btn.disabled = false; }
  };
}

// "Create backup plan" button placed right after the ASSET form's Backup plan combobox
// (ASSET.BackupPlanID). Creates a BACKUPPLAN for the current asset and points the asset at it.
function appendBackupPlanButton(prefix: string, assetId: number | null): void {
  if (assetId == null) return; // only on a saved asset
  const wrapper = document.getElementById(`${prefix}field_BackupPlanID`);
  const sel = document.getElementById(`${prefix}BackupPlanID`) as HTMLSelectElement | HTMLInputElement | null;
  if (!wrapper || !sel || wrapper.querySelector(".bp-create-btn")) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm bp-create-btn";
  btn.textContent = t("bp.add");
  btn.title = t("bp.tip");
  btn.style.cssText = "margin-top:6px;padding:3px 10px;font-size:11px";
  btn.onclick = () => openBackupPlanModal(assetId, (newId, name) => {
    // Point the asset at the new plan: add the option to the combobox and select it.
    if (sel.tagName === "SELECT") {
      const o = document.createElement("option"); o.value = String(newId); o.textContent = name; o.selected = true;
      (sel as HTMLSelectElement).appendChild(o);
    }
    (sel as HTMLInputElement).value = String(newId);
  });
  wrapper.appendChild(btn);
}

// Modal to create a BACKUPPLAN for an asset (AssetID prefilled). Reuses the generic insert API.
function openBackupPlanModal(assetId: number, onCreated: (id: number | string, name: string) => void): void {
  const escHtml = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(5,7,15,.72);display:flex;align-items:center;justify-content:center;z-index:3000";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface-2,#0f1322);border:1px solid var(--border,#2d3250);border-radius:14px;padding:20px 22px;width:min(540px,94vw);max-height:90vh;overflow:auto";
  const lbl = (s: string) => `<label style="display:block;font-size:12px;color:var(--text-muted,#94a3b8);margin:10px 0 4px">${escHtml(s)}</label>`;
  const css = "width:100%;background:var(--bg,#0f1117);border:1px solid var(--border,#2d3250);color:var(--text,#e2e8f0);border-radius:7px;padding:8px 10px;font-size:13px;box-sizing:border-box";
  const opt = (vals: string[]) => vals.map((v) => `<option value="${escHtml(v)}">${escHtml(v)}</option>`).join("");
  card.innerHTML =
    `<h3 style="margin:0 0 10px;font-size:16px;color:var(--text,#e7ebf3)">${t("bp.title")}</h3>
     ${lbl(t("bp.name") + " *")}<input id="bpf-name" type="text" style="${css}" placeholder="${t("bp.namePh")}" autocomplete="off">
     <div style="display:flex;gap:10px">
       <div style="flex:1">${lbl(t("bp.type"))}<select id="bpf-type" style="${css}">${opt(["Automated", "Manual", "Full", "Incremental", "Differential", "Snapshot", "Continuous", "Cloud", "Offsite", "Tape"])}</select></div>
       <div style="flex:1">${lbl(t("bp.status"))}<select id="bpf-status" style="${css}">${opt(["Active", "Inactive", "Planned", "Testing"])}</select></div>
     </div>
     <div style="display:flex;gap:10px">
       <div style="flex:1">${lbl(t("bp.frequency"))}<input id="bpf-freq" type="number" min="1" step="1" style="${css}" placeholder="1"></div>
       <div style="flex:1">${lbl(t("bp.frequencyUnit"))}<select id="bpf-unit" style="${css}">${opt(["Days", "Hours", "Weeks", "Months"])}</select></div>
     </div>
     <div style="display:flex;gap:10px">
       <div style="flex:1">${lbl(t("bp.rpo"))}<input id="bpf-rpo" type="number" min="0" step="1" style="${css}" placeholder="24"></div>
       <div style="flex:1">${lbl(t("bp.rto"))}<input id="bpf-rto" type="number" min="0" step="1" style="${css}" placeholder="8"></div>
     </div>
     ${lbl(t("bp.storage"))}<select id="bpf-storage" style="${css}"><option value=""></option>${opt(["On-site", "Offsite", "Cloud", "Tape", "NAS", "SAN", "Immutable", "Air-gapped"])}</select>
     ${lbl(t("bp.desc"))}<textarea id="bpf-desc" rows="2" style="${css};resize:vertical"></textarea>
     <div id="bpf-err" style="color:var(--danger,#f87171);font-size:12px;min-height:16px;margin-top:8px"></div>
     <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
       <button id="bpf-cancel" type="button" class="btn btn-ghost btn-sm">${t("modal.cancel") || "Cancel"}</button>
       <button id="bpf-create" type="button" class="btn btn-primary btn-sm">${t("bp.create")}</button>
     </div>`;
  bg.appendChild(card);
  document.body.appendChild(bg);
  const g = (id: string) => card.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(`#${id}`)!;
  (g("bpf-name") as HTMLInputElement).focus();
  (card.querySelector("#bpf-cancel") as HTMLButtonElement).onclick = () => bg.remove();
  (card.querySelector("#bpf-create") as HTMLButtonElement).onclick = async () => {
    const name = (g("bpf-name") as HTMLInputElement).value.trim();
    const err = card.querySelector("#bpf-err") as HTMLElement;
    if (!name) { err.textContent = t("bp.nameReq"); return; }
    const btn = card.querySelector("#bpf-create") as HTMLButtonElement;
    btn.disabled = true; err.textContent = t("rem.creating");
    const num = (id: string): number | undefined => { const v = (g(id) as HTMLInputElement).value.trim(); return v === "" ? undefined : Number(v); };
    const rowData: Record<string, unknown> = {
      BackupPlanName: name, AssetID: assetId,
      Type: (g("bpf-type") as HTMLSelectElement).value, Status: (g("bpf-status") as HTMLSelectElement).value,
      Frequency: num("bpf-freq"), FrequencyUnit: (g("bpf-unit") as HTMLSelectElement).value,
      RPOHours: num("bpf-rpo"), RTOHours: num("bpf-rto"),
      StorageLocation: (g("bpf-storage") as HTMLSelectElement).value || undefined,
      Description: (g("bpf-desc") as HTMLTextAreaElement).value.trim() || undefined,
    };
    for (const k of Object.keys(rowData)) if (rowData[k] === undefined) delete rowData[k];
    try {
      const r = await api.insertRow("XORCISM", "BACKUPPLAN", rowData);
      if (!r.ok || r.id == null) throw new Error("insert failed");
      bg.remove();
      toast(t("bp.created"), "ok");
      onCreated(r.id, name);
    } catch (e) { err.textContent = "⚠️ " + (e as Error).message; btn.disabled = false; }
  };
}

// "Vulnerabilities for Asset" section: Add Vulnerability button + table
async function appendVulnTable(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";

  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "Vulnerabilities for Asset (ASSETVULNERABILITY)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);

  // Deep-link to the ASSETVULNERABILITY explorer view filtered to this asset.
  if (assetId) {
    const viewLink = document.createElement("a");
    viewLink.href = `/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=AssetID&filterVal=${assetId}`;
    viewLink.textContent = t("asset.avLink");
    viewLink.title = t("asset.avLink.title");
    viewLink.style.cssText = "font-size:11px;color:var(--accent);text-decoration:none;margin-left:auto;margin-right:10px";
    header.appendChild(viewLink);
  }

  const box = document.createElement("div");
  box.style.cssText =
    "max-height:240px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";

  // "+ Plan for all" — bulk-create a remediation plan across every open vulnerability of the asset.
  const planAllBtn = document.createElement("button");
  planAllBtn.type = "button";
  planAllBtn.className = "btn btn-ghost btn-sm";
  planAllBtn.textContent = t("rem.all");
  planAllBtn.title = t("rem.allTip");
  planAllBtn.style.marginRight = "6px";
  if (assetId) header.appendChild(planAllBtn);

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "btn btn-ghost btn-sm";
  addBtn.textContent = t("vuln.add");
  if (assetId || pendingAssetLinks) header.appendChild(addBtn);

  div.appendChild(header);
  div.appendChild(box);
  body.appendChild(div);

  if (assetId) {
    addBtn.onclick = () => openVulnModal(assetId, () => renderVulnBox(box, assetId));
    planAllBtn.onclick = () => openBulkRemediationModal(assetId, () => renderVulnBox(box, assetId));
    await renderVulnBox(box, assetId);
  } else if (pendingAssetLinks) {
    const m = pendingAssetLinks.vulns;
    addBtn.onclick = () => openVulnModal(0, () => renderStagedBox(box, m, t("link.pendingNone")));
    renderStagedBox(box, m, t("link.pendingNone"));
  } else {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
  }
}

// Fills (or reloads) the "AssetGeolocation" table (ASSETGEOLOCATION, read-only)
async function renderGeoBox(box: HTMLElement, assetId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!assetId) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">—</div>`;
    return;
  }
  let rows: { AssetGeoLocationID: number; Location: string; CollectionTimestamp: string | null; CreatedDate: string | null }[] = [];
  try {
    rows = await api.getAssetGeolocations(assetId);
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  if (!rows.length) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucune géolocalisation liée.</div>`;
    return;
  }
  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed";
  table.innerHTML =
    '<thead><tr>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">Location</th>' +
    '<th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border);width:150px">Collecté le</th>' +
    '</tr></thead>';
  const tb = document.createElement("tbody");
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft);word-break:break-word;vertical-align:top";
    td1.textContent = r.Location || "—";
    const td2 = document.createElement("td");
    td2.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-muted);vertical-align:top";
    td2.textContent = r.CollectionTimestamp || r.CreatedDate || "";
    tr.appendChild(td1);
    tr.appendChild(td2);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  box.appendChild(table);
}

// "AssetGeolocation" section: table of ASSETGEOLOCATION links (read-only),
// address/coordinates resolved from GEOLOCATION (linked by AssetID).
async function appendGeoTable(body: HTMLElement, assetId: number | null): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "AssetGeolocation (ASSETGEOLOCATION)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);
  const box = document.createElement("div");
  box.style.cssText =
    "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  div.appendChild(header);
  div.appendChild(box);
  body.appendChild(div);
  if (assetId) await renderGeoBox(box, assetId);
  else box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
}

// "OVAL definition XML" section (OVALDEFINITION editing): displays, read-
// only, the XML of the matching OVAL file imported into the CIS OVALRepo repository.
async function appendOvalDefinitionXml(body: HTMLElement, pattern: string): Promise<void> {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = "OVAL definition XML (stored in OVALDEFINITION.BLOB)";
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "btn btn-ghost btn-sm";
  copy.textContent = "📋 Copier";
  header.appendChild(copy);
  // Open this definition in the advanced OVAL editor (criteria-tree builder reusing imported tests).
  const edit = document.createElement("a");
  edit.className = "btn btn-ghost btn-sm";
  edit.textContent = "✎ OVAL editor";
  edit.title = t("tip.ovalEditor");
  edit.href = pattern ? `/oval-editor?id=${encodeURIComponent(pattern)}` : "/oval-editor";
  edit.target = "_blank"; edit.rel = "noopener"; edit.style.textDecoration = "none";
  header.appendChild(edit);

  const ta = document.createElement("textarea");
  ta.readOnly = true;
  ta.wrap = "off"; // horizontal scroll: keeps the XML indentation
  ta.spellcheck = false;
  ta.style.cssText =
    "width:100%;box-sizing:border-box;height:380px;background:#0b0d14;border:1px solid var(--border);" +
    "border-radius:6px;padding:8px 10px;color:var(--text-soft);font-family:ui-monospace,Consolas,monospace;font-size:11px;overflow:auto";
  copy.onclick = () => {
    void navigator.clipboard?.writeText(ta.value);
    toast(t("toast.xmlCopied"), "ok");
  };

  div.appendChild(header);
  div.appendChild(ta);
  body.appendChild(div);

  if (!pattern) { ta.value = "—"; return; }
  ta.value = "…";
  try {
    const r = await fetch(`/api/oval-xml?id=${encodeURIComponent(pattern)}`);
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      ta.value = (d.error as string) || `Introuvable (HTTP ${r.status})`;
      return;
    }
    ta.value = await r.text();
  } catch (e) {
    ta.value = (e as Error).message;
  }
}

// ── Excel import (top of the QUESTIONNAIRE form): creates a NEW questionnaire
// and its questions from a .xlsx/.csv file, with column → field mapping. ────
// The target fields are those of a question (QUESTION) + the order (QUESTIONFORQUESTIONNAIRE).
interface QImportField { key: string; label: string; required?: boolean; guess: string[] }
const QUESTIONNAIRE_IMPORT_FIELDS: QImportField[] = [
  { key: "QuestionName", label: "Question name (QUESTION.QuestionName)", required: true, guess: ["question", "name", "intitul", "libell", "titre", "title", "control", "exigence", "requirement"] },
  { key: "QuestionText", label: "Question text (QUESTION.QuestionText)", guess: ["text", "texte", "wording", "énoncé", "enonce", "statement", "détail", "detail"] },
  { key: "QuestionDescription", label: "Description (QUESTION.QuestionDescription)", guess: ["description", "desc", "comment", "note", "guidance", "remarque", "help"] },
  { key: "QuestionType", label: "Type (QUESTION.QuestionType)", guess: ["type", "kind", "format", "category", "catégor"] },
  { key: "DefaultAnswer", label: "Default answer (QUESTION.DefaultAnswer)", guess: ["default", "answer", "réponse", "reponse", "valeur", "value"] },
  { key: "DisplayOrder", label: "Order (QUESTIONFORQUESTIONNAIRE.DisplayOrder)", guess: ["order", "ordre", "rank", "position", "n°", "num", "ref"] },
];

// "📥 Excel import" button placed at the TOP of the QUESTIONNAIRE form.
function appendQuestionnaireImportButton(body: HTMLElement): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-primary btn-sm";
  btn.textContent = "📥 Excel import";
  btn.title = t("tip.qImport");
  btn.onclick = () => openQuestionnaireExcelImport();
  const hint = document.createElement("span");
  hint.style.cssText = "font-size:11px;color:var(--text-dim)";
  hint.textContent = "Crée un nouveau questionnaire à partir d'un fichier (.xlsx/.csv).";
  div.appendChild(btn); div.appendChild(hint);
  body.insertBefore(div, body.firstChild); // always at the top, whatever the call order
}

// PDF threat-report ingestion panel placed at the TOP of the THREATREPORT form.
// Uploads the PDF → parsed server-side (pdf-parse): threat actors are added to
// THREATACTOR and IOCs to IOC; the file name / source are written into the form.
function appendThreatReportImportButton(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap";
  const label = document.createElement("div");
  label.textContent = "📄 Import threat report (PDF)";
  label.style.cssText = "flex:0 0 100%;font-size:12px;color:var(--text-muted)";
  const file = document.createElement("input");
  file.type = "file"; file.accept = "application/pdf,.pdf";
  file.style.cssText = "flex:1;min-width:200px;font-size:12px;color:var(--text)";
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-primary btn-sm"; btn.textContent = "Upload & parse";
  btn.title = "Extracts threat actors → THREATACTOR and IOCs → IOC";
  const status = document.createElement("span");
  status.style.cssText = "flex:0 0 100%;font-size:11px;color:var(--text-dim)";
  status.textContent = "Select a PDF: threat actors & IOCs are auto-extracted; the file name is stored on the report.";
  btn.onclick = async () => {
    const f = file.files?.[0];
    if (!f) { toast("Select a PDF first."); return; }
    btn.disabled = true; status.textContent = "Parsing…";
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const r = new FileReader(); r.onload = () => resolve(String(r.result)); r.onerror = () => reject(r.error); r.readAsDataURL(f);
      });
      const resp = await fetch("/api/threatreport/parse", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: f.name, dataBase64: dataUrl }),
      });
      const data = await resp.json().catch(() => ({})) as {
        error?: string; fileName?: string; source?: string;
        newActors?: number; newIocs?: number; actorsFound?: number; iocsFound?: number;
      };
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      const fn = document.getElementById(`${prefix}ThreatReportFileName`) as HTMLInputElement | null;
      if (fn) fn.value = data.fileName ?? f.name;
      const src = document.getElementById(`${prefix}ThreatReportSource`) as HTMLInputElement | null;
      if (src && !src.value.trim() && data.source) src.value = data.source;
      status.textContent = `Parsed “${data.fileName}”: +${data.newActors} actors (of ${data.actorsFound}), +${data.newIocs} IOCs (of ${data.iocsFound}).`;
      toast(`Threat report parsed: +${data.newActors} actors, +${data.newIocs} IOCs added.`);
    } catch (e) {
      status.textContent = "Failed: " + String(e); toast("Parse failed: " + String(e));
    } finally { btn.disabled = false; }
  };
  div.appendChild(label); div.appendChild(file); div.appendChild(btn); div.appendChild(status);
  body.insertBefore(div, body.firstChild);
}

// Sigma → SPL/KQL/EQL conversion panel at the TOP of the SIGMARULE form. Paste the
// Sigma YAML; "Convert" fills SigmaYaml + SplQuery/KqlQuery/EqlQuery (+ metadata).
function appendSigmaConvertButton(body: HTMLElement, prefix: string): void {
  const getEl = (col: string) =>
    document.getElementById(`${prefix}${col}`) as HTMLInputElement | HTMLTextAreaElement | null;
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:12px";
  const label = document.createElement("div");
  label.textContent = "🛡️ Sigma rule → SPL / KQL / EQL";
  label.style.cssText = "font-size:12px;color:var(--text-muted);margin-bottom:6px";
  const taCss = "width:100%;font-family:monospace;font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:6px";
  const yamlTa = document.createElement("textarea");
  yamlTa.rows = 7; yamlTa.placeholder = "Paste a Sigma rule (YAML)…"; yamlTa.style.cssText = taCss;
  yamlTa.value = getEl("SigmaYaml")?.value || "";
  yamlTa.oninput = () => { const f = getEl("SigmaYaml"); if (f) f.value = yamlTa.value; };
  const btn = document.createElement("button");
  btn.type = "button"; btn.className = "btn btn-primary btn-sm"; btn.textContent = "Convert → SPL / KQL / EQL";
  btn.style.marginTop = "8px";
  const status = document.createElement("span");
  status.style.cssText = "font-size:11px;color:var(--text-dim);margin-left:10px";
  const out = document.createElement("div");
  out.style.cssText = "margin-top:8px;display:none;flex-direction:column;gap:6px";
  const mkBox = (title: string): HTMLTextAreaElement => {
    const h = document.createElement("div"); h.textContent = title; h.style.cssText = "font-size:11px;color:var(--text-muted)";
    const ta = document.createElement("textarea"); ta.readOnly = true; ta.rows = 3; ta.style.cssText = taCss;
    out.appendChild(h); out.appendChild(ta); return ta;
  };
  const splTa = mkBox("SPL (Splunk)"), kqlTa = mkBox("KQL (Sentinel)"), eqlTa = mkBox("EQL (Elastic)");
  btn.onclick = async () => {
    const yaml = yamlTa.value.trim();
    if (!yaml) { toast("Paste a Sigma rule first."); return; }
    const f = getEl("SigmaYaml"); if (f) f.value = yaml;
    btn.disabled = true; status.textContent = "Converting…";
    try {
      const resp = await fetch("/api/sigma/convert", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ yaml }),
      });
      const d = await resp.json().catch(() => ({})) as {
        error?: string; title?: string; level?: string; status?: string; logsource?: string;
        attackTags?: string[]; spl?: string; kql?: string; eql?: string;
      };
      if (!resp.ok) throw new Error(d.error || `HTTP ${resp.status}`);
      splTa.value = d.spl || ""; kqlTa.value = d.kql || ""; eqlTa.value = d.eql || "";
      out.style.display = "flex";
      const set = (col: string, val?: string) => { const el = getEl(col); if (el) el.value = val || ""; };
      set("SplQuery", d.spl); set("KqlQuery", d.kql); set("EqlQuery", d.eql);
      const setIfEmpty = (col: string, val?: string) => { const el = getEl(col); if (el && !el.value.trim() && val) el.value = val; };
      setIfEmpty("SigmaRuleName", d.title); setIfEmpty("Level", d.level); setIfEmpty("Status", d.status);
      setIfEmpty("LogSource", d.logsource); setIfEmpty("AttackTags", (d.attackTags || []).join(", "));
      status.textContent = `Converted${d.title ? ` “${d.title}”` : ""} — fields filled.`;
      toast("Sigma converted → SPL / KQL / EQL.");
    } catch (e) {
      status.textContent = "Failed: " + String(e); toast("Sigma convert failed: " + String(e));
    } finally { btn.disabled = false; }
  };
  const row = document.createElement("div"); row.appendChild(btn); row.appendChild(status);
  div.appendChild(label); div.appendChild(yamlTa); div.appendChild(row); div.appendChild(out);
  body.insertBefore(div, body.firstChild);
}

// Import modal window: upload → column detection → mapping → import.
function openQuestionnaireExcelImport(): void {
  const inputCss = "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;color:var(--text);font-size:13px";
  const overlay = document.createElement("div");
  overlay.style.cssText = "position:fixed;inset:0;z-index:11000;background:rgba(0,0,0,.55);display:flex;align-items:flex-start;justify-content:center;overflow:auto;padding:40px 16px";
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface);border:1px solid var(--border);border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.5);width:min(680px,100%);padding:20px;display:flex;flex-direction:column;gap:14px";
  overlay.appendChild(card);
  const close = (): void => overlay.remove();
  overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) close(); });

  const title = document.createElement("div");
  title.style.cssText = "font-size:16px;font-weight:600;color:var(--text);display:flex;justify-content:space-between;align-items:center";
  const titleText = document.createElement("span"); titleText.textContent = "📥 Excel import — Questionnaire";
  const x = document.createElement("button");
  x.type = "button"; x.textContent = "✕"; x.title = "Fermer";
  x.style.cssText = "background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer";
  x.onclick = close;
  title.appendChild(titleText); title.appendChild(x); card.appendChild(title);

  const mkRow = (labelText: string): { row: HTMLElement; lbl: HTMLElement } => {
    const row = document.createElement("div"); row.style.cssText = "display:flex;flex-direction:column;gap:5px";
    const lbl = document.createElement("label"); lbl.textContent = labelText; lbl.style.cssText = "font-size:12px;color:var(--text-muted)";
    row.appendChild(lbl); return { row, lbl };
  };

  const { row: fileRow } = mkRow("Fichier Excel / CSV");
  const fileInput = document.createElement("input");
  fileInput.type = "file"; fileInput.accept = ".xlsx,.xls,.csv"; fileInput.style.cssText = inputCss;
  fileRow.appendChild(fileInput); card.appendChild(fileRow);

  const { row: nameRow } = mkRow("Nom du questionnaire (QuestionnaireName)");
  const nameInput = document.createElement("input");
  nameInput.type = "text"; nameInput.placeholder = "= nom du fichier par défaut"; nameInput.style.cssText = inputCss;
  nameRow.appendChild(nameInput); card.appendChild(nameRow);

  const status = document.createElement("div");
  status.style.cssText = "font-size:12px;color:var(--text-dim)";
  status.textContent = "Choisissez un fichier pour détecter les colonnes.";
  card.appendChild(status);

  const mapWrap = document.createElement("div");
  mapWrap.style.cssText = "display:none;flex-direction:column;gap:8px;border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--bg)";
  const mapTitle = document.createElement("div");
  mapTitle.textContent = "Mapping : colonnes Excel → champs"; mapTitle.style.cssText = "font-size:12px;font-weight:600;color:var(--text-muted)";
  mapWrap.appendChild(mapTitle); card.appendChild(mapWrap);

  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;justify-content:flex-end;gap:8px;margin-top:4px";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button"; cancelBtn.className = "btn btn-ghost btn-sm"; cancelBtn.textContent = "Annuler"; cancelBtn.onclick = close;
  const importBtn = document.createElement("button");
  importBtn.type = "button"; importBtn.className = "btn btn-primary btn-sm"; importBtn.textContent = "Importer"; importBtn.disabled = true;
  actions.appendChild(cancelBtn); actions.appendChild(importBtn); card.appendChild(actions);

  document.body.appendChild(overlay);

  let headers: string[] = [];
  let dataRows: unknown[][] = [];
  const selects: Record<string, HTMLSelectElement> = {};

  const buildMapping = (): void => {
    mapWrap.querySelectorAll(".imp-row").forEach((e) => e.remove());
    const used = new Set<number>();
    for (const f of QUESTIONNAIRE_IMPORT_FIELDS) {
      const row = document.createElement("div");
      row.className = "imp-row"; row.style.cssText = "display:flex;gap:8px;align-items:center";
      const lbl = document.createElement("label");
      lbl.textContent = f.label + (f.required ? " *" : ""); lbl.style.cssText = "flex:1;font-size:12px;color:var(--text-soft)";
      const sel = document.createElement("select"); sel.style.cssText = inputCss + ";flex:1";
      const none = document.createElement("option"); none.value = "-1"; none.textContent = "(ignorer)"; sel.appendChild(none);
      headers.forEach((h, i) => { const o = document.createElement("option"); o.value = String(i); o.textContent = h || `Colonne ${i + 1}`; sel.appendChild(o); });
      let guessIdx = -1;
      for (let i = 0; i < headers.length; i++) {
        const hl = (headers[i] || "").toLowerCase();
        if (!used.has(i) && f.guess.some((g) => hl.includes(g))) { guessIdx = i; break; }
      }
      if (guessIdx >= 0) { sel.value = String(guessIdx); used.add(guessIdx); }
      selects[f.key] = sel;
      row.appendChild(lbl); row.appendChild(sel); mapWrap.appendChild(row);
    }
  };

  fileInput.onchange = async (): Promise<void> => {
    const file = fileInput.files?.[0];
    if (!file) return;
    status.textContent = "Lecture du fichier…"; importBtn.disabled = true;
    try {
      const buf = await file.arrayBuffer();
      const XLSX = (window as unknown as { XLSX?: typeof import("xlsx") }).XLSX;
      if (!XLSX) { status.textContent = "Bibliothèque Excel (XLSX) indisponible."; return; }
      const wb = XLSX.read(new Uint8Array(buf), { type: "array" });
      const ws = wb.Sheets[wb.SheetNames[0]];
      const aoa = XLSX.utils.sheet_to_json(ws, { header: 1, blankrows: false, defval: "" }) as unknown[][];
      if (!aoa.length) { status.textContent = "Fichier vide."; return; }
      headers = (aoa[0] as unknown[]).map((h) => String(h ?? "").trim());
      dataRows = aoa.slice(1).filter((r) => Array.isArray(r) && r.some((c) => String(c ?? "").trim() !== ""));
      if (!nameInput.value.trim()) nameInput.value = file.name.replace(/\.[^.]+$/, "");
      buildMapping();
      mapWrap.style.display = "flex";
      status.textContent = `${headers.length} colonnes, ${dataRows.length} questions détectées.`;
      importBtn.disabled = dataRows.length === 0;
    } catch (e) {
      status.textContent = "Erreur de lecture : " + (e as Error).message;
    }
  };

  importBtn.onclick = async (): Promise<void> => {
    if (Number(selects.QuestionName?.value ?? -1) < 0) { toast(t("toast.mapQuestionName"), "err"); return; }
    const questions = dataRows.map((row) => {
      const o: Record<string, unknown> = {};
      for (const f of QUESTIONNAIRE_IMPORT_FIELDS) {
        const ci = Number(selects[f.key]?.value ?? -1);
        if (ci >= 0) o[f.key] = row[ci];
      }
      return o;
    }).filter((o) => String(o.QuestionName ?? "").trim() || String(o.QuestionText ?? "").trim());
    if (!questions.length) { toast(t("toast.noQuestionsImport"), "err"); return; }
    const file = fileInput.files?.[0];
    importBtn.disabled = true; importBtn.textContent = "Import…";
    try {
      const r = await api.importQuestionnaireExcel(nameInput.value.trim() || (file?.name ?? "Questionnaire"), file?.name ?? "", questions);
      toast(`${t("toast.questionnaireImported")} ${r.questions}`, "ok");
      close();
      ($("insert-modal") as HTMLElement).style.display = "none";
      ($("edit-modal") as HTMLElement).style.display = "none";
      clearNameHintCache();
      if (currentDb === "XCOMPLIANCE" && currentTable === "QUESTIONNAIRE") loadRows();
    } catch (e) {
      toast(t("toast.errImport") + " " + e, "err");
      importBtn.disabled = false; importBtn.textContent = "Importer";
    }
  };
}

// "Questionnaire questions" section: creates a QUESTION + checks
// questions to link (QUESTIONFORQUESTIONNAIRE). In CREATION (no
// QuestionnaireID yet), the selection is staged then saved after
// the questionnaire insertion (see pendingQuestionLinks / submitInsert).
// EXCEL button (bottom of the QUESTIONNAIRE form): exports the questionnaire (questions
// + linked ANSWER answers) to .xlsx named "QuestionnaireName_YYYY-MM-DD.xlsx".
function appendQuestionnaireExcelButton(body: HTMLElement, questionnaireId: number | null, name: string): void {
  if (!questionnaireId) return; // requires a saved questionnaire
  const div = document.createElement("div");
  div.style.cssText = "margin-top:16px;border-top:1px solid var(--border);padding-top:12px";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-primary btn-sm";
  btn.textContent = "📊 EXCEL";
  btn.title = t("tip.qExport");
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      const data = await api.getQuestionnaireExport(questionnaireId);
      const XLSX = (window as unknown as { XLSX: typeof import("xlsx") }).XLSX;
      const headers = ["QuestionID", "QuestionName", "QuestionText", "QuestionType", "QuestionDescription", "AnswerID", "Answer", "Result"];
      const cells = data.rows.map((r) => headers.map((h) => r[h] ?? ""));
      const ws = XLSX.utils.aoa_to_sheet([headers, ...cells]);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, "Questionnaire");
      const safe = (data.name || name || "questionnaire").replace(/[\\/:*?"<>|]/g, "_").trim() || "questionnaire";
      const dateNow = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      XLSX.writeFile(wb, `${safe}_${dateNow}.xlsx`);
    } catch (e) {
      toast(t("toast.errExportExcel") + " " + e, "err");
    } finally {
      btn.disabled = false;
    }
  };
  div.appendChild(btn);
  body.appendChild(div);
}

async function appendQuestionnaireQuestions(body: HTMLElement, questionnaireId: number | null): Promise<void> {
  const staging = !questionnaireId && pendingQuestionLinks != null;
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = "Questions du questionnaire (QUESTIONFORQUESTIONNAIRE)";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);

  const box = document.createElement("div");
  box.style.cssText = "max-height:260px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:6px 8px";

  if (!questionnaireId && !staging) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
    div.appendChild(box);
    body.appendChild(div);
    return;
  }

  const inputCss = "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:12px";

  // "New question": creates a QUESTION (QuestionName)
  const newRow = document.createElement("div");
  newRow.style.cssText = "display:flex;gap:6px;margin-bottom:6px";
  const newInput = document.createElement("input");
  newInput.placeholder = "New question (QuestionName)…";
  newInput.autocomplete = "off";
  newInput.style.cssText = inputCss + ";flex:1";
  const createBtn = document.createElement("button");
  createBtn.type = "button"; createBtn.className = "btn btn-ghost btn-sm";
  createBtn.textContent = "+ Créer la question";
  newRow.appendChild(newInput); newRow.appendChild(createBtn);
  div.appendChild(newRow);

  // Search in the questions table
  const search = document.createElement("input");
  search.type = "search"; search.placeholder = "Filtrer les questions…";
  search.style.cssText = inputCss + ";width:100%;box-sizing:border-box;margin-bottom:6px";
  div.appendChild(search);

  div.appendChild(box);

  // Editing: link save button. Creation: hint (links
  // saved automatically at creation).
  if (staging) {
    const hint = document.createElement("div");
    hint.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:6px";
    hint.textContent = "Les questions cochées seront liées à la création du questionnaire.";
    div.appendChild(hint);
  }
  const saveBtn = document.createElement("button");
  saveBtn.type = "button"; saveBtn.className = "btn btn-primary btn-sm";
  saveBtn.textContent = "Enregistrer les liens";
  saveBtn.style.marginTop = "6px";
  if (!staging) div.appendChild(saveBtn);
  body.appendChild(div);

  const addRow = (id: number, name: string, checked: boolean, prepend = false): void => {
    if (box.querySelector(`input[type=checkbox][value="${id}"]`)) return;
    const row = document.createElement("label");
    row.className = "qfq-opt";
    row.dataset.search = name.toLowerCase();
    row.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = String(id); cb.checked = checked;
    // Creation: the checkbox updates the pending buffer directly.
    if (staging) cb.addEventListener("change", () => {
      if (cb.checked) pendingQuestionLinks!.add(id); else pendingQuestionLinks!.delete(id);
    });
    const span = document.createElement("span");
    span.textContent = name; span.style.wordBreak = "break-word";
    row.appendChild(cb); row.appendChild(span);
    if (prepend) box.insertBefore(row, box.firstChild); else box.appendChild(row);
  };

  box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">…</div>`;
  let all: { id: unknown; label: unknown }[] = [];
  let linkedSet: Set<number>;
  try {
    if (staging) {
      all = await api.getLookup("XCOMPLIANCE", "QUESTION", "QuestionID", "QuestionName");
      linkedSet = new Set(pendingQuestionLinks!);
    } else {
      const [a, linked] = await Promise.all([
        api.getLookup("XCOMPLIANCE", "QUESTION", "QuestionID", "QuestionName"),
        api.getQuestionnaireQuestions(questionnaireId!),
      ]);
      all = a; linkedSet = new Set(linked.map(Number));
    }
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  box.innerHTML = "";
  // Linked/checked questions at the top, then the rest.
  const sorted = all.slice().sort((a, b) =>
    (linkedSet.has(Number(a.id)) ? 0 : 1) - (linkedSet.has(Number(b.id)) ? 0 : 1)
  );
  for (const q of sorted) {
    const name = q.label == null || q.label === "" ? `#${q.id}` : String(q.label);
    addRow(Number(q.id), name, linkedSet.has(Number(q.id)));
  }
  if (!box.children.length) box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucune question.</div>`;

  search.oninput = () => {
    const qy = search.value.trim().toLowerCase();
    box.querySelectorAll<HTMLElement>(".qfq-opt").forEach((el) => {
      el.style.display = !qy || (el.dataset.search ?? "").includes(qy) ? "" : "none";
    });
  };

  const doCreate = async (): Promise<void> => {
    const name = newInput.value.trim();
    if (!name) { newInput.focus(); return; }
    createBtn.disabled = true;
    try {
      const r = await api.createQuestion(name);
      if (!box.querySelector(".qfq-opt")) box.innerHTML = ""; // removes the "Aucune question." placeholder
      if (staging) pendingQuestionLinks!.add(r.id);
      const existing = box.querySelector<HTMLInputElement>(`input[type=checkbox][value="${r.id}"]`);
      if (existing) { existing.checked = true; (existing.closest(".qfq-opt") as HTMLElement | null)?.scrollIntoView({ block: "nearest" }); }
      else addRow(r.id, name, true, true);
      newInput.value = "";
      toast(r.created ? (staging ? t("toast.questionCreatedStaged") : t("toast.questionCreatedLink")) : t("toast.questionExists"), "ok");
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
    finally { createBtn.disabled = false; }
  };
  createBtn.onclick = () => void doCreate();
  newInput.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") { e.preventDefault(); void doCreate(); } });

  saveBtn.onclick = async () => {
    const ids = Array.from(box.querySelectorAll<HTMLInputElement>('input[type=checkbox]:checked')).map((c) => Number(c.value));
    saveBtn.disabled = true;
    try {
      await api.setQuestionnaireQuestions(questionnaireId!, ids);
      toast(`${t("toast.linksSaved")} (${ids.length})`, "ok");
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
    finally { saveBtn.disabled = false; }
  };
}

// "Linked evidence" section: creates an EVIDENCE + checks evidence to link to the
// answer (ANSWEREVIDENCE). In CREATION (no AnswerID yet), the selection is
// staged then saved after the insertion (pendingAnswerEvidences).
async function appendAnswerEvidences(body: HTMLElement, answerId: number | null): Promise<void> {
  const staging = !answerId && pendingAnswerEvidences != null;
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = "Preuves liées (ANSWEREVIDENCE)";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);

  const box = document.createElement("div");
  box.style.cssText = "max-height:240px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:6px 8px";

  if (!answerId && !staging) {
    box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
    div.appendChild(box); body.appendChild(div); return;
  }

  const inputCss = "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:12px";

  // "New evidence": creates an EVIDENCE (EvidenceName)
  const newRow = document.createElement("div");
  newRow.style.cssText = "display:flex;gap:6px;margin-bottom:6px";
  const newInput = document.createElement("input");
  newInput.placeholder = "New evidence (EvidenceName)…";
  newInput.autocomplete = "off";
  newInput.style.cssText = inputCss + ";flex:1";
  const createBtn = document.createElement("button");
  createBtn.type = "button"; createBtn.className = "btn btn-ghost btn-sm";
  createBtn.textContent = "+ Créer la preuve";
  newRow.appendChild(newInput); newRow.appendChild(createBtn);
  div.appendChild(newRow);

  const search = document.createElement("input");
  search.type = "search"; search.placeholder = "Filtrer les preuves…";
  search.style.cssText = inputCss + ";width:100%;box-sizing:border-box;margin-bottom:6px";
  div.appendChild(search);
  div.appendChild(box);

  if (staging) {
    const hint = document.createElement("div");
    hint.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:6px";
    hint.textContent = "Les preuves cochées seront liées à la création de la réponse.";
    div.appendChild(hint);
  }
  const saveBtn = document.createElement("button");
  saveBtn.type = "button"; saveBtn.className = "btn btn-primary btn-sm";
  saveBtn.textContent = "Enregistrer les preuves";
  saveBtn.style.marginTop = "6px";
  if (!staging) div.appendChild(saveBtn);
  body.appendChild(div);

  const addRow = (id: number, name: string, checked: boolean, prepend = false): void => {
    if (box.querySelector(`input[type=checkbox][value="${id}"]`)) return;
    const row = document.createElement("label");
    row.className = "ae-opt";
    row.dataset.search = name.toLowerCase();
    row.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = String(id); cb.checked = checked;
    if (staging) cb.addEventListener("change", () => {
      if (cb.checked) pendingAnswerEvidences!.add(id); else pendingAnswerEvidences!.delete(id);
    });
    const span = document.createElement("span");
    span.textContent = name; span.style.wordBreak = "break-word";
    row.appendChild(cb); row.appendChild(span);
    if (prepend) box.insertBefore(row, box.firstChild); else box.appendChild(row);
  };

  box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">…</div>`;
  let all: { id: unknown; label: unknown }[] = [];
  let linkedSet: Set<number>;
  try {
    if (staging) {
      all = await api.getLookup("XCOMPLIANCE", "EVIDENCE", "EvidenceID", "EvidenceName");
      linkedSet = new Set(pendingAnswerEvidences!);
    } else {
      const [a, linked] = await Promise.all([
        api.getLookup("XCOMPLIANCE", "EVIDENCE", "EvidenceID", "EvidenceName"),
        api.getAnswerEvidences(answerId!),
      ]);
      all = a; linkedSet = new Set(linked.map(Number));
    }
  } catch (e) {
    box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  box.innerHTML = "";
  const sorted = all.slice().sort((a, b) =>
    (linkedSet.has(Number(a.id)) ? 0 : 1) - (linkedSet.has(Number(b.id)) ? 0 : 1)
  );
  for (const ev of sorted) {
    const name = ev.label == null || ev.label === "" ? `#${ev.id}` : String(ev.label);
    addRow(Number(ev.id), name, linkedSet.has(Number(ev.id)));
  }
  if (!box.children.length) box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucune preuve.</div>`;

  search.oninput = () => {
    const qy = search.value.trim().toLowerCase();
    box.querySelectorAll<HTMLElement>(".ae-opt").forEach((el) => {
      el.style.display = !qy || (el.dataset.search ?? "").includes(qy) ? "" : "none";
    });
  };

  const doCreate = async (): Promise<void> => {
    const name = newInput.value.trim();
    if (!name) { newInput.focus(); return; }
    createBtn.disabled = true;
    try {
      const r = await api.createEvidence(name);
      if (!box.querySelector(".ae-opt")) box.innerHTML = "";
      if (staging) pendingAnswerEvidences!.add(r.id);
      const existing = box.querySelector<HTMLInputElement>(`input[type=checkbox][value="${r.id}"]`);
      if (existing) { existing.checked = true; (existing.closest(".ae-opt") as HTMLElement | null)?.scrollIntoView({ block: "nearest" }); }
      else addRow(r.id, name, true, true);
      newInput.value = "";
      toast(r.created ? (staging ? t("toast.evidenceCreatedStaged") : t("toast.evidenceCreatedLink")) : t("toast.evidenceExists"), "ok");
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
    finally { createBtn.disabled = false; }
  };
  createBtn.onclick = () => void doCreate();
  newInput.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") { e.preventDefault(); void doCreate(); } });

  saveBtn.onclick = async () => {
    const ids = Array.from(box.querySelectorAll<HTMLInputElement>('input[type=checkbox]:checked')).map((c) => Number(c.value));
    saveBtn.disabled = true;
    try {
      await api.setAnswerEvidences(answerId!, ids);
      toast(`${t("toast.evidenceSaved")} (${ids.length})`, "ok");
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
    finally { saveBtn.disabled = false; }
  };
}

// "MITRE ATT&CK techniques" section (THREAT form): search + list of
// linked ATT&CK techniques (THREATTTP). In CREATION, staged then
// saved after the THREAT insertion.
async function appendThreatTtps(body: HTMLElement, threatId: number | null): Promise<void> {
  const staging = !threatId && pendingThreatTtps != null;
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const label = document.createElement("label");
  label.textContent = "Techniques MITRE ATT&CK (THREATTTP)";
  label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";
  div.appendChild(label);

  const linkedBox = document.createElement("div");
  linkedBox.style.cssText = "max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg);padding:6px 8px";

  if (!threatId && !staging) {
    linkedBox.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("link.saveFirst")}</div>`;
    div.appendChild(linkedBox); body.appendChild(div); return;
  }

  const inputCss = "background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:12px";
  const sel = new Map<number, { aid: string; name: string; domain: string }>();

  // ATT&CK search (server, live)
  const searchWrap = document.createElement("div");
  searchWrap.style.cssText = "position:relative;margin-bottom:6px";
  const search = document.createElement("input");
  search.type = "search"; search.placeholder = "Rechercher une technique (ID Txxxx ou nom)…";
  search.autocomplete = "off";
  search.style.cssText = inputCss + ";width:100%;box-sizing:border-box";
  const results = document.createElement("div");
  results.style.cssText = "position:absolute;left:0;right:0;z-index:30;max-height:240px;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-top:2px;display:none";
  searchWrap.appendChild(search); searchWrap.appendChild(results);
  div.appendChild(searchWrap);
  div.appendChild(linkedBox);

  if (staging) {
    const hint = document.createElement("div");
    hint.style.cssText = "font-size:11px;color:var(--text-dim);margin-top:6px";
    hint.textContent = "Les techniques ajoutées seront liées à la création du THREAT.";
    div.appendChild(hint);
  }
  const saveBtn = document.createElement("button");
  saveBtn.type = "button"; saveBtn.className = "btn btn-primary btn-sm";
  saveBtn.textContent = "Enregistrer les techniques";
  saveBtn.style.marginTop = "6px";
  if (!staging) div.appendChild(saveBtn);
  body.appendChild(div);

  const renderLinked = (): void => {
    linkedBox.innerHTML = "";
    if (!sel.size) { linkedBox.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">Aucune technique liée.</div>`; return; }
    for (const [id, info] of sel) {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:center;gap:7px;padding:3px 0;font-size:12px;color:var(--text-soft)";
      const txt = document.createElement("span");
      txt.style.cssText = "flex:1;word-break:break-word";
      txt.innerHTML = `<span style="color:var(--text-dim);font-family:ui-monospace,Consolas,monospace;font-size:10px">${info.aid}</span> ${info.name} <span style="color:var(--text-faint);font-size:10px">(${info.domain})</span>`;
      const rm = document.createElement("button");
      rm.type = "button"; rm.textContent = "✕"; rm.title = t("tip.unlink");
      rm.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px";
      rm.onclick = () => { sel.delete(id); if (staging) pendingThreatTtps!.delete(id); renderLinked(); };
      row.appendChild(txt); row.appendChild(rm);
      linkedBox.appendChild(row);
    }
  };

  const addTech = (id: number, aid: string, name: string, domain: string): void => {
    if (!sel.has(id)) { sel.set(id, { aid, name, domain }); if (staging) pendingThreatTtps!.add(id); renderLinked(); }
  };

  const hide = () => { results.style.display = "none"; };
  let timer: number | undefined;
  search.addEventListener("input", () => {
    const q = search.value.trim();
    window.clearTimeout(timer);
    if (q.length < 2) { hide(); return; }
    timer = window.setTimeout(async () => {
      let rows: { AttackTechniqueID: number; AttackID: string; Name: string; Domain: string; IsSubtechnique: number }[] = [];
      try { rows = await api.searchAttackTechniques(q); } catch { hide(); return; }
      results.innerHTML = "";
      if (!rows.length) { results.innerHTML = `<div style="padding:7px 10px;font-size:12px;color:var(--text-dim)">Aucun résultat</div>`; }
      else for (const r of rows) {
        const item = document.createElement("div");
        item.style.cssText = "padding:6px 10px;font-size:12px;color:var(--text-soft);cursor:pointer;border-bottom:1px solid var(--surface)";
        item.innerHTML = `<span style="color:var(--text-dim);font-family:ui-monospace,Consolas,monospace;font-size:10px">${r.AttackID}</span> ${r.Name}${r.IsSubtechnique ? " <span style='color:var(--text-faint)'>(sous-tech.)</span>" : ""} <span style="color:var(--text-faint);font-size:10px">${r.Domain}</span>`;
        item.addEventListener("mouseenter", () => (item.style.background = "var(--surface)"));
        item.addEventListener("mouseleave", () => (item.style.background = ""));
        item.addEventListener("click", () => { addTech(r.AttackTechniqueID, r.AttackID, r.Name, r.Domain); search.value = ""; hide(); });
        results.appendChild(item);
      }
      results.style.display = "";
    }, 250);
  });
  search.addEventListener("blur", () => window.setTimeout(hide, 200));

  // Initial load (editing: existing links)
  if (!staging) {
    try {
      const linked = await api.getThreatTtps(threatId!);
      for (const l of linked) sel.set(l.AttackTechniqueID, { aid: l.AttackID, name: l.Name, domain: l.Domain });
    } catch { /* ignore */ }
  }
  renderLinked();

  saveBtn.onclick = async () => {
    saveBtn.disabled = true;
    try {
      await api.setThreatTtps(threatId!, [...sel.keys()]);
      toast(`${t("toast.techniquesSaved")} (${sel.size})`, "ok");
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
    finally { saveBtn.disabled = false; }
  };
}

// ── "Link / unlink vulnerabilities" modal (ASSETVULNERABILITY relation) ───
let vulnAssetId = 0;
let vulnRefresh: (() => void) | null = null;
const vulnSelected = new Map<number, string>(); // VulnerabilityID → label
let vulnSearchDebounce: ReturnType<typeof setTimeout> | null = null;

function vulnLabel(v: { VulnerabilityID: number; VULReferentialID?: string; VULGUID?: string }): string {
  return v.VULReferentialID || v.VULGUID || `#${v.VulnerabilityID}`;
}

function renderVulnSelected(): void {
  const host = $("vuln-selected");
  host.innerHTML = "";
  if (!vulnSelected.size) {
    host.innerHTML = `<div style="color:var(--text-dim);font-size:12px">${t("vuln.noneSelected")}</div>`;
    return;
  }
  vulnSelected.forEach((labelTxt, id) => {
    const chip = document.createElement("span");
    chip.style.cssText =
      "display:inline-flex;align-items:center;gap:5px;background:var(--surface-4);border:1px solid var(--border);border-radius:12px;padding:2px 8px;margin:2px;font-size:11px;color:var(--text-soft)";
    const txt = document.createElement("span");
    txt.textContent = labelTxt;
    chip.appendChild(txt);
    const x = document.createElement("button");
    x.type = "button";
    x.textContent = "✕";
    x.style.cssText = "background:none;border:none;color:var(--danger);cursor:pointer;font-size:11px;padding:0";
    x.onclick = () => {
      vulnSelected.delete(id);
      renderVulnSelected();
      // unchecks in the results if present
      const cb = $("vuln-results").querySelector<HTMLInputElement>(`input[value="${id}"]`);
      if (cb) cb.checked = false;
    };
    chip.appendChild(x);
    host.appendChild(chip);
  });
}

async function runVulnSearch(term: string): Promise<void> {
  const host = $("vuln-results");
  if (term.trim().length < 2) {
    host.innerHTML = `<div style="padding:4px;color:var(--text-dim);font-size:12px">${t("vuln.noResult")}</div>`;
    return;
  }
  host.innerHTML = `<div style="padding:4px;color:var(--text-dim);font-size:12px">…</div>`;
  let results: { VulnerabilityID: number; VULReferentialID: string; VULGUID: string; VULDescription: string }[] = [];
  try {
    results = await api.searchVulnerabilities(term.trim());
  } catch (e) {
    host.innerHTML = `<div style="padding:4px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  host.innerHTML = "";
  if (!results.length) {
    host.innerHTML = `<div style="padding:4px;color:var(--text-dim);font-size:12px">${t("vuln.noResult")}</div>`;
    return;
  }
  results.forEach((v) => {
    const row = document.createElement("label");
    row.style.cssText =
      "display:flex;align-items:flex-start;gap:7px;font-size:12px;color:var(--text-soft);padding:3px 0;cursor:pointer;border-bottom:1px solid var(--border-subtle)";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = String(v.VulnerabilityID);
    cb.checked = vulnSelected.has(v.VulnerabilityID);
    cb.style.marginTop = "2px";
    cb.onchange = () => {
      if (cb.checked) vulnSelected.set(v.VulnerabilityID, vulnLabel(v));
      else vulnSelected.delete(v.VulnerabilityID);
      renderVulnSelected();
    };
    row.appendChild(cb);
    const span = document.createElement("span");
    const desc = (v.VULDescription || "").slice(0, 140);
    span.innerHTML =
      `<b>${vulnLabel(v)}</b>` + (desc ? ` <span style="color:var(--text-muted)">— ${desc}</span>` : "");
    row.appendChild(span);
    host.appendChild(row);
  });
}

async function openVulnModal(assetId: number, refresh: () => void): Promise<void> {
  vulnAssetId = assetId;
  vulnRefresh = refresh;
  vulnSelected.clear();
  ($("vuln-search") as HTMLInputElement).value = "";
  $("vuln-results").innerHTML = `<div style="padding:4px;color:var(--text-dim);font-size:12px">${t("vuln.noResult")}</div>`;
  ($("vuln-modal") as HTMLElement).style.display = "flex";
  if (assetId === 0 && pendingAssetLinks) {
    // Creation mode: initial selection from the buffer (no server call)
    pendingAssetLinks.vulns.forEach((label, id) => vulnSelected.set(id, label));
  } else {
    try {
      const linked = await api.getAssetVulnerabilities(assetId);
      linked.forEach((v) => vulnSelected.set(v.VulnerabilityID, vulnLabel(v)));
    } catch {
      /* ignore */
    }
  }
  renderVulnSelected();
}

async function submitVuln(): Promise<void> {
  // Creation mode (vulnAssetId === 0): we remember the selection.
  if (vulnAssetId === 0 && pendingAssetLinks) {
    const m = pendingAssetLinks.vulns;
    m.clear();
    vulnSelected.forEach((label, id) => m.set(id, label));
    ($("vuln-modal") as HTMLElement).style.display = "none";
    toast(t("link.pendingQueued"), "ok");
    if (vulnRefresh) vulnRefresh();
    return;
  }
  try {
    await api.setAssetVulnerabilities(vulnAssetId, Array.from(vulnSelected.keys()));
    ($("vuln-modal") as HTMLElement).style.display = "none";
    toast(t("toast.vulnsUpdated"), "ok");
    if (vulnRefresh) vulnRefresh();
  } catch (e) {
    toast(t("toast.error") + " " + e, "err");
  }
}

// ── "Add / remove CPEs" modal (CPEFORASSET relation) ─────────────────
let cpeAssetId = 0;
let cpeRefresh: (() => void) | null = null;

async function openCpeModal(assetId: number, refresh: () => void): Promise<void> {
  cpeAssetId = assetId;
  cpeRefresh = refresh;
  const list = $("cpe-list");
  list.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">…</div>`;
  ($("cpe-filter") as HTMLInputElement).value = "";
  ($("cpe-modal") as HTMLElement).style.display = "flex";
  ensureCpeBuilder();
  void loadCpeBuilderOptions();

  let all: { id: unknown; label: unknown }[] = [];
  let linked: number[] = [];
  try {
    if (assetId === 0 && pendingAssetLinks) {
      // Creation mode: no AssetID in the database → links pre-checked from the buffer
      all = await api.getLookup("XORCISM", "CPE", "CPEID", "CPEName");
      linked = [...pendingAssetLinks.cpes.keys()];
    } else {
      [all, linked] = await Promise.all([
        api.getLookup("XORCISM", "CPE", "CPEID", "CPEName"),
        api.getAssetCpes(assetId).then((r) => r.map((x) => x.CPEID)),
      ]);
    }
  } catch (e) {
    list.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`;
    return;
  }
  const linkedSet = new Set(linked.map(Number));
  list.innerHTML = "";
  if (!all.length) {
    list.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${t("cpe.none")}</div>`;
    return;
  }
  all.forEach((c) => {
    const name = c.label == null || c.label === "" ? `#${c.id}` : String(c.label);
    const row = document.createElement("label");
    row.className = "cpe-opt";
    row.dataset.search = name.toLowerCase();
    row.style.cssText =
      "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = String(c.id);
    cb.checked = linkedSet.has(Number(c.id));
    row.appendChild(cb);
    const span = document.createElement("span");
    span.textContent = name;
    span.style.wordBreak = "break-all";
    row.appendChild(span);
    list.appendChild(row);
  });
}

function filterCpeList(term: string): void {
  const q = term.trim().toLowerCase();
  $("cpe-list")
    .querySelectorAll<HTMLElement>(".cpe-opt")
    .forEach((el) => {
      el.style.display = !q || (el.dataset.search ?? "").includes(q) ? "" : "none";
    });
}

// CPE validation (naming convention: cpe:2.3:… formatted string [11 attributes
// = part + 10], or cpe:/… URI 2.2). Must stay aligned with isValidCpe (server/db.ts).
function isValidCpeClient(s: string): boolean {
  const v = s.trim();
  return /^cpe:2\.3:[aho](:[^:\s]+){10}$/i.test(v) || /^cpe:\/[aho](:[^:/\s]*){1,6}$/i.test(v);
}

// Manual entry of a CPEID in the "Add / remove CPEs" window:
// validates the format, creates/fetches the CPE entry, adds it to the checked list.
async function addCpeManual(): Promise<void> {
  const inp = document.getElementById("cpe-add-input") as HTMLInputElement;
  const err = document.getElementById("cpe-add-err");
  const name = inp.value.trim();
  if (!isValidCpeClient(name)) { if (err) err.textContent = t("cpe.invalid"); return; }
  if (err) err.textContent = "";
  try {
    const r = await api.addCpe(name);
    const list = $("cpe-list");
    const existing = list.querySelector<HTMLInputElement>(`input[type=checkbox][value="${r.id}"]`);
    if (existing) {
      existing.checked = true;
      (existing.closest(".cpe-opt") as HTMLElement | null)?.scrollIntoView({ block: "nearest" });
    } else {
      const row = document.createElement("label");
      row.className = "cpe-opt";
      row.dataset.search = name.toLowerCase();
      row.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
      const cb = document.createElement("input");
      cb.type = "checkbox"; cb.value = String(r.id); cb.checked = true;
      const span = document.createElement("span");
      span.textContent = name; span.style.wordBreak = "break-all";
      row.appendChild(cb); row.appendChild(span);
      list.insertBefore(row, list.firstChild);
    }
    inp.value = "";
    toast(r.created ? t("cpe.added") : t("cpe.alreadyExists"), "ok");
  } catch (e) {
    if (err) err.textContent = (e as Error).message;
  }
}

// ── CPE 2.3 builder (field-by-field assembly) ──────────────────────
// Fields (CPE 2.3 order) after part: vendor, product (combos), then 8 text fields.
const CPE_BUILDER_FIELDS: { key: string; def: string; list?: string }[] = [
  { key: "vendor", def: "", list: "cpe-vendor-list" },
  { key: "product", def: "", list: "cpe-product-list" },
  { key: "version", def: "*" },
  { key: "update", def: "*" },
  { key: "edition", def: "*" },
  { key: "language", def: "*" },
  { key: "sw_edition", def: "*" },
  { key: "target_sw", def: "*" },
  { key: "target_hw", def: "*" },
  { key: "other", def: "-" },
];
let cpeBuilderBuilt = false;
let cpeBuilderOptionsLoaded = false;

// Normalizes a CPE component: lowercase, no space or ':' (otherwise invalid CPE).
function sanitizeCpeComponent(raw: string, fallback: string): string {
  const v = (raw || "").trim().toLowerCase().replace(/[:\s]+/g, "_");
  return v || fallback;
}

// Preview (always assemblable: empty vendor/product → '*' for display).
function cpeBuilderPreview(): string {
  const part = (document.getElementById("cpe-b-part") as HTMLSelectElement).value;
  const get = (k: string, def: string) =>
    sanitizeCpeComponent((document.getElementById("cpe-b-" + k) as HTMLInputElement).value, def);
  const comps = CPE_BUILDER_FIELDS.map((f) => get(f.key, f.def || "*"));
  return ["cpe:2.3", part, ...comps].join(":");
}

// Assembles the final CPE 2.3 string; requires vendor and product.
function assembleCpeFromBuilder(): { cpe: string | null; error?: string } {
  const part = (document.getElementById("cpe-b-part") as HTMLSelectElement).value;
  const get = (k: string) => (document.getElementById("cpe-b-" + k) as HTMLInputElement).value;
  const vendor = sanitizeCpeComponent(get("vendor"), "");
  const product = sanitizeCpeComponent(get("product"), "");
  if (!vendor || !product) return { cpe: null, error: t("cpe.builderNeedVP") };
  const rest = CPE_BUILDER_FIELDS.slice(2).map((f) => sanitizeCpeComponent(get(f.key), f.def));
  return { cpe: ["cpe:2.3", part, vendor, product, ...rest].join(":") };
}

// Builds the builder DOM only once in #cpe-builder-mount.
function ensureCpeBuilder(): void {
  if (cpeBuilderBuilt) return;
  const mount = document.getElementById("cpe-builder-mount");
  if (!mount) return;
  const det = document.createElement("details");
  det.style.cssText = "border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  const sum = document.createElement("summary");
  sum.textContent = t("cpe.builderTitle");
  sum.style.cssText = "cursor:pointer;padding:6px 8px;font-size:12px;color:var(--text-muted);user-select:none";
  det.appendChild(sum);

  const grid = document.createElement("div");
  grid.style.cssText = "padding:6px 8px;display:grid;grid-template-columns:1fr 1fr;gap:6px 8px";
  const fieldStyle = "display:flex;flex-direction:column;gap:2px;font-size:10px;color:var(--text-dim)";
  const inputStyle =
    "background:#0b0d14;border:1px solid var(--border);border-radius:5px;padding:5px 7px;color:var(--text);font-size:12px";

  // part (a/o dropdown)
  const partWrap = document.createElement("label");
  partWrap.style.cssText = fieldStyle;
  partWrap.innerHTML = "<span>part</span>";
  const partSel = document.createElement("select");
  partSel.id = "cpe-b-part";
  partSel.style.cssText = inputStyle;
  partSel.innerHTML =
    '<option value="a">a — application</option><option value="o">o — operating system</option>';
  partWrap.appendChild(partSel);
  grid.appendChild(partWrap);

  for (const f of CPE_BUILDER_FIELDS) {
    const wrap = document.createElement("label");
    wrap.style.cssText = fieldStyle;
    const lbl = document.createElement("span");
    lbl.textContent = f.def ? `${f.key} (${f.def})` : f.key;
    const inp = document.createElement("input");
    inp.id = "cpe-b-" + f.key;
    inp.type = "text";
    inp.autocomplete = "off";
    inp.spellcheck = false;
    inp.placeholder = f.def || "";
    inp.style.cssText = inputStyle;
    if (f.list) inp.setAttribute("list", f.list);
    inp.addEventListener("input", refreshCpeBuilderPreview);
    wrap.appendChild(lbl);
    wrap.appendChild(inp);
    grid.appendChild(wrap);
  }
  partSel.addEventListener("change", refreshCpeBuilderPreview);
  det.appendChild(grid);

  const foot = document.createElement("div");
  foot.style.cssText = "padding:0 8px 8px;display:flex;gap:8px;align-items:center";
  const preview = document.createElement("code");
  preview.id = "cpe-b-preview";
  preview.style.cssText = "flex:1;font-size:11px;color:#7dd3fc;word-break:break-all";
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "btn btn-ghost btn-sm";
  addBtn.id = "cpe-b-add";
  addBtn.textContent = t("cpe.builderAdd");
  addBtn.style.flex = "0 0 auto";
  addBtn.addEventListener("click", () => void addCpeFromBuilder());
  foot.appendChild(preview);
  foot.appendChild(addBtn);
  det.appendChild(foot);

  mount.appendChild(det);
  cpeBuilderBuilt = true;
  refreshCpeBuilderPreview();
}

function refreshCpeBuilderPreview(): void {
  const el = document.getElementById("cpe-b-preview");
  if (el) el.textContent = cpeBuilderPreview();
}

// Loads (once) the vendor/product suggestions into the datalists.
async function loadCpeBuilderOptions(): Promise<void> {
  if (cpeBuilderOptionsLoaded) return;
  try {
    const { vendors, products } = await api.cpeBuilderOptions();
    const fill = (listId: string, values: string[]) => {
      const dl = document.getElementById(listId);
      if (!dl) return;
      dl.innerHTML = "";
      const frag = document.createDocumentFragment();
      for (const v of values) {
        const o = document.createElement("option");
        o.value = v;
        frag.appendChild(o);
      }
      dl.appendChild(frag);
    };
    fill("cpe-vendor-list", vendors);
    fill("cpe-product-list", products);
    cpeBuilderOptionsLoaded = true;
  } catch {
    /* suggestions unavailable: free input is still possible */
  }
}

// Assembles from the builder, fills the text field, then adds (common validated path).
async function addCpeFromBuilder(): Promise<void> {
  const err = document.getElementById("cpe-add-err");
  const { cpe, error } = assembleCpeFromBuilder();
  if (!cpe) { if (err) err.textContent = error || t("cpe.invalid"); return; }
  (document.getElementById("cpe-add-input") as HTMLInputElement).value = cpe;
  await addCpeManual();
}

async function submitCpe(): Promise<void> {
  const checked = Array.from(
    $("cpe-list").querySelectorAll<HTMLInputElement>('input[type=checkbox]:checked')
  );
  // Creation mode (cpeAssetId === 0): we remember the selection (id → label).
  if (cpeAssetId === 0 && pendingAssetLinks) {
    const m = pendingAssetLinks.cpes;
    m.clear();
    for (const cb of checked) {
      const label = cb.closest(".cpe-opt")?.querySelector("span")?.textContent || `#${cb.value}`;
      m.set(Number(cb.value), label);
    }
    ($("cpe-modal") as HTMLElement).style.display = "none";
    toast(t("link.pendingQueued"), "ok");
    if (cpeRefresh) cpeRefresh();
    return;
  }
  try {
    await api.setAssetCpes(cpeAssetId, checked.map((c) => Number(c.value)));
    ($("cpe-modal") as HTMLElement).style.display = "none";
    toast(t("toast.cpeUpdated"), "ok");
    if (cpeRefresh) cpeRefresh();
  } catch (e) {
    toast(t("toast.error") + " " + e, "err");
  }
}

// ── Threat models: relational sub-panels ─────────────────────────────────

// Reusable "section" box (title + button + box) for the sub-panels.
function tmSection(body: HTMLElement, title: string, btnLabel: string | null,
                   onAdd: ((box: HTMLElement) => void) | null): HTMLElement {
  const div = document.createElement("div");
  div.style.marginTop = "12px";
  const header = document.createElement("div");
  header.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-bottom:4px";
  const label = document.createElement("label");
  label.textContent = title;
  label.style.cssText = "font-size:12px;color:var(--text-muted)";
  header.appendChild(label);
  const box = document.createElement("div");
  box.style.cssText = "max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg)";
  if (btnLabel && onAdd) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = btnLabel;
    btn.onclick = () => onAdd(box);
    header.appendChild(btn);
  }
  div.appendChild(header);
  div.appendChild(box);
  body.appendChild(div);
  return box;
}

function tmEmptyBox(box: HTMLElement, msg: string): void {
  box.innerHTML = `<div style="padding:8px;color:var(--text-dim);font-size:12px">${msg}</div>`;
}

// Generic picker (checkboxes + filter) built dynamically.
function openLinkPicker(opts: {
  title: string;
  options: { id: unknown; label: unknown }[];
  selected: Set<number>;
  onSave: (ids: number[]) => Promise<void>;
}): void {
  const bg = document.createElement("div");
  bg.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:1000";
  const modal = document.createElement("div");
  modal.style.cssText =
    "background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:18px;width:520px;max-width:92vw";
  modal.innerHTML = `<h3 style="font-size:14px;color:var(--text);margin:0 0 10px">${opts.title}</h3>`;
  const filter = document.createElement("input");
  filter.placeholder = t("explorer.search") || "Rechercher…";
  filter.style.cssText =
    "width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px;margin-bottom:8px";
  const list = document.createElement("div");
  list.style.cssText = "max-height:50vh;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:8px";
  if (!opts.options.length) tmEmptyBox(list, "—");
  opts.options.forEach((o) => {
    const name = o.label == null || o.label === "" ? `#${o.id}` : String(o.label);
    const row = document.createElement("label");
    row.dataset.s = name.toLowerCase();
    row.style.cssText = "display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text-soft);padding:2px 0;cursor:pointer";
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = String(o.id); cb.checked = opts.selected.has(Number(o.id));
    cb.style.width = "auto";
    const span = document.createElement("span");
    span.textContent = name; span.style.wordBreak = "break-all";
    row.appendChild(cb); row.appendChild(span); list.appendChild(row);
  });
  filter.oninput = () => {
    const q = filter.value.trim().toLowerCase();
    list.querySelectorAll<HTMLElement>("label").forEach((el) => {
      el.style.display = !q || (el.dataset.s ?? "").includes(q) ? "" : "none";
    });
  };
  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:12px";
  const cancel = document.createElement("button");
  cancel.className = "btn btn-ghost btn-sm"; cancel.textContent = t("modal.cancel") || "Annuler";
  cancel.onclick = () => bg.remove();
  const save = document.createElement("button");
  save.className = "btn btn-primary btn-sm"; save.textContent = t("modal.save") || "Enregistrer";
  save.onclick = async () => {
    const ids = Array.from(list.querySelectorAll<HTMLInputElement>("input[type=checkbox]:checked")).map((c) => Number(c.value));
    try { await opts.onSave(ids); bg.remove(); toast(t("tm.updated") || "Mis à jour", "ok"); }
    catch (e) { toast(t("toast.error") + " " + e, "err"); }
  };
  actions.appendChild(cancel); actions.appendChild(save);
  modal.appendChild(filter); modal.appendChild(list); modal.appendChild(actions);
  bg.appendChild(modal);
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  document.body.appendChild(bg);
  filter.focus();
}

// Scope (assets) of a threat model
async function renderTmScopeBox(box: HTMLElement, modelId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!modelId) { tmEmptyBox(box, t("tm.saveFirst") || "Enregistrez d'abord le modèle."); return; }
  let assets: { AssetID: number; AssetName: string }[] = [];
  try { assets = await api.getThreatModelAssets(modelId); }
  catch (e) { box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`; return; }
  if (!assets.length) { tmEmptyBox(box, t("tm.noScope") || "Aucun asset dans le périmètre."); return; }
  const tb = document.createElement("table");
  tb.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  assets.forEach((a) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft)";
    td.textContent = a.AssetName == null || a.AssetName === "" ? `#${a.AssetID}` : a.AssetName;
    tr.appendChild(td); tb.appendChild(tr);
  });
  box.appendChild(tb);
}

async function appendThreatModelScope(body: HTMLElement, modelId: number | null): Promise<void> {
  const box = tmSection(body, t("tm.scope") || "Assets in scope (THREATMODELASSET)",
    modelId ? (t("tm.addAsset") || "+ Asset") : null,
    modelId ? async () => {
      const [all, linked] = await Promise.all([
        api.getLookup("XORCISM", "ASSET", "AssetID", "AssetName"),
        api.getThreatModelAssets(modelId).then((r) => r.map((x) => x.AssetID)),
      ]);
      openLinkPicker({
        title: t("tm.scope") || "Assets in scope",
        options: all, selected: new Set(linked.map(Number)),
        onSave: async (ids) => { await api.setThreatModelAssets(modelId, ids); await renderTmScopeBox(box, modelId); },
      });
    } : null);
  await renderTmScopeBox(box, modelId);
}

// Threats of a threat model
async function renderTmThreatBox(box: HTMLElement, modelId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!modelId) { tmEmptyBox(box, t("tm.saveFirst") || "Enregistrez d'abord le modèle."); return; }
  let threats: { ThreatModelThreatID: number; Title: string; STRIDECategory: string; RiskScore: string; Status: string }[] = [];
  try { threats = await api.getThreatModelThreats(modelId); }
  catch (e) { box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`; return; }
  if (!threats.length) { tmEmptyBox(box, t("tm.noThreats") || "Aucune menace."); return; }
  const tb = document.createElement("table");
  tb.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  tb.innerHTML = `<thead><tr>
    <th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">Title</th>
    <th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">STRIDE</th>
    <th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">Risk</th>
    <th style="text-align:left;padding:5px 8px;color:var(--text-muted);border-bottom:1px solid var(--border)">Status</th></tr></thead>`;
  const body2 = document.createElement("tbody");
  threats.forEach((th) => {
    const tr = document.createElement("tr");
    const cell = (v: string) => {
      const td = document.createElement("td");
      td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft)";
      td.textContent = v ?? ""; return td;
    };
    tr.appendChild(cell(th.Title)); tr.appendChild(cell(th.STRIDECategory));
    tr.appendChild(cell(th.RiskScore)); tr.appendChild(cell(th.Status));
    body2.appendChild(tr);
  });
  tb.appendChild(body2); box.appendChild(tb);
}

async function appendThreatModelThreats(body: HTMLElement, modelId: number | null): Promise<void> {
  const box = tmSection(body, t("tm.threats") || "Threats (THREATMODELTHREAT)",
    modelId ? (t("tm.addThreat") || "+ Threat") : null,
    modelId ? () => openThreatForm(modelId, () => renderTmThreatBox(box, modelId)) : null);
  await renderTmThreatBox(box, modelId);
}

// Mini threat-creation form
function openThreatForm(modelId: number, onSaved: () => void): void {
  const strides = ENUM_COLUMNS["THREATMODELTHREAT.STRIDECategory"];
  const scale = ["Very Low", "Low", "Moderate", "High", "Very High"];
  const status = ["Open", "Mitigated", "Accepted", "Transferred"];
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:1000";
  const m = document.createElement("div");
  m.style.cssText = "background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:18px;width:560px;max-width:94vw;max-height:90vh;overflow:auto";
  const inp = "width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px;margin-bottom:8px";
  const sel = (id: string, arr: string[], def?: string) =>
    `<select id="${id}" style="${inp}">${arr.map((o) => `<option value="${o}" ${o === def ? "selected" : ""}>${o}</option>`).join("")}</select>`;
  m.innerHTML =
    `<h3 style="font-size:14px;color:var(--text);margin:0 0 12px">${t("tm.addThreat") || "Nouvelle menace"}</h3>` +
    `<label style="font-size:12px;color:var(--text-muted)">Title</label><input id="tf_title" style="${inp}">` +
    `<label style="font-size:12px;color:var(--text-muted)">STRIDE</label>${sel("tf_stride", strides, strides[0])}` +
    `<label style="font-size:12px;color:var(--text-muted)">Likelihood</label>${sel("tf_like", scale, "Moderate")}` +
    `<label style="font-size:12px;color:var(--text-muted)">Impact</label>${sel("tf_impact", scale, "Moderate")}` +
    `<label style="font-size:12px;color:var(--text-muted)">Status</label>${sel("tf_status", status, "Open")}` +
    `<label style="font-size:12px;color:var(--text-muted)">Description</label><textarea id="tf_desc" rows="3" style="${inp}"></textarea>`;
  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:6px";
  const cancel = document.createElement("button");
  cancel.className = "btn btn-ghost btn-sm"; cancel.textContent = t("modal.cancel") || "Annuler";
  cancel.onclick = () => bg.remove();
  const save = document.createElement("button");
  save.className = "btn btn-primary btn-sm"; save.textContent = t("modal.save") || "Enregistrer";
  save.onclick = async () => {
    const v = (id: string) => (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement).value;
    const title = v("tf_title").trim();
    if (!title) { toast(t("tm.titleReq") || "Titre requis", "err"); return; }
    // Derived risk score (likelihood × impact)
    const rank = (s: string) => scale.indexOf(s);
    const score = rank(v("tf_like")) + rank(v("tf_impact"));
    const risk = score >= 7 ? "Critical" : score >= 5 ? "High" : score >= 3 ? "Medium" : "Low";
    try {
      await api.addThreatModelThreat(modelId, {
        Title: title, STRIDECategory: v("tf_stride"), Likelihood: v("tf_like"),
        Impact: v("tf_impact"), RiskScore: risk, Status: v("tf_status"), Description: v("tf_desc"),
      });
      bg.remove(); toast(t("tm.threatAdded") || "Menace ajoutée", "ok"); onSaved();
    } catch (e) { toast(t("toast.error") + " " + e, "err"); }
  };
  actions.appendChild(cancel); actions.appendChild(save);
  m.appendChild(actions); bg.appendChild(m);
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  document.body.appendChild(bg);
  (document.getElementById("tf_title") as HTMLInputElement)?.focus();
}

// Mitigation controls of a threat
async function renderTmControlBox(box: HTMLElement, threatId: number | null): Promise<void> {
  box.innerHTML = "";
  if (!threatId) { tmEmptyBox(box, t("tm.saveFirst") || "Enregistrez d'abord la menace."); return; }
  let ctrls: { ControlID: number; ControlName: string }[] = [];
  try { ctrls = await api.getThreatControls(threatId); }
  catch (e) { box.innerHTML = `<div style="padding:8px;color:var(--danger);font-size:12px">${e}</div>`; return; }
  if (!ctrls.length) { tmEmptyBox(box, t("tm.noControls") || "Aucun contrôle de mitigation."); return; }
  const tb = document.createElement("table");
  tb.style.cssText = "width:100%;border-collapse:collapse;font-size:12px";
  ctrls.forEach((c) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.style.cssText = "padding:4px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text-soft)";
    td.textContent = c.ControlName == null || c.ControlName === "" ? `#${c.ControlID}` : c.ControlName;
    tr.appendChild(td); tb.appendChild(tr);
  });
  box.appendChild(tb);
}

async function appendThreatMitigations(body: HTMLElement, threatId: number | null): Promise<void> {
  const box = tmSection(body, t("tm.mitigations") || "Mitigating controls (THREATMODELCONTROL)",
    threatId ? (t("tm.addControl") || "+ Control") : null,
    threatId ? async () => {
      const [all, linked] = await Promise.all([
        api.getLookup("XORCISM", "CONTROL", "ControlID", "ControlName"),
        api.getThreatControls(threatId).then((r) => r.map((x) => x.ControlID)),
      ]);
      openLinkPicker({
        title: t("tm.mitigations") || "Mitigating controls",
        options: all, selected: new Set(linked.map(Number)),
        onSave: async (ids) => { await api.setThreatControls(threatId, ids); await renderTmControlBox(box, threatId); },
      });
    } : null);
  await renderTmControlBox(box, threatId);
}

// Shows a modal by repositioning it at the top: the ".modal" container
// (overflow-y:auto) is reused from one opening to the next and otherwise keeps
// its previous scrollTop → the modal opened scrolled (not on the 1st field).
// We reset the scroll to zero, then focus the 1st editable field WITHOUT
// re-scrolling (preventScroll).
function showModalAtTop(modalBgId: string): void {
  const bg = document.getElementById(modalBgId);
  if (!bg) return;
  (bg as HTMLElement).style.display = "flex";
  const modal = bg.querySelector(".modal") as HTMLElement | null;
  if (modal) modal.scrollTop = 0;
  const first = (modal ?? bg).querySelector(
    "input:not([readonly]):not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [contenteditable='true']"
  ) as HTMLElement | null;
  if (first) first.focus({ preventScroll: true });
  if (modal) modal.scrollTop = 0; // in case the focus scrolled despite preventScroll
}

async function openInsertModal(): Promise<void> {
  const body = $("modal-body");
  body.innerHTML = "";
  pendingAssetLinks = null; // links buffer: enabled only for ASSET creation
  pendingQuestionLinks = null; // question links buffer: QUESTIONNAIRE creation
  pendingAnswerEvidences = null; // evidence buffer: ANSWER creation
  pendingThreatTtps = null; // ATT&CK techniques buffer: THREAT creation
  pendingVulnTags = null; // tags buffer: VULNERABILITY creation
  pendingOvalTags = null; // tags buffer: OVALDEFINITION creation
  pendingCpeTags = null; // tags buffer: CPE creation
  pendingCweTags = null; // tags buffer: CWE creation
  pendingControlTags = null; // tags buffer: CONTROL creation

  if (!schema.length) {
    body.innerHTML = `<p style="color:var(--text-muted)">Schema non charge</p>`;
    return;
  }
  appendFormJsonImport(body, "f_"); // "pre-fill from JSON" button at the top of the form

  // Fetches the next auto-incremented ID of the primary key (from the DB)
  let nextPk: { column: string | null; value: number | null } = { column: null, value: null };
  try {
    nextPk = await api.getNextId(currentDb, currentTable);
  } catch {
    /* endpoint unavailable: we continue without pre-filling */
  }

  // Pre-loads the options of the "foreign key" columns
  const fkOpts = await fetchFkOptions();

  const INPUT_CSS =
    "width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:13px";

  // Key column: declared PK if present, otherwise the 1st column (XORCISM convention)
  const keyColName = (schema.find((c) => c.pk === 1) ?? schema[0])?.name;

  // OSV.dev enrichment + CIRCL search (KEV) + Exploit-DB lookup at the top of the VULNERABILITY form
  if (isOsvTable()) {
    appendOsvEnrichField(body, "f_", "");
    appendCirclSearchField(body, "f_");
    appendExploitDbSearchField(body, "f_");
  }
  if (currentTable === "OBSERVABLE") appendMalwareScanField(body, "f_", "observable");
  else if (currentTable === "DOCUMENT") appendMalwareScanField(body, "f_", currentDb === "XORCISM" ? "documentFile" : "manual");

  reorderSchema(currentTable, schema).forEach((col) => {
    if (isHiddenFormColumn(col.name)) return; // handled server-side (session)
    // Search field by name (fills the ID), inserted BEFORE the ID field
    const nsSpec = getNameSearch(currentTable, col.name);
    if (nsSpec) appendNameSearchField(body, "f_", col.name, nsSpec, "");
    if (nsSpec?.replaceIdField) {
      // The name dropdown replaces the ID field: hidden input (filled by the search).
      const hid = document.createElement("input");
      hid.type = "hidden"; hid.id = `f_${col.name}`;
      body.appendChild(hid);
      return;
    }
    // Vulnerability search (fills VulnerabilityID), inserted BEFORE the ID field
    if (hasVulnSearch(currentTable, col.name)) appendVulnSearchField(body, "f_", col.name, "");
    const div = document.createElement("div");
    div.id = `f_field_${col.name}`;
    div.style.marginBottom = "10px";
    const label = document.createElement("label");
    label.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:4px";

    // Primary key (by convention: 1st column)
    if (col.name === keyColName) {
      const isAutoInt = nextPk.column === col.name && nextPk.value != null;
      setFieldLabel(label, col, { pkSuffix: isAutoInt ? " 🔑 (auto)" : " 🔑" });
      const input = document.createElement("input");
      input.id = `f_${col.name}`;
      input.placeholder = col.type;
      input.style.cssText = INPUT_CSS;
      if (isAutoInt) {
        // Integer PK: pre-filled with MAX+1 and read-only
        input.value = String(nextPk.value);
        input.readOnly = true;
        input.style.opacity = "0.7";
        input.title = t("tip.autoIncrement");
      }
      // Text PK (CWEID, CCEID…): editable, to be entered by the user
      div.appendChild(label);
      div.appendChild(input);
      body.appendChild(div);
      return;
    }

    setFieldLabel(label, col);
    div.appendChild(label);

    // Selector + file upload (e.g. EVIDENCE.EvidenceFile, ASSET.AssetImage)
    if (hasFileUpload(currentTable, col.name)) {
      div.appendChild(
        mkFileUpload(`f_${col.name}`, undefined, {
          imageOnly: isImageUploadCol(currentTable, col.name),
        })
      );
      body.appendChild(div);
      return;
    }

    // Content-addressed object-store upload (BlobSha256 hash-pointer columns)
    if (isCasUploadCol(col.name)) {
      div.appendChild(mkCasUpload(`f_${col.name}`, undefined));
      body.appendChild(div);
      return;
    }

    // Labels selector (chips + autocompletion, OpenCTI style) → CSV Labels column
    if (isLabelsField(currentTable, col.name)) {
      appendLabelsField(div, `f_${col.name}`, "");
      body.appendChild(div);
      return;
    }

    // "Foreign key" dropdown (e.g. IncidentCategoryID, VocabularyID)
    const fk = getFkSpec(currentTable, col.name);
    if (fk) {
      const fSel = mkFkSelect(`f_${col.name}`, fkOpts[col.name] ?? [], fk.default ?? "");
      div.appendChild(
        FK_CREATE_BUTTON.has(`${currentTable}.${col.name}`) ? fkWithCreate(fSel, "f_", col.name, fk) : fSel
      );
      body.appendChild(div);
      return;
    }

    // Free input with autocompletion (e.g. AUDIT.AuditorName → PERSON.FullName)
    const dlSpec = getDatalistSpec(currentTable, col.name);
    if (dlSpec) {
      div.appendChild(
        mkDatalistInput(
          `f_${col.name}`,
          dlSpec,
          "",
          dlSpec.idTargetCol ? `f_${dlSpec.idTargetCol}` : undefined
        )
      );
      body.appendChild(div);
      return;
    }

    // Labeled <select> (shows a label, stores the int value, e.g. BusinessValue)
    const lsF = getLabeledSelect(currentTable, col.name);
    if (lsF) {
      div.appendChild(mkLabeledSelectInput(`f_${col.name}`, lsF, ""));
      body.appendChild(div);
      return;
    }

    // Dropdown with input (static options: e.g. Role, status)
    const sdlF = getStaticDatalist(currentTable, col.name);
    if (sdlF) {
      div.appendChild(mkStaticDatalistInput(`f_${col.name}`, sdlF, staticDatalistDefault(currentTable, col.name)));
      body.appendChild(div);
      return;
    }

    // Derived risk level (= probability × impact), read-only + live computation
    const rlF = getRiskLevelSpec(currentTable, col.name);
    if (rlF) {
      div.appendChild(mkRiskLevelInput(`f_${col.name}`, ""));
      body.appendChild(div);
      wireRiskLevelLive(`f_${col.name}`, `f_${rlF.prob}`, `f_${rlF.impact}`);
      return;
    }

    // Dropdown filtered by vocabulary (e.g. THREATACTOR.ThreatMotive → THREATMOTIVE)
    const vvSpec = getVocabValueSelect(currentTable, col.name);
    if (vvSpec) {
      div.appendChild(mkVocabValueSelect("f_", col.name, vvSpec, ""));
      body.appendChild(div);
      return;
    }

    // Label/value dropdown (e.g. INCIDENT.exercise: Yes/No → 1/0)
    const ve = getValueEnum(currentTable, col.name);
    if (ve) {
      div.appendChild(mkValueSelect(`f_${col.name}`, ve.options, ve.default ?? ""));
      body.appendChild(div);
      return;
    }

    // Dropdown for the enumerated columns (e.g. INCIDENT.Criticity)
    const opts = getEnumOptions(currentTable, col.name);
    if (opts) {
      div.appendChild(mkEnumSelect(`f_${col.name}`, opts, ""));
      body.appendChild(div);
      return;
    }

    // Checkbox (e.g. ASSET.Enabled) — default value at insertion
    const cbSpec = getCheckbox(currentTable, col.name);
    if (cbSpec) {
      div.appendChild(mkCheckbox(`f_${col.name}`, cbSpec, undefined));
      body.appendChild(div);
      return;
    }

    // WYSIWYG editor (AssetDescription, INCIDENT.summary…)
    if (isRichTextField(currentTable, col.name)) {
      const rte = mkRichText("", col.type, richTextOpts(currentTable, col.name));
      rte.hidden.id = `f_${col.name}`;
      div.appendChild(rte.hidden);
      div.appendChild(rte.mount);
      body.appendChild(div);
      return;
    }

    // Computed column (e.g. ASSET.RiskScore): read-only + hint
    if (isReadonlyFormColumn(currentTable, col.name)) {
      div.appendChild(mkReadonlyComputedInput(`f_${col.name}`, null));
      body.appendChild(div);
      return;
    }

    const input = document.createElement("input");
    input.id = `f_${col.name}`;
    input.placeholder = col.type;
    const fProminent = isProminentInput(currentTable, col.name);
    const fWide = isWideInput(currentTable, col.name);
    input.style.cssText = fProminent ? PROMINENT_INPUT_CSS : fWide ? WIDE_INPUT_CSS : INPUT_CSS;
    if (fProminent || fWide) input.dataset.fullwidth = "1";
    // Pre-fills (current date) + calendar icon for CreatedDate / ValidFromDate
    // and the per-table columns (e.g. VOCABULARY.DateModified)
    if (hasAutoDate(currentTable, col.name)) {
      input.value = todayStr();
      div.appendChild(wrapWithCalendar(input));
    } else if (hasDatePicker(currentTable, col.name)) {
      // Calendar icon; pre-filled to today if the column requires it (e.g. EvidenceDate)
      if (isDefaultTodayDate(currentTable, col.name) || isValidFromCol(col.name)) input.value = todayStr();
      // or "today + N years" (e.g. ValidUntil = +1 year)
      const plusY = defaultPlusYears(currentTable, col.name);
      if (plusY != null) input.value = todayPlusYears(plusY);
      div.appendChild(wrapWithCalendar(input));
    } else {
      // isEncrypted initialized to 0 by default (VocabularyID is handled as FK)
      if (col.name.toLowerCase() === "isencrypted") input.value = "0";
      // ValidFrom (all tables): current date at creation
      if (isValidFromCol(col.name)) input.value = todayStr();
      // All databases: pre-fills the *GUID fields with a UUIDv4 (STIX 2.1 compatible)
      if (isGuidColumn(col.name)) input.value = newGuid();
      // Duplicate check on blur of a *Name field (creation)
      if (/name$/i.test(col.name)) attachDuplicateNameCheck(input, col.name);
      div.appendChild(input);
    }
    body.appendChild(div);
  });

  // Split a long form into collapsible sections (required → details → advanced)
  groupFormFields("f_", currentTable);

  // Shows the label (e.g. AssetName) after the relevant identifier fields
  await appendNameHints("f_");

  // STIX 2.1 bundle generation (THREAT form)
  if (isStixTable()) appendStixBundleButton(body, "f_");

  // Web security scanner + network scanner (ASSET form)
  if (currentTable === "ASSET") { void appendWebScanPanel("f_"); void appendNetworkScanPanel("f_"); wireAssetScreenshot("f_"); appendEmailHarvestHint("f_"); }
  // SOCRadar IOC Radar: search a CVE (VULNERABILITY form)
  if (isOsvTable()) { appendSocradarIocField("f_"); appendEpssButton("f_"); appendDatePicker("f_", "ValidUntilDate"); }
  // BUGBOUNTYPROGRAM: date pickers to the right of StartDate / EndDate
  if (currentTable === "BUGBOUNTYPROGRAM") { appendDatePicker("f_", "StartDate"); appendDatePicker("f_", "EndDate"); }
  // Any form with a validity-end field gets a date picker (no-op if the field is absent).
  appendDatePicker("f_", "ValidUntil"); appendDatePicker("f_", "ValidUntilDate");
  // AI answer suggestion (QUESTION / OCIL form)
  if (currentTable === "QUESTION") appendOcilSuggestPanel(body, "f_");
  // Draft the policy body with the local AI (POLICY form)
  if (currentTable === "POLICY") appendPolicyAiDraftPanel(body, "f_");
  // Generate the crisis-scenario Description with the local AI (CRISISSCENARIO form)
  if (currentTable === "CRISISSCENARIO") { appendCrisisScenarioAiPanel(body, "f_"); appendCrisisAttackMapping(body, "f_"); }
  if (currentTable === "ALERT") appendCrisisAttackMapping(body, "f_"); // ALERT.AttackTechniques → MITRE ATT&CK picker

  // Many-to-many ASSET relation for the INCIDENT table + linked threat actor
  if (currentTable === "INCIDENT") {
    await appendAssetSelector(body, "f", new Set());
    await appendIncidentThreatActor(body, "f_", "");
  }
  // Impacted assets (ALERTFORASSET) for the ALERT table — Defender "Select entities"
  if (currentTable === "ALERT") await appendAssetSelector(body, "f", new Set(), "ALERTFORASSET");

  // CATEGORY dropdown (vocabulary-dependent) for the THREATAGENT table
  if (currentTable === "THREATAGENT") await appendThreatAgentCategory("f_", null);

  // Multi-ASSET selection for the AUDIT table (ASSETAUDIT links)
  if (currentTable === "AUDIT") await appendAuditAssetSelector(body, "f", new Set());

  // CPE table for the ASSET table (widens the modal). New asset: the
  // auto-incremented ID does NOT exist yet in the database → we pass null (CPE/vuln manageable
  // after saving). Otherwise getAssetCpes(nonexistentId) would return 403.
  setModalWide($("insert-modal") as HTMLElement, WIDE_MODAL_TABLES.has(currentTable));
  if (currentTable === "ASSET") {
    resetPendingAssetLinks(); // enables link staging (saved at insertion)
    await appendCpeTable(body, null);
    await appendOvalTable(body, null);
    await appendVulnTable(body, null);
    await appendAuditTable(body, null);
    await appendGeoTable(body, null);
    await appendAssetLocationTable(body, "f_");
    appendTagsPanel(body, "Tags (ASSETTAG)", null, api.getAssetTags, api.setAssetTags, {
      get: () => Array.from(pendingAssetLinks?.tags ?? []),
      set: (tg) => { if (pendingAssetLinks) pendingAssetLinks.tags = new Set(tg); },
    });
    await appendAssetOrgPanel(body, null);
    await appendAssetPersonPanel(body, null);
  } else if (currentTable === "VULNERABILITY") {
    pendingVulnTags = new Set(); // buffered tags (creation) → saved after the insert
    appendTagsPanel(body, "Tags (VULNERABILITYTAG)", null, api.getVulnerabilityTags, api.setVulnerabilityTags, {
      get: () => Array.from(pendingVulnTags ?? []),
      set: (tg) => { pendingVulnTags = new Set(tg); },
    });
  } else if (currentTable === "OVALDEFINITION") {
    pendingOvalTags = new Set(); // buffered tags (creation) → saved after the insert
    appendTagsPanel(body, "Tags (OVALDEFINITIONTAG)", null, api.getOvalDefinitionTags, api.setOvalDefinitionTags, {
      get: () => Array.from(pendingOvalTags ?? []),
      set: (tg) => { pendingOvalTags = new Set(tg); },
    });
  } else if (currentTable === "CPE") {
    appendCpeGcveSearch(body, "f_");
    pendingCpeTags = new Set(); // buffered tags (creation) → saved after the insert
    appendTagsPanel(body, "Tags (CPETAG)", null, api.getCpeTags, api.setCpeTags, {
      get: () => Array.from(pendingCpeTags ?? []),
      set: (tg) => { pendingCpeTags = new Set(tg); },
    });
  } else if (currentTable === "CWE") {
    pendingCweTags = new Set(); // buffered tags (creation) → saved after the insert
    appendTagsPanel(body, "Tags (CWETAG)", null, api.getCweTags, api.setCweTags, {
      get: () => Array.from(pendingCweTags ?? []),
      set: (tg) => { pendingCweTags = new Set(tg); },
    });
  } else if (currentTable === "CONTROL") {
    pendingControlTags = new Set(); // buffered tags (creation) → saved after the insert
    appendTagsPanel(body, "Tags (CONTROLTAG)", null, api.getControlTags, api.setControlTags, {
      get: () => Array.from(pendingControlTags ?? []),
      set: (tg) => { pendingControlTags = new Set(tg); },
    });
  } else if (currentTable === "THREATMODEL") {
    // Scope/threats: handled AFTER creation (the model must exist in the database).
    // We pass null → "save first" hint; querying the phantom id
    // (pre-filled PK MAX+1) would trigger a 403 (nonexistent row, tenant guard).
    await appendThreatModelScope(body, null);
    await appendThreatModelThreats(body, null);
  } else if (currentTable === "THREATMODELTHREAT") {
    // Mitigations: handled after creation (id required). null → "save first"
    // (querying the pre-filled phantom id would trigger a 403, like THREATMODEL).
    await appendThreatMitigations(body, null);
  } else if (currentTable === "QUESTIONNAIRE") {
    pendingQuestionLinks = new Set(); // prepares the links, saved at insertion
    appendQuestionnaireImportButton(body); // "📥 Excel import" at the top of the form
    await appendQuestionnaireQuestions(body, null);
  } else if (currentTable === "THREATREPORT") {
    appendThreatReportImportButton(body, "f_"); // PDF ingestion at the top of the form
  } else if (currentTable === "SIGMARULE") {
    appendSigmaConvertButton(body, "f_"); // Sigma → SPL/KQL/EQL at the top of the form
  } else if (currentTable === "ANSWER") {
    pendingAnswerEvidences = new Set(); // prepares the evidence, saved at insertion
    await appendAnswerEvidences(body, null);
  } else if (currentTable === "THREAT") {
    pendingThreatTtps = new Set(); // prepares the ATT&CK techniques, saved at insertion
    await appendThreatTtps(body, null);
    // Linked assets (XTHREAT.THREATFORASSET) — checked boxes saved after the insert.
    await appendAssetSelector(body, "f", new Set(), "THREATFORASSET");
  } else if (currentTable === "THREATFORASSET") {
    // Multi-asset creation: hide the single AssetName combobox (NAME_SEARCH replaces the raw
    // field with `f_field_AssetID_search`); pick assets via a tag-filterable, check-all selector.
    // ThreatID stays the searchable ThreatName combobox.
    for (const id of ["f_field_AssetID_search", "f_field_AssetID"]) {
      const el = document.getElementById(id); if (el) el.style.display = "none";
    }
    await appendAssetSelector(body, "f", new Set(), "ASSET (one THREATFORASSET per checked asset)", { tagFilter: true, checkAll: true });
  } else if (currentTable === "ASSETVULNERABILITYREMEDIATION") {
    appendRemediationAssetName("f_");
  }

  applyConditionalFields("f_");
  formDirty = false; // fresh form — ignore the programmatic value sets above
  showModalAtTop("insert-modal");
}

async function submitInsert(): Promise<void> {
  // THREATFORASSET: multi-asset creation — one row per checked asset, sharing the
  // chosen threat + Relationship/validity. Bypasses the generic single-row insert.
  if (currentDb === "XTHREAT" && currentTable === "THREATFORASSET") {
    const assetIds = collectCheckedAssets("f");
    if (!assetIds.length) { toast("Sélectionnez au moins un ASSET", "err"); return; }
    const threatId = Number((document.getElementById("f_ThreatID") as HTMLInputElement)?.value);
    if (!threatId) { toast("ThreatName / ThreatID requis", "err"); return; }
    const val = (id: string): string => (document.getElementById(id) as HTMLInputElement | null)?.value?.trim() || "";
    try {
      const r = await api.bulkThreatForAsset({
        threatId, assetIds,
        relationship: val("f_Relationship"), validFrom: val("f_ValidFrom"), validUntil: val("f_ValidUntil"),
      });
      ($("insert-modal") as HTMLElement).style.display = "none";
      toast(`${r.created} THREATFORASSET créé(s)${r.skipped ? ` (${r.skipped} déjà existant)` : ""}`, "ok");
      loadRows();
    } catch (e) {
      toast(t("toast.errInsert") + " " + e, "err");
    }
    return;
  }

  if (!validateRequiredForm("f_", currentTable)) return;

  const row: Record<string, string> = {};
  // Includes all columns, including the primary key (auto-incremented
  // for an integer PK, entered for a text PK).
  schema.forEach((col) => {
    if (isReadonlyFormColumn(currentTable, col.name)) return; // computed column (server)
    const input = document.getElementById(`f_${col.name}`) as HTMLInputElement;
    if (!input) return;
    if (input.type === "checkbox") row[col.name] = fieldValue(input);
    else if (input.value) row[col.name] = input.value;
    // VOCABULARY: CreatedDate / ValidFromDate emptied by the user →
    // we save the current date anyway (safety net)
    else if (currentTable === "VOCABULARY" && isAutoDateCol(col.name)) {
      row[col.name] = todayStr();
    }
  });

  try {
    const insResult = await api.insertRow(currentDb, currentTable, row);
    // "Foreign" creation triggered by a "+" button next to a FK dropdown:
    // returns the new id to the original form (restored) and selects the value.
    if (fkCreateReturn) {
      const ret = fkCreateReturn;
      fkCreateReturn = null;
      const newId = insResult.id != null ? String(insResult.id) : "";
      if (foreignInsertReturn) { foreignInsertReturn(); foreignInsertReturn = null; }
      ($("insert-modal") as HTMLElement).style.display = "none";
      toast(t("toast.rowInserted"), "ok");
      clearNameHintCache();
      await ret(newId);
      return;
    }
    // VULNERABILITY: saves the buffered tags (VULNERABILITYTAG) after the insert.
    if (currentTable === "VULNERABILITY" && pendingVulnTags && pendingVulnTags.size) {
      const vid = Number((document.getElementById("f_VulnerabilityID") as HTMLInputElement)?.value);
      if (vid) { try { await api.setVulnerabilityTags(vid, [...pendingVulnTags]); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
      pendingVulnTags = null;
    }
    // OVALDEFINITION: saves the buffered tags (OVALDEFINITIONTAG) after the insert.
    if (currentTable === "OVALDEFINITION" && pendingOvalTags && pendingOvalTags.size) {
      const oid = Number((document.getElementById("f_OVALDefinitionID") as HTMLInputElement)?.value);
      if (oid) { try { await api.setOvalDefinitionTags(oid, [...pendingOvalTags]); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
      pendingOvalTags = null;
    }
    // CPE: saves the buffered tags (CPETAG) after the insert.
    if (currentTable === "CPE" && pendingCpeTags && pendingCpeTags.size) {
      const cid = Number((document.getElementById("f_CPEID") as HTMLInputElement)?.value);
      if (cid) { try { await api.setCpeTags(cid, [...pendingCpeTags]); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
      pendingCpeTags = null;
    }
    // CWE: saves the buffered tags (CWETAG) after the insert.
    if (currentTable === "CWE" && pendingCweTags && pendingCweTags.size) {
      const cid = Number((document.getElementById("f_CWEID") as HTMLInputElement)?.value);
      if (cid) { try { await api.setCweTags(cid, [...pendingCweTags]); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
      pendingCweTags = null;
    }
    // CONTROL: saves the buffered tags (CONTROLTAG) after the insert.
    if (currentTable === "CONTROL" && pendingControlTags && pendingControlTags.size) {
      const cid = Number((document.getElementById("f_ControlID") as HTMLInputElement)?.value);
      if (cid) { try { await api.setControlTags(cid, [...pendingControlTags]); } catch (e) { toast(t("tag.saveErr") + " " + e, "err"); } }
      pendingControlTags = null;
    }
    // Creation of a VULNERABILITY in the KEV catalog (KEV=1) → notification. Best-effort.
    if (currentTable === "VULNERABILITY" && row["KEV"] === "1") {
      void api.createNotification({
        title: "New KEV vulnerability added",
        message: row["VULReferential"] ? `${row["VULReferential"]} (KEV)` : undefined,
        level: "warning",
      }).catch(() => {});
    }
    // ASSET links (INCIDENTFORASSET) — IncidentID = auto pre-filled PK
    if (currentTable === "INCIDENT") {
      const incidentId = Number((document.getElementById("f_IncidentID") as HTMLInputElement)?.value);
      if (incidentId) {
        try {
          await api.setIncidentAssets(incidentId, collectCheckedAssets("f"));
        } catch (e) {
          toast(t("toast.assetLinksErr") + " " + e, "err");
        }
        // THREATACTOR link (XTHREAT.THREATACTORFORINCIDENT)
        const ta = document.getElementById("f_threatactor") as HTMLInputElement | null;
        if (ta) {
          try {
            await api.setIncidentThreatActor(incidentId, ta.value.trim());
          } catch (e) {
            toast(t("toast.threatActorLinkErr") + " " + e, "err");
          }
        }
      }
    }
    // ASSET links (ASSETAUDIT) — AuditID = auto pre-filled PK
    if (currentTable === "AUDIT") {
      const auditId = Number((document.getElementById("f_AuditID") as HTMLInputElement)?.value);
      if (auditId) {
        try {
          await api.setAuditAssets(auditId, collectAuditAssets("f"));
        } catch (e) {
          toast(t("toast.assetLinksErr") + " " + e, "err");
        }
      }
    }
    // CATEGORY link (THREATAGENTCATEGORY) — ThreatAgentID = auto pre-filled PK
    if (currentTable === "THREATAGENT") {
      const taId = Number((document.getElementById("f_ThreatAgentID") as HTMLInputElement)?.value);
      const catSel = document.getElementById("f_ta_category") as HTMLSelectElement | null;
      if (taId && catSel) {
        try {
          await api.setThreatAgentCategory(taId, catSel.value ? Number(catSel.value) : null);
        } catch (e) {
          toast(t("toast.categoryLinkErr") + " " + e, "err");
        }
      }
    }
    // ASSET links staged in creation (CPE / vuln / OVAL / audits) — AssetID = auto pre-filled PK
    if (currentTable === "ASSET" && pendingAssetLinks) {
      const p = pendingAssetLinks;
      const assetId = Number((document.getElementById("f_AssetID") as HTMLInputElement)?.value);
      if (assetId) {
        try {
          if (p.cpes.size) await api.setAssetCpes(assetId, [...p.cpes.keys()]);
          if (p.vulns.size) await api.setAssetVulnerabilities(assetId, [...p.vulns.keys()]);
          if (p.audits.size) await api.setAssetAudits(assetId, [...p.audits.keys()]);
          for (const ovalId of p.ovals.keys()) await api.addAssetOval(assetId, ovalId);
          if (p.tags.size) await api.setAssetTags(assetId, [...p.tags]);
          if (p.orgs.size) await api.setAssetOrganisations(assetId, [...p.orgs.keys()]);
          if (p.persons.size) await api.setAssetPersons(assetId, [...p.persons.entries()].map(([pid, v]) => ({ personId: pid, relationshiptype: v.role })));
        } catch (e) {
          toast(t("toast.someLinksErr") + " " + e, "err");
        }
      }
      pendingAssetLinks = null;
    }
    // ASSET: after saving (vuln links included), detects the uncorrected KEV
    // ASSETVULNERABILITY rows and notifies. Best-effort (does not block creation).
    if (currentTable === "ASSET") void api.checkAssetKevNotify().catch(() => {});
    // ASSET: when AssetName is an email, capture it into the email directory
    // (EMAIL / EMAILADDRESS / EMAILFORORGANISATION). Idempotent, best-effort.
    if (currentTable === "ASSET") {
      const em = assetNameEmail("f_");
      if (em) void api.harvestAssetEmail(em).then((r) => {
        if (r.emailInserted || r.addressInserted || r.orgLinkInserted) toast(`📧 ${em} added to the email directory`, "ok");
      }).catch(() => {});
    }
    // First-run wizard: after the first ORGANISATION is created, create the
    // "XORCISM Admin account" ASSET + ASSETFORORGANISATION link — OrganisationID
    // = auto pre-filled PK.
    if (currentTable === "ORGANISATION" && setupWizardActive) {
      const orgId = Number((document.getElementById("f_OrganisationID") as HTMLInputElement)?.value);
      if (orgId) finishSetupWizard(orgId);
    }
    // QUESTION links staged at the creation of a QUESTIONNAIRE — QuestionnaireID = auto pre-filled PK
    if (currentTable === "QUESTIONNAIRE" && pendingQuestionLinks) {
      const ids = [...pendingQuestionLinks];
      const qnId = Number((document.getElementById("f_QuestionnaireID") as HTMLInputElement)?.value);
      if (qnId && ids.length) {
        try { await api.setQuestionnaireQuestions(qnId, ids); }
        catch (e) { toast(t("toast.questionLinksErr") + " " + e, "err"); }
      }
      pendingQuestionLinks = null;
    }
    // Evidence staged at the creation of an ANSWER — AnswerID = auto pre-filled PK
    if (currentTable === "ANSWER" && pendingAnswerEvidences) {
      const ids = [...pendingAnswerEvidences];
      const aId = Number((document.getElementById("f_AnswerID") as HTMLInputElement)?.value);
      if (aId && ids.length) {
        try { await api.setAnswerEvidences(aId, ids); }
        catch (e) { toast(t("toast.evidenceLinksErr") + " " + e, "err"); }
      }
      pendingAnswerEvidences = null;
    }
    // ATT&CK techniques staged at the creation of a THREAT — ThreatID = auto pre-filled PK
    if (currentTable === "THREAT" && pendingThreatTtps) {
      const ids = [...pendingThreatTtps];
      const tId = Number((document.getElementById("f_ThreatID") as HTMLInputElement)?.value);
      if (tId && ids.length) {
        try { await api.setThreatTtps(tId, ids); }
        catch (e) { toast(t("toast.techniqueLinksErr") + " " + e, "err"); }
      }
      pendingThreatTtps = null;
    }
    // ASSET links (THREATFORASSET) staged at the creation of a THREAT — ThreatID = auto pre-filled PK
    if (currentTable === "THREAT") {
      const tId = Number((document.getElementById("f_ThreatID") as HTMLInputElement)?.value);
      const aids = collectCheckedAssets("f");
      if (tId && aids.length) {
        try { await api.setThreatAssets(tId, aids); }
        catch (e) { toast(t("toast.assetLinksErr") + " " + e, "err"); }
      }
    }
    // ALERT (XINCIDENT): on creation, save impacted assets then offer to notify all
    // tenant users with read access to XINCIDENT. Best-effort (does not block creation).
    if (currentDb === "XINCIDENT" && currentTable === "ALERT") {
      const alertId = Number((document.getElementById("f_AlertID") as HTMLInputElement)?.value);
      const alertName = (document.getElementById("f_AlertName") as HTMLInputElement)?.value?.trim() || "";
      const impacted = collectCheckedAssets("f");
      if (alertId && impacted.length) {
        try { await api.setAlertAssets(alertId, impacted); } catch (e) { toast(t("toast.assetLinksErr") + " " + e, "err"); }
      }
      if (window.confirm(t("alert.notifyConfirm"))) {
        try {
          const r = await api.notifyAlert(alertId, alertName);
          toast(t("alert.notifySent").replace("{n}", String(r.count ?? 0)), "ok");
        } catch (e) {
          toast(t("alert.notifyErr") + " " + e, "err");
        }
      }
    }
    ($("insert-modal") as HTMLElement).style.display = "none";
    toast(t("toast.rowInserted"), "ok");
    // "Foreign" creation (e.g. new VULNERABILITY or ASSETVULNERABILITYREMEDIATION):
    // restores the original context, clears the label cache and refreshes the original
    // view (e.g. REMEDIATION column updated).
    if (foreignInsertReturn) {
      const ret = foreignInsertReturn;
      foreignInsertReturn = null;
      ret();
      clearNameHintCache();
      loadRows();
      return;
    }
    // ASSETVULNERABILITY: "corrected" status → offer to add evidence.
    if (
      currentTable === "ASSETVULNERABILITY" &&
      offerEvidenceForStatus(
        String(row["AssetVulnerabilityStatusID"] ?? ""),
        String(row["VulnerabilityID"] ?? "")
      )
    ) {
      return; // we navigated to the EVIDENCE form
    }
    // INCIDENT: offer to create an ALERT/NOTIFICATION linked to the new incident.
    if (currentTable === "INCIDENT" && offerAlertForIncident(Number(row["IncidentID"]))) {
      return; // we navigated to the ALERT creation form
    }
    loadRows();
  } catch (e) {
    toast(t("toast.errInsert") + " " + e, "err");
  }
}

// ── Export ────────────────────────────────────────────────────────────────────

// Builds the export matrix (headers + cells) reflecting the CURRENT
// grid COLUMNS: same order/selection (gridCols), renamed header
// labels (gridColLabel), resolved computed columns (injectGridDisplayColumn) and
// displayed values (value labels via gridLabel, e.g. 0/1 → Unpatched/Patched).
async function buildExportMatrix(): Promise<{ headers: string[]; cells: unknown[][] } | null> {
  if (!currentDb || !currentTable) return null;
  const result = await api.exportRows(
    currentDb, currentTable, currentSort || undefined, currentDir,
    currentVocab ? Number(currentVocab) : undefined
  );
  if (result.truncated)
    toast(`${t("toast.exportLimitedA")} ${result.limit.toLocaleString()} ${t("toast.exportLimitedB")} ${result.total.toLocaleString()}`, "ok");
  const data = result.rows as Record<string, unknown>[];
  if (!data.length) return { headers: [], cells: [] };
  // Computed columns (resolved) added as in the grid.
  await injectGridDisplayColumn(data);
  // Current columns: displayed order/selection; falls back to the keys if not rendered.
  const cols = gridCols.length ? gridCols.slice() : Object.keys(data[0]).filter((c) => c !== "rowid");
  const headers = cols.map((c) => gridColLabel(currentTable, c));
  const cells = data.map((r) =>
    cols.map((c) => {
      const lbl = gridLabel(currentTable, c, r[c]); // 0/1 → Unpatched/Patched, etc.
      return lbl != null ? lbl : (r[c] ?? "");
    })
  );
  return { headers, cells };
}

// Button at the top of the form: loads a JSON file and pre-fills the fields.
function appendFormJsonImport(body: HTMLElement, prefix: string): void {
  const div = document.createElement("div");
  div.style.cssText = "margin-bottom:12px;display:flex;justify-content:flex-end";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-ghost btn-sm";
  btn.textContent = t("modal.jsonImport") || "📤 Pré-remplir (JSON)";
  btn.title = t("tip.jsonPrefill");
  const file = document.createElement("input");
  file.type = "file";
  file.accept = ".json,application/json";
  file.style.display = "none";
  btn.onclick = () => file.click();
  file.onchange = async () => {
    const f = file.files?.[0];
    if (!f) return;
    try {
      const data = JSON.parse(await f.text());
      if (!data || typeof data !== "object" || Array.isArray(data)) {
        toast(t("toast.jsonInvalidObject"), "err");
        return;
      }
      const n = applyFormJson(prefix, data as Record<string, unknown>);
      toast(`${t("toast.formPrefilled")} (${n})`, "ok");
    } catch (e) {
      toast(t("toast.errReadJson") + " " + e, "err");
    } finally {
      file.value = "";
    }
  };
  div.appendChild(btn);
  div.appendChild(file);
  body.appendChild(div);
}

// Applies the values of a JSON object to the form fields (by column name).
// Triggers input+change to propagate (name hints, searches, conditional fields,
// resolvers like AssetName). Returns the number of filled fields.
function applyFormJson(prefix: string, data: Record<string, unknown>): number {
  let n = 0;
  for (const [key, value] of Object.entries(data)) {
    if (value == null) continue;
    const el = document.getElementById(`${prefix}${key}`) as HTMLInputElement | null;
    if (!el) continue; // field absent in this form
    const v = typeof value === "object" ? JSON.stringify(value) : String(value);
    if (el.type === "checkbox") {
      el.checked = v === (el.dataset.checked ?? "1") || v === "1" || v.toLowerCase() === "true";
    } else {
      el.value = v;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    n++;
  }
  return n;
}

// Downloads the current form's data (prefix f_/ef_ fields) to Excel
// (vertical layout Field / Value — one field per row).
function downloadFormExcel(prefix: string): void {
  if (!schema.length || !currentTable) return;
  const XLSX = (window as unknown as { XLSX: typeof import("xlsx") }).XLSX;
  const rows: unknown[][] = [["Field", "Value"]];
  for (const col of schema) {
    const input = document.getElementById(`${prefix}${col.name}`) as HTMLInputElement | null;
    if (!input) continue;
    rows.push([col.name, fieldValue(input)]); // checkbox → 0/1; otherwise field value
  }
  try {
    const ws = XLSX.utils.aoa_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, currentTable.slice(0, 31));
    XLSX.writeFile(wb, `${currentDb}_${currentTable}_${new Date().toISOString().slice(0, 10)}.xlsx`);
  } catch (e) {
    toast(t("toast.errExportExcel") + " " + e, "err");
  }
}

// Downloads the current form's data (prefix f_/ef_ fields) to JSON.
function downloadFormJson(prefix: string): void {
  if (!schema.length || !currentTable) return;
  const obj: Record<string, unknown> = {};
  for (const col of schema) {
    const input = document.getElementById(`${prefix}${col.name}`) as HTMLInputElement | null;
    if (!input) continue; // field absent (hidden column handled server-side)
    obj[col.name] = fieldValue(input); // checkbox → 0/1; otherwise field value
  }
  try {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${currentDb}_${currentTable}_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
  } catch (e) {
    toast(t("toast.errExportJson") + " " + e, "err");
  }
}

async function exportCSV(): Promise<void> {
  if (!currentDb || !currentTable) return;
  try {
    const m = await buildExportMatrix();
    if (!m || !m.headers.length) return;
    const esc = (v: unknown): string => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [
      m.headers.map(esc).join(","),
      ...m.cells.map((row) => row.map(esc).join(",")),
    ];
    const bom = "﻿";
    const blob = new Blob([bom + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${currentDb}_${currentTable}.csv`;
    a.click();
  } catch (e) {
    toast(t("toast.errExport") + " " + e, "err");
  }
}

async function exportExcel(): Promise<void> {
  if (!currentDb || !currentTable) return;
  try {
    const m = await buildExportMatrix();
    if (!m || !m.headers.length) return;
    const XLSX = (window as unknown as { XLSX: typeof import("xlsx") }).XLSX;
    const ws = XLSX.utils.aoa_to_sheet([m.headers, ...m.cells]); // forced headers + current order
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, currentTable.slice(0, 31));
    XLSX.writeFile(wb, `${currentDb}_${currentTable}.xlsx`);
  } catch (e) {
    toast(t("toast.errExportExcel") + " " + e, "err");
  }
}

// ── Import JSON ─────────────────────────────────────────────────────────────────

// Extracts an array of rows from the uploaded JSON (array, or object
// containing rows/objects/data/records/items, or single-row object).
function extractRows(data: unknown): Record<string, unknown>[] | null {
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (data && typeof data === "object") {
    for (const key of ["rows", "objects", "data", "records", "items"]) {
      const v = (data as Record<string, unknown>)[key];
      if (Array.isArray(v)) return v as Record<string, unknown>[];
    }
    if (Object.keys(data).length) return [data as Record<string, unknown>];
  }
  return null;
}

// Parses a CSV into rows via SheetJS (handles quotes, separators, headers).
// The 1st line = column names; empty cells omitted.
function parseCsv(text: string): Record<string, unknown>[] {
  const XLSX = (window as unknown as { XLSX: typeof import("xlsx") }).XLSX;
  const wb = XLSX.read(text, { type: "string" });
  const ws = wb.Sheets[wb.SheetNames[0]];
  return XLSX.utils.sheet_to_json(ws, { raw: true, defval: undefined }) as Record<string, unknown>[];
}

async function importFile(file: File): Promise<void> {
  if (!currentDb || !currentTable) return;
  const text = await file.text();
  const isCsv =
    /\.csv$/i.test(file.name) ||
    (file.type.includes("csv")) ||
    !/^\s*[[{]/.test(text); // neither JSON array nor object → treated as CSV

  let rows: Record<string, unknown>[] | null;
  try {
    rows = isCsv ? parseCsv(text) : extractRows(JSON.parse(text));
  } catch {
    toast(isCsv ? t("toast.csvInvalid") : t("toast.jsonInvalid"), "err");
    return;
  }
  if (!rows || !rows.length) {
    toast(t("toast.noRowsInFile"), "err");
    return;
  }

  const replace = ($("import-replace") as HTMLInputElement).checked;
  const kind = isCsv ? "CSV" : "JSON";
  const question = replace
    ? `${t("dialog.replaceA")} ${currentTable} ${t("dialog.replaceB")} ${rows.length} ${t("dialog.rowsKind")} (${kind}) ?\n${t("dialog.replaceWarn")}`
    : `${t("dialog.importA")} ${rows.length} ${t("dialog.rowsKind")} (${kind}) ${t("dialog.importB")} ${currentTable} ?`;
  if (!confirm(question)) return;

  try {
    const r = await api.importRows(currentDb, currentTable, rows, replace);
    const msg =
      (replace ? `${r.cleared} ${t("toast.cleared")}, ` : "") +
      `${r.inserted}/${r.total} ${t("toast.imported")}` +
      (r.failed ? ` — ${r.failed} ${t("toast.failed")}` : "");
    toast(msg, r.failed ? "err" : "ok");
    if (r.failed && r.errors.length) console.warn("Import errors:", r.errors);
    loadRows();
  } catch (e) {
    toast(t("toast.errImport") + " " + e, "err");
  }
}

// ── ORGANISATION wizard at first startup ───────────────────────────────
// At the very first launch (tables created + 1st admin), if no ORGANISATION
// exists, the admin enters the organisation (OrganisationID=1) in a window.
async function maybeShowOrganisationWizard(): Promise<void> {
  let me: { isAdmin?: boolean } | null = null;
  try {
    const r = await fetch("/api/auth/me");
    if (r.ok) me = await r.json();
  } catch { return; }
  if (!me || !me.isAdmin) return;
  try {
    const res = await api.getRows("XORCISM", "ORGANISATION", 1, 0);
    if (res.total > 0) return; // already filled in
  } catch { return; }
  showOrganisationModal();
}

function showOrganisationModal(): void {
  const overlay = document.createElement("div");
  overlay.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;display:flex;align-items:center;justify-content:center";
  const card = document.createElement("div");
  card.style.cssText =
    "background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:22px;width:440px;max-width:94vw";
  const head = document.createElement("div");
  head.innerHTML =
    `<div style="font-size:16px;font-weight:600;color:var(--text);margin-bottom:4px">🏢 ${t("org.title")}</div>` +
    `<div style="font-size:12px;color:var(--text-muted);margin-bottom:14px">${t("org.hint")}</div>`;
  card.appendChild(head);

  const css = "width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;color:var(--text);font-size:13px;margin-bottom:10px";
  const field = (id: string, label: string, type = "text"): HTMLInputElement => {
    const l = document.createElement("label");
    l.textContent = label;
    l.style.cssText = "display:block;font-size:12px;color:var(--text-muted);margin-bottom:3px";
    const i = document.createElement("input");
    i.id = id; i.type = type; i.style.cssText = css;
    card.appendChild(l); card.appendChild(i);
    return i;
  };
  const name = field("org_name", t("org.name") + " *");
  const otype = field("org_type", t("org.type"));
  const industry = field("org_industry", t("org.industry"));
  const employees = field("org_employees", t("org.employees"), "number");

  const err = document.createElement("div");
  err.style.cssText = "color:var(--danger);font-size:12px;min-height:16px;margin:2px 0 8px";
  const btn = document.createElement("button");
  btn.className = "btn btn-primary";
  btn.textContent = t("org.create");
  btn.style.cssText = "width:100%;justify-content:center;padding:10px";
  btn.onclick = async () => {
    const n = name.value.trim();
    if (!n) { err.textContent = t("org.nameRequired"); name.focus(); return; }
    btn.disabled = true; err.textContent = "";
    try {
      await api.insertRow("XORCISM", "ORGANISATION", {
        OrganisationID: 1,
        OrganisationGUID: newGuid(),
        OrganisationName: n,
        OrganisationType: otype.value.trim() || null,
        industry: industry.value.trim() || null,
        employee_count: employees.value ? Number(employees.value) : null,
        CreatedDate: todayStr(),
        ValidFromDate: todayStr(),
        isEncrypted: 0,
      });
      overlay.remove();
      toast(t("org.created"), "ok");
    } catch (e) {
      err.textContent = (e as Error).message;
      btn.disabled = false;
    }
  };
  card.appendChild(err);
  card.appendChild(btn);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
  name.focus();
}

// ── Wire events ───────────────────────────────────────────────────────────────

// ── Notifications (header bell + browser notifications) ────────────────
const NOTIF_SEEN_KEY = "xorcism.notif.lastSeen";
let notifLastSeen = Number(localStorage.getItem(NOTIF_SEEN_KEY) || "0") || 0;
let notifPollTimer: number | undefined;

function notifLevelColor(level: string | null): string {
  switch (level) {
    case "error": return "var(--danger)";
    case "warning": return "#fbbf24";
    case "success": return "var(--success)";
    default: return "var(--accent)";
  }
}

function renderNotifList(items: NotificationItem[]): void {
  const list = document.getElementById("notif-list");
  if (!list) return;
  list.innerHTML = "";
  if (!items.length) {
    list.innerHTML = `<div style="padding:14px 12px;color:var(--text-dim);font-size:12px">${t("notif.empty")}</div>`;
    return;
  }
  for (const n of items) {
    const row = document.createElement("div");
    row.style.cssText =
      "display:flex;gap:8px;padding:9px 12px;border-bottom:1px solid #1e2236;cursor:pointer;" +
      (n.IsRead ? "opacity:.6" : "background:#171b30");
    const dot = document.createElement("span");
    dot.style.cssText = `flex:0 0 8px;width:8px;height:8px;border-radius:50%;margin-top:5px;background:${notifLevelColor(n.Level)}`;
    const body = document.createElement("div");
    body.style.cssText = "flex:1;min-width:0";
    const title = document.createElement("div");
    title.textContent = n.Title;
    title.style.cssText = "font-size:12px;font-weight:600;color:var(--text);word-break:break-word";
    body.appendChild(title);
    if (n.Message) {
      const msg = document.createElement("div");
      msg.textContent = n.Message;
      msg.style.cssText = "font-size:11px;color:var(--text-muted);margin-top:2px;word-break:break-word";
      body.appendChild(msg);
    }
    const meta = document.createElement("div");
    meta.textContent = [n.Source, n.CreatedDate].filter(Boolean).join(" · ");
    meta.style.cssText = "font-size:10px;color:var(--text-dim);margin-top:3px";
    body.appendChild(meta);
    row.appendChild(dot);
    row.appendChild(body);
    row.onclick = () => void onNotifClick(n);
    list.appendChild(row);
  }
}

async function onNotifClick(n: NotificationItem): Promise<void> {
  try { if (!n.IsRead) await api.markNotificationRead(n.NotificationID); } catch { /* ignore */ }
  if (n.Link) { window.location.href = n.Link; return; }
  void refreshNotifications(false);
}

function setNotifBadge(unread: number): void {
  const badge = document.getElementById("notif-badge");
  if (!badge) return;
  if (unread > 0) { badge.textContent = unread > 99 ? "99+" : String(unread); badge.hidden = false; }
  else badge.hidden = true;
}

function maybeDesktopNotify(items: NotificationItem[]): void {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  const fresh = items.filter((n) => n.NotificationID > notifLastSeen && !n.IsRead).slice(0, 3);
  for (const n of fresh) {
    try { new Notification(n.Title, { body: n.Message || "", tag: `xorcism-${n.NotificationID}` }); }
    catch { /* some browsers restrict outside HTTPS */ }
  }
}

async function refreshNotifications(desktop: boolean): Promise<void> {
  try {
    const { items, unread } = await api.getNotifications(30);
    setNotifBadge(unread);
    const panel = document.getElementById("notif-panel");
    if (panel && !panel.hidden) renderNotifList(items);
    if (desktop) maybeDesktopNotify(items);
    const maxId = items.reduce((m, n) => Math.max(m, n.NotificationID), notifLastSeen);
    if (maxId > notifLastSeen) { notifLastSeen = maxId; localStorage.setItem(NOTIF_SEEN_KEY, String(maxId)); }
  } catch { /* not connected / endpoint unavailable */ }
}

function updateNotifEnableBtn(): void {
  const btn = document.getElementById("notif-enable") as HTMLButtonElement | null;
  if (!btn) return;
  const supported = "Notification" in window;
  btn.hidden = !supported || Notification.permission === "granted";
}

function toggleNotifPanel(force?: boolean): void {
  const panel = document.getElementById("notif-panel");
  if (!panel) return;
  const show = force ?? panel.hidden;
  panel.hidden = !show;
  if (show) { applyNotifSavedPos(); updateNotifEnableBtn(); void refreshNotifications(false); }
}

// Saved position of the notifications panel (persisted across sessions).
const NOTIF_POS_KEY = "xorcism.notif.pos";

// Restores the saved position (if valid), bounded to the current window.
// The panel must be visible to be measurable (called after panel.hidden=false).
function applyNotifSavedPos(): void {
  const panel = document.getElementById("notif-panel") as HTMLElement | null;
  if (!panel) return;
  let pos: { left: number; top: number } | null = null;
  try { const raw = localStorage.getItem(NOTIF_POS_KEY); if (raw) pos = JSON.parse(raw); } catch { /* ignore */ }
  if (!pos || typeof pos.left !== "number" || typeof pos.top !== "number") return;
  const w = panel.offsetWidth || 360, h = panel.offsetHeight || 200;
  panel.style.left = Math.max(0, Math.min(pos.left, window.innerWidth - w)) + "px";
  panel.style.top = Math.max(0, Math.min(pos.top, window.innerHeight - h)) + "px";
  panel.style.right = "auto";
  panel.style.bottom = "auto";
}

// Makes the notifications panel draggable by its title bar (#notif-header).
function makeNotifPanelDraggable(): void {
  const panel = document.getElementById("notif-panel") as HTMLElement | null;
  const handle = document.getElementById("notif-header") as HTMLElement | null;
  if (!panel || !handle) return;
  handle.addEventListener("pointerdown", (e) => {
    // Don't start the drag from a header button.
    if ((e.target as HTMLElement).closest("button")) return;
    const rect = panel.getBoundingClientRect();
    // Switch to top/left positioning (the initial CSS is bottom/right).
    panel.style.top = rect.top + "px";
    panel.style.left = rect.left + "px";
    panel.style.bottom = "auto";
    panel.style.right = "auto";
    const sx = e.clientX, sy = e.clientY, ox = rect.left, oy = rect.top;
    handle.setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent): void => {
      const w = panel.offsetWidth, h = panel.offsetHeight;
      const nx = Math.max(0, Math.min(ox + (ev.clientX - sx), window.innerWidth - w));
      const ny = Math.max(0, Math.min(oy + (ev.clientY - sy), window.innerHeight - h));
      panel.style.left = nx + "px";
      panel.style.top = ny + "px";
    };
    const up = (): void => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      try { handle.releasePointerCapture(e.pointerId); } catch { /* ignore */ }
      // Saves the position across sessions.
      try {
        localStorage.setItem(NOTIF_POS_KEY, JSON.stringify({
          left: parseFloat(panel.style.left) || 0, top: parseFloat(panel.style.top) || 0,
        }));
      } catch { /* ignore */ }
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    e.preventDefault();
  });
}

function initNotifications(): void {
  const bell = document.getElementById("notif-bell");
  if (!bell) return; // bell absent (other page)
  makeNotifPanelDraggable();
  bell.addEventListener("click", (e) => { e.stopPropagation(); toggleNotifPanel(); });
  document.getElementById("notif-readall")?.addEventListener("click", async () => {
    try { await api.markAllNotificationsRead(); await refreshNotifications(false); } catch { /* ignore */ }
  });
  // Reduce / minimize: collapse the list to just the header bar (persisted).
  const reduceBtn = document.getElementById("notif-reduce");
  const notifList = document.getElementById("notif-list");
  if (reduceBtn && notifList) {
    const KEY = "xorcism.notif.collapsed";
    const apply = (collapsed: boolean): void => {
      notifList.style.display = collapsed ? "none" : "";
      reduceBtn.innerHTML = collapsed ? "&#9633;" : "&#8211;"; // ▢ restore / – reduce
      reduceBtn.title = collapsed ? t("notif.restore") : t("notif.reduce");
    };
    let collapsed = false;
    try { collapsed = localStorage.getItem(KEY) === "1"; } catch { /* */ }
    apply(collapsed);
    reduceBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      collapsed = !collapsed; apply(collapsed);
      try { localStorage.setItem(KEY, collapsed ? "1" : "0"); } catch { /* */ }
    });
  }
  document.getElementById("notif-enable")?.addEventListener("click", async () => {
    if (!("Notification" in window)) { toast(t("notif.unsupported"), "err"); return; }
    let perm: NotificationPermission = "default";
    try { perm = await Notification.requestPermission(); } catch { /* ignore */ }
    updateNotifEnableBtn();
    if (perm === "granted") toast(t("notif.enabled"), "ok");
    else if (perm === "denied") toast(t("notif.denied"), "err");
    const panel = document.getElementById("notif-panel");
    if (panel) panel.hidden = true; // closes the panel after the permission choice
  });
  // Close the panel on outside click
  document.addEventListener("click", (e) => {
    const panel = document.getElementById("notif-panel");
    if (!panel || panel.hidden) return;
    const tgt = e.target as Node;
    if (!panel.contains(tgt) && !bell.contains(tgt)) panel.hidden = true;
  });
  void refreshNotifications(true);
  notifPollTimer = window.setInterval(() => void refreshNotifications(true), 45000);
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("btn-prev").onclick = () => { currentPage--; loadRows(); };
  $("btn-next").onclick = () => { currentPage++; loadRows(); };
  $("btn-insert").onclick = openInsertModal;
  $("btn-reset-cols").onclick = resetColOrder;
  $("btn-import").onclick = () => {
    if (!currentDb || !currentTable) { toast(t("toast.selectTableFirst"), "err"); return; }
    ($("import-file") as HTMLInputElement).click();
  };
  ($("import-file") as HTMLInputElement).onchange = (e) => {
    const inp = e.target as HTMLInputElement;
    const f = inp.files?.[0];
    inp.value = ""; // allows re-importing the same file
    if (f) void importFile(f);
  };
  $("btn-osv").onclick = importFromOsv;
  document.getElementById("btn-pentest")?.addEventListener("click", togglePentestMode);
  document.getElementById("pentest-launch")?.addEventListener("click", () => void openPentestLaunch());
  document.getElementById("pentest-agent")?.addEventListener("click", () => void bulkAgentScan());
  document.getElementById("pentest-cancel")?.addEventListener("click", togglePentestMode);
  $("btn-circl").onclick = importFromCircl;
  document.getElementById("btn-exploitdb")?.addEventListener("click", () => window.open("/exploitdb", "_blank", "noopener"));
  $("btn-csv").onclick = exportCSV;
  $("btn-excel").onclick = exportExcel;
  $("modal-submit").onclick = submitInsert;
  $("modal-json").onclick = () => downloadFormJson("f_");
  $("modal-excel").onclick = () => downloadFormExcel("f_");
  $("modal-cancel").onclick = () => {
    if (formDirty && !confirm(t("modal.discard"))) return;
    ($("insert-modal") as HTMLElement).style.display = "none";
    if (foreignInsertReturn) { foreignInsertReturn(); foreignInsertReturn = null; } // foreign creation: restores the context
  };
  $("edit-modal-submit").onclick = submitEdit;
  $("edit-modal-json").onclick = () => downloadFormJson("ef_");
  $("edit-modal-excel").onclick = () => downloadFormExcel("ef_");
  $("edit-modal-cancel").onclick = () => {
    if (formDirty && !confirm(t("modal.discard"))) return;
    ($("edit-modal") as HTMLElement).style.display = "none";
    if (foreignEditReturn) { foreignEditReturn(); foreignEditReturn = null; } // foreign editing: restores the context
  };
  // Keyboard: Ctrl/Cmd+Enter saves, Esc cancels (long forms — the buttons may be scrolled away)
  $("edit-modal").addEventListener("keydown", (e) => {
    const ev = e as KeyboardEvent;
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") { ev.preventDefault(); void submitEdit(); }
    else if (ev.key === "Escape") { ev.preventDefault(); ($("edit-modal-cancel") as HTMLElement).click(); }
  });
  $("insert-modal").addEventListener("keydown", (e) => {
    const ev = e as KeyboardEvent;
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") { ev.preventDefault(); void submitInsert(); }
    else if (ev.key === "Escape") { ev.preventDefault(); ($("modal-cancel") as HTMLElement).click(); }
  });
  // Unsaved-changes guard: mark dirty only on real user input (isTrusted), not programmatic value sets.
  for (const bid of ["modal-body", "edit-modal-body"]) {
    const el = document.getElementById(bid);
    if (!el) continue;
    el.addEventListener("input", (e) => { if (e.isTrusted) formDirty = true; });
    el.addEventListener("change", (e) => { if (e.isTrusted) formDirty = true; });
  }
  $("cpe-modal-submit").onclick = submitCpe;
  $("cpe-modal-cancel").onclick = () => { ($("cpe-modal") as HTMLElement).style.display = "none"; };
  ($("cpe-filter") as HTMLInputElement).oninput = (e) => filterCpeList((e.target as HTMLInputElement).value);
  document.getElementById("cpe-add-btn")?.addEventListener("click", () => void addCpeManual());
  ($("cpe-add-input") as HTMLInputElement).addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") { e.preventDefault(); void addCpeManual(); }
  });
  $("vuln-modal-submit").onclick = submitVuln;
  // "Add new vulnerability": opens the VULNERABILITY creation form (XVULNERABILITY)
  $("vuln-add-new").onclick = () => void openForeignInsertModal("XVULNERABILITY", "VULNERABILITY");
  $("vuln-modal-cancel").onclick = () => { ($("vuln-modal") as HTMLElement).style.display = "none"; };
  ($("vuln-search") as HTMLInputElement).oninput = (e) => {
    const v = (e.target as HTMLInputElement).value;
    if (vulnSearchDebounce) clearTimeout(vulnSearchDebounce);
    vulnSearchDebounce = setTimeout(() => runVulnSearch(v), 350);
  };

  // Search
  const searchInput = $("search-input") as HTMLInputElement;
  searchInput.oninput = (e) => onSearchInput((e.target as HTMLInputElement).value);
  searchInput.onkeydown = (e) => {
    if (e.key === "Escape") clearSearch();
    if (e.key === "Enter") {
      if (searchDebounce) clearTimeout(searchDebounce);
      currentSearch = searchInput.value;
      currentPage = 0;
      loadRows();
    }
  };
  $("btn-search-clear").onclick = clearSearch;

  void initVocabFilter();
  init();
  initNotifications();
  void maybeShowOrganisationWizard();
});
