/**
 * index.ts — XORCISM Express server (with XID authentication + RBAC)
 */

import "express-async-errors";
import express, { Request, Response, NextFunction } from "express";
import compression from "compression";
import path from "path";
import explorerRouter from "./routes/explorer";
import biaRouter from "./routes/bia";
import authRouter from "./routes/auth";
import oidcRouter from "./routes/oidc";
import adminRouter from "./routes/admin";
import connectorsRouter, { warmManifestCache } from "./routes/connectors";
import workerApiRouter from "./routes/worker_api";
import vaultRouter from "./routes/vault";
import { agentTokenRouter, agentAdminRouter } from "./routes/agent";
import { getAgentDb } from "./agents";
import feedbackRouter from "./routes/feedback";
import prefsRouter from "./routes/prefs";
import notificationsRouter from "./routes/notifications";
import ocilRouter from "./routes/ocil";
import osvRouter from "./routes/osv";
import pentestRouter from "./routes/pentest";
import { ensurePentestColumns } from "./engagements";
import { ensureChainTables, startChainEngine } from "./chain";
import screenshotRouter from "./routes/screenshot";
import circlRouter from "./routes/circl";
import exploitdbRouter from "./routes/exploitdb";
import fusionRouter from "./routes/fusion";
import attackPathRouter from "./routes/attackpath";
import purpleTeamRouter from "./routes/purpleteam";
import ransomwareRouter from "./routes/ransomware";
import assuranceRouter from "./routes/assurance";
import slaRouter from "./routes/sla";
import { ensureSlaColumns } from "./sla";
import pirRouter from "./routes/pir";
import identitiesRouter from "./routes/identities";
import assetsRouter from "./routes/assets";
import easmRouter from "./routes/easm";
import frameworksRouter from "./routes/frameworks";
import { ensureFrameworkVocabulary, seedFrameworks } from "./frameworks";
import { ensureTahitiColumns } from "./hunting";
import { ensureAiGuardTables } from "./aiguard";
import incidentsRouter from "./routes/incidents";
import complianceRouter from "./routes/compliance";
import otSecurityRouter from "./routes/otsecurity";
import patchMgmtRouter from "./routes/patchmgmt";
import ovalEditorRouter from "./routes/ovaleditor";
import monitoringRouter from "./routes/monitoring";
import control53Router from "./routes/control53";
import trustCenterRouter from "./routes/trustcenter";
import investmentRouter from "./routes/investment";
import bugBountyRouter from "./routes/bugbounty";
import vulnMgmtRouter from "./routes/vulnmgmt";
import orgChartRouter from "./routes/orgchart";
import attackTreeRouter from "./routes/attacktree";
import cloudSecRouter from "./routes/cloudsec";
import awarenessRouter from "./routes/awareness";
import malscanRouter from "./routes/malscan";
import journeysRouter from "./routes/journeys";
import questionnaireJourneysRouter from "./routes/questionnaires";
import tprmRouter from "./routes/tprm";
import { seedTprmDemo } from "./tprm";
import zeroTrustRouter from "./routes/zerotrust";
import { seedZtFunctions, seedZtSigninDemo, seedZtPolicyDemo } from "./zerotrust";
import itdrRouter from "./routes/itdr";
import { seedItdrDemo } from "./itdr";
import identityGovRouter from "./routes/identity-governance";
import { seedIdGovDemo } from "./identitygov";
import socRouter from "./routes/soc";
import soccmmRouter from "./routes/soccmm";
import certopsRouter from "./routes/certops";
import governanceRouter from "./routes/governance";
import aiexchangeRouter from "./routes/aiexchange";
import workforceRouter from "./routes/workforce";
import teamopsRouter from "./routes/teamops";
import vocRouter from "./routes/voc";
import vmtrendsRouter from "./routes/vmtrends";
import boardreportRouter from "./routes/boardreport";
import privacyRouter from "./routes/privacy";
import { ensurePrivacyTables, seedPrivacy } from "./privacy";
import soarCockpitRouter from "./routes/soar";
import { ensureSoarOpsTables, seedSoarOps, seedOdessaPlaybook } from "./soar";
import { backfillPolicyVersions } from "./policies";
import endpointQueryRouter from "./routes/endpointquery";
import { ensureEndpointQueryTables, seedEndpointQueryDemo } from "./endpointquery";
import ctemRouter from "./routes/ctem";
import { seedCtemIdentifiers } from "./ctem";
import ctiExpertRouter from "./routes/ctiexpert";
import { ensureCtiExpertTables } from "./ctiexpert";
import threatCopilotRouter from "./routes/threatcopilot";
import crqRouter from "./routes/crq";
import vulnAuditRouter from "./routes/vulnaudit";
import wifiPentestRouter from "./routes/wifipentest";
import { ensureWifiTables } from "./wifipentest";
import regObligationsRouter from "./routes/regobligations";
import { ensureRegObligationTables, seedRegObligationCatalogue } from "./regobligations";
import aiSystemsRouter from "./routes/aisystems";
import { ensureAiSystemTables } from "./aisystems";
import crocDigestRouter from "./routes/crocdigest";
import kgraphRouter from "./routes/kgraph";
import msspRouter from "./routes/mssp";
import orchestratorRouter from "./routes/orchestrator";
import { ensureOrchestratorTables, startOrchestrator } from "./orchestrator";
import siemRouter from "./routes/siem";
import { ensureSiemTables } from "./siem";
import aibasRouter from "./routes/aibas";
import { ensureAibasTables } from "./aibas";
import chatopsRouter from "./routes/chatops";
import teamsRouter from "./routes/teams";
import { ensureTeamsTables } from "./teams";
import crocRouter from "./routes/croc";
import { ensureCrocTables, seedCrocPolicies, ensureLoopHealthTable, startResilienceAccrual, startLoopDigest, seedCrocDemo } from "./croc";
import { ensureTicketingTargets } from "./ticketing";
import { ensureIamTargets } from "./iam";
import { ensureSoarTables } from "./soar";
import { ensureLandingAccessTable, FEATURE_PAGE_PATHS, canAccessFeaturePage } from "./landingaccess";
import landingRouter from "./routes/landing";
import stixStoreRouter from "./routes/stixstore";
import { startStixStoreSync } from "./stixstore";
import blobRouter from "./routes/blob";
import { ensureBlobStore } from "./blobstore";
import netflowRouter from "./routes/netflow";
import osintGraphRouter from "./routes/osintgraph";
import policiesRouter from "./routes/policies";
import configurationRouter from "./routes/configuration";
import crisisRouter from "./routes/crisis";
import fairmamRouter from "./routes/fairmam";
import fairtefRouter from "./routes/fairtef";
import devsecopsRouter from "./routes/devsecops";
import riskRegisterRouter from "./routes/riskregister";
import pqcmmRouter from "./routes/pqcmm";
import ess8Router from "./routes/ess8";
import { ensureEss8Tables, seedEss8Demo } from "./ess8";
import threatDebtRouter from "./routes/threatdebt";
import { ensureThreatDebtTables, seedThreatDebtDemo } from "./threatdebt";
import insuranceRouter from "./routes/insurance";
import { ensureInsuranceTables } from "./insurance";
import aiDetectRouter from "./routes/aidetect";
import { ensureAiDetectTables, seedAiUsageDemo } from "./aidetect";
import llmPentestRouter from "./routes/llmpentest";
import { ensureLlmPentestTables, seedLlmPentestDemo } from "./llmpentest";
import aiSkillsRouter from "./routes/aiskills";
import { ensureAiSkillsTables, seedAiSkillsDemo } from "./aiskills";
import regIncidentRouter from "./routes/regincident";
import { ensureRegIncidentTables } from "./regincident";
import slsaRouter from "./routes/slsa";
import { ensureSlsaTables, seedSlsaDemo } from "./slsa";
import scaRouter from "./routes/sca";
import { seedScaDemo } from "./sca";
import toolsRouter from "./routes/tools";
import tidRouter from "./routes/tid";
import v1Router from "./routes/v1";
import apikeysRouter from "./routes/apikeys";
import webhooksRouter from "./routes/webhooks";
import { apiKeyAuth } from "./apikey";
import ctiRouter from "./routes/cti";
import driftRouter from "./routes/drift";
import contentRouter from "./routes/content";
import { ensureDriftTable } from "./drift";
import aiRouter from "./routes/ai";
import uploadRouter, { UPLOAD_DIR } from "./routes/upload";
import threatReportRouter from "./routes/threatreport";
import sigmaRouter from "./routes/sigma";
import epssRouter from "./routes/epss";
import huntingRouter from "./routes/hunting";
import threatFeedsRouter from "./routes/threatfeeds";
import { antibot } from "./antibot";
import { getJobDb, ensureCveSchedule, ensureBoardReportSchedule } from "./jobs";
import { startScheduler } from "./scheduler";
import { ensureCveMatchTables, startCveMatcher } from "./cvematch";
import { startMonitorChecker } from "./monitorcheck";
import { startThreatFeedPoller } from "./feeds";
import { startRiskScoreLoop } from "./riskscore";
import {
  loadUser,
  requireAuthGate,
  requireAdmin,
  requirePageApi,
  userCanPage,
  seedAdmin,
} from "./auth";
import { purgeExpiredSessions, seedFeaturePageGrants } from "./xid";
import { ensureSchemaDbs, seedData, ensureTenantColumns, ensureThreatModelTables, ensureComplianceDb, ensureTicketDb, ensureThreatTables, ensureIncidentTables, ensureOpenctiColumns, ensureEmulationTables, ensureGrcColumns, ensureBugBountyTables, ensureEbiosTables, ensureNist80030Tables, ensureOtSecurityTables, ensurePatchTables, ensureMonitoringTables, ensureControlImplementationTables, ensureCisBenchmarkTables, ensureTrustCenterTables, ensureAssetColumns, ensureAssetPrimaryKey, ensureIdentityTables, ensureOvalScanTables, ensureVulnerabilityColumns, ensureDocumentSensitivity, ensurePersonOrgChartColumns, ensureAwarenessTables, ensureMalwareScanTables, ensureCloudComplianceTables, ensureComplianceJourneyTables, ensureQuestionnaireRunTables, ensureTprmTables, ensureZeroTrustTables, ensureZtSigninTable, ensureZtPolicyTable, ensureItdrTables, ensureIdGovTables, ensureNotificationRuleTable, ensureSocTables, ensureSocCmmTables, ensureCertOpsTables, ensureGovernanceTables, ensureAiThreatTables, ensureWorkforceTables, ensureTeamOpsTables, ensureVocTables, ensureVmTrendsTables, ensureCtemTables, ensureStixObjectStore, ensureDevSecOpsTables, ensureNetflowTables, ensureToolDocumentTable, ensureOrganisationRiskScoreTable, ensureFairMamTables, ensurePqcmmTables, ensureScaTables, ensureToolStarTable, ensurePolicyAckTable, ensurePolicyVersionTable, startReplicaSync, dbDriver } from "./db";
import { tr } from "./i18n";

const PORT = Number(process.env.PORT) || 9292;
const app = express();
app.disable("x-powered-by");

// ── Security headers (OWASP Secure Headers Project) ────────────────────────
app.use((req: Request, res: Response, next: NextFunction) => {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  // Disables unused browser APIs (OWASP: reduced attack surface)
  res.setHeader(
    "Permissions-Policy",
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"
  );
  // Cross-origin isolation (anti-XS-Leaks / Spectre)
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // HSTS: only on HTTPS (ignored by browsers over cleartext anyway)
  if (secure) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      // CDNs used: Chart.js (jsdelivr) and SheetJS (sheetjs.com); inline required by the pages
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.sheetjs.com",
      "style-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
      "object-src 'none'",
      "frame-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      ...(secure ? ["upgrade-insecure-requests"] : []),
    ].join("; ")
  );
  next();
});

// ── Middleware ────────────────────────────────────────────────────────────────
// gzip responses. The client bundles are i18n-string-heavy (each page inlines the 11-language
// dictionary → ~800 KB–1.4 MB unminified), which compresses ~6× (app.js 1.1 MB → ~325 KB). This
// is the single biggest first-load win. Runs first so it wraps both static assets and JSON APIs.
app.use(compression());
// stash the raw body so webhook receivers (ChatOps / Slack) can verify HMAC signatures
const keepRaw = (req: Request, _res: Response, buf: Buffer): void => { (req as Request & { rawBody?: Buffer }).rawBody = buf; };
app.use(express.json({ limit: "25mb", verify: keepRaw })); // large JSON imports
app.use(express.urlencoded({ extended: true, limit: "25mb", verify: keepRaw }));
app.use(antibot); // anti-bot / anti-scraping (rate + UA + bursts)
app.use(loadUser); // populates req.user from the session cookie

// Static resources (public — needed by the login page)
app.use("/js", express.static(path.join(__dirname, "../../dist/client/js")));
app.use("/css", express.static(path.join(__dirname, "../../client/css")));
app.use(
  "/vendor/xlsx.full.min.js",
  express.static(path.join(__dirname, "../../node_modules/xlsx/dist/xlsx.full.min.js"))
);

// Authentication routes (public login; the others check req.user)
app.use("/api/auth", authRouter);
app.use("/api/auth", oidcRouter); // OAuth/OIDC (public login + callback)

// Remote workers + XOR agents API: authenticated by TOKEN (no session) → before the gate
app.use("/api", workerApiRouter);
app.use("/api", agentTokenRouter);

// API-key auth: populates req.user from Authorization: Bearer xor_… / X-API-Key
// when there's no session, so the REST API works for programmatic clients.
app.use(apiKeyAuth);

// ── Authentication gate (everything else requires a session) ─────────────────
app.use(requireAuthGate);

// ── Protected APIs ──────────────────────────────────────────────────────────────
app.use("/api/admin", requireAdmin, adminRouter);
app.use("/api/bia", requirePageApi("/bia"), biaRouter);
app.use("/api", vaultRouter); // encryption vault (each route checks admin)
app.use("/api", agentAdminRouter); // XOR agents (list, events, launch a scan)
app.use("/api", feedbackRouter); // user feedback (ratings / improvements)
app.use("/api", prefsRouter); // user preferences (CTI feeds, display…)
app.use("/api", notificationsRouter); // notifications (header bell + browser)
app.use("/api", ocilRouter); // OCIL 2.0 import/export of XCOMPLIANCE questionnaires
app.use("/api", osvRouter); // OSV.dev integration (lookup + VULNERABILITY import)
app.use("/api", pentestRouter); // Pentest mode: bulk scan of assets
app.use("/api", screenshotRouter); // URL screenshot (ASSET websiteurl → AssetImage)
app.use("/api", circlRouter); // CIRCL vulnerability-lookup (KEV search + import)
app.use("/api", exploitdbRouter); // Exploit-DB search (local SearchSploit index) + CVE→exploit lookup
app.use("/api", fusionRouter); // exploitability & relevance fusion score + prioritized exposure worklist
app.use("/api", attackPathRouter); // attack-path & choke-point graph (reachability entry→crown-jewel)
app.use("/api", purpleTeamRouter); // purple-team: chain ATT&CK detection coverage (Sigma) + rule generation
app.use("/api", ransomwareRouter); // ransomware-to-$ scenario simulator (BIA/FAIR impact + D3FEND controls)
app.use("/api", assuranceRouter); // continuously-proven compliance (control assurance from live telemetry)
app.use("/api", slaRouter); // incident SLA view: incidents measured against asset-defined resolution SLAs
app.use("/api", pirRouter); // Priority Intelligence Requirements coverage register
app.use("/api", identitiesRouter); // IAM: identity inventory (human + non-human) + governance findings
app.use("/api", assetsRouter); // Asset Management: asset inventory + governance worklist
app.use("/api", easmRouter); // EASM: external attack surface inventory + exposures worklist
app.use("/api", frameworksRouter); // Frameworks management: FRAMEWORK catalogue + VOCABULARY mapping
app.use("/api", incidentsRouter); // Incident Management: incident inventory + governance worklist
app.use("/api", complianceRouter); // Compliance Management: audit inventory + findings/policy worklist
app.use("/api", otSecurityRouter); // OT Security: IEC 62443 / NIST 800-82 OT assessments + OT assets + zones
app.use("/api", patchMgmtRouter); // Patch Management: asset↔vuln patch status, SLAs, remediation plans
app.use("/api", ovalEditorRouter); // OVAL Definition editor: author defs + criteria trees reusing imported OVAL tests
app.use("/api", monitoringRouter); // Asset Monitoring: uptime/SSL/incident monitors over ASSET
app.use("/api", control53Router); // NIST SP 800-53 control management: catalogue + implementation status + baselines + posture
app.use("/api", trustCenterRouter); // Trust Center: admin config + PUBLIC read-only posture (/api/public/trust/:slug)
app.use("/api", investmentRouter); // Agentic Security Investment Advisor: what-if simulation + local-AI recommendation
app.use("/api", bugBountyRouter); // Bug Bounty Management: programmes + submissions inventory + triage worklist
app.use("/api", vulnMgmtRouter); // Vulnerability Management: vuln-centric inventory (KEV/CVSS/EPSS/SSVC) + triage worklist
app.use("/api", orgChartRouter); // Org Chart: PERSON management hierarchy (Entra/AD-aligned)
app.use("/api", attackTreeRouter); // Attack Trees: AND/OR threat-model decomposition + feasibility rollup
app.use("/api", cloudSecRouter); // Cloud Security: cloud asset inventory + exposure worklist + CCM posture
app.use("/api", awarenessRouter); // Security Awareness: training catalogue + phishing simulations + human-risk
app.use("/api", malscanRouter); // Malware scan: multi-engine IOC/file reputation (VT/OpenTIP/ANY.RUN/…) → XMALWARE
app.use("/api", journeysRouter); // Compliance journeys: guided multi-framework wizard (ISO/SOC2/NIST/NIS2/DORA/CRA/MiCA/FedRAMP)
app.use("/api", questionnaireJourneysRouter); // Questionnaire journeys: guided runner for QUESTIONNAIREs (OCIL, CSA AI-CAIQ TPRM)
app.use("/api", tprmRouter); // TPRM cockpit: vendor risk, outside-in posture, questionnaire conformance, AI copilots
app.use("/api", zeroTrustRouter); // Zero Trust cockpit: CISA ZTMM maturity + live pillar signals + fused trust score
app.use("/api", itdrRouter); // ITDR: identity threat detection (sign-in telemetry + posture) → ATT&CK-mapped detections + response
app.use("/api", identityGovRouter); // IGA/IDMS: access certification campaigns + lifecycle posture + revocation worklist over IDENTITY
app.use("/api", socRouter); // SOC Operations: shifts/on-call, MTTD/MTTA/MTTR, escalation procedure, IR playbooks
app.use("/api", soccmmRouter); // SOC-CMM maturity self-assessment
app.use("/api", certopsRouter); // CERT/CSIRT operations: forensic cases + chain of custody
app.use("/api", governanceRouter); // Governance: NIST CSF 2.0 Govern (GV) register
app.use("/api", aiexchangeRouter); // OWASP AI Exchange agent threat advisor
app.use("/api", workforceRouter); // NICE + ENISA ECSF workforce roles around PERSON
app.use("/api", teamopsRouter); // Purple/Red/Blue Team Operations: ATT&CK exercises + capabilities + automations
app.use("/api", vocRouter); // Vulnerability Operations Center: SLA policy, campaigns, exceptions, remediation KPIs
app.use("/api", vmtrendsRouter); // VM executive report: risk & SLA posture trends over time + data-driven myth-busting
app.use("/api", boardreportRouter); // Board cyber-risk report: 6 board questions, Likelihood × Impact, posture trend
app.use("/api", privacyRouter); // GDPR / DPO cockpit: RoPA (Art 30) + DSAR + DPIA + breach register (Art 33/34)
app.use("/api", soarCockpitRouter); // SOAR cockpit: orchestration playbooks (trigger→actions) + run engine
app.use("/api", endpointQueryRouter); // Tanium-style real-time endpoint querying (Interact): sensors + answer grid
app.use("/api", ctemRouter); // CTEM (ctem.org): standardized exposure-identifier taxonomy + 3-stage exposure cockpit
app.use("/api", ctiExpertRouter); // CTI-Expert: AI-orchestrated OSINT investigation (cti-expert skill → local AI)
app.use("/api", threatCopilotRouter); // Threat-Intel Copilot (Exvora-inspired): decision-ready triage + multi-mode analyst
app.use("/api", crqRouter); // CRQ decision support (Gartner-aligned): operationalize FAIR/CRQ ALE into decisions
app.use("/api", vulnAuditRouter); // Vulnerability Assessment (Vulners-style): software inventory → enriched vuln report
app.use("/api", wifiPentestRouter); // Wi-Fi pentest: local Wi-Fi security assessment (netsh/nmcli survey → A–F grading + toolkit)
app.use("/api", regObligationsRouter); // Regulatory calendar: obligations & deadlines (EU AI Act/DORA/NIS2/CRA/GDPR) → REGOBLIGATION
app.use("/api", aiSystemsRouter); // AI system inventory + AI-BOM + model-risk register (AISYSTEM, XORCISM)
app.use("/api", crocDigestRouter); // CROC daily digest ("standup"): cross-cutting deltas + prioritised actions
app.use("/api", kgraphRouter); // Unified security knowledge graph (asset↔software↔vuln↔risk↔incident) + blast radius
app.use("/api", msspRouter); // MSSP multi-tenant rollup (super-admin cross-tenant posture)
app.use("/api", orchestratorRouter); // Agentic CROC orchestrator: LOOPEVENT → proposed actions → human approval (CROCACTION)
app.use("/api", siemRouter); // SIEM-lite: log ingest → Sigma detection → ALERT + LOOPEVENT (SIEMEVENT, XINCIDENT)
app.use("/api", aibasRouter); // LLM red-team / AI-BAS: OWASP-LLM probe assessment of registered AI systems (AIBASRUN/RESULT)
app.use("/api", chatopsRouter); // Two-way ChatOps: query posture + approve orchestrator actions from Slack/Teams (signed) or the console
app.use("/api", teamsRouter); // Microsoft Teams: alert/notification distribution (webhook targets + test)
app.use("/api", crocRouter); // CROC: Continuous Defense Loop cockpit (event bus + pre-auth policies + bidirectional flow)
app.use("/api", landingRouter); // landing-menu NICE filter + access config for the current user
app.use("/api", stixStoreRouter); // Lossless STIX retention + FTS search: /stix/object/:id, /stix/search, /stix/ingest
app.use("/api", blobRouter); // Content-addressed blob store: GET /blob/:sha256, /blob/stats (large files by hash)
app.use("/api", netflowRouter); // NetFlow around ASSET: discovered assets, services, sessions cartography (obserae)
app.use("/api", osintGraphRouter); // OSINT Link Analysis: entity-link graph over INTELEXCHANGE
app.use("/api", policiesRouter); // Policy & Document Management: policy lifecycle + document register worklist
app.use("/api", configurationRouter); // Configuration Management: OVAL secure-config content library + verification worklist
app.use("/api", crisisRouter); // Crisis Management: tabletop-exercise readiness + scenario library + improvement worklist
app.use("/api", fairmamRouter); // FAIR-MAM: materiality assessment (loss-magnitude decomposition + verdict)
app.use("/api", fairtefRouter); // FAIR-TEF: threat/loss event frequency estimation (Monte Carlo over PERT factors)
app.use("/api", devsecopsRouter); // DevSecOps operations: pipeline security scans coverage + gates + posture
app.use("/api", riskRegisterRouter); // Risk Register: inherent→residual posture + treatment worklist (CRQ/FAIR ALE)
app.use("/api", pqcmmRouter); // PQCMM: post-quantum-crypto maturity assessment (quantum-readiness posture)
app.use("/api", ess8Router); // Essential Eight: ASD maturity-model assessment (backed by the ACSC ISM import)
app.use("/api", threatDebtRouter); // Adversary Opportunity Index (AOI): path-organized "threat debt" top-line + STOCK/FLOW
app.use("/api", insuranceRouter); // Cyber Insurance Readiness: insurer control checklist mapped to live signals
app.use("/api", aiDetectRouter); // AI runtime anomaly detection: usage telemetry → extraction/jailbreak/drift
app.use("/api", llmPentestRouter); // LLM Application Penetration Test methodology (OWASP-LLM-2025 engagement tracker)
app.use("/api", aiSkillsRouter); // AI Operations: Skills/Prompt library + AI activity log + agent handover routing
app.use("/api", regIncidentRouter); // Regulatory incident-reporting obligations: DORA/NIS2/GDPR/CRA deadlines
app.use("/api", slsaRouter); // SLSA supply-chain level tracker (build integrity L0-L3)
app.use("/api", scaRouter); // SCA / SBOM: software composition analysis, CycloneDX/SPDX import-export + graph
app.use("/api", toolsRouter); // TOOL catalogue + GitHub-style stars (/tools)
app.use("/api", tidRouter); // Threat-Informed Defense: ATT&CK technique coverage (adversary use vs detect/mitigate/test)
app.use("/api/v1", v1Router); // public REST API v1 (API-key auth, read-only, tenant-scoped)
app.use("/api", apikeysRouter); // manage your own API keys (session-authenticated)
app.use("/api", webhooksRouter); // manage outbound webhooks (session-authenticated)
app.use("/api", ctiRouter); // "CTI that acts": intel cross-referenced with inventory + auto-ticket
app.use("/api", driftRouter); // attack-surface drift (snapshot + diff)
app.use("/api", contentRouter); // content hub exports (OpenVEX, Sigma bundle)
app.use("/api", aiRouter); // local AI (Ollama): "Ask the threat model" + OCIL suggestion
app.use("/api", uploadRouter); // file upload (evidence, etc.)
app.use("/api", threatReportRouter); // THREATREPORT PDF ingestion → IOC / THREATACTOR
app.use("/api", sigmaRouter); // Sigma rule → SPL / KQL / EQL conversion
app.use("/api", epssRouter); // FIRST.org EPSS lookup (VULNERABILITY form)
app.use("/api", huntingRouter); // Threat Hunting domain (HUNT/IOC/XTHREAT + AI hunt assistant)
app.use("/api", threatFeedsRouter); // curated CTI RSS feeds (THREATFEED) + server-side fetch/parse
app.use("/api", connectorsRouter);
app.use("/api", explorerRouter);

// Uploaded files — served only to authenticated users (after the gate).
// Images/PDF inline (preview); everything else forced to download to neutralize
// execution of malicious HTML/SVG served from our origin.
const INLINE_OK = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"]);
app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    setHeaders: (res, filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      res.setHeader("Content-Disposition", INLINE_OK.has(ext) ? "inline" : "attachment");
      res.setHeader("X-Content-Type-Options", "nosniff");
    },
  })
);

// ── Pages HTML ──────────────────────────────────────────────────────────────────
const CLIENT_DIR = path.join(__dirname, "../../client");

// Page access guard (page-level RBAC; Admin = full access)
function pageGuard(pagePath: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (userCanPage(req.user, pagePath)) return next();
    res.status(403).send(tr(req, "page.deniedHtml"));
  };
}

// Unified feature access: a managed feature page (a landing card with a real route) requires BOTH the
// role's `page:<path>` RBAC grant AND the NICE-profile access control (LANDINGACCESS) — admins bypass
// both. Runs after requireAuthGate (req.user set), on top of each route's base pageGuard("/"). No route edits.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.method !== "GET" || !FEATURE_PAGE_PATHS.has(req.path)) return next();
  if (canAccessFeaturePage(req.user, req.path)) return next();
  res.status(403).send(tr(req, "page.deniedHtml"));
});

app.get("/login", (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "login.html"));
});
app.get("/register", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "register.html")));
app.get("/forgot", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "forgot.html")));
app.get("/reset", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "reset.html")));
app.get("/feedback", pageGuard("/"), (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "feedback.html")));

app.get("/", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "index.html"));
});

app.get("/bia", pageGuard("/bia"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "bia.html"));
});

app.get("/bia-graph", pageGuard("/bia"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "bia-graph.html"));
});
app.get("/dashboard", pageGuard("/dashboard"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "dashboard.html"));
});

app.get("/threat-feeds", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-feeds.html"));
});

app.get("/attack", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack.html"));
});
app.get("/kill-chain", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "kill-chain.html"));
});
app.get("/d3fend", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "d3fend.html"));
});
app.get("/ask", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ask.html"));
});
app.get("/cloud-attacks", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "mitigant.html"));
});
app.get("/a3m", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "a3m.html"));
});
app.get("/hunting", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "hunting.html"));
});
app.get("/tprm", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "tprm.html"));
});
app.get("/ebios", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ebios.html"));
});
app.get("/nist-800-30", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "nist-800-30.html"));
});
app.get("/ot-security", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ot-security.html"));
});
app.get("/patch-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "patch-management.html"));
});
app.get("/asset-monitoring", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "asset-monitoring.html"));
});
app.get("/control-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "control-management.html"));
});
app.get("/trust-center", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "trust-center.html"));
});
app.get("/investment-advisor", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "investment-advisor.html"));
});
app.get("/bug-bounty", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "bug-bounty.html"));
});
app.get("/vulnerability-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "vulnerability-management.html"));
});
app.get("/easm", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "easm.html"));
});
app.get("/frameworks", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "frameworks.html"));
});
app.get("/org-chart", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "org-chart.html"));
});
app.get("/attack-tree", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack-tree.html"));
});
app.get("/cloud-security", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cloud-security.html"));
});
app.get("/security-awareness", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "security-awareness.html"));
});
app.get("/malware-scan", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "malware-scan.html"));
});
app.get("/compliance-journeys", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "compliance-journeys.html"));
});
app.get("/questionnaire-journeys", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "questionnaire-journeys.html"));
});
app.get("/zero-trust", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "zero-trust.html"));
});
app.get("/itdr", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "itdr.html"));
});
app.get("/identity-governance", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "identity-governance.html"));
});
app.get("/soc", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "soc.html"));
});
app.get("/soc-cmm", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "soc-cmm.html"));
});
app.get("/cert-ops", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cert-ops.html"));
});
app.get("/governance", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "governance.html"));
});
app.get("/ai-threat-advisor", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-threat-advisor.html"));
});
app.get("/workforce", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "workforce.html"));
});
app.get("/team-ops", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "team-ops.html"));
});
app.get("/vm-report", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "vm-report.html"));
});
app.get("/board-report", pageGuard("/dashboard"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "board-report.html"));
});
app.get("/privacy", pageGuard("/privacy"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "privacy.html"));
});
app.get("/soar", pageGuard("/soar"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "soar.html"));
});
app.get("/endpoint-query", pageGuard("/endpoint-query"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "endpoint-query.html"));
});
app.get("/ctem", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ctem.html"));
});
app.get("/cti-expert", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cti-expert.html"));
});
app.get("/threat-copilot", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-copilot.html"));
});
app.get("/crq", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "crq.html"));
});
app.get("/vuln-assessment", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "vuln-assessment.html"));
});
app.get("/wifi-pentest", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "wifi-pentest.html"));
});
app.get("/reg-calendar", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "reg-calendar.html"));
});
app.get("/ai-systems", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-systems.html"));
});
app.get("/knowledge-graph", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "knowledge-graph.html"));
});
app.get("/mssp", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "mssp.html"));
});
app.get("/croc-orchestrator", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "croc-orchestrator.html"));
});
app.get("/siem", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "siem.html"));
});
app.get("/ai-redteam", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-redteam.html"));
});
app.get("/llm-pentest", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "llm-pentest.html"));
});
app.get("/ai-skills", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-skills.html"));
});
app.get("/chatops", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "chatops.html"));
});
app.get("/croc", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "croc.html"));
});
app.get("/cyber-risk-hunting", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cyber-risk-hunting.html"));
});
app.get("/agents", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "agents.html"));
});
app.get("/ai-guardrails", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-guardrails.html"));
});
app.get("/voc", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "voc.html"));
});
app.get("/network-sessions", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "network-sessions.html"));
});
app.get("/osint-graph", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "osint-graph.html"));
});
// PUBLIC trust center page (auth-exempt via the /trust/ prefix in requireAuthGate).
app.get("/trust/:slug", (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "trust-public.html"));
});
app.get("/stix-graph", pageGuard("/stix-graph"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "stix-graph.html"));
});
app.get("/attack-surface", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack-surface.html"));
});
app.get("/pentest", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pentest.html"));
});
app.get("/pentest/report", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pentest-report.html"));
});
app.get("/pentest/chain", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "chain.html"));
});
app.get("/exploitdb", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "exploitdb.html"));
});
app.get("/exposure", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "exposure.html"));
});
app.get("/attack-path", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack-path.html"));
});
app.get("/purple-team", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "purple-team.html"));
});
app.get("/ransomware", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ransomware.html"));
});
app.get("/assurance", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "assurance.html"));
});
app.get("/incident-sla", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "incident-sla.html"));
});
app.get("/pir", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pir.html"));
});
app.get("/identities", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "identities.html"));
});
app.get("/asset-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "asset-management.html"));
});
app.get("/incident-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "incident-management.html"));
});
app.get("/compliance-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "compliance-management.html"));
});
app.get("/crisis-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "crisis-management.html"));
});
app.get("/crisis-exercise", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "crisis-exercise.html"));
});
app.get("/fair-tef", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "fair-tef.html"));
});
app.get("/devsecops", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "devsecops.html"));
});
app.get("/fair-mam", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "fair-mam.html"));
});
app.get("/risk-register", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "risk-register.html"));
});
app.get("/pqcmm", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pqcmm.html"));
});
app.get("/essential-eight", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "essential-eight.html"));
});
app.get("/adversary-opportunity", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "adversary-opportunity.html"));
});
app.get("/insurance-readiness", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "insurance-readiness.html"));
});
app.get("/ai-detection", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ai-detection.html"));
});
app.get("/reg-incident-reporting", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "reg-incident-reporting.html"));
});
app.get("/slsa", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "slsa.html"));
});
app.get("/sca", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "sca.html"));
});
app.get("/tools", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "tools.html"));
});
app.get("/threat-model", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-model.html"));
});
app.get("/policy-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "policy-management.html"));
});
app.get("/configuration-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "configuration-management.html"));
});
app.get("/threat-informed-defense", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-informed-defense.html"));
});
app.get("/oval-scan", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "oval-scan.html"));
});
app.get("/oval-editor", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "oval-editor.html"));
});
app.get("/api-docs", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "api-docs.html"));
});
app.get("/api-keys", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "api-keys.html"));
});
app.get("/webhooks", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "webhooks.html"));
});
app.get("/cti-watch", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cti-watch.html"));
});
app.get("/drift", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "drift.html"));
});
app.get("/content", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "content.html"));
});

app.get("/vault", requireAdmin, (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "vault.html"));
});

app.get("/connectors", pageGuard("/connectors"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "connectors.html"));
});

app.get("/admin", requireAdmin, (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "admin.html"));
});

// ── Error handling ───────────────────────────────────────────────────────────
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: err.message });
});

// ── Startup ────────────────────────────────────────────────────────────────────
ensureSchemaDbs(); // creates the "schema" databases (XORCISM, XVULNERABILITY, XATTACK, XMALWARE, XINCIDENT, XTHREAT, XOVAL, XWINDOWS) if missing
seedAdmin();
ensureComplianceDb(); // creates the XCOMPLIANCE.db database (AUDIT, AUDITFINDING, AUDITREPORT)
ensurePentestColumns(); // links AUDITFINDING to its engagement (AUDIT type=Pentest) — must run after ensureComplianceDb
ensureChainTables(); // tool-chaining playbooks: XCHAINPLAYBOOK / XCHAINRUN / XCHAINSTEP (+ seeds builtins)
ensureDriftTable(); // attack-surface drift snapshots (XSURFACESNAPSHOT)
ensureTicketDb(); // creates the XTICKET.db database (TICKET, TICKETCOMMENT, TICKETCATEGORY, TICKETATTACHMENT)
getAgentDb(); // creates the XAGENT.db database (XOR agents, events, IOC) if needed
ensureThreatModelTables(); // creates the THREATMODEL* tables (XORCISM.db) if needed
ensureThreatTables(); // creates the XTHREAT tables (IOC…) if needed
ensureIncidentTables(); // creates the XINCIDENT.ALERT table if needed
ensureOpenctiColumns(); // adapts the XTHREAT tables to OpenCTI properties (Confidence/TLP/Sighting…)
ensureEmulationTables(); // adversary emulation / validation (BAS) module: EMULATION*/ATOMICTEST
ensureAssetColumns(); // adds ASSET.BusinessValue (and future core ASSET fields) if missing
ensureAssetPrimaryKey(); // rebuilds ASSET so AssetID is a real INTEGER PRIMARY KEY (legacy non-PK quirk); idempotent
ensureCveMatchTables(); // CVE→ASSET matcher watermark (CVEMATCHCURSOR); initialised to current MAX(VulnerabilityID)
ensurePatchTables(); // Patch Management: ASSETVULNERABILITY patch-status cols + ASSETVULNERABILITYREMEDIATION plan cols
ensureMonitoringTables(); // Asset Monitoring (CheckCle-style): MONITORINGCHECK + MONITORINGINCIDENT
ensureControlImplementationTables(); // NIST 800-53 management: CONTROLIMPLEMENTATION + CONTROL.Baseline* columns
ensureCisBenchmarkTables(); // CIS Benchmarks catalogue + CIS-CAT results (Configuration Management)
ensureTrustCenterTables(); // Trust Center: public posture page config (per tenant)
ensureIdentityTables(); // IAM registry: XORCISM.IDENTITY + IDENTITYPERSON (human + non-human identities)
ensureToolDocumentTable(); // XORCISM.TOOLDOCUMENT — TOOL ↔ DOCUMENT link table (provenance/validity/confidence)
ensureOrganisationRiskScoreTable(); // XORCISM.ORGANISATIONRISKSCORE — per-organisation risk-score history
ensureOvalScanTables(); // OVAL scan results: extend XOVAL.OVALRESULTS into per-asset verdicts + seed result enum
ensureSlaColumns(); // ASSET.SLAResponseHours/SLAResolutionHours + INCIDENT.Duration (SLA breach view)
ensureVulnerabilityColumns(); // adds VULNERABILITY.EPSS (Exploit Prediction Scoring System) if missing
ensureDocumentSensitivity(); // adds DOCUMENT.SensitivityLabel + TLP (data-classification labels) if missing
ensurePersonOrgChartColumns(); // adds PERSON org-chart/AD/Entra fields (ManagerPersonID, JobTitle, UPN…) if missing
ensureAwarenessTables(); // security-awareness training + phishing-simulation schema (PHISHINGSIMULATION/RESULT)
ensureMalwareScanTables(); // multi-engine malware scan store (XMALWARE.MALWARESCAN/MALWARESCANENGINE)
ensureCloudComplianceTables(); // cloud compliance checker findings (XORCISM.CLOUDFINDING)
ensureComplianceJourneyTables(); // guided compliance-journey wizard (XCOMPLIANCE.COMPLIANCEJOURNEY/STEP)
ensureQuestionnaireRunTables(); // guided questionnaire runner (XCOMPLIANCE.QUESTIONNAIRERUN/RESPONSE)
ensureTprmTables(); // TPRM cockpit (XCOMPLIANCE.TPRMVENDOR/TPRMFINDING)
ensureZeroTrustTables(); // Zero Trust maturity (XCOMPLIANCE.ZTFUNCTION/ZTMATURITYASSESSMENT/ZTMATURITYITEM)
ensureZtSigninTable(); // Zero Trust sign-in/access telemetry (XORCISM.IDENTITYSIGNIN) for UEBA
ensureZtPolicyTable(); // Zero Trust policy register (XCOMPLIANCE.ZTPOLICY) — conditional-access policies
ensureItdrTables(); // ITDR detections (XORCISM.IDENTITYDETECTION) — ATT&CK-mapped identity threat detection
ensureIdGovTables(); // IGA/IDMS access certification (XORCISM.ACCESSCAMPAIGN/ACCESSREVIEWITEM)
try { seedZtFunctions(); } catch { /* catalogue seed best-effort */ } // CISA ZTMM v2.0 function catalogue
try { seedZtSigninDemo(3); } catch { /* demo only */ } // UEBA demo: sign-in telemetry for tenant 3
try { seedZtPolicyDemo(3); } catch { /* demo only */ } // ZT policy register demo for tenant 3
try { seedItdrDemo(3); } catch { /* demo only */ } // ITDR demo: spray/MFA-bomb telemetry + run detectors for tenant 3
try { seedIdGovDemo(3); } catch { /* demo only */ } // IGA demo: a privileged recertification campaign for tenant 3
ensureNotificationRuleTable(); // per-user event→notification rules (XORCISM.NOTIFICATIONRULE)
ensureSocTables(); // SOC operations: shifts/on-call, escalation policy+log, IR playbooks (XINCIDENT)
ensureSocCmmTables(); // SOC-CMM maturity self-assessment (XINCIDENT)
ensureCertOpsTables(); // CERT/CSIRT operations: forensic cases + chain of custody (XINCIDENT)
ensureGovernanceTables(); // Governance: NIST CSF 2.0 Govern (GV) register (XCOMPLIANCE)
ensurePrivacyTables(); // GDPR/DPO registers: PRIVACYPROCESSING (RoPA) + DSAR + DPIA + PRIVACYBREACH (XCOMPLIANCE)
ensureAiThreatTables(); // OWASP AI Exchange agentic threat catalogue (XTHREAT)
ensureWorkforceTables(); // NICE + ENISA ECSF workforce role catalogue around PERSON (XORCISM)
ensureTeamOpsTables(); // Purple/Red/Blue Team Operations: ATT&CK exercises + capabilities (XTHREAT)
ensureVocTables(); // Vulnerability Operations Center: SLA policy + campaigns + exceptions (XVULNERABILITY)
ensureVmTrendsTables(); // VM posture history (VMSNAPSHOT) for the /vm-report executive trends + myth-busting
ensureCtemTables(); // CTEM (ctem.org): exposure-identifier catalogue (CTEMIDENTIFIER) + tracked exposures (CTEMEXPOSURE)
ensureCtiExpertTables(); // CTI-Expert: AI-orchestrated OSINT investigations (CTIINVESTIGATION, XTHREAT)
ensureWifiTables(); // Wi-Fi pentest: local Wi-Fi security assessment results (WIFINETWORK, XORCISM)
ensureRegObligationTables(); seedRegObligationCatalogue(); // Regulatory calendar: REGOBLIGATION + EU reference catalogue
ensureAiSystemTables(); // AI system inventory + AI-BOM (AISYSTEM/AISYSTEMCOMPONENT, XORCISM)
ensureOrchestratorTables(); startOrchestrator(); // Agentic CROC orchestrator (CROCACTION queue + LOOPEVENT poller; XOR_ORCHESTRATOR=0 to disable)
ensureSiemTables(); // SIEM-lite: ingested-log buffer (SIEMEVENT, XINCIDENT) for the log→Sigma→ALERT pipeline
ensureAibasTables(); // LLM red-team / AI-BAS run history (AIBASRUN/AIBASRESULT, XORCISM)
ensureTeamsTables(); // Microsoft Teams webhook targets (TEAMSWEBHOOK, XORCISM) for alert/notification distribution
ensureCrocTables(); seedCrocPolicies(null); // CROC Continuous Defense Loop: LOOPEVENT bus + LOOPPOLICY (seed default pre-auth policies)
ensureTicketingTargets(); // CROC outbound ticketing (Jira/ServiceNow) destination store
ensureIamTargets(); // CROC outbound IAM enforcement (Entra/Graph) target store
ensureSoarTables(); // CROC outbound SOAR/n8n automation webhook store
ensureSoarOpsTables(); // SOAR cockpit: orchestration playbooks + actions + runs (XINCIDENT)
ensureEndpointQueryTables(); // Tanium-style real-time endpoint querying: ENDPOINTQUESTION/ENDPOINTANSWER (XAGENT)
try { seedEndpointQueryDemo(3); } catch { /* demo only */ } // populated answer grids without a live agent fleet
ensureLoopHealthTable(); // CROC resilience-over-time snapshot store
ensureFrameworkVocabulary(); seedFrameworks(); // Frameworks management: FRAMEWORK→VOCABULARY mapping + curated catalogue
ensureTahitiColumns(); // TaHiTI methodology: HUNT.TahitiPhase + TahitiTrigger columns
ensureAiGuardTables(); // AI-agent guardrails: AIAGENT / AIGUARDRAILRESULT / AIGUARDRAILVIOLATION (XAGENT)
try { seedCrocDemo(3); } catch { /* demo only */ } // CROC value demo (tenant 3): 24h bidirectional loop feed + 30-day improving resilience
try { seedThreatDebtDemo(3); } catch { /* demo only */ } // AOI demo (tenant 3): 30-day improving (paid-down) Adversary Opportunity Index history
try { seedAiUsageDemo(3); } catch { /* demo only */ } // AI runtime detection demo (tenant 3): 30d usage baseline + an anomaly day (no-op if no AI systems)
try { seedLlmPentestDemo(3); } catch { /* demo only */ } // LLM pentest demo (tenant 3): one OWASP-LLM-2025 engagement with a realistic mix of outcomes
try { seedScaDemo(3); } catch { /* demo only */ } // SCA demo (tenant 3): a representative CycloneDX SBOM (incl. a vulnerable + license/version gaps) so /sca has content
try { seedAiSkillsDemo(3); } catch { /* demo only */ } // AI Operations demo (tenant 3): 6 skills/prompts mirroring real copilots + sample activity
try { seedSlsaDemo(3); } catch { /* demo only */ } // SLSA demo (tenant 3): 4 artifacts at varying build-integrity levels
try { seedTprmDemo(3); } catch { /* demo only */ } // TPRM demo (tenant 3): 4 vendors with tiers, posture, conformance, findings
try { seedOdessaPlaybook(3); } catch { /* idempotent */ } // ODESSA AI-IR Loop: 6-stage adversarial-AI incident-response SOAR playbook (tenant 3)
try { ensureEss8Tables(); } catch { /* boot */ } // ASD Essential Eight maturity assessment store (XCOMPLIANCE.ESSENTIALEIGHT)
try { seedEss8Demo(3); } catch { /* demo only */ } // Essential Eight demo (tenant 3): a mixed-maturity assessment vs target ML3
ensureLandingAccessTable(); // landing-menu NICE-profile access control store
seedFeaturePageGrants([...FEATURE_PAGE_PATHS]); // full RBAC: per-boot top-up so base roles keep access to existing + newly-added feature pages
ensureStixObjectStore(); // Lossless STIX retention: RawJson cols on OBSERVABLE/IOC/INTELEXCHANGE + STIXOBJECT + FTS5 index
ensureDevSecOpsTables(); // DevSecOps operations: DEVSECOPSAPP + DEVSECOPSSCAN + DEVSECOPSGATE (pipeline security posture)
ensureBlobStore(); // Content-addressed blob store (FILEBLOB + DB_DIR/blobstore) for large files by sha256 pointer
ensureNetflowTables(); // NetFlow around ASSET: ASSETSERVICE + NETWORKSESSION (discovery/monitoring, SOC)
ensureGrcColumns(); // advanced GRC: CRQ/FAIR (risk register), findings workflow, policy lifecycle
ensurePolicyAckTable(); // policy publication + per-user acceptance tracking (XORCISM.POLICYACKNOWLEDGEMENT)
ensurePolicyVersionTable(); // policy version history (XORCISM.POLICYVERSION) — snapshot on publish
try { backfillPolicyVersions(); } catch { /* best-effort */ } // give already-published policies an initial version entry
ensureBugBountyTables(); // Bug Bounty program management (XVULNERABILITY): BUGBOUNTY*
ensureEbiosTables(); // EBIOS Risk Manager (ANSSI) in XCOMPLIANCE: reuses RISKASSESSMENT/RISKSCENARIO + EBIOS* tables
ensureNist80030Tables(); // NIST SP 800-30 risk assessment in XCOMPLIANCE: reuses RISKASSESSMENT + NIST80030* tables
ensureOtSecurityTables(); // OT/ICS Security (IEC 62443/NIST 800-82): reuses AUDIT + OTZONE/OTCONDUIT/OTZONEASSET stubs
ensureFairMamTables(); // FAIR-MAM materiality assessment model: FAIRMAMCATEGORY taxonomy + FAIRMAMASSESSMENT/LINEITEM
ensurePqcmmTables(); // PQCMM post-quantum-crypto maturity model: PQCMMLEVEL taxonomy + PQCMMASSESSMENT
ensureThreatDebtTables(); // Adversary Opportunity Index: THREATDEBTSNAPSHOT (AOI STOCK/FLOW history)
ensureInsuranceTables(); // Cyber Insurance Readiness: CYBERINSURANCEPOLICY (carrier / limit / renewal record)
ensureAiDetectTables(); // AI runtime detection: AIUSAGE telemetry + AIDETECTION
ensureLlmPentestTables(); // LLM pentest methodology: LLMPENTEST engagement + LLMPENTESTCASE (OWASP-LLM-2025)
ensureAiSkillsTables(); // AI Operations: AISKILL library + AIACTIVITY provenance log + AIHANDOVER routing
ensureRegIncidentTables(); // Regulatory incident reporting: REGINCIDENTREPORT (DORA/NIS2/GDPR/CRA submissions)
ensureSlsaTables(); // SLSA supply-chain tracker: SLSAARTIFACT (build-integrity levels L0-L3)
ensureScaTables(); // SCA / SBOM: SBOM + enriched COMPONENT + COMPONENTDEPENDENCY (CycloneDX/SPDX over CPE inventory)
ensureToolStarTable(); // XORCISM.TOOLSTAR — per-user GitHub-style stars on the TOOL catalogue
ensureTenantColumns(); // adds TenantID to the operational tables (best-effort)
getJobDb(); // creates the job-queue schema (XJOB.db) if needed
seedData(); // pre-inserts reference data (e.g. VOCABULARY "XORCISM") — idempotent
seedCtemIdentifiers(); // ctem.org exposure-identifier catalogue (29 ids / 8 categories) — idempotent, additive by CtemId
startStixStoreSync(); // reconcile STIXOBJECT from OBSERVABLE/IOC/INTELEXCHANGE at boot + every 10 min (catches connector/form writes)
ensureCveSchedule(); // seeds the hourly NVD CVE import schedule (cron '0 * * * *'); XOR_CVE_IMPORT=0 to disable
ensureBoardReportSchedule(); // seeds the monthly board-report schedule (cron '0 8 1 * *'); XOR_BOARD_REPORT=1 to enable
console.log(`[db] active driver: ${dbDriver()}`); // better-sqlite3 (default) | libsql (XORCISM_DB_DRIVER=libsql)
startReplicaSync(); // refresh libsql embedded replicas (no-op unless libsql + LIBSQL_SYNC_URL configured)
startScheduler(); // fires the connectors' scheduled tasks (XSCHEDULE)
startCveMatcher(); // hourly CVE→ASSET tech matcher ("New CVEs for ASSET") — catches every import path
startMonitorChecker(); // live Asset-Monitoring prober (HTTP/TCP/DNS/SSL/ping due monitors); XOR_MONITOR=0 to disable
startThreatFeedPoller(); // periodically turns CTI RSS feed items into THREATREPORT entries
startRiskScoreLoop(); // recomputes ASSET.RiskScore every 30 s
startResilienceAccrual(); // CROC resilience-over-time: accrue a loop-health snapshot now + every 6h
startLoopDigest(); // CROC daily AI loop digest (~5min after boot, then daily; XOR_CROC_DIGEST=0 to disable)
startChainEngine(); // advances active tool-chaining runs (pentest playbooks)
warmManifestCache(); // pre-parse the 1200+ connector manifests so the first /connectors load is instant
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, () => {
  console.log(`\n  XORCISM TypeScript Server (auth XID activée)`);
  console.log(`  http://localhost:${PORT}/login\n`);
});
