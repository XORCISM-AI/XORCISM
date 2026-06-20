/**
 * openapi.ts — OpenAPI 3.0 description of the XORCISM REST API (v1).
 * Served at GET /api/v1/openapi.json and rendered by the /api-docs page.
 */
export function buildOpenApi(): Record<string, unknown> {
  const ok = (schema: string) => ({
    description: "Success",
    content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } },
  });
  const errors = {
    "401": { description: "Missing or invalid API key", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
    "403": { description: "Forbidden (insufficient role)", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
  };
  const pageParams = [
    { name: "limit", in: "query", schema: { type: "integer", default: 50, maximum: 500 }, description: "Max items to return." },
    { name: "offset", in: "query", schema: { type: "integer", default: 0 }, description: "Items to skip." },
  ];
  const idParam = [{ name: "id", in: "path", required: true, schema: { type: "integer" } }];
  const body = (schema: string) => ({ required: true, content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } } });
  const created = (schema: string) => ({ description: "Created", content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } } });

  return {
    openapi: "3.0.3",
    info: {
      title: "XORCISM API",
      version: "1.1.0-beta.1",
      description:
        "REST API over the XORCISM cyber-exposure platform. Authenticate with an API key " +
        "(`Authorization: Bearer xor_…` or `X-API-Key: xor_…`). A key acts as its owning user and is " +
        "tenant-scoped. Keys carry per-resource scopes (e.g. `incidents:write`) and may expire. " +
        "Manage keys at /api-keys and event webhooks at /webhooks.",
    },
    servers: [{ url: "/api/v1", description: "This instance" }],
    security: [{ ApiKeyBearer: [] }, { ApiKeyHeader: [] }],
    tags: [
      { name: "Meta", description: "Service metadata" },
      { name: "Assets", description: "Asset inventory" },
      { name: "Incidents", description: "Incidents & SLA/RTO posture" },
      { name: "Exposure", description: "Vulnerability exposure & risk" },
      { name: "Governance", description: "Asset & identity inventory with governance worklists" },
    ],
    paths: {
      "/health": {
        get: {
          tags: ["Meta"], summary: "Liveness probe (no auth)", security: [],
          responses: { "200": ok("Health") },
        },
      },
      "/me": {
        get: {
          tags: ["Meta"], summary: "Identity behind the API key",
          responses: { "200": ok("Identity"), ...errors },
        },
      },
      "/assets": {
        get: {
          tags: ["Assets"], summary: "List assets", parameters: pageParams,
          responses: { "200": ok("AssetList"), ...errors },
        },
      },
      "/assets/{id}": {
        get: {
          tags: ["Assets"], summary: "Get one asset", parameters: idParam,
          responses: { "200": ok("Asset"), "404": { description: "Not found" }, ...errors },
        },
        patch: {
          tags: ["Assets"], summary: "Set SLA / value fields on an asset (write scope)", parameters: idParam,
          requestBody: body("AssetUpdate"),
          responses: { "200": ok("UpdateResult"), "400": { description: "Nothing to update" }, "404": { description: "Not found" }, ...errors },
        },
      },
      "/incidents": {
        get: {
          tags: ["Incidents"], summary: "List incidents", parameters: pageParams,
          responses: { "200": ok("IncidentList"), ...errors },
        },
        post: {
          tags: ["Incidents"], summary: "Create an incident (write scope)",
          requestBody: body("IncidentCreate"),
          responses: { "201": created("Incident"), "400": { description: "name required" }, ...errors },
        },
      },
      "/incidents/{id}": {
        patch: {
          tags: ["Incidents"], summary: "Update an incident's duration/status/severity (write scope)", parameters: idParam,
          requestBody: body("IncidentUpdate"),
          responses: { "200": ok("UpdateResult"), "400": { description: "Nothing to update" }, "404": { description: "Not found" }, ...errors },
        },
      },
      "/incident-sla": {
        get: {
          tags: ["Incidents"],
          summary: "Incident durations vs asset SLAs & BIA RTOs",
          responses: { "200": ok("SlaView"), ...errors },
        },
      },
      "/exposures": {
        get: {
          tags: ["Exposure"], summary: "Top exposures (fusion exploitability score)",
          parameters: [{ name: "limit", in: "query", schema: { type: "integer", default: 50 } }],
          responses: { "200": ok("ExposureList"), ...errors },
        },
      },
      "/risk": {
        get: {
          tags: ["Exposure"], summary: "Enterprise risk score (current tenant)",
          responses: { "200": ok("Risk"), ...errors },
        },
      },
      "/asset-management": {
        get: {
          tags: ["Governance"],
          summary: "Asset inventory + governance worklist (owner / exposure / backup / controls / BIA / KEV-critical vulns), with a 0-100 risk score per asset",
          responses: { "200": ok("AssetInventory"), ...errors },
        },
      },
      "/identities": {
        get: {
          tags: ["Governance"],
          summary: "Identity inventory (human + non-human) + governance findings (orphaned NHI / privileged / stale / expiring credentials / missing MFA), with a risk score (scope: identities:read)",
          responses: { "200": ok("IdentityInventory"), ...errors },
        },
      },
      "/incident-management": {
        get: {
          tags: ["Governance"],
          summary: "Incident inventory + response worklist (open critical / SLA-RTO breach / unassigned / stale / compromise), with a priority score + MTTR (scope: incidents:read)",
          responses: { "200": ok("IncidentInventory"), ...errors },
        },
      },
      "/compliance-management": {
        get: {
          tags: ["Governance"],
          summary: "Audit inventory + remediation worklist (open findings by severity / overdue / unassigned / policies past review), with a posture score (scope: compliance:read)",
          responses: { "200": ok("ComplianceInventory"), ...errors },
        },
      },
      "/policy-management": {
        get: {
          tags: ["Governance"],
          summary: "Policy lifecycle inventory + document register + governance worklist (overdue reviews / unpublished / unowned / missing version / expired documents), with a per-policy governance score (scope: policies:read)",
          responses: { "200": ok("PolicyInventory"), ...errors },
        },
      },
      "/configuration-management": {
        get: {
          tags: ["Governance"],
          summary: "Secure-configuration content library (OVAL hardening baselines) + verification worklist (deprecated / unverified by scan / interim status / no CCE mapping), with a per-baseline health score (scope: configuration:read)",
          responses: { "200": ok("ConfigurationInventory"), ...errors },
        },
      },
      "/crisis-management": {
        get: {
          tags: ["Governance"],
          summary: "Crisis-management & tabletop-exercise readiness: exercises (inject progress, participants, improvement actions) + the crisis-scenario library + a worklist (overdue actions, scenarios never exercised, no after-action report) and a 0-100 readiness score (scope: crisis:read)",
          responses: { "200": ok("CrisisInventory"), ...errors },
        },
      },
      "/risk-register": {
        get: {
          tags: ["Governance"],
          summary: "Risk register inventory + treatment worklist: each risk's inherent → current → residual level, treatment strategy/owner/review and its CRQ/FAIR Annualized Loss Expectancy, with a worklist (untreated high/critical residual, accepted-without-justification, overdue reviews, treatments past target, unowned) and a residual-posture score (scope: risk:read)",
          responses: { "200": ok("RiskRegisterInventory"), ...errors },
        },
      },
      "/pqcmm": {
        get: {
          tags: ["Governance"],
          summary: "PQCMM — Post-Quantum Cryptography Maturity Model (PKI Consortium): the 6 reference levels (0 None → 5 Optimized) + per-subject quantum-readiness assessments (current vs target level, crypto-agility, CBOM, zero-legacy) and a posture rollup (quantum-vulnerable / production-ready / managed, maturity score, below-target worklist) (scope: pqcmm:read)",
          responses: { "200": ok("PqcmmInventory"), ...errors },
        },
      },
      "/fair-mam": {
        get: {
          tags: ["Governance"],
          summary: "FAIR-MAM materiality: the FAIR Materiality Assessment Model cost-category taxonomy (10 categories, primary/secondary loss) + saved assessments with the computed single-loss magnitude (PERT), primary/secondary split and a materiality verdict (scope: fairmam:read)",
          responses: { "200": ok("FairMamInventory"), ...errors },
        },
      },
      "/sca": {
        get: {
          tags: ["Governance"],
          summary: "Software Composition Analysis (SCA): imported SBOM documents (CycloneDX / SPDX) + their components (name, version, type, PURL, CPE, license, supplier) with by-type / by-license / by-supplier breakdowns and a worklist (known-vulnerable components, missing licenses, unpinned versions) (scope: sca:read)",
          responses: { "200": ok("ScaInventory"), ...errors },
        },
      },
      "/threat-informed-defense": {
        get: {
          tags: ["Governance"],
          summary: "Threat-Informed Defense scorecard: per ATT&CK technique, adversary use (groups) vs detection (Sigma) / mitigation (D3FEND + ATT&CK) / test (Atomic) coverage, with a prioritised gap worklist and a threat-weighted program score (scope: tid:read)",
          responses: { "200": ok("TidInventory"), ...errors },
        },
      },
      "/threat-informed-defense/navigator-layer": {
        get: {
          tags: ["Governance"],
          summary: "Export the Threat-Informed Defense program as a MITRE ATT&CK Navigator layer (v4.5 JSON): score = adversary prevalence, colour = defence status (red = false-coverage/exposed, amber = partial, green = covered). Opens in the official ATT&CK Navigator (scope: tid:read)",
          responses: { "200": { description: "ATT&CK Navigator layer (v4.5)", content: { "application/json": { schema: { type: "object" } } } }, ...errors },
        },
      },
    },
    components: {
      securitySchemes: {
        ApiKeyBearer: { type: "http", scheme: "bearer", bearerFormat: "xor_…", description: "Authorization: Bearer xor_…" },
        ApiKeyHeader: { type: "apiKey", in: "header", name: "X-API-Key", description: "X-API-Key: xor_…" },
      },
      schemas: {
        Error: { type: "object", properties: { error: { type: "string" } } },
        Health: { type: "object", properties: { status: { type: "string", example: "ok" }, name: { type: "string" }, version: { type: "string" }, time: { type: "string", format: "date-time" } } },
        Identity: { type: "object", properties: { userId: { type: "integer" }, email: { type: "string" }, tenantId: { type: "integer", nullable: true }, tenant: { type: "string", nullable: true }, roles: { type: "array", items: { type: "string" } }, isSuperAdmin: { type: "boolean" } } },
        Asset: {
          type: "object",
          properties: {
            assetId: { type: "integer" }, name: { type: "string" }, criticality: { type: "string", nullable: true },
            businessValue: { type: "integer", nullable: true }, financialValue: { type: "number", nullable: true },
            riskScore: { type: "integer", nullable: true }, slaResolutionHours: { type: "number", nullable: true },
          },
        },
        AssetList: { type: "object", properties: { total: { type: "integer" }, limit: { type: "integer" }, offset: { type: "integer" }, items: { type: "array", items: { $ref: "#/components/schemas/Asset" } } } },
        Incident: { type: "object", properties: { incidentId: { type: "integer" }, name: { type: "string" }, severity: { type: "string", nullable: true }, status: { type: "string", nullable: true }, durationHours: { type: "number", nullable: true } } },
        IncidentList: { type: "object", properties: { total: { type: "integer" }, limit: { type: "integer" }, offset: { type: "integer" }, items: { type: "array", items: { $ref: "#/components/schemas/Incident" } } } },
        SlaRow: {
          type: "object",
          properties: {
            incidentId: { type: "integer" }, incidentName: { type: "string" }, assetId: { type: "integer" }, assetName: { type: "string" },
            duration: { type: "number", nullable: true },
            slaHours: { type: "number", nullable: true }, slaStatus: { type: "string", enum: ["met", "breached", "no-target", "no-duration"] },
            rtoHours: { type: "number", nullable: true }, rtoStatus: { type: "string", enum: ["met", "breached", "no-target", "no-duration"] },
          },
        },
        SlaView: { type: "object", properties: { rows: { type: "array", items: { $ref: "#/components/schemas/SlaRow" } }, summary: { type: "object" } } },
        Exposure: { type: "object", properties: { vulnerabilityId: { type: "integer" }, cve: { type: "string", nullable: true }, score: { type: "number" }, priority: { type: "number" }, kev: { type: "boolean" }, epss: { type: "number", nullable: true } } },
        ExposureList: { type: "object", properties: { scanned: { type: "integer" }, items: { type: "array", items: { $ref: "#/components/schemas/Exposure" } } } },
        Risk: { type: "object", properties: { tenantId: { type: "integer", nullable: true }, enterpriseRiskScore: { type: "integer" } } },
        AssetInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" } }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "total, crownJewels, internetFacing, pii, unbackedCritical, noOwner, withCriticalVulns, stale, byCriticality, byEnvironment" } } },
        IdentityInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" } }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "total, human, nonHuman, privileged, orphaned, stale, expiring, hardcoded, compromised, mfaGaps, byType, byClass" } } },
        IncidentInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" } }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "total, open, criticalOpen, breached, unassigned, stale, compromises, mttrHours, byStatus, bySeverity" } } },
        ComplianceInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" } }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "audits, inProgress, completed, completionRate, openFindings, highOpen, overdue, unassigned, policiesReview, bySeverity, byType" } } },
        PolicyInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" }, description: "policies with lifecycle + governance score" }, documents: { type: "array", items: { type: "object" }, description: "controlled-document register" }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "policies, published, draft, inReview, approved, retired, overdueReview, dueSoon, noOwner, noVersion, documents, expiredDocs, frameworks, byStatus, byFramework, byCategory, byLanguage" } } },
        ConfigurationInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" }, description: "compliance/hardening OVAL baselines with a health score" }, findings: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "definitions, compliance, patch, vulnerability, inventory, deprecated, accepted, withCce, scannedAssets, complianceFail, passRate, byClass, byStatus" } } },
        TidInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" }, description: "ATT&CK techniques: threat (adversary groups) vs detect/mitigate/test pillars + gapScore" }, findings: { type: "array", items: { type: "object" }, description: "prioritised TID gaps" }, summary: { type: "object", description: "techniques, threatRelevant, detected, mitigated, tested, detectRate, mitigateRate, testRate, tidScore, exposed, fullyCovered, byTactic" } } },
        CrisisInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" }, description: "tabletop exercises (audits of type Tabletop Exercise): inject progress, participants, improvement actions, score" }, findings: { type: "array", items: { type: "object" }, description: "worklist: overdue improvement actions, scenarios never exercised, exercises with no after-action report" }, scenarios: { type: "array", items: { type: "object" }, description: "crisis-scenario template library (exercised flag, inject count)" }, summary: { type: "object", description: "exercises, planned, completed, completionRate, scenarios, scenariosNeverExercised, scenarioCoverage, openActions, overdueActions, withoutAAR, readinessScore" } } },
        RiskRegisterInventory: { type: "object", properties: { rows: { type: "array", items: { type: "object" }, description: "risk register entries: ref, title, inherent/current/residual level, treatment, owner, ALE, review, priority score" }, findings: { type: "array", items: { type: "object" }, description: "treatment worklist: untreated high/critical residual, accepted-without-justification, overdue review, treatment past target, no owner" }, summary: { type: "object", description: "risks, open, treatedRate, highCritical, untreated, accepted, overdueReview, quantified, totalALE, byLevel/byTreatment/byCategory, riskScore" } } },
        PqcmmInventory: { type: "object", properties: { levels: { type: "array", items: { type: "object" }, description: "the 6 PQCMM levels (0 None … 5 Optimized) with summary + criteria" }, rows: { type: "array", items: { type: "object" }, description: "per-subject assessments: subject, type, current/target level, gap, crypto-agility, CBOM, zero-legacy, owner" }, findings: { type: "array", items: { type: "object" }, description: "worklist: quantum-vulnerable (Level 0), below-target, no-target, re-assessment overdue" }, summary: { type: "object", description: "assessments, byLevel[0..5], quantumVulnerable, productionReady (≥2), managed (≥4), avgLevel, maturityScore, belowTarget" } } },
        ScaInventory: { type: "object", properties: { sboms: { type: "array", items: { type: "object" }, description: "imported SBOM documents: name, format (CycloneDX/SPDX), specVersion, subject, asset, componentCount, licenseCount, source, tool" }, components: { type: "array", items: { type: "object" }, description: "components: name, version, type, purl, cpe, supplier, license, scope, vulnerable" }, findings: { type: "array", items: { type: "object" }, description: "worklist: known-vulnerable components, missing licenses, unpinned versions" }, byType: { type: "array", items: { type: "object" } }, byLicense: { type: "array", items: { type: "object" } }, bySupplier: { type: "array", items: { type: "object" } }, summary: { type: "object", description: "sboms, components, distinctComponents, byFormat, vulnerable, noLicense, noVersion, licenses, suppliers, dependencies, cpeLinked, assetsCovered" } } },
        FairMamInventory: { type: "object", properties: { categories: { type: "array", items: { type: "object" }, description: "FAIR-MAM cost-category taxonomy (code, name, parent, lossType primary/secondary, party first/third-party)" }, assessments: { type: "array", items: { type: "object" }, description: "saved assessments: total (PERT single-loss), primary/secondary, firstParty/thirdParty, threshold, ratio, determination" }, summary: { type: "object", description: "assessments, material, approaching, largestExposure, totalExposure, currency, avgPrimaryShare" } } },
        IncidentCreate: {
          type: "object", required: ["name"],
          properties: { name: { type: "string" }, severity: { type: "string" }, status: { type: "string" }, synopsis: { type: "string" }, durationHours: { type: "number" } },
        },
        IncidentUpdate: { type: "object", properties: { durationHours: { type: "number" }, status: { type: "string" }, severity: { type: "string" } } },
        AssetUpdate: { type: "object", properties: { slaResponseHours: { type: "number" }, slaResolutionHours: { type: "number" }, businessValue: { type: "integer" }, financialValue: { type: "number" } } },
        UpdateResult: { type: "object", properties: { updated: { type: "boolean" }, assetId: { type: "integer" }, incidentId: { type: "integer" } } },
      },
    },
  };
}
