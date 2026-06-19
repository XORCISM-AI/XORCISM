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
      version: "1.0.0",
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
