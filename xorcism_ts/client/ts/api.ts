/**
 * api.ts — Typed API client shared between app.ts and bia.ts
 */

export interface RowsResponse {
  total: number;
  rows: Record<string, unknown>[];
}

export interface ExportResponse {
  rows: Record<string, unknown>[];
  total: number;
  truncated: boolean;
  limit: number;
}

export interface NotificationItem {
  NotificationID: number;
  Title: string;
  Message: string | null;
  Level: string | null;
  Link: string | null;
  Source: string | null;
  IsRead: number;
  CreatedDate: string | null;
}

export interface ColumnInfo {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
}

export interface BiaAudit {
  BIAAuditID?: number;
  BIAAuditName: string;
  BIAAuditDescription?: string;
  BIAAuditScope?: string;
  BIAAuditDate?: string;
  BIAAuditStatus?: string;
  Auditor?: string;
}

export interface BiaEntry {
  BIAEntryID?: number;
  BIAAuditID: number;
  AssetName?: string;
  AssetDescription?: string;
  AssetType?: string;
  CriticalityLevel?: string;
  OwnerName?: string;
  RiskDescription?: string;
  RiskLevel?: string;
  ImpactFinancial?: string;
  ImpactOperational?: string;
  ImpactLegal?: string;
  ImpactReputational?: string;
  MTD?: string;
  RTO?: string;
  RPO?: string;
  Notes?: string;
}

async function request<T>(
  url: string,
  method = "GET",
  body?: unknown
): Promise<T> {
  const opts: RequestInit = {
    method,
    headers: { "Content-Type": "application/json" },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((err as { error: string }).error ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

// ── Explorer API ──────────────────────────────────────────────────────────────

export const api = {
  getDatabases: () => request<string[]>("/api/databases"),
  getTables: (db: string) =>
    request<string[]>(`/api/tables?db=${encodeURIComponent(db)}`),
  getSchema: (db: string, table: string) =>
    request<ColumnInfo[]>(
      `/api/schema?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}`
    ),
  getRows: (
    db: string,
    table: string,
    limit: number,
    offset: number,
    sort?: string,
    dir?: string,
    search?: string,
    vocab?: number | null,
    filters?: Record<string, string>
  ) => {
    let url = `/api/rows?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}&limit=${limit}&offset=${offset}`;
    if (sort) url += `&sort=${encodeURIComponent(sort)}&dir=${dir ?? "asc"}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (vocab != null) url += `&vocab=${encodeURIComponent(vocab)}`;
    if (filters && Object.keys(filters).length)
      url += `&filters=${encodeURIComponent(JSON.stringify(filters))}`;
    return request<RowsResponse>(url);
  },
  exportRows: (db: string, table: string, sort?: string, dir?: string, vocab?: number | null) => {
    let url = `/api/export?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}`;
    if (sort) url += `&sort=${encodeURIComponent(sort)}&dir=${dir ?? "asc"}`;
    if (vocab != null) url += `&vocab=${encodeURIComponent(vocab)}`;
    return request<ExportResponse>(url);
  },
  getNextId: (db: string, table: string) =>
    request<{ column: string | null; value: number | null }>(
      `/api/nextid?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}`
    ),
  getLookup: (db: string, table: string, idCol: string, labelCol: string) =>
    request<{ id: unknown; label: unknown }[]>(
      `/api/lookup?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}` +
        `&idCol=${encodeURIComponent(idCol)}&labelCol=${encodeURIComponent(labelCol)}`
    ),
  // Work roles (NICE/ECSF) + the people assigned to each — used to filter a person picker by role.
  personRoles: (framework = "NICE") =>
    request<{ framework: string; roles: { id: number; name: string; category: string }[]; byRole: Record<string, number[]> }>(
      `/api/workforce/person-roles?framework=${encodeURIComponent(framework)}`
    ),
  // Lookup of ONE single value (large table: no full preloading)
  getLookupOne: (db: string, table: string, idCol: string, idVal: string, labelCol: string) =>
    request<{ label: unknown }>(
      `/api/lookup-one?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}` +
        `&idCol=${encodeURIComponent(idCol)}&idVal=${encodeURIComponent(idVal)}` +
        `&labelCol=${encodeURIComponent(labelCol)}`
    ),
  // Lookup of SEVERAL values in one call (visible rows of a grid)
  getLookupMany: (db: string, table: string, idCol: string, labelCol: string, ids: string[]) =>
    request<{ id: unknown; label: unknown }[]>(
      `/api/lookup-many?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}` +
        `&idCol=${encodeURIComponent(idCol)}&labelCol=${encodeURIComponent(labelCol)}` +
        `&ids=${encodeURIComponent(ids.join(","))}`
    ),
  // ONE complete row (with rowid) by column=value (editing a target table)
  getRowById: (db: string, table: string, idCol: string, idVal: string) =>
    request<{ row: Record<string, unknown> | null }>(
      `/api/row-by-id?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}` +
        `&idCol=${encodeURIComponent(idCol)}&idVal=${encodeURIComponent(idVal)}`
    ),
  // On ASSET submission: notifies the uncorrected KEV ASSETVULNERABILITY rows
  checkAssetKevNotify: () =>
    request<{ created: number }>("/api/asset/check-kev-notify", "POST", {}),
  // Available connectors (for the web scan panel of the ASSET form)
  getConnectors: () =>
    request<{ id: string; name: string; type: string; category?: string; intrusive?: boolean;
      parameters?: { name: string; type: string }[] }[]>("/api/connectors"),
  getEngagements: () =>
    request<{ EngagementID: number; name: string }[]>("/api/engagements"),
  assetScreenshot: (url: string) =>
    request<{ url: string }>("/api/asset/screenshot", "POST", { url }),
  pentestBulkScan: (assetIds: number[], engagement: number, worker: string) =>
    request<{ jobs: number; assets: number; outOfScope: number; skippedNoTarget: number }>(
      "/api/pentest/bulk-scan", "POST", { assetIds, engagement, worker }
    ),
  agentBulkScan: (assetIds: number[], kind: string) =>
    request<{ queued: number; noAgent: string[]; kind: string }>(
      "/api/agent-bulk-scan", "POST", { assetIds, kind }
    ),
  addCpe: (name: string) =>
    request<{ id: number; name: string; created: boolean }>("/api/cpe", "POST", { name }),
  cpeBuilderOptions: () =>
    request<{ vendors: string[]; products: string[] }>("/api/cpe-builder-options"),
  cpeGcveSearch: (q: string, part = "") =>
    request<{ items: { cpe: string; title: string; part: string; version: string | null; deprecated: boolean; cpeNameId: string | null }[]; total: number }>(
      `/api/cpe-gcve-search?q=${encodeURIComponent(q)}${part ? `&part=${encodeURIComponent(part)}` : ""}`),
  // ── OCIL: questions of a questionnaire ──
  getQuestionnaireQuestions: (questionnaireId: number) =>
    request<number[]>(`/api/questionnaire-questions?questionnaireId=${questionnaireId}`),
  setQuestionnaireQuestions: (questionnaireId: number, questionIds: number[]) =>
    request<{ ok: boolean; count: number }>("/api/questionnaire-questions", "POST", { questionnaireId, questionIds }),
  // Export of a questionnaire (questions + linked answers) to generate an Excel
  getQuestionnaireExport: (questionnaireId: number) =>
    request<{ name: string; rows: Record<string, unknown>[] }>(
      `/api/questionnaire-export?questionnaireId=${questionnaireId}`
    ),
  createQuestion: (name: string) =>
    request<{ id: number; name: string; created: boolean }>("/api/question", "POST", { name }),
  // Import of a complete questionnaire (questions + links) from a mapped Excel/CSV file
  importQuestionnaireExcel: (name: string, fileName: string, questions: Record<string, unknown>[]) =>
    request<{ ok: boolean; questionnaireId: number; questions: number }>(
      "/api/questionnaire-import", "POST", { name, fileName, questions }
    ),
  // ── OCIL: evidence linked to an answer (ANSWEREVIDENCE) ──
  getAnswerEvidences: (answerId: number) =>
    request<number[]>(`/api/answer-evidences?answerId=${answerId}`),
  setAnswerEvidences: (answerId: number, evidenceIds: number[]) =>
    request<{ ok: boolean; count: number }>("/api/answer-evidences", "POST", { answerId, evidenceIds }),
  createEvidence: (name: string) =>
    request<{ id: number; name: string; created: boolean }>("/api/evidence", "POST", { name }),
  // ── THREAT ↔ ATT&CK techniques (THREATTTP) ──
  searchAttackTechniques: (q: string) =>
    request<{ AttackTechniqueID: number; AttackID: string; Name: string; Domain: string; IsSubtechnique: number }[]>(
      `/api/attack/technique-search?q=${encodeURIComponent(q)}`),
  getThreatTtps: (threatId: number) =>
    request<{ AttackTechniqueID: number; AttackID: string; Name: string; Domain: string }[]>(
      `/api/threat-ttps?threatId=${threatId}`),
  setThreatTtps: (threatId: number, techniqueIds: number[]) =>
    request<{ ok: boolean; count: number }>("/api/threat-ttps", "POST", { threatId, techniqueIds }),
  // ── Notifications ──
  getNotifications: (limit = 30) =>
    request<{ items: NotificationItem[]; unread: number }>(`/api/notifications?limit=${limit}`),
  markNotificationRead: (id: number) =>
    request<{ ok: boolean; unread: number }>(`/api/notifications/${id}/read`, "POST"),
  markAllNotificationsRead: () =>
    request<{ ok: boolean; changed: number; unread: number }>("/api/notifications/read-all", "POST"),
  createNotification: (payload: { title: string; message?: string; level?: string; link?: string; target?: string | number }) =>
    request<{ ok: boolean; created: number; id?: number }>("/api/notifications", "POST", payload),
  // Broadcast a "new alert" notification to all tenant users with XINCIDENT read access.
  notifyAlert: (alertId: number, alertName: string) =>
    request<{ ok: boolean; count: number }>("/api/alert/notify", "POST", { alertId, alertName }),
  // Duplicate check "*Name" (creation): does this value already exist?
  nameCheck: (db: string, table: string, col: string, value: string) =>
    request<{ exists: boolean; count: number }>(
      `/api/name-check?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}` +
        `&col=${encodeURIComponent(col)}&value=${encodeURIComponent(value)}`
    ),
  // OSV.dev: form enrichment / VULNERABILITY import
  osvLookup: (id: string) =>
    request<{ referential: string; fields: Record<string, string | number>; summary: string; cvssVector: string | null }>(
      `/api/osv/lookup?id=${encodeURIComponent(id)}`
    ),
  osvImport: (id: string) =>
    request<{ action: "inserted" | "updated"; vulnerabilityId: number; referential: string }>(
      "/api/osv/import", "POST", { id }
    ),
  // CIRCL vulnerability-lookup: KEV search / enrichment / import
  circlSearch: (q: string) =>
    request<{ id: string; summary: string }[]>(`/api/circl/search?q=${encodeURIComponent(q)}`),
  circlLookup: (id: string) =>
    request<{ referential: string; fields: Record<string, string | number>; summary: string; kev: boolean; cvssVector: string | null }>(
      `/api/circl/lookup?id=${encodeURIComponent(id)}`
    ),
  circlImport: (id: string) =>
    request<{ action: "inserted" | "updated"; vulnerabilityId: number; referential: string; kev: boolean }>(
      "/api/circl/import", "POST", { id }
    ),
  // Exploit-DB search (local SearchSploit index)
  exploitdbForCve: (cve: string) =>
    request<{ cve: string; results: { id: string; title: string; date: string; type: string; platform: string; port: string; cves: string[]; url: string }[] }>(
      `/api/exploitdb/cve/${encodeURIComponent(cve)}`
    ),
  // THREATAGENT ↔ CATEGORY (vocabulary-dependent)
  getThreatAgentCategories: (vocabId: number) =>
    request<{ id: number; label: string }[]>(
      `/api/threatagent-categories?vocabId=${encodeURIComponent(vocabId)}`
    ),
  getThreatAgentCategory: (threatAgentId: number) =>
    request<{ categoryId: number | null }>(
      `/api/threatagent-category?threatAgentId=${encodeURIComponent(threatAgentId)}`
    ),
  setThreatAgentCategory: (threatAgentId: number, categoryId: number | null) =>
    request<{ ok: boolean }>("/api/threatagent-category", "PUT", { threatAgentId, categoryId }),
  importRows: (db: string, table: string, rows: unknown[], replace = false) =>
    request<{ inserted: number; total: number; failed: number; errors: string[]; cleared: number }>(
      "/api/import", "POST", { db, table, rows, replace }
    ),
  getEnterpriseRiskScore: () =>
    request<{ score: number; tenantId: number | null }>("/api/dashboard/risk-score"),
  getVulnByYear: () =>
    request<{ year: string; count: number }[]>("/api/dashboard/vuln-by-year"),
  getAssetTagCloud: () =>
    request<{ tag: string; count: number }[]>("/api/dashboard/tag-cloud"),
  getIncidentsByStatus: () =>
    request<{ status: string; count: number }[]>("/api/dashboard/incidents-by-status"),
  getAssetFinancialValues: () =>
    request<{ assets: { name: string; value: number }[]; total: number; count: number }>(
      "/api/dashboard/asset-financial-value"
    ),
  getAssetRiskExposure: () =>
    request<{
      assets: { name: string; risk: number; value: number; exposure: number }[];
      totalExposure: number; totalValue: number; count: number;
    }>("/api/dashboard/asset-risk-exposure"),
  getAssetFinancialHistory: (asset: string) =>
    request<{ asset: string; points: { date: string; value: number; currency: string | null }[] }>(
      "/api/dashboard/asset-financial-history?asset=" + encodeURIComponent(asset)
    ),
  getIncidentsByAsset: (from?: string, to?: string) => {
    const q: string[] = [];
    if (from) q.push("from=" + encodeURIComponent(from));
    if (to) q.push("to=" + encodeURIComponent(to));
    const url = "/api/dashboard/incidents-by-asset" + (q.length ? "?" + q.join("&") : "");
    return request<{ asset: string; count: number }[]>(url);
  },
  getAssetCpes: (assetId: number) =>
    request<{ CPEID: number; CPEName: string }[]>(`/api/asset-cpes?assetId=${assetId}`),
  getVulnerabilityCpes: (vulnerabilityId: number) =>
    request<{ CPEID: number; CPEName: string; KnownVulnerable: boolean }[]>(`/api/vulnerability-cpes?vulnerabilityId=${vulnerabilityId}`),
  setAssetCpes: (assetId: number, cpeIds: number[]) =>
    request<{ ok: boolean }>("/api/asset-cpes", "PUT", { assetId, cpeIds }),
  getAssetVulnerabilities: (assetId: number) =>
    request<{ VulnerabilityID: number; VULReferentialID: string; VULGUID: string; VULDescription: string; AssetVulnerabilityID?: number; PatchStatus?: string | null; RemediationCount?: number; FalsePositive?: number }[]>(
      `/api/asset-vulnerabilities?assetId=${assetId}`
    ),
  setVulnFalsePositive: (assetVulnId: number, falsePositive: boolean, reason?: string) =>
    request<{ ok: boolean; falsePositive: boolean }>("/api/patch-management/false-positive", "POST", { assetVulnId, falsePositive, reason }),
  setVulnFalsePositiveBulk: (assetVulnIds: number[], falsePositive: boolean, reason?: string) =>
    request<{ ok: boolean; changed: number }>("/api/patch-management/false-positive/bulk", "POST", { assetVulnIds, falsePositive, reason }),
  createRemediationBulk: (body: { assetId: number; name: string; type?: string; status?: string; priority?: string; targetDate?: string; ownerPersonId?: string | number; description?: string; scope?: "missing" | "all" }) =>
    request<{ ok: boolean; created: number; skipped: number; total: number }>("/api/patch-management/remediation-bulk", "POST", body),
  getAssetRemediations: (assetId: number) =>
    request<{ plans: Record<string, { AssetVulnerabilityRemediationID: number; AssetVulnerabilityID: number; RemediationName: string; RemediationType: string | null; Status: string | null; Priority: string | null; TargetDate: string | null; OwnerName: string | null }[]> }>(
      `/api/patch-management/remediations?assetId=${assetId}`
    ),
  searchVulnerabilities: (q: string) =>
    request<{ VulnerabilityID: number; VULReferential: string; VULReferentialID: string; VULGUID: string; VULDescription: string }[]>(
      `/api/vuln-search?q=${encodeURIComponent(q)}`
    ),
  setAssetVulnerabilities: (assetId: number, vulnerabilityIds: number[]) =>
    request<{ ok: boolean }>("/api/asset-vulnerabilities", "PUT", { assetId, vulnerabilityIds }),
  getAssetTags: (assetId: number) =>
    request<string[]>(`/api/asset-tags?assetId=${assetId}`),
  setAssetTags: (assetId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/asset-tags", "PUT", { assetId, tags }),
  listTags: () => request<string[]>("/api/tags"),
  getVulnerabilityTags: (vulnerabilityId: number) =>
    request<string[]>(`/api/vuln-tags?vulnerabilityId=${vulnerabilityId}`),
  setVulnerabilityTags: (vulnerabilityId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/vuln-tags", "PUT", { vulnerabilityId, tags }),
  getCpeTags: (cpeId: number) =>
    request<string[]>(`/api/cpe-tags?cpeId=${cpeId}`),
  setCpeTags: (cpeId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/cpe-tags", "PUT", { cpeId, tags }),
  getCweTags: (cweId: number) =>
    request<string[]>(`/api/cwe-tags?cweId=${cweId}`),
  setCweTags: (cweId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/cwe-tags", "PUT", { cweId, tags }),
  getControlTags: (controlId: number) =>
    request<string[]>(`/api/control-tags?controlId=${controlId}`),
  setControlTags: (controlId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/control-tags", "PUT", { controlId, tags }),
  getSigmaRuleTags: (sigmaRuleId: number) =>
    request<string[]>(`/api/sigmarule-tags?sigmaRuleId=${sigmaRuleId}`),
  setSigmaRuleTags: (sigmaRuleId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/sigmarule-tags", "PUT", { sigmaRuleId, tags }),
  harvestAssetEmail: (email: string) =>
    request<{ ok: boolean; email: string; organisationId: number | null; emailInserted: boolean; addressInserted: boolean; orgLinkInserted: boolean }>(
      "/api/asset-email-harvest", "POST", { email }),
  lookupOrganisations: (q: string) =>
    request<{ OrganisationID: number; OrganisationName: string }[]>(`/api/lookup/organisations?q=${encodeURIComponent(q)}`),
  lookupPersons: (q: string) =>
    request<{ PersonID: number; PersonName: string }[]>(`/api/lookup/persons?q=${encodeURIComponent(q)}`),
  defaultOrganisation: () =>
    request<{ OrganisationID?: number; OrganisationName?: string }>("/api/default-organisation"),
  getAssetOrganisations: (assetId: number) =>
    request<{ OrganisationID: number; OrganisationName: string }[]>(`/api/asset-organisations?assetId=${assetId}`),
  setAssetOrganisations: (assetId: number, organisationIds: number[]) =>
    request<{ ok: boolean }>("/api/asset-organisations", "PUT", { assetId, organisationIds }),
  getAssetPersons: (assetId: number) =>
    request<{ PersonID: number; PersonName: string; relationshiptype: string }[]>(`/api/asset-persons?assetId=${assetId}`),
  setAssetPersons: (assetId: number, links: { personId: number; relationshiptype: string }[]) =>
    request<{ ok: boolean }>("/api/asset-persons", "PUT", { assetId, links }),
  setupStatus: () =>
    request<{ needed: boolean }>("/api/setup/status"),
  setupAdminAsset: (organisationId: number) =>
    request<{ ok: boolean; adminAssetId: number; xorcismAssetId: number; applicationId: number;
      created: { adminAsset: boolean; xorcismAsset: boolean; application: boolean } }>(
      "/api/setup/admin-asset", "POST", { organisationId }),
  getOvalDefinitionTags: (ovalDefinitionId: number) =>
    request<string[]>(`/api/ovaldef-tags?ovalDefinitionId=${ovalDefinitionId}`),
  setOvalDefinitionTags: (ovalDefinitionId: number, tags: string[]) =>
    request<{ ok: boolean }>("/api/ovaldef-tags", "PUT", { ovalDefinitionId, tags }),
  getIncidentAssets: (incidentId: number) =>
    request<number[]>(`/api/incident-assets?incidentId=${incidentId}`),
  setIncidentAssets: (incidentId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/incident-assets", "PUT", { incidentId, assetIds }),
  getPolicyAssets: (policyId: number) =>
    request<number[]>(`/api/policy-assets?policyId=${policyId}`),
  setPolicyAssets: (policyId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/policy-assets", "PUT", { policyId, assetIds }),
  getAlertAssets: (alertId: number) =>
    request<number[]>(`/api/alert-assets?alertId=${alertId}`),
  setAlertAssets: (alertId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/alert-assets", "PUT", { alertId, assetIds }),
  triageVuln: (p: { cve?: string; vulnerabilityId?: number }) =>
    request<{ assessment: string; context: string; model: string }>("/api/ai/triage-vuln", "POST", p),
  enrichReport: (reportId: number) =>
    request<{ summary: string; cves: string[]; model: string }>("/api/ai/enrich-report", "POST", { reportId }),
  buildBrief: (reportIds: number[], focus?: string) =>
    request<{ brief: string; sources: string[]; model: string }>("/api/ai/brief", "POST", { reportIds, focus }),
  assetsWithTags: () =>
    request<{ AssetID: number; AssetName: string; Tags: string }[]>("/api/assets-with-tags"),
  bulkThreatForAsset: (p: { threatId: number; assetIds: number[]; relationship?: string; validFrom?: string; validUntil?: string }) =>
    request<{ ok: boolean; created: number; skipped: number }>("/api/threat-for-asset/bulk", "POST", p),
  getThreatAssets: (threatId: number) =>
    request<number[]>(`/api/threat-assets?threatId=${threatId}`),
  setThreatAssets: (threatId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/threat-assets", "PUT", { threatId, assetIds }),
  getIncidentThreatActor: (incidentId: number) =>
    request<{ name: string }>(`/api/incident-threatactor?incidentId=${incidentId}`),
  setIncidentThreatActor: (incidentId: number, actorName: string) =>
    request<{ ok: boolean }>("/api/incident-threatactor", "PUT", { incidentId, actorName }),
  // ── Audit ↔ assets (ASSETAUDIT) ──
  getAuditAssets: (auditId: number) =>
    request<number[]>(`/api/audit-assets?auditId=${auditId}`),
  setAuditAssets: (auditId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/audit-assets", "PUT", { auditId, assetIds }),
  // ── Audits linked to an asset (ASSETAUDIT) ──
  getAssetAudits: (assetId: number) =>
    request<{ AuditID: number; AuditName: string }[]>(`/api/asset-audits?assetId=${assetId}`),
  setAssetAudits: (assetId: number, auditIds: number[]) =>
    request<{ ok: boolean }>("/api/asset-audits", "PUT", { assetId, auditIds }),
  // ── OVAL definitions linked to an asset (ASSETOVALDEFINITION) ──
  getAssetOvals: (assetId: number) =>
    request<{ AssetOVALDefinitionID: number; OVALDefinitionID: number; Pattern: string; Title: string | null; Status: string | null }[]>(
      `/api/asset-ovals?assetId=${assetId}`
    ),
  searchOvalDefinitions: (q: string) =>
    request<{ OVALDefinitionID: number; OVALDefinitionIDPattern: string; OVALDefinitionTitle: string }[]>(
      `/api/oval-search?q=${encodeURIComponent(q)}`
    ),
  addAssetOval: (assetId: number, ovalDefinitionId: number) =>
    request<{ ok: boolean }>("/api/asset-ovals", "POST", { assetId, ovalDefinitionId }),
  removeAssetOval: (assetId: number, assetOvalDefinitionId: number) =>
    request<{ ok: boolean }>("/api/asset-ovals", "DELETE", { assetId, assetOvalDefinitionId }),
  // ── Geolocations of an asset (ASSETGEOLOCATION) ──
  getAssetGeolocations: (assetId: number) =>
    request<{ AssetGeoLocationID: number; GeoLocationID: number | null; Location: string; CollectionTimestamp: string | null; CreatedDate: string | null }[]>(
      `/api/asset-geolocations?assetId=${assetId}`
    ),
  // ── Threat models ──
  getThreatModelAssets: (modelId: number) =>
    request<{ AssetID: number; AssetName: string }[]>(`/api/threatmodel-assets?modelId=${modelId}`),
  setThreatModelAssets: (modelId: number, assetIds: number[]) =>
    request<{ ok: boolean }>("/api/threatmodel-assets", "PUT", { modelId, assetIds }),
  getThreatModelThreats: (modelId: number) =>
    request<{ ThreatModelThreatID: number; Title: string; STRIDECategory: string; Likelihood: string; Impact: string; RiskScore: string; Status: string }[]>(
      `/api/threatmodel-threats?modelId=${modelId}`
    ),
  addThreatModelThreat: (modelId: number, threat: Record<string, unknown>) =>
    request<{ ok: boolean; id: number }>("/api/threatmodel-threats", "POST", { modelId, threat }),
  getThreatControls: (threatId: number) =>
    request<{ ControlID: number; ControlName: string }[]>(`/api/threat-controls?threatId=${threatId}`),
  setThreatControls: (threatId: number, controlIds: number[]) =>
    request<{ ok: boolean }>("/api/threat-controls", "PUT", { threatId, controlIds }),
  insertRow: (db: string, table: string, row: Record<string, unknown>) =>
    request<{ ok: boolean; id?: number | string | null }>("/api/insert", "POST", { db, table, row }),
  updateRow: (db: string, table: string, rowid: number, row: Record<string, unknown>) =>
    request<{ ok: boolean }>("/api/update", "PUT", { db, table, rowid, row }),
  deleteRow: (db: string, table: string, rowid: number) =>
    request<{ ok: boolean }>("/api/delete", "POST", { db, table, rowid }),
};

// ── BIA API ───────────────────────────────────────────────────────────────────

export const biaApi = {
  getAudits: () => request<BiaAudit[]>("/api/bia/audits"),
  createAudit: (data: BiaAudit) =>
    request<{ id: number }>("/api/bia/audits", "POST", data),
  updateAuditStatus: (id: number, status: string) =>
    request<{ ok: boolean }>(`/api/bia/audits/${id}`, "PATCH", {
      BIAAuditStatus: status,
    }),
  deleteAudit: (id: number) =>
    request<{ ok: boolean }>(`/api/bia/audits/${id}`, "DELETE"),

  getEntries: (auditId: number) =>
    request<BiaEntry[]>(`/api/bia/entries?auditId=${auditId}`),
  createEntry: (data: BiaEntry) =>
    request<{ id: number }>("/api/bia/entries", "POST", data),
  updateEntry: (id: number, data: BiaEntry) =>
    request<{ ok: boolean }>(`/api/bia/entries/${id}`, "PUT", data),
  deleteEntry: (id: number) =>
    request<{ ok: boolean }>(`/api/bia/entries/${id}`, "DELETE"),

  searchAssets: (q: string) =>
    request<Record<string, unknown>[]>(
      `/api/bia/assets?q=${encodeURIComponent(q)}`
    ),
  assetNames: () => request<string[]>("/api/bia/asset-names"),
  personNames: () => request<string[]>("/api/bia/person-names"),
  searchPersons: (q: string) =>
    request<Record<string, unknown>[]>(
      `/api/bia/persons?q=${encodeURIComponent(q)}`
    ),
};
