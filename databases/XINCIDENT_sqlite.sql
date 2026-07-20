BEGIN TRANSACTION;

/****** 
Copyright (C) 2014-2015 Jerome Athias
Incidents related tables for XORCISM database
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "INCIDENT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENT"(
	"IncidentID" INTEGER NOT NULL,
	"source_id" TEXT NULL,
	"IncidentCategoryID" INTEGER NULL,
	"publication_status" TEXT NULL,
	"datetime_reported" TEXT NULL,
	"start_datetime" TEXT NULL,
	"end_datetime" TEXT NULL,
	"detect_datetime" TEXT NULL,
	"confirmed" INTEGER NULL,
	"security_compromise" TEXT NULL,
	"exercise" INTEGER NULL,
	"ProjectID" INTEGER NULL,
	"exercise_name" TEXT NULL,
	"import_datetime" TEXT NULL,
	BLOB TEXT NULL,
	"IncidentStatusID" INTEGER NULL,
	"status" TEXT NULL,
	"status_description" TEXT NULL,
	"synopsis" TEXT NULL,
	"summary" TEXT NULL,
	"impact" TEXT NULL,
	"confidence" TEXT NULL,
	"notes" TEXT NULL,
	"locations_affected" INTEGER NULL,
	"IncidentDiscoveryMethodID" INTEGER NULL,
	"control_failure" TEXT NULL,
	"corrective_action" TEXT NULL,
	"AlternativeID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "INCIDENTCATEGORY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTCATEGORY"(
	"IncidentCategoryID" INTEGER NOT NULL,
	"IncidentCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"IncidentCategoryName" TEXT NOT NULL,
	"IncidentCategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTCATEGORYDESCRIPTION"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTCATEGORYDESCRIPTION"(
	"IncidentCategoryDescriptionID" INTEGER NOT NULL,
	"IncidentCategoryID" INTEGER NOT NULL,
	"IncidentCategoryGUID" TEXT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"DescriptionGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTCATEGORYRACIMATRIX"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTCATEGORYRACIMATRIX"(
	"IncidentCategoryRACIMatrixID" INTEGER NOT NULL
)

;
/****** Object:  Table "INCIDENTCOMPROMISE"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTCOMPROMISE"(
	"IncidentCompromiseID" INTEGER NOT NULL,
	"IncidentCompromiseGUID" TEXT NULL,
	"SecurityCompromise" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"documentation" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTDISCOVERYMETHOD"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTDISCOVERYMETHOD"(
	"IncidentDiscoveryMethodID" INTEGER NOT NULL,
	"DiscoveryMethodID" INTEGER NULL,
	"IncidentDiscoveryMethodName" TEXT NOT NULL,
	"IncidentDiscoveryMethodDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTEFFECT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTEFFECT"(
	"IncidentEffectID" INTEGER NOT NULL,
	"IncidentEffectGUID" TEXT NULL,
	"PossibleEffect" TEXT NOT NULL,
	"IncidentEffectDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTFORASSET"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTFORASSET"(
	"AssetIncidentID" INTEGER NOT NULL,
	"AssetIncidentGUID" TEXT NULL,
	"AssetID" INTEGER NOT NULL,
	"AssetGUID" TEXT NULL,
	"AssetIncidentRelationship" TEXT NULL,
	"AssetIncidentDescription" TEXT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"notes" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTFORINCIDENT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTFORINCIDENT"(
	"IncidentRefID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"relationshipscope" TEXT NULL,
	"IncidentSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "INCIDENTFORPERSON"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTFORPERSON"(
	"IncidentID" INTEGER NOT NULL,
	"PersonID" INTEGER NOT NULL,
	"relationshiptype" TEXT NULL,
	"notes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "INCIDENTFORTHREATCAMPAIGN"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTFORTHREATCAMPAIGN"(
	"IncidentID" INTEGER NOT NULL,
	"CampaignID" INTEGER NOT NULL
)

;
/****** Object:  Table "INCIDENTID"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTID"(
	"IncidentIDID" INTEGER NOT NULL,
	"name" TEXT NOT NULL,
	"instance" TEXT NULL,
	"restriction" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIMPACT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACT"(
	"IncidentImpactID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentImpactRatingID" INTEGER NULL,
	"IncidentImpactLossVarietyID" INTEGER NULL,
	"IncidentImpactLossRatingID" INTEGER NULL,
	"overall_amount" REAL NULL,
	"overall_min_amount" REAL NULL,
	"overall_max_amount" REAL NULL,
	"iso_currency_code" TEXT NULL,
	"notes" TEXT NULL,
	"DateCreated" TEXT NULL,
	BLOB TEXT NULL,
	"IncidentImpactAvailabilityVarietyID" INTEGER NULL,
	"IncidentImpactAvailabilityDurationLossID" INTEGER NULL,
	"IncidentImpactIntegrityVarietyID" INTEGER NULL,
	"IncidentImpactConfidentialityStateID" INTEGER NULL,
	"IncidentImpactConfidentialityVarietyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIMPACTAVAILABILITYLOSSDURATION"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTAVAILABILITYLOSSDURATION"(
	"IncidentImpactAvailabilityLossDurationID" INTEGER NOT NULL,
	"LossDuration" TEXT NOT NULL,
	"LossDurationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIMPACTAVAILABILITYVARIETY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTAVAILABILITYVARIETY"(
	"IncidentImpactAvailabilityVarietyID" INTEGER NOT NULL,
	"IncidentImpactAvailabilityVarietyName" TEXT NULL,
	"IncidentImpactAvailabilityVarietyDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTIMPACTCONFIDENTIALITYSTATE"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTCONFIDENTIALITYSTATE"(
	"IncidentImpactConfidentialityStateID" INTEGER NOT NULL,
	"IncidentImpactConfidentialityStateName" TEXT NOT NULL,
	"IncidentImpactConfidentialityStateDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTIMPACTCONFIDENTIALITYVARIETY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTCONFIDENTIALITYVARIETY"(
	"IncidentImpactConfidentialityVarietyID" INTEGER NOT NULL,
	"IncidentImpactConfidentialityVarietyName" TEXT NOT NULL,
	"IncidentImpactConfidentialityVarietyDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTIMPACTINTEGRITYVARIETY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTINTEGRITYVARIETY"(
	"IncidentImpactIntegrityVarietyID" INTEGER NOT NULL,
	"IncidentImpactIntegrityVarietyName" TEXT NOT NULL,
	"IncidentImpactIntegrityVarietyDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTIMPACTLOSSPROPERTY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTLOSSPROPERTY"(
	"IncidentImpactLossPropertyID" INTEGER NOT NULL,
	"IncidentImpactLossPropertyName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIMPACTLOSSRATING"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTLOSSRATING"(
	"IncidentImpactLossRatingID" INTEGER NOT NULL,
	"IncidentImpactLossRatingName" TEXT NOT NULL,
	"IncidentImpactLossRatingDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTIMPACTLOSSVARIETY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTLOSSVARIETY"(
	"IncidentImpactLossVarietyID" INTEGER NOT NULL,
	"IncidentImpactLossVarietyName" TEXT NOT NULL,
	"IncidentImpactLossVarietyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIMPACTRATING"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIMPACTRATING"(
	"IncidentImpactRatingID" INTEGER NOT NULL,
	"IncidentImpactRatingName" TEXT NOT NULL,
	"IncidentImpactRatingDescription" TEXT NULL
)

;
/****** Object:  Table "INCIDENTINQUIRY"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTINQUIRY"(
	"IncidentIQID" INTEGER NOT NULL,
	"IncidentInquiryIntentID" INTEGER NULL,
	"purpose" TEXT NOT NULL,
	"CreatedDate" TEXT NULL,
	"format" TEXT NULL,
	BLOB TEXT NULL,
	"lang" TEXT NULL,
	"restriction" TEXT NULL,
	"IODEFversion" TEXT NULL,
	"formatid" TEXT NULL
)

;
/****** Object:  Table "INCIDENTINQUIRYINTENT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTINQUIRYINTENT"(
	"IncidentInquiryIntentID" INTEGER NOT NULL,
	"PackageIntent" TEXT NOT NULL,
	"PackageIntentDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIOC"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIOC"(
	"IncidentIOCID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"comment" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"IncidentIOCTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "INCIDENTIOCFORTHREATCAMPAIGN"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIOCFORTHREATCAMPAIGN"(
	"IncidentIOCID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL
)

;
/****** Object:  Table "INCIDENTIOCTYPE"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIOCTYPE"(
	"IncidentIOCTypeID" INTEGER NOT NULL,
	"IndicatorTypeName" TEXT NOT NULL,
	"IndicatorTypeDocumentaion" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTIOCTYPEFORINDICATOR"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTIOCTYPEFORINDICATOR"(
	"IncidentIOCTypeID" INTEGER NOT NULL,
	"IndicatorID" INTEGER NOT NULL
)

;
/****** Object:  Table "INCIDENTREGISTRYHANDLE"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTREGISTRYHANDLE"(
	"IncidentRegistryHandleID" INTEGER NOT NULL,
	"registry" TEXT NOT NULL
)

;
/****** Object:  Table "INCIDENTSTATUS"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTSTATUS"(
	"IncidentStatusID" INTEGER NOT NULL,
	"IncidentStatusGUID" TEXT NULL,
	"IncidentStatusName" TEXT NOT NULL,
	"IncidentStatusDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "INCIDENTTIMELINE"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTTIMELINE"(
	"IncidentTimelineID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"investigationDate" TEXT NULL,
	"incidentDate" TEXT NULL,
	"TimetoCompromiseValue" INTEGER NULL,
	"TimetoCompromiseUnit" TEXT NULL,
	"TimetoExfiltrationValue" INTEGER NULL,
	"TimetoExfiltrationUnit" TEXT NULL,
	"TimetoDiscoveryValue" INTEGER NULL,
	"TimetoDiscoveryUnit" TEXT NULL,
	"TimetoContainmentValue" INTEGER NULL,
	"TimetoContainmentUnit" TEXT NULL
)

;
/****** Object:  Table "INCIDENTTIMELINEUNIT"    Script Date: 04/03/2015 19:13:11 ******/

;

;
CREATE TABLE "INCIDENTTIMELINEUNIT"(
	"IncidentTimelineUnitID" INTEGER NOT NULL,
	"TimeUnit" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;

/****** Object:  Table "ALERT"  (security alerts, optionally linked to an INCIDENT; tenant-scoped) ******/

;
CREATE TABLE IF NOT EXISTS "ALERT"(
	"AlertID" INTEGER PRIMARY KEY,
	"AlertGUID" TEXT NULL,
	"AlertName" TEXT NULL,
	"AlertDescription" TEXT NULL,
	"Severity" TEXT NULL,
	"Status" TEXT NULL,
	"Category" TEXT NULL,
	"AttackTechniques" TEXT NULL,
	"RecommendedActions" TEXT NULL,
	"ServiceSource" TEXT NULL DEFAULT 'XORCISM',
	"DetectionSource" TEXT NULL DEFAULT 'Manual',
	"Classification" TEXT NULL,
	"Determination" TEXT NULL,
	"AssignedTo" TEXT NULL,
	"Tags" TEXT NULL,
	"Duration" REAL NULL,
	"PersonID" INTEGER NULL,
	"CreatedDate" DATE NULL,
	"IncidentID" INTEGER NULL,
	"TenantID" INTEGER NULL
)

;
CREATE INDEX IF NOT EXISTS ix_alert_incident ON ALERT(IncidentID)

;

/****** Object:  Table "ALERTFORASSET"  (Defender "Select entities": impacted assets of an alert) ******/

;
CREATE TABLE IF NOT EXISTS "ALERTFORASSET"(
	"AssetAlertID" INTEGER PRIMARY KEY,
	"AlertID" INTEGER NULL,
	"AssetID" INTEGER NULL,
	"Relationship" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"TenantID" INTEGER NULL,
	UNIQUE("AlertID", "AssetID")
)

;
CREATE INDEX IF NOT EXISTS ix_alertforasset_alert ON ALERTFORASSET(AlertID)

;
/****** Object:  Table "ALERTEVIDENCE"  (Defender "Select entities": related evidence of an alert) ******/

;
CREATE TABLE IF NOT EXISTS "ALERTEVIDENCE"(
	"AlertEvidenceID" INTEGER PRIMARY KEY,
	"AlertID" INTEGER NULL,
	"EvidenceType" TEXT NULL,
	"EvidenceValue" TEXT NULL,
	"EvidenceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"TenantID" INTEGER NULL
)

;
CREATE INDEX IF NOT EXISTS ix_alertevidence_alert ON ALERTEVIDENCE(AlertID)

;

-- Regulatory incident-reporting obligations — tracked submissions per incident × regulator × stage
-- (DORA / NIS2 / GDPR / CRA reporting deadlines).
CREATE TABLE IF NOT EXISTS "REGINCIDENTREPORT" (
  "ReportID" INTEGER PRIMARY KEY, "IncidentID" INTEGER, "TenantID" INTEGER, "Regulator" TEXT, "Stage" TEXT,
  "DueDate" TEXT, "Status" TEXT DEFAULT 'pending', "SubmittedDate" TEXT, "Reference" TEXT, "Notes" TEXT, "CreatedDate" TEXT);
CREATE INDEX IF NOT EXISTS ix_regincrep_inc ON "REGINCIDENTREPORT"("IncidentID");
CREATE INDEX IF NOT EXISTS ix_regincrep_tenant ON "REGINCIDENTREPORT"("TenantID");

-- Lightweight per-incident evidence file attachments. File bytes live in the content-addressed
-- blob store (XORCISM.FILEBLOB, deduped by Sha256); this table is the per-incident registry only.
-- For chain-of-custody evidence use CERT Operations (forensic cases). Tenant-scoped.
CREATE TABLE IF NOT EXISTS "INCIDENTEVIDENCE" (
  "EvidenceID" INTEGER PRIMARY KEY, "EvidenceGUID" TEXT, "IncidentID" INTEGER, "FileName" TEXT, "ContentType" TEXT,
  "Sha256" TEXT, "Size" INTEGER, "Description" TEXT, "UploadedByUserID" INTEGER, "UploadedByName" TEXT,
  "CreatedDate" TEXT, "TenantID" INTEGER);
CREATE INDEX IF NOT EXISTS ix_incevidence_inc ON "INCIDENTEVIDENCE"("IncidentID");
CREATE INDEX IF NOT EXISTS ix_incevidence_tenant ON "INCIDENTEVIDENCE"("TenantID");

COMMIT;

-- ============================================================================
-- Schema sync — runtime tables/columns/indexes created by the server's ensure*
-- functions, appended to keep this canonical script in step with the live schema.
-- Generated 2026-06-29. Additive; safe to re-run the script.
-- ============================================================================
-- New tables (18)
CREATE TABLE IF NOT EXISTS CERTACTIVITY ( ActivityID INTEGER PRIMARY KEY, ActivityGUID TEXT, Title TEXT, ActivityType TEXT, Service TEXT, Status TEXT, Priority TEXT, IncidentID INTEGER, CaseID INTEGER, AssignedTo TEXT, Description TEXT, DueDate TEXT, TenantID INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS CUSTODYEVENT ( CustodyID INTEGER PRIMARY KEY, EvidenceID INTEGER, CaseID INTEGER, Action TEXT, FromParty TEXT, ToParty TEXT, Purpose TEXT, Hash TEXT, HashVerified INTEGER, At TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS ESCALATIONPOLICY ( PolicyID INTEGER PRIMARY KEY, PolicyGUID TEXT, Name TEXT, Description TEXT, IsDefault INTEGER DEFAULT 0, TenantID INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS ESCALATIONTIER ( TierID INTEGER PRIMARY KEY, PolicyID INTEGER, Level INTEGER, Name TEXT, TargetRole TEXT, AckMinutes INTEGER, ResolveMinutes INTEGER, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS FORENSICCASE ( CaseID INTEGER PRIMARY KEY, CaseGUID TEXT, CaseNumber TEXT, Title TEXT, IncidentID INTEGER, Status TEXT, Severity TEXT, Examiner TEXT, ExaminerPersonID INTEGER, Description TEXT, Methodology TEXT, OpenedDate TEXT, ClosedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS FORENSICEVIDENCE ( EvidenceID INTEGER PRIMARY KEY, EvidenceGUID TEXT, CaseID INTEGER, ExhibitNumber TEXT, Description TEXT, EvidenceType TEXT, Source TEXT, AcquisitionTool TEXT, Sha256 TEXT, Md5 TEXT, Size TEXT, Status TEXT, CollectedBy TEXT, CollectedAt TEXT, StorageLocation TEXT, TenantID INTEGER, CreatedDate TEXT);
-- Forensix DFIR methodology conformity checklist (/cert-ops, server/certops.ts): 85 controls / 6 phases per forensic case.
CREATE TABLE IF NOT EXISTS FORENSICCHECK ( CheckID INTEGER PRIMARY KEY, CaseID INTEGER, PhaseKey TEXT, Ref TEXT, Title TEXT, Description TEXT, Norm TEXT, Status TEXT, EvidenceRef TEXT, EvidenceID INTEGER, Notes TEXT, UpdatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS INCIDENTESCALATION ( EscalationID INTEGER PRIMARY KEY, IncidentID INTEGER, FromTier TEXT, ToTier TEXT, Reason TEXT, ByPerson TEXT, ToPerson TEXT, EscalatedAt TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS INCIDENTPLAYBOOKSTEP ( RunStepID INTEGER PRIMARY KEY, IncidentID INTEGER, PlaybookID INTEGER, Phase TEXT, StepOrder INTEGER, Title TEXT, Description TEXT, Status TEXT DEFAULT 'todo', CompletedBy TEXT, CompletedAt TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS PLAYBOOK ( PlaybookID INTEGER PRIMARY KEY, PlaybookGUID TEXT, Name TEXT, Category TEXT, Description TEXT, Severity TEXT, StepCount INTEGER, TenantID INTEGER, CreatedDate TEXT, "Scenario" TEXT, "IncidentType" TEXT, "Priority" TEXT, "DetectionSources" TEXT, "AttackTechniques" TEXT, "Tools" TEXT, "Metrics" TEXT, "Source" TEXT);
CREATE TABLE IF NOT EXISTS PLAYBOOKSTEP ( StepID INTEGER PRIMARY KEY, PlaybookID INTEGER, Phase TEXT, StepOrder INTEGER, Title TEXT, Description TEXT, Role TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SIEMEVENT ( EventID INTEGER PRIMARY KEY, EventGUID TEXT, Source TEXT, Host TEXT, UserName TEXT, Raw TEXT, Matched INTEGER DEFAULT 0, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SOARPLAYBOOK ( PlaybookID INTEGER PRIMARY KEY, PlaybookGUID TEXT, Name TEXT, Description TEXT, TriggerType TEXT, Category TEXT, Enabled INTEGER DEFAULT 1, RunCount INTEGER DEFAULT 0, LastRunAt TEXT, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SOARPLAYBOOKACTION ( ActionID INTEGER PRIMARY KEY, PlaybookID INTEGER, StepOrder INTEGER, ActionType TEXT, Name TEXT, Params TEXT, OnFailure TEXT DEFAULT 'continue', CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SOARRUN ( RunID INTEGER PRIMARY KEY, RunGUID TEXT, PlaybookID INTEGER, Mode TEXT, TriggerRef TEXT, Status TEXT, Steps INTEGER, StartedAt TEXT, FinishedAt TEXT, Summary TEXT, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SOARRUNSTEP ( RunStepID INTEGER PRIMARY KEY, RunID INTEGER, StepOrder INTEGER, ActionType TEXT, Name TEXT, Status TEXT, Output TEXT, CreatedDate TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS SOCCMMASPECT ( AspectID INTEGER PRIMARY KEY, Domain TEXT, Aspect TEXT, Description TEXT, Weight REAL DEFAULT 1, SortOrder INTEGER);
CREATE TABLE IF NOT EXISTS SOCCMMSCORE ( ScoreID INTEGER PRIMARY KEY, AspectID INTEGER, Maturity INTEGER, Importance INTEGER DEFAULT 3, Notes TEXT, AssessedDate TEXT, TenantID INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS SOCSHIFT ( ShiftID INTEGER PRIMARY KEY, ShiftGUID TEXT, PersonID INTEGER, PersonName TEXT, Tier TEXT, ShiftDate TEXT, StartTime TEXT, EndTime TEXT, OnCall INTEGER DEFAULT 0, Status TEXT, Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
-- New columns (16)
ALTER TABLE "INCIDENT" ADD COLUMN "Severity" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "AttackTechniques" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "Classification" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "Determination" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "AssignedTo" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "Tags" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "RecommendedActions" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "Duration" REAL;
ALTER TABLE "INCIDENT" ADD COLUMN "acknowledge_datetime" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "EscalationTier" TEXT;
ALTER TABLE "INCIDENT" ADD COLUMN "PlaybookID" INTEGER;
ALTER TABLE "INCIDENT" ADD COLUMN "AssignedPersonID" INTEGER;
ALTER TABLE "INCIDENT" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "INCIDENTFORASSET" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "ALERT" ADD COLUMN "ExternalID" TEXT;
ALTER TABLE "ALERT" ADD COLUMN "ExternalUrl" TEXT;
-- New indexes (21)
CREATE INDEX IF NOT EXISTS "ix_ALERTEVIDENCE_tenant" ON "ALERTEVIDENCE" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_ALERTFORASSET_tenant" ON "ALERTFORASSET" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_ALERT_tenant" ON "ALERT" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_INCIDENTFORASSET_tenant" ON "INCIDENTFORASSET" ("TenantID");
CREATE INDEX IF NOT EXISTS "ix_INCIDENT_tenant" ON "INCIDENT" ("TenantID");
CREATE INDEX IF NOT EXISTS ix_alert_extid ON ALERT(DetectionSource, ExternalID);
CREATE INDEX IF NOT EXISTS ix_certact_tenant ON CERTACTIVITY(TenantID);
CREATE INDEX IF NOT EXISTS ix_custody_evid ON CUSTODYEVENT(EvidenceID);
CREATE INDEX IF NOT EXISTS ix_esctier_policy ON ESCALATIONTIER(PolicyID);
CREATE INDEX IF NOT EXISTS ix_fcase_tenant ON FORENSICCASE(TenantID);
CREATE INDEX IF NOT EXISTS ix_fcheck_case ON FORENSICCHECK(CaseID);
CREATE UNIQUE INDEX IF NOT EXISTS ux_fcheck_case_ref ON FORENSICCHECK(CaseID, Ref);
CREATE INDEX IF NOT EXISTS ix_fevid_case ON FORENSICEVIDENCE(CaseID);
CREATE INDEX IF NOT EXISTS ix_incesc_incident ON INCIDENTESCALATION(IncidentID);
CREATE INDEX IF NOT EXISTS ix_incpbstep_incident ON INCIDENTPLAYBOOKSTEP(IncidentID);
CREATE INDEX IF NOT EXISTS ix_pbstep_playbook ON PLAYBOOKSTEP(PlaybookID);
CREATE INDEX IF NOT EXISTS ix_siemevent_created ON SIEMEVENT(CreatedDate);
CREATE INDEX IF NOT EXISTS ix_siemevent_tenant ON SIEMEVENT(TenantID);
CREATE INDEX IF NOT EXISTS ix_soarplaybook_tenant ON SOARPLAYBOOK(TenantID);
CREATE INDEX IF NOT EXISTS ix_soarrun_pb ON SOARRUN(PlaybookID);
CREATE INDEX IF NOT EXISTS ix_socshift_person ON SOCSHIFT(PersonID);
CREATE INDEX IF NOT EXISTS ix_socshift_tenant ON SOCSHIFT(TenantID);
CREATE UNIQUE INDEX IF NOT EXISTS ux_soccmm_score ON SOCCMMSCORE(AspectID, TenantID);
