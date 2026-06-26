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
