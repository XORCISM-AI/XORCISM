BEGIN TRANSACTION;

/****** 
Copyright (C) 2014-2015 Jerome Athias
Threats related tables for XORCISM database
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "THREATACTION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTION"(
	"ThreatActionID" INTEGER NOT NULL,
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionCategoryName" TEXT NULL,
	"ThreatActionName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"notes" TEXT NULL,
	"target" TEXT NULL,
	"AssetID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"PhysicalLocationID" INTEGER NULL,
	"ThreatActionTargetID" INTEGER NULL,
	"ThreatActionLocationID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTIONCATEGORY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONCATEGORY"(
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionCategoryName" TEXT NOT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTIONFORINCIDENT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONFORINCIDENT"(
	"IncidentThreatActionID" INTEGER NOT NULL,
	"ThreatActionID" INTEGER NOT NULL,
	"ThreatActorID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ThreatIntendedEffectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTIONLOCATION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONLOCATION"(
	"ThreatActionLocationID" INTEGER NOT NULL,
	"ThreatActionLocationName" TEXT NOT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"PhysicalLocationID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTIONLOCATIONFORTHREATACTIONCATEGORY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONLOCATIONFORTHREATACTIONCATEGORY"(
	"ThreatActionCategoryLocationID" INTEGER NOT NULL,
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionLocationID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATACTIONTARGET"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONTARGET"(
	"ThreatActionTargetID" INTEGER NOT NULL,
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionTargetName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTIONVARIETY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONVARIETY"(
	"ThreatActionVarietyID" INTEGER NOT NULL,
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionVarietyName" TEXT NOT NULL,
	"ThreatActionCategoryDescription" TEXT NULL,
	"WASCID" TEXT NULL,
	"note" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTIONVARIETYFORTHREATACTORTTP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONVARIETYFORTHREATACTORTTP"(
	"ThreatActorTTPActionVarietyID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActionVarietyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTIONVECTOR"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTIONVECTOR"(
	"ThreatActionVectorID" INTEGER NOT NULL,
	"ThreatActionCategoryID" INTEGER NOT NULL,
	"ThreatActionVectorName" TEXT NOT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTOR"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTOR"(
	"ThreatActorID" INTEGER NOT NULL,
	"ThreatActorGUID" TEXT NULL,
	"ThreatActorName" TEXT NULL,
	"ThreatActorDescription" TEXT NULL,
	"ActorExternal" INTEGER NULL,
	"ActorInternal" INTEGER NULL,
	"role" TEXT NULL,
	"country" TEXT NULL,
	"notes" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"CriticalityLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORADDRESS"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORADDRESS"(
	"ThreatActorAddressID" INTEGER NOT NULL,
	"ThreatActorID" INTEGER NULL,
	"ThreatActorGUID" TEXT NULL,
	"AddressID" INTEGER NULL,
	"AddressGUID" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"CollectionMethodID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"LastCheckedDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORCHANGERECORD"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORCHANGERECORD"(
	"ThreatActorChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATACTOREMAILADDRESS"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTOREMAILADDRESS"(
	"ThreatActorEmailAddressID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATACTORFORINCIDENT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORFORINCIDENT"(
	"IncidentThreatActorID" INTEGER NOT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentGUID" TEXT NULL,
	"ThreatActorID" INTEGER NOT NULL,
	"ThreatActorGUID" TEXT NULL,
	"ThreatMotiveID" INTEGER NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"ThreatActorRoleID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORFORTHREATCAMPAIGN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORFORTHREATCAMPAIGN"(
	"ThreatCampaignActorID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"ThreatActorID" INTEGER NOT NULL,
	"ThreatActorGUID" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"notes" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORGROUP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORGROUP"(
	"ThreatActorGroupID" INTEGER NOT NULL,
	"ThreatActorGroupGUID" TEXT NULL,
	"GroupID" INTEGER NULL,
	"ThreatActorGroupName" TEXT NULL,
	"ThreatActorGroupDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORGROUPTACTIC"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORGROUPTACTIC"(
	"ThreatActorGroupTacticID" INTEGER NOT NULL,
	"ThreatActorGroupID" INTEGER NOT NULL,
	"ThreatActorGroupGUID" TEXT NULL,
	"TacticID" INTEGER NOT NULL,
	"TacticGUID" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORINFRASTRUCTURE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORINFRASTRUCTURE"(
	"ThreatActorInfrastructureID" INTEGER NOT NULL,
	"AttackerInfrastructureGUID" TEXT NULL,
	"AttackerInfrastructureName" TEXT NOT NULL,
	"AttackerInfrastructureDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORINFRASTRUCTUREFORTHREATACTOR"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORINFRASTRUCTUREFORTHREATACTOR"(
	"ThreatActorThreatActorInfrastructureID" INTEGER NOT NULL,
	"ThreatActorID" INTEGER NOT NULL,
	"ThreatActorInfrastructureID" INTEGER NOT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"notes" TEXT NULL,
	"Description" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORINFRASTRUCTUREFORTHREATACTORTTP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORINFRASTRUCTUREFORTHREATACTORTTP"(
	"ThreatActorTTPInfrastructureID" INTEGER NOT NULL,
	"ThreatActorInfrastructureID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"Information_Source" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORPAOS"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORPAOS"(
	"ThreatActorPAOSID" INTEGER NOT NULL,
	"PlanningAndOperationalSupport" TEXT NOT NULL,
	"PAOSDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORROLE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORROLE"(
	"ThreatActorRoleID" INTEGER NOT NULL,
	"role" TEXT NOT NULL,
	"roleDescription" TEXT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORSKILLFORATTACKPATTERN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORSKILLFORATTACKPATTERN"(
	"AttackPatternRequiredSkillID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternRequiredSkillOrder" INTEGER NULL,
	"Skill_or_Knowledge_Level" TEXT NULL,
	"SkillLevelID" INTEGER NULL,
	"Skill_or_Knowledge_Type" TEXT NULL,
	"SkillID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORSOPHISTICATION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORSOPHISTICATION"(
	"ThreatActorSophisticationID" INTEGER NOT NULL,
	"ThreatActorSophisticationGUID" TEXT NULL,
	"ThreatActorSophisticationName" TEXT NULL,
	"ThreatActorSophisticationDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORTACTIC"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTACTIC"(
	"ThreatActorTacticID" INTEGER NOT NULL,
	"TacticID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORTAG"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTAG"(
	"ThreatActorTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATACTORTTP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTTP"(
	"ThreatActorTTPID" INTEGER NOT NULL,
	"TTPTitle" TEXT NOT NULL,
	"TTPDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"Information_Source" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORTTPFORINCIDENT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTTPFORINCIDENT"(
	"ThreatActorTTPIncidentID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActorGUID" TEXT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORTTPFORINDICATOR"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTTPFORINDICATOR"(
	"ThreatActorTTPIndicatorID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"ThreatActorTTPGUID" TEXT NULL,
	"IndicatorID" INTEGER NOT NULL,
	"IndicatorGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NOT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATACTORTTPFORTHREATACTORTTP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORTTPFORTHREATACTORTTP"(
	"ThreatActorTTPMappingID" INTEGER NOT NULL,
	"ThreatActorTTPRefID" INTEGER NOT NULL,
	"Relationship" TEXT NULL,
	"ThreatActorTTPSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "THREATACTORVARIETY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATACTORVARIETY"(
	"ThreatActorVarietyID" INTEGER NOT NULL,
	"ThreatActorTypeGUID" TEXT NULL,
	"ExternalVariety" INTEGER NULL,
	"InternalVariety" INTEGER NULL,
	"ActorVariety" TEXT NOT NULL,
	"ActorVarietyDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATAGENT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATAGENT"(
	"ThreatAgentID" INTEGER NOT NULL,
	"ThreatAgentGUID" TEXT NULL,
	"ThreatAgentName" TEXT NOT NULL,
	"ThreatAgentDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "THREATAGENTCATEGORY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATAGENTCATEGORY"(
	"ThreatAgentCategoryID" INTEGER NOT NULL,
	"CategoryID" INTEGER NULL
)

;
/****** Object:  Table "THREATAGENTCHANGERECORD"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATAGENTCHANGERECORD"(
	"ThreatAgentChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATAGENTFOROWASPTOP10"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATAGENTFOROWASPTOP10"(
	"OWASPTOP10ThreatAgentID" INTEGER NOT NULL,
	"OWASPTOP10ID" INTEGER NOT NULL,
	"ThreatAgentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"LastCheckedDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATAGENTTAG"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATAGENTTAG"(
	"ThreatAgentTagID" INTEGER NOT NULL,
	"ThreatAgentID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATCAMPAIGN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGN"(
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"ThreatCampaignTitle" TEXT NULL,
	"ThreatCampaignStatus" TEXT NULL,
	"ThreatCampaignDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"SourceID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ImportanceID" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNCHANGERECORD"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNCHANGERECORD"(
	"ThreatCampaignChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNDESCRIPTION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNDESCRIPTION"(
	"ThreatCampaignDescriptionID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"DescriptionGUID" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"SourceID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNFORTHREATCAMPAIGN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNFORTHREATCAMPAIGN"(
	"ThreatCampaignMappingID" INTEGER NOT NULL,
	"ThreatCampaignRefID" INTEGER NOT NULL,
	"ThreatCampaignRefGUID" TEXT NULL,
	"Relationship" TEXT NULL,
	"ThreatCampaignSubjectID" INTEGER NOT NULL,
	"ThreatCampaignSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"ConfidenceLevel" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"notes" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNMETHODOLOGY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNMETHODOLOGY"(
	"ThreatCampaignMethodologyID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNNAME"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNNAME"(
	"ThreatCampaignNameID" INTEGER NOT NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"ThreatCampaignName" TEXT NOT NULL,
	"internalname" INTEGER NULL,
	"externalname" INTEGER NULL,
	"Information_Source" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NOT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNNAMEFORTHREATCAMPAIGN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNNAMEFORTHREATCAMPAIGN"(
	"ThreatCampaignThreatCampaignNameID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatCampaignNameID" INTEGER NOT NULL,
	"CreatedDate" TEXT NOT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NOT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNREFERENCE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNREFERENCE"(
	"ThreatCampaignReferenceID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNSOURCE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNSOURCE"(
	"ThreatCampaignSourceID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNSTATUS"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNSTATUS"(
	"ThreatCampaignStatusID" INTEGER NOT NULL,
	"CampaignStatus" TEXT NOT NULL,
	"CampaignStatusDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNTAG"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNTAG"(
	"ThreatCampaignTagID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"ThreatCampaignGUID" TEXT NULL,
	"TagID" INTEGER NOT NULL,
	"TagGUID" TEXT NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATCAMPAIGNTECHNIQUE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNTECHNIQUE"(
	"ThreatCampaignTechniqueID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNTOOL"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNTOOL"(
	"ThreatCampaignToolID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATCAMPAIGNTYPE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCAMPAIGNTYPE"(
	"ThreatCampaignTypeID" INTEGER NOT NULL,
	"CampaignTypeTitle" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "THREATCATEGORY"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCATEGORY"(
	"ThreatCategoryID" INTEGER NOT NULL,
	"ThreatCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"ThreatCategoryName" TEXT NULL,
	"ThreatCategoryDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ImportanceID" INTEGER NULL,
	"ValidityID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATCATEGORYDESCRIPTION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCATEGORYDESCRIPTION"(
	"ThreatCategoryDescriptionID" INTEGER NOT NULL,
	"ThreatCategoryID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATCATEGORYREFERENCE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCATEGORYREFERENCE"(
	"ThreatCategoryReferenceID" INTEGER NOT NULL,
	"ThreatCategoryID" INTEGER NOT NULL,
	"ReferenceID" INTEGER NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"CreationObjectID" INTEGER NULL,
	"ConfidentialityLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATCATEGORYTAG"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATCATEGORYTAG"(
	"ThreatCategoryTagID" INTEGER NOT NULL,
	"ThreatCategoryID" INTEGER NOT NULL,
	"TagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ValidityID" INTEGER NULL,
	"VocbularyID" INTEGER NULL
)

;
/****** Object:  Table "THREATINTENDEDEFFECT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATINTENDEDEFFECT"(
	"ThreatIntendedEffectID" INTEGER NOT NULL,
	"ThreatIntendedEffectGUID" TEXT NULL,
	"IntendedEffectName" TEXT NOT NULL,
	"IntendedEffectDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATINTENDEDEFFECTFORINCIDENT"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATINTENDEDEFFECTFORINCIDENT"(
	"IncidentThreatIntendedEffectID" INTEGER NOT NULL,
	"ThreatIntendedEffectID" INTEGER NOT NULL,
	"ThreatIntendedEffectGUID" TEXT NULL,
	"IncidentID" INTEGER NOT NULL,
	"IncidentGUID" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NOT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "THREATINTENDEDEFFECTFORTHREATACTORTTP"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATINTENDEDEFFECTFORTHREATACTORTTP"(
	"ThreatActorTTPIntendedEffectID" INTEGER NOT NULL,
	"ThreatIntendedEffectID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"notes" TEXT NULL,
	"ConfidenceLevel" TEXT NULL,
	"Information_Source" TEXT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NOT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATINTENDEDEFFECTFORTHREATCAMPAIGN"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATINTENDEDEFFECTFORTHREATCAMPAIGN"(
	"ThreatCampaignIntendedEffectID" INTEGER NOT NULL,
	"ThreatIntendedEffectID" INTEGER NOT NULL,
	"ThreatCampaignID" INTEGER NOT NULL,
	"CreatedDate" TEXT NOT NULL,
	BLOB TEXT NOT NULL,
	"ValidFromDate" TEXT NOT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "THREATMOTIVE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATMOTIVE"(
	"ThreatMotiveID" INTEGER NOT NULL,
	"ThreatMotiveGUID" TEXT NULL,
	"motive" TEXT NOT NULL,
	"motiveDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntildate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "THREATMOTIVEDESCRIPTION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATMOTIVEDESCRIPTION"(
	"ThreatMotiveDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATMOTIVEFORTHREATACTOR"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATMOTIVEFORTHREATACTOR"(
	"ThreatActorMotiveID" INTEGER NOT NULL,
	"ThreatMotiveID" INTEGER NOT NULL,
	"ThreatActorID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATMOTIVETAG"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATMOTIVETAG"(
	"ThreatMotiveTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "THREATTYPE"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATTYPE"(
	"ThreatTypeID" INTEGER NOT NULL,
	"ThreatTypeGUID" TEXT NULL,
	"ThreatTypeName" TEXT NOT NULL,
	"ThreatTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "THREATTYPEDESCRIPTION"    Script Date: 04/03/2015 18:51:03 ******/

;

;
CREATE TABLE "THREATTYPEDESCRIPTION"(
	"ThreatTypeDescriptionID" INTEGER NOT NULL,
	"ThreatTypeID" INTEGER NOT NULL,
	"DescriptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;


;
/****** XORCISM schema catch-up — generated 2026-06-14 (tables & columns added since 2025) ******/
;

-- New tables
CREATE TABLE IF NOT EXISTS HUNT (
  HuntID INTEGER PRIMARY KEY,
  HuntGUID TEXT, HuntName TEXT, HuntDescription TEXT, CreatedDate DATE,
  HuntReference TEXT, ValidFrom DATE, ValidUntil DATE,
  HuntStatus TEXT, HuntDate DATE, HuntTool TEXT, AttackTags TEXT,
  HuntFindings TEXT, HuntSource TEXT);
CREATE TABLE IF NOT EXISTS HYPOTHESIS (
  HypothesisID INTEGER PRIMARY KEY,
  HypothesisGUID TEXT, HypothesisName TEXT, HypothesisDescription TEXT,
  CreatedDate DATE, ValidFromDate DATE, ValidUntil DATE, ConfidenceLevel TEXT);
CREATE TABLE IF NOT EXISTS THREATREPORT (
  ThreatReportID INTEGER PRIMARY KEY,
  ThreatReportGUID TEXT, ThreatReportName TEXT, ThreatReportDescription TEXT,
  CreatedDate DATE, ValidFrom DATE, ValidUntil DATE, PersonID INTEGER,
  ThreatReportFileName TEXT, ThreatReportSource TEXT, ThreatReportReference TEXT);
CREATE INDEX IF NOT EXISTS ix_threatreport_ref ON THREATREPORT(ThreatReportReference);
CREATE TABLE IF NOT EXISTS SIGMARULE (
  SigmaRuleID INTEGER PRIMARY KEY,
  SigmaRuleGUID TEXT, SigmaRuleName TEXT, SigmaRuleDescription TEXT,
  SigmaYaml TEXT, LogSource TEXT, Level TEXT, Status TEXT, Author TEXT,
  SigmaReference TEXT, AttackTags TEXT,
  SplQuery TEXT, KqlQuery TEXT, EqlQuery TEXT,
  CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
CREATE TABLE IF NOT EXISTS HUNTATTACK (
  HuntAttackID INTEGER PRIMARY KEY, HuntID INTEGER, AttackID TEXT,
  AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(HuntID, AttackID));
CREATE INDEX IF NOT EXISTS ix_huntattack_hunt ON HUNTATTACK(HuntID);
CREATE INDEX IF NOT EXISTS ix_huntattack_aid ON HUNTATTACK(AttackID);
CREATE TABLE IF NOT EXISTS HUNTIOC (
  HuntIOCID INTEGER PRIMARY KEY, HuntID INTEGER, IOCID INTEGER,
  Relationship TEXT, CreatedDate DATE, UNIQUE(HuntID, IOCID));
CREATE INDEX IF NOT EXISTS ix_huntioc_hunt ON HUNTIOC(HuntID);
-- Community threat-intel reports (detections.ai Intel Exchange), imported by the
-- detections-ai connector. Idempotent by IntelReference (source URL).
CREATE TABLE IF NOT EXISTS INTELEXCHANGE (
  IntelID INTEGER PRIMARY KEY,
  IntelGUID TEXT, IntelName TEXT, IntelDescription TEXT, CreatedDate DATE,
  IntelReference TEXT, IntelExternalID TEXT, IntelAuthor TEXT, IntelDate DATE,
  IntelSource TEXT, AttackTags TEXT, ActorTags TEXT, MalwareTags TEXT,
  CveTags TEXT, IntelTags TEXT, Views INTEGER, ValidFrom DATE, ValidUntil DATE);
CREATE INDEX IF NOT EXISTS ix_intelexchange_ref ON INTELEXCHANGE(IntelReference);
CREATE TABLE IF NOT EXISTS INTELEXCHANGEATTACK (
  IntelAttackID INTEGER PRIMARY KEY, IntelID INTEGER, AttackID TEXT,
  AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(IntelID, AttackID));
CREATE INDEX IF NOT EXISTS ix_intelattack_intel ON INTELEXCHANGEATTACK(IntelID);
CREATE INDEX IF NOT EXISTS ix_intelattack_aid ON INTELEXCHANGEATTACK(AttackID);
CREATE TABLE IF NOT EXISTS ATTACKDATASOURCE (
  AttackDataSourceID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Platforms TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKGROUP (
  AttackGroupID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Aliases TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, ThreatActorID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKMITIGATION (
  AttackMitigationID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKRELATIONSHIP (
  AttackRelationshipID INTEGER PRIMARY KEY,
  StixID TEXT, RelationshipType TEXT, SourceStixID TEXT, TargetStixID TEXT,
  SourceAttackID TEXT, TargetAttackID TEXT, Description TEXT, Domain TEXT, CreatedDate TEXT,
  UNIQUE(Domain, StixID));
CREATE INDEX IF NOT EXISTS ix_attackrel_type ON ATTACKRELATIONSHIP(RelationshipType);
CREATE INDEX IF NOT EXISTS ix_attackrel_src ON ATTACKRELATIONSHIP(SourceStixID);
CREATE TABLE IF NOT EXISTS ATTACKSOFTWARE (
  AttackSoftwareID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, SoftwareType TEXT, Description TEXT, Aliases TEXT,
  Platforms TEXT, Domain TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKTACTIC (
  AttackTacticID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, ShortName TEXT, Description TEXT,
  Domain TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0, MatrixOrder INTEGER,
  ThreatActorTacticID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE INDEX IF NOT EXISTS ix_attacktactic_aid ON ATTACKTACTIC(AttackID);
CREATE TABLE IF NOT EXISTS ATTACKTECHNIQUE (
  AttackTechniqueID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Domain TEXT,
  IsSubtechnique INTEGER DEFAULT 0, ParentAttackID TEXT,
  Platforms TEXT, DataSources TEXT, Detection TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0,
  ThreatActorTTPID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE INDEX IF NOT EXISTS ix_attacktech_aid ON ATTACKTECHNIQUE(AttackID);
CREATE TABLE IF NOT EXISTS ATTACKTECHNIQUETACTIC (
  AttackTechniqueTacticID INTEGER PRIMARY KEY,
  AttackTechniqueID INTEGER, AttackTacticID INTEGER, TacticShortName TEXT, Domain TEXT, CreatedDate TEXT,
  UNIQUE(AttackTechniqueID, AttackTacticID));
CREATE TABLE IF NOT EXISTS D3FENDATTACKMAP (
      D3FENDAttackMapID INTEGER PRIMARY KEY, D3FENDID TEXT, AttackID TEXT, Relationship TEXT,
      UNIQUE(D3FENDID, AttackID, Relationship));
CREATE INDEX IF NOT EXISTS ix_d3map_d3 ON D3FENDATTACKMAP(D3FENDID);
CREATE INDEX IF NOT EXISTS ix_d3map_attack ON D3FENDATTACKMAP(AttackID);
CREATE TABLE IF NOT EXISTS D3FENDTACTIC (
      D3FENDTacticID INTEGER PRIMARY KEY, ShortName TEXT UNIQUE, Name TEXT,
      Definition TEXT, MatrixOrder INTEGER, URL TEXT);
CREATE TABLE IF NOT EXISTS D3FENDTECHNIQUE (
      D3FENDTechniqueID INTEGER PRIMARY KEY, D3FENDID TEXT UNIQUE, Name TEXT,
      Definition TEXT, TacticShortName TEXT, ParentD3FENDID TEXT,
      IsSubtechnique INTEGER DEFAULT 0, URL TEXT);
CREATE INDEX IF NOT EXISTS ix_d3tech_tactic ON D3FENDTECHNIQUE(TacticShortName);
CREATE TABLE IF NOT EXISTS IOC (
      IOCID INTEGER PRIMARY KEY,
      IOCGUID TEXT, IOCName TEXT, IOCDescription TEXT, CreatedDate TEXT,
      IOCtype TEXT DEFAULT 'indicator', OrganisationID INTEGER, PersonID INTEGER,
      created_by_ref TEXT, ValidFrom DATE, ValidUntil DATE,
      -- STIX 2.1 compatibility (indicator / observable)
      StixID TEXT, SpecVersion TEXT DEFAULT '2.1', ModifiedDate TEXT,
      Pattern TEXT, PatternType TEXT DEFAULT 'stix', PatternVersion TEXT,
      IndicatorTypes TEXT, KillChainPhases TEXT, Labels TEXT,
      ExternalReferences TEXT, ObjectMarkingRefs TEXT,
      Confidence INTEGER, Revoked INTEGER DEFAULT 0, Lang TEXT,
      VocabularyID INTEGER, TenantID INTEGER);
CREATE INDEX IF NOT EXISTS ix_ioc_stixid ON IOC(StixID);
CREATE INDEX IF NOT EXISTS ix_ioc_type ON IOC(IOCtype);
CREATE TABLE IF NOT EXISTS "RELATIONSHIP"(
  "RelationshipID" INTEGER PRIMARY KEY,
  "RelationshipGUID" TEXT,
  "relationship_type" TEXT,
  "source_ref" TEXT,
  "target_ref" TEXT,
  "description" TEXT,
  "start_time" TEXT,
  "stop_time" TEXT,
  "CreatedDate" TEXT,
  "VocabularyID" INTEGER,
  "isEncrypted" INTEGER);
CREATE TABLE IF NOT EXISTS "THREAT" (
  "ThreatID" INTEGER PRIMARY KEY,
  "ThreatGUID" TEXT,
  "ThreatName" TEXT,
  "ThreatDescription" TEXT,
  "ThreatProvenance" TEXT,
  "Criticity" INTEGER,
  "ValidFrom" TEXT,
  "ValidUntil" TEXT,
  "ConfidenceLevel" TEXT,
  "TrustLevel" INTEGER
, "STIXType" TEXT, "ThreatActorID" INTEGER);
CREATE TABLE IF NOT EXISTS "THREATEVENT" (
        "ThreatEventID" INTEGER PRIMARY KEY,
        "ReferentialID" TEXT,
        "KCPhase" TEXT,
        "Tier" INTEGER,
        "Description" TEXT,
        "VocabularyID" INTEGER
    , "Category" TEXT);
CREATE TABLE IF NOT EXISTS THREATTTP (
    ThreatTTPID INTEGER PRIMARY KEY,
    ThreatID INTEGER, AttackTechniqueID INTEGER, AttackID TEXT, CreatedDate TEXT,
    UNIQUE(ThreatID, AttackTechniqueID));

-- New columns on existing tables
ALTER TABLE "THREATACTOR" ADD COLUMN "ThreatMotive" TEXT;
ALTER TABLE "THREATACTORFORINCIDENT" ADD COLUMN "ConfidenceLevel" TEXT;
ALTER TABLE "THREATACTORFORINCIDENT" ADD COLUMN "ValidFrom" TEXT;
ALTER TABLE "THREATACTORFORINCIDENT" ADD COLUMN "ValidUntil" TEXT;
ALTER TABLE "THREATAGENT" ADD COLUMN "Capability" TEXT;
ALTER TABLE "THREATAGENT" ADD COLUMN "Intent" TEXT;
ALTER TABLE "THREATAGENT" ADD COLUMN "Targeting" TEXT;
ALTER TABLE "THREATAGENTCATEGORY" ADD COLUMN "ThreatAgentID" INTEGER;
ALTER TABLE "THREATMOTIVE" ADD COLUMN "ThreatMotive" TEXT;
ALTER TABLE "THREATMOTIVE" ADD COLUMN "ThreatMotiveDescription" TEXT;






;
/****** OpenCTI schema catch-up — generated 2026-06-14 (OpenCTI + Adversary Emulation/BAS: Confidence, TLP, Sighting, Observable, EMULATION tables, ATOMICTEST) ******/
;

-- New tables
CREATE TABLE IF NOT EXISTS SIGHTING (
      SightingID INTEGER PRIMARY KEY, SightingGUID TEXT, Name TEXT,
      SightingOfRef TEXT, IOCID INTEGER, WhereSightedRef TEXT,
      Count INTEGER DEFAULT 1, FirstSeen DATE, LastSeen DATE,
      Confidence INTEGER, TLP TEXT, Labels TEXT, Negative INTEGER DEFAULT 0,
      Description TEXT, CreatedByRef TEXT, CreatedDate DATE);
CREATE TABLE IF NOT EXISTS OBSERVABLE (
      ObservableID INTEGER PRIMARY KEY, ObservableGUID TEXT, StixID TEXT,
      ObservableType TEXT, Value TEXT, Description TEXT, Labels TEXT, TLP TEXT,
      Score INTEGER, CreatedByRef TEXT, ExternalReferences TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
CREATE TABLE IF NOT EXISTS INDICATOROBSERVABLE (
      IndicatorObservableID INTEGER PRIMARY KEY, IOCID INTEGER, ObservableID INTEGER,
      Relationship TEXT DEFAULT 'based-on', Confidence INTEGER, CreatedDate DATE,
      UNIQUE(IOCID, ObservableID));
CREATE TABLE IF NOT EXISTS EMULATIONSCENARIO (
      ScenarioID INTEGER PRIMARY KEY, ScenarioGUID TEXT, Name TEXT, Description TEXT,
      AdversaryRef TEXT, KillChainPhase TEXT, Status TEXT,
      Confidence INTEGER, TLP TEXT, Labels TEXT,
      CreatedDate DATE, ValidFrom DATE, ValidUntil DATE);
CREATE TABLE IF NOT EXISTS ATOMICTEST (
      AtomicTestID INTEGER PRIMARY KEY, AtomicGUID TEXT UNIQUE, Name TEXT, Description TEXT,
      AttackID TEXT, AttackTechniqueID INTEGER, Platform TEXT, Executor TEXT,
      Command TEXT, Cleanup TEXT, Source TEXT, ExternalReferences TEXT, CreatedDate DATE);
CREATE TABLE IF NOT EXISTS SCENARIOTEST (
      ScenarioTestID INTEGER PRIMARY KEY, ScenarioID INTEGER, AtomicTestID INTEGER,
      StepOrder INTEGER, CreatedDate DATE, UNIQUE(ScenarioID, AtomicTestID));
CREATE TABLE IF NOT EXISTS EMULATIONRUN (
      RunID INTEGER PRIMARY KEY, RunGUID TEXT, ScenarioID INTEGER, Name TEXT,
      TargetAssetID INTEGER, Status TEXT, RunDate DATE, Score INTEGER, CreatedDate DATE);
CREATE TABLE IF NOT EXISTS EMULATIONRESULT (
      EmulationResultID INTEGER PRIMARY KEY, RunID INTEGER, AtomicTestID INTEGER,
      AttackID TEXT, Outcome TEXT, DetectedBy TEXT, Notes TEXT, CreatedDate DATE);
CREATE INDEX IF NOT EXISTS ix_sighting_ioc ON SIGHTING(IOCID);
CREATE INDEX IF NOT EXISTS ix_observable_type ON OBSERVABLE(ObservableType);
CREATE INDEX IF NOT EXISTS ix_indobs_ioc ON INDICATOROBSERVABLE(IOCID);
CREATE INDEX IF NOT EXISTS ix_indobs_obs ON INDICATOROBSERVABLE(ObservableID);
CREATE INDEX IF NOT EXISTS ix_atomic_attack ON ATOMICTEST(AttackID);
CREATE INDEX IF NOT EXISTS ix_emresult_run ON EMULATIONRESULT(RunID);
CREATE INDEX IF NOT EXISTS ix_emresult_attack ON EMULATIONRESULT(AttackID);

-- New columns on existing tables
ALTER TABLE "THREATACTOR" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "THREATACTOR" ADD COLUMN "TLP" TEXT;
ALTER TABLE "THREATACTOR" ADD COLUMN "Labels" TEXT;
ALTER TABLE "THREATACTOR" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "THREATACTOR" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "THREATACTOR" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "THREATACTOR" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "THREATACTOR" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "TLP" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "Labels" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "THREATCAMPAIGN" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "RELATIONSHIP" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "RELATIONSHIP" ADD COLUMN "TLP" TEXT;
ALTER TABLE "RELATIONSHIP" ADD COLUMN "Labels" TEXT;
ALTER TABLE "RELATIONSHIP" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "THREAT" ADD COLUMN "TLP" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "Labels" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "THREAT" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "THREAT" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "TLP" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "Labels" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "ATTACKTECHNIQUE" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "TLP" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "Labels" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "ATTACKMITIGATION" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "TLP" TEXT;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "Labels" TEXT;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "ATTACKGROUP" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "TLP" TEXT;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "Labels" TEXT;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "ATTACKSOFTWARE" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "IOC" ADD COLUMN "TLP" TEXT;
ALTER TABLE "IOC" ADD COLUMN "Score" INTEGER;
ALTER TABLE "IOC" ADD COLUMN "Detection" INTEGER;
ALTER TABLE "IOC" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "HUNT" ADD COLUMN "TLP" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "Labels" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "HUNT" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "HUNT" ADD COLUMN "WorkflowStatus" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "Confidence" INTEGER;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "TLP" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "Labels" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "CreatedByRef" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "ExternalReferences" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "Revoked" INTEGER;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "Aliases" TEXT;
ALTER TABLE "HYPOTHESIS" ADD COLUMN "WorkflowStatus" TEXT;


;
/****** OpenCTI schema catch-up — generated 2026-06-14 (schema catch-up, no asterisk-slash here) ******/
;

-- New tables
CREATE TABLE IF NOT EXISTS A3MTACTIC (A3MTacticID INTEGER PRIMARY KEY, Name TEXT UNIQUE, MatrixOrder INTEGER, URL TEXT);
CREATE TABLE IF NOT EXISTS A3MTECHNIQUE (
        A3MTechniqueID INTEGER PRIMARY KEY, AATID TEXT UNIQUE, Name TEXT, Description TEXT,
        TacticName TEXT, MatrixOrder INTEGER, URL TEXT);
CREATE INDEX IF NOT EXISTS ix_a3mtech_tactic ON A3MTECHNIQUE(TacticName);
-- LLM ATT&CK Navigator (Anthropic) — AI-enablement layer over MITRE ATT&CK, populated by import_llm_attack.py.
CREATE TABLE IF NOT EXISTS LLMATTACKTECHNIQUE (
        LLMAttackTechniqueID INTEGER PRIMARY KEY,
        AttackID TEXT UNIQUE, Name TEXT, TacticName TEXT,
        ActorCount INTEGER, PrevalencePct REAL, AriesMean REAL,
        Observed INTEGER DEFAULT 1, Notes TEXT, Source TEXT, CreatedDate TEXT);
CREATE INDEX IF NOT EXISTS ix_llmattack_attackid ON LLMATTACKTECHNIQUE(AttackID);
-- SAIF — Google Secure AI Framework risk map (saif.google), populated by import_saif.py.
CREATE TABLE IF NOT EXISTS SAIFCOMPONENT (
        SaifComponentID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Description TEXT,
        MatrixOrder INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS SAIFCONTROL (
        SaifControlID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Category TEXT, Description TEXT,
        CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS SAIFRISK (
        SaifRiskID INTEGER PRIMARY KEY, SaifID TEXT, Name TEXT UNIQUE, Description TEXT,
        Component TEXT, ResponsibleParty TEXT, Controls TEXT, MatrixOrder INTEGER, URL TEXT,
        CreatedDate TEXT);
CREATE INDEX IF NOT EXISTS ix_saifrisk_component ON SAIFRISK(Component);
-- Curated CTI RSS feeds shown on /threat-feeds (seeded by seedThreatFeeds() in db.ts).
CREATE TABLE IF NOT EXISTS THREATFEED (
        ThreatFeedID INTEGER PRIMARY KEY,
        ThreatFeedGUID TEXT, ThreatFeedName TEXT, FeedURL TEXT UNIQUE, SiteURL TEXT,
        ThreatFeedDescription TEXT, Category TEXT, Vendor TEXT,
        Enabled INTEGER DEFAULT 1, CreatedDate TEXT);
CREATE INDEX IF NOT EXISTS ix_threatfeed_enabled ON THREATFEED(Enabled);

-- THREATFORASSET: links a THREAT to an ASSET (relationship + validity + tenant).
CREATE TABLE IF NOT EXISTS THREATFORASSET (
        AssetThreatID INTEGER PRIMARY KEY,
        AssetID INTEGER, ThreatID INTEGER, CreatedDate TEXT, PersonID INTEGER,
        Relationship TEXT, ValidFrom TEXT, ValidUntil TEXT, TenantID INTEGER);
CREATE INDEX IF NOT EXISTS ix_threatforasset_asset ON THREATFORASSET(AssetID);
CREATE INDEX IF NOT EXISTS ix_threatforasset_threat ON THREATFORASSET(ThreatID);

-- WATCHLIST: keyword/actor/CVE terms tracked across the feed (alerts on new matches).
CREATE TABLE IF NOT EXISTS WATCHLIST (
        WatchlistID INTEGER PRIMARY KEY,
        Term TEXT, WatchType TEXT DEFAULT 'keyword', WatchlistName TEXT,
        UserID INTEGER, Enabled INTEGER DEFAULT 1, CreatedDate TEXT, TenantID INTEGER);
CREATE INDEX IF NOT EXISTS ix_watchlist_enabled ON WATCHLIST(Enabled);

-- PIR: standing priority intelligence requirements (CTI tasking).
CREATE TABLE IF NOT EXISTS PIR (
        PIRID INTEGER PRIMARY KEY,
        PIRName TEXT, PIRDescription TEXT, Priority TEXT DEFAULT 'Medium',
        Keywords TEXT, Status TEXT DEFAULT 'Active', PersonID INTEGER,
        CreatedDate TEXT, ValidFrom TEXT, ValidUntil TEXT, TenantID INTEGER);
CREATE INDEX IF NOT EXISTS ix_pir_status ON PIR(Status);

COMMIT;
